package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.DiscoveryFailureKind
import com.velumtegra.xuimobile.core.model.DiscoveryResult
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.DiscoveryTerminalKind
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.terminalKind
import java.time.Instant

/**
 * Process-local safe handoff for normalized Discovery outcomes.
 *
 * Nothing here is recovery truth. Detailed results and host notices disappear on process death;
 * only the generic OperationJournal terminal category/time remains durable. The registry is bounded
 * and never stores raw command/output, credentials, SessionId or mutation authorization.
 */
internal class DiscoveryResultRegistry(
    private val maxTrackedOperations: Int = 32,
) {
    init {
        require(maxTrackedOperations > 0)
    }

    private val lock = Any()
    private val tracked = LinkedHashSet<OperationId>()
    private val detailed = linkedMapOf<OperationId, DiscoveryResult>()
    private val notices = linkedMapOf<OperationId, DiscoveryProcessNotice>()

    fun beginAttempt(operationId: OperationId) = synchronized(lock) {
        track(operationId)
        notices.remove(operationId)
    }

    fun isTracked(operationId: OperationId): Boolean = synchronized(lock) {
        operationId in tracked
    }

    fun publishResult(result: DiscoveryResult) = synchronized(lock) {
        val operationId = result.scope.operationId
        if (operationId !in tracked) return@synchronized
        detailed[operationId] = result
        notices.remove(operationId)
        trim()
    }

    fun publishNotice(operationId: OperationId, notice: DiscoveryProcessNotice) = synchronized(lock) {
        if (operationId !in tracked || operationId in detailed) return@synchronized
        notices[operationId] = notice
        trim()
    }

    fun latestResult(operationId: OperationId): DiscoveryResult? = synchronized(lock) {
        detailed[operationId]
    }

    fun latestNotice(operationId: OperationId): DiscoveryProcessNotice? = synchronized(lock) {
        notices[operationId]
    }

    fun clear(operationId: OperationId) = synchronized(lock) {
        tracked.remove(operationId)
        detailed.remove(operationId)
        notices.remove(operationId)
    }

    private fun track(operationId: OperationId) {
        tracked.remove(operationId)
        tracked.add(operationId)
        trim()
    }

    private fun trim() {
        while (tracked.size > maxTrackedOperations) {
            val eldest = tracked.first()
            tracked.remove(eldest)
            detailed.remove(eldest)
            notices.remove(eldest)
        }
    }
}

/** Safe process-only status for a host attempt that did not produce a durable Discovery RESULT. */
internal sealed interface DiscoveryProcessNotice {
    data object HostStartRejected : DiscoveryProcessNotice
    data object WaitingForNetwork : DiscoveryProcessNotice
    data object HostInterrupted : DiscoveryProcessNotice
    data object BusyOrSuperseded : DiscoveryProcessNotice
    data object DurableStateUnavailable : DiscoveryProcessNotice
    data object NotExecutable : DiscoveryProcessNotice
    data class Failure(val failure: DiscoveryFailureKind) : DiscoveryProcessNotice
}

internal class DiscoveryResultProjector(
    private val journal: OperationJournal,
    private val registry: DiscoveryResultRegistry,
) {
    suspend fun read(operationId: OperationId): DiscoveryReadResult = when (val current = journal.get(operationId)) {
        is OperationJournalResult.Success -> project(current.value.snapshot)
        OperationJournalResult.NotFound -> DiscoveryReadResult.NotFound
        is OperationJournalResult.Corruption -> DiscoveryReadResult.Unavailable(DiscoveryReadFailure.JOURNAL_CORRUPTION)
        is OperationJournalResult.StorageFailure -> DiscoveryReadResult.Unavailable(DiscoveryReadFailure.JOURNAL_STORAGE_FAILURE)
        else -> DiscoveryReadResult.ContractViolation(
            "Discovery journal read returned ${current::class.simpleName}",
        )
    }

    private fun project(snapshot: com.velumtegra.xuimobile.core.model.OperationSnapshot): DiscoveryReadResult {
        if (snapshot.type != OperationType.DISCOVERY) {
            return DiscoveryReadResult.ContractViolation("Operation is not DISCOVERY")
        }
        val target = snapshot.target as? OperationTarget.ServerTarget
            ?: return DiscoveryReadResult.ContractViolation("Discovery requires exact ServerTarget")
        val scope = DiscoveryScope(snapshot.operationId, target.serverId, target.serverAccessId)
        val statusTerminal = snapshot.status in TERMINAL_STATUSES
        val checkpointTerminal = snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
        if (statusTerminal != checkpointTerminal) {
            return DiscoveryReadResult.ContractViolation(
                "Discovery terminal status/checkpoint semantics disagree",
            )
        }

        if (!statusTerminal) {
            if (snapshot.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
                return DiscoveryReadResult.ContractViolation(
                    "Nonterminal Discovery checkpoint must remain READ_ONLY",
                )
            }
            return DiscoveryReadResult.InProgress(
                scope = scope,
                status = snapshot.status,
                phaseName = snapshot.checkpoint.phaseName,
                processNotice = registry.latestNotice(snapshot.operationId),
            )
        }

        if (snapshot.updatedAt != snapshot.checkpoint.recordedAt) {
            return DiscoveryReadResult.ContractViolation(
                "Discovery terminal completion time must equal terminal checkpoint time",
            )
        }
        val kind = DiscoveryTerminalKind.fromPhaseName(snapshot.checkpoint.phaseName)
            ?: return DiscoveryReadResult.ContractViolation("Unknown durable Discovery terminal phase")
        if (snapshot.status != kind.operationStatus) {
            return DiscoveryReadResult.ContractViolation(
                "Durable Discovery status disagrees with terminal category",
            )
        }

        val detailed = registry.latestResult(snapshot.operationId)
        if (detailed != null) {
            if (
                detailed.scope != scope ||
                detailed.completedAt != snapshot.checkpoint.recordedAt ||
                detailed.terminalKind() != kind
            ) {
                return DiscoveryReadResult.ContractViolation(
                    "Process-local Discovery detail disagrees with durable scope/category/time",
                )
            }
            return DiscoveryReadResult.Detailed(detailed)
        }

        return DiscoveryReadResult.DurableTerminal(
            DiscoveryTerminalSummary(
                scope = scope,
                kind = kind,
                completedAt = snapshot.checkpoint.recordedAt,
            ),
        )
    }

    private companion object {
        val TERMINAL_STATUSES = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}

internal sealed interface DiscoveryReadResult {
    data class InProgress(
        val scope: DiscoveryScope,
        val status: OperationStatus,
        val phaseName: String,
        val processNotice: DiscoveryProcessNotice?,
    ) : DiscoveryReadResult

    /** Full normalized detail exists only while the process-local registry survives. */
    data class Detailed(val result: DiscoveryResult) : DiscoveryReadResult

    /** Process-death fallback: safe durable category only; no proof/evidence is invented. */
    data class DurableTerminal(val summary: DiscoveryTerminalSummary) : DiscoveryReadResult

    data class ContractViolation(val reason: String) : DiscoveryReadResult
    data class Unavailable(val failure: DiscoveryReadFailure) : DiscoveryReadResult
    data object NotFound : DiscoveryReadResult
}

internal data class DiscoveryTerminalSummary(
    val scope: DiscoveryScope,
    val kind: DiscoveryTerminalKind,
    val completedAt: Instant,
)

internal enum class DiscoveryReadFailure {
    JOURNAL_CORRUPTION,
    JOURNAL_STORAGE_FAILURE,
}
