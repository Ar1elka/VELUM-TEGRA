package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.DeepDiagnosticScope
import com.velumtegra.xuimobile.core.model.DeepDiagnosticSnapshot
import com.velumtegra.xuimobile.core.model.ManagementFailureKind
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import java.time.Instant

/** Bounded process-local handoff. Detailed Deep Diagnostic state is never recovery truth. */
internal class DeepDiagnosticResultRegistry(
    private val maxTrackedOperations: Int = 32,
) {
    init { require(maxTrackedOperations > 0) }

    private val lock = Any()
    private val tracked = LinkedHashSet<OperationId>()
    private val detailed = linkedMapOf<OperationId, DeepDiagnosticProcessDetail>()
    private val notices = linkedMapOf<OperationId, DeepDiagnosticProcessNotice>()

    fun beginAttempt(operationId: OperationId) = synchronized(lock) {
        track(operationId)
        notices.remove(operationId)
    }

    fun isTracked(operationId: OperationId): Boolean = synchronized(lock) { operationId in tracked }

    fun publishCompleted(
        operationId: OperationId,
        snapshot: DeepDiagnosticSnapshot,
        committedRevision: OperationRevision,
    ) = synchronized(lock) {
        if (operationId !in tracked || snapshot.scope.operationId != operationId) return@synchronized
        detailed[operationId] = DeepDiagnosticProcessDetail.Completed(snapshot, committedRevision)
        notices.remove(operationId)
        trim()
    }

    fun publishReadbackFailure(
        operationId: OperationId,
        kind: ManagementFailureKind,
        committedRevision: OperationRevision,
    ) = synchronized(lock) {
        if (operationId !in tracked) return@synchronized
        detailed[operationId] = DeepDiagnosticProcessDetail.ReadbackFailed(kind, committedRevision)
        notices.remove(operationId)
        trim()
    }

    fun publishNotice(operationId: OperationId, notice: DeepDiagnosticProcessNotice) = synchronized(lock) {
        if (operationId !in tracked || operationId in detailed) return@synchronized
        notices[operationId] = notice
        trim()
    }

    fun latestDetail(operationId: OperationId): DeepDiagnosticProcessDetail? = synchronized(lock) { detailed[operationId] }
    fun latestNotice(operationId: OperationId): DeepDiagnosticProcessNotice? = synchronized(lock) { notices[operationId] }

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

internal sealed interface DeepDiagnosticProcessDetail {
    val committedRevision: OperationRevision

    data class Completed(
        val snapshot: DeepDiagnosticSnapshot,
        override val committedRevision: OperationRevision,
    ) : DeepDiagnosticProcessDetail

    data class ReadbackFailed(
        val kind: ManagementFailureKind,
        override val committedRevision: OperationRevision,
    ) : DeepDiagnosticProcessDetail
}

/** Safe process-only status for host attempts that have not produced a durable terminal. */
internal sealed interface DeepDiagnosticProcessNotice {
    data object HostStartRejected : DeepDiagnosticProcessNotice
    data object WaitingForNetwork : DeepDiagnosticProcessNotice
    data object HostInterrupted : DeepDiagnosticProcessNotice
    data object BusyOrSuperseded : DeepDiagnosticProcessNotice
    data object DurableStateUnavailable : DeepDiagnosticProcessNotice
    data object NotExecutable : DeepDiagnosticProcessNotice
    data class Failure(val failure: ManagementFailureKind) : DeepDiagnosticProcessNotice
}

internal enum class DeepDiagnosticTerminalKind(
    val phaseName: String,
    val operationStatus: OperationStatus,
) {
    RESULT("DEEP_DIAGNOSTIC_RESULT", OperationStatus.SUCCEEDED),
    READBACK_FAILED("DEEP_DIAGNOSTIC_FAILED", OperationStatus.FAILED),
    ;

    companion object {
        fun fromPhaseName(phaseName: String): DeepDiagnosticTerminalKind? =
            entries.firstOrNull { it.phaseName == phaseName }
    }
}

internal class DeepDiagnosticResultProjector(
    private val journal: OperationJournal,
    private val registry: DeepDiagnosticResultRegistry,
) {
    suspend fun read(operationId: OperationId): DeepDiagnosticReadResult = when (val current = journal.get(operationId)) {
        is OperationJournalResult.Success -> project(current.value)
        OperationJournalResult.NotFound -> DeepDiagnosticReadResult.NotFound
        is OperationJournalResult.Corruption -> DeepDiagnosticReadResult.Unavailable(
            DeepDiagnosticReadFailure.JOURNAL_CORRUPTION,
        )
        is OperationJournalResult.StorageFailure -> DeepDiagnosticReadResult.Unavailable(
            DeepDiagnosticReadFailure.JOURNAL_STORAGE_FAILURE,
        )
        else -> DeepDiagnosticReadResult.ContractViolation(
            "DEEP_DIAGNOSTIC journal read returned ${current::class.simpleName}",
        )
    }

    private fun project(
        current: com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot,
    ): DeepDiagnosticReadResult {
        val snapshot = current.snapshot
        if (snapshot.type != OperationType.DEEP_DIAGNOSTIC) {
            return DeepDiagnosticReadResult.ContractViolation("Operation is not DEEP_DIAGNOSTIC")
        }
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return DeepDiagnosticReadResult.ContractViolation(
                "DEEP_DIAGNOSTIC requires exact InstallationTarget",
            )
        val scope = DeepDiagnosticScope(
            operationId = snapshot.operationId,
            serverId = target.serverId,
            serverAccessId = target.serverAccessId,
            installationId = target.installationId,
        )
        val statusTerminal = snapshot.status in TERMINAL_STATUSES
        val checkpointTerminal = snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
        if (statusTerminal != checkpointTerminal) {
            return DeepDiagnosticReadResult.ContractViolation(
                "DEEP_DIAGNOSTIC terminal status/checkpoint semantics disagree",
            )
        }
        if (!statusTerminal) {
            if (snapshot.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
                return DeepDiagnosticReadResult.ContractViolation(
                    "Nonterminal DEEP_DIAGNOSTIC checkpoint must remain READ_ONLY",
                )
            }
            return DeepDiagnosticReadResult.InProgress(
                scope = scope,
                status = snapshot.status,
                phaseName = snapshot.checkpoint.phaseName,
                processNotice = registry.latestNotice(snapshot.operationId),
            )
        }
        if (snapshot.updatedAt != snapshot.checkpoint.recordedAt) {
            return DeepDiagnosticReadResult.ContractViolation(
                "DEEP_DIAGNOSTIC terminal completion time must equal terminal checkpoint time",
            )
        }
        val kind = DeepDiagnosticTerminalKind.fromPhaseName(snapshot.checkpoint.phaseName)
            ?: return DeepDiagnosticReadResult.ContractViolation(
                "Unknown durable DEEP_DIAGNOSTIC terminal phase",
            )
        if (snapshot.status != kind.operationStatus) {
            return DeepDiagnosticReadResult.ContractViolation(
                "Durable DEEP_DIAGNOSTIC status disagrees with terminal category",
            )
        }

        when (val detail = registry.latestDetail(snapshot.operationId)) {
            is DeepDiagnosticProcessDetail.Completed -> {
                if (
                    kind != DeepDiagnosticTerminalKind.RESULT ||
                    detail.committedRevision != current.revision ||
                    detail.snapshot.scope != scope ||
                    detail.snapshot.observedAt.isAfter(snapshot.checkpoint.recordedAt)
                ) {
                    return DeepDiagnosticReadResult.ContractViolation(
                        "Process-local Deep Diagnostic detail disagrees with durable scope/category/revision/time",
                    )
                }
                return DeepDiagnosticReadResult.Detailed(detail.snapshot)
            }
            is DeepDiagnosticProcessDetail.ReadbackFailed -> {
                if (
                    kind != DeepDiagnosticTerminalKind.READBACK_FAILED ||
                    detail.committedRevision != current.revision
                ) {
                    return DeepDiagnosticReadResult.ContractViolation(
                        "Process-local Deep Diagnostic failure disagrees with durable category/revision",
                    )
                }
                return DeepDiagnosticReadResult.DetailedFailure(
                    scope = scope,
                    kind = detail.kind,
                    completedAt = snapshot.checkpoint.recordedAt,
                )
            }
            null -> Unit
        }

        return DeepDiagnosticReadResult.DurableTerminal(
            DeepDiagnosticTerminalSummary(
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

internal sealed interface DeepDiagnosticReadResult {
    data class InProgress(
        val scope: DeepDiagnosticScope,
        val status: OperationStatus,
        val phaseName: String,
        val processNotice: DeepDiagnosticProcessNotice?,
    ) : DeepDiagnosticReadResult

    /** Full normalized diagnostic detail exists only while this process survives. */
    data class Detailed(val snapshot: DeepDiagnosticSnapshot) : DeepDiagnosticReadResult

    data class DetailedFailure(
        val scope: DeepDiagnosticScope,
        val kind: ManagementFailureKind,
        val completedAt: Instant,
    ) : DeepDiagnosticReadResult

    /** Process-death fallback: only durable category/scope/time; no live snapshot is reconstructed. */
    data class DurableTerminal(val summary: DeepDiagnosticTerminalSummary) : DeepDiagnosticReadResult

    data class ContractViolation(val reason: String) : DeepDiagnosticReadResult
    data class Unavailable(val failure: DeepDiagnosticReadFailure) : DeepDiagnosticReadResult
    data object NotFound : DeepDiagnosticReadResult
}

internal data class DeepDiagnosticTerminalSummary(
    val scope: DeepDiagnosticScope,
    val kind: DeepDiagnosticTerminalKind,
    val completedAt: Instant,
)

internal enum class DeepDiagnosticReadFailure {
    JOURNAL_CORRUPTION,
    JOURNAL_STORAGE_FAILURE,
}
