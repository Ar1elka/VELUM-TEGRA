package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ManagementFailureKind
import com.velumtegra.xuimobile.core.model.ManagementLiveSnapshot
import com.velumtegra.xuimobile.core.model.ManagementScope
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import java.time.Instant

/** Bounded process-local handoff. Detailed QUICK_INSPECT state is never recovery truth. */
internal class ManagementResultRegistry(
    private val maxTrackedOperations: Int = 32,
) {
    init { require(maxTrackedOperations > 0) }

    private val lock = Any()
    private val tracked = LinkedHashSet<OperationId>()
    private val detailed = linkedMapOf<OperationId, ManagementProcessDetail>()
    private val notices = linkedMapOf<OperationId, ManagementProcessNotice>()

    fun beginAttempt(operationId: OperationId) = synchronized(lock) {
        track(operationId)
        notices.remove(operationId)
    }

    fun isTracked(operationId: OperationId): Boolean = synchronized(lock) { operationId in tracked }

    fun publishCompleted(
        operationId: OperationId,
        snapshot: ManagementLiveSnapshot,
        committedRevision: OperationRevision,
    ) = synchronized(lock) {
        if (operationId !in tracked || snapshot.scope.operationId != operationId) return@synchronized
        detailed[operationId] = ManagementProcessDetail.Completed(snapshot, committedRevision)
        notices.remove(operationId)
        trim()
    }

    fun publishReadbackFailure(
        operationId: OperationId,
        kind: ManagementFailureKind,
        committedRevision: OperationRevision,
    ) = synchronized(lock) {
        if (operationId !in tracked) return@synchronized
        detailed[operationId] = ManagementProcessDetail.ReadbackFailed(kind, committedRevision)
        notices.remove(operationId)
        trim()
    }

    fun publishNotice(operationId: OperationId, notice: ManagementProcessNotice) = synchronized(lock) {
        if (operationId !in tracked || operationId in detailed) return@synchronized
        notices[operationId] = notice
        trim()
    }

    fun latestDetail(operationId: OperationId): ManagementProcessDetail? = synchronized(lock) { detailed[operationId] }
    fun latestNotice(operationId: OperationId): ManagementProcessNotice? = synchronized(lock) { notices[operationId] }

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

internal sealed interface ManagementProcessDetail {
    val committedRevision: OperationRevision

    data class Completed(
        val snapshot: ManagementLiveSnapshot,
        override val committedRevision: OperationRevision,
    ) : ManagementProcessDetail

    data class ReadbackFailed(
        val kind: ManagementFailureKind,
        override val committedRevision: OperationRevision,
    ) : ManagementProcessDetail
}

/** Safe process-only status for host attempts that have not produced a durable QUICK_INSPECT terminal. */
internal sealed interface ManagementProcessNotice {
    data object HostStartRejected : ManagementProcessNotice
    data object WaitingForNetwork : ManagementProcessNotice
    data object HostInterrupted : ManagementProcessNotice
    data object BusyOrSuperseded : ManagementProcessNotice
    data object DurableStateUnavailable : ManagementProcessNotice
    data object NotExecutable : ManagementProcessNotice
    data class Failure(val failure: ManagementFailureKind) : ManagementProcessNotice
}

internal enum class ManagementTerminalKind(
    val phaseName: String,
    val operationStatus: OperationStatus,
) {
    RESULT("QUICK_INSPECT_RESULT", OperationStatus.SUCCEEDED),
    READBACK_FAILED("QUICK_INSPECT_FAILED", OperationStatus.FAILED),
    ;

    companion object {
        fun fromPhaseName(phaseName: String): ManagementTerminalKind? =
            entries.firstOrNull { it.phaseName == phaseName }
    }
}

internal class ManagementResultProjector(
    private val journal: OperationJournal,
    private val registry: ManagementResultRegistry,
) {
    suspend fun read(operationId: OperationId): ManagementReadResult = when (val current = journal.get(operationId)) {
        is OperationJournalResult.Success -> project(current.value)
        OperationJournalResult.NotFound -> ManagementReadResult.NotFound
        is OperationJournalResult.Corruption -> ManagementReadResult.Unavailable(ManagementReadFailure.JOURNAL_CORRUPTION)
        is OperationJournalResult.StorageFailure -> ManagementReadResult.Unavailable(ManagementReadFailure.JOURNAL_STORAGE_FAILURE)
        else -> ManagementReadResult.ContractViolation(
            "QUICK_INSPECT journal read returned ${current::class.simpleName}",
        )
    }

    private fun project(current: com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot): ManagementReadResult {
        val snapshot = current.snapshot
        if (snapshot.type != OperationType.QUICK_INSPECT) {
            return ManagementReadResult.ContractViolation("Operation is not QUICK_INSPECT")
        }
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ManagementReadResult.ContractViolation("QUICK_INSPECT requires exact InstallationTarget")
        val scope = ManagementScope(
            operationId = snapshot.operationId,
            serverId = target.serverId,
            serverAccessId = target.serverAccessId,
            installationId = target.installationId,
        )
        val statusTerminal = snapshot.status in TERMINAL_STATUSES
        val checkpointTerminal = snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
        if (statusTerminal != checkpointTerminal) {
            return ManagementReadResult.ContractViolation(
                "QUICK_INSPECT terminal status/checkpoint semantics disagree",
            )
        }
        if (!statusTerminal) {
            if (snapshot.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
                return ManagementReadResult.ContractViolation(
                    "Nonterminal QUICK_INSPECT checkpoint must remain READ_ONLY",
                )
            }
            return ManagementReadResult.InProgress(
                scope = scope,
                status = snapshot.status,
                phaseName = snapshot.checkpoint.phaseName,
                processNotice = registry.latestNotice(snapshot.operationId),
            )
        }
        if (snapshot.updatedAt != snapshot.checkpoint.recordedAt) {
            return ManagementReadResult.ContractViolation(
                "QUICK_INSPECT terminal completion time must equal terminal checkpoint time",
            )
        }
        val kind = ManagementTerminalKind.fromPhaseName(snapshot.checkpoint.phaseName)
            ?: return ManagementReadResult.ContractViolation("Unknown durable QUICK_INSPECT terminal phase")
        if (snapshot.status != kind.operationStatus) {
            return ManagementReadResult.ContractViolation(
                "Durable QUICK_INSPECT status disagrees with terminal category",
            )
        }

        when (val detail = registry.latestDetail(snapshot.operationId)) {
            is ManagementProcessDetail.Completed -> {
                if (
                    kind != ManagementTerminalKind.RESULT ||
                    detail.committedRevision != current.revision ||
                    detail.snapshot.scope != scope ||
                    detail.snapshot.observedAt.isAfter(snapshot.checkpoint.recordedAt)
                ) {
                    return ManagementReadResult.ContractViolation(
                        "Process-local Management detail disagrees with durable scope/category/revision/time",
                    )
                }
                return ManagementReadResult.Detailed(detail.snapshot)
            }
            is ManagementProcessDetail.ReadbackFailed -> {
                if (kind != ManagementTerminalKind.READBACK_FAILED || detail.committedRevision != current.revision) {
                    return ManagementReadResult.ContractViolation(
                        "Process-local Management failure disagrees with durable category/revision",
                    )
                }
                return ManagementReadResult.DetailedFailure(
                    scope = scope,
                    kind = detail.kind,
                    completedAt = snapshot.checkpoint.recordedAt,
                )
            }
            null -> Unit
        }

        return ManagementReadResult.DurableTerminal(
            ManagementTerminalSummary(
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

internal sealed interface ManagementReadResult {
    data class InProgress(
        val scope: ManagementScope,
        val status: OperationStatus,
        val phaseName: String,
        val processNotice: ManagementProcessNotice?,
    ) : ManagementReadResult

    /** Full live detail (including any fresh InstallationProof) exists only while this process survives. */
    data class Detailed(val snapshot: ManagementLiveSnapshot) : ManagementReadResult

    data class DetailedFailure(
        val scope: ManagementScope,
        val kind: ManagementFailureKind,
        val completedAt: Instant,
    ) : ManagementReadResult

    /** Process-death fallback: only durable category/scope/time, never reconstructed live proof. */
    data class DurableTerminal(val summary: ManagementTerminalSummary) : ManagementReadResult

    data class ContractViolation(val reason: String) : ManagementReadResult
    data class Unavailable(val failure: ManagementReadFailure) : ManagementReadResult
    data object NotFound : ManagementReadResult
}

internal data class ManagementTerminalSummary(
    val scope: ManagementScope,
    val kind: ManagementTerminalKind,
    val completedAt: Instant,
)

internal enum class ManagementReadFailure {
    JOURNAL_CORRUPTION,
    JOURNAL_STORAGE_FAILURE,
}
