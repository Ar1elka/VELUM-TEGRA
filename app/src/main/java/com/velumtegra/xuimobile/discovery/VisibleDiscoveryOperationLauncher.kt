package com.velumtegra.xuimobile.discovery

import android.app.Activity
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.runtime.ExactOperationHostStartResult
import com.velumtegra.xuimobile.runtime.VisibleExactOperationHostLauncher
import java.time.Instant
import java.util.UUID

/**
 * Explicit visible-user entry boundary for one exact read-only Discovery operation.
 *
 * Durable truth is created before Android is asked to start the host, so the Service can only bind
 * an OperationId that already exists in OperationJournal. The exact ServerId/ServerAccessId pair is
 * immutable inside OperationTarget.ServerTarget; there is no list/latest/fallback lookup here.
 *
 * Android start acceptance is deliberately not treated as remote-operation success. If Android
 * rejects the visible host start, the exact nonterminal operation remains durable and the caller may
 * retry only that same OperationId through [resume].
 */
internal class VisibleDiscoveryOperationLauncher(
    private val journal: OperationJournal,
    private val hostStart: DiscoveryHostStartPort,
    private val resultRegistry: DiscoveryResultRegistry = DiscoveryResultRegistry(),
    private val now: () -> Instant = Instant::now,
    private val operationIdFactory: () -> OperationId = {
        OperationId(UUID.randomUUID().toString())
    },
) {
    constructor(
        activity: Activity,
        journal: OperationJournal,
        resultRegistry: DiscoveryResultRegistry,
    ) : this(
        journal = journal,
        hostStart = DiscoveryHostStartPort { operationId ->
            VisibleExactOperationHostLauncher(activity).start(operationId)
        },
        resultRegistry = resultRegistry,
    )

    suspend fun start(
        serverId: ServerId,
        serverAccessId: ServerAccessId,
    ): DiscoveryOperationStartResult {
        val operationId = operationIdFactory()
        if (operationId.value.isBlank()) {
            return DiscoveryOperationStartResult.ContractViolation(
                "Discovery OperationId factory returned a blank id",
            )
        }
        val startedAt = now()
        val scope = DiscoveryScope(
            operationId = operationId,
            serverId = serverId,
            serverAccessId = serverAccessId,
        )
        val initial = OperationSnapshot(
            operationId = operationId,
            type = OperationType.DISCOVERY,
            target = OperationTarget.ServerTarget(serverId, serverAccessId),
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = "DISCOVER",
                semantics = CheckpointSemantics.READ_ONLY,
                recordedAt = startedAt,
            ),
            startedAt = startedAt,
            updatedAt = startedAt,
        )

        val created = when (val result = journal.create(initial)) {
            is OperationJournalResult.Success -> result.value
            OperationJournalResult.AlreadyExists -> {
                return DiscoveryOperationStartResult.OperationIdCollision(operationId)
            }
            is OperationJournalResult.InvalidTransition -> {
                return DiscoveryOperationStartResult.ContractViolation(result.reason)
            }
            is OperationJournalResult.Corruption -> {
                return DiscoveryOperationStartResult.JournalFailure(
                    DiscoveryOperationJournalFailureKind.CORRUPTION,
                    result.reason,
                )
            }
            is OperationJournalResult.StorageFailure -> {
                return DiscoveryOperationStartResult.JournalFailure(
                    DiscoveryOperationJournalFailureKind.STORAGE,
                    result.reason,
                )
            }
            else -> {
                return DiscoveryOperationStartResult.ContractViolation(
                    "Discovery OperationJournal create returned ${result::class.simpleName}",
                )
            }
        }

        resultRegistry.beginAttempt(operationId)
        return when (val platform = hostStart.start(operationId)) {
            ExactOperationHostStartResult.START_REQUEST_ACCEPTED -> DiscoveryOperationStartResult.Started(
                scope = scope,
                revision = created.revision,
            )
            else -> {
                resultRegistry.publishNotice(operationId, DiscoveryProcessNotice.HostStartRejected)
                DiscoveryOperationStartResult.HostStartNotAccepted(
                    scope = scope,
                    revision = created.revision,
                    reason = platform,
                )
            }
        }
    }

    /**
     * Retry only the exact already-created nonterminal Discovery OperationId.
     *
     * Durable truth is re-read before Android is touched, so this narrow Discovery entry API cannot
     * be abused to launch an arbitrary/non-Discovery OperationId. Target/access identity is never
     * replaced or reselected.
     */
    suspend fun resume(operationId: OperationId): DiscoveryOperationResumeResult {
        if (operationId.value.isBlank()) {
            return DiscoveryOperationResumeResult.InvalidOperationId
        }
        val current = when (val read = journal.get(operationId)) {
            is OperationJournalResult.Success -> read.value.snapshot
            OperationJournalResult.NotFound -> return DiscoveryOperationResumeResult.NotFound
            is OperationJournalResult.Corruption -> {
                return DiscoveryOperationResumeResult.JournalFailure(
                    DiscoveryOperationJournalFailureKind.CORRUPTION,
                    read.reason,
                )
            }
            is OperationJournalResult.StorageFailure -> {
                return DiscoveryOperationResumeResult.JournalFailure(
                    DiscoveryOperationJournalFailureKind.STORAGE,
                    read.reason,
                )
            }
            else -> {
                return DiscoveryOperationResumeResult.ContractViolation(
                    "Discovery OperationJournal get returned ${read::class.simpleName}",
                )
            }
        }
        if (current.type != OperationType.DISCOVERY || current.target !is OperationTarget.ServerTarget) {
            return DiscoveryOperationResumeResult.NotRelaunchable(
                DiscoveryOperationRelaunchBlock.NOT_DISCOVERY_CONTRACT,
            )
        }
        if (current.status in TERMINAL_STATUSES || current.checkpoint.semantics == CheckpointSemantics.TERMINAL) {
            return DiscoveryOperationResumeResult.NotRelaunchable(
                DiscoveryOperationRelaunchBlock.TERMINAL,
            )
        }
        if (current.checkpoint.semantics != CheckpointSemantics.READ_ONLY) {
            return DiscoveryOperationResumeResult.NotRelaunchable(
                DiscoveryOperationRelaunchBlock.NOT_DISCOVERY_CONTRACT,
            )
        }

        resultRegistry.beginAttempt(operationId)
        return when (val platform = hostStart.start(operationId)) {
            ExactOperationHostStartResult.START_REQUEST_ACCEPTED -> DiscoveryOperationResumeResult.StartRequestAccepted
            else -> {
                resultRegistry.publishNotice(operationId, DiscoveryProcessNotice.HostStartRejected)
                DiscoveryOperationResumeResult.HostStartNotAccepted(platform)
            }
        }
    }

    private companion object {
        val TERMINAL_STATUSES = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}

internal fun interface DiscoveryHostStartPort {
    fun start(operationId: OperationId): ExactOperationHostStartResult
}

internal enum class DiscoveryOperationJournalFailureKind {
    CORRUPTION,
    STORAGE,
}

internal sealed interface DiscoveryOperationStartResult {
    data class Started(
        val scope: DiscoveryScope,
        val revision: OperationRevision,
    ) : DiscoveryOperationStartResult

    data class HostStartNotAccepted(
        val scope: DiscoveryScope,
        val revision: OperationRevision,
        val reason: ExactOperationHostStartResult,
    ) : DiscoveryOperationStartResult

    data class OperationIdCollision(val operationId: OperationId) : DiscoveryOperationStartResult

    data class JournalFailure(
        val kind: DiscoveryOperationJournalFailureKind,
        val reason: String,
    ) : DiscoveryOperationStartResult

    data class ContractViolation(val reason: String) : DiscoveryOperationStartResult
}

internal enum class DiscoveryOperationRelaunchBlock {
    TERMINAL,
    NOT_DISCOVERY_CONTRACT,
}

internal sealed interface DiscoveryOperationResumeResult {
    data object StartRequestAccepted : DiscoveryOperationResumeResult
    data class HostStartNotAccepted(
        val reason: ExactOperationHostStartResult,
    ) : DiscoveryOperationResumeResult
    data class NotRelaunchable(val block: DiscoveryOperationRelaunchBlock) : DiscoveryOperationResumeResult
    data class JournalFailure(
        val kind: DiscoveryOperationJournalFailureKind,
        val reason: String,
    ) : DiscoveryOperationResumeResult
    data class ContractViolation(val reason: String) : DiscoveryOperationResumeResult
    data object NotFound : DiscoveryOperationResumeResult
    data object InvalidOperationId : DiscoveryOperationResumeResult
}
