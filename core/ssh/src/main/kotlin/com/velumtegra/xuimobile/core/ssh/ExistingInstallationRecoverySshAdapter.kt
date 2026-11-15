package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.ExistingInstallationRecoveryRepairPolicy
import com.velumtegra.xuimobile.core.domain.ExistingInstallationRecoveryRepairPolicyResult
import com.velumtegra.xuimobile.core.domain.ManagementProbeParseResult
import com.velumtegra.xuimobile.core.domain.ManagementProbeParsers
import com.velumtegra.xuimobile.core.domain.ManagementProbeSpec
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationActionPreflight
import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationRecoveryRepair
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ExistingInstallationRecoveryDiagnosis
import com.velumtegra.xuimobile.core.model.ExistingInstallationRecoveryEvidence
import com.velumtegra.xuimobile.core.model.ExistingInstallationRecoveryCapability
import com.velumtegra.xuimobile.core.model.ManagementPathKind
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.XuiInstallation
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** Read-only Phase 9.5 diagnosis. It never writes the journal or dispatches a mutation command. */
class ExistingInstallationRecoveryDiagnosisSshAdapter(
    private val now: () -> Instant = Instant::now,
) {
    suspend fun diagnose(
        preflight: VerifiedExistingInstallationActionPreflight,
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        session: SshSessionHandle,
    ): ExistingInstallationRecoveryDiagnosisResult {
        validate(preflight, current, installation, session)?.let {
            return ExistingInstallationRecoveryDiagnosisResult.Rejected(it)
        }

        val identity = installation.identity
        val presenceProbes = listOf(
            ManagementProbeSpec.ServiceUnitPresence(identity.serviceUnit),
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.BINARY, identity.binaryPath),
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.ROOT, identity.rootPath),
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.DATABASE, identity.databasePath),
        )
        for (probe in presenceProbes) {
            when (executePresence(probe, session)) {
                PresenceVerdict.PRESENT -> Unit
                PresenceVerdict.ABSENT -> return evidenceResult(
                    preflight,
                    ExistingInstallationRecoveryDiagnosis.UNSUPPORTED_OR_CONTRADICTED,
                    ManagementServiceState.UNKNOWN,
                )
                PresenceVerdict.INCOMPLETE -> return evidenceResult(
                    preflight,
                    ExistingInstallationRecoveryDiagnosis.INCOMPLETE,
                    ManagementServiceState.UNKNOWN,
                )
            }
        }

        val serviceState = executeServiceState(
            ManagementProbeSpec.ServiceLiveState(identity.serviceUnit),
            session,
        ) ?: return evidenceResult(
            preflight,
            ExistingInstallationRecoveryDiagnosis.INCOMPLETE,
            ManagementServiceState.UNKNOWN,
        )

        val listener = executePresence(
            ManagementProbeSpec.ExactListenerPresence(
                expectedPort = installation.baseline.panelPort,
                expectedListenAddress = installation.baseline.listenAddress,
            ),
            session,
        )
        if (listener == PresenceVerdict.INCOMPLETE) {
            return evidenceResult(preflight, ExistingInstallationRecoveryDiagnosis.INCOMPLETE, serviceState)
        }

        val diagnosis = when {
            serviceState == ManagementServiceState.ACTIVE && listener == PresenceVerdict.PRESENT ->
                ExistingInstallationRecoveryDiagnosis.HEALTHY
            serviceState == ManagementServiceState.INACTIVE && listener == PresenceVerdict.ABSENT ->
                ExistingInstallationRecoveryDiagnosis.EXACT_SERVICE_INACTIVE_LISTENER_ABSENT
            else -> ExistingInstallationRecoveryDiagnosis.UNSUPPORTED_OR_CONTRADICTED
        }
        return evidenceResult(preflight, diagnosis, serviceState)
    }

    private fun validate(
        preflight: VerifiedExistingInstallationActionPreflight,
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        session: SshSessionHandle,
    ): ExistingInstallationRecoveryDiagnosisFailure? {
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationRecoveryDiagnosisFailure.ScopeTargetMismatch
        if (preflight.authorization.action != OperationType.RECOVERY ||
            preflight.evidence.scope.action != OperationType.RECOVERY ||
            preflight.evidence.scope.operationRevision != current.revision.value ||
            snapshot.type != OperationType.RECOVERY ||
            snapshot.operationId != preflight.authorization.operationId ||
            target.serverId != installation.serverId ||
            target.installationId != installation.id ||
            target.serverAccessId != preflight.evidence.scope.serverAccessId ||
            snapshot.status != OperationStatus.RUNNING ||
            snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED
        ) return ExistingInstallationRecoveryDiagnosisFailure.ScopeTargetMismatch
        if (session.binding.owner != SessionOwner.Operation(snapshot.operationId) ||
            session.binding.serverAccessId != target.serverAccessId
        ) return ExistingInstallationRecoveryDiagnosisFailure.ExactSessionBindingMismatch
        if (!session.isOpen) return ExistingInstallationRecoveryDiagnosisFailure.SessionClosed
        return null
    }

    private suspend fun executePresence(
        probe: ManagementProbeSpec,
        session: SshSessionHandle,
    ): PresenceVerdict {
        currentCoroutineContext().ensureActive()
        val compiled = ManagementReadOnlyCommandCompiler.compile(probe) as? CompiledManagementProbe.Command
            ?: return PresenceVerdict.INCOMPLETE
        val result = session.execute(compiled.command, configFor(probe.timeout))
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.stdout.truncated || result.stderr.truncated) {
            return PresenceVerdict.INCOMPLETE
        }
        return when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> PresenceVerdict.PRESENT
            is CommandCompletion.ConfirmedFailure -> if (completion.exitCode == 1) PresenceVerdict.ABSENT else PresenceVerdict.INCOMPLETE
            is CommandCompletion.Unknown -> PresenceVerdict.INCOMPLETE
        }
    }

    private suspend fun executeServiceState(
        probe: ManagementProbeSpec.ServiceLiveState,
        session: SshSessionHandle,
    ): ManagementServiceState? {
        currentCoroutineContext().ensureActive()
        val compiled = ManagementReadOnlyCommandCompiler.compile(probe) as? CompiledManagementProbe.Command ?: return null
        val result = session.execute(compiled.command, configFor(probe.timeout))
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.stdout.truncated || result.stderr.truncated ||
            result.completion !is CommandCompletion.ConfirmedSuccess
        ) return null
        val raw = strictText(result.stdout) ?: return null
        return when (val parsed = ManagementProbeParsers.parseServiceState(raw)) {
            is ManagementProbeParseResult.Parsed -> parsed.value
            ManagementProbeParseResult.Malformed -> null
        }
    }

    private fun evidenceResult(
        preflight: VerifiedExistingInstallationActionPreflight,
        diagnosis: ExistingInstallationRecoveryDiagnosis,
        serviceState: ManagementServiceState,
    ): ExistingInstallationRecoveryDiagnosisResult.Diagnosed {
        val observed = now()
        val evidence = ExistingInstallationRecoveryEvidence(
            scope = preflight.evidence.scope,
            diagnosis = diagnosis,
            serviceState = serviceState,
            observedAt = observed,
            validUntil = minOf(preflight.evidence.validUntil, observed.plusSeconds(30)),
        )
        return ExistingInstallationRecoveryDiagnosisResult.Diagnosed(
            evidence = evidence,
            repairDecision = ExistingInstallationRecoveryRepairPolicy.authorize(preflight, evidence, observed),
        )
    }

    private fun strictText(output: CapturedOutput): String? {
        val bytes = output.copyBytes()
        return try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: Exception) {
            null
        } finally {
            java.util.Arrays.fill(bytes, 0)
        }
    }

    private fun configFor(timeout: Duration) = SshTransportConfig(
        channelOpenTimeout = timeout.coerceAtMost(Duration.ofSeconds(5)),
        commandExecutionTimeout = timeout,
        stdoutCaptureLimitBytes = 512,
        stderrCaptureLimitBytes = 512,
    )

    private enum class PresenceVerdict { PRESENT, ABSENT, INCOMPLETE }
}

sealed interface ExistingInstallationRecoveryDiagnosisResult {
    data class Diagnosed(
        val evidence: ExistingInstallationRecoveryEvidence,
        val repairDecision: ExistingInstallationRecoveryRepairPolicyResult,
    ) : ExistingInstallationRecoveryDiagnosisResult
    data class Rejected(val failure: ExistingInstallationRecoveryDiagnosisFailure) : ExistingInstallationRecoveryDiagnosisResult
}

enum class ExistingInstallationRecoveryDiagnosisFailure {
    ScopeTargetMismatch,
    ExactSessionBindingMismatch,
    SessionClosed,
}

/** Phase 9.5 one-shot exact repair dispatcher. MUTATION_IN_FLIGHT is durable before first write. */
class ExistingInstallationRecoveryRepairSshAdapter(
    private val journal: OperationJournal,
    private val now: () -> Instant = Instant::now,
) {
    suspend fun dispatch(
        repair: VerifiedExistingInstallationRecoveryRepair,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationRecoveryRepairResult {
        validate(repair, current, session)?.let { return ExistingInstallationRecoveryRepairResult.Rejected(it) }
        currentCoroutineContext().ensureActive()
        val checkpointed = advanceMutationInFlight(current)
            ?: return ExistingInstallationRecoveryRepairResult.Rejected(
                ExistingInstallationRecoveryRepairFailure.PredispatchCheckpointRejected,
            )
        val compiled = ExistingInstallationRecoveryCommandCompiler.compile(repair)
            ?: return requireReconciliation(checkpointed, ExistingInstallationRecoveryReconciliationReason.PLAN_COMPILATION_REJECTED_AFTER_CHECKPOINT)

        currentCoroutineContext().ensureActive()
        val result = session.execute(compiled.command, compiled.config)
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED) {
            return requireReconciliation(checkpointed, ExistingInstallationRecoveryReconciliationReason.DISPATCH_NOT_CONFIRMED)
        }
        return when (result.completion) {
            CommandCompletion.ConfirmedSuccess -> ExistingInstallationRecoveryRepairResult.PostVerifyRequired(checkpointed)
            is CommandCompletion.ConfirmedFailure -> requireReconciliation(
                checkpointed,
                ExistingInstallationRecoveryReconciliationReason.REMOTE_REPAIR_FAILED_AFTER_DISPATCH,
            )
            is CommandCompletion.Unknown -> requireReconciliation(
                checkpointed,
                ExistingInstallationRecoveryReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
            )
        }
    }

    private fun validate(
        repair: VerifiedExistingInstallationRecoveryRepair,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationRecoveryRepairFailure? {
        if (!ExistingInstallationRecoveryRepairPolicy.isCanonical(repair.plan) ||
            repair.evidence.diagnosis != ExistingInstallationRecoveryDiagnosis.EXACT_SERVICE_INACTIVE_LISTENER_ABSENT ||
            repair.preflight.evidence.scope != repair.plan.scope
        ) return ExistingInstallationRecoveryRepairFailure.PlanOutsideApprovedPolicy
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationRecoveryRepairFailure.ScopeTargetMismatch
        if (snapshot.type != OperationType.RECOVERY ||
            snapshot.operationId != repair.plan.scope.operationId ||
            current.revision.value != repair.plan.scope.operationRevision ||
            target.serverId != repair.plan.scope.serverId ||
            target.serverAccessId != repair.plan.scope.serverAccessId ||
            target.installationId != repair.plan.scope.installationId ||
            snapshot.status != OperationStatus.RUNNING
        ) return ExistingInstallationRecoveryRepairFailure.ScopeTargetMismatch
        if (snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return ExistingInstallationRecoveryRepairFailure.NotAtPredispatchCheckpoint
        }
        if (session.binding.owner != SessionOwner.Operation(snapshot.operationId) ||
            session.binding.serverAccessId != target.serverAccessId
        ) return ExistingInstallationRecoveryRepairFailure.ExactSessionBindingMismatch
        if (!session.isOpen) return ExistingInstallationRecoveryRepairFailure.SessionClosed
        return null
    }

    private suspend fun advanceMutationInFlight(current: VersionedOperationSnapshot): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = "RECOVERY_REPAIR_DISPATCHED",
                semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> advanced.value
            else -> null
        }
    }

    private suspend fun requireReconciliation(
        current: VersionedOperationSnapshot,
        reason: ExistingInstallationRecoveryReconciliationReason,
    ): ExistingInstallationRecoveryRepairResult.ReconciliationRequired {
        val at = now()
        val next = if (at.isBefore(current.snapshot.updatedAt)) null else current.snapshot.copy(
            status = OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint = OperationCheckpoint(
                phaseName = "RECOVERY_RECONCILIATION_REQUIRED",
                semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        val recorded = if (next == null) null else when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> advanced.value
            else -> null
        }
        return ExistingInstallationRecoveryRepairResult.ReconciliationRequired(
            durable = recorded ?: current,
            reason = reason,
            reconciliationCheckpointRecorded = recorded != null,
        )
    }
}

sealed interface ExistingInstallationRecoveryRepairResult {
    data class PostVerifyRequired(val durable: VersionedOperationSnapshot) : ExistingInstallationRecoveryRepairResult
    data class Rejected(val failure: ExistingInstallationRecoveryRepairFailure) : ExistingInstallationRecoveryRepairResult
    data class ReconciliationRequired(
        val durable: VersionedOperationSnapshot,
        val reason: ExistingInstallationRecoveryReconciliationReason,
        val reconciliationCheckpointRecorded: Boolean,
    ) : ExistingInstallationRecoveryRepairResult
}

enum class ExistingInstallationRecoveryRepairFailure {
    PlanOutsideApprovedPolicy,
    ScopeTargetMismatch,
    NotAtPredispatchCheckpoint,
    ExactSessionBindingMismatch,
    SessionClosed,
    PredispatchCheckpointRejected,
}

enum class ExistingInstallationRecoveryReconciliationReason {
    PLAN_COMPILATION_REJECTED_AFTER_CHECKPOINT,
    DISPATCH_NOT_CONFIRMED,
    REMOTE_REPAIR_FAILED_AFTER_DISPATCH,
    TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
}

internal data class CompiledExistingInstallationRecoveryRepair(
    val command: RemoteCommand,
    val config: SshTransportConfig,
)

internal object ExistingInstallationRecoveryCommandCompiler {
    const val STANDARD_3X_UI_SERVICE_UNIT: String = "x-ui.service"

    fun compile(repair: VerifiedExistingInstallationRecoveryRepair): CompiledExistingInstallationRecoveryRepair? {
        if (!ExistingInstallationRecoveryRepairPolicy.isCanonical(repair.plan) ||
            repair.plan.capability != ExistingInstallationRecoveryCapability.SYSTEMD_START_EXACT_SERVICE_V1 ||
            repair.evidence.diagnosis != ExistingInstallationRecoveryDiagnosis.EXACT_SERVICE_INACTIVE_LISTENER_ABSENT ||
            repair.preflight.evidence.installationProof.observedIdentity.serviceUnit != STANDARD_3X_UI_SERVICE_UNIT
        ) return null
        val raw = "systemctl start $STANDARD_3X_UI_SERVICE_UNIT"
        return CompiledExistingInstallationRecoveryRepair(
            command = RemoteCommand.create(raw, "phase9-recovery-start-exact-service"),
            config = SshTransportConfig(
                channelOpenTimeout = repair.plan.timeout.coerceAtMost(Duration.ofSeconds(5)),
                commandExecutionTimeout = repair.plan.timeout,
                stdoutCaptureLimitBytes = 512,
                stderrCaptureLimitBytes = 512,
            ),
        )
    }
}
