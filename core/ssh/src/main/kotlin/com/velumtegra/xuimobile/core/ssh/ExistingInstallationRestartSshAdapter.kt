package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.ManagedInstallMarkerProtocol
import com.velumtegra.xuimobile.core.domain.ExistingInstallationActionAuthorizationPolicy
import com.velumtegra.xuimobile.core.domain.ExistingInstallationActionAuthorizationResult
import com.velumtegra.xuimobile.core.domain.ExistingInstallationActionPreflightPolicy
import com.velumtegra.xuimobile.core.domain.ExistingInstallationActionPreflightResult
import com.velumtegra.xuimobile.core.domain.TargetProofPolicy
import com.velumtegra.xuimobile.core.domain.TargetVerificationResult
import com.velumtegra.xuimobile.core.domain.ManagementProbeParseResult
import com.velumtegra.xuimobile.core.domain.ManagementProbeParsers
import com.velumtegra.xuimobile.core.domain.ManagementProbeSpec
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.ReviewedExistingInstallationActionPlanPolicy
import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationActionPreflight
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.ExistingInstallationServiceAction
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ExistingInstallationAccessPathState
import com.velumtegra.xuimobile.core.model.ExistingInstallationActionScope
import com.velumtegra.xuimobile.core.model.ExistingInstallationMutationBarrierState
import com.velumtegra.xuimobile.core.model.ExistingInstallationPreflightEvidence
import com.velumtegra.xuimobile.core.model.InstallationProof
import com.velumtegra.xuimobile.core.model.ExistingInstallationActionPlanStep
import com.velumtegra.xuimobile.core.model.ExistingInstallationLayoutCapability
import com.velumtegra.xuimobile.core.model.ExistingInstallationPrivilegeCapability
import com.velumtegra.xuimobile.core.model.ExistingInstallationRemoteCapability
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.ManagementPathKind
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ReviewedExistingInstallationActionPlan
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import java.util.UUID
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/**
 * Phase 9.4 one-shot exact RESTART dispatcher.
 *
 * It consumes only one already-open exact operation-owned SSH session. RESTART_IN_FLIGHT is durable
 * before command dispatch. The adapter never reconnects and never retries the command. Even a
 * confirmed command success means only that the caller must close/reconnect through the existing
 * Phase 4 machinery before read-only post-verification may create success.
 */
class ExistingInstallationRestartSshAdapter(
    private val journal: OperationJournal,
    private val now: () -> Instant = Instant::now,
) {
    suspend fun dispatch(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: ReviewedExistingInstallationActionPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationRestartDispatchResult {
        validateBeforeCheckpoint(preflight, plan, current, session)?.let {
            return ExistingInstallationRestartDispatchResult.Rejected(it)
        }

        currentCoroutineContext().ensureActive()
        val action = ExistingInstallationServiceAction.fromPhaseName(current.snapshot.checkpoint.phaseName)
        val xrayBefore = if (action == ExistingInstallationServiceAction.XRAY_RESTART) {
            if (!XuiExtendedServiceReadback.hasOfficialReload(session)) return rejectXrayBeforeDispatch(current)
            XuiExtendedServiceReadback.readXray(session) ?: return rejectXrayBeforeDispatch(current)
        } else null
        currentCoroutineContext().ensureActive()
        val checkpointed = advanceRestartInFlight(current, xrayBefore?.evidence)
            ?: return ExistingInstallationRestartDispatchResult.Rejected(
                ExistingInstallationRestartDispatchFailure.PredispatchCheckpointRejected,
            )

        val compiled = ExistingInstallationRestartCommandCompiler.compile(preflight, plan, action)
            ?: return requireReconciliation(
                checkpointed,
                ExistingInstallationRestartReconciliationReason.PLAN_COMPILATION_REJECTED_AFTER_CHECKPOINT,
            )

        currentCoroutineContext().ensureActive()
        val result = session.execute(compiled.command, compiled.config)
        currentCoroutineContext().ensureActive()

        if (result.dispatchState != CommandDispatchState.DISPATCHED) {
            return requireReconciliation(
                checkpointed,
                ExistingInstallationRestartReconciliationReason.DISPATCH_NOT_CONFIRMED,
            )
        }

        return when (result.completion) {
            CommandCompletion.ConfirmedSuccess -> ExistingInstallationRestartDispatchResult.ReconnectRequired(
                durable = checkpointed,
            )

            is CommandCompletion.ConfirmedFailure -> requireReconciliation(
                checkpointed,
                ExistingInstallationRestartReconciliationReason.REMOTE_RESTART_FAILED_AFTER_DISPATCH,
            )

            is CommandCompletion.Unknown -> requireReconciliation(
                checkpointed,
                ExistingInstallationRestartReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
            )
        }
    }

    private fun validateBeforeCheckpoint(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: ReviewedExistingInstallationActionPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationRestartDispatchFailure? {
        if (!ReviewedExistingInstallationActionPlanPolicy.isCanonical(plan) ||
            plan.scope.action != OperationType.RESTART ||
            preflight.authorization.action != OperationType.RESTART ||
            preflight.evidence.scope != plan.scope ||
            preflight.evidence.layoutCapability != ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1 ||
            preflight.evidence.privilegeCapability != ExistingInstallationPrivilegeCapability.DIRECT_ROOT
        ) {
            return ExistingInstallationRestartDispatchFailure.PlanOutsideApprovedPolicy
        }
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationRestartDispatchFailure.ScopeTargetMismatch
        if (snapshot.type != OperationType.RESTART ||
            snapshot.operationId != plan.scope.operationId ||
            current.revision.value != plan.scope.operationRevision ||
            target.serverId != plan.scope.serverId ||
            target.serverAccessId != plan.scope.serverAccessId ||
            target.installationId != plan.scope.installationId ||
            snapshot.status != OperationStatus.RUNNING
        ) {
            return ExistingInstallationRestartDispatchFailure.ScopeTargetMismatch
        }
        if (snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return ExistingInstallationRestartDispatchFailure.NotAtPredispatchCheckpoint
        }
        if (session.binding.owner != SessionOwner.Operation(plan.scope.operationId) ||
            session.binding.serverAccessId != plan.scope.serverAccessId
        ) {
            return ExistingInstallationRestartDispatchFailure.ExactSessionBindingMismatch
        }
        if (!session.isOpen) return ExistingInstallationRestartDispatchFailure.SessionClosed
        return null
    }

    private suspend fun rejectXrayBeforeDispatch(
        current: VersionedOperationSnapshot,
    ): ExistingInstallationRestartDispatchResult.Rejected {
        val at = now()
        if (!at.isBefore(current.snapshot.updatedAt)) {
            val next = current.snapshot.copy(
                status = OperationStatus.FAILED,
                checkpoint = OperationCheckpoint(
                    current.servicePhaseName("RESTART_PREFLIGHT_XRAY_RELOAD_UNCONFIRMED"),
                    CheckpointSemantics.TERMINAL,
                    at,
                ),
                updatedAt = at,
            )
            journal.advance(current.snapshot.operationId, current.revision, next)
        }
        return ExistingInstallationRestartDispatchResult.Rejected(
            ExistingInstallationRestartDispatchFailure.PredispatchCheckpointRejected,
        )
    }

    private suspend fun advanceRestartInFlight(
        current: VersionedOperationSnapshot,
        xrayEvidence: String?,
    ): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = current.servicePhaseName("RESTART_DISPATCHED") + (xrayEvidence?.let { "#$it" } ?: ""),
                semantics = CheckpointSemantics.RESTART_IN_FLIGHT,
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
        reason: ExistingInstallationRestartReconciliationReason,
    ): ExistingInstallationRestartDispatchResult.ReconciliationRequired {
        val at = now()
        val next = if (at.isBefore(current.snapshot.updatedAt)) {
            null
        } else {
            current.snapshot.copy(
                status = OperationStatus.RECONCILIATION_REQUIRED,
                checkpoint = OperationCheckpoint(
                    phaseName = current.servicePhaseName("RESTART_RECONCILIATION_REQUIRED"),
                    semantics = CheckpointSemantics.RESTART_IN_FLIGHT,
                    recordedAt = at,
                ),
                updatedAt = at,
            )
        }
        val recorded = if (next == null) {
            null
        } else {
            when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
                is OperationJournalResult.Success -> advanced.value
                else -> null
            }
        }
        return ExistingInstallationRestartDispatchResult.ReconciliationRequired(
            durable = recorded ?: current,
            reason = reason,
            reconciliationCheckpointRecorded = recorded != null,
        )
    }
}

sealed interface ExistingInstallationRestartDispatchResult {
    /** Restart command completed, but success is impossible until exact reconnect + read-only verify. */
    data class ReconnectRequired(
        val durable: VersionedOperationSnapshot,
    ) : ExistingInstallationRestartDispatchResult

    data class Rejected(
        val failure: ExistingInstallationRestartDispatchFailure,
    ) : ExistingInstallationRestartDispatchResult

    data class ReconciliationRequired(
        val durable: VersionedOperationSnapshot,
        val reason: ExistingInstallationRestartReconciliationReason,
        val reconciliationCheckpointRecorded: Boolean,
    ) : ExistingInstallationRestartDispatchResult
}

enum class ExistingInstallationRestartDispatchFailure {
    PlanOutsideApprovedPolicy,
    ScopeTargetMismatch,
    NotAtPredispatchCheckpoint,
    ExactSessionBindingMismatch,
    SessionClosed,
    PredispatchCheckpointRejected,
}

enum class ExistingInstallationRestartReconciliationReason {
    PLAN_COMPILATION_REJECTED_AFTER_CHECKPOINT,
    DISPATCH_NOT_CONFIRMED,
    REMOTE_RESTART_FAILED_AFTER_DISPATCH,
    TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
}

internal data class CompiledExistingInstallationRestart(
    val command: RemoteCommand,
    val config: SshTransportConfig,
)

internal object ExistingInstallationRestartCommandCompiler {
    const val STANDARD_3X_UI_SERVICE_UNIT: String = "x-ui.service"
    private val maxChannelOpenTimeout = Duration.ofSeconds(5)

    fun compile(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: ReviewedExistingInstallationActionPlan,
        action: ExistingInstallationServiceAction = ExistingInstallationServiceAction.RESTART,
    ): CompiledExistingInstallationRestart? {
        if (!ReviewedExistingInstallationActionPlanPolicy.isCanonical(plan) ||
            plan.scope.action != OperationType.RESTART ||
            preflight.evidence.scope != plan.scope ||
            preflight.evidence.layoutCapability != ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1 ||
            preflight.evidence.privilegeCapability != ExistingInstallationPrivilegeCapability.DIRECT_ROOT
        ) {
            return null
        }
        val restart = plan.steps.firstOrNull() as? ExistingInstallationActionPlanStep.RestartExactService
            ?: return null
        if (restart.capability != ExistingInstallationRemoteCapability.SYSTEMD_RESTART_EXACT_SERVICE_V1) {
            return null
        }
        val identity = preflight.evidence.installationProof.observedIdentity
        if (identity.serviceUnit != STANDARD_3X_UI_SERVICE_UNIT) return null
        val subcommand = when (action) {
            ExistingInstallationServiceAction.START -> "start"
            ExistingInstallationServiceAction.STOP -> "stop"
            ExistingInstallationServiceAction.RESTART -> "restart"
            ExistingInstallationServiceAction.XRAY_RESTART -> "reload"
            ExistingInstallationServiceAction.ENABLE_AUTOSTART -> "enable"
            ExistingInstallationServiceAction.DISABLE_AUTOSTART -> "disable"
        }
        val raw = "systemctl $subcommand $STANDARD_3X_UI_SERVICE_UNIT"
        return CompiledExistingInstallationRestart(
            command = RemoteCommand.create(raw, "phase9-restart-exact-service"),
            config = SshTransportConfig(
                channelOpenTimeout = restart.timeout.coerceAtMost(maxChannelOpenTimeout),
                commandExecutionTimeout = restart.timeout,
                stdoutCaptureLimitBytes = 512,
                stderrCaptureLimitBytes = 512,
            ),
        )
    }
}

/**
 * Phase 9.4 read-only post-reconnect verifier for the exact RESTART plan.
 *
 * No journal writes occur here. The runtime layer decides whether verified evidence may be locally
 * committed. The verifier checks exactly identity + service active + expected listener and, for a
 * MANAGED installation, the already-canonical Phase 8 managed-install marker.
 */
class ExistingInstallationRestartPostVerifySshAdapter(
    private val expectedAction: OperationType = OperationType.RESTART,
    private val now: () -> Instant = Instant::now,
) {
    init {
        require(expectedAction == OperationType.RESTART || expectedAction == OperationType.RECOVERY) {
            "Existing-installation post-verify supports only RESTART or RECOVERY"
        }
    }
    suspend fun verify(
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        session: SshSessionHandle,
    ): ExistingInstallationRestartPostVerifyResult {
        validateScope(current, installation, session)?.let {
            return ExistingInstallationRestartPostVerifyResult.Rejected(it)
        }

        val phase = current.snapshot.checkpoint.phaseName
        val action = if (expectedAction == OperationType.RESTART) ExistingInstallationServiceAction.fromPhaseName(phase)
            else ExistingInstallationServiceAction.RESTART
        val stopped = action == ExistingInstallationServiceAction.STOP
        val autostart = action.autostartState
        val expectedService = if (stopped) ManagementServiceState.INACTIVE else ManagementServiceState.ACTIVE
        val identity = installation.identity
        val probes = listOf(
            ManagementProbeSpec.ServiceUnitPresence(identity.serviceUnit),
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.BINARY, identity.binaryPath),
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.ROOT, identity.rootPath),
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.DATABASE, identity.databasePath),
        ) + if (autostart != null) emptyList() else listOf(
            ManagementProbeSpec.ServiceLiveState(identity.serviceUnit),
            ManagementProbeSpec.ExactListenerPresence(
                expectedPort = installation.baseline.panelPort,
                expectedListenAddress = if (stopped) null else installation.baseline.listenAddress,
            ),
        )

        for (probe in probes) {
            currentCoroutineContext().ensureActive()
            val compiled = ManagementReadOnlyCommandCompiler.compile(probe)
                as? CompiledManagementProbe.Command
                ?: return ExistingInstallationRestartPostVerifyResult.Incomplete(
                    ExistingInstallationRestartPostVerifyReason.PROBE_COMPILATION_REJECTED,
                )
            val result = session.execute(compiled.command, configFor(probe.timeout))
            currentCoroutineContext().ensureActive()
            when (classifyProbe(probe, result, expectedService)) {
                ProbeVerdict.Verified -> Unit
                ProbeVerdict.Contradicted -> {
                    return ExistingInstallationRestartPostVerifyResult.Contradicted(
                        reasonFor(probe, stopped),
                    )
                }
                ProbeVerdict.Incomplete -> {
                    return ExistingInstallationRestartPostVerifyResult.Incomplete(
                        ExistingInstallationRestartPostVerifyReason.READ_ONLY_PROBE_INCOMPLETE,
                    )
                }
            }
        }

        identity.managedInstallId?.let { managedId ->
            currentCoroutineContext().ensureActive()
            val marker = readManagedMarker(managedId, session)
            currentCoroutineContext().ensureActive()
            when (marker) {
                ManagedInstallMarkerReadbackState.MATCH -> Unit
                ManagedInstallMarkerReadbackState.ABSENT -> {
                    return ExistingInstallationRestartPostVerifyResult.Contradicted(
                        ExistingInstallationRestartPostVerifyReason.MANAGED_MARKER_ABSENT,
                    )
                }
                ManagedInstallMarkerReadbackState.MISMATCH -> {
                    return ExistingInstallationRestartPostVerifyResult.Contradicted(
                        ExistingInstallationRestartPostVerifyReason.MANAGED_MARKER_MISMATCH,
                    )
                }
                ManagedInstallMarkerReadbackState.MALFORMED -> {
                    return ExistingInstallationRestartPostVerifyResult.Incomplete(
                        ExistingInstallationRestartPostVerifyReason.MANAGED_MARKER_MALFORMED,
                    )
                }
            }
        }

        if (autostart != null) {
            val observed = XuiExtendedServiceReadback.readAutostart(session)
                ?: return ExistingInstallationRestartPostVerifyResult.Incomplete(
                    ExistingInstallationRestartPostVerifyReason.READ_ONLY_PROBE_INCOMPLETE,
                )
            if (observed != autostart) return ExistingInstallationRestartPostVerifyResult.Contradicted(
                ExistingInstallationRestartPostVerifyReason.AUTOSTART_STATE_MISMATCH,
            )
        }
        if (action == ExistingInstallationServiceAction.XRAY_RESTART) {
            val before = phase.substringAfter('#', "").split(':')
            val observed = XuiExtendedServiceReadback.readXray(session)
            if (observed == null || before.size != 2 || before.any { !it.matches(Regex("[0-9a-f]{32}")) }) {
                return ExistingInstallationRestartPostVerifyResult.Incomplete(
                    ExistingInstallationRestartPostVerifyReason.READ_ONLY_PROBE_INCOMPLETE,
                )
            }
            if (observed.panel != before[0] || observed.xray == before[1]) {
                return ExistingInstallationRestartPostVerifyResult.Contradicted(
                    ExistingInstallationRestartPostVerifyReason.XRAY_RESTART_NOT_OBSERVED,
                )
            }
        }
        return ExistingInstallationRestartPostVerifyResult.Verified(now())
    }

    private fun validateScope(
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        session: SshSessionHandle,
    ): ExistingInstallationRestartPostVerifyFailure? {
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationRestartPostVerifyFailure.ScopeTargetMismatch
        if (snapshot.type != expectedAction ||
            target.installationId != installation.id ||
            target.serverId != installation.serverId ||
            snapshot.checkpoint.semantics != CheckpointSemantics.POST_VERIFY_REQUIRED ||
            snapshot.status !in setOf(OperationStatus.RUNNING, OperationStatus.RECONCILIATION_REQUIRED)
        ) {
            return ExistingInstallationRestartPostVerifyFailure.ScopeTargetMismatch
        }
        if (session.binding.owner != SessionOwner.Operation(snapshot.operationId) ||
            session.binding.serverAccessId != target.serverAccessId
        ) {
            return ExistingInstallationRestartPostVerifyFailure.ExactSessionBindingMismatch
        }
        if (!session.isOpen) return ExistingInstallationRestartPostVerifyFailure.SessionClosed
        return null
    }

    private fun classifyProbe(
        probe: ManagementProbeSpec,
        result: SshCommandResult,
        expectedService: ManagementServiceState,
    ): ProbeVerdict {
        if (result.stdout.truncated || result.stderr.truncated || result.dispatchState != CommandDispatchState.DISPATCHED) {
            return ProbeVerdict.Incomplete
        }
        return when (probe) {
            is ManagementProbeSpec.ServiceUnitPresence,
            is ManagementProbeSpec.ExactPathPresence,
            -> when (val completion = result.completion) {
                CommandCompletion.ConfirmedSuccess -> ProbeVerdict.Verified
                is CommandCompletion.ConfirmedFailure -> if (completion.exitCode == 1) {
                    ProbeVerdict.Contradicted
                } else {
                    ProbeVerdict.Incomplete
                }
                is CommandCompletion.Unknown -> ProbeVerdict.Incomplete
            }

            is ManagementProbeSpec.ExactListenerPresence -> when (val completion = result.completion) {
                CommandCompletion.ConfirmedSuccess -> if (expectedService == ManagementServiceState.ACTIVE) {
                    ProbeVerdict.Verified
                } else ProbeVerdict.Contradicted
                is CommandCompletion.ConfirmedFailure -> when {
                    completion.exitCode != 1 -> ProbeVerdict.Incomplete
                    expectedService == ManagementServiceState.INACTIVE -> ProbeVerdict.Verified
                    else -> ProbeVerdict.Contradicted
                }
                is CommandCompletion.Unknown -> ProbeVerdict.Incomplete
            }

            is ManagementProbeSpec.ServiceLiveState -> when (result.completion) {
                CommandCompletion.ConfirmedSuccess -> {
                    val raw = strictText(result.stdout) ?: return ProbeVerdict.Incomplete
                    when (val parsed = ManagementProbeParsers.parseServiceState(raw)) {
                        is ManagementProbeParseResult.Parsed -> if (parsed.value == expectedService) {
                            ProbeVerdict.Verified
                        } else {
                            ProbeVerdict.Contradicted
                        }
                        ManagementProbeParseResult.Malformed -> ProbeVerdict.Incomplete
                    }
                }
                is CommandCompletion.ConfirmedFailure,
                is CommandCompletion.Unknown,
                -> ProbeVerdict.Incomplete
            }

            else -> ProbeVerdict.Incomplete
        }
    }

    private fun reasonFor(probe: ManagementProbeSpec, stopped: Boolean): ExistingInstallationRestartPostVerifyReason = when (probe) {
        is ManagementProbeSpec.ServiceUnitPresence -> ExistingInstallationRestartPostVerifyReason.SERVICE_UNIT_ABSENT
        is ManagementProbeSpec.ExactPathPresence -> when (probe.pathKind) {
            ManagementPathKind.BINARY -> ExistingInstallationRestartPostVerifyReason.BINARY_PATH_ABSENT
            ManagementPathKind.ROOT -> ExistingInstallationRestartPostVerifyReason.ROOT_PATH_ABSENT
            ManagementPathKind.DATABASE -> ExistingInstallationRestartPostVerifyReason.DATABASE_PATH_ABSENT
        }
        is ManagementProbeSpec.ServiceLiveState -> if (stopped) ExistingInstallationRestartPostVerifyReason.SERVICE_NOT_INACTIVE
            else ExistingInstallationRestartPostVerifyReason.SERVICE_NOT_ACTIVE
        is ManagementProbeSpec.ExactListenerPresence -> if (stopped) ExistingInstallationRestartPostVerifyReason.LISTENER_STILL_PRESENT
            else ExistingInstallationRestartPostVerifyReason.EXPECTED_LISTENER_ABSENT
        else -> ExistingInstallationRestartPostVerifyReason.READ_ONLY_PROBE_INCOMPLETE
    }

    private suspend fun readManagedMarker(
        expected: com.velumtegra.xuimobile.core.model.ManagedInstallId,
        session: SshSessionHandle,
    ): ManagedInstallMarkerReadbackState {
        val path = shellQuote(ManagedInstallMarkerProtocol.MARKER_PATH)
        val result = session.execute(
            RemoteCommand.create(
                "if [ -f $path ]; then cat -- $path; else exit $MARKER_ABSENT_EXIT_CODE; fi",
                "phase9-restart-managed-marker-readback",
            ),
            SshTransportConfig(
                channelOpenTimeout = Duration.ofSeconds(5),
                commandExecutionTimeout = Duration.ofSeconds(5),
                stdoutCaptureLimitBytes = 256,
                stderrCaptureLimitBytes = 256,
            ),
        )
        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.stdout.truncated) {
            return ManagedInstallMarkerReadbackState.MALFORMED
        }
        return when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> {
                val raw = strictText(result.stdout) ?: return ManagedInstallMarkerReadbackState.MALFORMED
                ManagedInstallMarkerProtocol.classifyReadback(expected, raw)
            }
            is CommandCompletion.ConfirmedFailure -> if (completion.exitCode == MARKER_ABSENT_EXIT_CODE) {
                ManagedInstallMarkerReadbackState.ABSENT
            } else {
                ManagedInstallMarkerReadbackState.MALFORMED
            }
            is CommandCompletion.Unknown -> ManagedInstallMarkerReadbackState.MALFORMED
        }
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
            Arrays.fill(bytes, 0)
        }
    }

    private fun configFor(timeout: Duration): SshTransportConfig = SshTransportConfig(
        channelOpenTimeout = timeout.coerceAtMost(Duration.ofSeconds(5)),
        commandExecutionTimeout = timeout,
        stdoutCaptureLimitBytes = 1024,
        stderrCaptureLimitBytes = 512,
    )

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"

    private enum class ProbeVerdict {
        Verified,
        Contradicted,
        Incomplete,
    }

    private companion object {
        const val MARKER_ABSENT_EXIT_CODE = 44
    }
}

sealed interface ExistingInstallationRestartPostVerifyResult {
    data class Verified(val observedAt: Instant) : ExistingInstallationRestartPostVerifyResult
    data class Contradicted(
        val reason: ExistingInstallationRestartPostVerifyReason,
    ) : ExistingInstallationRestartPostVerifyResult
    data class Incomplete(
        val reason: ExistingInstallationRestartPostVerifyReason,
    ) : ExistingInstallationRestartPostVerifyResult
    data class Rejected(
        val failure: ExistingInstallationRestartPostVerifyFailure,
    ) : ExistingInstallationRestartPostVerifyResult
}

enum class ExistingInstallationRestartPostVerifyFailure {
    ScopeTargetMismatch,
    ExactSessionBindingMismatch,
    SessionClosed,
}

enum class ExistingInstallationRestartPostVerifyReason {
    PROBE_COMPILATION_REJECTED,
    READ_ONLY_PROBE_INCOMPLETE,
    SERVICE_UNIT_ABSENT,
    BINARY_PATH_ABSENT,
    ROOT_PATH_ABSENT,
    DATABASE_PATH_ABSENT,
    MANAGED_MARKER_ABSENT,
    MANAGED_MARKER_MISMATCH,
    MANAGED_MARKER_MALFORMED,
    SERVICE_NOT_ACTIVE,
    EXPECTED_LISTENER_ABSENT,
    SERVICE_NOT_INACTIVE,
    LISTENER_STILL_PRESENT,
    AUTOSTART_STATE_MISMATCH,
    XRAY_RESTART_NOT_OBSERVED,
}

/** Read-only production preflight on the shared runtime's exact pinned operation-owned session.
 * No connection, retry or mutation; raw output stays in this reviewed parser and copies are wiped. */
class ExistingInstallationRestartPreflightSshAdapter(private val now: () -> Instant = Instant::now) {
    suspend fun verify(current: VersionedOperationSnapshot, installation: XuiInstallation, access: ServerAccess,
        session: SshSessionHandle, barrier: ExistingInstallationMutationBarrierState): ExistingInstallationRestartPreflightResult {
        val s = current.snapshot
        val t = s.target as? OperationTarget.InstallationTarget ?: return rejected(ExistingInstallationRestartPreflightRejection.EXACT_SCOPE_REQUIRED)
        if (s.type != OperationType.RESTART || s.status != OperationStatus.RUNNING ||
            s.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED || t.installationId != installation.id ||
            t.serverId != installation.serverId || t.serverAccessId != access.id || access.serverId != installation.serverId ||
            session.binding.owner != SessionOwner.Operation(s.operationId) || session.binding.serverAccessId != access.id || !session.isOpen
        ) return rejected(ExistingInstallationRestartPreflightRejection.EXACT_SCOPE_REQUIRED)
        if (barrier != ExistingInstallationMutationBarrierState.PROVEN_CLEAR) return rejected(ExistingInstallationRestartPreflightRejection.MUTATION_BARRIER_BLOCKED)
        val identity = installation.identity
        if (identity.serviceUnit != "x-ui.service" || identity.binaryPath != "/usr/local/x-ui/x-ui" ||
            identity.rootPath != "/usr/local/x-ui" || identity.databasePath != "/etc/x-ui/x-ui.db")
            return rejected(ExistingInstallationRestartPreflightRejection.STANDARD_LAYOUT_REQUIRED)
        val probes = listOf(ManagementProbeSpec.ServiceUnitPresence(identity.serviceUnit),
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.BINARY, identity.binaryPath),
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.ROOT, identity.rootPath),
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.DATABASE, identity.databasePath),
            ManagementProbeSpec.PanelSettingsReadback(identity.databasePath))
        val compiled = probes.map { ManagementReadOnlyCommandCompiler.compile(it) as? CompiledManagementProbe.Command
            ?: return rejected(ExistingInstallationRestartPreflightRejection.STANDARD_LAYOUT_REQUIRED) }
        val binding = session.binding
        val uid = fixedText(session, "id -u", "restart-preflight-effective-uid", 64)
            ?: return rejected(ExistingInstallationRestartPreflightRejection.READ_ONLY_CHECK_INCOMPLETE)
        if (uid.trim() != "0") return rejected(ExistingInstallationRestartPreflightRejection.DIRECT_ROOT_REQUIRED)
        val exec = fixedText(session, "systemctl show x-ui.service --property=ExecStart --value", "restart-preflight-exact-systemd-executable", 2048)
            ?: return rejected(ExistingInstallationRestartPreflightRejection.READ_ONLY_CHECK_INCOMPLETE)
        val executable = Regex("""^\{\s*path=([^;\s]+)\s*;[^\r\n]*\}$""").matchEntire(exec.trim())?.groupValues?.get(1)
        if (executable != identity.binaryPath || Regex("""\bpath=""").findAll(exec).count() != 1)
            return rejected(ExistingInstallationRestartPreflightRejection.IDENTITY_MISMATCH)
        for ((index, command) in compiled.withIndex()) {
            currentCoroutineContext().ensureActive()
            val result = session.execute(command.command, config())
            currentCoroutineContext().ensureActive()
            if (result.dispatchState != CommandDispatchState.DISPATCHED || result.completion != CommandCompletion.ConfirmedSuccess ||
                result.stdout.truncated || result.stderr.truncated)
                return rejected(ExistingInstallationRestartPreflightRejection.READ_ONLY_CHECK_INCOMPLETE)
            if (probes[index] is ManagementProbeSpec.PanelSettingsReadback) {
                val raw = text(result) ?: return rejected(ExistingInstallationRestartPreflightRejection.READ_ONLY_CHECK_INCOMPLETE)
                val settings = when (val p = ManagementProbeParsers.parsePanelSettings(raw)) {
                    is ManagementProbeParseResult.Parsed -> p.value
                    ManagementProbeParseResult.Malformed -> return rejected(ExistingInstallationRestartPreflightRejection.READ_ONLY_CHECK_INCOMPLETE)
                }
                if (settings.panelPort != installation.baseline.panelPort || settings.webBasePath != installation.baseline.webBasePath ||
                    settings.listenAddress != installation.baseline.listenAddress) return rejected(ExistingInstallationRestartPreflightRejection.PANEL_SETTINGS_CHANGED)
            }
        }
        identity.managedInstallId?.let { expected ->
            val path = "'" + ManagedInstallMarkerProtocol.MARKER_PATH.replace("'", "'\"'\"'") + "'"
            val marker = fixedText(session, "cat -- $path", "restart-preflight-managed-marker", 256)
                ?: return rejected(ExistingInstallationRestartPreflightRejection.MANAGED_MARKER_UNCONFIRMED)
            if (ManagedInstallMarkerProtocol.classifyReadback(expected, marker) != ManagedInstallMarkerReadbackState.MATCH)
                return rejected(ExistingInstallationRestartPreflightRejection.MANAGED_MARKER_UNCONFIRMED)
        }
        if (!session.isOpen || session.binding != binding) return rejected(ExistingInstallationRestartPreflightRejection.EXACT_SCOPE_REQUIRED)
        val at = now()
        if (at.isBefore(s.updatedAt)) return rejected(ExistingInstallationRestartPreflightRejection.READ_ONLY_CHECK_INCOMPLETE)
        val proof = InstallationProof(TargetProofId(UUID.randomUUID().toString()), installation.id, installation.serverId,
            access.id, identity, at, at.plusSeconds(15))
        val target = (TargetProofPolicy.verifyKnownInstallation(installation, access, proof, at) as? TargetVerificationResult.Verified)?.target
            ?: return rejected(ExistingInstallationRestartPreflightRejection.EXACT_SCOPE_REQUIRED)
        val authorization = (ExistingInstallationActionAuthorizationPolicy.verify(current, installation, target, at)
            as? ExistingInstallationActionAuthorizationResult.Verified)?.authorization
            ?: return rejected(ExistingInstallationRestartPreflightRejection.EXACT_SCOPE_REQUIRED)
        val evidence = ExistingInstallationPreflightEvidence(
            ExistingInstallationActionScope(s.operationId, current.revision.value, installation.serverId, access.id, installation.id,
                OperationType.RESTART, installation.ownership, identity.managedInstallId), proof,
            ExistingInstallationAccessPathState.EXACT_PINNED_AUTHENTICATED,
            ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1, ExistingInstallationPrivilegeCapability.DIRECT_ROOT,
            barrier, at, proof.validUntil)
        return when (val p = ExistingInstallationActionPreflightPolicy.verify(authorization, current, installation, evidence, at)) {
            is ExistingInstallationActionPreflightResult.Verified -> ExistingInstallationRestartPreflightResult.Verified(p.preflight)
            is ExistingInstallationActionPreflightResult.Rejected -> rejected(ExistingInstallationRestartPreflightRejection.EXACT_SCOPE_REQUIRED)
        }
    }
    private suspend fun fixedText(session: SshSessionHandle, raw: String, label: String, limit: Int): String? {
        currentCoroutineContext().ensureActive()
        val result = session.execute(RemoteCommand.create(raw, label), config(limit))
        currentCoroutineContext().ensureActive()
        return text(result)
    }
    private fun text(result: SshCommandResult): String? {
        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.completion != CommandCompletion.ConfirmedSuccess ||
            result.stdout.truncated || result.stderr.truncated) return null
        val bytes = result.stdout.copyBytes()
        return try { StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString() }
        catch (_: Exception) { null } finally { Arrays.fill(bytes, 0) }
    }
    private fun config(limit: Int = 1024) = SshTransportConfig(channelOpenTimeout = Duration.ofSeconds(3),
        commandExecutionTimeout = Duration.ofSeconds(4), stdoutCaptureLimitBytes = limit, stderrCaptureLimitBytes = 256)
    private fun rejected(reason: ExistingInstallationRestartPreflightRejection) = ExistingInstallationRestartPreflightResult.Rejected(reason)
}
sealed interface ExistingInstallationRestartPreflightResult {
    data class Verified(val preflight: VerifiedExistingInstallationActionPreflight) : ExistingInstallationRestartPreflightResult
    data class Rejected(val reason: ExistingInstallationRestartPreflightRejection) : ExistingInstallationRestartPreflightResult
}
enum class ExistingInstallationRestartPreflightRejection {
    EXACT_SCOPE_REQUIRED, STANDARD_LAYOUT_REQUIRED, DIRECT_ROOT_REQUIRED, IDENTITY_MISMATCH,
    PANEL_SETTINGS_CHANGED, MANAGED_MARKER_UNCONFIRMED, MUTATION_BARRIER_BLOCKED, READ_ONLY_CHECK_INCOMPLETE,
    LOCAL_METADATA_CHANGED, CONFIRMATION_EXPIRED,
}


private fun VersionedOperationSnapshot.servicePhaseName(restartPhaseName: String): String =
    ExistingInstallationServiceAction.nextPhaseName(snapshot.checkpoint.phaseName, restartPhaseName)
