package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.ManagementProbeSpec
import com.velumtegra.xuimobile.core.domain.ReviewedExistingInstallationActionPlanPolicy
import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationActionPreflight
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ExistingInstallationActionPlanStep
import com.velumtegra.xuimobile.core.model.ExistingInstallationLayoutCapability
import com.velumtegra.xuimobile.core.model.ExistingInstallationPrivilegeCapability
import com.velumtegra.xuimobile.core.model.ExistingInstallationRemoteCapability
import com.velumtegra.xuimobile.core.model.ManagementPathKind
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ReviewedExistingInstallationActionPlan
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.XuiInstallation
import java.time.Duration
import java.time.Instant
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/**
 * Phase 9.6 one-shot destructive UNINSTALL dispatcher.
 *
 * The reviewed command explicitly confirms panel removal and explicitly declines the optional
 * PostgreSQL purge. This keeps the destructive capability bounded to the 3x-ui panel itself.
 * MUTATION_IN_FLIGHT is durable before command dispatch and no result creates replay authority.
 */
class ExistingInstallationUninstallSshAdapter(
    private val journal: OperationJournal,
    private val now: () -> Instant = Instant::now,
) {
    suspend fun dispatch(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: ReviewedExistingInstallationActionPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationUninstallDispatchResult {
        validate(preflight, plan, current, session)?.let {
            return ExistingInstallationUninstallDispatchResult.Rejected(it)
        }
        currentCoroutineContext().ensureActive()
        val checkpointed = advanceMutationInFlight(current)
            ?: return ExistingInstallationUninstallDispatchResult.Rejected(
                ExistingInstallationUninstallDispatchFailure.PredispatchCheckpointRejected,
            )
        val compiled = ExistingInstallationUninstallCommandCompiler.compile(preflight, plan)
            ?: return requireReconciliation(
                checkpointed,
                ExistingInstallationUninstallReconciliationReason.PLAN_COMPILATION_REJECTED_AFTER_CHECKPOINT,
            )

        currentCoroutineContext().ensureActive()
        val result = session.execute(compiled.command, compiled.config)
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED) {
            return requireReconciliation(
                checkpointed,
                ExistingInstallationUninstallReconciliationReason.DISPATCH_NOT_CONFIRMED,
            )
        }

        return when (result.completion) {
            CommandCompletion.ConfirmedSuccess ->
                ExistingInstallationUninstallDispatchResult.PostVerifyRequired(checkpointed)
            is CommandCompletion.ConfirmedFailure ->
                ExistingInstallationUninstallDispatchResult.PostVerifyRequired(checkpointed)
            is CommandCompletion.Unknown -> requireReconciliation(
                checkpointed,
                ExistingInstallationUninstallReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
            )
        }
    }

    private fun validate(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: ReviewedExistingInstallationActionPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationUninstallDispatchFailure? {
        if (!ReviewedExistingInstallationActionPlanPolicy.isCanonical(plan) ||
            plan.scope.action != OperationType.UNINSTALL ||
            preflight.authorization.action != OperationType.UNINSTALL ||
            preflight.evidence.scope != plan.scope ||
            preflight.evidence.layoutCapability != ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1 ||
            preflight.evidence.privilegeCapability != ExistingInstallationPrivilegeCapability.DIRECT_ROOT
        ) return ExistingInstallationUninstallDispatchFailure.PlanOutsideApprovedPolicy

        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationUninstallDispatchFailure.ScopeTargetMismatch
        if (snapshot.type != OperationType.UNINSTALL ||
            snapshot.operationId != plan.scope.operationId ||
            current.revision.value != plan.scope.operationRevision ||
            target.serverId != plan.scope.serverId ||
            target.serverAccessId != plan.scope.serverAccessId ||
            target.installationId != plan.scope.installationId ||
            snapshot.status != OperationStatus.RUNNING
        ) return ExistingInstallationUninstallDispatchFailure.ScopeTargetMismatch
        if (snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return ExistingInstallationUninstallDispatchFailure.NotAtPredispatchCheckpoint
        }
        if (session.binding.owner != SessionOwner.Operation(snapshot.operationId) ||
            session.binding.serverAccessId != target.serverAccessId
        ) return ExistingInstallationUninstallDispatchFailure.ExactSessionBindingMismatch
        if (!session.isOpen) return ExistingInstallationUninstallDispatchFailure.SessionClosed
        return null
    }

    private suspend fun advanceMutationInFlight(current: VersionedOperationSnapshot): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = "UNINSTALL_DISPATCHED",
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
        reason: ExistingInstallationUninstallReconciliationReason,
    ): ExistingInstallationUninstallDispatchResult.ReconciliationRequired {
        val at = now()
        val next = if (at.isBefore(current.snapshot.updatedAt)) null else current.snapshot.copy(
            status = OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint = OperationCheckpoint(
                phaseName = "UNINSTALL_RECONCILIATION_REQUIRED",
                semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
                recordedAt = at,
            ),
            updatedAt = at,
        )
        val recorded = if (next == null) null else when (
            val advanced = journal.advance(current.snapshot.operationId, current.revision, next)
        ) {
            is OperationJournalResult.Success -> advanced.value
            else -> null
        }
        return ExistingInstallationUninstallDispatchResult.ReconciliationRequired(
            durable = recorded ?: current,
            reason = reason,
            reconciliationCheckpointRecorded = recorded != null,
        )
    }
}

sealed interface ExistingInstallationUninstallDispatchResult {
    data class PostVerifyRequired(val durable: VersionedOperationSnapshot) : ExistingInstallationUninstallDispatchResult
    data class Rejected(val failure: ExistingInstallationUninstallDispatchFailure) : ExistingInstallationUninstallDispatchResult
    data class ReconciliationRequired(
        val durable: VersionedOperationSnapshot,
        val reason: ExistingInstallationUninstallReconciliationReason,
        val reconciliationCheckpointRecorded: Boolean,
    ) : ExistingInstallationUninstallDispatchResult
}

enum class ExistingInstallationUninstallDispatchFailure {
    PlanOutsideApprovedPolicy,
    ScopeTargetMismatch,
    NotAtPredispatchCheckpoint,
    ExactSessionBindingMismatch,
    SessionClosed,
    PredispatchCheckpointRejected,
}

enum class ExistingInstallationUninstallReconciliationReason {
    PLAN_COMPILATION_REJECTED_AFTER_CHECKPOINT,
    DISPATCH_NOT_CONFIRMED,
    TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
}

internal data class CompiledExistingInstallationUninstall(
    val command: RemoteCommand,
    val config: SshTransportConfig,
)

internal object ExistingInstallationUninstallCommandCompiler {
    const val STANDARD_SERVICE_UNIT = "x-ui.service"
    const val STANDARD_BINARY_PATH = "/usr/local/x-ui/x-ui"
    const val STANDARD_ROOT_PATH = "/usr/local/x-ui"
    const val STANDARD_DATABASE_PATH = "/etc/x-ui/x-ui.db"
    const val STANDARD_MENU_PATH = "/usr/bin/x-ui"
    const val EXACT_UNINSTALL_COMMAND =
        "[ -x /usr/bin/x-ui ] || exit 42; printf 'y\\nn\\n' | /usr/bin/x-ui uninstall"

    fun compile(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: ReviewedExistingInstallationActionPlan,
    ): CompiledExistingInstallationUninstall? {
        if (!ReviewedExistingInstallationActionPlanPolicy.isCanonical(plan) ||
            plan.scope.action != OperationType.UNINSTALL ||
            preflight.evidence.scope != plan.scope ||
            preflight.evidence.layoutCapability != ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1 ||
            preflight.evidence.privilegeCapability != ExistingInstallationPrivilegeCapability.DIRECT_ROOT
        ) return null
        val uninstall = plan.steps.firstOrNull() as? ExistingInstallationActionPlanStep.ExecuteReviewedUninstall
            ?: return null
        if (uninstall.capability != ExistingInstallationRemoteCapability.OFFICIAL_3X_UI_UNINSTALL_V1) return null
        val identity = preflight.evidence.installationProof.observedIdentity
        if (identity.serviceUnit != STANDARD_SERVICE_UNIT ||
            identity.binaryPath != STANDARD_BINARY_PATH ||
            identity.rootPath != STANDARD_ROOT_PATH ||
            identity.databasePath != STANDARD_DATABASE_PATH
        ) return null
        return CompiledExistingInstallationUninstall(
            command = RemoteCommand.create(EXACT_UNINSTALL_COMMAND, "phase9-uninstall-official-panel-preserve-postgresql"),
            config = SshTransportConfig(
                channelOpenTimeout = uninstall.timeout.coerceAtMost(Duration.ofSeconds(5)),
                commandExecutionTimeout = uninstall.timeout,
                stdoutCaptureLimitBytes = 1024,
                stderrCaptureLimitBytes = 1024,
            ),
        )
    }
}

/** Read-only Phase 9.6 proof that the supported exact installation is absent. */
class ExistingInstallationUninstallAbsenceSshAdapter(
    private val now: () -> Instant = Instant::now,
) {
    suspend fun verify(
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        session: SshSessionHandle,
    ): ExistingInstallationUninstallAbsenceResult {
        validate(current, installation, session)?.let { return ExistingInstallationUninstallAbsenceResult.Rejected(it) }
        val identity = installation.identity
        val probes: List<Pair<ManagementProbeSpec, ExistingInstallationUninstallAbsenceReason>> = listOf(
            ManagementProbeSpec.ServiceUnitPresence(identity.serviceUnit) to ExistingInstallationUninstallAbsenceReason.SERVICE_UNIT_PRESENT,
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.BINARY, identity.binaryPath) to ExistingInstallationUninstallAbsenceReason.BINARY_PATH_PRESENT,
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.ROOT, identity.rootPath) to ExistingInstallationUninstallAbsenceReason.ROOT_PATH_PRESENT,
            ManagementProbeSpec.ExactPathPresence(ManagementPathKind.DATABASE, identity.databasePath) to ExistingInstallationUninstallAbsenceReason.DATABASE_PATH_PRESENT,
            ManagementProbeSpec.ExactListenerPresence(
                expectedPort = installation.baseline.panelPort,
                expectedListenAddress = installation.baseline.listenAddress,
            ) to ExistingInstallationUninstallAbsenceReason.EXPECTED_LISTENER_PRESENT,
        )
        for ((probe, presentReason) in probes) {
            currentCoroutineContext().ensureActive()
            val compiled = ManagementReadOnlyCommandCompiler.compile(probe) as? CompiledManagementProbe.Command
                ?: return ExistingInstallationUninstallAbsenceResult.Incomplete(
                    ExistingInstallationUninstallAbsenceReason.PROBE_COMPILATION_REJECTED,
                )
            val result = session.execute(compiled.command, configFor(probe.timeout))
            currentCoroutineContext().ensureActive()
            when (absenceVerdict(result)) {
                AbsenceVerdict.ABSENT -> Unit
                AbsenceVerdict.PRESENT -> return ExistingInstallationUninstallAbsenceResult.Contradicted(presentReason)
                AbsenceVerdict.INCOMPLETE -> return ExistingInstallationUninstallAbsenceResult.Incomplete(
                    ExistingInstallationUninstallAbsenceReason.READ_ONLY_PROBE_INCOMPLETE,
                )
            }
        }

        currentCoroutineContext().ensureActive()
        val menuResult = session.execute(
            RemoteCommand.create("[ -x ${ExistingInstallationUninstallCommandCompiler.STANDARD_MENU_PATH} ]", "phase9-uninstall-menu-absence"),
            SshTransportConfig(
                channelOpenTimeout = Duration.ofSeconds(5),
                commandExecutionTimeout = Duration.ofSeconds(10),
                stdoutCaptureLimitBytes = 128,
                stderrCaptureLimitBytes = 128,
            ),
        )
        currentCoroutineContext().ensureActive()
        return when (absenceVerdict(menuResult)) {
            AbsenceVerdict.ABSENT -> ExistingInstallationUninstallAbsenceResult.Verified(now())
            AbsenceVerdict.PRESENT -> ExistingInstallationUninstallAbsenceResult.Contradicted(
                ExistingInstallationUninstallAbsenceReason.MENU_WRAPPER_PRESENT,
            )
            AbsenceVerdict.INCOMPLETE -> ExistingInstallationUninstallAbsenceResult.Incomplete(
                ExistingInstallationUninstallAbsenceReason.READ_ONLY_PROBE_INCOMPLETE,
            )
        }
    }

    private fun validate(
        current: VersionedOperationSnapshot,
        installation: XuiInstallation,
        session: SshSessionHandle,
    ): ExistingInstallationUninstallAbsenceFailure? {
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationUninstallAbsenceFailure.ScopeTargetMismatch
        if (snapshot.type != OperationType.UNINSTALL ||
            target.installationId != installation.id ||
            target.serverId != installation.serverId ||
            snapshot.checkpoint.semantics != CheckpointSemantics.POST_VERIFY_REQUIRED ||
            snapshot.status !in setOf(OperationStatus.RUNNING, OperationStatus.RECONCILIATION_REQUIRED)
        ) return ExistingInstallationUninstallAbsenceFailure.ScopeTargetMismatch
        if (session.binding.owner != SessionOwner.Operation(snapshot.operationId) ||
            session.binding.serverAccessId != target.serverAccessId
        ) return ExistingInstallationUninstallAbsenceFailure.ExactSessionBindingMismatch
        if (!session.isOpen) return ExistingInstallationUninstallAbsenceFailure.SessionClosed
        return null
    }

    private fun absenceVerdict(result: SshCommandResult): AbsenceVerdict {
        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.stdout.truncated || result.stderr.truncated) {
            return AbsenceVerdict.INCOMPLETE
        }
        return when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> AbsenceVerdict.PRESENT
            is CommandCompletion.ConfirmedFailure -> if (completion.exitCode == 1) AbsenceVerdict.ABSENT else AbsenceVerdict.INCOMPLETE
            is CommandCompletion.Unknown -> AbsenceVerdict.INCOMPLETE
        }
    }

    private fun configFor(timeout: Duration) = SshTransportConfig(
        channelOpenTimeout = timeout.coerceAtMost(Duration.ofSeconds(5)),
        commandExecutionTimeout = timeout,
        stdoutCaptureLimitBytes = 256,
        stderrCaptureLimitBytes = 256,
    )

    private enum class AbsenceVerdict { ABSENT, PRESENT, INCOMPLETE }
}

sealed interface ExistingInstallationUninstallAbsenceResult {
    data class Verified(val observedAt: Instant) : ExistingInstallationUninstallAbsenceResult
    data class Contradicted(val reason: ExistingInstallationUninstallAbsenceReason) : ExistingInstallationUninstallAbsenceResult
    data class Incomplete(val reason: ExistingInstallationUninstallAbsenceReason) : ExistingInstallationUninstallAbsenceResult
    data class Rejected(val failure: ExistingInstallationUninstallAbsenceFailure) : ExistingInstallationUninstallAbsenceResult
}

enum class ExistingInstallationUninstallAbsenceFailure {
    ScopeTargetMismatch,
    ExactSessionBindingMismatch,
    SessionClosed,
}

enum class ExistingInstallationUninstallAbsenceReason {
    SERVICE_UNIT_PRESENT,
    BINARY_PATH_PRESENT,
    ROOT_PATH_PRESENT,
    DATABASE_PATH_PRESENT,
    EXPECTED_LISTENER_PRESENT,
    MENU_WRAPPER_PRESENT,
    PROBE_COMPILATION_REJECTED,
    READ_ONLY_PROBE_INCOMPLETE,
}
