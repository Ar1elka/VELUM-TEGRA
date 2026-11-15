package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.InstallerPostInstallFacts
import com.velumtegra.xuimobile.core.domain.InstallerPostInstallPolicy
import com.velumtegra.xuimobile.core.domain.InstallerPostInstallVerificationDecision
import com.velumtegra.xuimobile.core.domain.InstallerWorkerLivenessPolicy
import com.velumtegra.xuimobile.core.domain.ManagedInstallMarkerProtocol
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.ReviewedExistingInstallationActionPlanPolicy
import com.velumtegra.xuimobile.core.domain.VerifiedExistingInstallationActionPreflight
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ExistingInstallationActionPlanStep
import com.velumtegra.xuimobile.core.model.ExistingInstallationLayoutCapability
import com.velumtegra.xuimobile.core.model.ExistingInstallationPrivilegeCapability
import com.velumtegra.xuimobile.core.model.ExistingInstallationRemoteCapability
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.InstallerWorkerEvidence
import com.velumtegra.xuimobile.core.model.InstallerWorkerLiveness
import com.velumtegra.xuimobile.core.model.InstallerWorkerProcessState
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.InstallerWorkerTerminalState
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ReviewedExistingInstallationActionPlan
import com.velumtegra.xuimobile.core.model.SessionOwner
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive

/**
 * Phase 9.7 one-shot managed REINSTALL compound dispatcher.
 *
 * One durable MUTATION_IN_FLIGHT checkpoint precedes the first remote write. The reviewed compound
 * sequence is executed once in-order and is never resumed/replayed from durable state. Any partial,
 * failed or transport-uncertain outcome remains reconciliation-only; a later admission may perform
 * read-only final verification but may not redispatch the compound plan.
 */
class ExistingInstallationReinstallSshAdapter(
    private val journal: OperationJournal,
    private val now: () -> Instant = Instant::now,
) {
    suspend fun dispatch(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: ReviewedExistingInstallationActionPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationReinstallDispatchResult {
        validate(preflight, plan, current, session)?.let {
            return ExistingInstallationReinstallDispatchResult.Rejected(it)
        }
        currentCoroutineContext().ensureActive()
        val checkpointed = advanceMutationInFlight(current)
            ?: return ExistingInstallationReinstallDispatchResult.Rejected(
                ExistingInstallationReinstallDispatchFailure.PredispatchCheckpointRejected,
            )
        val compiled = ExistingInstallationReinstallCommandCompiler.compile(preflight, plan)
            ?: return requireReconciliation(
                checkpointed,
                ExistingInstallationReinstallReconciliationReason.PLAN_COMPILATION_REJECTED_AFTER_CHECKPOINT,
            )

        for (step in compiled.steps) {
            currentCoroutineContext().ensureActive()
            val result = session.execute(step.command, step.config)
            currentCoroutineContext().ensureActive()
            if (result.dispatchState != CommandDispatchState.DISPATCHED) {
                return requireReconciliation(
                    checkpointed,
                    ExistingInstallationReinstallReconciliationReason.DISPATCH_NOT_CONFIRMED,
                )
            }
            when (result.completion) {
                CommandCompletion.ConfirmedSuccess -> Unit
                is CommandCompletion.ConfirmedFailure -> {
                    return requireReconciliation(
                        checkpointed,
                        ExistingInstallationReinstallReconciliationReason.REMOTE_STEP_FAILED,
                    )
                }
                is CommandCompletion.Unknown -> {
                    return requireReconciliation(
                        checkpointed,
                        ExistingInstallationReinstallReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
                    )
                }
            }
        }
        return ExistingInstallationReinstallDispatchResult.PostVerifyRequired(checkpointed)
    }

    private fun validate(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: ReviewedExistingInstallationActionPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): ExistingInstallationReinstallDispatchFailure? {
        if (!ReviewedExistingInstallationActionPlanPolicy.isCanonical(plan) ||
            plan.scope.action != OperationType.REINSTALL ||
            plan.scope.ownership != InstallationOwnership.MANAGED ||
            plan.scope.managedInstallId == null ||
            preflight.authorization.action != OperationType.REINSTALL ||
            preflight.authorization.ownership != InstallationOwnership.MANAGED ||
            preflight.evidence.scope != plan.scope ||
            preflight.evidence.layoutCapability != ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1 ||
            preflight.evidence.privilegeCapability != ExistingInstallationPrivilegeCapability.DIRECT_ROOT
        ) return ExistingInstallationReinstallDispatchFailure.PlanOutsideApprovedPolicy

        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationReinstallDispatchFailure.ScopeTargetMismatch
        if (snapshot.type != OperationType.REINSTALL ||
            snapshot.operationId != plan.scope.operationId ||
            current.revision.value != plan.scope.operationRevision ||
            target.serverId != plan.scope.serverId ||
            target.serverAccessId != plan.scope.serverAccessId ||
            target.installationId != plan.scope.installationId ||
            snapshot.status != OperationStatus.RUNNING
        ) return ExistingInstallationReinstallDispatchFailure.ScopeTargetMismatch
        if (snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return ExistingInstallationReinstallDispatchFailure.NotAtPredispatchCheckpoint
        }
        if (session.binding.owner != SessionOwner.Operation(snapshot.operationId) ||
            session.binding.serverAccessId != target.serverAccessId
        ) return ExistingInstallationReinstallDispatchFailure.ExactSessionBindingMismatch
        if (!session.isOpen) return ExistingInstallationReinstallDispatchFailure.SessionClosed
        return null
    }

    private suspend fun advanceMutationInFlight(current: VersionedOperationSnapshot): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = "REINSTALL_COMPOUND_DISPATCHED",
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
        reason: ExistingInstallationReinstallReconciliationReason,
    ): ExistingInstallationReinstallDispatchResult.ReconciliationRequired {
        val at = now()
        val next = if (at.isBefore(current.snapshot.updatedAt)) null else current.snapshot.copy(
            status = OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint = OperationCheckpoint(
                phaseName = "REINSTALL_RECONCILIATION_REQUIRED",
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
        return ExistingInstallationReinstallDispatchResult.ReconciliationRequired(
            durable = recorded ?: current,
            reason = reason,
            reconciliationCheckpointRecorded = recorded != null,
        )
    }
}

sealed interface ExistingInstallationReinstallDispatchResult {
    data class PostVerifyRequired(val durable: VersionedOperationSnapshot) : ExistingInstallationReinstallDispatchResult
    data class Rejected(val failure: ExistingInstallationReinstallDispatchFailure) : ExistingInstallationReinstallDispatchResult
    data class ReconciliationRequired(
        val durable: VersionedOperationSnapshot,
        val reason: ExistingInstallationReinstallReconciliationReason,
        val reconciliationCheckpointRecorded: Boolean,
    ) : ExistingInstallationReinstallDispatchResult
}

enum class ExistingInstallationReinstallDispatchFailure {
    PlanOutsideApprovedPolicy,
    ScopeTargetMismatch,
    NotAtPredispatchCheckpoint,
    ExactSessionBindingMismatch,
    SessionClosed,
    PredispatchCheckpointRejected,
}

enum class ExistingInstallationReinstallReconciliationReason {
    PLAN_COMPILATION_REJECTED_AFTER_CHECKPOINT,
    DISPATCH_NOT_CONFIRMED,
    REMOTE_STEP_FAILED,
    TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
}

internal enum class ExistingInstallationReinstallStepKind {
    UNINSTALL,
    PREPARE_WORKER,
    FETCH_INSTALLER,
    EXECUTE_INSTALLER,
    WRITE_MANAGED_MARKER,
}

internal data class CompiledExistingInstallationReinstallStep(
    val kind: ExistingInstallationReinstallStepKind,
    val command: RemoteCommand,
    val config: SshTransportConfig,
)

internal data class CompiledExistingInstallationReinstall(
    val workerScope: InstallerWorkerScope,
    val workerDirectory: String,
    val steps: List<CompiledExistingInstallationReinstallStep>,
)

/** Exact Phase 9.7 compiler. No caller-controlled command/url/path/answers exist. */
internal object ExistingInstallationReinstallCommandCompiler {
    private const val REINSTALL_WORK_ROOT = "/var/lib/velum-tegra/reinstall/v1"
    private val managedIdRegex = Regex("v1-[0-9a-f]{32}")
    private val maxChannelOpenTimeout = Duration.ofSeconds(5)
    private val prepareTimeout = Duration.ofSeconds(10)
    private val fetchTimeout = Duration.ofMinutes(2)

    fun compile(
        preflight: VerifiedExistingInstallationActionPreflight,
        plan: ReviewedExistingInstallationActionPlan,
    ): CompiledExistingInstallationReinstall? {
        if (!ReviewedExistingInstallationActionPlanPolicy.isCanonical(plan) ||
            plan.scope.action != OperationType.REINSTALL ||
            plan.scope.ownership != InstallationOwnership.MANAGED ||
            preflight.evidence.scope != plan.scope ||
            preflight.evidence.layoutCapability != ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1 ||
            preflight.evidence.privilegeCapability != ExistingInstallationPrivilegeCapability.DIRECT_ROOT
        ) return null
        val managedId = plan.scope.managedInstallId ?: return null
        if (!managedIdRegex.matches(managedId.value)) return null
        val identity = preflight.evidence.installationProof.observedIdentity
        if (identity.serviceUnit != ExistingInstallationUninstallCommandCompiler.STANDARD_SERVICE_UNIT ||
            identity.binaryPath != ExistingInstallationUninstallCommandCompiler.STANDARD_BINARY_PATH ||
            identity.rootPath != ExistingInstallationUninstallCommandCompiler.STANDARD_ROOT_PATH ||
            identity.databasePath != ExistingInstallationUninstallCommandCompiler.STANDARD_DATABASE_PATH ||
            identity.managedInstallId != managedId
        ) return null

        val uninstall = plan.steps.getOrNull(0) as? ExistingInstallationActionPlanStep.ExecuteReviewedUninstall ?: return null
        val install = plan.steps.getOrNull(1) as? ExistingInstallationActionPlanStep.ExecuteReviewedInstaller ?: return null
        val marker = plan.steps.getOrNull(2) as? ExistingInstallationActionPlanStep.WriteManagedMarker ?: return null
        if (uninstall.capability != ExistingInstallationRemoteCapability.OFFICIAL_3X_UI_UNINSTALL_V1 ||
            install.capability != ExistingInstallationRemoteCapability.OFFICIAL_3X_UI_INSTALL_V1 ||
            marker.managedInstallId != managedId
        ) return null

        val workerScope = InstallerWorkerScope(
            operationId = plan.scope.operationId,
            serverId = plan.scope.serverId,
            serverAccessId = plan.scope.serverAccessId,
            managedInstallId = managedId,
        )
        val workDir = "$REINSTALL_WORK_ROOT/${managedId.value}/${operationTag(plan.scope.operationId.value)}"
        val installerPath = "$workDir/install.sh"
        val workerPath = "$workDir/worker.sh"
        val steps = listOf(
            compiled(
                ExistingInstallationReinstallStepKind.UNINSTALL,
                ExistingInstallationUninstallCommandCompiler.EXACT_UNINSTALL_COMMAND,
                uninstall.timeout,
                "phase9-reinstall-official-uninstall",
            ),
            compiled(
                ExistingInstallationReinstallStepKind.PREPARE_WORKER,
                prepareWorkerCommand(workDir),
                prepareTimeout,
                "phase9-reinstall-prepare-worker",
            ),
            compiled(
                ExistingInstallationReinstallStepKind.FETCH_INSTALLER,
                fetchInstallerCommand(workDir, installerPath),
                fetchTimeout,
                "phase9-reinstall-fetch-installer",
            ),
            compiled(
                ExistingInstallationReinstallStepKind.EXECUTE_INSTALLER,
                executeInstallerCommand(workDir, installerPath, workerPath),
                install.timeout,
                "phase9-reinstall-execute-installer",
            ),
            compiled(
                ExistingInstallationReinstallStepKind.WRITE_MANAGED_MARKER,
                writeMarkerCommand(managedId.value),
                marker.timeout,
                "phase9-reinstall-managed-marker",
            ),
        )
        return CompiledExistingInstallationReinstall(workerScope, workDir, steps)
    }

    fun workerDirectory(scope: InstallerWorkerScope): String? {
        if (!managedIdRegex.matches(scope.managedInstallId.value) || scope.operationId.value.isBlank()) return null
        return "$REINSTALL_WORK_ROOT/${scope.managedInstallId.value}/${operationTag(scope.operationId.value)}"
    }

    private fun compiled(
        kind: ExistingInstallationReinstallStepKind,
        raw: String,
        timeout: Duration,
        label: String,
    ) = CompiledExistingInstallationReinstallStep(
        kind = kind,
        command = RemoteCommand.create(raw, label),
        config = SshTransportConfig(
            channelOpenTimeout = timeout.coerceAtMost(maxChannelOpenTimeout),
            commandExecutionTimeout = timeout,
            stdoutCaptureLimitBytes = 2 * 1024,
            stderrCaptureLimitBytes = 2 * 1024,
        ),
    )

    private fun prepareWorkerCommand(workDir: String): String = """
        set -eu
        umask 077
        root=${shellQuote(REINSTALL_WORK_ROOT)}
        managed=${shellQuote(workDir.substringBeforeLast('/'))}
        work=${shellQuote(workDir)}
        install -d -m 0700 "${'$'}root"
        install -d -m 0700 "${'$'}managed"
        [ ! -e "${'$'}work" ] || exit 73
        install -d -m 0700 "${'$'}work"
    """.trimIndent()

    private fun fetchInstallerCommand(workDir: String, installerPath: String): String = """
        set -eu
        umask 077
        work=${shellQuote(workDir)}
        target=${shellQuote(installerPath)}
        part="${'$'}target.part"
        [ -d "${'$'}work" ] || exit 70
        [ ! -e "${'$'}target" ] && [ ! -e "${'$'}part" ] || exit 73
        command -v curl >/dev/null 2>&1 || exit 69
        command -v sha1sum >/dev/null 2>&1 || exit 69
        curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --connect-timeout 15 --max-time 120 --retry 2 --retry-delay 2 --retry-connrefused -o "${'$'}part" ${shellQuote(InstallerReviewedCommandCompiler.PINNED_INSTALLER_URL)}
        size=${'$'}(wc -c < "${'$'}part" | tr -d '[:space:]')
        actual=${'$'}( (printf 'blob %s\000' "${'$'}size"; cat "${'$'}part") | sha1sum | awk '{print ${'$'}1}' )
        [ "${'$'}actual" = ${shellQuote(InstallerReviewedCommandCompiler.PINNED_INSTALLER_GIT_BLOB_SHA1)} ] || { rm -f "${'$'}part"; exit 74; }
        chmod 0700 "${'$'}part"
        mv "${'$'}part" "${'$'}target"
    """.trimIndent()

    private fun executeInstallerCommand(
        workDir: String,
        installerPath: String,
        workerPath: String,
    ): String = """
        set -eu
        umask 077
        work=${shellQuote(workDir)}
        installer=${shellQuote(installerPath)}
        worker=${shellQuote(workerPath)}
        terminal="${'$'}work/terminal"
        pidfile="${'$'}work/pid"
        pgidfile="${'$'}work/pgid"
        [ -x "${'$'}installer" ] || exit 70
        [ ! -e "${'$'}worker" ] && [ ! -e "${'$'}terminal" ] && [ ! -e "${'$'}pidfile" ] || exit 73
        command -v setsid >/dev/null 2>&1 || exit 69
        cat > "${'$'}worker" <<'VELUM_REINSTALL_WORKER_EOF'
#!/bin/sh
set +e
work_dir=${'$'}(CDPATH= cd -- "${'$'}(dirname -- "${'$'}0")" && pwd)
heartbeat="${'$'}work_dir/heartbeat"
heartbeat_tmp="${'$'}work_dir/.heartbeat.tmp"
terminal="${'$'}work_dir/terminal"
terminal_tmp="${'$'}work_dir/.terminal.tmp"
heartbeat_loop() {
    while :; do
        date +%s > "${'$'}heartbeat_tmp" 2>/dev/null && mv -f "${'$'}heartbeat_tmp" "${'$'}heartbeat"
        sleep 5
    done
}
heartbeat_loop &
hb_pid=${'$'}!
trap 'kill "${'$'}hb_pid" >/dev/null 2>&1 || true' EXIT HUP INT TERM
XUI_NONINTERACTIVE=1 "${'$'}work_dir/install.sh" ${InstallerReviewedCommandCompiler.PINNED_3X_UI_VERSION} >/dev/null 2>&1
code=${'$'}?
kill "${'$'}hb_pid" >/dev/null 2>&1 || true
wait "${'$'}hb_pid" 2>/dev/null || true
if [ "${'$'}code" -eq 0 ]; then
    printf 'SUCCESS\n' > "${'$'}terminal_tmp"
else
    printf 'FAILED:%s\n' "${'$'}code" > "${'$'}terminal_tmp"
fi
mv -f "${'$'}terminal_tmp" "${'$'}terminal"
exit "${'$'}code"
VELUM_REINSTALL_WORKER_EOF
        chmod 0700 "${'$'}worker"
        nohup setsid "${'$'}worker" </dev/null >/dev/null 2>&1 &
        pid=${'$'}!
        printf '%s\n' "${'$'}pid" > "${'$'}pidfile.tmp"
        mv "${'$'}pidfile.tmp" "${'$'}pidfile"
        printf '%s\n' "${'$'}pid" > "${'$'}pgidfile.tmp"
        mv "${'$'}pgidfile.tmp" "${'$'}pgidfile"
        deadline=${'$'}(( ${'$'}(date +%s) + 895 ))
        while [ ${'$'}(date +%s) -le "${'$'}deadline" ]; do
            if [ -f "${'$'}terminal" ]; then
                state=${'$'}(cat -- "${'$'}terminal")
                case "${'$'}state" in
                    SUCCESS) exit 0 ;;
                    FAILED:*) exit 1 ;;
                    *) exit 76 ;;
                esac
            fi
            sleep 2
        done
        exit 75
    """.trimIndent()

    /** Existing exact marker is accepted only when it already matches this managed identity. */
    private fun writeMarkerCommand(managedId: String): String {
        val path = ManagedInstallMarkerProtocol.MARKER_PATH
        val dir = path.substringBeforeLast('/')
        val marker = ManagedInstallMarkerProtocol.encode(com.velumtegra.xuimobile.core.model.ManagedInstallId(managedId)).removeSuffix("\n")
        val tmp = "$dir/.identity.$managedId.reinstall.tmp"
        return """
            set -eu
            umask 077
            dir=${shellQuote(dir)}
            path=${shellQuote(path)}
            tmp=${shellQuote(tmp)}
            expected=${shellQuote(marker)}
            if [ -f "${'$'}path" ]; then
                actual=${'$'}(cat -- "${'$'}path") || exit 74
                [ "${'$'}actual" = "${'$'}expected" ] || exit 74
            else
                [ ! -e "${'$'}tmp" ] || exit 73
                install -d -m 0700 "${'$'}dir"
                printf '%s\n' "${'$'}expected" > "${'$'}tmp"
                chmod 0600 "${'$'}tmp"
                mv "${'$'}tmp" "${'$'}path"
            fi
        """.trimIndent()
    }

    private fun operationTag(operationId: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(operationId.toByteArray(StandardCharsets.UTF_8))
        return digest.take(12).joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"
}

/** Read-only Phase 9.7 verifier for the action-scoped worker, marker and new installation facts. */
class ExistingInstallationReinstallPostVerifySshAdapter(
    private val now: () -> Instant = Instant::now,
    private val deathRecheckDelay: Duration = InstallerWorkerLivenessPolicy.MIN_DEATH_RECHECK_DELAY,
) {
    suspend fun verify(
        current: VersionedOperationSnapshot,
        managedInstallId: com.velumtegra.xuimobile.core.model.ManagedInstallId,
        session: SshSessionHandle,
    ): ExistingInstallationReinstallPostVerifyResult {
        val target = current.snapshot.target as? OperationTarget.InstallationTarget
            ?: return ExistingInstallationReinstallPostVerifyResult.Rejected(
                ExistingInstallationReinstallPostVerifyFailure.ScopeTargetMismatch,
            )
        if (current.snapshot.type != OperationType.REINSTALL ||
            current.snapshot.checkpoint.semantics != CheckpointSemantics.POST_VERIFY_REQUIRED ||
            current.snapshot.status !in setOf(OperationStatus.RUNNING, OperationStatus.RECONCILIATION_REQUIRED)
        ) return ExistingInstallationReinstallPostVerifyResult.Rejected(
            ExistingInstallationReinstallPostVerifyFailure.ScopeTargetMismatch,
        )
        val scope = InstallerWorkerScope(
            operationId = current.snapshot.operationId,
            serverId = target.serverId,
            serverAccessId = target.serverAccessId,
            managedInstallId = managedInstallId,
        )
        if (session.binding.owner != SessionOwner.Operation(scope.operationId) ||
            session.binding.serverAccessId != scope.serverAccessId
        ) return ExistingInstallationReinstallPostVerifyResult.Rejected(
            ExistingInstallationReinstallPostVerifyFailure.ExactSessionBindingMismatch,
        )
        if (!session.isOpen) return ExistingInstallationReinstallPostVerifyResult.Rejected(
            ExistingInstallationReinstallPostVerifyFailure.SessionClosed,
        )

        val first = readWorker(scope, session)
            ?: return ExistingInstallationReinstallPostVerifyResult.ReconciliationRequired(
                ExistingInstallationReinstallPostVerifyReason.WORKER_EVIDENCE_UNREADABLE,
            )
        var evidence = first
        var liveness = InstallerWorkerLivenessPolicy.classify(scope, evidence, now())
        if (liveness is InstallerWorkerLiveness.Unknown && shouldConfirmDeath(evidence, now())) {
            currentCoroutineContext().ensureActive()
            delay(deathRecheckDelay.toMillis())
            currentCoroutineContext().ensureActive()
            val second = readWorker(scope, session)
                ?: return ExistingInstallationReinstallPostVerifyResult.ReconciliationRequired(
                    ExistingInstallationReinstallPostVerifyReason.WORKER_EVIDENCE_UNREADABLE,
                )
            evidence = first.copy(
                confirmationProcessState = second.primaryProcessState,
                confirmationObservedAt = second.primaryObservedAt,
                terminalState = if (second.terminalState != InstallerWorkerTerminalState.NONE) second.terminalState else first.terminalState,
                terminalObservedAt = second.terminalObservedAt ?: first.terminalObservedAt,
                heartbeatAt = maxInstant(first.heartbeatAt, second.heartbeatAt),
            )
            liveness = InstallerWorkerLivenessPolicy.classify(scope, evidence, now())
        }
        when (liveness) {
            InstallerWorkerLiveness.TerminalSuccess -> Unit
            InstallerWorkerLiveness.KnownAlive -> return ExistingInstallationReinstallPostVerifyResult.WorkerStillRunning(evidence)
            InstallerWorkerLiveness.TerminalFailure -> return reconciliation(ExistingInstallationReinstallPostVerifyReason.WORKER_TERMINAL_FAILURE, evidence)
            InstallerWorkerLiveness.ProvenDead -> return reconciliation(ExistingInstallationReinstallPostVerifyReason.WORKER_DIED_WITHOUT_SUCCESS, evidence)
            is InstallerWorkerLiveness.Unknown -> return reconciliation(ExistingInstallationReinstallPostVerifyReason.WORKER_STATE_UNKNOWN, evidence)
        }

        val marker = readMarker(scope, session)
            ?: return reconciliation(ExistingInstallationReinstallPostVerifyReason.MANAGED_MARKER_UNREADABLE, evidence)
        val facts = readFacts(scope, marker, session)
            ?: return reconciliation(ExistingInstallationReinstallPostVerifyReason.INSTALLATION_FACTS_UNREADABLE, evidence)
        return when (val decision = InstallerPostInstallPolicy.verify(scope, facts)) {
            is InstallerPostInstallVerificationDecision.Verified ->
                ExistingInstallationReinstallPostVerifyResult.Verified(
                    facts = facts,
                    verifiedBaseline = decision.request.baseline,
                    workerEvidence = evidence,
                )
            is InstallerPostInstallVerificationDecision.Rejected ->
                reconciliation(ExistingInstallationReinstallPostVerifyReason.INSTALLATION_FACTS_REJECTED, evidence)
        }
    }

    private suspend fun readWorker(scope: InstallerWorkerScope, session: SshSessionHandle): InstallerWorkerEvidence? {
        val work = ExistingInstallationReinstallCommandCompiler.workerDirectory(scope) ?: return null
        val raw = """
            set -eu
            work=${shellQuote(work)}
            [ -d "${'$'}work" ] || exit 44
            terminal=NONE
            if [ -f "${'$'}work/terminal" ]; then
                terminal=${'$'}(cat -- "${'$'}work/terminal" 2>/dev/null || true)
                case "${'$'}terminal" in SUCCESS|FAILED:[0-9]*) ;; *) terminal=UNKNOWN ;; esac
            fi
            heartbeat=NONE
            if [ -f "${'$'}work/heartbeat" ]; then
                heartbeat=${'$'}(cat -- "${'$'}work/heartbeat" 2>/dev/null || true)
                case "${'$'}heartbeat" in ''|*[!0-9]*) heartbeat=INVALID ;; esac
            fi
            process=UNKNOWN
            if [ -f "${'$'}work/pid" ]; then
                pid=${'$'}(cat -- "${'$'}work/pid" 2>/dev/null || true)
                case "${'$'}pid" in ''|*[!0-9]*) process=UNKNOWN ;; *) if kill -0 "${'$'}pid" 2>/dev/null; then process=ALIVE; else process=DEAD; fi ;; esac
            fi
            printf 'PROCESS=%s\nHEARTBEAT=%s\nTERMINAL=%s\n' "${'$'}process" "${'$'}heartbeat" "${'$'}terminal"
        """.trimIndent()
        val result = executeReadOnly(session, RemoteCommand.create(raw, "phase9-reinstall-worker-readback"), WORKER_CONFIG) ?: return null
        return InstallerPostInstallParsers.parseWorkerEvidence(scope, result, now())
    }

    private suspend fun readMarker(
        scope: InstallerWorkerScope,
        session: SshSessionHandle,
    ): ManagedInstallMarkerReadbackState? {
        val path = ManagedInstallMarkerProtocol.MARKER_PATH
        val command = RemoteCommand.create(
            "if [ -f ${shellQuote(path)} ]; then cat -- ${shellQuote(path)}; else exit 44; fi",
            "phase9-reinstall-marker-readback",
        )
        currentCoroutineContext().ensureActive()
        val result = session.execute(command, MARKER_CONFIG)
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.stdout.truncated) return null
        when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> Unit
            is CommandCompletion.ConfirmedFailure -> return if (completion.exitCode == 44) ManagedInstallMarkerReadbackState.ABSENT else null
            is CommandCompletion.Unknown -> return null
        }
        val raw = strictText(result.stdout) ?: return null
        return ManagedInstallMarkerProtocol.classifyReadback(scope.managedInstallId, raw)
    }

    private suspend fun readFacts(
        scope: InstallerWorkerScope,
        marker: ManagedInstallMarkerReadbackState,
        session: SshSessionHandle,
    ): InstallerPostInstallFacts? {
        val command = InstallerPostInstallReadOnlyCompiler.installationFacts(scope) ?: return null
        val raw = executeReadOnly(session, command, FACTS_CONFIG) ?: return null
        return InstallerPostInstallParsers.parseInstallationFacts(raw, marker, now())
    }

    private suspend fun executeReadOnly(
        session: SshSessionHandle,
        command: RemoteCommand,
        config: SshTransportConfig,
    ): String? {
        currentCoroutineContext().ensureActive()
        val result = session.execute(command, config)
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED ||
            result.completion !is CommandCompletion.ConfirmedSuccess ||
            result.stdout.truncated
        ) return null
        return strictText(result.stdout)
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

    private fun shouldConfirmDeath(evidence: InstallerWorkerEvidence, at: Instant): Boolean {
        if (evidence.terminalState != InstallerWorkerTerminalState.NONE) return false
        if (evidence.primaryProcessState != InstallerWorkerProcessState.DEAD) return false
        val heartbeat = evidence.heartbeatAt ?: return false
        return Duration.between(heartbeat, at) > InstallerWorkerLivenessPolicy.HEARTBEAT_STALE_AFTER
    }

    private fun reconciliation(
        reason: ExistingInstallationReinstallPostVerifyReason,
        evidence: InstallerWorkerEvidence,
    ) = ExistingInstallationReinstallPostVerifyResult.ReconciliationRequired(reason, evidence)

    private fun maxInstant(a: Instant?, b: Instant?): Instant? = when {
        a == null -> b
        b == null -> a
        a >= b -> a
        else -> b
    }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"

    companion object {
        private val WORKER_CONFIG = SshTransportConfig(
            channelOpenTimeout = Duration.ofSeconds(5),
            commandExecutionTimeout = Duration.ofSeconds(5),
            stdoutCaptureLimitBytes = 512,
            stderrCaptureLimitBytes = 512,
        )
        private val MARKER_CONFIG = SshTransportConfig(
            channelOpenTimeout = Duration.ofSeconds(5),
            commandExecutionTimeout = Duration.ofSeconds(5),
            stdoutCaptureLimitBytes = 256,
            stderrCaptureLimitBytes = 256,
        )
        private val FACTS_CONFIG = SshTransportConfig(
            channelOpenTimeout = Duration.ofSeconds(5),
            commandExecutionTimeout = Duration.ofSeconds(10),
            stdoutCaptureLimitBytes = 4096,
            stderrCaptureLimitBytes = 1024,
        )
    }
}

sealed interface ExistingInstallationReinstallPostVerifyResult {
    data class Verified(
        val facts: InstallerPostInstallFacts,
        val verifiedBaseline: com.velumtegra.xuimobile.core.model.InstallationBaseline,
        val workerEvidence: InstallerWorkerEvidence,
    ) : ExistingInstallationReinstallPostVerifyResult

    data class WorkerStillRunning(val workerEvidence: InstallerWorkerEvidence) : ExistingInstallationReinstallPostVerifyResult
    data class ReconciliationRequired(
        val reason: ExistingInstallationReinstallPostVerifyReason,
        val workerEvidence: InstallerWorkerEvidence? = null,
    ) : ExistingInstallationReinstallPostVerifyResult
    data class Rejected(val failure: ExistingInstallationReinstallPostVerifyFailure) : ExistingInstallationReinstallPostVerifyResult
}

enum class ExistingInstallationReinstallPostVerifyFailure {
    ScopeTargetMismatch,
    ExactSessionBindingMismatch,
    SessionClosed,
}

enum class ExistingInstallationReinstallPostVerifyReason {
    WORKER_EVIDENCE_UNREADABLE,
    WORKER_TERMINAL_FAILURE,
    WORKER_DIED_WITHOUT_SUCCESS,
    WORKER_STATE_UNKNOWN,
    MANAGED_MARKER_UNREADABLE,
    INSTALLATION_FACTS_UNREADABLE,
    INSTALLATION_FACTS_REJECTED,
}
