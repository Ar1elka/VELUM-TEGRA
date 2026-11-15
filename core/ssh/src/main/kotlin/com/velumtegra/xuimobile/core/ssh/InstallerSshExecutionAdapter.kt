package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.InstallerCheckpointPolicy
import com.velumtegra.xuimobile.core.domain.ManagedInstallMarkerProtocol
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.ReviewedInstallPlanPolicy
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.FreshInstallInstallerCapability
import com.velumtegra.xuimobile.core.model.InstallerPhase
import com.velumtegra.xuimobile.core.model.InstallerPlanStep
import com.velumtegra.xuimobile.core.model.InstallerPlanStepKind
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ReviewedInstallPlan
import com.velumtegra.xuimobile.core.model.SessionOwner
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/**
 * Phase 8.4 narrow SSH adapter for one exact reviewed fresh-install plan.
 *
 * The adapter owns no connection lookup/retry framework. It consumes one already-open exact
 * operation-owned session, commits the durable MUTATION_IN_FLIGHT checkpoint before the first
 * remote write, executes only the fixed compiler below, never retries after dispatch uncertainty,
 * and stops at POST_VERIFY_REQUIRED even on the happy path. Phase 8.6 owns authoritative install
 * verification/publication.
 */
class InstallerSshExecutionAdapter(
    private val journal: OperationJournal,
    private val now: () -> Instant = Instant::now,
) {
    suspend fun execute(
        plan: ReviewedInstallPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): InstallerSshExecutionResult {
        val preflightFailure = validateBeforeCheckpoint(plan, current, session)
        if (preflightFailure != null) {
            return InstallerSshExecutionResult.Rejected(preflightFailure)
        }

        currentCoroutineContext().ensureActive()
        val checkpointed = advancePredispatch(current)
            ?: return InstallerSshExecutionResult.Rejected(
                InstallerSshExecutionFailure.PredispatchCheckpointRejected,
            )

        val compiled = InstallerReviewedCommandCompiler.compile(plan)
            ?: return requireReconciliation(
                checkpointed,
                InstallerReconciliationReason.PLAN_COMPILATION_REJECTED_AFTER_CHECKPOINT,
            )

        var durable = checkpointed
        for (step in compiled.steps) {
            currentCoroutineContext().ensureActive()
            val result = session.execute(step.command, step.config)
            currentCoroutineContext().ensureActive()

            if (result.dispatchState != CommandDispatchState.DISPATCHED) {
                return requireReconciliation(
                    durable,
                    InstallerReconciliationReason.DISPATCH_NOT_CONFIRMED,
                )
            }

            when (result.completion) {
                CommandCompletion.ConfirmedSuccess -> Unit
                is CommandCompletion.ConfirmedFailure -> {
                    return requireReconciliation(
                        durable,
                        InstallerReconciliationReason.REMOTE_STEP_FAILED,
                    )
                }
                is CommandCompletion.Unknown -> {
                    return requireReconciliation(
                        durable,
                        InstallerReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
                    )
                }
            }
        }

        val markerReadback = readBackManagedMarker(plan, session)
        when (markerReadback) {
            ManagedInstallMarkerReadbackState.MATCH -> Unit
            ManagedInstallMarkerReadbackState.ABSENT -> {
                return requireReconciliation(durable, InstallerReconciliationReason.MANAGED_MARKER_ABSENT)
            }
            ManagedInstallMarkerReadbackState.MISMATCH -> {
                return requireReconciliation(durable, InstallerReconciliationReason.MANAGED_MARKER_MISMATCH)
            }
            ManagedInstallMarkerReadbackState.MALFORMED -> {
                return requireReconciliation(durable, InstallerReconciliationReason.MANAGED_MARKER_MALFORMED)
            }
        }

        durable = advancePostVerifyRequired(durable)
            ?: return requireReconciliation(
                durable,
                InstallerReconciliationReason.POST_VERIFY_CHECKPOINT_REJECTED,
            )

        return InstallerSshExecutionResult.AwaitingVerification(
            durable = durable,
            markerReadback = markerReadback,
        )
    }

    /**
     * Explicit-consent route: after the same MUTATION_IN_FLIGHT CAS, only short commands run. They take an
     * atomic cross-client guard, prepare a private worker directory, write the worker and start it detached.
     * Download (pinned hash), install and marker publication all happen inside the detached worker, so the
     * client never waits. On confirmed hand-off the durable checkpoint becomes POST_VERIFY_REQUIRED; any
     * refusal or uncertainty keeps the barrier and is resolved by read-only reconciliation, never replay.
     */
    suspend fun launchDetached(
        plan: ReviewedInstallPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): InstallerSshExecutionResult {
        val preflightFailure = validateBeforeCheckpoint(plan, current, session)
        if (preflightFailure != null) {
            return InstallerSshExecutionResult.Rejected(preflightFailure)
        }

        currentCoroutineContext().ensureActive()
        val checkpointed = advancePredispatch(current)
            ?: return InstallerSshExecutionResult.Rejected(
                InstallerSshExecutionFailure.PredispatchCheckpointRejected,
            )

        val compiled = InstallerReviewedCommandCompiler.compileDetached(plan)
            ?: return requireReconciliation(
                checkpointed,
                InstallerReconciliationReason.PLAN_COMPILATION_REJECTED_AFTER_CHECKPOINT,
            )

        for (step in compiled.steps) {
            currentCoroutineContext().ensureActive()
            val result = session.execute(step.command, step.config)
            currentCoroutineContext().ensureActive()

            if (result.dispatchState != CommandDispatchState.DISPATCHED) {
                return requireReconciliation(checkpointed, InstallerReconciliationReason.DISPATCH_NOT_CONFIRMED)
            }
            when (val completion = result.completion) {
                CommandCompletion.ConfirmedSuccess -> Unit
                is CommandCompletion.ConfirmedFailure -> {
                    return requireReconciliation(
                        checkpointed,
                        if (completion.exitCode == INSTALL_GUARD_HELD_EXIT_CODE) {
                            InstallerReconciliationReason.INSTALL_GUARD_HELD
                        } else {
                            InstallerReconciliationReason.REMOTE_STEP_FAILED
                        },
                    )
                }
                is CommandCompletion.Unknown -> {
                    return requireReconciliation(
                        checkpointed,
                        InstallerReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
                    )
                }
            }
        }

        val durable = advancePostVerifyRequired(checkpointed)
            ?: return requireReconciliation(
                checkpointed,
                InstallerReconciliationReason.POST_VERIFY_CHECKPOINT_REJECTED,
            )
        return InstallerSshExecutionResult.DetachedWorkerLaunched(durable)
    }

    private fun validateBeforeCheckpoint(
        plan: ReviewedInstallPlan,
        current: VersionedOperationSnapshot,
        session: SshSessionHandle,
    ): InstallerSshExecutionFailure? {
        if (!ReviewedInstallPlanPolicy.isCanonical(plan) ||
            plan.scope.operationId.value.isBlank() ||
            plan.scope.serverId.value.isBlank() ||
            plan.scope.serverAccessId.value.isBlank()
        ) {
            return InstallerSshExecutionFailure.PlanOutsideApprovedPolicy
        }
        val snapshot = current.snapshot
        val target = snapshot.target as? OperationTarget.ServerTarget
            ?: return InstallerSshExecutionFailure.ScopeTargetMismatch
        if (snapshot.type != OperationType.INSTALL ||
            snapshot.operationId != plan.scope.operationId ||
            target.serverId != plan.scope.serverId ||
            target.serverAccessId != plan.scope.serverAccessId
        ) {
            return InstallerSshExecutionFailure.ScopeTargetMismatch
        }
        if (snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED) {
            return InstallerSshExecutionFailure.NotAtPredispatchCheckpoint
        }
        if (session.binding.owner != SessionOwner.Operation(plan.scope.operationId) ||
            session.binding.serverAccessId != plan.scope.serverAccessId
        ) {
            return InstallerSshExecutionFailure.ExactSessionBindingMismatch
        }
        if (!session.isOpen) return InstallerSshExecutionFailure.SessionClosed
        return null
    }

    private suspend fun advancePredispatch(
        current: VersionedOperationSnapshot,
    ): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = InstallerPhase.DOWNLOADING.name,
                semantics = InstallerCheckpointPolicy.forPhase(InstallerPhase.DOWNLOADING),
                recordedAt = at,
            ),
            updatedAt = at,
        )
        return when (val advanced = journal.advance(current.snapshot.operationId, current.revision, next)) {
            is OperationJournalResult.Success -> advanced.value
            else -> null
        }
    }

    private suspend fun advancePostVerifyRequired(
        current: VersionedOperationSnapshot,
    ): VersionedOperationSnapshot? {
        val at = now()
        if (at.isBefore(current.snapshot.updatedAt)) return null
        val next = current.snapshot.copy(
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = InstallerPhase.VERIFYING.name,
                semantics = InstallerCheckpointPolicy.forPhase(InstallerPhase.VERIFYING),
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
        reason: InstallerReconciliationReason,
    ): InstallerSshExecutionResult.ReconciliationRequired {
        val at = now()
        val next = if (at.isBefore(current.snapshot.updatedAt)) {
            null
        } else {
            current.snapshot.copy(
                status = OperationStatus.RECONCILIATION_REQUIRED,
                checkpoint = OperationCheckpoint(
                    phaseName = "INSTALLER_RECONCILIATION_REQUIRED",
                    semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
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
        return InstallerSshExecutionResult.ReconciliationRequired(
            durable = recorded ?: current,
            reason = reason,
            reconciliationCheckpointRecorded = recorded != null,
        )
    }

    private suspend fun readBackManagedMarker(
        plan: ReviewedInstallPlan,
        session: SshSessionHandle,
    ): ManagedInstallMarkerReadbackState {
        val readback = InstallerReviewedCommandCompiler.compileMarkerReadback(plan)
            ?: return ManagedInstallMarkerReadbackState.MALFORMED
        currentCoroutineContext().ensureActive()
        val result = session.execute(readback.command, readback.config)
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED) {
            return ManagedInstallMarkerReadbackState.MALFORMED
        }
        when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> Unit
            is CommandCompletion.ConfirmedFailure -> {
                return if (completion.exitCode == MARKER_ABSENT_EXIT_CODE) {
                    ManagedInstallMarkerReadbackState.ABSENT
                } else {
                    ManagedInstallMarkerReadbackState.MALFORMED
                }
            }
            is CommandCompletion.Unknown -> return ManagedInstallMarkerReadbackState.MALFORMED
        }
        if (result.stdout.truncated) return ManagedInstallMarkerReadbackState.MALFORMED
        val bytes = result.stdout.copyBytes()
        val raw = try {
            decodeUtf8Strict(bytes) ?: return ManagedInstallMarkerReadbackState.MALFORMED
        } finally {
            Arrays.fill(bytes, 0)
        }
        return ManagedInstallMarkerProtocol.classifyReadback(plan.scope.managedInstallId, raw)
    }

    private fun decodeUtf8Strict(bytes: ByteArray): String? = runCatching {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    }.getOrNull()

    companion object {
        private const val MARKER_ABSENT_EXIT_CODE = 44
        private const val INSTALL_GUARD_HELD_EXIT_CODE = 77
    }
}

sealed interface InstallerSshExecutionResult {
    /**
     * The detached worker was handed off and the durable checkpoint is POST_VERIFY_REQUIRED. Nothing was
     * awaited: completion is observed later, read-only, by the existing post-install verifier.
     */
    data class DetachedWorkerLaunched(val durable: VersionedOperationSnapshot) : InstallerSshExecutionResult

    data class AwaitingVerification(
        val durable: VersionedOperationSnapshot,
        val markerReadback: ManagedInstallMarkerReadbackState,
    ) : InstallerSshExecutionResult

    data class Rejected(val failure: InstallerSshExecutionFailure) : InstallerSshExecutionResult

    data class ReconciliationRequired(
        val durable: VersionedOperationSnapshot,
        val reason: InstallerReconciliationReason,
        val reconciliationCheckpointRecorded: Boolean,
    ) : InstallerSshExecutionResult
}

enum class InstallerSshExecutionFailure {
    PlanOutsideApprovedPolicy,
    ScopeTargetMismatch,
    NotAtPredispatchCheckpoint,
    ExactSessionBindingMismatch,
    SessionClosed,
    PredispatchCheckpointRejected,
}

enum class InstallerReconciliationReason {
    PLAN_COMPILATION_REJECTED_AFTER_CHECKPOINT,
    DISPATCH_NOT_CONFIRMED,
    REMOTE_STEP_FAILED,
    TRANSPORT_UNCERTAIN_AFTER_DISPATCH,
    MANAGED_MARKER_ABSENT,
    MANAGED_MARKER_MISMATCH,
    MANAGED_MARKER_MALFORMED,
    POST_VERIFY_CHECKPOINT_REJECTED,
    INSTALL_GUARD_HELD,
}

internal data class CompiledInstallerStep(
    val kind: InstallerPlanStepKind,
    val command: RemoteCommand,
    val config: SshTransportConfig,
)

internal data class CompiledInstallerPlan(
    val steps: List<CompiledInstallerStep>,
)

internal object InstallerReviewedCommandCompiler {
    const val PINNED_3X_UI_VERSION: String = "v3.7.0"
    const val PINNED_INSTALLER_URL: String =
        "https://raw.githubusercontent.com/MHSanaei/3x-ui/v3.7.0/install.sh"
    const val PINNED_INSTALLER_GIT_BLOB_SHA1: String = "4ff60a069362e618d5149abc4cbc5246629c93ea"

    private const val WORK_ROOT = "/var/lib/velum-tegra/installer/v1"
    private const val MARKER_ABSENT_EXIT_CODE = 44
    private val managedIdRegex = Regex("v1-[0-9a-f]{32}")

    /**
     * Every external utility the reviewed commands below (including the embedded worker) invoke.
     * Read-only fresh-install readiness observation must prove all of them resolvable before a
     * target can ever be considered ready. Keep in sync: a unit test cross-checks this list
     * against the compiled command text.
     */
    internal val REQUIRED_REMOTE_TOOLS: List<String> = listOf(
        "sh", "install", "curl", "sha1sum", "wc", "tr", "cat", "awk", "mv", "rm",
        "chmod", "setsid", "nohup", "date", "sleep", "dirname", "ln", "mkdir",
    )

    private val maxChannelOpenTimeout: Duration = Duration.ofSeconds(5)

    /**
     * Best-effort post-install prerequisite for every later read-only management probe (status,
     * backup, diagnostics read panel settings through the sqlite3 CLI). The pinned 3x-ui installer
     * does not install it. Runs only after a successful installer and never changes the install
     * outcome: a missing apt-get, a held lock or a failed download simply leaves sqlite3 absent.
     * A fresh VPS usually still runs unattended-upgrades, so the dpkg lock is awaited, not raced.
     */
    internal val ENSURE_SQLITE_CLI_STEP: String = """
        if ! command -v sqlite3 >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
            apt_env="DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l"
            env ${'$'}apt_env apt-get install -y -q --no-install-recommends -o DPkg::Lock::Timeout=600 sqlite3 >/dev/null 2>&1 ||
                { env ${'$'}apt_env apt-get update -q -o DPkg::Lock::Timeout=600 >/dev/null 2>&1 &&
                  env ${'$'}apt_env apt-get install -y -q --no-install-recommends -o DPkg::Lock::Timeout=600 sqlite3 >/dev/null 2>&1; } ||
                true
        fi
        # End-of-life Debian: the security index still names the candidate, but its pool moved to
        # archive.debian.org (404 above). Fetch exactly that file and accept it only if it matches the
        # SHA-256 from the signed apt index; the same version keeps libsqlite3-0 untouched.
        if ! command -v sqlite3 >/dev/null 2>&1 && command -v apt-cache >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
            cand=${'$'}(apt-cache policy sqlite3 2>/dev/null | awk '/Candidate:/ {print ${'$'}2; exit}')
            meta=${'$'}(apt-cache show "sqlite3=${'$'}cand" 2>/dev/null)
            file=${'$'}(printf '%s\n' "${'$'}meta" | awk '/^Filename:/ {print ${'$'}2; exit}')
            sum=${'$'}(printf '%s\n' "${'$'}meta" | awk '/^SHA256:/ {print ${'$'}2; exit}')
            case "${'$'}file" in
                pool/updates/*.deb)
                    deb=${'$'}(mktemp) &&
                        curl -fsS --max-time 120 -o "${'$'}deb" "http://archive.debian.org/debian-security/${'$'}file" >/dev/null 2>&1 &&
                        printf '%s  %s\n' "${'$'}sum" "${'$'}deb" | sha256sum -c --quiet - >/dev/null 2>&1 &&
                        env DEBIAN_FRONTEND=noninteractive dpkg -i "${'$'}deb" >/dev/null 2>&1
                    rm -f "${'$'}deb"
                    ;;
            esac
        fi
    """.trimIndent()

    fun compile(plan: ReviewedInstallPlan): CompiledInstallerPlan? {
        if (!ReviewedInstallPlanPolicy.isCanonical(plan)) return null
        val managedId = plan.scope.managedInstallId.value
        if (!managedIdRegex.matches(managedId)) return null
        val workDir = "$WORK_ROOT/$managedId"
        val installerPath = "$workDir/install.sh"
        val workerPath = "$workDir/worker.sh"

        val compiled = plan.steps.map { step ->
            val raw = when (step) {
                is InstallerPlanStep.PrepareWorker -> prepareWorkerCommand(workDir)
                is InstallerPlanStep.FetchReviewedInstaller -> {
                    if (step.capability != FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1) return null
                    fetchInstallerCommand(workDir, installerPath)
                }
                is InstallerPlanStep.ExecuteReviewedInstaller -> {
                    if (step.capability != FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1) return null
                    executeInstallerCommand(workDir, installerPath, workerPath)
                }
                is InstallerPlanStep.WriteManagedMarker -> {
                    if (step.managedInstallId != plan.scope.managedInstallId) return null
                    writeMarkerCommand(plan)
                }
            }
            CompiledInstallerStep(
                kind = step.kind,
                command = RemoteCommand.create(raw, "installer-${step.kind.name.lowercase()}"),
                config = transportConfig(step.timeout),
            )
        }
        return CompiledInstallerPlan(compiled)
    }

    /**
     * Detached-worker variant for the explicit-consent route. Three short commands only; the worker file
     * itself carries download+hash check, installer execution and no-overwrite marker publication.
     */
    fun compileDetached(plan: ReviewedInstallPlan): CompiledInstallerPlan? {
        if (!ReviewedInstallPlanPolicy.isCanonical(plan)) return null
        if (plan.capability != FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1) return null
        val managedId = plan.scope.managedInstallId.value
        if (!managedIdRegex.matches(managedId)) return null
        val workDir = "$WORK_ROOT/$managedId"
        val installerPath = "$workDir/install.sh"
        val workerPath = "$workDir/worker.sh"
        val timeout = ReviewedInstallPlanPolicy.PREPARE_WORKER_TIMEOUT
        fun step(kind: InstallerPlanStepKind, label: String, raw: String) = CompiledInstallerStep(
            kind = kind,
            command = RemoteCommand.create(raw, label),
            config = transportConfig(timeout),
        )
        return CompiledInstallerPlan(
            listOf(
                step(InstallerPlanStepKind.PREPARE_WORKER, "installer-detached-guard-prepare", guardAndPrepareCommand(managedId, workDir)),
                step(
                    InstallerPlanStepKind.PREPARE_WORKER,
                    "installer-detached-write-worker",
                    writeDetachedWorkerCommand(workerPath, detachedWorkerScript(plan, workDir, installerPath)),
                ),
                step(InstallerPlanStepKind.EXECUTE_REVIEWED_INSTALLER, "installer-detached-spawn", spawnDetachedWorkerCommand(workDir, workerPath)),
            ),
        )
    }

    /**
     * Atomic cross-client guard: mkdir is atomic, so only one client (not just one operation) can pass.
     * It is deliberately never removed automatically (not on disconnect, not by the worker).
     * Exit 77 = guard already held, 78 = guard could not be created for another reason.
     */
    private fun guardAndPrepareCommand(managedId: String, workDir: String): String = """
        set -eu
        umask 077
        root=${shellQuote(WORK_ROOT)}
        work=${shellQuote(workDir)}
        guard="${'$'}root/.install-guard"
        install -d -m 0700 "${'$'}root"
        if ! mkdir -m 0700 "${'$'}guard" 2>/dev/null; then
            if [ -d "${'$'}guard" ]; then exit 77; fi
            exit 78
        fi
        printf '%s\n' ${shellQuote(managedId)} > "${'$'}guard/owner"
        [ ! -e "${'$'}work" ] || exit 73
        install -d -m 0700 "${'$'}work"
    """.trimIndent()

    private fun writeDetachedWorkerCommand(workerPath: String, script: String): String =
        "set -eu\numask 077\nworker=${shellQuote(workerPath)}\n" +
            "[ ! -e \"${'$'}worker\" ] || exit 73\n" +
            "cat > \"${'$'}worker\" <<'VELUM_INSTALLER_WORKER_EOF'\n$script\nVELUM_INSTALLER_WORKER_EOF\n" +
            "chmod 0700 \"${'$'}worker\"\n"

    private fun spawnDetachedWorkerCommand(workDir: String, workerPath: String): String = """
        set -eu
        umask 077
        work=${shellQuote(workDir)}
        worker=${shellQuote(workerPath)}
        [ -x "${'$'}worker" ] || exit 70
        [ ! -e "${'$'}work/pid" ] && [ ! -e "${'$'}work/terminal" ] || exit 73
        command -v setsid >/dev/null 2>&1 || exit 69
        command -v nohup >/dev/null 2>&1 || exit 69
        mkdir -m 0700 "${'$'}work/launch" || exit 73
        nohup setsid "${'$'}worker" </dev/null >/dev/null 2>&1 &
    """.trimIndent()

    /**
     * Same heartbeat/terminal file format as the synchronous worker. Order inside: pinned download with
     * the existing hash check, installer, then no-overwrite marker publication (hard link fails if the
     * path exists), and only then terminal SUCCESS.
     */
    private fun detachedWorkerScript(plan: ReviewedInstallPlan, workDir: String, installerPath: String): String {
        val markerPath = ManagedInstallMarkerProtocol.MARKER_PATH
        val markerDir = markerPath.substringBeforeLast('/')
        val marker = ManagedInstallMarkerProtocol.encode(plan.scope.managedInstallId).removeSuffix("\n")
        val tempPath = "$markerDir/.identity.${plan.scope.managedInstallId.value}.tmp"
        val fetch = fetchInstallerCommand(workDir, installerPath)
        val publish = """
            set -eu
            umask 077
            dir=${shellQuote(markerDir)}
            path=${shellQuote(markerPath)}
            tmp=${shellQuote(tempPath)}
            install -d -m 0700 "${'$'}dir"
            [ ! -e "${'$'}path" ] && [ ! -L "${'$'}path" ] || exit 73
            rm -f -- "${'$'}tmp"
            printf '%s\n' ${shellQuote(marker)} > "${'$'}tmp"
            chmod 0600 "${'$'}tmp"
            ln -T -- "${'$'}tmp" "${'$'}path" || { rm -f -- "${'$'}tmp"; exit 73; }
            rm -f -- "${'$'}tmp"
        """.trimIndent()
        return """
            #!/bin/sh
            set +e
            umask 077
            work_dir=${'$'}(CDPATH= cd -- "${'$'}(dirname -- "${'$'}0")" && pwd) || exit 70
            # setsid makes this worker the leader of its process group.
            pid=${'$'}${'$'}
            printf '%s\n' "${'$'}pid" > "${'$'}work_dir/pid.tmp" &&
                mv "${'$'}work_dir/pid.tmp" "${'$'}work_dir/pid" &&
                printf '%s\n' "${'$'}pid" > "${'$'}work_dir/pgid.tmp" &&
                mv "${'$'}work_dir/pgid.tmp" "${'$'}work_dir/pgid" || exit 70
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
            finish() {
                code=${'$'}1
                kill "${'$'}hb_pid" >/dev/null 2>&1 || true
                wait "${'$'}hb_pid" 2>/dev/null || true
                if [ "${'$'}code" -eq 0 ]; then
                    printf 'SUCCESS\n' > "${'$'}terminal_tmp"
                else
                    printf 'FAILED:%s\n' "${'$'}code" > "${'$'}terminal_tmp"
                fi
                mv -f "${'$'}terminal_tmp" "${'$'}terminal"
                exit "${'$'}code"
            }
            (
        """.trimIndent() + "\n" + fetch + "\n" + """
            ) >/dev/null 2>&1
            code=${'$'}?
            [ "${'$'}code" -eq 0 ] || finish "${'$'}code"
            XUI_NONINTERACTIVE=1 "${'$'}work_dir/install.sh" ${PINNED_3X_UI_VERSION} >/dev/null 2>&1
            code=${'$'}?
            [ "${'$'}code" -eq 0 ] || finish "${'$'}code"
        """.trimIndent() + "\n" + ENSURE_SQLITE_CLI_STEP + "\n" + """
            (
        """.trimIndent() + "\n" + publish + "\n" + """
            ) >/dev/null 2>&1
            code=${'$'}?
            [ "${'$'}code" -eq 0 ] || finish "${'$'}code"
            # The pinned installer copy (~80 KB) is not needed after success; state markers stay.
            rm -f -- "${'$'}work_dir/install.sh"
            finish 0
        """.trimIndent()
    }

    fun compileMarkerReadback(plan: ReviewedInstallPlan): CompiledInstallerStep? {
        if (!ReviewedInstallPlanPolicy.isCanonical(plan)) return null
        val markerPath = ManagedInstallMarkerProtocol.MARKER_PATH
        val raw = "if [ -f ${shellQuote(markerPath)} ]; then cat -- ${shellQuote(markerPath)}; else exit $MARKER_ABSENT_EXIT_CODE; fi"
        return CompiledInstallerStep(
            kind = InstallerPlanStepKind.WRITE_MANAGED_MARKER,
            command = RemoteCommand.create(raw, "installer-managed-marker-readback"),
            config = SshTransportConfig(
                channelOpenTimeout = maxChannelOpenTimeout,
                commandExecutionTimeout = Duration.ofSeconds(5),
                stdoutCaptureLimitBytes = 256,
                stderrCaptureLimitBytes = 256,
            ),
        )
    }

    private fun prepareWorkerCommand(workDir: String): String = """
        set -eu
        umask 077
        root=${shellQuote(WORK_ROOT)}
        work=${shellQuote(workDir)}
        install -d -m 0700 "${'$'}root"
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
        # Minimal images (Debian 13 cloud) ship without curl; the readiness check accepted apt-get instead.
        if ! command -v curl >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
            env DEBIAN_FRONTEND=noninteractive apt-get update -q -o DPkg::Lock::Timeout=600 >/dev/null 2>&1 || true
            env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends -o DPkg::Lock::Timeout=600 curl ca-certificates >/dev/null 2>&1 || true
        fi
        command -v curl >/dev/null 2>&1 || exit 69
        command -v sha1sum >/dev/null 2>&1 || exit 69
        curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --connect-timeout 15 --max-time 120 --retry 2 --retry-delay 2 --retry-connrefused -o "${'$'}part" ${shellQuote(PINNED_INSTALLER_URL)}
        size=${'$'}(wc -c < "${'$'}part" | tr -d '[:space:]')
        actual=${'$'}( (printf 'blob %s\000' "${'$'}size"; cat "${'$'}part") | sha1sum | awk '{print ${'$'}1}' )
        [ "${'$'}actual" = ${shellQuote(PINNED_INSTALLER_GIT_BLOB_SHA1)} ] || { rm -f "${'$'}part"; exit 74; }
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
        cat > "${'$'}worker" <<'VELUM_INSTALLER_WORKER_EOF'
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
XUI_NONINTERACTIVE=1 "${'$'}work_dir/install.sh" v3.7.0 >/dev/null 2>&1
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
VELUM_INSTALLER_WORKER_EOF
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

    private fun writeMarkerCommand(plan: ReviewedInstallPlan): String {
        val markerPath = ManagedInstallMarkerProtocol.MARKER_PATH
        val markerDir = markerPath.substringBeforeLast('/')
        val marker = ManagedInstallMarkerProtocol.encode(plan.scope.managedInstallId).removeSuffix("\n")
        val tempPath = "$markerDir/.identity.${plan.scope.managedInstallId.value}.tmp"
        return """
            set -eu
            umask 077
            dir=${shellQuote(markerDir)}
            path=${shellQuote(markerPath)}
            tmp=${shellQuote(tempPath)}
            [ ! -e "${'$'}path" ] && [ ! -e "${'$'}tmp" ] || exit 73
            install -d -m 0700 "${'$'}dir"
            printf '%s\n' ${shellQuote(marker)} > "${'$'}tmp"
            chmod 0600 "${'$'}tmp"
            mv "${'$'}tmp" "${'$'}path"
        """.trimIndent()
    }

    private fun transportConfig(timeout: Duration): SshTransportConfig = SshTransportConfig(
        channelOpenTimeout = timeout.coerceAtMost(maxChannelOpenTimeout),
        commandExecutionTimeout = timeout,
        stdoutCaptureLimitBytes = 2 * 1024,
        stderrCaptureLimitBytes = 2 * 1024,
    )

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"
}
