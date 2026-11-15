package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.InstallerPostInstallFacts
import com.velumtegra.xuimobile.core.domain.InstallerPostInstallPolicy
import com.velumtegra.xuimobile.core.domain.InstallerWorkerLivenessPolicy
import com.velumtegra.xuimobile.core.domain.ManagedInstallMarkerProtocol
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.InstallerWorkerEvidence
import com.velumtegra.xuimobile.core.model.InstallerWorkerLiveness
import com.velumtegra.xuimobile.core.model.InstallerWorkerProcessState
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.InstallerWorkerTerminalState
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.SessionOwner
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive

interface InstallerPostInstallRemoteVerifier {
    suspend fun verify(
        scope: InstallerWorkerScope,
        session: SshSessionHandle,
    ): InstallerPostInstallRemoteVerificationResult
}

/**
 * Phase 8.5 read-only verifier for the exact detached worker and the installation it produced.
 * It never writes remote state and never replays the installer command.
 */
class InstallerPostInstallSshVerifier(
    private val now: () -> Instant = Instant::now,
    private val deathRecheckDelay: Duration = InstallerWorkerLivenessPolicy.MIN_DEATH_RECHECK_DELAY,
) : InstallerPostInstallRemoteVerifier {
    override suspend fun verify(
        scope: InstallerWorkerScope,
        session: SshSessionHandle,
    ): InstallerPostInstallRemoteVerificationResult {
        if (session.binding.owner != SessionOwner.Operation(scope.operationId) ||
            session.binding.serverAccessId != scope.serverAccessId
        ) {
            return InstallerPostInstallRemoteVerificationResult.Rejected(
                InstallerPostInstallRemoteFailure.ExactSessionBindingMismatch,
            )
        }
        if (!session.isOpen) {
            return InstallerPostInstallRemoteVerificationResult.Rejected(
                InstallerPostInstallRemoteFailure.SessionClosed,
            )
        }

        val first = readWorkerObservation(scope, session)
            ?: return InstallerPostInstallRemoteVerificationResult.ReconciliationRequired(
                InstallerPostInstallRemoteReconciliation.WORKER_EVIDENCE_UNREADABLE,
            )

        var evidence = first
        var liveness = InstallerWorkerLivenessPolicy.classify(scope, evidence, now())
        if (liveness is InstallerWorkerLiveness.Unknown && shouldConfirmDeath(evidence, now())) {
            currentCoroutineContext().ensureActive()
            delay(deathRecheckDelay.toMillis())
            currentCoroutineContext().ensureActive()
            val second = readWorkerObservation(scope, session)
                ?: return InstallerPostInstallRemoteVerificationResult.ReconciliationRequired(
                    InstallerPostInstallRemoteReconciliation.WORKER_EVIDENCE_UNREADABLE,
                )
            evidence = first.copy(
                confirmationProcessState = second.primaryProcessState,
                confirmationObservedAt = second.primaryObservedAt,
                terminalState = if (second.terminalState != InstallerWorkerTerminalState.NONE) {
                    second.terminalState
                } else {
                    first.terminalState
                },
                terminalObservedAt = second.terminalObservedAt ?: first.terminalObservedAt,
                heartbeatAt = maxInstant(first.heartbeatAt, second.heartbeatAt),
            )
            liveness = InstallerWorkerLivenessPolicy.classify(scope, evidence, now())
        }

        when (liveness) {
            InstallerWorkerLiveness.TerminalSuccess -> Unit
            InstallerWorkerLiveness.KnownAlive -> {
                return InstallerPostInstallRemoteVerificationResult.WorkerStillRunning(evidence)
            }
            InstallerWorkerLiveness.TerminalFailure -> {
                return InstallerPostInstallRemoteVerificationResult.ReconciliationRequired(
                    InstallerPostInstallRemoteReconciliation.WORKER_TERMINAL_FAILURE,
                    evidence,
                )
            }
            InstallerWorkerLiveness.ProvenDead -> {
                return InstallerPostInstallRemoteVerificationResult.ReconciliationRequired(
                    InstallerPostInstallRemoteReconciliation.WORKER_DIED_WITHOUT_SUCCESS,
                    evidence,
                )
            }
            is InstallerWorkerLiveness.Unknown -> {
                return InstallerPostInstallRemoteVerificationResult.ReconciliationRequired(
                    InstallerPostInstallRemoteReconciliation.WORKER_STATE_UNKNOWN,
                    evidence,
                )
            }
        }

        val markerReadback = readManagedMarker(scope, session)
            ?: return InstallerPostInstallRemoteVerificationResult.ReconciliationRequired(
                InstallerPostInstallRemoteReconciliation.MANAGED_MARKER_UNREADABLE,
                evidence,
            )
        val facts = readInstallationFacts(scope, markerReadback, session)
            ?: return InstallerPostInstallRemoteVerificationResult.ReconciliationRequired(
                InstallerPostInstallRemoteReconciliation.INSTALLATION_FACTS_UNREADABLE,
                evidence,
            )
        return InstallerPostInstallRemoteVerificationResult.Verified(
            facts = facts,
            workerEvidence = evidence,
        )
    }

    private suspend fun readWorkerObservation(
        scope: InstallerWorkerScope,
        session: SshSessionHandle,
    ): InstallerWorkerEvidence? {
        val command = InstallerPostInstallReadOnlyCompiler.workerEvidence(scope) ?: return null
        currentCoroutineContext().ensureActive()
        val result = session.execute(command, READBACK_CONFIG)
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED) return null
        if (result.completion !is CommandCompletion.ConfirmedSuccess || result.stdout.truncated) return null
        val raw = strictText(result.stdout) ?: return null
        return InstallerPostInstallParsers.parseWorkerEvidence(scope, raw, now())
    }

    private suspend fun readManagedMarker(
        scope: InstallerWorkerScope,
        session: SshSessionHandle,
    ): ManagedInstallMarkerReadbackState? {
        val command = InstallerPostInstallReadOnlyCompiler.managedMarker()
        currentCoroutineContext().ensureActive()
        val result = session.execute(command, MARKER_CONFIG)
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.stdout.truncated) return null
        when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> Unit
            is CommandCompletion.ConfirmedFailure -> {
                return if (completion.exitCode == MARKER_ABSENT_EXIT_CODE) {
                    ManagedInstallMarkerReadbackState.ABSENT
                } else {
                    null
                }
            }
            is CommandCompletion.Unknown -> return null
        }
        val raw = strictText(result.stdout) ?: return null
        return ManagedInstallMarkerProtocol.classifyReadback(scope.managedInstallId, raw)
    }

    private suspend fun readInstallationFacts(
        scope: InstallerWorkerScope,
        markerReadback: ManagedInstallMarkerReadbackState,
        session: SshSessionHandle,
    ): InstallerPostInstallFacts? {
        val command = InstallerPostInstallReadOnlyCompiler.installationFacts(scope) ?: return null
        currentCoroutineContext().ensureActive()
        val result = session.execute(command, FACTS_CONFIG)
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED) return null
        if (result.completion !is CommandCompletion.ConfirmedSuccess || result.stdout.truncated) return null
        val raw = strictText(result.stdout) ?: return null
        return InstallerPostInstallParsers.parseInstallationFacts(raw, markerReadback, now())
    }

    private fun shouldConfirmDeath(evidence: InstallerWorkerEvidence, at: Instant): Boolean {
        if (evidence.terminalState != InstallerWorkerTerminalState.NONE) return false
        if (evidence.primaryProcessState != InstallerWorkerProcessState.DEAD) return false
        val heartbeat = evidence.heartbeatAt ?: return false
        return Duration.between(heartbeat, at) > InstallerWorkerLivenessPolicy.HEARTBEAT_STALE_AFTER
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

    private fun maxInstant(a: Instant?, b: Instant?): Instant? = when {
        a == null -> b
        b == null -> a
        a >= b -> a
        else -> b
    }

    companion object {
        private const val MARKER_ABSENT_EXIT_CODE = 44
        private val READBACK_CONFIG = SshTransportConfig(
            channelOpenTimeout = Duration.ofSeconds(5),
            commandExecutionTimeout = Duration.ofSeconds(5),
            stdoutCaptureLimitBytes = 1024,
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
            stdoutCaptureLimitBytes = 2048,
            stderrCaptureLimitBytes = 1024,
        )
    }
}

sealed interface InstallerPostInstallRemoteVerificationResult {
    data class Verified(
        val facts: InstallerPostInstallFacts,
        val workerEvidence: InstallerWorkerEvidence,
    ) : InstallerPostInstallRemoteVerificationResult

    data class WorkerStillRunning(
        val workerEvidence: InstallerWorkerEvidence,
    ) : InstallerPostInstallRemoteVerificationResult

    data class ReconciliationRequired(
        val reason: InstallerPostInstallRemoteReconciliation,
        val workerEvidence: InstallerWorkerEvidence? = null,
    ) : InstallerPostInstallRemoteVerificationResult

    data class Rejected(
        val failure: InstallerPostInstallRemoteFailure,
    ) : InstallerPostInstallRemoteVerificationResult
}

enum class InstallerPostInstallRemoteFailure {
    ExactSessionBindingMismatch,
    SessionClosed,
}

enum class InstallerPostInstallRemoteReconciliation {
    WORKER_EVIDENCE_UNREADABLE,
    WORKER_TERMINAL_FAILURE,
    WORKER_DIED_WITHOUT_SUCCESS,
    WORKER_STATE_UNKNOWN,
    MANAGED_MARKER_UNREADABLE,
    INSTALLATION_FACTS_UNREADABLE,
}

internal object InstallerPostInstallReadOnlyCompiler {
    private const val WORK_ROOT = "/var/lib/velum-tegra/installer/v1"
    private val managedIdRegex = Regex("v1-[0-9a-f]{32}")

    fun workerEvidence(scope: InstallerWorkerScope): RemoteCommand? {
        val managedId = scope.managedInstallId.value
        if (!managedIdRegex.matches(managedId)) return null
        val work = "$WORK_ROOT/$managedId"
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
            pid=NONE
            if [ -f "${'$'}work/pid" ]; then
                pid=${'$'}(cat -- "${'$'}work/pid" 2>/dev/null || true)
                case "${'$'}pid" in ''|*[!0-9]*) process=UNKNOWN ;; *) if kill -0 "${'$'}pid" 2>/dev/null; then process=ALIVE; else process=DEAD; fi ;; esac
            fi
            printf 'PROCESS=%s\nHEARTBEAT=%s\nTERMINAL=%s\n' "${'$'}process" "${'$'}heartbeat" "${'$'}terminal"
        """.trimIndent()
        return RemoteCommand.create(raw, "installer-worker-evidence-readback")
    }

    fun managedMarker(): RemoteCommand {
        val path = ManagedInstallMarkerProtocol.MARKER_PATH
        val raw = "if [ -f ${shellQuote(path)} ]; then cat -- ${shellQuote(path)}; else exit 44; fi"
        return RemoteCommand.create(raw, "installer-managed-marker-post-verify-readback")
    }

    fun installationFacts(scope: InstallerWorkerScope): RemoteCommand? {
        val managedId = scope.managedInstallId.value
        if (!managedIdRegex.matches(managedId)) return null
        val raw = """
            set -eu
            unit=${shellQuote(InstallerPostInstallPolicy.SERVICE_UNIT)}
            binary=${shellQuote(InstallerPostInstallPolicy.BINARY_PATH)}
            root=${shellQuote(InstallerPostInstallPolicy.ROOT_PATH)}
            db=${shellQuote(InstallerPostInstallPolicy.DATABASE_PATH)}
            service_present=0
            load=${'$'}(systemctl show --property=LoadState --value -- "${'$'}unit" 2>/dev/null || true)
            [ -n "${'$'}load" ] && [ "${'$'}load" != not-found ] && service_present=1
            service_state=${'$'}(systemctl is-active -- "${'$'}unit" 2>/dev/null || true)
            [ -n "${'$'}service_state" ] || service_state=unknown
            binary_present=0; [ -x "${'$'}binary" ] && binary_present=1
            root_present=0; [ -d "${'$'}root" ] && root_present=1
            database_present=0; [ -f "${'$'}db" ] && database_present=1
            settings=${'$'}("${'$'}binary" setting -show true 2>/dev/null) || exit 78
            port=${'$'}(printf '%s\n' "${'$'}settings" | sed -n 's/^port:[[:space:]]*//p')
            web=${'$'}(printf '%s\n' "${'$'}settings" | sed -n 's/^webBasePath:[[:space:]]*//p')
            [ "${'$'}(printf '%s\n' "${'$'}port" | wc -l | tr -d '[:space:]')" = 1 ] || exit 79
            [ "${'$'}(printf '%s\n' "${'$'}web" | wc -l | tr -d '[:space:]')" = 1 ] || exit 79
            case "${'$'}port" in ''|*[!0-9]*) exit 79 ;; esac
            case "${'$'}web" in /*) ;; *) exit 79 ;; esac
            command -v ss >/dev/null 2>&1 || exit 69
            listener_present=0
            ss -H -ltn "sport = :${'$'}port" 2>/dev/null | grep -q . && listener_present=1 || true
            printf 'SERVICE_PRESENT=%s\nBINARY_PRESENT=%s\nROOT_PRESENT=%s\nDATABASE_PRESENT=%s\nSERVICE_STATE=%s\nPORT=%s\nWEB_BASE_PATH=%s\nLISTEN_ADDRESS=\nLISTENER_PRESENT=%s\n' \
                "${'$'}service_present" "${'$'}binary_present" "${'$'}root_present" "${'$'}database_present" "${'$'}service_state" "${'$'}port" "${'$'}web" "${'$'}listener_present"
        """.trimIndent()
        return RemoteCommand.create(raw, "installer-post-install-facts-readback")
    }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"
}

internal object InstallerPostInstallParsers {
    private val keys = setOf(
        "SERVICE_PRESENT",
        "BINARY_PRESENT",
        "ROOT_PRESENT",
        "DATABASE_PRESENT",
        "SERVICE_STATE",
        "PORT",
        "WEB_BASE_PATH",
        "LISTEN_ADDRESS",
        "LISTENER_PRESENT",
    )

    fun parseWorkerEvidence(
        scope: InstallerWorkerScope,
        raw: String,
        observedAt: Instant,
    ): InstallerWorkerEvidence? {
        val values = parseExact(raw, setOf("PROCESS", "HEARTBEAT", "TERMINAL")) ?: return null
        val process = when (values["PROCESS"]) {
            "ALIVE" -> InstallerWorkerProcessState.ALIVE
            "DEAD" -> InstallerWorkerProcessState.DEAD
            "UNKNOWN" -> InstallerWorkerProcessState.UNKNOWN
            else -> return null
        }
        val heartbeat = when (val value = values["HEARTBEAT"]) {
            "NONE" -> null
            "INVALID" -> return null
            else -> value?.toLongOrNull()?.let { runCatching { Instant.ofEpochSecond(it) }.getOrNull() } ?: return null
        }
        val terminalRaw = values["TERMINAL"] ?: return null
        val terminal = when {
            terminalRaw == "NONE" -> InstallerWorkerTerminalState.NONE
            terminalRaw == "SUCCESS" -> InstallerWorkerTerminalState.SUCCESS
            terminalRaw.matches(Regex("FAILED:[0-9]+")) -> InstallerWorkerTerminalState.FAILED
            terminalRaw == "UNKNOWN" -> InstallerWorkerTerminalState.UNKNOWN
            else -> return null
        }
        return InstallerWorkerEvidence(
            scope = scope,
            heartbeatAt = heartbeat,
            primaryProcessState = process,
            primaryObservedAt = observedAt,
            terminalState = terminal,
            terminalObservedAt = if (terminal == InstallerWorkerTerminalState.NONE) null else observedAt,
        )
    }

    fun parseInstallationFacts(
        raw: String,
        markerReadback: ManagedInstallMarkerReadbackState,
        observedAt: Instant,
    ): InstallerPostInstallFacts? {
        val values = parseExact(raw, keys) ?: return null
        fun bit(key: String): Boolean? = when (values[key]) {
            "1" -> true
            "0" -> false
            else -> null
        }
        val service = bit("SERVICE_PRESENT") ?: return null
        val binary = bit("BINARY_PRESENT") ?: return null
        val root = bit("ROOT_PRESENT") ?: return null
        val database = bit("DATABASE_PRESENT") ?: return null
        val listener = bit("LISTENER_PRESENT") ?: return null
        val serviceState = when (values["SERVICE_STATE"]?.lowercase()) {
            "active" -> ManagementServiceState.ACTIVE
            "inactive" -> ManagementServiceState.INACTIVE
            "failed" -> ManagementServiceState.FAILED
            "activating" -> ManagementServiceState.ACTIVATING
            "deactivating" -> ManagementServiceState.DEACTIVATING
            "reloading" -> ManagementServiceState.RELOADING
            "unknown" -> ManagementServiceState.UNKNOWN
            else -> return null
        }
        val port = values["PORT"]?.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        val web = values["WEB_BASE_PATH"] ?: return null
        val listen = values["LISTEN_ADDRESS"]?.takeIf { it.isNotEmpty() }
        return runCatching {
            InstallerPostInstallFacts(
                markerReadback = markerReadback,
                serviceUnitPresent = service,
                binaryPresent = binary,
                rootPresent = root,
                databasePresent = database,
                serviceState = serviceState,
                panelPort = port,
                webBasePath = web,
                listenAddress = listen,
                listenerPresent = listener,
                observedAt = observedAt,
            )
        }.getOrNull()
    }

    private fun parseExact(raw: String, expectedKeys: Set<String>): Map<String, String>? {
        if (raw.toByteArray(StandardCharsets.UTF_8).size > 4096 || '\u0000' in raw || '\r' in raw) return null
        val lines = raw.lineSequence().filter { it.isNotEmpty() }.toList()
        if (lines.size != expectedKeys.size) return null
        val values = linkedMapOf<String, String>()
        for (line in lines) {
            val index = line.indexOf('=')
            if (index <= 0) return null
            val key = line.substring(0, index)
            val value = line.substring(index + 1)
            if (key !in expectedKeys || values.put(key, value) != null) return null
            if ('\n' in value || '\r' in value || '\u0000' in value) return null
        }
        return if (values.keys == expectedKeys) values else null
    }
}
