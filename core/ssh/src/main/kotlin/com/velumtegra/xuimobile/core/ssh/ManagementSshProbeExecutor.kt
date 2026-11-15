package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.ManagedInstallMarkerProtocol
import com.velumtegra.xuimobile.core.domain.ManagementProbeParseResult
import com.velumtegra.xuimobile.core.domain.ManagementProbeParsers
import com.velumtegra.xuimobile.core.domain.ManagementProbePlan
import com.velumtegra.xuimobile.core.domain.ManagementProbeSpec
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.ManagementEvidence
import com.velumtegra.xuimobile.core.model.ManagementObservation
import com.velumtegra.xuimobile.core.model.ManagementPathKind
import com.velumtegra.xuimobile.core.model.ManagementPresence
import com.velumtegra.xuimobile.core.model.ManagementScope
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.XuiInstallation
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/**
 * Exact read-only Management adapter over one already-open operation-owned SSH session.
 *
 * It owns no access lookup, secret resolution, connect/reconnect loop, durable baseline write,
 * WebPanel state or remote mutation. Raw command output is transient and is normalized before it
 * can cross the core:ssh boundary.
 */
class ManagementSshProbeExecutor(
    private val now: () -> Instant = Instant::now,
) {
    suspend fun executeEnrollmentBaseline(
        scope: ManagementScope,
        expectedIdentity: InstallationIdentity,
        session: SshSessionHandle,
    ): ManagementSshProbeRunResult = executePlan(
        scope = scope,
        probes = ManagementProbePlan.enrollmentBaseline(expectedIdentity),
        session = session,
    )

    suspend fun executeQuickInspect(
        scope: ManagementScope,
        installation: XuiInstallation,
        session: SshSessionHandle,
    ): ManagementSshProbeRunResult {
        if (scope.serverId != installation.serverId || scope.installationId != installation.id) {
            return ManagementSshProbeRunResult.Failed(
                scope = scope,
                failedProbe = null,
                failure = ManagementSshProbeExecutionFailure.ScopeTargetMismatch,
                observations = emptyList(),
            )
        }
        return executePlan(
            scope = scope,
            probes = ManagementProbePlan.quickInspect(installation),
            session = session,
        )
    }

    private suspend fun executePlan(
        scope: ManagementScope,
        probes: List<ManagementProbeSpec>,
        session: SshSessionHandle,
    ): ManagementSshProbeRunResult {
        val expectedOwner = SessionOwner.Operation(scope.operationId)
        if (session.binding.serverAccessId != scope.serverAccessId || session.binding.owner != expectedOwner) {
            return ManagementSshProbeRunResult.Failed(
                scope = scope,
                failedProbe = null,
                failure = ManagementSshProbeExecutionFailure.ExactSessionBindingMismatch,
                observations = emptyList(),
            )
        }
        if (!session.isOpen) {
            return ManagementSshProbeRunResult.Failed(
                scope = scope,
                failedProbe = null,
                failure = ManagementSshProbeExecutionFailure.SessionClosed,
                observations = emptyList(),
            )
        }

        val observations = mutableListOf<ManagementObservation>()
        for (probe in probes) {
            currentCoroutineContext().ensureActive()
            when (val compiled = ManagementReadOnlyCommandCompiler.compile(probe)) {
                null -> {
                    return ManagementSshProbeRunResult.Failed(
                        scope = scope,
                        failedProbe = probe,
                        failure = ManagementSshProbeExecutionFailure.ProbeOutsideApprovedPolicy,
                        observations = observations.toList(),
                    )
                }
                is CompiledManagementProbe.Command -> {
                    val result = session.execute(
                        command = compiled.command,
                        config = transportConfigFor(probe),
                    )
                    currentCoroutineContext().ensureActive()

                    if (result.dispatchState != CommandDispatchState.DISPATCHED) {
                        return ManagementSshProbeRunResult.Failed(
                            scope = scope,
                            failedProbe = probe,
                            failure = ManagementSshProbeExecutionFailure.CommandUncertain(result.dispatchState),
                            observations = observations.toList(),
                        )
                    }

                    when (val normalized = normalize(probe, result)) {
                        is ProbeNormalization.Observation -> observations += normalized.observation
                        is ProbeNormalization.Failed -> {
                            return ManagementSshProbeRunResult.Failed(
                                scope = scope,
                                failedProbe = probe,
                                failure = normalized.failure,
                                observations = observations.toList(),
                            )
                        }
                    }
                }
            }
        }

        return ManagementSshProbeRunResult.Completed(
            ManagementEvidence(scope = scope, observations = observations.toList()),
        )
    }

    private fun normalize(
        probe: ManagementProbeSpec,
        result: SshCommandResult,
    ): ProbeNormalization = when (probe) {
        is ManagementProbeSpec.ServiceUnitPresence -> normalizePresence(result) { presence ->
            ManagementObservation.ServiceUnitPresence(
                serviceUnit = probe.serviceUnit,
                presence = presence,
                observedAt = now(),
            )
        }
        is ManagementProbeSpec.ExactPathPresence -> normalizePresence(result) { presence ->
            ManagementObservation.PathPresence(
                pathKind = probe.pathKind,
                path = probe.path,
                presence = presence,
                observedAt = now(),
            )
        }
        is ManagementProbeSpec.ServiceLiveState -> normalizeText(result) { raw ->
            when (val parsed = ManagementProbeParsers.parseServiceState(raw)) {
                is ManagementProbeParseResult.Parsed -> ProbeNormalization.Observation(
                    ManagementObservation.ServiceState(
                        serviceUnit = probe.serviceUnit,
                        state = parsed.value,
                        observedAt = now(),
                    ),
                )
                ManagementProbeParseResult.Malformed -> malformed()
            }
        }
        is ManagementProbeSpec.PanelSettingsReadback -> normalizeText(result) { raw ->
            when (val parsed = ManagementProbeParsers.parsePanelSettings(raw)) {
                is ManagementProbeParseResult.Parsed -> ProbeNormalization.Observation(
                    ManagementObservation.PanelSettings(
                        settings = parsed.value,
                        observedAt = now(),
                    ),
                )
                ManagementProbeParseResult.Malformed -> malformed()
            }
        }
        is ManagementProbeSpec.ExactListenerPresence -> normalizePresence(result) { presence ->
            ManagementObservation.ListenerPresence(
                port = probe.expectedPort,
                listenAddress = probe.expectedListenAddress,
                presence = presence,
                observedAt = now(),
            )
        }
        is ManagementProbeSpec.ManagedInstallMarkerReadback -> normalizeMarker(result)
    }

    /**
     * Reads the canonical Phase 8.3 marker. Only the exact id or a proven absence crosses the
     * boundary; the 6.3 policy compares it with the expected id. Anything else fails closed.
     */
    private fun normalizeMarker(result: SshCommandResult): ProbeNormalization {
        if (result.stdout.truncated) {
            return ProbeNormalization.Failed(ManagementSshProbeExecutionFailure.OutputTruncated)
        }
        when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> Unit
            is CommandCompletion.ConfirmedFailure -> {
                return if (completion.exitCode == ManagementReadOnlyCommandCompiler.MARKER_ABSENT_EXIT_CODE) {
                    ProbeNormalization.Observation(
                        ManagementObservation.ManagedInstallMarker(
                            managedInstallId = null,
                            presence = ManagementPresence.ABSENT,
                            observedAt = now(),
                        ),
                    )
                } else {
                    ProbeNormalization.Failed(ManagementSshProbeExecutionFailure.CommandFailed(completion.exitCode))
                }
            }
            is CommandCompletion.Unknown -> {
                return ProbeNormalization.Failed(
                    ManagementSshProbeExecutionFailure.CommandUncertain(result.dispatchState),
                )
            }
        }
        val bytes = result.stdout.copyBytes()
        val raw = try {
            decodeUtf8Strict(bytes) ?: return malformed()
        } finally {
            Arrays.fill(bytes, 0)
        }
        val id = ManagedInstallMarkerProtocol.parseReadback(raw) ?: return malformed()
        return ProbeNormalization.Observation(
            ManagementObservation.ManagedInstallMarker(
                managedInstallId = id,
                presence = ManagementPresence.PRESENT,
                observedAt = now(),
            ),
        )
    }

    private fun normalizePresence(
        result: SshCommandResult,
        observation: (ManagementPresence) -> ManagementObservation,
    ): ProbeNormalization {
        if (result.stdout.truncated) {
            return ProbeNormalization.Failed(ManagementSshProbeExecutionFailure.OutputTruncated)
        }
        val exitCode = when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> 0
            is CommandCompletion.ConfirmedFailure -> completion.exitCode
                ?: return malformed()
            is CommandCompletion.Unknown -> {
                return ProbeNormalization.Failed(
                    ManagementSshProbeExecutionFailure.CommandUncertain(result.dispatchState),
                )
            }
        }
        return when (val parsed = ManagementProbeParsers.parsePresenceExitCode(exitCode)) {
            is ManagementProbeParseResult.Parsed -> ProbeNormalization.Observation(observation(parsed.value))
            ManagementProbeParseResult.Malformed -> malformed()
        }
    }

    private fun normalizeText(
        result: SshCommandResult,
        parse: (String) -> ProbeNormalization,
    ): ProbeNormalization {
        when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> Unit
            is CommandCompletion.ConfirmedFailure -> {
                return ProbeNormalization.Failed(
                    ManagementSshProbeExecutionFailure.CommandFailed(completion.exitCode),
                )
            }
            is CommandCompletion.Unknown -> {
                return ProbeNormalization.Failed(
                    ManagementSshProbeExecutionFailure.CommandUncertain(result.dispatchState),
                )
            }
        }
        if (result.stdout.truncated) {
            return ProbeNormalization.Failed(ManagementSshProbeExecutionFailure.OutputTruncated)
        }

        val bytes = result.stdout.copyBytes()
        val raw = try {
            decodeUtf8Strict(bytes) ?: return malformed()
        } finally {
            Arrays.fill(bytes, 0)
        }
        return parse(raw)
    }

    private fun transportConfigFor(probe: ManagementProbeSpec): SshTransportConfig = SshTransportConfig(
        channelOpenTimeout = probe.timeout.coerceAtMost(MAX_CHANNEL_OPEN_TIMEOUT),
        commandExecutionTimeout = probe.timeout,
        stdoutCaptureLimitBytes = MANAGEMENT_STDOUT_LIMIT_BYTES,
        stderrCaptureLimitBytes = MANAGEMENT_STDERR_LIMIT_BYTES,
    )

    private fun decodeUtf8Strict(bytes: ByteArray): String? = runCatching {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    }.getOrNull()

    private fun malformed(): ProbeNormalization = ProbeNormalization.Failed(
        ManagementSshProbeExecutionFailure.MalformedProbeEvidence,
    )

    private sealed interface ProbeNormalization {
        data class Observation(val observation: ManagementObservation) : ProbeNormalization
        data class Failed(val failure: ManagementSshProbeExecutionFailure) : ProbeNormalization
    }

    companion object {
        private val MAX_CHANNEL_OPEN_TIMEOUT: Duration = Duration.ofSeconds(5)
        private const val MANAGEMENT_STDOUT_LIMIT_BYTES = 4 * 1024
        private const val MANAGEMENT_STDERR_LIMIT_BYTES = 2 * 1024
    }
}

sealed interface ManagementSshProbeRunResult {
    data class Completed(val evidence: ManagementEvidence) : ManagementSshProbeRunResult

    data class Failed(
        val scope: ManagementScope,
        val failedProbe: ManagementProbeSpec?,
        val failure: ManagementSshProbeExecutionFailure,
        val observations: List<ManagementObservation>,
    ) : ManagementSshProbeRunResult
}

sealed interface ManagementSshProbeExecutionFailure {
    data object ScopeTargetMismatch : ManagementSshProbeExecutionFailure
    data object ExactSessionBindingMismatch : ManagementSshProbeExecutionFailure
    data object SessionClosed : ManagementSshProbeExecutionFailure
    data object ProbeOutsideApprovedPolicy : ManagementSshProbeExecutionFailure
    data class CommandUncertain(val dispatchState: CommandDispatchState) : ManagementSshProbeExecutionFailure
    data class CommandFailed(val exitCode: Int?) : ManagementSshProbeExecutionFailure
    data object OutputTruncated : ManagementSshProbeExecutionFailure
    data object MalformedProbeEvidence : ManagementSshProbeExecutionFailure
}

internal sealed interface CompiledManagementProbe {
    data class Command(val command: RemoteCommand) : CompiledManagementProbe
}

/** Reserved results of the fixed settings reader; sqlite's own errors are mapped to QUERY_FAILED. */
object ManagementPanelSettingsExit {
    const val SQLITE_UNAVAILABLE = 69
    const val DATABASE_UNREADABLE = 77
    const val QUERY_FAILED = 74
}

/**
 * Fixed compiler from the typed 6.3 vocabulary to bounded read-only shell forms.
 * Dynamic exact identity values are validated and shell-quoted; callers cannot supply raw shell.
 */
internal object ManagementReadOnlyCommandCompiler {
    private val maxProbeTimeout: Duration = Duration.ofSeconds(30)
    private val serviceUnitRegex = Regex("[A-Za-z0-9_.@:-]{1,255}")
    private val pathRegex = Regex("/[A-Za-z0-9_./@:+-]{0,1023}")
    private val listenAddressRegex = Regex("[A-Za-z0-9_.:%-]{1,128}")
    const val MARKER_ABSENT_EXIT_CODE = 44

    fun compile(probe: ManagementProbeSpec): CompiledManagementProbe? {
        if (probe.timeout.isZero || probe.timeout.isNegative || probe.timeout > maxProbeTimeout) return null

        val raw = when (probe) {
            is ManagementProbeSpec.ServiceUnitPresence -> {
                if (!isSafeServiceUnit(probe.serviceUnit)) return null
                val unit = shellQuote(probe.serviceUnit)
                "state=\$(systemctl show --property=LoadState --value -- $unit 2>/dev/null) || exit 2; [ \"\$state\" != \"not-found\" ]"
            }
            is ManagementProbeSpec.ServiceLiveState -> {
                if (!isSafeServiceUnit(probe.serviceUnit)) return null
                val unit = shellQuote(probe.serviceUnit)
                "state=\$(systemctl is-active -- $unit 2>/dev/null); code=\$?; case \"\$state\" in active|inactive|failed|activating|deactivating|reloading|unknown) printf '%s\\n' \"\$state\"; exit 0 ;; *) exit \"\$code\" ;; esac"
            }
            is ManagementProbeSpec.ExactPathPresence -> {
                if (!isSafeAbsolutePath(probe.path)) return null
                val predicate = when (probe.pathKind) {
                    ManagementPathKind.BINARY -> "-x"
                    ManagementPathKind.ROOT -> "-d"
                    ManagementPathKind.DATABASE -> "-f"
                }
                "[ $predicate ${shellQuote(probe.path)} ]"
            }
            is ManagementProbeSpec.ManagedInstallMarkerReadback -> {
                // Canonical Phase 8.3 marker, the same fixed read the restart preflight uses.
                val path = shellQuote(ManagedInstallMarkerProtocol.MARKER_PATH)
                "if [ -f $path ]; then cat -- $path; else exit $MARKER_ABSENT_EXIT_CODE; fi"
            }
            is ManagementProbeSpec.PanelSettingsReadback -> {
                if (!isSafeAbsolutePath(probe.exactDatabasePath)) return null
                val sql = "SELECT 'PORT=' || COALESCE((SELECT value FROM settings WHERE key='webPort' LIMIT 1),''); " +
                    "SELECT 'WEB_BASE_PATH=' || COALESCE((SELECT value FROM settings WHERE key='webBasePath' LIMIT 1),''); " +
                    "SELECT 'LISTEN_ADDRESS=' || COALESCE((SELECT value FROM settings WHERE key='webListen' LIMIT 1),'');"
                val database = shellQuote(probe.exactDatabasePath)
                "command -v sqlite3 >/dev/null 2>&1 || exit ${ManagementPanelSettingsExit.SQLITE_UNAVAILABLE}; " +
                    "[ -f $database ] && [ -r $database ] || exit ${ManagementPanelSettingsExit.DATABASE_UNREADABLE}; " +
                    "sqlite3 -readonly -batch -noheader $database ${shellQuote(sql)} || exit ${ManagementPanelSettingsExit.QUERY_FAILED}"
            }
            is ManagementProbeSpec.ExactListenerPresence -> {
                if (probe.expectedPort !in 1..65535) return null
                val filter = shellQuote("sport = :${probe.expectedPort}")
                val prelude = "command -v ss >/dev/null 2>&1 || exit 2; out=\$(ss -H -ltn $filter 2>/dev/null) || exit 2; "
                val address = probe.expectedListenAddress
                if (address == null) {
                    prelude + "[ -n \"\$out\" ]"
                } else {
                    if (!listenAddressRegex.matches(address)) return null
                    val awk = "BEGIN { found=0 } { local=\$4; sub(/:[0-9]+\$/, \"\", local); if (substr(local,1,1)==\"[\" && substr(local,length(local),1)==\"]\") local=substr(local,2,length(local)-2); if (local==expected) found=1 } END { exit(found ? 0 : 1) }"
                    prelude + "printf '%s\\n' \"\$out\" | awk -v expected=${shellQuote(address)} ${shellQuote(awk)}"
                }
            }
        }

        val label = when (probe) {
            is ManagementProbeSpec.ServiceUnitPresence -> "management-service-presence"
            is ManagementProbeSpec.ServiceLiveState -> "management-service-state"
            is ManagementProbeSpec.ExactPathPresence -> "management-path-presence"
            is ManagementProbeSpec.ManagedInstallMarkerReadback -> "management-managed-marker"
            is ManagementProbeSpec.PanelSettingsReadback -> "management-panel-settings"
            is ManagementProbeSpec.ExactListenerPresence -> "management-listener-presence"
        }
        return CompiledManagementProbe.Command(RemoteCommand.create(raw = raw, redactedLabel = label))
    }

    private fun isSafeServiceUnit(value: String): Boolean =
        serviceUnitRegex.matches(value) && value.endsWith(".service")

    private fun isSafeAbsolutePath(value: String): Boolean =
        pathRegex.matches(value) &&
            !value.contains("//") &&
            value.split('/').none { it == "." || it == ".." }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"
}
