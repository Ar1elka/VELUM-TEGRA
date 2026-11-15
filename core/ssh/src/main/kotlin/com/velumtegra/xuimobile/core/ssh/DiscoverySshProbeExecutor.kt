package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.DiscoveryProbeParseResult
import com.velumtegra.xuimobile.core.domain.DiscoveryProbeParsers
import com.velumtegra.xuimobile.core.domain.DiscoveryProbePlan
import com.velumtegra.xuimobile.core.domain.DiscoveryProbeSpec
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.DiscoveryEvidence
import com.velumtegra.xuimobile.core.model.DiscoveryObservation
import com.velumtegra.xuimobile.core.model.DiscoveryPanelFamily
import com.velumtegra.xuimobile.core.model.DiscoveryPathKind
import com.velumtegra.xuimobile.core.model.DiscoveryPresence
import com.velumtegra.xuimobile.core.model.DiscoveryScope
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
 * Executes only the reviewed Phase 5 Discovery probe algebra over one already-open exact SSH
 * session. Connection lookup, secret resolution, retry/reconnect and lifecycle ownership remain
 * outside this adapter and stay owned by the existing Phase 3/4 runtime.
 */
class DiscoverySshProbeExecutor(
    private val now: () -> Instant = Instant::now,
) {
    suspend fun executeInitialPlan(
        scope: DiscoveryScope,
        session: SshSessionHandle,
    ): DiscoverySshProbeRunResult {
        val expectedOwner = SessionOwner.Operation(scope.operationId)
        if (session.binding.serverAccessId != scope.serverAccessId || session.binding.owner != expectedOwner) {
            return DiscoverySshProbeRunResult.Failed(
                scope = scope,
                failedProbe = null,
                failure = DiscoverySshProbeExecutionFailure.ExactSessionBindingMismatch,
                observations = emptyList(),
            )
        }
        if (!session.isOpen) {
            return DiscoverySshProbeRunResult.Failed(
                scope = scope,
                failedProbe = null,
                failure = DiscoverySshProbeExecutionFailure.SessionClosed,
                observations = emptyList(),
            )
        }

        val observations = mutableListOf<DiscoveryObservation>()
        for (probe in DiscoveryProbePlan.initialProbes) {
            currentCoroutineContext().ensureActive()
            val compiled = DiscoveryReadOnlyCommandCompiler.compile(probe)
                ?: return DiscoverySshProbeRunResult.Failed(
                    scope = scope,
                    failedProbe = probe,
                    failure = DiscoverySshProbeExecutionFailure.ProbeOutsideApprovedPolicy,
                    observations = observations.toList(),
                )

            val result = session.execute(
                command = compiled.command,
                config = transportConfigFor(probe),
            )
            currentCoroutineContext().ensureActive()

            if (result.dispatchState != CommandDispatchState.DISPATCHED) {
                return DiscoverySshProbeRunResult.Failed(
                    scope = scope,
                    failedProbe = probe,
                    failure = DiscoverySshProbeExecutionFailure.CommandUncertain(result.dispatchState),
                    observations = observations.toList(),
                )
            }

            when (val normalized = normalize(probe, result)) {
                is ProbeNormalization.Observation -> observations += normalized.observation
                ProbeNormalization.NoObservation -> Unit
                is ProbeNormalization.Failed -> {
                    return DiscoverySshProbeRunResult.Failed(
                        scope = scope,
                        failedProbe = probe,
                        failure = normalized.failure,
                        observations = observations.toList(),
                    )
                }
            }
        }

        return DiscoverySshProbeRunResult.Completed(
            DiscoveryEvidence(scope = scope, observations = observations.toList()),
        )
    }

    private fun normalize(
        probe: DiscoveryProbeSpec,
        result: SshCommandResult,
    ): ProbeNormalization = when (probe) {
        is DiscoveryProbeSpec.PlatformRelease -> normalizePlatform(result)
        is DiscoveryProbeSpec.ServiceUnitPresence -> normalizePresence(result) { presence ->
            DiscoveryObservation.ServiceUnit(
                serviceUnit = probe.serviceUnit,
                presence = presence,
                observedAt = now(),
            )
        }
        is DiscoveryProbeSpec.InstallationPathPresence -> normalizePresence(result) { presence ->
            DiscoveryObservation.InstallationPath(
                pathKind = probe.pathKind,
                path = probe.path,
                presence = presence,
                observedAt = now(),
            )
        }
        is DiscoveryProbeSpec.ForeignPanelPathMarker -> normalizePresence(result) { presence ->
            if (presence == DiscoveryPresence.PRESENT) {
                DiscoveryObservation.PanelFamily(
                    family = DiscoveryPanelFamily.FOREIGN_PANEL,
                    observedAt = now(),
                )
            } else {
                null
            }
        }
    }

    private fun normalizePlatform(result: SshCommandResult): ProbeNormalization {
        when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> Unit
            is CommandCompletion.ConfirmedFailure -> {
                return ProbeNormalization.Failed(
                    DiscoverySshProbeExecutionFailure.CommandFailed(completion.exitCode),
                )
            }
            is CommandCompletion.Unknown -> {
                return ProbeNormalization.Failed(
                    DiscoverySshProbeExecutionFailure.CommandUncertain(result.dispatchState),
                )
            }
        }
        if (result.stdout.truncated) {
            return ProbeNormalization.Failed(DiscoverySshProbeExecutionFailure.OutputTruncated)
        }

        val bytes = result.stdout.copyBytes()
        val raw = try {
            decodeUtf8Strict(bytes)
                ?: return ProbeNormalization.Failed(DiscoverySshProbeExecutionFailure.MalformedProbeEvidence)
        } finally {
            Arrays.fill(bytes, 0)
        }

        return when (val parsed = DiscoveryProbeParsers.parseOsRelease(raw, now())) {
            is DiscoveryProbeParseResult.Parsed -> ProbeNormalization.Observation(parsed.value)
            DiscoveryProbeParseResult.Malformed -> {
                ProbeNormalization.Failed(DiscoverySshProbeExecutionFailure.MalformedProbeEvidence)
            }
        }
    }

    private fun normalizePresence(
        result: SshCommandResult,
        observation: (DiscoveryPresence) -> DiscoveryObservation?,
    ): ProbeNormalization {
        val exitCode = when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> 0
            is CommandCompletion.ConfirmedFailure -> completion.exitCode
                ?: return ProbeNormalization.Failed(DiscoverySshProbeExecutionFailure.MalformedProbeEvidence)
            is CommandCompletion.Unknown -> {
                return ProbeNormalization.Failed(
                    DiscoverySshProbeExecutionFailure.CommandUncertain(result.dispatchState),
                )
            }
        }

        val presence = when (val parsed = DiscoveryProbeParsers.parsePresenceExitCode(exitCode)) {
            is DiscoveryProbeParseResult.Parsed -> parsed.value
            DiscoveryProbeParseResult.Malformed -> {
                return ProbeNormalization.Failed(DiscoverySshProbeExecutionFailure.MalformedProbeEvidence)
            }
        }
        val normalized = observation(presence)
        return if (normalized == null) ProbeNormalization.NoObservation else ProbeNormalization.Observation(normalized)
    }

    private fun transportConfigFor(probe: DiscoveryProbeSpec): SshTransportConfig = SshTransportConfig(
        channelOpenTimeout = probe.timeout.coerceAtMost(MAX_CHANNEL_OPEN_TIMEOUT),
        commandExecutionTimeout = probe.timeout,
        stdoutCaptureLimitBytes = DISCOVERY_STDOUT_LIMIT_BYTES,
        stderrCaptureLimitBytes = DISCOVERY_STDERR_LIMIT_BYTES,
    )

    private fun decodeUtf8Strict(bytes: ByteArray): String? = runCatching {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    }.getOrNull()

    private sealed interface ProbeNormalization {
        data class Observation(val observation: DiscoveryObservation) : ProbeNormalization
        data object NoObservation : ProbeNormalization
        data class Failed(val failure: DiscoverySshProbeExecutionFailure) : ProbeNormalization
    }

    companion object {
        private val MAX_CHANNEL_OPEN_TIMEOUT: Duration = Duration.ofSeconds(5)
        private const val DISCOVERY_STDOUT_LIMIT_BYTES = 8 * 1024
        private const val DISCOVERY_STDERR_LIMIT_BYTES = 4 * 1024
    }
}

sealed interface DiscoverySshProbeRunResult {
    data class Completed(val evidence: DiscoveryEvidence) : DiscoverySshProbeRunResult

    data class Failed(
        val scope: DiscoveryScope,
        val failedProbe: DiscoveryProbeSpec?,
        val failure: DiscoverySshProbeExecutionFailure,
        val observations: List<DiscoveryObservation>,
    ) : DiscoverySshProbeRunResult
}

sealed interface DiscoverySshProbeExecutionFailure {
    data object ExactSessionBindingMismatch : DiscoverySshProbeExecutionFailure
    data object SessionClosed : DiscoverySshProbeExecutionFailure
    data object ProbeOutsideApprovedPolicy : DiscoverySshProbeExecutionFailure
    data class CommandUncertain(val dispatchState: CommandDispatchState) : DiscoverySshProbeExecutionFailure
    data class CommandFailed(val exitCode: Int?) : DiscoverySshProbeExecutionFailure
    data object OutputTruncated : DiscoverySshProbeExecutionFailure
    data object MalformedProbeEvidence : DiscoverySshProbeExecutionFailure
}

internal data class CompiledDiscoveryCommand(
    val command: RemoteCommand,
)

/** Fixed compiler from typed allowlisted probes to read-only shell. No caller-provided raw shell exists. */
internal object DiscoveryReadOnlyCommandCompiler {
    private val maxProbeTimeout: Duration = Duration.ofSeconds(30)

    fun compile(probe: DiscoveryProbeSpec): CompiledDiscoveryCommand? {
        if (probe.timeout.isZero || probe.timeout.isNegative || probe.timeout > maxProbeTimeout) return null

        val raw = when (probe) {
            is DiscoveryProbeSpec.PlatformRelease -> "cat -- /etc/os-release"
            is DiscoveryProbeSpec.ServiceUnitPresence -> {
                if (probe.serviceUnit !in DiscoveryProbePlan.supportedServiceUnits) return null
                "state=\$(systemctl show --property=LoadState --value -- '${probe.serviceUnit}' 2>/dev/null) || exit 2; [ \"\$state\" != \"not-found\" ]"
            }
            is DiscoveryProbeSpec.InstallationPathPresence -> {
                if (!isApprovedInstallationPath(probe.pathKind, probe.path)) return null
                val predicate = when (probe.pathKind) {
                    DiscoveryPathKind.BINARY -> "-x"
                    DiscoveryPathKind.ROOT -> "-d"
                    DiscoveryPathKind.DATABASE -> "-f"
                }
                "[ $predicate '${probe.path}' ]"
            }
            is DiscoveryProbeSpec.ForeignPanelPathMarker -> {
                if (probe.path !in DiscoveryProbePlan.foreignPanelPathMarkers) return null
                "[ -e '${probe.path}' ]"
            }
        }

        val label = when (probe) {
            is DiscoveryProbeSpec.PlatformRelease -> "discovery-platform-release"
            is DiscoveryProbeSpec.ServiceUnitPresence -> "discovery-service-presence"
            is DiscoveryProbeSpec.InstallationPathPresence -> "discovery-path-presence"
            is DiscoveryProbeSpec.ForeignPanelPathMarker -> "discovery-foreign-marker"
        }
        return CompiledDiscoveryCommand(RemoteCommand.create(raw = raw, redactedLabel = label))
    }

    private fun isApprovedInstallationPath(kind: DiscoveryPathKind, path: String): Boolean = when (kind) {
        DiscoveryPathKind.BINARY -> path in DiscoveryProbePlan.supportedBinaryProbePaths
        DiscoveryPathKind.ROOT -> path in DiscoveryProbePlan.supportedRootProbePaths
        DiscoveryPathKind.DATABASE -> path in DiscoveryProbePlan.supportedDatabaseProbePaths
    }
}
