package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** One fixed, bounded, read-only service query. No caller-provided shell fragments. */
enum class XuiObservedServiceState { ACTIVE, INACTIVE, FAILED, ACTIVATING, DEACTIVATING, RELOADING, UNKNOWN }

sealed interface XuiServiceProbeOutcome {
    data class Observed(val state: XuiObservedServiceState) : XuiServiceProbeOutcome
    data object Unavailable : XuiServiceProbeOutcome
}

object XuiReadOnlyServiceStateProbe {
    private const val APPROVED_UNIT = "x-ui.service"
    private val config = SshTransportConfig(
        channelOpenTimeout = Duration.ofSeconds(5),
        commandExecutionTimeout = Duration.ofSeconds(12),
        stdoutCaptureLimitBytes = 128,
        stderrCaptureLimitBytes = 128,
    )

    /** Confirmed command, strict bounded UTF-8, exactly one known status token. */
    suspend fun inspect(session: SshSessionHandle, serviceUnit: String): XuiServiceProbeOutcome {
        if (serviceUnit != APPROVED_UNIT || !session.isOpen) return XuiServiceProbeOutcome.Unavailable
        currentCoroutineContext().ensureActive()
        val result = session.execute(
            RemoteCommand.create(
                raw = "systemctl show --property=ActiveState --value -- x-ui.service",
                redactedLabel = "xui-readonly-service-active-state",
            ),
            config,
        )
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED ||
            result.completion != CommandCompletion.ConfirmedSuccess ||
            result.stdout.truncated || result.stderr.truncated
        ) return XuiServiceProbeOutcome.Unavailable
        val bytes = result.stdout.copyBytes()
        val value = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString().trimEnd('\n', '\r')
        } catch (_: Exception) {
            null
        } finally { Arrays.fill(bytes, 0) }
        return when (value) {
            "active" -> XuiServiceProbeOutcome.Observed(XuiObservedServiceState.ACTIVE)
            "inactive" -> XuiServiceProbeOutcome.Observed(XuiObservedServiceState.INACTIVE)
            "failed" -> XuiServiceProbeOutcome.Observed(XuiObservedServiceState.FAILED)
            "activating" -> XuiServiceProbeOutcome.Observed(XuiObservedServiceState.ACTIVATING)
            "deactivating" -> XuiServiceProbeOutcome.Observed(XuiObservedServiceState.DEACTIVATING)
            "reloading" -> XuiServiceProbeOutcome.Observed(XuiObservedServiceState.RELOADING)
            "unknown" -> XuiServiceProbeOutcome.Observed(XuiObservedServiceState.UNKNOWN)
            else -> XuiServiceProbeOutcome.Unavailable
        }
    }
}
