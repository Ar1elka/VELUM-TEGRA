package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

sealed interface XuiVersionProbeOutcome {
    data class Observed(val version: String) : XuiVersionProbeOutcome
    data object Unavailable : XuiVersionProbeOutcome
}

/** Strict one-command version readback; rejects text that could contain panel secrets. */
object XuiReadOnlyVersionProbe {
    private val APPROVED = mapOf(
        "/usr/local/x-ui/x-ui" to "'/usr/local/x-ui/x-ui' -v",
        "/opt/x-ui/x-ui" to "'/opt/x-ui/x-ui' -v",
    )
    // Upstream -v emits a single version token. Reject banners, URLs, command text and tokens.
    private val VERSION = Regex("v?[0-9]{1,3}(?:\\.[0-9]{1,3}){1,3}(?:-(?:rc|beta|alpha|dev)(?:[.-][A-Za-z0-9]{1,12}){0,2})?")
    private val config = SshTransportConfig(
        channelOpenTimeout = Duration.ofSeconds(5),
        commandExecutionTimeout = Duration.ofSeconds(12),
        stdoutCaptureLimitBytes = 96,
        stderrCaptureLimitBytes = 96,
    )

    suspend fun inspect(session: SshSessionHandle, binaryPath: String): XuiVersionProbeOutcome {
        val command = APPROVED[binaryPath] ?: return XuiVersionProbeOutcome.Unavailable
        if (!session.isOpen) return XuiVersionProbeOutcome.Unavailable
        currentCoroutineContext().ensureActive()
        val result = session.execute(
            RemoteCommand.create(command, "xui-readonly-binary-version"), config,
        )
        currentCoroutineContext().ensureActive()
        if (result.dispatchState != CommandDispatchState.DISPATCHED ||
            result.completion != CommandCompletion.ConfirmedSuccess ||
            result.stdout.truncated || result.stderr.truncated
        ) return XuiVersionProbeOutcome.Unavailable
        val stderr = result.stderr.copyBytes()
        try { if (stderr.isNotEmpty()) return XuiVersionProbeOutcome.Unavailable }
        finally { Arrays.fill(stderr, 0) }
        val stdout = result.stdout.copyBytes()
        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(stdout)).toString()
        } catch (_: Exception) {
            return XuiVersionProbeOutcome.Unavailable
        } finally { Arrays.fill(stdout, 0) }
        val version = if (text.endsWith("\r\n")) text.dropLast(2)
                      else if (text.endsWith("\n")) text.dropLast(1) else text
        return if (VERSION.matches(version)) XuiVersionProbeOutcome.Observed(version)
               else XuiVersionProbeOutcome.Unavailable
    }
}
