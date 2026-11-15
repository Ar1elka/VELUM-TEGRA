package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import java.time.Duration

/** Panel sign-in written by the official 3x-ui installer into its root-only result file. */
data class XuiPanelCredentials(
    val username: String,
    val password: String,
    val panelPort: Int,
    val webBasePath: String,
) {
    override fun toString(): String = "XuiPanelCredentials(username=<redacted>, password=<redacted>, " +
        "panelPort=$panelPort, webBasePath=<redacted>)"
}

sealed interface XuiInstallResultRead {
    data class Observed(val credentials: XuiPanelCredentials) : XuiInstallResultRead
    /** The file does not exist: the panel was not installed by the official non-interactive installer. */
    data object NotRecorded : XuiInstallResultRead
    data object Unavailable : XuiInstallResultRead
}

/**
 * Reads only `/etc/x-ui/install-result.env` (mode 0600, root) that 3x-ui v3.x `install.sh` writes after a
 * non-interactive install. Read-only: one fixed `cat`, no shell evaluation of the file on either side.
 * Values may have been changed later in the panel; the file reflects the installer's original choice.
 */
object XuiInstallResultProbe {
    const val RESULT_PATH: String = "/etc/x-ui/install-result.env"
    private const val NOT_RECORDED_EXIT = 44
    private val config = SshTransportConfig(
        channelOpenTimeout = Duration.ofSeconds(5),
        commandExecutionTimeout = Duration.ofSeconds(10),
        stdoutCaptureLimitBytes = 4096,
        stderrCaptureLimitBytes = 512,
    )
    private val command = "f='$RESULT_PATH'; [ -e \"\$f\" ] || exit $NOT_RECORDED_EXIT; " +
        "[ -f \"\$f\" ] && [ ! -L \"\$f\" ] && [ -r \"\$f\" ] || exit 2; cat -- \"\$f\""

    suspend fun read(session: SshSessionHandle): XuiInstallResultRead {
        if (!session.isOpen) return XuiInstallResultRead.Unavailable
        val result = session.execute(RemoteCommand.create(command, "management-panel-install-result"), config)
        if (result.dispatchState != CommandDispatchState.DISPATCHED) return XuiInstallResultRead.Unavailable
        val completion = result.completion
        if (completion is CommandCompletion.ConfirmedFailure && completion.exitCode == NOT_RECORDED_EXIT) {
            return XuiInstallResultRead.NotRecorded
        }
        if (completion != CommandCompletion.ConfirmedSuccess || result.stdout.truncated) {
            return XuiInstallResultRead.Unavailable
        }
        val bytes = result.stdout.copyBytes()
        return try {
            parse(bytes.decodeToString(throwOnInvalidSequence = true))
        } catch (_: java.nio.charset.CharacterCodingException) {
            XuiInstallResultRead.Unavailable
        } finally {
            bytes.fill(0)
        }
    }

    /** Accepts plain values and bash `printf %q` backslash escapes; rejects `$'...'` forms and duplicates. */
    internal fun parse(text: String): XuiInstallResultRead {
        val values = HashMap<String, String>()
        for (line in text.lineSequence()) {
            if (line.isBlank()) continue
            val index = line.indexOf('=')
            if (index <= 0) return XuiInstallResultRead.Unavailable
            val key = line.substring(0, index)
            if (!key.startsWith("XUI_")) return XuiInstallResultRead.Unavailable
            val value = unescape(line.substring(index + 1)) ?: return XuiInstallResultRead.Unavailable
            if (values.put(key, value) != null) return XuiInstallResultRead.Unavailable
        }
        val username = values["XUI_USERNAME"]?.takeIf { it.isNotEmpty() } ?: return XuiInstallResultRead.Unavailable
        val password = values["XUI_PASSWORD"]?.takeIf { it.isNotEmpty() } ?: return XuiInstallResultRead.Unavailable
        val port = values["XUI_PANEL_PORT"]?.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: return XuiInstallResultRead.Unavailable
        val path = values["XUI_WEB_BASE_PATH"]?.trim('/') ?: return XuiInstallResultRead.Unavailable
        return XuiInstallResultRead.Observed(XuiPanelCredentials(username, password, port, "/$path/".replace("//", "/")))
    }

    private fun unescape(raw: String): String? {
        if (raw == "''") return ""
        if (raw.startsWith("$'")) return null
        val out = StringBuilder(raw.length)
        var escaped = false
        for (ch in raw) {
            when {
                escaped -> { out.append(ch); escaped = false }
                ch == '\\' -> escaped = true
                ch.isISOControl() -> return null
                else -> out.append(ch)
            }
        }
        return if (escaped) null else out.toString()
    }
}
