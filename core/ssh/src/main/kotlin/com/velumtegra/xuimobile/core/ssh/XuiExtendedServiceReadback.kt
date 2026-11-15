package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import java.security.MessageDigest
import java.time.Duration
import java.util.Locale

/** Bounded probes against the standard service. No process arguments or output reach the UI. */
internal object XuiExtendedServiceReadback {
    private val execReload = Regex(
        """^\{ path=(/bin/kill|/usr/bin/kill) ; argv\[\]=\1 -USR1 \${'$'}MAINPID ; ignore_errors=no(?: ; [^{}\r\n]*)? \}$""",
    )
    private val bootId = Regex("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
    private val number = Regex("[1-9][0-9]{0,19}")

    data class XrayProcesses(val panel: String, val xray: String) {
        val evidence: String get() = "$panel:$xray"
    }

    fun supportsOfficialReload(value: String): Boolean = execReload.matches(value.trim())

    suspend fun hasOfficialReload(session: SshSessionHandle): Boolean =
        read(session, "systemctl show --property=ExecReload --value -- x-ui.service", "management-xray-reload-config")
            ?.let(::supportsOfficialReload) == true

    suspend fun readAutostart(session: SshSessionHandle): String? =
        read(session, "systemctl show --property=UnitFileState --value -- x-ui.service", "management-autostart-state")
            ?.trim()?.takeIf { it.matches(Regex("[a-z][a-z-]{0,31}")) }

    suspend fun readXray(session: SshSessionHandle): XrayProcesses? =
        read(session, xrayProcessProbe, "management-xray-processes")?.let(::parseProcesses)

    fun parseProcesses(text: String): XrayProcesses? {
        val fields = text.trim().split(' ')
        if (fields.size != 5 || !bootId.matches(fields[0]) || fields.drop(1).any { !number.matches(it) }) return null
        return XrayProcesses(
            fingerprint("${fields[0]}:${fields[1]}:${fields[2]}"),
            fingerprint("${fields[0]}:${fields[3]}:${fields[4]}"),
        )
    }

    private fun fingerprint(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.encodeToByteArray()).take(16)
            .joinToString("") { "%02x".format(Locale.ROOT, it) }

    private suspend fun read(session: SshSessionHandle, raw: String, label: String): String? {
        val result = session.execute(
            RemoteCommand.create(raw, label),
            SshTransportConfig(
                channelOpenTimeout = Duration.ofSeconds(5),
                commandExecutionTimeout = Duration.ofSeconds(10),
                stdoutCaptureLimitBytes = 2048,
                stderrCaptureLimitBytes = 512,
            ),
        )
        if (result.dispatchState != CommandDispatchState.DISPATCHED ||
            result.completion != CommandCompletion.ConfirmedSuccess || result.stdout.truncated || result.stderr.truncated) return null
        val bytes = result.stdout.copyBytes()
        return try { bytes.decodeToString(throwOnInvalidSequence = true) }
        catch (_: java.nio.charset.CharacterCodingException) { null }
        finally { bytes.fill(0) }
    }

    private val xrayProcessProbe = """
        set -eu
        export LC_ALL=C
        panel=${'$'}(systemctl show --property=MainPID --value -- x-ui.service)
        case "${'$'}panel" in ''|0|*[!0-9]*) exit 2;; esac
        [ "${'$'}(readlink "/proc/${'$'}panel/exe")" = /usr/local/x-ui/x-ui ]
        usr1=${'$'}(/bin/kill -l USR1)
        case "${'$'}usr1" in ''|*[!0-9]*) exit 2;; esac
        [ "${'$'}usr1" -ge 1 ] && [ "${'$'}usr1" -le 32 ] || exit 2
        caught=${'$'}(awk '${'$'}1 == "SigCgt:" { print substr(${'$'}2, length(${'$'}2) - 7) }' "/proc/${'$'}panel/status")
        case "${'$'}caught" in ''|*[!0-9a-fA-F]*) exit 2;; esac
        [ "${'$'}(( (0x${'$'}caught >> (${'$'}usr1 - 1)) & 1 ))" -eq 1 ] || exit 2
        start_tick() {
            raw=${'$'}(cat "/proc/${'$'}1/stat") || return 2
            raw=${'$'}{raw##*) }
            set -- ${'$'}raw
            [ "${'$'}#" -ge 20 ] && [ "${'$'}1" != Z ] || return 2
            printf '%s' "${'$'}{20}"
        }
        panel_start=${'$'}(start_tick "${'$'}panel")
        children=${'$'}(ps -o pid= --ppid "${'$'}panel") || exit 2
        xray=''
        for child in ${'$'}children; do
            exe=${'$'}(readlink "/proc/${'$'}child/exe") || continue
            case "${'$'}exe" in
                /usr/local/x-ui/bin/xray-linux-*)
                    [ -z "${'$'}xray" ] || exit 2
                    xray="${'$'}child"
                    ;;
            esac
        done
        [ -n "${'$'}xray" ]
        xray_start=${'$'}(start_tick "${'$'}xray")
        [ "${'$'}(start_tick "${'$'}panel")" = "${'$'}panel_start" ]
        boot=${'$'}(cat /proc/sys/kernel/random/boot_id)
        printf '%s %s %s %s %s\n' "${'$'}boot" "${'$'}panel" "${'$'}panel_start" "${'$'}xray" "${'$'}xray_start"
    """.trimIndent()
}
