package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import java.time.Duration
import java.time.Instant
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Locale

sealed interface XuiPanelTlsResult {
    data class Observed(val expiresAt: Instant, val fingerprint: String) : XuiPanelTlsResult
    data object NotConfigured : XuiPanelTlsResult
    data object Unavailable : XuiPanelTlsResult
}

/** Reads only the configured public certificate of the standard local 3x-ui database. */
object XuiReadOnlyPanelTlsProbe {
    private val absolutePath = Regex("/[A-Za-z0-9_./-]{1,1023}")
    private val fingerprint = Regex("(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}")
    private val opensslDate = DateTimeFormatter.ofPattern("MMM d HH:mm:ss uuuu z", Locale.US)
    private val config = SshTransportConfig(
        channelOpenTimeout = Duration.ofSeconds(5),
        commandExecutionTimeout = Duration.ofSeconds(10),
        stdoutCaptureLimitBytes = 2048,
        stderrCaptureLimitBytes = 512,
    )

    suspend fun read(session: SshSessionHandle, databasePath: String): XuiPanelTlsResult {
        if (!session.isOpen || databasePath != "/etc/x-ui/x-ui.db") return XuiPanelTlsResult.Unavailable
        val path = readText(session, certificateReferenceCommand, "management-panel-tls-reference")
            ?.trimEnd('\r', '\n') ?: return XuiPanelTlsResult.Unavailable
        if (path.isEmpty()) return XuiPanelTlsResult.NotConfigured
        if (!absolutePath.matches(path) || path.split('/').drop(1).any { it in setOf(".", "..", "") }) {
            return XuiPanelTlsResult.Unavailable
        }
        val command = "[ -f '$path' ] && LC_ALL=C openssl x509 -in '$path' -noout -enddate -fingerprint -sha256"
        val text = readText(session, command, "management-panel-tls-metadata") ?: return XuiPanelTlsResult.Unavailable
        return parseMetadata(text)
    }

    internal fun parseMetadata(text: String): XuiPanelTlsResult {
        val lines = text.lineSequence().filter(String::isNotBlank).toList()
        if (lines.size != 2) return XuiPanelTlsResult.Unavailable
        val end = lines.singleOrNull { it.startsWith("notAfter=") }?.substringAfter('=')
            ?: return XuiPanelTlsResult.Unavailable
        val digest = lines.singleOrNull { it.startsWith("sha256 Fingerprint=", ignoreCase = true) }
            ?.substringAfter('=')?.takeIf(fingerprint::matches) ?: return XuiPanelTlsResult.Unavailable
        val expiration = runCatching {
            ZonedDateTime.parse(end.trim().replace(Regex("\\s+"), " "), opensslDate).toInstant()
        }.getOrNull() ?: return XuiPanelTlsResult.Unavailable
        return XuiPanelTlsResult.Observed(expiration, digest.uppercase(Locale.ROOT))
    }

    private suspend fun readText(session: SshSessionHandle, command: String, label: String): String? {
        val result = session.execute(RemoteCommand.create(command, label), config)
        if (result.dispatchState != CommandDispatchState.DISPATCHED ||
            result.completion != CommandCompletion.ConfirmedSuccess ||
            result.stdout.truncated || result.stderr.truncated) return null
        val bytes = result.stdout.copyBytes()
        return try { bytes.decodeToString(throwOnInvalidSequence = true) }
        catch (_: java.nio.charset.CharacterCodingException) { null }
        finally { bytes.fill(0) }
    }

    private val certificateReferenceCommand = """
        db=/etc/x-ui/x-ui.db
        [ -r "${'$'}db" ] || exit 2
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 -readonly -batch -noheader "${'$'}db" "SELECT COALESCE((SELECT value FROM settings WHERE key='webCertFile' LIMIT 1),'')"
        elif command -v python3 >/dev/null 2>&1; then
            python3 -c 'import sqlite3; db=sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True); row=db.execute("SELECT value FROM settings WHERE key=?", ("webCertFile",)).fetchone(); print((row and row[0]) or "")'
        else
            exit 2
        fi
    """.trimIndent()
}
