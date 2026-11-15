package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.domain.DeepDiagnosticProbeSpec
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import java.util.Locale

sealed interface ServiceLogSshResult {
    data class Completed(val snapshot: ServiceLogSnapshot) : ServiceLogSshResult
    data class Failed(val kind: ServiceLogFailure) : ServiceLogSshResult
}

/** One finite read on an existing exact session; no arbitrary command, path, cursor or query API. */
class ServiceLogSshReader(private val now: () -> Instant = Instant::now) {
    suspend fun read(scope: ManagementScope, installation: XuiInstallation, handle: SshSessionHandle): ServiceLogSshResult {
        if (scope.serverId != installation.serverId || scope.installationId != installation.id ||
            handle.binding.owner != SessionOwner.Operation(scope.operationId) ||
            handle.binding.serverAccessId != scope.serverAccessId || !handle.isOpen)
            return ServiceLogSshResult.Failed(ServiceLogFailure.INTERNAL_CONTRACT)
        val unit = installation.identity.serviceUnit
        val command = ServiceLogCommandCompiler.compile(unit)
            ?: return ServiceLogSshResult.Failed(ServiceLogFailure.INTERNAL_CONTRACT)
        val exactBinding = handle.binding
        if (!verifyServiceExecutable(unit, installation.identity.binaryPath, handle))
            return ServiceLogSshResult.Failed(ServiceLogFailure.TARGET_NOT_VERIFIED)
        if (!handle.isOpen || handle.binding != exactBinding)
            return ServiceLogSshResult.Failed(ServiceLogFailure.INTERNAL_CONTRACT)
        val result = handle.execute(command, SshTransportConfig(
            channelOpenTimeout = Duration.ofSeconds(5), commandExecutionTimeout = Duration.ofSeconds(15),
            stdoutCaptureLimitBytes = 128 * 1024, stderrCaptureLimitBytes = 1024,
        ))
        when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> if (result.dispatchState != CommandDispatchState.DISPATCHED)
                return ServiceLogSshResult.Failed(ServiceLogFailure.INTERNAL_CONTRACT)
            is CommandCompletion.Unknown -> return ServiceLogSshResult.Failed(ServiceLogFailure.TRANSPORT_UNCERTAIN)
            is CommandCompletion.ConfirmedFailure -> return ServiceLogSshResult.Failed(
                if (completion.exitCode == 127) ServiceLogFailure.COMMAND_UNAVAILABLE else ServiceLogFailure.COMMAND_FAILED)
        }
        // A warning about limited journal access must never become a misleading empty/success result.
        if (result.stderr.sizeBytes != 0 || result.stderr.truncated)
            return ServiceLogSshResult.Failed(ServiceLogFailure.INCOMPLETE_ACCESS)
        if (result.stdout.truncated || result.stdout.sizeBytes > 128 * 1024)
            return ServiceLogSshResult.Failed(ServiceLogFailure.OUTPUT_LIMIT)
        val bytes = result.stdout.copyBytes()
        val parsed = try {
            val raw = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            ServiceLogJsonProjection.parse(raw, unit)
        } catch (_: Exception) { null } finally { Arrays.fill(bytes, 0) }
        return parsed?.let { ServiceLogSshResult.Completed(ServiceLogSnapshot(scope, it.first, it.second, now())) }
            ?: ServiceLogSshResult.Failed(ServiceLogFailure.MALFORMED_OUTPUT)
    }
    private suspend fun verifyServiceExecutable(unit: String, expectedBinary: String, handle: SshSessionHandle): Boolean {
        val probe = runCatching { DeepDiagnosticProbeSpec.ServiceDefinitionReadback(unit, expectedBinary) }.getOrNull() ?: return false
        val command = DeepDiagnosticReadOnlyCommandCompiler.compile(probe) ?: return false
        val result = handle.execute(command, SshTransportConfig(channelOpenTimeout = Duration.ofSeconds(5),
            commandExecutionTimeout = Duration.ofSeconds(15), stdoutCaptureLimitBytes = 4096, stderrCaptureLimitBytes = 1024))
        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.completion != CommandCompletion.ConfirmedSuccess ||
            result.stdout.truncated || result.stdout.sizeBytes > 4096 || result.stderr.truncated || result.stderr.sizeBytes != 0) return false
        val bytes = result.stdout.copyBytes()
        return try {
            val raw = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            DeepDiagnosticProbeParsers.parseServiceDefinition(raw, expectedBinary) == DeepDiagnosticServiceDefinitionStatus.CONSISTENT
        } catch (_: Exception) { false } finally { Arrays.fill(bytes, 0) }
    }

}

internal object ServiceLogCommandCompiler {
    fun compile(unit: String): RemoteCommand? {
        if (!Regex("[A-Za-z0-9_][A-Za-z0-9_.@:-]{0,246}\\.service").matches(unit)) return null
        // Field equality excludes unrelated units. Do not use --quiet: access warnings must reach stderr.
        return RemoteCommand.create(
            "command -v journalctl >/dev/null 2>&1 || exit 127; " +
                "LC_ALL=C SYSTEMD_COLORS=0 SYSTEMD_URLIFY=0 journalctl --no-pager --lines=101 " +
                "--output=json --output-fields=__REALTIME_TIMESTAMP,PRIORITY,MESSAGE,_SYSTEMD_UNIT " +
                "'_SYSTEMD_UNIT=$unit'",
            "service-log-read-bounded",
        )
    }
}

/**
 * Strict bounded journal JSON subset. Unknown/duplicate fields and malformed records fail closed.
 * Arbitrary MESSAGE bytes are NEVER returned: only fixed categories, time and priority survive.
 * Binary/multi-valued MESSAGE is consumed as JSON and suppressed, not decoded into UI text.
 */
internal object ServiceLogJsonProjection {
    fun parse(raw: String, unit: String): Pair<List<ServiceLogEntry>, Boolean>? {
        if (raw.length > 128 * 1024) return null
        val lines = raw.lineSequence().filter { it.isNotBlank() }.toList()
        if (lines.size > 101) return null
        val entries = lines.map { line ->
            if (line.length > 8192) return null
            val fields = FlatJournalJson(line).parse() ?: return null
            if (fields["_SYSTEMD_UNIT"] != unit) return null
            val stamp = fields["__REALTIME_TIMESTAMP"] ?: return null
            if (!Regex("[0-9]{1,18}").matches(stamp)) return null
            val micros = stamp.toLongOrNull() ?: return null
            val at = runCatching { Instant.ofEpochSecond(micros / 1_000_000, (micros % 1_000_000) * 1000) }.getOrNull()
                ?: return null
            val priority = fields["PRIORITY"]?.let {
                if (!Regex("[0-7]").matches(it)) return null
                it.toInt()
            }
            ServiceLogEntry(at, priority, classify(fields["MESSAGE"]))
        }
        return entries.takeLast(100) to (entries.size > 100)
    }

    private fun classify(message: String?): ServiceLogCategory {
        val text = message?.lowercase(Locale.ROOT) ?: return ServiceLogCategory.OTHER_REDACTED
        return when {
            "connection refused" in text -> ServiceLogCategory.CONNECTION_REFUSED
            "timed out" in text || "timeout" in text -> ServiceLogCategory.TIMEOUT
            "tls handshake error" in text || "certificate has expired" in text -> ServiceLogCategory.TLS_ERROR
            "permission denied" in text -> ServiceLogCategory.PERMISSION_DENIED
            "address already in use" in text -> ServiceLogCategory.ADDRESS_IN_USE
            else -> ServiceLogCategory.OTHER_REDACTED
        }
    }
}

private class FlatJournalJson(private val text: String) {
    private var i = 0
    private val allowed = setOf("__REALTIME_TIMESTAMP", "__MONOTONIC_TIMESTAMP", "__CURSOR", "_BOOT_ID",
        "__SEQNUM", "__SEQNUM_ID", "PRIORITY", "MESSAGE", "_SYSTEMD_UNIT")

    fun parse(): Map<String, String?>? = runCatching {
        val fields = linkedMapOf<String, String?>()
        expect('{')
        if (!take('}')) {
            do {
                val key = string()
                require(key in allowed && !fields.containsKey(key))
                expect(':')
                fields[key] = value(0)
            } while (take(','))
            expect('}')
        }
        space(); require(i == text.length)
        fields
    }.getOrNull()

    private fun value(depth: Int): String? {
        space(); require(depth < 3 && i < text.length)
        if (text[i] == '"') return string()
        if (take('[')) {
            var count = 0
            if (!take(']')) {
                do { require(++count <= 4096); value(depth + 1) } while (take(','))
                expect(']')
            }
            return null
        }
        if (text.startsWith("null", i)) { i += 4; return null }
        val start = i
        while (i < text.length && text[i] in '0'..'9') i++
        require(i > start && i - start <= 3)
        require(i - start == 1 || text[start] != '0')
        require(text.substring(start, i).toInt() in 0..255)
        return null
    }

    private fun string(): String {
        expect('"')
        val out = StringBuilder()
        while (i < text.length) {
            val c = text[i++]
            if (c == '"') return out.toString()
            require(c.code >= 32)
            if (c != '\\') out.append(c) else {
                require(i < text.length)
                when (val escape = text[i++]) {
                    '"', '\\', '/' -> out.append(escape)
                    'b' -> out.append('\b')
                    'f' -> out.append('\u000c')
                    'n' -> out.append('\n')
                    'r' -> out.append('\r')
                    't' -> out.append('\t')
                    'u' -> {
                        require(i + 4 <= text.length)
                        val code = text.substring(i, i + 4).toIntOrNull(16) ?: error("Invalid escape")
                        out.append(code.toChar()); i += 4
                    }
                    else -> error("Invalid escape")
                }
            }
            require(out.length <= 8192)
        }
        error("Unterminated string")
    }
    private fun space() { while (i < text.length && text[i] in " \t\r\n") i++ }
    private fun take(c: Char): Boolean { space(); return if (i < text.length && text[i] == c) { i++; true } else false }
    private fun expect(c: Char) { require(take(c)) }
}
