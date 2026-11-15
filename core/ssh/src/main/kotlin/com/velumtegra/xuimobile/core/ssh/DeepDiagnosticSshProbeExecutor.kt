package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.DeepDiagnosticProbePlan
import com.velumtegra.xuimobile.core.domain.DeepDiagnosticProbeSpec
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.DeepDiagnosticBinaryVersionStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticCertificateReferences
import com.velumtegra.xuimobile.core.model.DeepDiagnosticDatabaseIntegrityStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticDatabaseSchemaStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticEvidence
import com.velumtegra.xuimobile.core.model.DeepDiagnosticFilePresence
import com.velumtegra.xuimobile.core.model.DeepDiagnosticObservation
import com.velumtegra.xuimobile.core.model.DeepDiagnosticScope
import com.velumtegra.xuimobile.core.model.DeepDiagnosticServiceDefinitionStatus
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.XuiInstallation
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.Arrays
import java.util.Locale

/**
 * Exact bounded SSH executor for the deep-specific portion of one explicit DEEP_DIAGNOSTIC operation.
 *
 * The canonical Management read-back prelude is intentionally executed by ManagementSshProbeExecutor
 * in the later runtime slice. This executor owns no connection/reconnect/session lifecycle and accepts
 * only an already-open exact operation-owned session.
 */
class DeepDiagnosticSshProbeExecutor(
    private val now: () -> Instant = Instant::now,
) {
    suspend fun execute(
        scope: DeepDiagnosticScope,
        installation: XuiInstallation,
        handle: SshSessionHandle,
    ): DeepDiagnosticSshProbeRunResult {
        if (scope.serverId != installation.serverId || scope.installationId != installation.id) {
            return failed(scope, null, DeepDiagnosticSshProbeExecutionFailure.ScopeTargetMismatch)
        }
        if (!exactBindingMatches(scope, handle)) {
            return failed(scope, null, DeepDiagnosticSshProbeExecutionFailure.ExactSessionBindingMismatch)
        }
        if (!handle.isOpen) {
            return failed(scope, null, DeepDiagnosticSshProbeExecutionFailure.SessionClosed)
        }

        val observations = mutableListOf<DeepDiagnosticObservation>()
        val primary = DeepDiagnosticProbePlan.forInstallation(installation).primaryProbes
        for (probe in primary) {
            when (val outcome = executeOne(probe, handle)) {
                is ProbeNormalization.Observation -> observations += outcome.observation
                is ProbeNormalization.Failed -> return failed(scope, probe, outcome.failure, observations)
            }
        }

        val references = observations.filterIsInstance<DeepDiagnosticObservation.CertificateReferences>().singleOrNull()
            ?: return failed(
                scope,
                null,
                DeepDiagnosticSshProbeExecutionFailure.MalformedProbeEvidence,
                observations,
            )

        for (probe in DeepDiagnosticProbePlan.derivedCertificateProbes(references.references)) {
            when (val outcome = executeOne(probe, handle)) {
                is ProbeNormalization.Observation -> observations += outcome.observation
                is ProbeNormalization.Failed -> return failed(scope, probe, outcome.failure, observations)
            }
        }

        return DeepDiagnosticSshProbeRunResult.Completed(
            DeepDiagnosticEvidence(scope = scope, observations = observations.toList()),
        )
    }

    private fun exactBindingMatches(scope: DeepDiagnosticScope, handle: SshSessionHandle): Boolean =
        handle.binding.serverAccessId == scope.serverAccessId &&
            handle.binding.owner == SessionOwner.Operation(scope.operationId)

    private suspend fun executeOne(
        probe: DeepDiagnosticProbeSpec,
        handle: SshSessionHandle,
    ): ProbeNormalization {
        val command = DeepDiagnosticReadOnlyCommandCompiler.compile(probe)
            ?: return ProbeNormalization.Failed(DeepDiagnosticSshProbeExecutionFailure.ProbeOutsideApprovedPolicy)
        if (!handle.isOpen) {
            return ProbeNormalization.Failed(DeepDiagnosticSshProbeExecutionFailure.SessionClosed)
        }
        val result = handle.execute(command, transportConfigFor(probe))
        return normalize(probe, result)
    }

    private fun normalize(probe: DeepDiagnosticProbeSpec, result: SshCommandResult): ProbeNormalization = when (probe) {
        is DeepDiagnosticProbeSpec.ServiceDefinitionReadback -> normalizeText(result) { raw ->
            DeepDiagnosticProbeParsers.parseServiceDefinition(raw, probe.expectedBinaryPath)?.let { status ->
                observation(
                    DeepDiagnosticObservation.ServiceDefinition(
                        serviceUnit = probe.serviceUnit,
                        expectedBinaryPath = probe.expectedBinaryPath,
                        status = status,
                        observedAt = now(),
                    ),
                )
            } ?: malformed()
        }
        is DeepDiagnosticProbeSpec.BinaryVersionReadback -> normalizeTextAllowConfirmedFailure(result) { raw, success ->
            val parsed = if (success) DeepDiagnosticProbeParsers.parseBinaryVersion(raw) else null
            observation(
                DeepDiagnosticObservation.BinaryVersion(
                    binaryPath = probe.binaryPath,
                    status = if (parsed != null) DeepDiagnosticBinaryVersionStatus.AVAILABLE else DeepDiagnosticBinaryVersionStatus.UNAVAILABLE,
                    normalizedVersion = parsed,
                    observedAt = now(),
                ),
            )
        }
        is DeepDiagnosticProbeSpec.DatabaseQuickCheck -> normalizeTextAllowConfirmedFailure(result) { raw, success ->
            val status = when {
                !success -> DeepDiagnosticDatabaseIntegrityStatus.UNREADABLE
                DeepDiagnosticProbeParsers.parseDatabaseQuickCheck(raw) == true -> DeepDiagnosticDatabaseIntegrityStatus.OK
                DeepDiagnosticProbeParsers.parseDatabaseQuickCheck(raw) == false -> DeepDiagnosticDatabaseIntegrityStatus.FAILED
                else -> return@normalizeTextAllowConfirmedFailure malformed()
            }
            observation(DeepDiagnosticObservation.DatabaseIntegrity(probe.databasePath, status, now()))
        }
        is DeepDiagnosticProbeSpec.DatabaseSchemaReadback -> normalizeTextAllowConfirmedFailure(result) { raw, success ->
            val status = when {
                !success -> DeepDiagnosticDatabaseSchemaStatus.UNREADABLE
                else -> DeepDiagnosticProbeParsers.parseDatabaseSchema(raw) ?: return@normalizeTextAllowConfirmedFailure malformed()
            }
            observation(DeepDiagnosticObservation.DatabaseSchema(probe.databasePath, status, now()))
        }
        is DeepDiagnosticProbeSpec.CertificateReferencesReadback -> normalizeText(result) { raw ->
            val refs = DeepDiagnosticProbeParsers.parseCertificateReferences(raw) ?: return@normalizeText malformed()
            observation(DeepDiagnosticObservation.CertificateReferences(probe.databasePath, refs, now()))
        }
        is DeepDiagnosticProbeSpec.ExactCertificateFileReadback -> normalizeText(result) { raw ->
            val metadata = DeepDiagnosticProbeParsers.parseCertificateFile(raw) ?: return@normalizeText malformed()
            observation(
                DeepDiagnosticObservation.CertificateFile(
                    path = probe.certificatePath,
                    presence = metadata.presence,
                    notBefore = metadata.notBefore,
                    notAfter = metadata.notAfter,
                    observedAt = now(),
                ),
            )
        }
        is DeepDiagnosticProbeSpec.ExactPrivateKeyPresence -> normalizeText(result) { raw ->
            val presence = DeepDiagnosticProbeParsers.parseFilePresence(raw) ?: return@normalizeText malformed()
            observation(DeepDiagnosticObservation.PrivateKeyFile(probe.privateKeyPath, presence, now()))
        }
    }

    private fun normalizeText(
        result: SshCommandResult,
        parse: (String) -> ProbeNormalization,
    ): ProbeNormalization {
        when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> Unit
            is CommandCompletion.ConfirmedFailure -> {
                return ProbeNormalization.Failed(DeepDiagnosticSshProbeExecutionFailure.CommandFailed(completion.exitCode))
            }
            is CommandCompletion.Unknown -> {
                return ProbeNormalization.Failed(
                    DeepDiagnosticSshProbeExecutionFailure.CommandUncertain(result.dispatchState),
                )
            }
        }
        return decodeCapturedText(result, parse)
    }

    private fun normalizeTextAllowConfirmedFailure(
        result: SshCommandResult,
        parse: (raw: String, success: Boolean) -> ProbeNormalization,
    ): ProbeNormalization {
        val success = when (result.completion) {
            CommandCompletion.ConfirmedSuccess -> true
            is CommandCompletion.ConfirmedFailure -> false
            is CommandCompletion.Unknown -> {
                return ProbeNormalization.Failed(
                    DeepDiagnosticSshProbeExecutionFailure.CommandUncertain(result.dispatchState),
                )
            }
        }
        return decodeCapturedText(result) { raw -> parse(raw, success) }
    }

    private fun decodeCapturedText(
        result: SshCommandResult,
        parse: (String) -> ProbeNormalization,
    ): ProbeNormalization {
        if (result.stdout.truncated) {
            return ProbeNormalization.Failed(DeepDiagnosticSshProbeExecutionFailure.OutputTruncated)
        }
        val bytes = result.stdout.copyBytes()
        val raw = try {
            decodeUtf8Strict(bytes) ?: return malformed()
        } finally {
            Arrays.fill(bytes, 0)
        }
        return parse(raw)
    }

    private fun transportConfigFor(probe: DeepDiagnosticProbeSpec): SshTransportConfig = SshTransportConfig(
        channelOpenTimeout = probe.timeout.coerceAtMost(MAX_CHANNEL_OPEN_TIMEOUT),
        commandExecutionTimeout = probe.timeout,
        stdoutCaptureLimitBytes = DEEP_STDOUT_LIMIT_BYTES,
        stderrCaptureLimitBytes = DEEP_STDERR_LIMIT_BYTES,
    )

    private fun decodeUtf8Strict(bytes: ByteArray): String? = runCatching {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    }.getOrNull()

    private fun observation(value: DeepDiagnosticObservation): ProbeNormalization = ProbeNormalization.Observation(value)

    private fun malformed(): ProbeNormalization = ProbeNormalization.Failed(
        DeepDiagnosticSshProbeExecutionFailure.MalformedProbeEvidence,
    )

    private fun failed(
        scope: DeepDiagnosticScope,
        failedProbe: DeepDiagnosticProbeSpec?,
        failure: DeepDiagnosticSshProbeExecutionFailure,
        observations: List<DeepDiagnosticObservation> = emptyList(),
    ): DeepDiagnosticSshProbeRunResult.Failed = DeepDiagnosticSshProbeRunResult.Failed(
        scope = scope,
        failedProbe = failedProbe,
        failure = failure,
        observations = observations.toList(),
    )

    private sealed interface ProbeNormalization {
        data class Observation(val observation: DeepDiagnosticObservation) : ProbeNormalization
        data class Failed(val failure: DeepDiagnosticSshProbeExecutionFailure) : ProbeNormalization
    }

    companion object {
        private val MAX_CHANNEL_OPEN_TIMEOUT: Duration = Duration.ofSeconds(5)
        private const val DEEP_STDOUT_LIMIT_BYTES = 8 * 1024
        private const val DEEP_STDERR_LIMIT_BYTES = 2 * 1024
    }
}

sealed interface DeepDiagnosticSshProbeRunResult {
    data class Completed(val evidence: DeepDiagnosticEvidence) : DeepDiagnosticSshProbeRunResult

    data class Failed(
        val scope: DeepDiagnosticScope,
        val failedProbe: DeepDiagnosticProbeSpec?,
        val failure: DeepDiagnosticSshProbeExecutionFailure,
        val observations: List<DeepDiagnosticObservation>,
    ) : DeepDiagnosticSshProbeRunResult
}

sealed interface DeepDiagnosticSshProbeExecutionFailure {
    data object ScopeTargetMismatch : DeepDiagnosticSshProbeExecutionFailure
    data object ExactSessionBindingMismatch : DeepDiagnosticSshProbeExecutionFailure
    data object SessionClosed : DeepDiagnosticSshProbeExecutionFailure
    data object ProbeOutsideApprovedPolicy : DeepDiagnosticSshProbeExecutionFailure
    data class CommandUncertain(val dispatchState: CommandDispatchState) : DeepDiagnosticSshProbeExecutionFailure
    data class CommandFailed(val exitCode: Int?) : DeepDiagnosticSshProbeExecutionFailure
    data object OutputTruncated : DeepDiagnosticSshProbeExecutionFailure
    data object MalformedProbeEvidence : DeepDiagnosticSshProbeExecutionFailure
}

internal object DeepDiagnosticReadOnlyCommandCompiler {
    private val maxProbeTimeout = Duration.ofSeconds(30)
    private val serviceUnitRegex = Regex("[A-Za-z0-9_.@:-]{1,255}")
    private val pathRegex = Regex("/[A-Za-z0-9_./@:+-]{0,1023}")

    fun compile(probe: DeepDiagnosticProbeSpec): RemoteCommand? {
        if (probe.timeout.isZero || probe.timeout.isNegative || probe.timeout > maxProbeTimeout) return null

        val raw: String
        val label: String
        when (probe) {
            is DeepDiagnosticProbeSpec.ServiceDefinitionReadback -> {
                if (!isSafeServiceUnit(probe.serviceUnit) || !isSafeAbsolutePath(probe.expectedBinaryPath)) return null
                val unit = shellQuote(probe.serviceUnit)
                raw = "command -v systemctl >/dev/null 2>&1 || { printf 'LOAD=unreadable\\n'; exit 0; }; " +
                    "load=\$(systemctl show --property=LoadState --value -- $unit 2>/dev/null) || { printf 'LOAD=unreadable\\n'; exit 0; }; " +
                    "printf 'LOAD=%s\\n' \"\$load\"; [ \"\$load\" = 'not-found' ] && exit 0; " +
                    "exec=\$(systemctl show --property=ExecStart --value -- $unit 2>/dev/null) || exit 2; printf 'EXEC=%s\\n' \"\$exec\""
                label = "deep-service-definition"
            }
            is DeepDiagnosticProbeSpec.BinaryVersionReadback -> {
                if (!isSafeAbsolutePath(probe.binaryPath)) return null
                raw = "${shellQuote(probe.binaryPath)} -v"
                label = "deep-binary-version"
            }
            is DeepDiagnosticProbeSpec.DatabaseQuickCheck -> {
                if (!isSafeAbsolutePath(probe.databasePath)) return null
                raw = "command -v sqlite3 >/dev/null 2>&1 || exit 2; " +
                    "sqlite3 -readonly -batch -noheader ${shellQuote(probe.databasePath)} ${shellQuote("PRAGMA quick_check;")}"
                label = "deep-database-quick-check"
            }
            is DeepDiagnosticProbeSpec.DatabaseSchemaReadback -> {
                if (!isSafeAbsolutePath(probe.databasePath)) return null
                val sql = "SELECT CASE WHEN " +
                    "EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='settings') AND " +
                    "EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='inbounds') AND " +
                    "EXISTS(SELECT 1 FROM pragma_table_info('settings') WHERE name='key') AND " +
                    "EXISTS(SELECT 1 FROM pragma_table_info('settings') WHERE name='value') AND " +
                    "EXISTS(SELECT 1 FROM pragma_table_info('inbounds') WHERE name='id') AND " +
                    "EXISTS(SELECT 1 FROM pragma_table_info('inbounds') WHERE name='settings') " +
                    "THEN 'SUPPORTED' ELSE 'INCOMPLETE' END;"
                raw = "command -v sqlite3 >/dev/null 2>&1 || exit 2; " +
                    "sqlite3 -readonly -batch -noheader ${shellQuote(probe.databasePath)} ${shellQuote(sql)}"
                label = "deep-database-schema"
            }
            is DeepDiagnosticProbeSpec.CertificateReferencesReadback -> {
                if (!isSafeAbsolutePath(probe.databasePath)) return null
                val sql = "SELECT 'CERT=' || COALESCE((SELECT value FROM settings WHERE key='webCertFile' LIMIT 1),''); " +
                    "SELECT 'KEY=' || COALESCE((SELECT value FROM settings WHERE key='webKeyFile' LIMIT 1),'');"
                raw = "command -v sqlite3 >/dev/null 2>&1 || exit 2; " +
                    "sqlite3 -readonly -batch -noheader ${shellQuote(probe.databasePath)} ${shellQuote(sql)}"
                label = "deep-certificate-references"
            }
            is DeepDiagnosticProbeSpec.ExactCertificateFileReadback -> {
                if (!isSafeAbsolutePath(probe.certificatePath)) return null
                val path = shellQuote(probe.certificatePath)
                raw = "if [ ! -e $path ]; then printf 'PRESENCE=ABSENT\\n'; exit 0; fi; " +
                    "if [ ! -f $path ] || [ ! -r $path ] || ! command -v openssl >/dev/null 2>&1; then printf 'PRESENCE=UNREADABLE\\n'; exit 0; fi; " +
                    "dates=\$(openssl x509 -in $path -noout -startdate -enddate 2>/dev/null) || { printf 'PRESENCE=UNREADABLE\\n'; exit 0; }; " +
                    "printf 'PRESENCE=PRESENT\\n%s\\n' \"\$dates\""
                label = "deep-certificate-metadata"
            }
            is DeepDiagnosticProbeSpec.ExactPrivateKeyPresence -> {
                if (!isSafeAbsolutePath(probe.privateKeyPath)) return null
                val path = shellQuote(probe.privateKeyPath)
                raw = "if [ ! -e $path ]; then printf 'ABSENT\\n'; elif [ -f $path ] && [ -r $path ]; then printf 'PRESENT\\n'; else printf 'UNREADABLE\\n'; fi"
                label = "deep-private-key-presence"
            }
        }
        return RemoteCommand.create(raw = raw, redactedLabel = label)
    }

    private fun isSafeServiceUnit(value: String): Boolean =
        serviceUnitRegex.matches(value) && value.endsWith(".service")

    private fun isSafeAbsolutePath(value: String): Boolean =
        pathRegex.matches(value) &&
            !value.contains("//") &&
            value.split('/').none { it == "." || it == ".." }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"
}

internal object DeepDiagnosticProbeParsers {
    private const val MAX_SERVICE_DEFINITION_BYTES = 4 * 1024
    private const val MAX_VERSION_BYTES = 256
    private const val MAX_DATABASE_BYTES = 4 * 1024
    private const val MAX_CERT_REFERENCES_BYTES = 2 * 1024
    private const val MAX_CERT_METADATA_BYTES = 2 * 1024

    internal data class CertificateMetadata(
        val presence: DeepDiagnosticFilePresence,
        val notBefore: Instant?,
        val notAfter: Instant?,
    )

    fun parseServiceDefinition(raw: String, expectedBinaryPath: String): DeepDiagnosticServiceDefinitionStatus? {
        if (!bounded(raw, MAX_SERVICE_DEFINITION_BYTES)) return null
        val values = strictKeyValues(raw, setOf("LOAD", "EXEC")) ?: return null
        val load = values["LOAD"] ?: return null
        if (load == "unreadable") return DeepDiagnosticServiceDefinitionStatus.UNREADABLE
        if (load == "not-found") return DeepDiagnosticServiceDefinitionStatus.UNIT_MISSING
        if (load != "loaded") return DeepDiagnosticServiceDefinitionStatus.UNREADABLE
        val exec = values["EXEC"] ?: return DeepDiagnosticServiceDefinitionStatus.UNREADABLE
        val path = Regex("(?:^|[ {;])path=([^ ;}]+)").find(exec)?.groupValues?.get(1)
            ?: return DeepDiagnosticServiceDefinitionStatus.UNREADABLE
        return if (path == expectedBinaryPath) {
            DeepDiagnosticServiceDefinitionStatus.CONSISTENT
        } else {
            DeepDiagnosticServiceDefinitionStatus.EXEC_START_MISMATCH
        }
    }

    fun parseBinaryVersion(raw: String): String? {
        if (!bounded(raw, MAX_VERSION_BYTES)) return null
        val lines = raw.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        if (lines.size != 1) return null
        val value = lines.single()
        if (value.length !in 1..128 || value.any { it == '\u0000' || it == '\r' || it == '\n' }) return null
        return value
    }

    /** true = OK, false = integrity failure, null = malformed transport evidence. */
    fun parseDatabaseQuickCheck(raw: String): Boolean? {
        if (!bounded(raw, MAX_DATABASE_BYTES)) return null
        val lines = raw.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        if (lines.isEmpty()) return null
        return lines.size == 1 && lines.single().equals("ok", ignoreCase = true)
    }

    fun parseDatabaseSchema(raw: String): DeepDiagnosticDatabaseSchemaStatus? {
        if (!bounded(raw, MAX_DATABASE_BYTES)) return null
        return when (raw.trim()) {
            "SUPPORTED" -> DeepDiagnosticDatabaseSchemaStatus.SUPPORTED
            "INCOMPLETE" -> DeepDiagnosticDatabaseSchemaStatus.INCOMPLETE
            else -> null
        }
    }

    fun parseCertificateReferences(raw: String): DeepDiagnosticCertificateReferences? {
        if (!bounded(raw, MAX_CERT_REFERENCES_BYTES)) return null
        val values = strictKeyValues(raw, setOf("CERT", "KEY")) ?: return null
        if (values.keys != setOf("CERT", "KEY")) return null
        return try {
            DeepDiagnosticCertificateReferences(
                certificatePath = values.getValue("CERT").takeIf { it.isNotEmpty() },
                privateKeyPath = values.getValue("KEY").takeIf { it.isNotEmpty() },
            )
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    fun parseCertificateFile(raw: String): CertificateMetadata? {
        if (!bounded(raw, MAX_CERT_METADATA_BYTES)) return null
        val values = strictKeyValues(raw, setOf("PRESENCE", "notBefore", "notAfter")) ?: return null
        return when (values["PRESENCE"]) {
            "ABSENT" -> if (values.size == 1) CertificateMetadata(DeepDiagnosticFilePresence.ABSENT, null, null) else null
            "UNREADABLE" -> if (values.size == 1) CertificateMetadata(DeepDiagnosticFilePresence.UNREADABLE, null, null) else null
            "PRESENT" -> {
                if (values.keys != setOf("PRESENCE", "notBefore", "notAfter")) return null
                val notBefore = parseOpenSslDate(values.getValue("notBefore")) ?: return null
                val notAfter = parseOpenSslDate(values.getValue("notAfter")) ?: return null
                if (notAfter.isBefore(notBefore)) return null
                CertificateMetadata(DeepDiagnosticFilePresence.PRESENT, notBefore, notAfter)
            }
            else -> null
        }
    }

    fun parseFilePresence(raw: String): DeepDiagnosticFilePresence? = when (raw.trim()) {
        "PRESENT" -> DeepDiagnosticFilePresence.PRESENT
        "ABSENT" -> DeepDiagnosticFilePresence.ABSENT
        "UNREADABLE" -> DeepDiagnosticFilePresence.UNREADABLE
        else -> null
    }

    private fun strictKeyValues(raw: String, allowedKeys: Set<String>): LinkedHashMap<String, String>? {
        if ('\u0000' in raw) return null
        val lines = raw.lineSequence().filter { it.isNotBlank() }.toList()
        if (lines.isEmpty() || lines.size > 8) return null
        val values = linkedMapOf<String, String>()
        for (line in lines) {
            val index = line.indexOf('=')
            if (index <= 0) return null
            val key = line.substring(0, index)
            val value = line.substring(index + 1)
            if (key !in allowedKeys || values.put(key, value) != null) return null
        }
        return values
    }

    private fun parseOpenSslDate(value: String): Instant? {
        val normalized = value.trim().replace(Regex("\\s+"), " ")
        val formatter = DateTimeFormatter.ofPattern("MMM d HH:mm:ss yyyy z", Locale.ENGLISH)
        return try {
            ZonedDateTime.parse(normalized, formatter).withZoneSameInstant(ZoneOffset.UTC).toInstant()
        } catch (_: DateTimeParseException) {
            null
        }
    }

    private fun bounded(raw: String, maxBytes: Int): Boolean =
        '\u0000' !in raw && raw.toByteArray(StandardCharsets.UTF_8).size <= maxBytes
}
