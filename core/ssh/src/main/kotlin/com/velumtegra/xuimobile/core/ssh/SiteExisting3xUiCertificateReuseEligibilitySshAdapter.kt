package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityObservation
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * Phase 11.65 exact real-VPS read-only 3x-ui certificate discovery adapter.
 *
 * Callers cannot provide command strings. The finite command vocabulary reads exactly the 3x-ui
 * SQLite certificate/key references, public X.509 metadata and certificate file SHA-256, then only
 * probes the referenced private-key path type. Private-key bytes are never read or passed to a
 * parser/process, and this adapter has no mutation command.
 */
class SiteExisting3xUiCertificateReuseEligibilitySshAdapter {
    suspend fun observe(
        plan: SiteExisting3xUiCertificateReuseEligibilityPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ): SiteExisting3xUiCertificateReuseEligibilityObservation {
        SiteExisting3xUiCertificateReuseEligibilityBoundary.validatePlan(plan)
        require(access.endpoint.host == plan.remoteHostIdentity) {
            "Phase 11.65 certificate discovery host differs from exact SSH endpoint"
        }
        require(session.binding.serverAccessId == access.id) { "SSH session is not bound to requested ServerAccess" }
        require(session.binding.owner is SessionOwner.Operation) { "Phase 11.65 requires operation-owned SSH session" }
        require(session.isOpen) { "SSH session is closed" }
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("SSH session does not expose verified host-key evidence")

        var commandCount = 0
        suspend fun runText(raw: String, label: String): String {
            commandCount += 1
            return executeText(session, RemoteCommand.create(raw, label))
        }

        val references = parseReferenceObservation(
            runText(referenceDiscoveryCommand(plan.databasePath), "site-cert-3x-ui-reference-discovery"),
        )
        val certificatePath = canonicalDerivedPathOrNull(references.certificatePath)
        val privateKeyPath = canonicalDerivedPathOrNull(references.privateKeyPath)

        var certificatePathType: SiteWebServingObservedPathType? = null
        var certificateSha256: String? = null
        var dnsNames: List<String> = emptyList()
        var notBeforeEpochMillis: Long? = null
        var notAfterEpochMillis: Long? = null
        if (certificatePath != null) {
            val metadata = parseCertificateMetadata(
                runText(certificateMetadataCommand(certificatePath), "site-cert-public-certificate-metadata"),
            )
            certificatePathType = metadata.pathType
            certificateSha256 = metadata.sha256
            dnsNames = metadata.dnsNames
            notBeforeEpochMillis = metadata.notBeforeEpochMillis
            notAfterEpochMillis = metadata.notAfterEpochMillis
        }

        val privateKeyPathType = if (privateKeyPath != null) {
            SiteWebServingObservedPathType.valueOf(
                runText(pathTypeCommand(privateKeyPath), "site-cert-private-key-presence").trim(),
            )
        } else null

        return SiteExisting3xUiCertificateReuseEligibilityObservation(
            remoteHostIdentity = plan.remoteHostIdentity,
            verifiedHostKeySha256 = verified.verifiedHostKeySha256,
            databasePath = plan.databasePath,
            databasePathType = references.databasePathType,
            sqliteReadOnlyAvailable = references.sqliteReadOnlyAvailable,
            certificatePath = certificatePath,
            privateKeyPath = privateKeyPath,
            certificatePathType = certificatePathType,
            privateKeyPathType = privateKeyPathType,
            certificateSha256 = certificateSha256,
            certificateDnsNames = dnsNames,
            certificateNotBeforeEpochMillis = notBeforeEpochMillis,
            certificateNotAfterEpochMillis = notAfterEpochMillis,
            remoteCommandCount = commandCount,
            mutationOperationPerformed = false,
            arbitraryCommandAccepted = false,
            privateKeyContentReadPerformed = false,
        )
    }

    private data class ReferenceObservation(
        val databasePathType: SiteWebServingObservedPathType,
        val sqliteReadOnlyAvailable: Boolean,
        val certificatePath: String?,
        val privateKeyPath: String?,
    )

    private data class CertificateMetadata(
        val pathType: SiteWebServingObservedPathType,
        val sha256: String?,
        val dnsNames: List<String>,
        val notBeforeEpochMillis: Long?,
        val notAfterEpochMillis: Long?,
    )

    private fun referenceDiscoveryCommand(databasePath: String): String {
        require(databasePath == SiteExisting3xUiCertificateReuseEligibilityBoundary.DATABASE_PATH)
        val db = quoteDerivedPath(databasePath)
        val sql = "SELECT 'CERT=' || COALESCE((SELECT value FROM settings WHERE key='webCertFile' LIMIT 1),''); " +
            "SELECT 'KEY=' || COALESCE((SELECT value FROM settings WHERE key='webKeyFile' LIMIT 1),'');"
        val qSql = shellQuoteConstant(sql)
        val pythonReadOnly = shellQuoteConstant(
            "import sqlite3,sys; " +
                "c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); " +
                "c.execute('PRAGMA query_only=ON'); " +
                "cert=c.execute(\"SELECT value FROM settings WHERE key='webCertFile' LIMIT 1\").fetchone(); " +
                "key=c.execute(\"SELECT value FROM settings WHERE key='webKeyFile' LIMIT 1\").fetchone(); " +
                "print('CERT='+str(cert[0] if cert and cert[0] is not None else '')); " +
                "print('KEY='+str(key[0] if key and key[0] is not None else '')); c.close()",
        )
        return "if [ -L $db ]; then printf 'DB=SYMLINK\\nSQLITE=SKIPPED\\nCERT=\\nKEY=\\n'; exit 0; " +
            "elif [ -d $db ]; then printf 'DB=DIRECTORY\\nSQLITE=SKIPPED\\nCERT=\\nKEY=\\n'; exit 0; " +
            "elif [ ! -e $db ]; then printf 'DB=ABSENT\\nSQLITE=SKIPPED\\nCERT=\\nKEY=\\n'; exit 0; " +
            "elif [ ! -f $db ]; then printf 'DB=OTHER\\nSQLITE=SKIPPED\\nCERT=\\nKEY=\\n'; exit 0; fi; " +
            "if command -v sqlite3 >/dev/null 2>&1; then " +
            "out=\$(sqlite3 -readonly -batch -noheader $db $qSql 2>/dev/null); code=\$?; " +
            "elif command -v python3 >/dev/null 2>&1; then " +
            "out=\$(python3 -c $pythonReadOnly $db 2>/dev/null); code=\$?; " +
            "else printf 'DB=FILE\\nSQLITE=ABSENT\\nCERT=\\nKEY=\\n'; exit 0; fi; " +
            "if [ \$code -ne 0 ]; then printf 'DB=FILE\\nSQLITE=ERROR\\nCERT=\\nKEY=\\n'; exit 0; fi; " +
            "printf 'DB=FILE\\nSQLITE=PRESENT\\n%s\\n' \"\$out\""
    }

    private fun certificateMetadataCommand(path: String): String {
        val q = quoteDerivedPath(path)
        return "if [ -L $q ]; then printf 'TYPE=SYMLINK\\n'; exit 0; " +
            "elif [ -d $q ]; then printf 'TYPE=DIRECTORY\\n'; exit 0; " +
            "elif [ ! -e $q ]; then printf 'TYPE=ABSENT\\n'; exit 0; " +
            "elif [ ! -f $q ]; then printf 'TYPE=OTHER\\n'; exit 0; fi; " +
            "printf 'TYPE=FILE\\n'; " +
            "if ! command -v sha256sum >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then printf 'METADATA=UNAVAILABLE\\n'; exit 0; fi; " +
            "sha=\$(sha256sum -- $q 2>/dev/null | cut -d' ' -f1); " +
            "case \"\$sha\" in (*[!0-9a-f]*|'') printf 'METADATA=UNAVAILABLE\\n'; exit 0;; esac; " +
            "printf 'SHA256=%s\\n' \"\$sha\"; " +
            "meta=\$(LC_ALL=C openssl x509 -in $q -noout -startdate -enddate -ext subjectAltName 2>/dev/null); code=\$?; " +
            "if [ \$code -ne 0 ]; then printf 'METADATA=UNAVAILABLE\\n'; exit 0; fi; printf '%s\\n' \"\$meta\""
    }

    private fun pathTypeCommand(path: String): String {
        val q = quoteDerivedPath(path)
        return "if [ -L $q ]; then printf 'SYMLINK\\n'; " +
            "elif [ -d $q ]; then printf 'DIRECTORY\\n'; " +
            "elif [ -f $q ]; then printf 'FILE\\n'; " +
            "elif [ -e $q ]; then printf 'OTHER\\n'; else printf 'ABSENT\\n'; fi"
    }

    private fun parseReferenceObservation(text: String): ReferenceObservation {
        val values = strictKeyValues(text, setOf("DB", "SQLITE", "CERT", "KEY"))
        val databaseType = SiteWebServingObservedPathType.valueOf(values.getValue("DB"))
        val sqliteAvailable = values.getValue("SQLITE") == "PRESENT"
        return ReferenceObservation(
            databasePathType = databaseType,
            sqliteReadOnlyAvailable = sqliteAvailable,
            certificatePath = values.getValue("CERT").takeIf(String::isNotBlank),
            privateKeyPath = values.getValue("KEY").takeIf(String::isNotBlank),
        )
    }

    private fun parseCertificateMetadata(text: String): CertificateMetadata {
        val typeLine = text.lineSequence().firstOrNull { it.startsWith("TYPE=") }
            ?: throw IllegalArgumentException("Phase 11.65 certificate path type is missing")
        val pathType = SiteWebServingObservedPathType.valueOf(typeLine.substringAfter('=').trim())
        if (pathType != SiteWebServingObservedPathType.FILE) {
            return CertificateMetadata(pathType, null, emptyList(), null, null)
        }
        val sha = text.lineSequence().firstOrNull { it.startsWith("SHA256=") }
            ?.substringAfter('=')?.trim()?.takeIf { it.matches(Regex("^[0-9a-f]{64}$")) }
        val notBefore = text.lineSequence().firstOrNull { it.startsWith("notBefore=") }
            ?.substringAfter('=')?.let(::parseOpenSslInstant)
        val notAfter = text.lineSequence().firstOrNull { it.startsWith("notAfter=") }
            ?.substringAfter('=')?.let(::parseOpenSslInstant)
        val dnsNames = DNS_NAME.findAll(text)
            .map { it.groupValues[1].trim().lowercase(Locale.ROOT) }
            .filter { it.isNotBlank() }
            .distinct()
            .sorted()
            .take(SiteExisting3xUiCertificateReuseEligibilityBoundary.MAX_DNS_NAMES + 1)
            .toList()
        return CertificateMetadata(pathType, sha, dnsNames, notBefore, notAfter)
    }

    private fun parseOpenSslInstant(value: String): Long? = runCatching {
        val normalized = value.trim().replace(Regex("\\s+"), " ")
        ZonedDateTime.parse(normalized, OPENSSL_DATE_FORMATTER).toInstant().toEpochMilli()
    }.getOrNull()

    private fun strictKeyValues(text: String, expected: Set<String>): Map<String, String> {
        val result = linkedMapOf<String, String>()
        text.lineSequence().map { it.trimEnd('\r') }.filter { it.isNotBlank() }.forEach { line ->
            val split = line.indexOf('=')
            require(split > 0) { "Malformed Phase 11.65 reference observation" }
            val key = line.substring(0, split)
            require(key in expected && key !in result) { "Unexpected Phase 11.65 reference observation key" }
            result[key] = line.substring(split + 1)
        }
        require(result.keys == expected) { "Incomplete Phase 11.65 reference observation" }
        return result
    }

    private fun canonicalDerivedPathOrNull(raw: String?): String? {
        if (raw == null || raw.length !in 2..220 || !raw.startsWith('/') || raw.endsWith('/')) return null
        if ('\\' in raw || '\u0000' in raw || "//" in raw || '\n' in raw || '\r' in raw || '\'' in raw) return null
        val segments = raw.split('/').drop(1)
        if (segments.isEmpty() || segments.any { it.isBlank() || it == "." || it == ".." || !PATH_SEGMENT.matches(it) }) return null
        return raw
    }

    private suspend fun executeText(session: SshSessionHandle, command: RemoteCommand): String {
        val result = session.execute(command, READ_ONLY_CONFIG)
        require(result.dispatchState == CommandDispatchState.DISPATCHED) { "Phase 11.65 read-only command was not dispatched" }
        require(!result.stdout.truncated && !result.stderr.truncated) { "Phase 11.65 read-only output was truncated" }
        require(result.completion == CommandCompletion.ConfirmedSuccess) { "Phase 11.65 read-only command failed" }
        return decodeUtf8(result.stdout.copyBytes())
    }

    private fun quoteDerivedPath(path: String): String {
        require(canonicalDerivedPathOrNull(path) == path) { "Unsafe Phase 11.65 derived path" }
        return "'$path'"
    }

    private fun shellQuoteConstant(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"

    private fun decodeUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()

    companion object {
        private val PATH_SEGMENT = Regex("^[A-Za-z0-9._-]+$")
        private val DNS_NAME = Regex("DNS:([^,\\s]+)")
        private val OPENSSL_DATE_FORMATTER = DateTimeFormatter.ofPattern("MMM d HH:mm:ss yyyy z", Locale.US)
        private val READ_ONLY_CONFIG = SshTransportConfig(
            stdoutCaptureLimitBytes = 16 * 1024,
            stderrCaptureLimitBytes = 16 * 1024,
        )
    }
}
