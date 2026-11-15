package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.site.SiteCaddyCertificateCandidate
import com.velumtegra.xuimobile.core.site.SiteCaddyCertificatePolicy
import com.velumtegra.xuimobile.core.site.SiteCaddyConfigReader
import com.velumtegra.xuimobile.core.site.SiteCaddyObservation
import com.velumtegra.xuimobile.core.site.SiteCaddyServingPlan
import com.velumtegra.xuimobile.core.site.SiteCaddyServingPlanner
import com.velumtegra.xuimobile.core.site.SiteCaddyTlsFilePair
import com.velumtegra.xuimobile.core.site.SiteCaddyTlsMode
import com.velumtegra.xuimobile.core.site.SiteFirewallObservation
import com.velumtegra.xuimobile.core.site.SiteFirewallState
import com.velumtegra.xuimobile.core.site.SiteListeningSocket
import com.velumtegra.xuimobile.core.site.SiteNginxObservation
import com.velumtegra.xuimobile.core.site.SitePortTlsState
import com.velumtegra.xuimobile.core.site.SiteServiceState
import com.velumtegra.xuimobile.core.site.SiteWebServerInventory
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Base64

/** Result of the read-only web server probe plus the managed site files next to the Caddyfile. */
data class SiteWebServerProbeResult(
    val inventory: SiteWebServerInventory,
    val managedSiteFileNames: Set<String>,
)

enum class SiteCaddyApplyResult {
    APPLIED,

    /** Caddy was not `active` (e.g. stuck in `reloading`); nothing was changed. */
    CADDY_NOT_ACTIVE,

    /** The caddy service user cannot read the referenced certificate or key; nothing was changed. */
    CERTIFICATE_UNREADABLE,
    CADDYFILE_CHANGED,
    SITE_FILE_EXISTS,
    BACKUP_EXISTS,
    BACKUP_FAILED,
    WRITE_FAILED,
    VALIDATE_FAILED,
    RELOAD_FAILED_ROLLED_BACK,
    RELOAD_FAILED_ROLLBACK_FAILED,
}

data class SiteCaddyApplyObservation(
    val result: SiteCaddyApplyResult,
    /** Tail of `caddy validate` / reload output for the operator (already UTF-8 decoded). */
    val detail: String?,
)

data class SiteCaddyVerifyObservation(
    val caddyActive: Boolean,
    val bodySha256: String?,
    val curlExitCode: Int?,
    val listeningPorts: Set<Int>,
    val attempts: Int,
)

enum class SiteCaddyRollbackResult { ROLLED_BACK, NO_BACKUP, ROLLBACK_FAILED }

/**
 * A Caddy SSH command ended without a parsable result: non-zero exit, timeout, lost channel or
 * truncated output. Carries bounded, redacted diagnostics (never the command text or credentials)
 * so the operator sees what actually happened instead of a generic failure.
 */
class SiteCaddyCommandFailedException(
    val label: String,
    val stage: String,
    val exitCode: Int?,
    val timedOut: Boolean,
    val reason: String,
    val stdoutTail: String,
    val stderrTail: String,
) : IllegalStateException(
    buildString {
        append("Этап «").append(stage).append("»: ")
        append(
            when {
                timedOut -> "команда на сервере не уложилась в отведённое время"
                exitCode != null -> "команда на сервере завершилась с кодом $exitCode"
                else -> "команда на сервере завершилась без результата ($reason)"
            },
        )
        val tail = stderrTail.ifBlank { stdoutTail }.trim()
        if (tail.isNotEmpty()) append(". Вывод сервера: ").append(tail)
    },
)

/** Bounds and redacts remote command output before it reaches logs or the UI. */
object SiteCommandOutputRedactor {
    const val DEFAULT_MAX_CHARS: Int = 1024

    private val privateKey = Regex(
        "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\\s\\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
    )
    private val longBase64 = Regex("[A-Za-z0-9+/=]{120,}")
    private val secretAssignment = Regex("(?i)(password|passwd|secret|token|api[_-]?key)(\\s*[=:]\\s*)\\S+")

    fun redact(text: String, maxChars: Int = DEFAULT_MAX_CHARS): String {
        val cleaned = text
            .replace(privateKey, "[private key redacted]")
            .replace(longBase64, "[base64 redacted]")
            .replace(secretAssignment) { "${it.groupValues[1]}${it.groupValues[2]}[redacted]" }
            .filter { it == '\n' || it == '\t' || !it.isISOControl() }
        return if (cleaned.length <= maxChars) cleaned else "…" + cleaned.takeLast(maxChars)
    }
}

/**
 * SSH adapter for the Caddy serving path.
 *
 * - [probe] is strictly read-only: binaries, service states, the Caddyfile digest, `caddy adapt`
 *   (which only translates config, it does not load it), listening sockets, UFW status and a TLS
 *   handshake check on the requested port.
 * - [apply] performs exactly one reviewed mutation: back up the Caddyfile, write one managed site
 *   file, append one import line if missing, `caddy validate`, `caddy reload` (admin API, bounded by `timeout`). Any failing
 *   step restores the backup inside the same remote script; nothing else is touched.
 * - [verify] is read-only (loopback HTTP(S) fetch with SNI, listening sockets).
 * - [rollback] restores the backup and reloads, used when verification fails after apply.
 *
 * DNS, firewall and package changes are never performed.
 */
class SiteCaddyServingSshAdapter {
    suspend fun probe(
        domain: String,
        port: Int,
        session: SshSessionHandle,
    ): SiteWebServerProbeResult {
        requireVerified(session)
        val host = SiteCaddyServingPlanner.canonicalDomain(domain)
        require(port in 1..65535) { "Probe port is invalid" }
        val raw = buildString {
            append("printf 'CADDY_BIN %s\\n' \"$(command -v caddy 2>/dev/null || echo NONE)\"; ")
            append("printf 'NGINX_BIN %s\\n' \"$(command -v nginx 2>/dev/null || echo NONE)\"; ")
            append("if command -v systemctl >/dev/null 2>&1; then ")
            append("printf 'CADDY_ACTIVE %s\\n' \"$(systemctl is-active caddy 2>/dev/null | head -n 1)\"; ")
            append("printf 'NGINX_ACTIVE %s\\n' \"$(systemctl is-active nginx 2>/dev/null | head -n 1)\"; ")
            append("es=$(systemctl show caddy -p ExecStart --value 2>/dev/null | head -c 2000); ")
            append("printf 'CADDY_USER %s\\n' \"$(systemctl show caddy -p User --value 2>/dev/null | head -n 1)\"; ")
            append("else printf 'CADDY_ACTIVE unknown\\nNGINX_ACTIVE unknown\\n'; es=''; fi; ")
            append("cf=$(printf '%s' \"${'$'}es\" | sed -n 's/.*--config[ =]\\([^ ;]*\\).*/\\1/p' | head -n 1); ")
            append("[ -n \"${'$'}cf\" ] || cf=/etc/caddy/Caddyfile; ")
            append("ad=$(printf '%s' \"${'$'}es\" | sed -n 's/.*--adapter[ =]\\([^ ;]*\\).*/\\1/p' | head -n 1); ")
            append("printf 'CADDYFILE %s\\n' \"${'$'}cf\"; printf 'CADDY_ADAPTER %s\\n' \"${'$'}{ad:-NONE}\"; ")
            append("if [ -f \"${'$'}cf\" ]; then printf 'CADDYFILE_SHA %s\\n' \"$(sha256sum < \"${'$'}cf\" | cut -d' ' -f1)\"; ")
            append("if command -v caddy >/dev/null 2>&1; then ")
            append("j=$(caddy adapt --config \"${'$'}cf\" --adapter caddyfile 2>/dev/null | base64 | tr -d '\\n'); ")
            append("printf 'CADDY_ADAPT %s\\n' \"${'$'}{j:-FAILED}\"; fi; ")
            append("md=\"$(dirname \"${'$'}cf\")/velum-sites\"; ")
            append("if grep -qxF \"import ${'$'}md/*.caddy\" \"${'$'}cf\" 2>/dev/null; then echo 'VELUM_IMPORT yes'; else echo 'VELUM_IMPORT no'; fi; ")
            append("if [ -d \"${'$'}md\" ]; then ls -1 \"${'$'}md\" 2>/dev/null | head -n 512 | sed 's/^/MANAGED /'; fi; ")
            append("else echo 'CADDYFILE_SHA ABSENT'; fi; ")
            append("if command -v ss >/dev/null 2>&1; then ss -H -ltnp 2>/dev/null | awk '{print \"L \" ${'$'}4 \" \" ${'$'}NF}' | head -n 1024; ")
            append("else echo 'SS MISSING'; fi; ")
            append("if command -v ufw >/dev/null 2>&1; then u=$(ufw status verbose 2>/dev/null); ")
            append("if [ -n \"${'$'}u\" ]; then printf '%s\\n' \"${'$'}u\" | head -n 400 | sed 's/^/UFW /'; else echo 'UFW_UNKNOWN'; fi; ")
            append("else echo 'UFW_ABSENT'; fi; ")
            append("if command -v curl >/dev/null 2>&1; then ")
            append("t=$(curl -sk -o /dev/null --max-time 4 -w '%{http_code}' --resolve ")
            append(quote("$host:$port:127.0.0.1")).append(' ').append(quote("https://$host:$port/")).append(" 2>/dev/null); ")
            append("if [ \"${'$'}t\" != '000' ] && [ -n \"${'$'}t\" ]; then echo 'PORT_TLS tls'; else ")
            append("h=$(curl -s -o /dev/null --max-time 4 -w '%{http_code}' ").append(quote("http://127.0.0.1:$port/"))
            append(" 2>/dev/null); if [ \"${'$'}h\" != '000' ] && [ -n \"${'$'}h\" ]; then echo 'PORT_TLS plain'; else echo 'PORT_TLS closed'; fi; fi; ")
            append("else echo 'PORT_TLS unknown'; fi")
        }
        val lines = execute(session, raw, "site-web-server-probe-read-only", 1024 * 1024, Duration.ofSeconds(30))
        return parseProbe(lines)
    }

    internal fun parseProbe(lines: List<String>): SiteWebServerProbeResult {
        fun value(key: String): String? = lines.firstOrNull { it.startsWith("$key ") }?.removePrefix("$key ")?.trim()
        fun state(raw: String?): SiteServiceState = when (raw) {
            "active" -> SiteServiceState.ACTIVE
            "reloading" -> SiteServiceState.RELOADING
            "inactive", "failed", "dead" -> SiteServiceState.INACTIVE
            else -> SiteServiceState.UNKNOWN
        }
        val caddyBin = value("CADDY_BIN")?.takeIf { it != "NONE" && it.isNotEmpty() }
        val nginxBin = value("NGINX_BIN")?.takeIf { it != "NONE" && it.isNotEmpty() }
        val caddyfile = value("CADDYFILE") ?: error("Malformed web server probe: no Caddyfile path")
        val caddyfileSha = value("CADDYFILE_SHA")?.takeIf { it != "ABSENT" }
        require(caddyfileSha == null || sha256.matches(caddyfileSha)) { "Malformed Caddyfile digest" }
        val adaptedJson = value("CADDY_ADAPT")?.takeIf { it != "FAILED" }?.let { b64 ->
            runCatching { decodeUtf8(Base64.getDecoder().decode(b64)) }.getOrNull()
        }
        val adapted = adaptedJson?.let { runCatching { SiteCaddyConfigReader.servers(it) }.getOrNull() }
        val tlsPairs = adaptedJson?.let { runCatching { SiteCaddyConfigReader.tlsFilePairs(it) }.getOrNull() }.orEmpty()
        val serviceUser = lines.firstOrNull { it == "CADDY_USER" || it.startsWith("CADDY_USER ") }
            ?.removePrefix("CADDY_USER")?.trim()
            ?.let { if (it.isEmpty()) "root" else it }
            ?.takeIf { serviceUserPattern.matches(it) }
        val listeners = if (lines.any { it == "SS MISSING" }) {
            error("Не удалось проверить занятые порты: на сервере нет утилиты ss (пакет iproute2)")
        } else {
            lines.filter { it.startsWith("L ") }.mapNotNull { line ->
                val parts = line.removePrefix("L ").split(' ', limit = 2)
                val port = parts[0].substringAfterLast(':').toIntOrNull()?.takeIf { it in 1..65535 } ?: return@mapNotNull null
                val processes = processName.findAll(parts.getOrElse(1) { "" }).map { it.groupValues[1] }.toSet()
                SiteListeningSocket(port, processes)
            }
        }
        val ufwLines = lines.filter { it.startsWith("UFW ") }.map { it.removePrefix("UFW ") }
        val firewall = when {
            lines.any { it == "UFW_ABSENT" } -> SiteFirewallObservation(SiteFirewallState.ABSENT, true, emptyList())
            lines.any { it == "UFW_UNKNOWN" } -> SiteFirewallObservation(SiteFirewallState.UNKNOWN, false, emptyList())
            ufwLines.any { it.trim().equals("Status: inactive", ignoreCase = true) } ->
                SiteFirewallObservation(SiteFirewallState.INACTIVE, true, emptyList())
            ufwLines.any { it.trim().equals("Status: active", ignoreCase = true) } -> SiteFirewallObservation(
                state = SiteFirewallState.ACTIVE,
                defaultIncomingAllow = ufwLines.any {
                    it.trim().startsWith("Default:", ignoreCase = true) && Regex("allow \\(incoming\\)", RegexOption.IGNORE_CASE).containsMatchIn(it)
                },
                ruleLines = ufwLines.dropWhile { !it.trim().startsWith("--") }.drop(1).filter { it.isNotBlank() },
            )
            else -> SiteFirewallObservation(SiteFirewallState.UNKNOWN, false, emptyList())
        }
        val tls = when (value("PORT_TLS")) {
            "tls" -> SitePortTlsState.TLS
            "plain" -> SitePortTlsState.PLAIN_HTTP
            "closed" -> SitePortTlsState.CLOSED
            else -> SitePortTlsState.UNKNOWN
        }
        val inventory = SiteWebServerInventory(
            caddy = SiteCaddyObservation(
                binaryPath = caddyBin,
                state = state(value("CADDY_ACTIVE")),
                caddyfilePath = caddyfile,
                caddyfileSha256 = caddyfileSha,
                adapter = value("CADDY_ADAPTER")?.takeIf { it != "NONE" && it.isNotEmpty() },
                servers = adapted,
                managedImportPresent = value("VELUM_IMPORT") == "yes",
                serviceUser = serviceUser,
                tlsFilePairs = tlsPairs,
            ),
            nginx = SiteNginxObservation(binaryPath = nginxBin, state = state(value("NGINX_ACTIVE"))),
            listeners = listeners,
            firewall = firewall,
            requestedPortTls = tls,
        )
        val managed = lines.filter { it.startsWith("MANAGED ") }.map { it.removePrefix("MANAGED ").trim() }.toSet()
        return SiteWebServerProbeResult(inventory, managed)
    }

    /**
     * Read-only proof for certificate/key pairs Caddy already loads: readable by the caddy service
     * user (`runuser -u <user> -- test -r`), not expired, SAN list and certificate digest. Key bytes
     * are never read into the output.
     */
    suspend fun probeCertificates(
        pairs: List<SiteCaddyTlsFilePair>,
        serviceUser: String,
        session: SshSessionHandle,
    ): List<SiteCaddyCertificateCandidate> {
        requireVerified(session)
        require(serviceUserPattern.matches(serviceUser)) { "Caddy service user is invalid" }
        val bounded = pairs.distinct().take(SiteCaddyCertificatePolicy.MAX_CANDIDATES)
        if (bounded.isEmpty()) return emptyList()
        bounded.forEach {
            require(safePath.matches(it.certificatePath) && safePath.matches(it.keyPath)) { "Certificate path is not supported" }
        }
        val raw = buildString {
            append("u=").append(quote(serviceUser)).append("; ")
            append(RUN_AS_SERVICE_USER)
            append("rd() { if ! command -v runuser >/dev/null 2>&1 && [ \"${'$'}u\" != root ]; then echo unknown; ")
            append("elif asu test -r \"${'$'}1\"; then echo yes; else echo no; fi; }; ")
            append("ck() { i=\"${'$'}1\"; c=\"${'$'}2\"; k=\"${'$'}3\"; rc=$(rd \"${'$'}c\"); rk=$(rd \"${'$'}k\"); ")
            append("if command -v openssl >/dev/null 2>&1 && [ -r \"${'$'}c\" ]; then ")
            append("if openssl x509 -in \"${'$'}c\" -noout -checkend 0 >/dev/null 2>&1; then v=yes; else v=no; fi; ")
            append("san=$(openssl x509 -in \"${'$'}c\" -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name' | tail -n 1 | tr -d ' ' | head -c 4000); ")
            append("sh=$(openssl x509 -in \"${'$'}c\" -outform der 2>/dev/null | sha256sum | cut -d' ' -f1); ")
            append("else v=unknown; san=''; sh=NONE; fi; ")
            append("printf 'CAND %s %s %s %s %s %s\\n' \"${'$'}i\" \"${'$'}rc\" \"${'$'}rk\" \"${'$'}v\" \"${'$'}{sh:-NONE}\" \"${'$'}{san:-NONE}\"; }; ")
            bounded.forEachIndexed { index, pair ->
                append("ck ").append(index).append(' ').append(quote(pair.certificatePath)).append(' ')
                    .append(quote(pair.keyPath)).append("; ")
            }
            append("true")
        }
        val lines = execute(session, raw, "site-caddy-certificates-read-only", 64 * 1024, Duration.ofSeconds(30))
        return parseCertificates(lines, bounded, serviceUser)
    }

    internal fun parseCertificates(
        lines: List<String>,
        pairs: List<SiteCaddyTlsFilePair>,
        serviceUser: String,
    ): List<SiteCaddyCertificateCandidate> = lines.filter { it.startsWith("CAND ") }.mapNotNull { line ->
        val parts = line.removePrefix("CAND ").split(' ')
        if (parts.size < 6) return@mapNotNull null
        val pair = parts[0].toIntOrNull()?.let(pairs::getOrNull) ?: return@mapNotNull null
        fun tri(v: String): Boolean? = when (v) { "yes" -> true; "no" -> false; else -> null }
        val sha = parts[4].takeIf { sha256.matches(it) && it != EMPTY_SHA256 }
        val names = parts[5].takeIf { it != "NONE" }.orEmpty().split(',')
            .map { it.trim() }.filter { it.startsWith("DNS:") }.map { it.removePrefix("DNS:").lowercase() }
        SiteCaddyCertificateCandidate(
            pair = pair,
            serviceUser = serviceUser,
            certificateReadableByService = tri(parts[1]),
            keyReadableByService = tri(parts[2]),
            notExpired = tri(parts[3]),
            dnsNames = names,
            certificateSha256 = sha,
        )
    }

    suspend fun apply(plan: SiteCaddyServingPlan, session: SshSessionHandle): SiteCaddyApplyObservation {
        SiteCaddyServingPlanner.validate(plan)
        requireVerified(session)
        val block = Base64.getEncoder().encodeToString(plan.siteBlockUtf8.encodeToByteArray())
        val raw = buildString {
            append("cf=").append(quote(plan.caddyfilePath)).append("; dir=").append(quote(plan.managedDirectory))
            append("; site=").append(quote(plan.siteFilePath)).append("; bk=").append(quote(plan.backupPath))
            append("; imp=").append(quote(plan.importLine)).append("; u=").append(quote(plan.serviceUser)).append("; ")
            append("res() { printf 'RESULT %s\\n' \"${'$'}1\"; }; ")
            append("det() { printf 'DETAIL %s\\n' \"$(printf '%s' \"${'$'}1\" | tail -c 800 | base64 | tr -d '\\n')\"; }; ")
            append(RUN_AS_SERVICE_USER)
            append(RELOAD_FUNCTION)
            append("st=$(systemctl is-active caddy 2>/dev/null | head -n 1); ")
            append("if [ \"${'$'}st\" != active ]; then det \"systemctl is-active caddy: ${'$'}st\"; res CADDY_NOT_ACTIVE; exit 0; fi; ")
            append("if [ \"$(sha256sum < \"${'$'}cf\" | cut -d' ' -f1)\" != ").append(quote(plan.expectedCaddyfileSha256))
            append(" ]; then res CADDYFILE_CHANGED; exit 0; fi; ")
            append("if [ -e \"${'$'}site\" ]; then res SITE_FILE_EXISTS; exit 0; fi; ")
            if (plan.tlsCertificatePath != null && plan.tlsKeyPath != null) {
                append("for f in ").append(quote(plan.tlsCertificatePath!!)).append(' ').append(quote(plan.tlsKeyPath!!)).append("; do ")
                append("if ! asu test -r \"${'$'}f\"; then det \"${'$'}u cannot read ${'$'}f\"; res CERTIFICATE_UNREADABLE; exit 0; fi; done; ")
            }
            append("if [ -e \"${'$'}bk\" ]; then res BACKUP_EXISTS; exit 0; fi; ")
            append("cp -p -- \"${'$'}cf\" \"${'$'}bk\" || { res BACKUP_FAILED; exit 0; }; ")
            append("made=0; if [ ! -d \"${'$'}dir\" ]; then mkdir -p -- \"${'$'}dir\" || { rm -f -- \"${'$'}bk\"; res WRITE_FAILED; exit 0; }; made=1; fi; ")
            append("restore() { cp -p -- \"${'$'}bk\" \"${'$'}cf\" && rm -f -- \"${'$'}site\" \"${'$'}site.velum-tmp\" \"${'$'}cf.velum-tmp\" && ")
            append("{ [ \"${'$'}made\" != 1 ] || rmdir -- \"${'$'}dir\" 2>/dev/null || true; }; }; ")
            append("printf '%s' ").append(quote(block)).append(" | base64 -d > \"${'$'}site.velum-tmp\" && mv -f -- \"${'$'}site.velum-tmp\" \"${'$'}site\" ")
            append("|| { restore; rm -f -- \"${'$'}bk\"; res WRITE_FAILED; exit 0; }; ")
            append("if ! grep -qxF \"${'$'}imp\" \"${'$'}cf\"; then cp -p -- \"${'$'}cf\" \"${'$'}cf.velum-tmp\" && ")
            append("printf '\\n# VELUM//TEGRA managed sites\\n%s\\n' \"${'$'}imp\" >> \"${'$'}cf.velum-tmp\" && mv -f -- \"${'$'}cf.velum-tmp\" \"${'$'}cf\" ")
            append("|| { restore; rm -f -- \"${'$'}bk\"; res WRITE_FAILED; exit 0; }; fi; ")
            append("out=$(asu_home timeout 30 caddy validate --config \"${'$'}cf\" --adapter caddyfile 2>&1); ")
            append("if [ ${'$'}? -ne 0 ]; then restore; rm -f -- \"${'$'}bk\"; det \"${'$'}out\"; res VALIDATE_FAILED; exit 0; fi; ")
            append("out=$(rl 2>&1); ")
            append("if [ ${'$'}? -ne 0 ]; then det \"${'$'}out\"; ")
            append("if restore && rl >/dev/null 2>&1 && [ \"$(systemctl is-active caddy 2>/dev/null | head -n 1)\" = active ]; ")
            append("then rm -f -- \"${'$'}bk\"; res RELOAD_FAILED_ROLLED_BACK; ")
            append("else res RELOAD_FAILED_ROLLBACK_FAILED; fi; exit 0; fi; ")
            append("res APPLIED")
        }
        val lines = execute(session, raw, "site-caddy-apply", 64 * 1024, Duration.ofSeconds(APPLY_TIMEOUT_SECONDS))
        val result = lines.lastOrNull { it.startsWith("RESULT ") }?.removePrefix("RESULT ")?.trim()
            ?: error("Caddy apply returned no result")
        val detail = lines.firstOrNull { it.startsWith("DETAIL ") }?.removePrefix("DETAIL ")?.trim()?.let {
            runCatching { String(Base64.getDecoder().decode(it), Charsets.UTF_8) }.getOrNull()
        }?.let { SiteCommandOutputRedactor.redact(it) }
        return SiteCaddyApplyObservation(SiteCaddyApplyResult.valueOf(result), detail)
    }

    /**
     * Loopback fetch of index.html through Caddy with the exact SNI/Host. Automatic certificates may
     * take a little while to be issued, so the read-only fetch is polled a bounded number of times.
     */
    suspend fun verify(
        plan: SiteCaddyServingPlan,
        session: SshSessionHandle,
        maxAttempts: Int = if (plan.tlsMode == SiteCaddyTlsMode.AUTOMATIC) 12 else 3,
        delaySeconds: Int = 5,
    ): SiteCaddyVerifyObservation {
        SiteCaddyServingPlanner.validate(plan)
        requireVerified(session)
        require(maxAttempts in 1..30 && delaySeconds in 0..15)
        val url = plan.plannedUrl + "index.html"
        val raw = buildString {
            append("printf 'CADDY_ACTIVE %s\\n' \"$(systemctl is-active caddy 2>/dev/null | head -n 1)\"; ")
            append("i=0; sha=''; rc=0; while [ ${'$'}i -lt ").append(maxAttempts).append(" ]; do i=$((i+1)); ")
            append("sha=$(curl -fsS --max-time 8 --resolve ").append(quote("${plan.domain}:${plan.port}:127.0.0.1")).append(' ')
            append(quote(url)).append(" 2>/dev/null | sha256sum | cut -d' ' -f1); ")
            append("rc=$(curl -fsS -o /dev/null --max-time 8 --resolve ").append(quote("${plan.domain}:${plan.port}:127.0.0.1")).append(' ')
            append(quote(url)).append(" >/dev/null 2>&1; echo ${'$'}?); ")
            append("if [ \"${'$'}rc\" = 0 ] && [ \"${'$'}sha\" = ").append(quote(plan.indexSha256)).append(" ]; then break; fi; ")
            append("sleep ").append(delaySeconds).append("; done; ")
            append("printf 'ATTEMPTS %s\\nCURL_EXIT %s\\nBODY_SHA %s\\n' \"${'$'}i\" \"${'$'}rc\" \"${'$'}sha\"; ")
            append("ss -H -ltn 2>/dev/null | awk '{print \"L \" ${'$'}4}' | head -n 1024")
        }
        val timeout = Duration.ofSeconds((maxAttempts * (delaySeconds + 17L)).coerceAtMost(600L) + 10L)
        val lines = execute(session, raw, "site-caddy-verify-read-only", 128 * 1024, timeout)
        fun value(key: String) = lines.firstOrNull { it.startsWith("$key ") }?.removePrefix("$key ")?.trim()
        return SiteCaddyVerifyObservation(
            caddyActive = value("CADDY_ACTIVE") == "active",
            bodySha256 = value("BODY_SHA")?.takeIf { sha256.matches(it) },
            curlExitCode = value("CURL_EXIT")?.toIntOrNull(),
            listeningPorts = lines.filter { it.startsWith("L ") }
                .mapNotNull { it.substringAfterLast(':').toIntOrNull() }.toSet(),
            attempts = value("ATTEMPTS")?.toIntOrNull() ?: 0,
        )
    }

    suspend fun rollback(plan: SiteCaddyServingPlan, session: SshSessionHandle): SiteCaddyRollbackResult {
        SiteCaddyServingPlanner.validate(plan)
        requireVerified(session)
        val raw = buildString {
            append("cf=").append(quote(plan.caddyfilePath)).append("; dir=").append(quote(plan.managedDirectory))
            append("; site=").append(quote(plan.siteFilePath)).append("; bk=").append(quote(plan.backupPath))
            append("; u=").append(quote(plan.serviceUser)).append("; ")
            append(RUN_AS_SERVICE_USER)
            append(RELOAD_FUNCTION)
            append("if [ ! -f \"${'$'}bk\" ]; then echo 'RESULT NO_BACKUP'; exit 0; fi; ")
            append("if cp -p -- \"${'$'}bk\" \"${'$'}cf\" && rm -f -- \"${'$'}site\" && ")
            append("asu_home timeout 30 caddy validate --config \"${'$'}cf\" --adapter caddyfile >/dev/null 2>&1 && rl >/dev/null 2>&1; ")
            append("then rm -f -- \"${'$'}bk\"; rmdir -- \"${'$'}dir\" 2>/dev/null; echo 'RESULT ROLLED_BACK'; ")
            append("else echo 'RESULT ROLLBACK_FAILED'; fi")
        }
        val lines = execute(session, raw, "site-caddy-rollback", 16 * 1024, Duration.ofSeconds(APPLY_TIMEOUT_SECONDS))
        val result = lines.lastOrNull { it.startsWith("RESULT ") }?.removePrefix("RESULT ")?.trim()
            ?: error("Caddy rollback returned no result")
        return SiteCaddyRollbackResult.valueOf(result)
    }

    private suspend fun execute(
        session: SshSessionHandle,
        raw: String,
        label: String,
        stdoutLimit: Int,
        timeout: Duration,
    ): List<String> {
        val result = session.execute(
            RemoteCommand.create(raw, label),
            SshTransportConfig(
                commandExecutionTimeout = timeout,
                stdoutCaptureLimitBytes = stdoutLimit,
                stderrCaptureLimitBytes = 64 * 1024,
            ),
        )
        val completion = result.completion
        val failureReason = when {
            result.dispatchState != CommandDispatchState.DISPATCHED -> "команда не была отправлена"
            completion is CommandCompletion.ConfirmedFailure -> completion.reason
            completion is CommandCompletion.Unknown -> completion.reason
            result.stdout.truncated || result.stderr.truncated -> "вывод команды превысил лимит"
            else -> null
        }
        if (failureReason != null) {
            throw SiteCaddyCommandFailedException(
                label = label,
                stage = stageName(label),
                exitCode = (completion as? CommandCompletion.ConfirmedFailure)?.exitCode,
                timedOut = completion is CommandCompletion.Unknown && "timed out" in completion.reason,
                reason = SiteCommandOutputRedactor.redact(failureReason, 200),
                stdoutTail = SiteCommandOutputRedactor.redact(decodeLenient(result.stdout.copyBytes())),
                stderrTail = SiteCommandOutputRedactor.redact(decodeLenient(result.stderr.copyBytes())),
            )
        }
        return decodeUtf8(result.stdout.copyBytes()).lineSequence().map { it.trimEnd('\r') }.filter { it.isNotEmpty() }.toList()
    }

    private fun stageName(label: String): String = when (label) {
        "site-web-server-probe-read-only" -> "проверка веб-сервера (только чтение)"
        "site-caddy-certificates-read-only" -> "проверка сертификатов (только чтение)"
        "site-caddy-apply" -> "применение конфига Caddy"
        "site-caddy-verify-read-only" -> "проверка сайта на сервере"
        "site-caddy-rollback" -> "откат конфига Caddy"
        else -> label
    }

    private fun decodeLenient(bytes: ByteArray): String = String(bytes, Charsets.UTF_8)

    private fun requireVerified(session: SshSessionHandle) {
        require(session.isOpen) { "SSH session is closed" }
        require(session is VerifiedHostKeySshSessionHandle) { "Caddy operations require verified host-key evidence" }
    }

    private fun quote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' }) { "Unsafe shell token" }
        return "'$value'"
    }

    private fun decodeUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()

    private companion object {
        val sha256 = Regex("^[0-9a-f]{64}$")
        val processName = Regex("\"([^\"]+)\"")
        val serviceUserPattern = Regex("^[a-z_][a-z0-9_-]{0,31}$")
        val safePath = Regex("^/(?!.*\\.\\.)[A-Za-z0-9._/@+-]{1,1024}$")

        /** sha256 of empty input: openssl produced nothing. */
        const val EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        /**
         * Upper bound for apply/rollback: validate (30 s) + reload (25 s) + rollback reload (25 s)
         * plus file operations, so the remote script always reports its RESULT before SSH gives up.
         */
        const val APPLY_TIMEOUT_SECONDS = 120L

        /**
         * `asu` runs a command as the caddy service user; `asu_home` also sets that user's HOME so
         * `caddy validate` uses the same storage as the service. Root needs no switch.
         */
        const val RUN_AS_SERVICE_USER =
            "asu() { if [ \"${'$'}u\" = root ]; then \"${'$'}@\"; else runuser -u \"${'$'}u\" -- \"${'$'}@\"; fi; }; " +
                "asu_home() { if [ \"${'$'}u\" = root ]; then \"${'$'}@\"; else h=$(getent passwd \"${'$'}u\" | cut -d: -f6); " +
                "runuser -u \"${'$'}u\" -- env HOME=\"${'$'}{h:-/var/lib/caddy}\" XDG_DATA_HOME= XDG_CONFIG_HOME= \"${'$'}@\"; fi; }; "

        /**
         * Reload through Caddy's admin API with a hard time limit, the same thing the packaged
         * ExecReload does. `systemctl reload` is avoided: with Type=notify it can hang in
         * `reloading` for ~90 s after a failed config load (caddyserver/caddy#7385).
         */
        const val RELOAD_FUNCTION =
            "rl() { timeout 25 caddy reload --config \"${'$'}cf\" --adapter caddyfile; }; "
    }
}
