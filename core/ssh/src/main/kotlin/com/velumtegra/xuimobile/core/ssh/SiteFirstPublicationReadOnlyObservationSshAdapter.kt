package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.site.SiteEndpointObservation
import com.velumtegra.xuimobile.core.site.SiteExistingSitePolicy
import com.velumtegra.xuimobile.core.site.SiteExistingTargetFile
import com.velumtegra.xuimobile.core.site.SiteExistingTargetObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPolicy
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * Phase 11.100 finite read-only service-binding probe used before first publication.
 *
 * Inspect the deterministic future config path, exact TCP port, and required Nginx
 * executable and directory through one already-open pinned-key SSH session.
 * Consequence: return CONFIGURED / UNCONFIGURED only when the live evidence is unambiguous.
 * Counteraction: missing `ss`, truncated/unknown output, command failure, or any malformed evidence
 * fails closed instead of treating the endpoint as available.
 *
 * This adapter has no write verb, accepts no arbitrary command input, and grants no nginx/DNS/
 * firewall/package/certificate mutation authority.
 */
class SiteFirstPublicationReadOnlyObservationSshAdapter {
    fun exactFutureConfigPath(
        remoteHostIdentity: String,
        targetRoot: String,
        domain: String,
        port: Int,
    ): String = SiteWebServingPublicationPlanBoundary.exactNginxConfigPath(
        remoteHostIdentity = remoteHostIdentity,
        targetRoot = targetRoot,
        domain = domain,
        port = port,
    )

    suspend fun observeConfigured(
        configPath: String,
        port: Int,
        session: SshSessionHandle,
    ): Boolean {
        val canonicalConfigPath = SiteRemoteDeployPolicy.prepareTargetRoot(configPath)
        require(canonicalConfigPath.startsWith("/etc/nginx/conf.d/") && canonicalConfigPath.endsWith(".conf")) {
            "First-publication probe config path is outside the deterministic nginx config namespace"
        }
        require(port in 1..65535) { "First-publication probe port is invalid" }
        require(session.isOpen) { "First-publication probe SSH session is closed" }
        require(session is VerifiedHostKeySshSessionHandle) {
            "First-publication probe requires live verified host-key evidence"
        }

        val raw = buildString {
            val config = quote(canonicalConfigPath)
            append("if [ -e $config ] || [ -L $config ]; then printf 'CONFIGURED\\n'; ")
            append("elif ! listeners=\$(ss -H -ltn ").append(quote("sport = :$port"))
            append(" 2>/dev/null); then printf 'UNKNOWN\\n'; ")
            append("elif [ -n \"\$listeners\" ]; then printf 'CONFIGURED\\n'; ")
            append("elif ! nginx_path=\$(command -v nginx 2>/dev/null); then printf 'NGINX_MISSING\\n'; ")
            append("elif [ -L /etc/nginx/conf.d ] || [ ! -d /etc/nginx/conf.d ]; ")
            append("then printf 'NGINX_CONF_D_INVALID\\n'; ")
            append("else case \"\$nginx_path\" in /*) printf 'UNCONFIGURED\\n';; ")
            append("*) printf 'NGINX_MISSING\\n';; esac; fi")
        }
        val result = session.execute(
            RemoteCommand.create(raw, "site-first-publication-service-binding-read-only"),
            READ_ONLY_CONFIG,
        )
        require(result.dispatchState == CommandDispatchState.DISPATCHED) {
            "First-publication read-only service-binding probe was not dispatched"
        }
        require(!result.stdout.truncated && !result.stderr.truncated) {
            "First-publication read-only service-binding probe output was truncated"
        }
        require(result.completion == CommandCompletion.ConfirmedSuccess) {
            "First-publication read-only service-binding probe failed"
        }
        return when (decodeUtf8(result.stdout.copyBytes()).trim()) {
            "CONFIGURED" -> true
            "UNCONFIGURED" -> false
            "UNKNOWN" -> error("Не удалось проверить TCP-порт $port на VPS через ss.")
            "NGINX_MISSING" -> error("На VPS не найден Nginx. Для публикации через приложение нужен Nginx.")
            "NGINX_CONF_D_INVALID" -> error("Для публикации нужна обычная папка /etc/nginx/conf.d на VPS.")
            else -> error("Malformed first-publication service-binding observation")
        }
    }

    /**
     * Read-only endpoint evidence: whether the exact deterministic VELUM nginx config exists, whether
     * the requested port is listening, and the full set of listening TCP ports (used only to suggest
     * a free alternative port to the operator).
     */
    suspend fun observeEndpoint(
        configPath: String,
        port: Int,
        session: SshSessionHandle,
    ): SiteEndpointObservation {
        val canonicalConfigPath = requireConfigPath(configPath)
        require(port in 1..65535) { "Endpoint probe port is invalid" }
        requireVerified(session)
        val raw = buildString {
            append("if [ -e ").append(quote(canonicalConfigPath)).append(" ]; then printf 'CONFIG PRESENT\\n'; else printf 'CONFIG ABSENT\\n'; fi; ")
            append("if ! command -v ss >/dev/null 2>&1; then printf 'SS MISSING\\n'; else printf 'SS OK\\n'; ")
            append("ss -H -ltn | awk '{print ${'$'}4}' | sed -E 's/.*:([0-9]+)${'$'}/\\1/' | grep -E '^[0-9]+${'$'}' | sort -un | head -n 1024 | sed 's/^/PORT /'; fi")
        }
        val lines = executeLines(session, raw, "site-endpoint-read-only", 64 * 1024)
        val config = when (lines.firstOrNull()) {
            "CONFIG PRESENT" -> true
            "CONFIG ABSENT" -> false
            else -> error("Malformed endpoint observation")
        }
        when (lines.getOrNull(1)) {
            "SS OK" -> Unit
            "SS MISSING" -> error("Не удалось проверить занятые порты: на сервере нет утилиты ss (пакет iproute2)")
            else -> error("Malformed endpoint observation")
        }
        val ports = lines.drop(2).map { line ->
            require(line.startsWith("PORT ")) { "Malformed endpoint port observation" }
            line.removePrefix("PORT ").toIntOrNull()?.takeIf { it in 1..65535 } ?: error("Malformed endpoint port observation")
        }.toSet()
        return SiteEndpointObservation(
            configPresent = config,
            portInUse = port in ports,
            listeningPorts = ports,
        )
    }

    /**
     * Read-only inventory of the requested target folder. File paths, sizes and SHA-256 digests
     * are collected only while the folder is small enough to be replaced by the bounded rename-only
     * transaction; otherwise only the count is returned.
     */
    suspend fun observeExistingTarget(
        targetRoot: String,
        session: SshSessionHandle,
    ): SiteExistingTargetObservation {
        val root = SiteRemoteDeployPolicy.prepareTargetRoot(targetRoot)
        requireVerified(session)
        val q = quote(root)
        val limit = SiteExistingSitePolicy.MAX_REPLACEABLE_FILES
        val raw = buildString {
            append("if [ ! -e ").append(q).append(" ] && [ ! -L ").append(q).append(" ]; then printf 'ABSENT\\n'; ")
            append("elif [ -L ").append(q).append(" ] || [ ! -d ").append(q).append(" ]; then printf 'NOT_DIRECTORY\\n'; ")
            append("else printf 'DIRECTORY\\n'; ")
            append("printf 'SPECIAL %s\\n' \"${'$'}(find ").append(q).append(" -mindepth 1 ! -type f ! -type d | head -n 1 | wc -l)\"; ")
            append("printf 'EMPTYDIR %s\\n' \"${'$'}(find ").append(q).append(" -mindepth 1 -type d -empty | head -n 1 | wc -l)\"; ")
            append("c=${'$'}(find ").append(q).append(" -type f | wc -l); printf 'COUNT %s\\n' \"${'$'}c\"; ")
            append("if [ \"${'$'}c\" -le ").append(limit).append(" ]; then ")
            append("find ").append(q).append(" -type f -printf 'SIZE\\t%s\\t%P\\n'; ")
            append("cd ").append(q).append(" && find . -type f -exec sha256sum -- {} + | sed 's/^/HASH /'; fi; fi")
        }
        val lines = executeLines(session, raw, "site-existing-target-read-only", 256 * 1024)
        return when (lines.firstOrNull()) {
            "ABSENT" -> SiteExistingTargetObservation.ABSENT
            "NOT_DIRECTORY" -> SiteExistingTargetObservation(
                present = true,
                isDirectory = false,
                totalFileCount = 0,
                hasSymlinksOrSpecialEntries = true,
                hasEmptyDirectories = false,
                files = emptyList(),
            )
            "DIRECTORY" -> parseDirectory(lines.drop(1), limit)
            else -> error("Malformed existing target observation")
        }
    }

    private fun parseDirectory(lines: List<String>, limit: Int): SiteExistingTargetObservation {
        fun number(prefix: String): Int = lines.firstOrNull { it.startsWith("$prefix ") }
            ?.removePrefix("$prefix ")?.trim()?.toIntOrNull()
            ?: error("Malformed existing target observation: $prefix")
        val special = number("SPECIAL") > 0
        val emptyDir = number("EMPTYDIR") > 0
        val count = number("COUNT")
        require(count >= 0) { "Malformed existing target file count" }
        val sizes = LinkedHashMap<String, Long>()
        val hashes = HashMap<String, String>()
        var unsupported = false
        lines.forEach { line ->
            when {
                line.startsWith("SIZE\t") -> {
                    val parts = line.split('\t', limit = 3)
                    val size = parts.getOrNull(1)?.toLongOrNull()
                    val path = parts.getOrNull(2)
                    if (size == null || path.isNullOrEmpty()) unsupported = true else sizes[path] = size
                }
                line.startsWith("HASH ") -> {
                    // sha256sum prefixes a backslash when the file name needs escaping.
                    val body = line.removePrefix("HASH ")
                    val hash = body.substringBefore(' ')
                    val path = body.substringAfter("  ", "").removePrefix("./")
                    if (hash.startsWith("\\") || path.isEmpty()) unsupported = true else hashes[path] = hash
                }
            }
        }
        val files = if (count <= limit) {
            if (sizes.size != count || hashes.keys != sizes.keys) unsupported = true
            sizes.mapNotNull { (path, size) ->
                hashes[path]?.let { SiteExistingTargetFile(relativePath = path, byteSize = size, sha256 = it) }
            }.sortedBy { it.relativePath }
        } else {
            emptyList()
        }
        return SiteExistingTargetObservation(
            present = true,
            isDirectory = true,
            totalFileCount = count,
            hasSymlinksOrSpecialEntries = special || unsupported,
            hasEmptyDirectories = emptyDir,
            files = files,
        )
    }

    private suspend fun executeLines(
        session: SshSessionHandle,
        raw: String,
        label: String,
        stdoutLimit: Int,
    ): List<String> {
        val result = session.execute(
            RemoteCommand.create(raw, label),
            SshTransportConfig(stdoutCaptureLimitBytes = stdoutLimit, stderrCaptureLimitBytes = 16 * 1024),
        )
        require(result.dispatchState == CommandDispatchState.DISPATCHED) { "Read-only probe was not dispatched" }
        require(!result.stdout.truncated && !result.stderr.truncated) { "Read-only probe output was truncated" }
        require(result.completion == CommandCompletion.ConfirmedSuccess) { "Read-only probe failed" }
        return decodeUtf8(result.stdout.copyBytes()).lineSequence().map { it.trimEnd('\r') }.filter { it.isNotEmpty() }.toList()
    }

    private fun requireConfigPath(configPath: String): String {
        val canonical = SiteRemoteDeployPolicy.prepareTargetRoot(configPath)
        require(canonical.startsWith("/etc/nginx/conf.d/") && canonical.endsWith(".conf")) {
            "Probe config path is outside the deterministic nginx config namespace"
        }
        return canonical
    }

    private fun requireVerified(session: SshSessionHandle) {
        require(session.isOpen) { "Read-only probe SSH session is closed" }
        require(session is VerifiedHostKeySshSessionHandle) { "Read-only probe requires live verified host-key evidence" }
    }

    private fun quote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' }) {
            "Unsafe first-publication shell token"
        }
        return "'$value'"
    }

    private fun decodeUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()

    companion object {
        private val READ_ONLY_CONFIG = SshTransportConfig(
            stdoutCaptureLimitBytes = 4 * 1024,
            stderrCaptureLimitBytes = 8 * 1024,
        )
    }
}
