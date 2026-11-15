package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.*
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeoutOrNull

/** Reads only a bounded known file set in the already-open operation session. Never owns a connection. */
class RecoveryFileInventorySshReader(private val now: () -> Instant = Instant::now) {
    suspend fun read(scope: ManagementScope, installation: XuiInstallation, session: SshSessionHandle,
        source: UpdateRecoverySourceSnapshot): RecoveryFileInventory {
        val i = installation.identity
        fun unavailable(issue: RecoveryFileIssue) = RecoveryFileInventory.unavailable(scope, issue, now())
        if (scope.serverId != installation.serverId || scope.installationId != installation.id || source.scope != scope ||
            i.serviceUnit != "x-ui.service" || i.binaryPath != "/usr/local/x-ui/x-ui" || i.rootPath != "/usr/local/x-ui" ||
            i.databasePath != "/etc/x-ui/x-ui.db" || source.database != UpdateRecoveryDatabaseState.PRIVATE_REGULAR ||
            source.schema != DeepDiagnosticDatabaseSchemaStatus.SUPPORTED || !session.isOpen ||
            session.binding.owner != SessionOwner.Operation(scope.operationId) || session.binding.serverAccessId != scope.serverAccessId)
            return unavailable(RecoveryFileIssue.TARGET_UNVERIFIED)
        val binding = session.binding
        suspend fun query(raw: String, label: String, limit: Int): String {
            currentCoroutineContext().ensureActive()
            if (!session.isOpen || session.binding != binding) throw Rejected(RecoveryFileIssue.TARGET_UNVERIFIED)
            val result = session.execute(RemoteCommand.create(raw, label), SshTransportConfig(
                channelOpenTimeout = Duration.ofSeconds(5), commandExecutionTimeout = Duration.ofSeconds(12),
                stdoutCaptureLimitBytes = limit, stderrCaptureLimitBytes = 512))
            currentCoroutineContext().ensureActive()
            if (!session.isOpen || session.binding != binding) throw Rejected(RecoveryFileIssue.TARGET_UNVERIFIED)
            if (result.dispatchState != CommandDispatchState.DISPATCHED || result.completion != CommandCompletion.ConfirmedSuccess ||
                result.stdout.truncated || result.stderr.truncated || result.stdout.sizeBytes > limit || result.stderr.sizeBytes != 0)
                throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
            val bytes = result.stdout.copyBytes()
            return try {
                StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            } catch (_: Exception) { throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
            } finally { Arrays.fill(bytes, 0) }
        }
        return try {
            withTimeoutOrNull(35_000) {
                if (query(RecoveryFileInventoryCommands.prepare(), "recovery-files-tools", 32) != "READY\n")
                    throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
                val runtime = query(RecoveryFileInventoryCommands.runtime(), "recovery-files-runtime", 12_288)
                val service = query(RecoveryFileInventoryCommands.service(), "recovery-files-service", 4096)
                val issues = linkedSetOf<RecoveryFileIssue>()
                val candidates = linkedMapOf<String, Candidate>()
                fun add(path: String, group: RecoveryFileGroup, secret: Boolean = false) {
                    if (!RecoveryFileInventoryCommands.safePath(path)) { issues += RecoveryFileIssue.UNSAFE_PATH; return }
                    val old = candidates[path]
                    if (old == null) candidates[path] = Candidate(path, linkedSetOf(group), secret)
                    else { old.groups += group; old.secret = old.secret || secret }
                }
                val runtimeSet = parseRuntime(runtime, issues)
                runtimeSet.forEach { add(it, RecoveryFileGroup.RUNTIME, it.endsWith("/config.json")) }
                if ("/usr/local/x-ui/x-ui" !in runtimeSet || runtimeSet.none { it in setOf("/usr/local/x-ui/bin/xray-linux-amd64", "/usr/local/x-ui/bin/xray-linux-arm64") })
                    issues += RecoveryFileIssue.FILE_MISSING
                parseService(service, issues).forEach { add(it, RecoveryFileGroup.SERVICE) }
                val activeConfig = "/usr/local/x-ui/bin/config.json" in runtimeSet
                val references = query(RecoveryFileInventoryCommands.references(activeConfig), "recovery-files-references", 24_576)
                parseReferences(references, issues) { path, group, secret -> add(path, group, secret) }
                if (candidates.size > RecoveryFileInventory.MAX_FILES) issues += RecoveryFileIssue.LIMIT_EXCEEDED
                if (issues.any { it in setOf(RecoveryFileIssue.UNSAFE_PATH, RecoveryFileIssue.LIMIT_EXCEEDED, RecoveryFileIssue.REFERENCES_UNAVAILABLE) })
                    return@withTimeoutOrNull unavailable(issues.first { it in setOf(RecoveryFileIssue.UNSAFE_PATH, RecoveryFileIssue.LIMIT_EXCEEDED, RecoveryFileIssue.REFERENCES_UNAVAILABLE) })
                val files = candidates.values.sortedBy { it.path }
                val metadata = query(RecoveryFileInventoryCommands.metadata(files.map { it.path }), "recovery-files-metadata", 16_384)
                val observed = parseMetadata(metadata, files, issues)
                // Re-read reference/configuration sources and the complete known metadata set; no partial green report.
                val runtimeAfter = query(RecoveryFileInventoryCommands.runtime(), "recovery-files-runtime", 12_288)
                if (runtime.lineSequence().sorted().toList() != runtimeAfter.lineSequence().sorted().toList()) issues += RecoveryFileIssue.FILES_CHANGED
                if (query(RecoveryFileInventoryCommands.service(), "recovery-files-service", 4096) != service) issues += RecoveryFileIssue.FILES_CHANGED
                if (query(RecoveryFileInventoryCommands.references(activeConfig), "recovery-files-references", 24_576) != references)
                    issues += RecoveryFileIssue.REFERENCES_CHANGED
                if (query(RecoveryFileInventoryCommands.metadata(files.map { it.path }), "recovery-files-metadata", 16_384) != metadata)
                    issues += RecoveryFileIssue.FILES_CHANGED
                val total = observed.values.sum()
                if (total > RecoveryFileInventory.MAX_TOTAL_BYTES) return@withTimeoutOrNull unavailable(RecoveryFileIssue.LIMIT_EXCEEDED)
                val groups = RecoveryFileGroup.values().associateWith { group ->
                    val matching = files.withIndex().filter { group in it.value.groups && it.index in observed }
                    RecoveryFileGroupObservation(matching.size, matching.sumOf { observed.getValue(it.index) })
                }
                val digest = if (issues.isEmpty()) {
                    val parts = listOf(scope.operationId.value, scope.serverId.value, scope.installationId.value, scope.serverAccessId.value) +
                        files.map { it.path + "|" + it.groups.map { g -> g.name }.sorted().joinToString(",") + "|" + it.secret } +
                        listOf(metadata, service, references)
                    val canonical = parts.joinToString("") { "${it.length}:$it" }
                    MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(StandardCharsets.UTF_8))
                        .joinToString("") { "%02x".format(it.toInt() and 255) }
                } else null
                val sourceDigest = if (issues.isEmpty()) {
                    val rows = metadata.dropLast(1).split('\n')
                    val canonical = files.mapIndexed { index, file ->
                        file.path + "|" + file.groups.map { it.name }.sorted().joinToString(",") + "|" +
                            (if (file.secret) "1" else "0") + "|" + rows[index].split('|').drop(2).joinToString("|") + "\n"
                    }.joinToString("")
                    MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(StandardCharsets.UTF_8))
                        .joinToString("") { "%02x".format(it.toInt() and 255) }
                } else null
                RecoveryFileInventory(scope, groups, observed.size, total, issues, digest, now(), sourceDigest)
            } ?: unavailable(RecoveryFileIssue.READ_UNAVAILABLE)
        } catch (failure: Rejected) { unavailable(failure.issue) }
    }

    private data class Candidate(val path: String, val groups: MutableSet<RecoveryFileGroup>, var secret: Boolean)
    private class Rejected(val issue: RecoveryFileIssue) : RuntimeException()

    private fun lines(raw: String): List<String> {
        if (!raw.endsWith('\n') || '\r' in raw || '\u0000' in raw) throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
        return raw.dropLast(1).split('\n')
    }
    private fun parseRuntime(raw: String, issues: MutableSet<RecoveryFileIssue>): Set<String> {
        val rows = lines(raw)
        if (rows.size > 192) throw Rejected(RecoveryFileIssue.LIMIT_EXCEEDED)
        val seen = linkedSetOf<String>(); val files = linkedSetOf<String>()
        for (row in rows) {
            val fields = row.split('|')
            if (fields.size != 2 || !seen.add(fields[1]) || !fields[1].startsWith("/usr/local/x-ui/") ||
                !RecoveryFileInventoryCommands.safePath(fields[1])) throw Rejected(RecoveryFileIssue.UNSAFE_PATH)
            when (fields[0]) {
                "f" -> files += fields[1]
                "d" -> if (fields[1].removePrefix("/usr/local/x-ui/").split('/').size >= 4) issues += RecoveryFileIssue.LIMIT_EXCEEDED
                else -> issues += RecoveryFileIssue.UNSAFE_FILE
            }
        }
        return files
    }
    private fun parseService(raw: String, issues: MutableSet<RecoveryFileIssue>): List<String> {
        val fields = linkedMapOf<String, String>()
        for (line in lines(raw)) {
            val parts = line.split('=', limit = 2)
            if (parts.size != 2 || fields.put(parts[0], parts[1]) != null) throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
        }
        if (fields.keys != setOf("FRAGMENT", "DROPINS", "ENVIRONMENT", "ENVFILES", "DIRECTORY", "NODEKEY")) throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
        when (fields.getValue("ENVIRONMENT")) {
            "NONE", "STOCK_VMESS_FALSE" -> Unit
            "PRESENT" -> issues += RecoveryFileIssue.SERVICE_ENVIRONMENT
            else -> throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
        }
        when (fields.getValue("ENVFILES")) {
            "NONE", "STOCK_OPTIONAL_DEFAULT_ABSENT" -> Unit
            "PRESENT" -> issues += RecoveryFileIssue.SERVICE_ENVIRONMENT
            else -> throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
        }
        when (fields.getValue("NODEKEY")) {
            "ABSENT" -> Unit
            "PRESENT" -> issues += RecoveryFileIssue.UNKNOWN_REFERENCE
            "UNSAFE" -> issues += RecoveryFileIssue.UNSAFE_PATH
            else -> throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
        }
        if (fields["DIRECTORY"]?.removeSuffix("/") != "/usr/local/x-ui") issues += RecoveryFileIssue.SERVICE_ENVIRONMENT
        val paths = listOf(fields.getValue("FRAGMENT")) + fields.getValue("DROPINS").split(' ').filter { it.isNotEmpty() }
        if (paths.size > 9) throw Rejected(RecoveryFileIssue.LIMIT_EXCEEDED)
        if (paths.any { !it.startsWith("/etc/systemd/system/") && !it.startsWith("/usr/lib/systemd/system/") && !it.startsWith("/lib/systemd/system/") })
            throw Rejected(RecoveryFileIssue.UNSAFE_PATH)
        return paths
    }
    private fun parseReferences(raw: String, issues: MutableSet<RecoveryFileIssue>, add: (String, RecoveryFileGroup, Boolean) -> Unit) {
        val rows = lines(raw)
        val header = rows.first().split('|')
        if (header.size != 5 || header[0] != "DOCS" || header.drop(1).any { !Regex("0|[1-9][0-9]{0,8}").matches(it) })
            throw Rejected(RecoveryFileIssue.REFERENCES_UNAVAILABLE)
        val n = header.drop(1).map { it.toLong() }
        if (n[0] !in 1..514 || n[1] > 2_097_152 || n[2] != 0L || n[3] != 0L || rows.size > 33)
            throw Rejected(RecoveryFileIssue.REFERENCES_UNAVAILABLE)
        val seen = linkedSetOf<String>()
        for (row in rows.drop(1)) {
            val fields = row.split('|')
            if (fields.size != 2 || !seen.add(row)) throw Rejected(RecoveryFileIssue.REFERENCES_UNAVAILABLE)
            val path = decodeHex(fields[1]) ?: throw Rejected(RecoveryFileIssue.UNSAFE_PATH)
            when (fields[0]) {
                "PANEL_CERT", "PANEL_KEY" -> add(path, RecoveryFileGroup.PANEL_TLS, fields[0] == "PANEL_KEY")
                "XRAY_CERT", "XRAY_KEY" -> add(path, RecoveryFileGroup.XRAY_TLS, fields[0] == "XRAY_KEY")
                "XRAY_DATA" -> {
                    val parts = path.split(':')
                    if (parts.size != 3 || parts[0] !in setOf("ext", "ext-ip") || !Regex("[A-Za-z0-9_-][A-Za-z0-9_.-]{0,95}\\.dat").matches(parts[1]) || parts[2].isBlank())
                        throw Rejected(RecoveryFileIssue.UNSAFE_PATH)
                    add("/usr/local/x-ui/bin/" + parts[1], RecoveryFileGroup.XRAY_DATA, false)
                }
                "UNKNOWN" -> issues += RecoveryFileIssue.UNKNOWN_REFERENCE
                else -> throw Rejected(RecoveryFileIssue.REFERENCES_UNAVAILABLE)
            }
        }
    }
    private fun decodeHex(raw: String): String? {
        if (raw.length !in 2..2048 || raw.length % 2 != 0 || !Regex("[0-9A-F]+").matches(raw)) return null
        val bytes = ByteArray(raw.length / 2) { raw.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        return try { StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: Exception) { null } finally { Arrays.fill(bytes, 0) }
    }
    private fun parseMetadata(raw: String, files: List<Candidate>, issues: MutableSet<RecoveryFileIssue>): Map<Int, Long> {
        val rows = lines(raw)
        if (rows.size != files.size) throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
        val values = linkedMapOf<Int, Long>()
        for ((index, row) in rows.withIndex()) {
            val fields = row.split('|')
            if (fields.size < 2 || fields[1] != index.toString()) throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
            if (fields.size == 2) {
                issues += when (fields[0]) { "M" -> RecoveryFileIssue.FILE_MISSING; "U" -> RecoveryFileIssue.UNSAFE_FILE
                    else -> throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE) }
                continue
            }
            if (fields.size != 10 || fields[0] != "F" || fields.drop(2).any { !Regex("0|[1-9][0-9]{0,18}").matches(it) } ||
                fields.drop(2).any { it.toLongOrNull() == null } || !Regex("[0-7]{3,4}").matches(fields[5])) throw Rejected(RecoveryFileIssue.READ_UNAVAILABLE)
            val mode = fields[5].toInt(8)
            if (fields[4] != "0" || fields[9] != "1" || (mode and 3584) != 0 || (mode and 18) != 0 || (mode and 256) == 0 ||
                (files[index].secret && mode !in setOf(256, 384))) { issues += RecoveryFileIssue.UNSAFE_FILE; continue }
            val bytes = fields[6].toLong()
            if (files[index].path in setOf("/usr/local/x-ui/x-ui", "/usr/local/x-ui/bin/xray-linux-amd64", "/usr/local/x-ui/bin/xray-linux-arm64") &&
                (bytes == 0L || (mode and 64) == 0)) { issues += RecoveryFileIssue.UNSAFE_FILE; continue }
            if (bytes > RecoveryFileInventory.MAX_FILE_BYTES) { issues += RecoveryFileIssue.LIMIT_EXCEEDED; continue }
            values[index] = bytes
        }
        return values
    }
}

/** No arbitrary shell/SQL surface. Paths must pass the closed ASCII absolute-path policy. */
internal object RecoveryFileInventoryCommands {
    fun safePath(path: String) = path.length in 2..1024 && Regex("/[A-Za-z0-9_./@:+-]+").matches(path) &&
        !path.contains("//") && path.split('/').none { it == "." || it == ".." } &&
        listOf("/root/", "/etc/", "/usr/local/x-ui/", "/usr/lib/systemd/system/", "/lib/systemd/system/", "/var/lib/").any { path.startsWith(it) }
    private val guard = """
        guard() {
            p=${'$'}1
            while [ "${'$'}p" != '/' ]; do
                [ ! -L "${'$'}p" ] || return 1
                p=${'$'}{p%/*}; [ -n "${'$'}p" ] || p=/
                [ -d "${'$'}p" ] && [ ! -L "${'$'}p" ] && [ "${'$'}(stat -c '%u' -- "${'$'}p")" = 0 ] || return 1
                m=${'$'}(stat -c '%a' -- "${'$'}p") || return 1
                [ ${'$'}((0${'$'}m & 022)) -eq 0 ] || return 1
            done
        }
    """.trimIndent()
    fun prepare() = "set -eu; [ \"\$(id -u)\" = 0 ] || exit 81; " +
        "for t in sqlite3 stat find timeout prlimit systemctl; do command -v \"\$t\" >/dev/null 2>&1 || exit 81; done; " + guard +
        "\nguard '/etc/x-ui/x-ui.db' && [ -f '/etc/x-ui/x-ui.db' ] && [ ! -L '/etc/x-ui/x-ui.db' ] || exit 82; " +
        "case \"\$(stat -c '%u:%a:%h' -- '/etc/x-ui/x-ui.db')\" in '0:600:1'|'0:400:1') ;; *) exit 82 ;; esac; " +
        "[ \"\$(stat -c '%s' -- '/etc/x-ui/x-ui.db')\" -le 134217728 ] || exit 82; printf 'READY\\n'"
    fun runtime() = "set -eu; $guard\nguard '/usr/local/x-ui/x-ui' || exit 82; " +
        "timeout --kill-after=1s 8s find -P '/usr/local/x-ui' -xdev -mindepth 1 -maxdepth 4 -printf '%y|%p\\n'"
    fun service() = "set -eu\n$guard\n" + """
        fragment=${'$'}(systemctl show --property=FragmentPath --value -- x-ui.service)
        dropins=${'$'}(systemctl show --property=DropInPaths --value -- x-ui.service)
        directory=${'$'}(systemctl show --property=WorkingDirectory --value -- x-ui.service)
        environment=${'$'}(systemctl show --property=Environment --value -- x-ui.service)
        envfiles=${'$'}(systemctl show --property=EnvironmentFiles --value -- x-ui.service)
        printf 'FRAGMENT=%s\nDROPINS=%s\n' "${'$'}fragment" "${'$'}dropins"
        case "${'$'}environment" in
            '') printf 'ENVIRONMENT=NONE\n' ;;
            'XRAY_VMESS_AEAD_FORCED=false') printf 'ENVIRONMENT=STOCK_VMESS_FALSE\n' ;;
            *) printf 'ENVIRONMENT=PRESENT\n' ;;
        esac
        if [ -z "${'$'}envfiles" ]; then printf 'ENVFILES=NONE\n'
        elif [ "${'$'}envfiles" = '/etc/default/x-ui (ignore_errors=yes)' ] &&
            [ ! -e /etc/default/x-ui ] && [ ! -L /etc/default/x-ui ] && guard /etc/default/x-ui; then
            printf 'ENVFILES=STOCK_OPTIONAL_DEFAULT_ABSENT\n'
        else printf 'ENVFILES=PRESENT\n'; fi
        printf 'DIRECTORY=%s\n' "${'$'}directory"
        if ! guard /etc/x-ui/node_token_key.json; then printf 'NODEKEY=UNSAFE\n'
        elif [ -e /etc/x-ui/node_token_key.json ] || [ -L /etc/x-ui/node_token_key.json ]; then printf 'NODEKEY=PRESENT\n'
        else printf 'NODEKEY=ABSENT\n'; fi
    """.trimIndent()
    fun metadata(paths: List<String>): String {
        require(paths.size in 1..RecoveryFileInventory.MAX_FILES && paths.all(::safePath))
        return "set -eu; $guard\n" + paths.mapIndexed { index, path ->
            "if [ ! -e '$path' ] && [ ! -L '$path' ]; then printf 'M|$index\\n'; " +
                "elif ! guard '$path' || [ ! -f '$path' ] || [ -L '$path' ]; then printf 'U|$index\\n'; " +
                "else printf 'F|$index|'; stat -c '%d|%i|%u|%a|%s|%Y|%Z|%h' -- '$path'; fi"
        }.joinToString("\n")
    }
    /**
     * URL paths that only look like file paths: the REALITY spider path, the HTTP path of web transports,
     * the HTTP-header path list and the path matcher of a fallback. Everything else that starts with "/"
     * (for example a fallback `dest` unix socket) is still reported as an unknown reference.
     */
    private const val WEB_PATH = "j.key='spiderX' OR j.path LIKE '%.request.path' OR (j.key='path' AND (" +
        "j.path LIKE '%.wsSettings' OR j.path LIKE '%.httpupgradeSettings' OR j.path LIKE '%.xhttpSettings' OR " +
        "j.path LIKE '%.splithttpSettings' OR j.path LIKE '%.httpSettings' OR j.path LIKE '%.fallbacks[%]'))"

    fun references(activeConfig: Boolean): String {
        val active = if (activeConfig) " UNION ALL SELECT CAST(readfile('/usr/local/x-ui/bin/config.json') AS TEXT)" else ""
        val docs = "WITH docs(d) AS MATERIALIZED (SELECT value FROM settings WHERE key='xrayTemplateConfig' UNION ALL SELECT stream_settings FROM inbounds UNION ALL SELECT settings FROM inbounds$active) "
        val valid = "length(CAST(d AS BLOB))<=65536 AND json_valid(d)=1 AND json_type(d)='object'"
        val sql = "PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; BEGIN; " + docs + ", header(line) AS (SELECT 'DOCS|' || count(*) || '|' || COALESCE(sum(length(CAST(d AS BLOB))),0) || '|' || " +
            "COALESCE(sum(CASE WHEN $valid THEN 0 ELSE 1 END),0) || '|' || " +
            "(SELECT count(*) FROM (SELECT key FROM settings WHERE key IN ('webCertFile','webKeyFile','subCertFile','subKeyFile','xrayTemplateConfig') GROUP BY key HAVING count(*)>1)) FROM docs), refs(kind,p) AS (" +
            "SELECT CASE WHEN key IN ('webKeyFile','subKeyFile') THEN 'PANEL_KEY' ELSE 'PANEL_CERT' END, value FROM settings " +
            "WHERE key IN ('webCertFile','webKeyFile','subCertFile','subKeyFile') AND value<>'' UNION ALL " +
            "SELECT CASE WHEN j.key='certificateFile' THEN 'XRAY_CERT' WHEN j.key IN ('keyFile','echKeyFile') THEN 'XRAY_KEY' " +
            "WHEN j.type='text' AND (j.atom LIKE 'ext:%' OR j.atom LIKE 'ext-ip:%') THEN 'XRAY_DATA' ELSE 'UNKNOWN' END, " +
            "CASE WHEN j.type='text' THEN j.atom ELSE 'INVALID_REFERENCE' END FROM docs, " +
            "json_tree(CASE WHEN $valid THEN d ELSE '{}' END) j WHERE " +
            "(j.key IN ('certificateFile','keyFile','echKeyFile') AND (j.type<>'text' OR j.atom<>'')) OR " +
            "(j.type='text' AND (j.atom LIKE 'ext:%' OR j.atom LIKE 'ext-ip:%' OR " +
            "j.atom LIKE 'file:%' OR j.atom LIKE 'unix:%' OR j.atom LIKE 'fd:%' OR " +
            "(j.atom LIKE '/%' AND COALESCE(j.key,'') NOT IN ('access','error') AND NOT COALESCE(($WEB_PATH),0))))) " +
            ", refrows(line) AS (SELECT DISTINCT kind || '|' || hex(p) FROM refs ORDER BY 1 LIMIT 33) " +
            "SELECT line FROM header UNION ALL SELECT line FROM refrows; COMMIT;"
        // Validate the generated config before SQLite's readfile() is allowed to touch it.
        val configGuard = if (activeConfig) "$guard\nguard '/usr/local/x-ui/bin/config.json' && [ -f '/usr/local/x-ui/bin/config.json' ] && " +
            "[ ! -L '/usr/local/x-ui/bin/config.json' ] && [ \"\$(stat -c '%u:%a:%h' -- '/usr/local/x-ui/bin/config.json')\" = '0:600:1' ] && " +
            "[ \"\$(stat -c '%s' -- '/usr/local/x-ui/bin/config.json')\" -le 65536 ] || exit 82; " else ""
        return "set -eu; $configGuard" + "timeout --kill-after=1s 8s prlimit --as=268435456:268435456 --cpu=5:5 -- sqlite3 -readonly -batch -noheader " +
            "'/etc/x-ui/x-ui.db' '" + sql.replace("'", "'\"'\"'") + "'"
    }
}
