package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

enum class DatabaseBackupCopyResult { FINISHED, FAILED, UNCERTAIN, REJECTED }

/** Only the shared runtime can supply a verified dispatch and a durable in-flight checkpoint. */
class DatabaseBackupSshAdapter(private val now: () -> Instant = Instant::now) {
    suspend fun storage(scope: ManagementScope, session: SshSessionHandle): DatabaseBackupStorageObservation? {
        if (!exact(scope, session)) return null
        val raw = query(session, DatabaseBackupCommands.storage(), "database-backup-storage", 256) ?: return null
        if (!exact(scope, session)) return null
        val lines = raw.removeSuffix("\n").split('\n').map { it.trim() }
        if (lines.size != 2 || !Regex("[0-5]").matches(lines[0])) return null
        val space = lines[1].split('|')
        if (space.size != 2 || space.any { !Regex("[0-9]{1,18}").matches(it) }) return null
        val blocks = space[0].toLongOrNull() ?: return null
        val size = space[1].toLongOrNull() ?: return null
        val bytes = try { Math.multiplyExact(blocks, size) } catch (_: ArithmeticException) { return null }
        if (size <= 0 || bytes < 0) return null
        return DatabaseBackupStorageObservation(scope, true, true, lines[0].toInt(), bytes, now())
    }

    suspend fun copy(dispatch: VerifiedDatabaseBackupDispatch, current: VersionedOperationSnapshot,
        session: SshSessionHandle): DatabaseBackupCopyResult {
        val s = current.snapshot
        val t = s.target as? OperationTarget.InstallationTarget ?: return DatabaseBackupCopyResult.REJECTED
        if (!exact(dispatch.scope, session) || s.type != OperationType.DATABASE_BACKUP ||
            s.operationId != dispatch.scope.operationId || t.serverId != dispatch.scope.serverId ||
            t.installationId != dispatch.scope.installationId || t.serverAccessId != dispatch.scope.serverAccessId ||
            s.status != OperationStatus.RUNNING || s.checkpoint.semantics != CheckpointSemantics.MUTATION_IN_FLIGHT ||
            s.checkpoint.phaseName != dispatch.binding.phaseName(DatabaseBackupPhase.COPYING) ||
            current.revision.value != dispatch.expectedRevision.value + 1) return DatabaseBackupCopyResult.REJECTED
        currentCoroutineContext().ensureActive()
        if (!dispatch.consumeOnce(current.revision)) return DatabaseBackupCopyResult.REJECTED
        val binding = session.binding
        val result = session.execute(RemoteCommand.create(DatabaseBackupCommands.copy(dispatch.binding), "database-backup-create-once"),
            config(64, 85))
        currentCoroutineContext().ensureActive()
        if (!session.isOpen || session.binding != binding || result.dispatchState != CommandDispatchState.DISPATCHED)
            return DatabaseBackupCopyResult.UNCERTAIN
        return when (result.completion) {
            CommandCompletion.ConfirmedSuccess -> if (text(result, 64) == "CREATED\n") DatabaseBackupCopyResult.FINISHED else DatabaseBackupCopyResult.UNCERTAIN
            is CommandCompletion.ConfirmedFailure -> DatabaseBackupCopyResult.FAILED
            is CommandCompletion.Unknown -> DatabaseBackupCopyResult.UNCERTAIN
        }
    }

    /** Read-only positive proof. Missing/incomplete data never proves that an uncertain writer stopped. */
    suspend fun verify(scope: ManagementScope, binding: DatabaseBackupBinding,
        session: SshSessionHandle): DatabaseBackupReceipt? {
        if (!exact(scope, session)) return null
        val sessionBinding = session.binding
        suspend fun read(command: String, label: String, limit: Int): String? {
            if (!exact(scope, session) || session.binding != sessionBinding) return null
            val value = query(session, command, label, limit)
            return value.takeIf { exact(scope, session) && session.binding == sessionBinding }
        }
        val before = read(DatabaseBackupCommands.metadata(binding), "database-backup-artifact-metadata", 512) ?: return null
        val metadata = parseMetadata(before) ?: return null
        val raw = read(DatabaseBackupCommands.manifest(binding), "database-backup-manifest", 512) ?: return null
        if (raw.toByteArray(StandardCharsets.UTF_8).size.toLong() != metadata.second) return null
        val manifest = parseManifest(raw) ?: return null
        if (manifest["FORMAT"] != "VELUM_DB_BACKUP_V1" || manifest["SCOPE"] != binding.digest ||
            manifest["VERSION"] != binding.version || manifest["ARCH"] != binding.architecture.name ||
            manifest["BYTES"] != metadata.first.toString()) return null
        val hash = manifest["SHA256"]?.takeIf { Regex("[0-9a-f]{64}").matches(it) } ?: return null
        val hashRaw = read(DatabaseBackupCommands.hash(binding), "database-backup-sha256", 256) ?: return null
        if (hashRaw != "$hash  ${binding.remoteDirectory}/database.sqlite\n") return null
        if (read(DatabaseBackupCommands.check(binding), "database-backup-integrity", 64) != "ok\n") return null
        val after = read(DatabaseBackupCommands.metadata(binding), "database-backup-artifact-metadata", 512) ?: return null
        if (before != after || parseMetadata(after) == null) return null
        return DatabaseBackupReceipt(scope, binding, hash, metadata.first, now())
    }

    private fun parseMetadata(raw: String): Pair<Long, Long>? {
        val lines = raw.removeSuffix("\n").split('\n')
        if (lines.size != 2) return null
        val sizes = lines.mapIndexed { index, line ->
            val f = line.split('|')
            if (f.size != 8 || f.any { !Regex("0|[1-9][0-9]{0,18}").matches(it) }) return null
            if (f[2] != "0" || f[3] != "600" || f[7] != "1") return null
            val bytes = f[4].toLongOrNull() ?: return null
            if (bytes !in 1..(if (index == 0) DatabaseBackupBinding.MAX_BYTES else 512L)) return null
            if (f.any { it.toLongOrNull() == null }) return null
            bytes
        }
        return sizes[0] to sizes[1]
    }
    private fun parseManifest(raw: String): Map<String, String>? {
        if (!raw.endsWith('\n')) return null
        val lines = raw.dropLast(1).split('\n')
        if (lines.size != 6) return null
        val map = linkedMapOf<String, String>()
        for (line in lines) {
            val parts = line.split('=')
            if (parts.size != 2 || map.put(parts[0], parts[1]) != null) return null
        }
        return map.takeIf { it.keys == setOf("FORMAT", "SCOPE", "VERSION", "ARCH", "BYTES", "SHA256") }
    }
    private fun exact(scope: ManagementScope, session: SshSessionHandle) = session.isOpen &&
        session.binding.owner == SessionOwner.Operation(scope.operationId) && session.binding.serverAccessId == scope.serverAccessId
    private suspend fun query(session: SshSessionHandle, raw: String, label: String, limit: Int): String? {
        currentCoroutineContext().ensureActive()
        val result = session.execute(RemoteCommand.create(raw, label), config(limit, 30))
        currentCoroutineContext().ensureActive()
        return text(result, limit)
    }
    private fun config(limit: Int, seconds: Long) = SshTransportConfig(channelOpenTimeout = Duration.ofSeconds(5),
        commandExecutionTimeout = Duration.ofSeconds(seconds), stdoutCaptureLimitBytes = limit, stderrCaptureLimitBytes = 512)
    private fun text(result: SshCommandResult, limit: Int): String? {
        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.completion != CommandCompletion.ConfirmedSuccess ||
            result.stdout.truncated || result.stderr.truncated || result.stdout.sizeBytes > limit || result.stderr.sizeBytes != 0) return null
        val bytes = result.stdout.copyBytes()
        return try { StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: Exception) { null } finally { Arrays.fill(bytes, 0) }
    }
}

/** Closed command vocabulary: only validated hashes, finite architectures and numeric versions vary. */
internal object DatabaseBackupCommands {
    private const val ROOT = DatabaseBackupBinding.REMOTE_ROOT
    private val tools = "for t in sqlite3 sha256sum stat find head wc prlimit timeout sync mv mkdir flock; do command -v \"\$t\" >/dev/null 2>&1 || exit 81; done"
    private val privateRoot = "[ ! -L '/root' ] && [ -d '/root' ] && [ \"\$(stat -c '%u:%a' -- '/root')\" = '0:700' ] || exit 82; " +
        "if [ -e '$ROOT' ] || [ -L '$ROOT' ]; then [ ! -L '$ROOT' ] && [ -d '$ROOT' ] && [ \"\$(stat -c '%u:%a' -- '$ROOT')\" = '0:700' ] || exit 82; fi"
    private val slots = "if [ -d '$ROOT' ]; then find '$ROOT' -mindepth 1 -maxdepth 1 ! -name '.writer.lock' -printf x | head -c 5 | wc -c; else printf '0\\n'; fi"
    fun storage() = "set -eu; $tools; $privateRoot; $slots; stat -f -c '%a|%S' -- '/root'"
    fun copy(b: DatabaseBackupBinding): String {
        val d = b.remoteDirectory
        return """
            set -eu
            umask 077
            $tools
            $privateRoot
            [ ! -L '/etc' ] && [ ! -L '/etc/x-ui' ] && [ ! -L '/etc/x-ui/x-ui.db' ] && [ -f '/etc/x-ui/x-ui.db' ] || exit 83
            case "${'$'}(stat -c '%u:%a:%h' -- '/etc/x-ui/x-ui.db')" in '0:600:1'|'0:400:1') ;; *) exit 83 ;; esac
            source_identity=${'$'}(stat -c '%d:%i:%u:%a:%h' -- '/etc/x-ui/x-ui.db')
            source_bytes=${'$'}(stat -c '%s' -- '/etc/x-ui/x-ui.db')
            [ "${'$'}source_bytes" -gt 0 ] && [ "${'$'}source_bytes" -le 134217728 ] || exit 83
            if [ ! -d '$ROOT' ]; then mkdir -m 700 -- '$ROOT'; fi
            if [ -e '$ROOT/.writer.lock' ] || [ -L '$ROOT/.writer.lock' ]; then
                [ ! -L '$ROOT/.writer.lock' ] && [ -f '$ROOT/.writer.lock' ] && [ "${'$'}(stat -c '%u:%a:%h' -- '$ROOT/.writer.lock')" = '0:600:1' ] || exit 84
            fi
            exec 9>>'$ROOT/.writer.lock'
            flock -n 9 || exit 84
            slots=${'$'}($slots)
            [ "${'$'}slots" -lt 4 ] || exit 84
            mkdir -m 700 -- '$d'
            timeout --kill-after=5s 60s prlimit --fsize=134217728:134217728 --cpu=45:45 -- sqlite3 -readonly -batch -noheader -cmd '.timeout 5000' '/etc/x-ui/x-ui.db' ".backup '$d/database.sqlite'"
            [ ! -L '/etc' ] && [ ! -L '/etc/x-ui' ] && [ ! -L '/etc/x-ui/x-ui.db' ] && [ "${'$'}(stat -c '%d:%i:%u:%a:%h' -- '/etc/x-ui/x-ui.db')" = "${'$'}source_identity" ] || exit 85
            check=${'$'}(timeout --kill-after=5s 20s sqlite3 -batch -noheader '$d/database.sqlite' 'PRAGMA journal_mode=DELETE; PRAGMA quick_check;')
            [ "${'$'}check" = 'delete
ok' ] || exit 85
            [ ! -L '$d/database.sqlite' ] && [ "${'$'}(stat -c '%u:%a:%h' -- '$d/database.sqlite')" = '0:600:1' ] || exit 85
            bytes=${'$'}(stat -c '%s' -- '$d/database.sqlite')
            [ "${'$'}bytes" -gt 0 ] && [ "${'$'}bytes" -le 134217728 ] || exit 85
            sum=${'$'}(sha256sum -- '$d/database.sqlite')
            sum=${'$'}{sum%% *}
            sync -f '$d/database.sqlite'
            printf 'FORMAT=VELUM_DB_BACKUP_V1\nSCOPE=${b.digest}\nVERSION=${b.version}\nARCH=${b.architecture.name}\nBYTES=%s\nSHA256=%s\n' "${'$'}bytes" "${'$'}sum" > '$d/manifest.pending'
            sync -f '$d/manifest.pending'
            mv -T -- '$d/manifest.pending' '$d/manifest.v1'
            sync -f '$d'
            printf 'CREATED\n'
        """.trimIndent()
    }
    private fun artifactGuard(b: DatabaseBackupBinding): String {
        val d = b.remoteDirectory
        return "set -eu; $privateRoot; [ ! -L '$d' ] && [ -d '$d' ] && [ \"\$(stat -c '%u:%a' -- '$d')\" = '0:700' ] || exit 86; " +
            "for f in '$d/database.sqlite' '$d/manifest.v1'; do [ ! -L \"\$f\" ] && [ -f \"\$f\" ] && [ \"\$(stat -c '%u:%a:%h' -- \"\$f\")\" = '0:600:1' ] || exit 86; done; " +
            "[ ! -e '$d/database.sqlite-wal' ] && [ ! -L '$d/database.sqlite-wal' ] && [ ! -e '$d/database.sqlite-shm' ] && [ ! -L '$d/database.sqlite-shm' ] || exit 86"
    }
    fun metadata(b: DatabaseBackupBinding) = "${artifactGuard(b)}; stat -c '%d|%i|%u|%a|%s|%Y|%Z|%h' -- '${b.remoteDirectory}/database.sqlite' '${b.remoteDirectory}/manifest.v1'"
    fun manifest(b: DatabaseBackupBinding) = "${artifactGuard(b)}; [ \"\$(stat -c '%s' -- '${b.remoteDirectory}/manifest.v1')\" -le 512 ] || exit 86; head -c 512 -- '${b.remoteDirectory}/manifest.v1'"
    fun hash(b: DatabaseBackupBinding) = "${artifactGuard(b)}; timeout --kill-after=2s 20s sha256sum -- '${b.remoteDirectory}/database.sqlite'"
    fun check(b: DatabaseBackupBinding) = "${artifactGuard(b)}; timeout --kill-after=2s 20s sqlite3 -readonly -batch -noheader '${b.remoteDirectory}/database.sqlite' 'PRAGMA quick_check;'"
}
