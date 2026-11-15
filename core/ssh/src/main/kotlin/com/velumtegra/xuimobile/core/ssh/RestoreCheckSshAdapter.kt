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

enum class RestoreCheckCopyResult { FINISHED, FAILED, UNCERTAIN, REJECTED }

/** Fixed private test directory only. No live replacement, service command or migration. */
class RestoreCheckSshAdapter(private val now: () -> Instant = Instant::now) {
    suspend fun storage(scope: ManagementScope, binding: RestoreCheckBinding, session: SshSessionHandle): InstallationBackupStorageObservation? {
        if (!exact(scope, session) || !binding.hasSourceProof) return null
        val before = session.binding
        val raw = query(session, RestoreCheckCommands.storage(binding), "restore-check-storage", 128, 10) ?: return null
        if (!exact(scope, session) || session.binding != before) return null
        val parts = raw.removeSuffix("\n").split('\n')
        if (parts.size != 2 || !Regex("[0-4]").matches(parts[0]) || !Regex("0|[1-9][0-9]{0,18}").matches(parts[1])) return null
        val available = parts[1].toLongOrNull() ?: return null
        return InstallationBackupStorageObservation(scope, true, true, parts[0].toInt(), available, now())
    }

    suspend fun copy(dispatch: VerifiedRestoreCheckDispatch, current: VersionedOperationSnapshot,
        session: SshSessionHandle): RestoreCheckCopyResult {
        val s = current.snapshot
        val target = s.target as? OperationTarget.InstallationTarget ?: return RestoreCheckCopyResult.REJECTED
        if (!exact(dispatch.scope, session) || s.type != OperationType.INSTALLATION_RESTORE_CHECK || s.operationId != dispatch.scope.operationId ||
            target.serverId != dispatch.scope.serverId || target.installationId != dispatch.scope.installationId ||
            target.serverAccessId != dispatch.scope.serverAccessId || s.status != OperationStatus.RUNNING ||
            s.checkpoint.semantics != CheckpointSemantics.MUTATION_IN_FLIGHT ||
            s.checkpoint.phaseName != dispatch.binding.phaseName(RestoreCheckPhase.COPYING) ||
            current.revision.value != dispatch.expectedRevision.value + 1) return RestoreCheckCopyResult.REJECTED
        currentCoroutineContext().ensureActive()
        if (!dispatch.consumeOnce(current.revision, now())) return RestoreCheckCopyResult.REJECTED
        val binding = session.binding
        val result = session.execute(RemoteCommand.create(RestoreCheckCommands.copy(dispatch.binding), "restore-check-create-once"), config(64, 140))
        currentCoroutineContext().ensureActive()
        if (!session.isOpen || session.binding != binding || result.dispatchState != CommandDispatchState.DISPATCHED) return RestoreCheckCopyResult.UNCERTAIN
        return when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> if (text(result, 64) == "RESTORED\n") RestoreCheckCopyResult.FINISHED else RestoreCheckCopyResult.UNCERTAIN
            is CommandCompletion.ConfirmedFailure -> if (completion.exitCode == 81) RestoreCheckCopyResult.FAILED else RestoreCheckCopyResult.UNCERTAIN
            is CommandCompletion.Unknown -> RestoreCheckCopyResult.UNCERTAIN
        }
    }

    /** Explicit read-only proof of separately restored files and SQLite snapshot. */
    suspend fun verify(scope: ManagementScope, binding: RestoreCheckBinding, session: SshSessionHandle): RestoreCheckReceipt? {
        if (!exact(scope, session) || !binding.hasSourceProof) return null
        val before = session.binding
        val raw = query(session, RestoreCheckCommands.verify(binding), "restore-check-verify-existing", 1024, 90) ?: return null
        if (!exact(scope, session) || session.binding != before || !raw.endsWith('\n')) return null
        val values = linkedMapOf<String, String>()
        val lines = raw.dropLast(1).split('\n')
        if (lines.size != 10 || !binding.hasSourceProof) return null
        for (line in lines) {
            val parts = line.split('=')
            if (parts.size != 2 || values.put(parts[0], parts[1]) != null) return null
        }
        if (values.keys != setOf("FORMAT", "SCOPE", "SOURCE_SCOPE", "VERSION", "ARCH", "BYTES", "SHA256", "DATABASE_SHA256", "FILES", "INVENTORY_SHA256") ||
            values["FORMAT"] != "VELUM_RESTORE_FILES_V1" || values["SCOPE"] != binding.digest || values["SOURCE_SCOPE"] != binding.source.digest ||
            values["VERSION"] != binding.source.version || values["ARCH"] != binding.source.architecture.name ||
            values["SHA256"] != binding.archiveSha256 || values["DATABASE_SHA256"] != binding.databaseSha256 ||
            values["INVENTORY_SHA256"] != binding.inventorySha256 || values["FILES"] != binding.fileCount.toString()) return null
        val bytes = values["BYTES"]?.takeIf { Regex("[1-9][0-9]{0,9}").matches(it) }?.toLongOrNull() ?: return null
        if (bytes !in 1..RestoreCheckBinding.MAX_RESTORED_BYTES) return null
        return RestoreCheckReceipt(scope, binding, bytes, now())
    }
    private fun exact(scope: ManagementScope, session: SshSessionHandle) = session.isOpen &&
        session.binding.owner == SessionOwner.Operation(scope.operationId) && session.binding.serverAccessId == scope.serverAccessId
    private suspend fun query(session: SshSessionHandle, command: String, label: String, limit: Int, seconds: Long): String? {
        currentCoroutineContext().ensureActive()
        val result = session.execute(RemoteCommand.create(command, label), config(limit, seconds))
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

internal object RestoreCheckCommands {
    private fun quote(value: String) = "'" + value.replace("'", "'\"'\"'") + "'"
    private fun command(mode: String, binding: RestoreCheckBinding, seconds: Int): String {
        require(binding.hasSourceProof && mode in setOf("space", "copy", "check"))
        return "timeout --kill-after=2s ${seconds}s python3 -I -c " + quote(RestoreCheckWorker.source) +
            " $mode ${binding.digest} ${binding.source.digest} ${binding.source.version} ${binding.source.architecture.name}" +
            " ${binding.archiveSha256} ${binding.databaseSha256} ${binding.inventorySha256} ${binding.archiveBytes} ${binding.fileCount}"
    }
    fun storage(binding: RestoreCheckBinding) = command("space", binding, 8)
    fun copy(binding: RestoreCheckBinding) = command("copy", binding, 130)
    fun verify(binding: RestoreCheckBinding) = command("check", binding, 85)
}
