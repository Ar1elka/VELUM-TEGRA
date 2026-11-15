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

enum class InstallationBackupCopyResult { FINISHED, FAILED, UNCERTAIN, REJECTED }

/** Exact session only. Worker emits closed finite proof, never private member names or contents. */
class InstallationBackupSshAdapter(private val now: () -> Instant = Instant::now) {
    suspend fun storage(scope: ManagementScope, session: SshSessionHandle): InstallationBackupStorageObservation? {
        if (!exact(scope, session)) return null
        val binding = session.binding
        val raw = query(session, InstallationBackupCommands.storage(), "installation-backup-storage", 128, 10) ?: return null
        if (!exact(scope, session) || session.binding != binding) return null
        val parts = raw.removeSuffix("\n").split('\n')
        if (parts.size != 2 || !Regex("[0-4]").matches(parts[0]) || !Regex("0|[1-9][0-9]{0,18}").matches(parts[1])) return null
        val available = parts[1].toLongOrNull() ?: return null
        return InstallationBackupStorageObservation(scope, true, true, parts[0].toInt(), available, now())
    }

    suspend fun copy(dispatch: VerifiedInstallationBackupDispatch, current: VersionedOperationSnapshot,
        session: SshSessionHandle): InstallationBackupCopyResult {
        val s = current.snapshot
        val target = s.target as? OperationTarget.InstallationTarget ?: return InstallationBackupCopyResult.REJECTED
        if (!exact(dispatch.scope, session) || s.type != OperationType.INSTALLATION_BACKUP || s.operationId != dispatch.scope.operationId ||
            target.serverId != dispatch.scope.serverId || target.installationId != dispatch.scope.installationId ||
            target.serverAccessId != dispatch.scope.serverAccessId || s.status != OperationStatus.RUNNING ||
            s.checkpoint.semantics != CheckpointSemantics.MUTATION_IN_FLIGHT ||
            s.checkpoint.phaseName != dispatch.binding.phaseName(InstallationBackupPhase.COPYING) ||
            current.revision.value != dispatch.expectedRevision.value + 1) return InstallationBackupCopyResult.REJECTED
        currentCoroutineContext().ensureActive()
        if (!dispatch.consumeOnce(current.revision, now())) return InstallationBackupCopyResult.REJECTED
        val binding = session.binding
        val result = session.execute(RemoteCommand.create(InstallationBackupCommands.copy(dispatch.binding, dispatch.fileSetDigest), "installation-backup-create-once"), config(64, 95))
        currentCoroutineContext().ensureActive()
        if (!session.isOpen || session.binding != binding || result.dispatchState != CommandDispatchState.DISPATCHED) return InstallationBackupCopyResult.UNCERTAIN
        return when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> if (text(result, 64) == "CREATED\n") InstallationBackupCopyResult.FINISHED else InstallationBackupCopyResult.UNCERTAIN
            is CommandCompletion.ConfirmedFailure -> if (completion.exitCode == 81) InstallationBackupCopyResult.FAILED else InstallationBackupCopyResult.UNCERTAIN
            is CommandCompletion.Unknown -> InstallationBackupCopyResult.UNCERTAIN
        }
    }

    /** Explicit read-only proof of all tar members and SQLite snapshot; never creates/extracts. */
    suspend fun verify(scope: ManagementScope, binding: InstallationBackupBinding, session: SshSessionHandle): InstallationBackupReceipt? {
        if (!exact(scope, session)) return null
        val before = session.binding
        val raw = query(session, InstallationBackupCommands.verify(binding), "installation-backup-verify-existing", 1024, 80) ?: return null
        if (!exact(scope, session) || session.binding != before || !raw.endsWith('\n')) return null
        val values = linkedMapOf<String, String>()
        val lines = raw.dropLast(1).split('\n')
        if (lines.size != 9) return null
        for (line in lines) {
            val parts = line.split('=')
            if (parts.size != 2 || values.put(parts[0], parts[1]) != null) return null
        }
        if (values.keys != setOf("FORMAT", "SCOPE", "VERSION", "ARCH", "BYTES", "SHA256", "DATABASE_SHA256", "FILES", "INVENTORY_SHA256") ||
            values["FORMAT"] != "VELUM_KNOWN_INSTALLATION_V1" || values["SCOPE"] != binding.digest ||
            values["VERSION"] != binding.version || values["ARCH"] != binding.architecture.name) return null
        val hash = values["SHA256"]?.takeIf { Regex("[0-9a-f]{64}").matches(it) } ?: return null
        val dbHash = values["DATABASE_SHA256"]?.takeIf { Regex("[0-9a-f]{64}").matches(it) } ?: return null
        val inventoryHash = values["INVENTORY_SHA256"]?.takeIf { Regex("[0-9a-f]{64}").matches(it) } ?: return null
        val bytes = values["BYTES"]?.takeIf { Regex("[1-9][0-9]{0,9}").matches(it) }?.toLongOrNull() ?: return null
        val count = values["FILES"]?.takeIf { Regex("[1-9][0-9]?").matches(it) }?.toIntOrNull() ?: return null
        if (bytes !in 1..InstallationBackupBinding.MAX_BYTES || count !in 1..RecoveryFileInventory.MAX_FILES) return null
        return InstallationBackupReceipt(scope, binding, hash, bytes, now(), dbHash, count, inventoryHash)
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

internal object InstallationBackupCommands {
    private fun quote(value: String) = "'" + value.replace("'", "'\"'\"'") + "'"
    private fun command(mode: String, binding: InstallationBackupBinding, seconds: Int, fileSetDigest: String = "0".repeat(64)): String {
        require(Regex("[0-9a-f]{64}").matches(fileSetDigest))
        return "timeout --kill-after=2s ${seconds}s python3 -I -c " + quote(InstallationBackupWorker.source) +
            " $mode ${binding.digest} ${binding.version} ${binding.architecture.name} $fileSetDigest"
    }
    fun storage() = command("storage", InstallationBackupBinding("0.0.0", UpdateServerArchitecture.AMD64, "0".repeat(64)), 8)
    fun copy(binding: InstallationBackupBinding, fileSetDigest: String) = command("create", binding, 90, fileSetDigest)
    fun verify(binding: InstallationBackupBinding) = command("verify", binding, 75)
}
