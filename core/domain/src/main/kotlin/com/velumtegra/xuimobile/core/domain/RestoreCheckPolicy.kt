package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.security.MessageDigest
import java.time.Instant

object RestoreCheckBindingPolicy {
    fun parentMatches(parent: VersionedOperationSnapshot, installation: XuiInstallation, access: ServerAccess): Boolean =
        parent.snapshot.status == OperationStatus.SUCCEEDED && parent.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL &&
            InstallationBackupBinding.parse(parent.snapshot.checkpoint.phaseName)?.first == InstallationBackupPhase.VERIFIED &&
            InstallationBackupBindingPolicy.matches(parent, installation, access)

    fun bind(id: OperationId, installation: XuiInstallation, access: ServerAccess, parent: VersionedOperationSnapshot,
        archiveSha256: String = RestoreCheckBinding.ZERO, databaseSha256: String = RestoreCheckBinding.ZERO,
        inventorySha256: String = RestoreCheckBinding.ZERO, archiveBytes: Long = 0, fileCount: Int = 0): RestoreCheckBinding {
        require(parentMatches(parent, installation, access))
        val source = requireNotNull(InstallationBackupBinding.parse(parent.snapshot.checkpoint.phaseName)).second
        val seed = InstallationBackupBindingPolicy.bind(id, installation, access, source.version, source.architecture).digest
        val canonical = listOf("ISOLATED_RESTORE_V1", seed, parent.snapshot.operationId.value, parent.revision.value.toString(),
            source.digest, archiveSha256, databaseSha256, inventorySha256, archiveBytes.toString(), fileCount.toString())
            .joinToString("") { "${it.length}:$it" }
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        return RestoreCheckBinding(parent.snapshot.operationId, parent.revision.value, source, digest,
            archiveSha256, databaseSha256, inventorySha256, archiveBytes, fileCount)
    }
    fun matches(current: VersionedOperationSnapshot, installation: XuiInstallation, access: ServerAccess,
        parent: VersionedOperationSnapshot): Boolean {
        val s = current.snapshot; val b = RestoreCheckBinding.parse(s.checkpoint.phaseName)?.second ?: return false
        if (s.type != OperationType.INSTALLATION_RESTORE_CHECK || !parentMatches(parent, installation, access) || s.target != parent.snapshot.target ||
            b.sourceOperationId != parent.snapshot.operationId || b.sourceRevision != parent.revision.value || s.operationId == b.sourceOperationId) return false
        return try { b == bind(s.operationId, installation, access, parent, b.archiveSha256, b.databaseSha256,
            b.inventorySha256, b.archiveBytes, b.fileCount) } catch (_: IllegalArgumentException) { false }
    }
}

class RestoreCheckConfirmation internal constructor(val operationId: OperationId, val revision: OperationRevision,
    val target: OperationTarget.InstallationTarget, val installation: XuiInstallation, val access: ServerAccess,
    val binding: RestoreCheckBinding, val validUntil: Instant)

object RestoreCheckConfirmationPolicy {
    fun confirm(current: VersionedOperationSnapshot, installation: XuiInstallation, access: ServerAccess,
        parent: VersionedOperationSnapshot, now: Instant): RestoreCheckConfirmation? {
        val s = current.snapshot; val parsed = RestoreCheckBinding.parse(s.checkpoint.phaseName) ?: return null
        if (parsed.first != RestoreCheckPhase.REVIEWED || !parsed.second.hasSourceProof || s.status != OperationStatus.RUNNING ||
            s.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED || now.isBefore(s.updatedAt) ||
            now.epochSecond - s.updatedAt.epochSecond >= 300 || !RestoreCheckBindingPolicy.matches(current, installation, access, parent)) return null
        return RestoreCheckConfirmation(s.operationId, current.revision, s.target as OperationTarget.InstallationTarget,
            installation, access, parsed.second, now.plusSeconds(90))
    }
}

class VerifiedRestoreCheckDispatch internal constructor(val scope: ManagementScope, val binding: RestoreCheckBinding,
    val expectedRevision: OperationRevision, val validFrom: Instant, val validUntil: Instant) {
    private val consumed = java.util.concurrent.atomic.AtomicBoolean(false)
    fun consumeOnce(revision: OperationRevision, at: Instant): Boolean = !at.isBefore(validFrom) && at.isBefore(validUntil) &&
        revision.value == expectedRevision.value + 1 && consumed.compareAndSet(false, true)
}

object RestoreCheckDispatchPolicy {
    fun authorize(c: RestoreCheckConfirmation, current: VersionedOperationSnapshot,
        space: InstallationBackupStorageObservation, now: Instant): VerifiedRestoreCheckDispatch? {
        val s = current.snapshot
        val scope = ManagementScope(s.operationId, c.target.serverId, c.target.serverAccessId, c.target.installationId)
        if (s.operationId != c.operationId || s.target != c.target || current.revision != c.revision ||
            s.type != OperationType.INSTALLATION_RESTORE_CHECK || s.status != OperationStatus.RUNNING ||
            s.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED ||
            s.checkpoint.phaseName != c.binding.phaseName(RestoreCheckPhase.REVIEWED) || !c.binding.hasSourceProof ||
            now.isBefore(s.updatedAt) || !now.isBefore(c.validUntil) || space.scope != scope ||
            !space.safePrivateRoot || !space.limitedToolsAvailable || space.slotsUsed !in 0 until RestoreCheckBinding.MAX_SLOTS ||
            space.availableBytes < c.binding.archiveBytes * 2 + 48L * 1024 * 1024 || space.observedAt.isAfter(now) ||
            now.epochSecond - space.observedAt.epochSecond > 30) return null
        return VerifiedRestoreCheckDispatch(scope, c.binding, current.revision, now, c.validUntil)
    }
}
