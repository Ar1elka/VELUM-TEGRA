package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant

/** Hashes exact non-secret metadata; only the digest, version and architecture enter the journal. */
object DatabaseBackupBindingPolicy {
    fun bind(operationId: OperationId, installation: XuiInstallation, access: ServerAccess,
        version: String, architecture: UpdateServerArchitecture): DatabaseBackupBinding {
        val i = installation.identity; val b = installation.baseline
        val parts = listOf(operationId.value, installation.id.value, installation.serverId.value, installation.ownership.name,
            i.serviceUnit, i.binaryPath, i.rootPath, i.databasePath, i.managedInstallId?.value,
            b.serviceUnit, b.binaryPath, b.rootPath, b.databasePath, b.panelPort.toString(), b.webBasePath,
            b.listenAddress, b.capturedAt.toString(), access.id.value, access.serverId.value, access.endpoint.host,
            access.endpoint.port.toString(), access.username, when (access.auth) { is SshAuthRef.Password -> "PASSWORD"; is SshAuthRef.PrivateKey -> "PRIVATE_KEY" },
            access.auth.secretId.value, access.pinnedHostKey.value,
            version.removePrefix("v"), architecture.name)
        val canonical = parts.joinToString("") { if (it == null) "-1:" else "${it.length}:$it" }
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        return DatabaseBackupBinding(version.removePrefix("v"), architecture, digest)
    }
    fun matches(current: VersionedOperationSnapshot, installation: XuiInstallation, access: ServerAccess): Boolean {
        val s = current.snapshot
        val target = s.target as? OperationTarget.InstallationTarget ?: return false
        val binding = DatabaseBackupBinding.parse(s.checkpoint.phaseName)?.second ?: return false
        if (s.type != OperationType.DATABASE_BACKUP || target.serverId != installation.serverId || target.installationId != installation.id ||
            target.serverAccessId != access.id || access.serverId != installation.serverId) return false
        return bind(s.operationId, installation, access, binding.version, binding.architecture) == binding
    }
}

class VerifiedDatabaseBackupDispatch internal constructor(val scope: ManagementScope, val binding: DatabaseBackupBinding,
    val expectedRevision: OperationRevision, val sourceBytes: Long) {
    private val used = java.util.concurrent.atomic.AtomicBoolean(false)
    fun consumeOnce(inFlightRevision: OperationRevision): Boolean =
        inFlightRevision.value == expectedRevision.value + 1 && used.compareAndSet(false, true)
}

object DatabaseBackupDispatchPolicy {
    fun authorize(confirmation: DatabaseBackupConfirmation, current: VersionedOperationSnapshot,
        fresh: UpdatePreflightSnapshot, storage: DatabaseBackupStorageObservation, now: Instant): VerifiedDatabaseBackupDispatch? {
        val s = current.snapshot
        val scope = ManagementScope(s.operationId, confirmation.target.serverId, confirmation.target.serverAccessId, confirmation.target.installationId)
        val bytes = fresh.recovery?.databaseBytes ?: return null
        if (s.operationId != confirmation.operationId || current.revision != confirmation.revision || s.target != confirmation.target ||
            s.status != OperationStatus.RUNNING || s.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED ||
            s.checkpoint.phaseName != confirmation.binding.phaseName(DatabaseBackupPhase.PENDING) || now.isBefore(s.updatedAt) ||
            !now.isBefore(confirmation.validUntil) || fresh.scope != scope || storage.scope != scope ||
            fresh.currentVersion?.removePrefix("v") != confirmation.binding.version || fresh.architecture != confirmation.binding.architecture ||
            UpdateRecoveryReadinessPolicy.review(fresh, now) !is UpdateRecoveryPlanReview.Draft ||
            bytes !in 1..DatabaseBackupBinding.MAX_BYTES || !storage.safePrivateRoot || !storage.limitedToolsAvailable ||
            storage.slotsUsed !in 0 until DatabaseBackupBinding.MAX_SLOTS || storage.availableBytes < bytes * 2 + 16L * 1024 * 1024 ||
            storage.observedAt.isAfter(now) || now.epochSecond - storage.observedAt.epochSecond > 30) return null
        return VerifiedDatabaseBackupDispatch(scope, confirmation.binding, current.revision, bytes)
    }
}

/** One explicit native creation confirmation. Never reconstruct from durable state. */
class DatabaseBackupConfirmation internal constructor(val operationId: OperationId, val revision: OperationRevision,
    val target: OperationTarget.InstallationTarget, val installation: XuiInstallation, val access: ServerAccess,
    val binding: DatabaseBackupBinding, val validUntil: Instant)

object DatabaseBackupConfirmationPolicy {
    fun confirm(current: VersionedOperationSnapshot, installation: XuiInstallation, access: ServerAccess,
        source: UpdatePreflightSnapshot, now: Instant): DatabaseBackupConfirmation? {
        val s = current.snapshot
        val phase = DatabaseBackupBinding.parse(s.checkpoint.phaseName) ?: return null
        val t = s.target as? OperationTarget.InstallationTarget ?: return null
        if (s.status != OperationStatus.RUNNING || s.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED ||
            phase.first != DatabaseBackupPhase.PENDING || now.isBefore(s.updatedAt) ||
            !DatabaseBackupBindingPolicy.matches(current, installation, access) ||
            source.scope.serverId != t.serverId || source.scope.installationId != t.installationId || source.scope.serverAccessId != t.serverAccessId ||
            UpdateRecoveryReadinessPolicy.review(source, now) !is UpdateRecoveryPlanReview.Draft ||
            source.currentVersion?.removePrefix("v") != phase.second.version || source.architecture != phase.second.architecture) return null
        return DatabaseBackupConfirmation(s.operationId, current.revision, t, installation, access, phase.second, now.plusSeconds(90))
    }
}
