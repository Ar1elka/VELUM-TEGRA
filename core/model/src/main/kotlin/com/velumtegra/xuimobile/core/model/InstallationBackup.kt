package com.velumtegra.xuimobile.core.model

import java.time.Instant

enum class InstallationBackupPhase { PENDING, COPYING, FINISHED, COMMAND_FAILED, UNCERTAIN, VERIFIED, FAILED, CANCELLED }

/** Durable non-secret binding carried by the existing journal checkpoint, never write authority. */
data class InstallationBackupBinding(val version: String, val architecture: UpdateServerArchitecture, val digest: String) {
    init {
        require(Regex("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}").matches(version))
        require(Regex("[0-9a-f]{64}").matches(digest))
    }
    val artifactId: String get() = digest.take(32)
    val remoteDirectory: String get() = "$REMOTE_ROOT/$artifactId"
    fun phaseName(phase: InstallationBackupPhase): String = "IBB1_${phase.name}:${architecture.name}:$version:$digest"
    companion object {
        const val REMOTE_ROOT: String = "/root/.velum-tegra-installation-backups"
        const val MAX_BYTES: Long = 704L * 1024 * 1024
        const val MAX_SLOTS: Int = 4
        fun parse(phaseName: String): Pair<InstallationBackupPhase, InstallationBackupBinding>? {
            val parts = phaseName.split(':')
            if (parts.size != 4 || !parts[0].startsWith("IBB1_")) return null
            val phase = InstallationBackupPhase.values().singleOrNull { "IBB1_${it.name}" == parts[0] } ?: return null
            val architecture = UpdateServerArchitecture.values().singleOrNull { it.name == parts[1] } ?: return null
            return try { phase to InstallationBackupBinding(parts[2], architecture, parts[3]) } catch (_: IllegalArgumentException) { null }
        }
    }
}

/** Verified known-file archive paired with a consistent DB snapshot. Never restore/update authority. */
data class InstallationBackupReceipt(val scope: ManagementScope, val binding: InstallationBackupBinding,
    val sha256: String, val sizeBytes: Long, val verifiedAt: Instant,
    val databaseSha256: String, val fileCount: Int, val inventorySha256: String) {
    init {
        require(Regex("[0-9a-f]{64}").matches(sha256))
        require(sizeBytes in 1..InstallationBackupBinding.MAX_BYTES)
        require(fileCount in 1..RecoveryFileInventory.MAX_FILES)
        require(Regex("[0-9a-f]{64}").matches(databaseSha256))
        require(Regex("[0-9a-f]{64}").matches(inventorySha256))
    }
}

enum class InstallationBackupFailure {
    EXACT_TARGET, AUTHORITY_MISSING, PRECHECK, STORAGE_UNAVAILABLE, CAPACITY,
    JOURNAL, SESSION, SOURCE_CHANGED, COPY_FAILED, PROOF_UNAVAILABLE,
}

data class InstallationBackupStorageObservation(val scope: ManagementScope, val safePrivateRoot: Boolean,
    val limitedToolsAvailable: Boolean, val slotsUsed: Int, val availableBytes: Long, val observedAt: Instant) {
    init { require(slotsUsed >= 0); require(availableBytes >= 0) }
}
