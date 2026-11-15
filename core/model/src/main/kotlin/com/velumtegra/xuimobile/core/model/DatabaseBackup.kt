package com.velumtegra.xuimobile.core.model

import java.time.Instant

enum class DatabaseBackupPhase { PENDING, COPYING, FINISHED, COMMAND_FAILED, UNCERTAIN, VERIFIED, FAILED, CANCELLED }

/** Durable non-secret binding carried by the existing journal checkpoint, never write authority. */
data class DatabaseBackupBinding(val version: String, val architecture: UpdateServerArchitecture, val digest: String) {
    init {
        require(Regex("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}").matches(version))
        require(Regex("[0-9a-f]{64}").matches(digest))
    }
    val artifactId: String get() = digest.take(32)
    val remoteDirectory: String get() = "$REMOTE_ROOT/$artifactId"
    fun phaseName(phase: DatabaseBackupPhase): String = "DBB1_${phase.name}:${architecture.name}:$version:$digest"
    companion object {
        const val REMOTE_ROOT: String = "/root/.velum-tegra-db-backups"
        const val MAX_BYTES: Long = 128L * 1024 * 1024
        const val MAX_SLOTS: Int = 4
        fun parse(phaseName: String): Pair<DatabaseBackupPhase, DatabaseBackupBinding>? {
            val parts = phaseName.split(':')
            if (parts.size != 4 || !parts[0].startsWith("DBB1_")) return null
            val phase = DatabaseBackupPhase.values().singleOrNull { "DBB1_${it.name}" == parts[0] } ?: return null
            val architecture = UpdateServerArchitecture.values().singleOrNull { it.name == parts[1] } ?: return null
            return try { phase to DatabaseBackupBinding(parts[2], architecture, parts[3]) } catch (_: IllegalArgumentException) { null }
        }
    }
}

/** Verified DATABASE copy only. It is not a complete installation backup or restore/update consent. */
data class DatabaseBackupReceipt(val scope: ManagementScope, val binding: DatabaseBackupBinding,
    val sha256: String, val sizeBytes: Long, val verifiedAt: Instant) {
    init {
        require(Regex("[0-9a-f]{64}").matches(sha256))
        require(sizeBytes in 1..DatabaseBackupBinding.MAX_BYTES)
    }
}

enum class DatabaseBackupFailure {
    EXACT_TARGET, AUTHORITY_MISSING, PRECHECK, STORAGE_UNAVAILABLE, CAPACITY,
    JOURNAL, SESSION, SOURCE_CHANGED, COPY_FAILED, PROOF_UNAVAILABLE,
}

data class DatabaseBackupStorageObservation(val scope: ManagementScope, val safePrivateRoot: Boolean,
    val limitedToolsAvailable: Boolean, val slotsUsed: Int, val availableBytes: Long, val observedAt: Instant) {
    init { require(slotsUsed >= 0); require(availableBytes >= 0) }
}
