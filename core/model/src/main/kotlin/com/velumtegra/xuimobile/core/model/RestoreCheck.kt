package com.velumtegra.xuimobile.core.model

import java.time.Instant

enum class RestoreCheckPhase { SOURCE_PENDING, REVIEWED, COPYING, FINISHED, COMMAND_FAILED, UNCERTAIN, VERIFIED, FAILED, CANCELLED }

/** Durable public hashes and exact journal pointers. Never live restore, migration or update authority. */
data class RestoreCheckBinding(
    val sourceOperationId: OperationId, val sourceRevision: Long, val source: InstallationBackupBinding,
    val digest: String, val archiveSha256: String = ZERO, val databaseSha256: String = ZERO,
    val inventorySha256: String = ZERO, val archiveBytes: Long = 0, val fileCount: Int = 0,
) {
    init {
        require(Regex("[A-Za-z0-9._-]{1,96}").matches(sourceOperationId.value) && sourceRevision >= 0)
        require(listOf(digest, archiveSha256, databaseSha256, inventorySha256).all { Regex("[0-9a-f]{64}").matches(it) })
        require((archiveBytes == 0L && fileCount == 0 && listOf(archiveSha256, databaseSha256, inventorySha256).all { it == ZERO }) ||
            (archiveBytes in 1..InstallationBackupBinding.MAX_BYTES && fileCount in 1..RecoveryFileInventory.MAX_FILES &&
                listOf(archiveSha256, databaseSha256, inventorySha256).none { it == ZERO }))
    }
    val hasSourceProof: Boolean get() = archiveBytes > 0
    fun phaseName(phase: RestoreCheckPhase): String {
        require(when (phase) {
            RestoreCheckPhase.SOURCE_PENDING -> !hasSourceProof
            RestoreCheckPhase.FAILED, RestoreCheckPhase.CANCELLED -> true
            else -> hasSourceProof
        })
        return listOf("RCB1_${phase.name}", source.architecture.name, source.version,
            sourceOperationId.value, sourceRevision.toString(), source.digest, digest, archiveSha256, databaseSha256,
            inventorySha256, archiveBytes.toString(), fileCount.toString()).joinToString(":")
    }
    companion object {
        const val ROOT: String = "/root/.velum-tegra-restore-checks"
        const val MAX_SLOTS: Int = 4
        const val MAX_RESTORED_BYTES: Long = 640L * 1024 * 1024
        const val ZERO: String = "0000000000000000000000000000000000000000000000000000000000000000"
        fun parse(value: String): Pair<RestoreCheckPhase, RestoreCheckBinding>? {
            val p = value.split(':'); if (p.size != 12) return null
            val phase = RestoreCheckPhase.values().singleOrNull { "RCB1_${it.name}" == p[0] } ?: return null
            val arch = UpdateServerArchitecture.values().singleOrNull { it.name == p[1] } ?: return null
            return try {
                val binding = RestoreCheckBinding(OperationId(p[3]), p[4].toLong(), InstallationBackupBinding(p[2], arch, p[5]),
                    p[6], p[7], p[8], p[9], p[10].toLong(), p[11].toInt())
                if (binding.phaseName(phase) == value) phase to binding else null
            } catch (_: IllegalArgumentException) { null }
        }
    }
}

/** Only files restored into an isolated private directory and read back. No execution or live replacement. */
data class RestoreCheckReceipt(val scope: ManagementScope, val binding: RestoreCheckBinding,
    val restoredBytes: Long, val verifiedAt: Instant) {
    init { require(binding.hasSourceProof && restoredBytes in 1..RestoreCheckBinding.MAX_RESTORED_BYTES) }
}

enum class RestoreCheckFailure { EXACT_TARGET, SOURCE, AUTHORITY_MISSING, JOURNAL, SESSION, PRECHECK, CAPACITY, PROOF_UNAVAILABLE }
