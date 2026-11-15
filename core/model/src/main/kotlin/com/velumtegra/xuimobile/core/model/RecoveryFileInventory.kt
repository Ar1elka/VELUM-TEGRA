package com.velumtegra.xuimobile.core.model

import java.time.Instant

enum class RecoveryFileGroup { RUNTIME, SERVICE, PANEL_TLS, XRAY_TLS, XRAY_DATA }
enum class RecoveryFileIssue {
    READ_UNAVAILABLE, TARGET_UNVERIFIED, UNSAFE_PATH, UNSAFE_FILE, FILE_MISSING,
    LIMIT_EXCEEDED, REFERENCES_UNAVAILABLE, REFERENCES_CHANGED, FILES_CHANGED,
    SERVICE_ENVIRONMENT, UNKNOWN_REFERENCE,
}

data class RecoveryFileGroupObservation(val files: Int, val bytes: Long) {
    init { require(files in 0..RecoveryFileInventory.MAX_FILES); require(bytes in 0..RecoveryFileInventory.MAX_TOTAL_BYTES) }
}

/** Read-only process evidence. Paths, database values, private bytes and write authority are absent. */
data class RecoveryFileInventory(
    val scope: ManagementScope,
    val groups: Map<RecoveryFileGroup, RecoveryFileGroupObservation>,
    val fileCount: Int,
    val totalBytes: Long,
    val issues: Set<RecoveryFileIssue>,
    val knownSetDigest: String?,
    val observedAt: Instant,
    val sourceSetDigest: String? = null,
) {
    init {
        require(groups.keys == RecoveryFileGroup.values().toSet())
        require(fileCount in 0..MAX_FILES)
        require(totalBytes in 0..MAX_TOTAL_BYTES)
        require(groups.values.all { it.files <= fileCount && it.bytes <= totalBytes })
        sourceSetDigest?.let { require(Regex("[0-9a-f]{64}").matches(it)); require(issues.isEmpty()) }
        knownSetDigest?.let { require(Regex("[0-9a-f]{64}").matches(it)); require(issues.isEmpty()) }
    }
    companion object {
        const val MAX_FILES: Int = 96
        const val MAX_REFERENCES: Int = 32
        const val MAX_FILE_BYTES: Long = 256L * 1024 * 1024
        const val MAX_TOTAL_BYTES: Long = 512L * 1024 * 1024
        fun unavailable(scope: ManagementScope, issue: RecoveryFileIssue, at: Instant) = RecoveryFileInventory(
            scope, RecoveryFileGroup.values().associateWith { RecoveryFileGroupObservation(0, 0) }, 0, 0, setOf(issue), null, at)
    }
}

/** Requirements for a future archive, never a created-file receipt or execution consent. */
enum class RecoveryFileArtifactProof {
    REVALIDATED_FILE_SET, CONSISTENT_DATABASE_PAIRING, PRIVATE_ARCHIVE_CREATION,
    EXACT_MANIFEST_AND_HASH, VERIFIED_RESTORE,
}
