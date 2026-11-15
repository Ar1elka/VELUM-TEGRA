package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant

sealed interface RecoveryFileInventoryReview {
    data object Missing : RecoveryFileInventoryReview
    data object Stale : RecoveryFileInventoryReview
    data class Findings(val issues: Set<RecoveryFileIssue>) : RecoveryFileInventoryReview
    /** The known set was observed; complete external-resource coverage is NOT established. */
    data class KnownSet(val fileCount: Int, val totalBytes: Long,
        val pendingProofs: List<RecoveryFileArtifactProof> = RecoveryFileArtifactProof.values().toList()) : RecoveryFileInventoryReview
}

object RecoveryFileInventoryPolicy {
    fun review(report: UpdatePreflightSnapshot, now: Instant): RecoveryFileInventoryReview {
        val files = report.recoveryFiles ?: return RecoveryFileInventoryReview.Missing
        if (files.scope != report.scope || files.observedAt.isAfter(report.observedAt) || report.observedAt.isAfter(now) ||
            files.observedAt.isAfter(now) || !now.isBefore(files.observedAt.plusSeconds(300))) return RecoveryFileInventoryReview.Stale
        if (report.root != UpdateRootStatus.DIRECT_ROOT || report.layout != UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD ||
            report.serviceDefinition != DeepDiagnosticServiceDefinitionStatus.CONSISTENT ||
            report.baselineStatus != ManagementBaselineStatus.Matched) return RecoveryFileInventoryReview.Findings(setOf(RecoveryFileIssue.TARGET_UNVERIFIED))
        if (files.issues.isNotEmpty()) return RecoveryFileInventoryReview.Findings(files.issues)
        if (files.knownSetDigest == null || files.fileCount == 0 || files.groups.getValue(RecoveryFileGroup.RUNTIME).files == 0 ||
            files.groups.getValue(RecoveryFileGroup.SERVICE).files == 0) return RecoveryFileInventoryReview.Findings(setOf(RecoveryFileIssue.READ_UNAVAILABLE))
        return RecoveryFileInventoryReview.KnownSet(files.fileCount, files.totalBytes)
    }
}
