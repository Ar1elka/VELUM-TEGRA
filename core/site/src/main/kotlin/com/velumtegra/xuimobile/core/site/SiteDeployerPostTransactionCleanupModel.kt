package com.velumtegra.xuimobile.core.site

enum class SiteDeployerPostTransactionCleanupKind {
    RETAINED_BACKUP_AFTER_COMMIT,
    STAGING_AFTER_ROLLBACK,
}

data class SiteDeployerPostTransactionCleanupPlan(
    val contractVersion: Int,
    val commitTransactionPlanSha256: String,
    val remoteHostIdentity: String,
    val existingTargetPolicy: SiteRemoteExistingTargetPolicy,
    val cleanupKind: SiteDeployerPostTransactionCleanupKind,
    val targetRoot: String,
    val stagingRoot: String,
    val backupRoot: String?,
    val cleanupRoot: String,
    val cleanupTree: SiteDeployerRemoteTreeExpectation,
    val preservedTargetTree: SiteDeployerRemoteTreeExpectation?,
    val preservedTargetMustBeAbsent: Boolean,
    val siblingRootThatMustRemainAbsent: String?,
    val verifyBeforeCleanup: Boolean,
    val verifyAfterCleanup: Boolean,
    val postTransactionCleanupPlanSha256: String,
)
