package com.velumtegra.xuimobile.core.site

data class SiteDeployerRemoteTreeFileExpectation(
    val relativePath: String,
    val mediaType: String,
    val byteSize: Int,
    val sha256: String,
)

data class SiteDeployerRemoteTreeExpectation(
    val treeSha256: String,
    val fileCount: Int,
    val totalBytes: Long,
    val files: List<SiteDeployerRemoteTreeFileExpectation>,
)

data class SiteDeployerCommitTransactionPlan(
    val contractVersion: Int,
    val preparationSha256: String,
    val deploymentPlanSha256: String,
    val stagingWritePlanSha256: String,
    val remoteHostIdentity: String,
    val targetRoot: String,
    val stagingRoot: String,
    val backupRoot: String?,
    val existingTargetPolicy: SiteRemoteExistingTargetPolicy,
    val sourceTree: SiteDeployerRemoteTreeExpectation,
    val previousTargetTree: SiteDeployerRemoteTreeExpectation?,
    val verifyBeforeCommit: Boolean,
    val verifyAfterCommit: Boolean,
    val rollbackByRenameOnly: Boolean,
    val retainBackupAfterSuccessfulReplacement: Boolean,
    val commitTransactionPlanSha256: String,
)
