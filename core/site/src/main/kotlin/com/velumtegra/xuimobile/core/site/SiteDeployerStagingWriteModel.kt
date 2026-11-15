package com.velumtegra.xuimobile.core.site

data class SiteDeployerStagingDirectory(
    val relativePath: String,
    val remotePath: String,
)

data class SiteDeployerStagingFile(
    val relativePath: String,
    val remotePath: String,
    val mediaType: String,
    val byteSize: Int,
    val sha256: String,
)

data class SiteDeployerStagingWritePlan(
    val contractVersion: Int,
    val preparationSha256: String,
    val deploymentPlanSha256: String,
    val remoteHostIdentity: String,
    val targetRoot: String,
    val stagingRoot: String,
    val sourceTreeSha256: String,
    val fileCount: Int,
    val totalBytes: Long,
    val directories: List<SiteDeployerStagingDirectory>,
    val files: List<SiteDeployerStagingFile>,
    val stagingWritePlanSha256: String,
)
