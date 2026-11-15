package com.velumtegra.xuimobile.core.site

/**
 * Non-network derivation of the exact rename-only publish/rollback transaction that may consume a
 * previously verified Phase 11.52 staging tree. This boundary authorizes no upload, delete, chmod,
 * chown/chgrp, shell command, certificate mutation, coordinator call or UI action.
 */
object SiteDeployerCommitTransactionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun expectation(preparation: SiteDeployerLocalPreparationResult): SiteDeployerRemoteTreeExpectation {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        val bundle = preparation.bundle
        val expectation = SiteDeployerRemoteTreeExpectation(
            treeSha256 = bundle.manifest.treeSha256,
            fileCount = bundle.manifest.fileCount,
            totalBytes = bundle.manifest.totalBytes,
            files = bundle.documents.sortedBy { it.path }.map { document ->
                SiteDeployerRemoteTreeFileExpectation(
                    relativePath = document.path,
                    mediaType = document.mediaType,
                    byteSize = document.byteSize,
                    sha256 = document.sha256,
                )
            },
        )
        return expectation.also(::validateExpectation)
    }

    fun prepare(
        preparation: SiteDeployerLocalPreparationResult,
        stagingPlan: SiteDeployerStagingWritePlan,
        previousTargetTree: SiteDeployerRemoteTreeExpectation? = null,
    ): SiteDeployerCommitTransactionPlan {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteDeployerStagingWriteBoundary.validate(stagingPlan, preparation.bundle)
        require(stagingPlan.preparationSha256 == preparation.preparationSha256)
        require(stagingPlan.deploymentPlanSha256 == preparation.remoteDeployPlan.deploymentPlanSha256)
        val publish = preparation.remoteDeployPlan.publish
        val source = expectation(preparation)
        when (publish.existingTargetPolicy) {
            SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> require(previousTargetTree == null) {
                "Absent-target commit must not bind a previous target tree"
            }
            SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> {
                require(previousTargetTree != null) { "Replacement commit requires an exact previous target tree" }
                validateExpectation(previousTargetTree)
            }
        }
        val base = SiteDeployerCommitTransactionPlan(
            contractVersion = CONTRACT_VERSION,
            preparationSha256 = preparation.preparationSha256,
            deploymentPlanSha256 = preparation.remoteDeployPlan.deploymentPlanSha256,
            stagingWritePlanSha256 = stagingPlan.stagingWritePlanSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = publish.targetRoot,
            stagingRoot = publish.stagingRoot,
            backupRoot = publish.backupRoot,
            existingTargetPolicy = publish.existingTargetPolicy,
            sourceTree = source,
            previousTargetTree = previousTargetTree,
            verifyBeforeCommit = true,
            verifyAfterCommit = true,
            rollbackByRenameOnly = true,
            retainBackupAfterSuccessfulReplacement = publish.existingTargetPolicy == SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
            commitTransactionPlanSha256 = "",
        )
        return base.copy(commitTransactionPlanSha256 = digest(base)).also(::validate)
    }

    fun validate(plan: SiteDeployerCommitTransactionPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(plan.preparationSha256))
        require(sha256.matches(plan.deploymentPlanSha256))
        require(sha256.matches(plan.stagingWritePlanSha256))
        require(sha256.matches(plan.commitTransactionPlanSha256))
        require(plan.remoteHostIdentity.isNotBlank())
        val target = SiteRemoteDeployPolicy.prepareTargetRoot(plan.targetRoot)
        val staging = SiteRemoteDeployPolicy.prepareTargetRoot(plan.stagingRoot)
        require(target != staging)
        require(plan.verifyBeforeCommit && plan.verifyAfterCommit && plan.rollbackByRenameOnly)
        validateExpectation(plan.sourceTree)
        when (plan.existingTargetPolicy) {
            SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> {
                require(plan.backupRoot == null)
                require(plan.previousTargetTree == null)
                require(!plan.retainBackupAfterSuccessfulReplacement)
            }
            SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> {
                val backup = requireNotNull(plan.backupRoot)
                SiteRemoteDeployPolicy.prepareTargetRoot(backup)
                require(backup != target && backup != staging)
                require(plan.previousTargetTree != null)
                validateExpectation(plan.previousTargetTree)
                require(plan.retainBackupAfterSuccessfulReplacement)
            }
        }
        require(plan.commitTransactionPlanSha256 == digest(plan.copy(commitTransactionPlanSha256 = "")))
    }

    fun validateExpectation(expectation: SiteDeployerRemoteTreeExpectation) {
        require(sha256.matches(expectation.treeSha256))
        require(expectation.fileCount == expectation.files.size && expectation.fileCount > 0)
        require(expectation.totalBytes == expectation.files.sumOf { it.byteSize.toLong() })
        require(expectation.totalBytes in 0..SiteBuildPolicy.MAX_TOTAL_BYTES)
        require(expectation.files == expectation.files.sortedBy { it.relativePath })
        require(expectation.files.map { it.relativePath }.distinct().size == expectation.files.size)
        expectation.files.forEach { file ->
            SiteBuildPolicy.validatePath(file.relativePath)
            require(file.mediaType.isNotBlank())
            require(file.byteSize in 0..SiteBuildPolicy.MAX_DOCUMENT_BYTES)
            require(sha256.matches(file.sha256))
        }
    }

    private fun digest(plan: SiteDeployerCommitTransactionPlan): String {
        val canonical = buildString {
            append("contractVersion=").append(plan.contractVersion).append('\n')
            append("preparation=").append(plan.preparationSha256).append('\n')
            append("deploymentPlan=").append(plan.deploymentPlanSha256).append('\n')
            append("stagingPlan=").append(plan.stagingWritePlanSha256).append('\n')
            append("host=").append(plan.remoteHostIdentity).append('\n')
            append("target=").append(plan.targetRoot).append('\n')
            append("staging=").append(plan.stagingRoot).append('\n')
            append("backup=").append(plan.backupRoot ?: "").append('\n')
            append("policy=").append(plan.existingTargetPolicy.name).append('\n')
            append("verifyBefore=").append(plan.verifyBeforeCommit).append('\n')
            append("verifyAfter=").append(plan.verifyAfterCommit).append('\n')
            append("rollbackByRenameOnly=").append(plan.rollbackByRenameOnly).append('\n')
            append("retainBackup=").append(plan.retainBackupAfterSuccessfulReplacement).append('\n')
            appendExpectation("source", plan.sourceTree)
            plan.previousTargetTree?.let { appendExpectation("previous", it) }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun StringBuilder.appendExpectation(prefix: String, expectation: SiteDeployerRemoteTreeExpectation) {
        append(prefix).append("Tree=").append(expectation.treeSha256).append('\n')
        append(prefix).append("FileCount=").append(expectation.fileCount).append('\n')
        append(prefix).append("TotalBytes=").append(expectation.totalBytes).append('\n')
        expectation.files.forEach { file ->
            append(prefix).append("File=").append(file.relativePath).append('|').append(file.mediaType).append('|')
                .append(file.byteSize).append('|').append(file.sha256).append('\n')
        }
    }
}
