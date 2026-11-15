package com.velumtegra.xuimobile.core.site

/**
 * Exact residual cleanup boundary after a Phase 11.53 commit/rollback result has already been
 * proven. This boundary can derive cleanup only for a retained replacement backup or for the exact
 * staging tree restored by rollback. The live target is never a cleanup root.
 */
object SiteDeployerPostTransactionCleanupBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun prepareRetainedBackupAfterCommit(
        commitPlan: SiteDeployerCommitTransactionPlan,
    ): SiteDeployerPostTransactionCleanupPlan {
        SiteDeployerCommitTransactionBoundary.validate(commitPlan)
        require(commitPlan.existingTargetPolicy == SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE) {
            "Only replacement commit can retain a cleanup backup"
        }
        val backup = requireNotNull(commitPlan.backupRoot)
        val previous = requireNotNull(commitPlan.previousTargetTree)
        val base = SiteDeployerPostTransactionCleanupPlan(
            contractVersion = CONTRACT_VERSION,
            commitTransactionPlanSha256 = commitPlan.commitTransactionPlanSha256,
            remoteHostIdentity = commitPlan.remoteHostIdentity,
            existingTargetPolicy = commitPlan.existingTargetPolicy,
            cleanupKind = SiteDeployerPostTransactionCleanupKind.RETAINED_BACKUP_AFTER_COMMIT,
            targetRoot = commitPlan.targetRoot,
            stagingRoot = commitPlan.stagingRoot,
            backupRoot = backup,
            cleanupRoot = backup,
            cleanupTree = previous,
            preservedTargetTree = commitPlan.sourceTree,
            preservedTargetMustBeAbsent = false,
            siblingRootThatMustRemainAbsent = commitPlan.stagingRoot,
            verifyBeforeCleanup = true,
            verifyAfterCleanup = true,
            postTransactionCleanupPlanSha256 = "",
        )
        return base.copy(postTransactionCleanupPlanSha256 = digest(base)).also {
            validateAgainstCommit(it, commitPlan)
        }
    }

    fun prepareStagingAfterRollback(
        commitPlan: SiteDeployerCommitTransactionPlan,
    ): SiteDeployerPostTransactionCleanupPlan {
        SiteDeployerCommitTransactionBoundary.validate(commitPlan)
        val previous = commitPlan.previousTargetTree
        val base = SiteDeployerPostTransactionCleanupPlan(
            contractVersion = CONTRACT_VERSION,
            commitTransactionPlanSha256 = commitPlan.commitTransactionPlanSha256,
            remoteHostIdentity = commitPlan.remoteHostIdentity,
            existingTargetPolicy = commitPlan.existingTargetPolicy,
            cleanupKind = SiteDeployerPostTransactionCleanupKind.STAGING_AFTER_ROLLBACK,
            targetRoot = commitPlan.targetRoot,
            stagingRoot = commitPlan.stagingRoot,
            backupRoot = commitPlan.backupRoot,
            cleanupRoot = commitPlan.stagingRoot,
            cleanupTree = commitPlan.sourceTree,
            preservedTargetTree = previous,
            preservedTargetMustBeAbsent = commitPlan.existingTargetPolicy == SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT,
            siblingRootThatMustRemainAbsent = commitPlan.backupRoot,
            verifyBeforeCleanup = true,
            verifyAfterCleanup = true,
            postTransactionCleanupPlanSha256 = "",
        )
        return base.copy(postTransactionCleanupPlanSha256 = digest(base)).also {
            validateAgainstCommit(it, commitPlan)
        }
    }

    fun validate(plan: SiteDeployerPostTransactionCleanupPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(plan.commitTransactionPlanSha256))
        require(sha256.matches(plan.postTransactionCleanupPlanSha256))
        require(plan.remoteHostIdentity.isNotBlank())
        val target = SiteRemoteDeployPolicy.prepareTargetRoot(plan.targetRoot)
        val staging = SiteRemoteDeployPolicy.prepareTargetRoot(plan.stagingRoot)
        require(target != staging)
        val cleanup = SiteRemoteDeployPolicy.prepareTargetRoot(plan.cleanupRoot)
        require(cleanup != target) { "Live target can never be a post-transaction cleanup root" }
        plan.backupRoot?.let {
            val backup = SiteRemoteDeployPolicy.prepareTargetRoot(it)
            require(backup != target && backup != staging)
        }
        require(plan.verifyBeforeCleanup && plan.verifyAfterCleanup)
        SiteDeployerCommitTransactionBoundary.validateExpectation(plan.cleanupTree)
        plan.preservedTargetTree?.let(SiteDeployerCommitTransactionBoundary::validateExpectation)

        when (plan.cleanupKind) {
            SiteDeployerPostTransactionCleanupKind.RETAINED_BACKUP_AFTER_COMMIT -> {
                require(plan.existingTargetPolicy == SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE)
                require(plan.backupRoot != null && cleanup == plan.backupRoot)
                require(plan.cleanupRoot != plan.stagingRoot)
                require(plan.preservedTargetTree != null && !plan.preservedTargetMustBeAbsent)
                require(plan.siblingRootThatMustRemainAbsent == plan.stagingRoot)
            }
            SiteDeployerPostTransactionCleanupKind.STAGING_AFTER_ROLLBACK -> {
                require(cleanup == plan.stagingRoot)
                require(plan.siblingRootThatMustRemainAbsent == plan.backupRoot)
                when (plan.existingTargetPolicy) {
                    SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> {
                        require(plan.backupRoot == null)
                        require(plan.preservedTargetTree == null && plan.preservedTargetMustBeAbsent)
                    }
                    SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> {
                        require(plan.backupRoot != null)
                        require(plan.preservedTargetTree != null && !plan.preservedTargetMustBeAbsent)
                    }
                }
            }
        }
        require(plan.postTransactionCleanupPlanSha256 == digest(plan.copy(postTransactionCleanupPlanSha256 = "")))
    }

    fun validateAgainstCommit(
        plan: SiteDeployerPostTransactionCleanupPlan,
        commitPlan: SiteDeployerCommitTransactionPlan,
    ) {
        validate(plan)
        SiteDeployerCommitTransactionBoundary.validate(commitPlan)
        require(plan.commitTransactionPlanSha256 == commitPlan.commitTransactionPlanSha256)
        require(plan.remoteHostIdentity == commitPlan.remoteHostIdentity)
        require(plan.existingTargetPolicy == commitPlan.existingTargetPolicy)
        require(plan.targetRoot == commitPlan.targetRoot)
        require(plan.stagingRoot == commitPlan.stagingRoot)
        require(plan.backupRoot == commitPlan.backupRoot)
        when (plan.cleanupKind) {
            SiteDeployerPostTransactionCleanupKind.RETAINED_BACKUP_AFTER_COMMIT -> {
                require(plan.cleanupRoot == commitPlan.backupRoot)
                require(plan.cleanupTree == commitPlan.previousTargetTree)
                require(plan.preservedTargetTree == commitPlan.sourceTree)
            }
            SiteDeployerPostTransactionCleanupKind.STAGING_AFTER_ROLLBACK -> {
                require(plan.cleanupRoot == commitPlan.stagingRoot)
                require(plan.cleanupTree == commitPlan.sourceTree)
                require(plan.preservedTargetTree == commitPlan.previousTargetTree)
            }
        }
    }

    private fun digest(plan: SiteDeployerPostTransactionCleanupPlan): String = SiteBundleDigest.sha256(buildString {
        append("contractVersion=").append(plan.contractVersion).append('\n')
        append("commitPlan=").append(plan.commitTransactionPlanSha256).append('\n')
        append("host=").append(plan.remoteHostIdentity).append('\n')
        append("policy=").append(plan.existingTargetPolicy.name).append('\n')
        append("kind=").append(plan.cleanupKind.name).append('\n')
        append("target=").append(plan.targetRoot).append('\n')
        append("staging=").append(plan.stagingRoot).append('\n')
        append("backup=").append(plan.backupRoot ?: "").append('\n')
        append("cleanup=").append(plan.cleanupRoot).append('\n')
        append("preservedTargetMustBeAbsent=").append(plan.preservedTargetMustBeAbsent).append('\n')
        append("siblingAbsent=").append(plan.siblingRootThatMustRemainAbsent ?: "").append('\n')
        append("verifyBefore=").append(plan.verifyBeforeCleanup).append('\n')
        append("verifyAfter=").append(plan.verifyAfterCleanup).append('\n')
        appendExpectation("cleanup", plan.cleanupTree)
        plan.preservedTargetTree?.let { appendExpectation("target", it) }
    }.encodeToByteArray())

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
