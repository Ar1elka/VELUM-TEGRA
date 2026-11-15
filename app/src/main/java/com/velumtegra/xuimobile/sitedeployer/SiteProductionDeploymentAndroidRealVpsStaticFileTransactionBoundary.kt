package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteDeployerCommitTransactionBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerPostTransactionCleanupBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerPostTransactionCleanupKind
import com.velumtegra.xuimobile.core.site.SiteDeployerStagingWriteBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentDurableReplayFence
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpCommitOutcome

/**
 * Phase 11.55 production-shaped static-file transaction composition.
 *
 * This boundary composes only the already accepted Phase 11.52/11.53/11.54 mutation primitives.
 * It does not add a new remote primitive, shell command, web-server mutation, certificate mutation,
 * coordinator invocation or Deploy UI action.
 *
 * The first staging receipt is the top-level replay fence: invoking this transaction again with the
 * same preparation fails before a second production write. Every step receives a separately resolved
 * one-shot credential lease just-in-time. There is no automatic retry. A proven commit rollback may
 * be followed by the exact Phase 11.54 staging cleanup as the explicit counteraction.
 */
internal object SiteProductionDeploymentAndroidRealVpsStaticFileTransactionBoundary {
    suspend fun executeOnce(
        request: SiteProductionDeploymentRealVpsStaticFileTransactionRequest,
        credentialProvider: SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider,
        replayFence: SiteProductionDeploymentDurableReplayFence,
    ): SiteProductionDeploymentRealVpsStaticFileTransactionResult {
        val preparation = request.preparation
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        require(preparation.remoteDeployPlan.remoteHostIdentity == request.serverAccess.endpoint.host) {
            "Static-file transaction host differs from the prepared deployment host"
        }

        val stagingPlan = SiteDeployerStagingWriteBoundary.prepare(preparation)
        val stagingCredential = credentialProvider.acquire(
            SiteProductionDeploymentRealVpsStaticFileTransactionStep.STAGING_WRITE,
        )
        val stagingProof = SiteProductionDeploymentAndroidRealVpsStagingWriteExecutionBoundary
            .stageVerifiedBundleOnce(
                preparation = preparation,
                stagingPlan = stagingPlan,
                freshResolutionProof = stagingCredential.proof,
                freshCredentialLease = stagingCredential.lease,
                serverAccess = request.serverAccess,
                executionAttemptId = stagingCredential.executionAttemptId,
                executedAtEpochMillis = stagingCredential.executedAtEpochMillis,
                executionUsePort = replayFence.realVpsStagingWriteExecutionUsePort(),
            )
        SiteProductionDeploymentAndroidRealVpsStagingWriteExecutionBoundary.validateProof(stagingProof)

        val commitPlan = SiteDeployerCommitTransactionBoundary.prepare(
            preparation = preparation,
            stagingPlan = stagingPlan,
            previousTargetTree = request.previousTargetTree,
        )
        val commitCredential = credentialProvider.acquire(
            SiteProductionDeploymentRealVpsStaticFileTransactionStep.COMMIT_TRANSACTION,
        )
        val commitProof = SiteProductionDeploymentAndroidRealVpsCommitTransactionExecutionBoundary
            .commitOrRollbackOnce(
                plan = commitPlan,
                stagingExecutionProof = stagingProof,
                freshResolutionProof = commitCredential.proof,
                freshCredentialLease = commitCredential.lease,
                serverAccess = request.serverAccess,
                executionAttemptId = commitCredential.executionAttemptId,
                executedAtEpochMillis = commitCredential.executedAtEpochMillis,
                failureInjection = request.failureInjection,
                executionUsePort = replayFence.realVpsCommitTransactionExecutionUsePort(),
            )
        SiteProductionDeploymentAndroidRealVpsCommitTransactionExecutionBoundary.validateProof(commitProof)

        val cleanupPlan = when (commitProof.outcome) {
            SiteRemoteSftpCommitOutcome.COMMITTED -> when (commitPlan.existingTargetPolicy) {
                SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> null
                SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE ->
                    SiteDeployerPostTransactionCleanupBoundary.prepareRetainedBackupAfterCommit(commitPlan)
            }
            SiteRemoteSftpCommitOutcome.ROLLED_BACK ->
                SiteDeployerPostTransactionCleanupBoundary.prepareStagingAfterRollback(commitPlan)
        }

        val cleanupProof = cleanupPlan?.let { plan ->
            val cleanupCredential = credentialProvider.acquire(
                SiteProductionDeploymentRealVpsStaticFileTransactionStep.POST_TRANSACTION_CLEANUP,
            )
            SiteProductionDeploymentAndroidRealVpsPostTransactionCleanupExecutionBoundary.cleanupOnce(
                plan = plan,
                commitPlan = commitPlan,
                commitExecutionProof = commitProof,
                freshResolutionProof = cleanupCredential.proof,
                freshCredentialLease = cleanupCredential.lease,
                serverAccess = request.serverAccess,
                executionAttemptId = cleanupCredential.executionAttemptId,
                executedAtEpochMillis = cleanupCredential.executedAtEpochMillis,
                executionUsePort = replayFence.realVpsPostTransactionCleanupExecutionUsePort(),
            ).also(SiteProductionDeploymentAndroidRealVpsPostTransactionCleanupExecutionBoundary::validateProof)
        }

        val outcome = when (commitProof.outcome) {
            SiteRemoteSftpCommitOutcome.COMMITTED -> SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.COMMITTED_CLEAN
            SiteRemoteSftpCommitOutcome.ROLLED_BACK -> SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.ROLLED_BACK_CLEAN
        }
        val expectedCleanupKind = when (commitProof.outcome) {
            SiteRemoteSftpCommitOutcome.COMMITTED -> if (commitPlan.existingTargetPolicy == SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE) {
                SiteDeployerPostTransactionCleanupKind.RETAINED_BACKUP_AFTER_COMMIT
            } else null
            SiteRemoteSftpCommitOutcome.ROLLED_BACK -> SiteDeployerPostTransactionCleanupKind.STAGING_AFTER_ROLLBACK
        }
        require(cleanupProof?.cleanupKind == expectedCleanupKind) {
            "Static-file transaction cleanup result does not match commit outcome"
        }
        require(cleanupProof == null || cleanupProof.cleanupRootAbsentAfterDelete) {
            "Static-file transaction did not prove residual cleanup"
        }
        require(cleanupProof == null || cleanupProof.preservedTargetVerifiedAfterDelete) {
            "Static-file transaction did not re-verify preserved target after cleanup"
        }

        val finalTargetTreeSha256 = when (commitProof.outcome) {
            SiteRemoteSftpCommitOutcome.COMMITTED -> commitPlan.sourceTree.treeSha256
            SiteRemoteSftpCommitOutcome.ROLLED_BACK -> commitPlan.previousTargetTree?.treeSha256
        }
        val result = SiteProductionDeploymentRealVpsStaticFileTransactionResult(
            outcome = outcome,
            preparationSha256 = preparation.preparationSha256,
            stagingPlan = stagingPlan,
            stagingProof = stagingProof,
            commitPlan = commitPlan,
            commitProof = commitProof,
            cleanupPlan = cleanupPlan,
            cleanupProof = cleanupProof,
            finalTargetTreeSha256 = finalTargetTreeSha256,
            remoteResidualStateClean = cleanupPlan == null || cleanupProof?.cleanupRootAbsentAfterDelete == true,
            automaticRetryPerformed = false,
            coordinatorInvoked = false,
            exposesDeployUiAction = false,
        )
        validateResult(result)
        return result
    }

    fun validateResult(result: SiteProductionDeploymentRealVpsStaticFileTransactionResult) {
        require(result.preparationSha256 == result.stagingPlan.preparationSha256)
        require(result.stagingPlan.stagingWritePlanSha256 == result.stagingProof.stagingWritePlanSha256)
        SiteProductionDeploymentAndroidRealVpsStagingWriteExecutionBoundary.validateProof(result.stagingProof)
        SiteDeployerCommitTransactionBoundary.validate(result.commitPlan)
        require(result.commitPlan.preparationSha256 == result.preparationSha256)
        require(result.commitPlan.stagingWritePlanSha256 == result.stagingPlan.stagingWritePlanSha256)
        require(result.commitProof.commitTransactionPlanSha256 == result.commitPlan.commitTransactionPlanSha256)
        SiteProductionDeploymentAndroidRealVpsCommitTransactionExecutionBoundary.validateProof(result.commitProof)
        result.cleanupPlan?.let { SiteDeployerPostTransactionCleanupBoundary.validateAgainstCommit(it, result.commitPlan) }
        result.cleanupProof?.let { SiteProductionDeploymentAndroidRealVpsPostTransactionCleanupExecutionBoundary.validateProof(it) }
        require((result.cleanupPlan == null) == (result.cleanupProof == null))
        require(result.remoteResidualStateClean)
        require(!result.automaticRetryPerformed)
        require(!result.coordinatorInvoked)
        require(!result.exposesDeployUiAction)

        when (result.outcome) {
            SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.COMMITTED_CLEAN -> {
                require(result.commitProof.outcome == SiteRemoteSftpCommitOutcome.COMMITTED)
                require(result.finalTargetTreeSha256 == result.commitPlan.sourceTree.treeSha256)
                when (result.commitPlan.existingTargetPolicy) {
                    SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> require(result.cleanupPlan == null)
                    SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> {
                        require(result.cleanupPlan?.cleanupKind == SiteDeployerPostTransactionCleanupKind.RETAINED_BACKUP_AFTER_COMMIT)
                        require(result.cleanupProof?.cleanupRootAbsentAfterDelete == true)
                        require(result.cleanupProof?.preservedTargetVerifiedAfterDelete == true)
                    }
                }
            }
            SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.ROLLED_BACK_CLEAN -> {
                require(result.commitProof.outcome == SiteRemoteSftpCommitOutcome.ROLLED_BACK)
                require(result.cleanupPlan?.cleanupKind == SiteDeployerPostTransactionCleanupKind.STAGING_AFTER_ROLLBACK)
                require(result.cleanupProof?.cleanupRootAbsentAfterDelete == true)
                require(result.cleanupProof?.preservedTargetVerifiedAfterDelete == true)
                require(result.finalTargetTreeSha256 == result.commitPlan.previousTargetTree?.treeSha256)
            }
        }
    }
}
