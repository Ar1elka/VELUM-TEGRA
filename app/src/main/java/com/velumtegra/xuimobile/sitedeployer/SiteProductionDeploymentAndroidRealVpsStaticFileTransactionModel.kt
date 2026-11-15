package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteDeployerCommitTransactionPlan
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteDeployerPostTransactionCleanupPlan
import com.velumtegra.xuimobile.core.site.SiteDeployerRemoteTreeExpectation
import com.velumtegra.xuimobile.core.site.SiteDeployerStagingWritePlan
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpCommitFailureInjection

enum class SiteProductionDeploymentRealVpsStaticFileTransactionStep {
    STAGING_WRITE,
    COMMIT_TRANSACTION,
    POST_TRANSACTION_CLEANUP,
}

data class SiteProductionDeploymentRealVpsExecutionCredential(
    val proof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
    val lease: SiteProductionDeploymentEphemeralCredentialLease,
    val executionAttemptId: String,
    val executedAtEpochMillis: Long,
)

interface SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider {
    suspend fun acquire(
        step: SiteProductionDeploymentRealVpsStaticFileTransactionStep,
    ): SiteProductionDeploymentRealVpsExecutionCredential
}

data class SiteProductionDeploymentRealVpsStaticFileTransactionRequest(
    val preparation: SiteDeployerLocalPreparationResult,
    val serverAccess: ServerAccess,
    val previousTargetTree: SiteDeployerRemoteTreeExpectation? = null,
    val failureInjection: SiteRemoteSftpCommitFailureInjection = SiteRemoteSftpCommitFailureInjection.NONE,
)

enum class SiteProductionDeploymentRealVpsStaticFileTransactionOutcome {
    COMMITTED_CLEAN,
    ROLLED_BACK_CLEAN,
}

data class SiteProductionDeploymentRealVpsStaticFileTransactionResult(
    val outcome: SiteProductionDeploymentRealVpsStaticFileTransactionOutcome,
    val preparationSha256: String,
    val stagingPlan: SiteDeployerStagingWritePlan,
    val stagingProof: SiteProductionDeploymentRealVpsStagingWriteExecutionProof,
    val commitPlan: SiteDeployerCommitTransactionPlan,
    val commitProof: SiteProductionDeploymentRealVpsCommitTransactionExecutionProof,
    val cleanupPlan: SiteDeployerPostTransactionCleanupPlan?,
    val cleanupProof: SiteProductionDeploymentRealVpsPostTransactionCleanupExecutionProof?,
    val finalTargetTreeSha256: String?,
    val remoteResidualStateClean: Boolean,
    val automaticRetryPerformed: Boolean,
    val coordinatorInvoked: Boolean,
    val exposesDeployUiAction: Boolean,
)
