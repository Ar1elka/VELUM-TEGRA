package com.velumtegra.xuimobile.core.site

enum class SiteProductionDeploymentReplayScope(
    internal val directoryName: String,
) {
    RUNTIME_MUTATION_PERMIT("runtime-mutation-permit"),
    COORDINATOR_INVOCATION_AUTHORIZATION("coordinator-invocation-authorization"),
    TRANSPORT_ACQUISITION_HANDOFF_AUTHORIZATION("transport-acquisition-handoff-authorization"),
    CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION("credential-resolution-handoff-authorization"),
    CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT("credential-resolution-execution-receipt"),
    SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION("ssh-session-acquisition-handoff-authorization"),
    SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION("sftp-channel-open-handoff-authorization"),
    SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION("sftp-read-only-preflight-handoff-authorization"),
    REAL_VPS_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION("real-vps-read-only-preflight-handoff-authorization"),
    REAL_VPS_CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION("real-vps-credential-resolution-handoff-authorization"),
    REAL_VPS_CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT("real-vps-credential-resolution-execution-receipt"),
    REAL_VPS_SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION("real-vps-ssh-session-acquisition-handoff-authorization"),
    REAL_VPS_SSH_SESSION_ACQUISITION_EXECUTION_RECEIPT("real-vps-ssh-session-acquisition-execution-receipt"),
    REAL_VPS_SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION("real-vps-sftp-channel-open-handoff-authorization"),
    REAL_VPS_SFTP_CHANNEL_OPEN_EXECUTION_RECEIPT("real-vps-sftp-channel-open-execution-receipt"),
    REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION("real-vps-sftp-read-only-preflight-handoff-authorization"),
    REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_EXECUTION_RECEIPT("real-vps-sftp-read-only-preflight-execution-receipt"),
    REAL_VPS_STAGING_WRITE_EXECUTION_RECEIPT("real-vps-staging-write-execution-receipt"),
    REAL_VPS_COMMIT_TRANSACTION_EXECUTION_RECEIPT("real-vps-commit-transaction-execution-receipt"),
    REAL_VPS_POST_TRANSACTION_CLEANUP_EXECUTION_RECEIPT("real-vps-post-transaction-cleanup-execution-receipt"),
    REAL_VPS_WEB_SERVING_CONFIG_STAGING_SYNTAX_EXECUTION_RECEIPT("real-vps-web-serving-config-staging-syntax-execution-receipt"),
    REAL_VPS_WEB_SERVING_RUNTIME_PROVISIONING_EXECUTION_RECEIPT("real-vps-web-serving-runtime-provisioning-execution-receipt"),
    REAL_VPS_WEB_SERVING_CONFIG_ACTIVATION_EXECUTION_RECEIPT("real-vps-web-serving-config-activation-execution-receipt"),
    REAL_VPS_WEB_SERVING_NGINX_RELOAD_EXECUTION_RECEIPT("real-vps-web-serving-nginx-reload-execution-receipt"),
}

data class SiteProductionDeploymentReplayFenceSnapshot(
    val contractVersion: Int,
    val canonicalRootPath: String,
    val runtimeMutationPermitMarkerCount: Int,
    val coordinatorInvocationAuthorizationMarkerCount: Int,
    val transportAcquisitionHandoffAuthorizationMarkerCount: Int,
    val credentialResolutionHandoffAuthorizationMarkerCount: Int,
    val credentialResolutionExecutionReceiptMarkerCount: Int,
    val sshSessionAcquisitionHandoffAuthorizationMarkerCount: Int,
    val sftpChannelOpenHandoffAuthorizationMarkerCount: Int,
    val sftpReadOnlyPreflightHandoffAuthorizationMarkerCount: Int,
    val realVpsReadOnlyPreflightHandoffAuthorizationMarkerCount: Int,
    val realVpsCredentialResolutionHandoffAuthorizationMarkerCount: Int,
    val realVpsCredentialResolutionExecutionReceiptMarkerCount: Int,
    val realVpsSshSessionAcquisitionHandoffAuthorizationMarkerCount: Int,
    val realVpsSshSessionAcquisitionExecutionReceiptMarkerCount: Int,
    val realVpsSftpChannelOpenHandoffAuthorizationMarkerCount: Int,
    val realVpsSftpChannelOpenExecutionReceiptMarkerCount: Int,
    val realVpsSftpReadOnlyPreflightHandoffAuthorizationMarkerCount: Int,
    val realVpsSftpReadOnlyPreflightExecutionReceiptMarkerCount: Int,
    val realVpsStagingWriteExecutionReceiptMarkerCount: Int,
    val realVpsCommitTransactionExecutionReceiptMarkerCount: Int,
    val realVpsPostTransactionCleanupExecutionReceiptMarkerCount: Int,
    val realVpsWebServingConfigStagingSyntaxExecutionReceiptMarkerCount: Int,
    val realVpsWebServingRuntimeProvisioningExecutionReceiptMarkerCount: Int,
    val realVpsWebServingConfigActivationExecutionReceiptMarkerCount: Int,
    val realVpsWebServingNginxReloadExecutionReceiptMarkerCount: Int,
)


fun interface SiteProductionDeploymentTransportAcquisitionHandoffConsumptionPort {
    /**
     * Atomically records the first durable handoff consumption of [authorizationSha256].
     * False means the handoff was already consumed or the replay fence cannot safely prove first use.
     */
    fun consumeOnce(authorizationSha256: String): Boolean
}


fun interface SiteProductionDeploymentCredentialResolutionHandoffConsumptionPort {
    /**
     * Atomically records the first durable handoff consumption of [authorizationSha256].
     * False means the handoff was already consumed or the replay fence cannot safely prove first use.
     */
    fun consumeOnce(authorizationSha256: String): Boolean
}


fun interface SiteProductionDeploymentCredentialResolutionExecutionUsePort {
    /**
     * Atomically records the first execution attempt for one exact Phase 11.29 durable receipt.
     * False means resolution was already attempted or durable first-use proof cannot be established.
     */
    fun consumeOnce(credentialResolutionConsumptionReceiptSha256: String): Boolean
}


fun interface SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionPort {
    /**
     * Atomically records the first durable handoff consumption of one exact Phase 11.31
     * SSH-session-acquisition authorization SHA-256. False means it was already consumed or
     * durable first-use proof cannot be established safely.
     */
    fun consumeOnce(authorizationSha256: String): Boolean
}


fun interface SiteProductionDeploymentSftpChannelOpenHandoffConsumptionPort {
    /** Atomically consumes one exact approved SFTP channel-open authorization. */
    fun consumeOnce(authorizationSha256: String): Boolean
}


fun interface SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionPort {
    /** Atomically consumes one exact approved read-only SFTP preflight authorization. */
    fun consumeOnce(authorizationSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionPort {
    /**
     * Atomically consumes one exact explicitly approved Phase 11.37 real-VPS read-only preflight
     * authorization. False means it was already consumed or durable first-use proof failed closed.
     */
    fun consumeOnce(authorizationSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionPort {
    /**
     * Atomically consumes one exact explicitly approved Phase 11.39 real-VPS credential-resolution
     * authorization. False means it was already consumed or durable first-use proof failed closed.
     */
    fun consumeOnce(authorizationSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsCredentialResolutionExecutionUsePort {
    /**
     * Atomically records the first execution attempt for one exact Phase 11.40 durable real-VPS
     * credential-resolution receipt. False means execution was already attempted or durable
     * first-use proof cannot be established safely.
     */
    fun consumeOnce(credentialResolutionConsumptionReceiptSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionPort {
    /**
     * Atomically consumes one exact explicitly approved Phase 11.42 real-VPS SSH-session-acquisition
     * authorization. False means it was already consumed or durable first-use proof failed closed.
     */
    fun consumeOnce(authorizationSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionUsePort {
    /**
     * Atomically records the first real-network execution attempt for one exact Phase 11.43 durable
     * SSH-session-acquisition receipt. False means the execution was already attempted or durable
     * first-use proof cannot be established safely.
     */
    fun consumeOnce(sshSessionAcquisitionConsumptionReceiptSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionPort {
    /**
     * Atomically consumes one exact explicitly approved Phase 11.45 real-VPS SFTP channel-open
     * authorization. False means it was already consumed or durable first-use proof failed closed.
     */
    fun consumeOnce(authorizationSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsSftpChannelOpenExecutionUsePort {
    /**
     * Atomically records the first real-network SFTP channel-open execution attempt for one exact
     * Phase 11.46 durable receipt. False means execution was already attempted or durable first-use
     * proof cannot be established safely.
     */
    fun consumeOnce(sftpChannelOpenConsumptionReceiptSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionPort {
    /**
     * Atomically consumes one exact explicitly approved Phase 11.48 real-VPS bounded SFTP
     * read-only preflight authorization. False means it was already consumed or durable first-use
     * proof failed closed.
     */
    fun consumeOnce(authorizationSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionUsePort {
    /**
     * Atomically records the first real-network bounded read-only SFTP preflight execution attempt
     * for one exact Phase 11.49 durable receipt. False means execution was already attempted or
     * durable first-use proof cannot be established safely.
     */
    fun consumeOnce(readOnlyPreflightConsumptionReceiptSha256: String): Boolean
}

fun interface SiteProductionDeploymentRealVpsStagingWriteExecutionUsePort {
    /**
     * Atomically records the first real-network staging-write execution attempt for one exact
     * Phase 11.51 preparation/staging plan. False means the attempt was already made or durable
     * first-use proof cannot be established safely.
     */
    fun consumeOnce(stagingWritePlanSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsCommitTransactionExecutionUsePort {
    /** Atomically burns one exact Phase 11.53 commit/rollback transaction before network mutation. */
    fun consumeOnce(commitTransactionPlanSha256: String): Boolean
}

fun interface SiteProductionDeploymentRealVpsPostTransactionCleanupExecutionUsePort {
    /** Atomically burns one exact Phase 11.54 residual cleanup plan before destructive deletion. */
    fun consumeOnce(postTransactionCleanupPlanSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionUsePort {
    /**
     * Durably records the exact Phase 11.59 execution plan before its first remote write. False
     * means the plan was already attempted or the durable baseline checkpoint cannot be proven.
     */
    fun consumeOnce(executionPlanSha256: String): Boolean
}

fun interface SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionUsePort {
    /**
     * Durably burns one exact Phase 11.59B nginx provisioning plan immediately before the first
     * apt mutation. False means the plan was already attempted or first-use proof failed closed.
     */
    fun consumeOnce(provisioningPlanSha256: String): Boolean
}


fun interface SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionUsePort {
    /** Durably burns one exact Phase 11.60 activation plan immediately before its first write. */
    fun consumeOnce(activationPlanSha256: String): Boolean
}

fun interface SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionUsePort {
    /** Durably burns one exact Phase 11.61 reload plan immediately before the one nginx reload. */
    fun consumeOnce(reloadPlanSha256: String): Boolean
}
