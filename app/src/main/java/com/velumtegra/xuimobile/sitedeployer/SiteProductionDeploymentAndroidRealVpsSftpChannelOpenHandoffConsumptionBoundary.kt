package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionPort
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpChannelLifecycleProbe
import java.security.MessageDigest

/**
 * Phase 11.46 durable consume-once boundary for one exact Phase 11.45 real-VPS SFTP channel-open
 * authorization.
 *
 * Marker creation in the dedicated app-private real-VPS SFTP handoff namespace is the only side
 * effect. This boundary does not receive credential material, does not touch production network,
 * does not acquire SSH, does not open SFTP, and does not perform any remote command/read/mutation.
 * A later execution boundary must obtain a fresh credential lease and a fresh SSH session with live
 * host-key verification before one SFTP channel may be opened.
 */
internal object SiteProductionDeploymentAndroidRealVpsSftpChannelOpenHandoffConsumptionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")

    fun consume(
        authorization: SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization,
        consumedAtEpochMillis: Long,
        consumptionPort: SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionPort,
    ): SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionReceipt {
        SiteProductionDeploymentAndroidRealVpsSftpChannelOpenAuthorizationBoundary
            .validateAuthorization(authorization)
        require(authorization.authorizesSingleSftpChannelOpenHandoff) {
            "Real-VPS SFTP channel-open authorization does not authorize one durable handoff"
        }
        require(!authorization.authorizesNetworkAccess)
        require(!authorization.authorizesSftpChannelOpen)
        require(!authorization.authorizesReadOnlyPreflightExecution)
        require(!authorization.authorizesMutation)
        require(authorization.requiresDurableOneShotConsumptionBeforeSftpChannelOpen) {
            "Real-VPS SFTP channel-open handoff must be durably consumed before execution"
        }
        require(authorization.requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution) {
            "Fresh credential resolution must remain mandatory before SFTP execution"
        }
        require(authorization.requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution) {
            "Fresh SSH acquisition must remain mandatory before SFTP execution"
        }
        require(authorization.requiresSeparateSftpChannelOpenExecutionBoundary) {
            "Actual real-VPS SFTP channel open must remain a separate execution boundary"
        }
        require(consumedAtEpochMillis >= authorization.evaluatedAtEpochMillis) {
            "Real-VPS SFTP channel-open handoff cannot be consumed before authorization evaluation"
        }
        require(consumedAtEpochMillis <= authorization.authorizationExpiresAtEpochMillis) {
            "Real-VPS SFTP channel-open authorization expired before durable consumption"
        }
        require(consumptionPort.consumeOnce(authorization.authorizationSha256)) {
            "Real-VPS SFTP channel-open handoff was already consumed or replay fence failed closed"
        }

        val base = SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionReceipt(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_FRESH_CREDENTIAL_SSH_AND_SEPARATE_SFTP_EXECUTION_BOUNDARY,
            singleUseConsumed = true,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemoteByPriorProof = true,
            authorizesNetworkAccess = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution = true,
            requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution = true,
            requiresFreshLiveRemoteHostKeyVerificationBeforeSftpChannelOpenExecution = true,
            requiresSeparateSftpChannelOpenExecutionBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            authorizationAttemptId = authorization.authorizationAttemptId,
            authorizationSha256 = authorization.authorizationSha256,
            priorSshExecutionProofSha256 = authorization.priorSshExecutionProofSha256,
            priorSshExecutionReceiptSha256 = authorization.priorSshExecutionReceiptSha256,
            serverAccessBindingSha256 = authorization.serverAccessBindingSha256,
            requestSha256 = authorization.requestSha256,
            capabilityProfileSha256 = authorization.capabilityProfileSha256,
            serverAccessId = authorization.serverAccessId,
            remoteHostIdentity = authorization.remoteHostIdentity,
            remotePort = authorization.remotePort,
            username = authorization.username,
            pinnedHostKeySha256 = authorization.pinnedHostKeySha256,
            secretReferenceType = authorization.secretReferenceType,
            secretReferenceSha256 = authorization.secretReferenceSha256,
            sshConnectionFactoryImplementation = authorization.sshConnectionFactoryImplementation,
            exactSessionRegistryImplementation = authorization.exactSessionRegistryImplementation,
            sftpLifecycleProbeImplementation = authorization.sftpLifecycleProbeImplementation,
            consumedAtEpochMillis = consumedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorization.authorizationExpiresAtEpochMillis,
            sftpChannelOpenConsumptionReceiptSha256 = "",
        )
        return base.copy(
            sftpChannelOpenConsumptionReceiptSha256 = receiptSha256(base),
        ).also(::validateReceipt)
    }

    fun validateReceipt(
        receipt: SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionReceipt,
    ) {
        require(receipt.contractVersion == CONTRACT_VERSION)
        require(
            receipt.status ==
                SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionStatus
                    .DURABLY_CONSUMED_AWAITING_FRESH_CREDENTIAL_SSH_AND_SEPARATE_SFTP_EXECUTION_BOUNDARY,
        )
        require(receipt.singleUseConsumed)
        require(!receipt.credentialLeaseMaterialRead)
        require(!receipt.productionNetworkTouched)
        require(receipt.hostKeyPinVerifiedAgainstRemoteByPriorProof)
        require(!receipt.authorizesNetworkAccess)
        require(!receipt.authorizesCredentialResolution)
        require(!receipt.authorizesSshSessionAcquisition)
        require(!receipt.authorizesSftpChannelOpen)
        require(!receipt.authorizesReadOnlyPreflightExecution)
        require(!receipt.authorizesMutation)
        require(!receipt.authorizesCoordinatorInvocation)
        require(!receipt.exposesDeployUiAction)
        require(!receipt.realVpsAccessAllowed)
        require(receipt.requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution)
        require(receipt.requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution)
        require(receipt.requiresFreshLiveRemoteHostKeyVerificationBeforeSftpChannelOpenExecution)
        require(receipt.requiresSeparateSftpChannelOpenExecutionBoundary)
        require(receipt.requiresSeparateReadOnlyExecutionBoundary)
        require(receipt.requiresSeparateMutationBoundary)
        require(receipt.remoteHostIdentity.isNotBlank())
        require(receipt.remotePort in 1..65535)
        require(receipt.username.isNotBlank())
        require(receipt.secretReferenceType == "password" || receipt.secretReferenceType == "private-key")
        require(receipt.consumedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis)
        require(receipt.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(receipt.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        require(receipt.sftpLifecycleProbeImplementation == SiteRemoteSftpChannelLifecycleProbe::class.java.name)
        validateHashes(
            receipt.authorizationSha256,
            receipt.priorSshExecutionProofSha256,
            receipt.priorSshExecutionReceiptSha256,
            receipt.serverAccessBindingSha256,
            receipt.requestSha256,
            receipt.capabilityProfileSha256,
            receipt.pinnedHostKeySha256,
            receipt.secretReferenceSha256,
            receipt.sftpChannelOpenConsumptionReceiptSha256,
        )
        require(
            receipt.sftpChannelOpenConsumptionReceiptSha256 ==
                receiptSha256(receipt.copy(sftpChannelOpenConsumptionReceiptSha256 = "")),
        ) { "Real-VPS SFTP channel-open handoff receipt SHA-256 mismatch" }
    }

    private fun receiptSha256(
        receipt: SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionReceipt,
    ): String = sha256(
        buildString {
            append("phase=11.46\n")
            append("contractVersion=").append(receipt.contractVersion).append('\n')
            append("status=").append(receipt.status.name).append('\n')
            append("singleUseConsumed=").append(receipt.singleUseConsumed).append('\n')
            append("credentialLeaseMaterialRead=").append(receipt.credentialLeaseMaterialRead).append('\n')
            append("productionNetworkTouched=").append(receipt.productionNetworkTouched).append('\n')
            append("hostKeyPinVerifiedAgainstRemoteByPriorProof=")
                .append(receipt.hostKeyPinVerifiedAgainstRemoteByPriorProof).append('\n')
            append("authorizesNetworkAccess=").append(receipt.authorizesNetworkAccess).append('\n')
            append("authorizesCredentialResolution=").append(receipt.authorizesCredentialResolution).append('\n')
            append("authorizesSshSessionAcquisition=").append(receipt.authorizesSshSessionAcquisition).append('\n')
            append("authorizesSftpChannelOpen=").append(receipt.authorizesSftpChannelOpen).append('\n')
            append("authorizesReadOnlyPreflightExecution=")
                .append(receipt.authorizesReadOnlyPreflightExecution).append('\n')
            append("authorizesMutation=").append(receipt.authorizesMutation).append('\n')
            append("authorizesCoordinatorInvocation=").append(receipt.authorizesCoordinatorInvocation).append('\n')
            append("exposesDeployUiAction=").append(receipt.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(receipt.realVpsAccessAllowed).append('\n')
            append("requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution=")
                .append(receipt.requiresFreshCredentialResolutionBeforeSftpChannelOpenExecution).append('\n')
            append("requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution=")
                .append(receipt.requiresFreshSshSessionAcquisitionBeforeSftpChannelOpenExecution).append('\n')
            append("requiresFreshLiveRemoteHostKeyVerificationBeforeSftpChannelOpenExecution=")
                .append(receipt.requiresFreshLiveRemoteHostKeyVerificationBeforeSftpChannelOpenExecution).append('\n')
            append("requiresSeparateSftpChannelOpenExecutionBoundary=")
                .append(receipt.requiresSeparateSftpChannelOpenExecutionBoundary).append('\n')
            append("requiresSeparateReadOnlyExecutionBoundary=")
                .append(receipt.requiresSeparateReadOnlyExecutionBoundary).append('\n')
            append("requiresSeparateMutationBoundary=")
                .append(receipt.requiresSeparateMutationBoundary).append('\n')
            append("authorizationAttemptId=").append(receipt.authorizationAttemptId).append('\n')
            append("authorizationSha256=").append(receipt.authorizationSha256).append('\n')
            append("priorSshExecutionProofSha256=").append(receipt.priorSshExecutionProofSha256).append('\n')
            append("priorSshExecutionReceiptSha256=").append(receipt.priorSshExecutionReceiptSha256).append('\n')
            append("serverAccessBindingSha256=").append(receipt.serverAccessBindingSha256).append('\n')
            append("requestSha256=").append(receipt.requestSha256).append('\n')
            append("capabilityProfileSha256=").append(receipt.capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(receipt.serverAccessId).append('\n')
            append("remoteHostIdentity=").append(receipt.remoteHostIdentity).append('\n')
            append("remotePort=").append(receipt.remotePort).append('\n')
            append("username=").append(receipt.username).append('\n')
            append("pinnedHostKeySha256=").append(receipt.pinnedHostKeySha256).append('\n')
            append("secretReferenceType=").append(receipt.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(receipt.secretReferenceSha256).append('\n')
            append("sshConnectionFactoryImplementation=")
                .append(receipt.sshConnectionFactoryImplementation).append('\n')
            append("exactSessionRegistryImplementation=")
                .append(receipt.exactSessionRegistryImplementation).append('\n')
            append("sftpLifecycleProbeImplementation=")
                .append(receipt.sftpLifecycleProbeImplementation).append('\n')
            append("consumedAtEpochMillis=").append(receipt.consumedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=")
                .append(receipt.authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS SFTP channel-open handoff hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
