package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionPort
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import java.security.MessageDigest

/**
 * Phase 11.43 durable consume-once boundary for one exact Phase 11.42 real-VPS
 * SSH-session-acquisition authorization.
 *
 * The only side effect is creation of one app-private replay-fence marker in the dedicated real-VPS
 * SSH-session-acquisition handoff namespace. This boundary does not receive or read credential lease
 * material, does not touch production network, does not verify a live remote host key, does not
 * invoke JSch/ExactSessionRegistry, does not open SSH/SFTP, and does not perform any remote action.
 */
internal object SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionHandoffConsumptionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")

    fun consume(
        authorization: SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization,
        consumedAtEpochMillis: Long,
        consumptionPort: SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionPort,
    ): SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionReceipt {
        SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionAuthorizationBoundary
            .validateAuthorization(authorization)
        require(authorization.authorizesSingleSshSessionAcquisitionHandoff) {
            "Real-VPS SSH-session-acquisition authorization does not authorize one handoff"
        }
        require(!authorization.authorizesNetworkAccess) {
            "Phase 11.42 must not authorize production network access"
        }
        require(!authorization.authorizesSshSessionAcquisition) {
            "Phase 11.42 must not authorize actual SSH-session acquisition"
        }
        require(authorization.requiresDurableOneShotConsumptionBeforeSshSessionAcquisition) {
            "Real-VPS SSH-session-acquisition handoff must require durable one-shot consumption"
        }
        require(authorization.requiresLiveRemoteHostKeyVerification) {
            "Live remote host-key verification must remain mandatory"
        }
        require(authorization.requiresSeparateSshSessionAcquisitionExecutionBoundary) {
            "Actual SSH-session acquisition must remain a separate boundary"
        }
        require(consumedAtEpochMillis >= authorization.evaluatedAtEpochMillis) {
            "Real-VPS SSH-session-acquisition handoff cannot be consumed before authorization evaluation"
        }
        require(consumedAtEpochMillis <= authorization.authorizationExpiresAtEpochMillis) {
            "Real-VPS SSH-session-acquisition authorization expired before durable consumption"
        }
        require(consumptionPort.consumeOnce(authorization.authorizationSha256)) {
            "Real-VPS SSH-session-acquisition handoff was already consumed or replay fence failed closed"
        }

        val base = SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionReceipt(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_REAL_VPS_SSH_SESSION_ACQUISITION_EXECUTION_BOUNDARY,
            singleUseConsumed = true,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemote = false,
            authorizesNetworkAccess = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresLiveRemoteHostKeyVerification = true,
            requiresSeparateSshSessionAcquisitionExecutionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            authorizationAttemptId = authorization.authorizationAttemptId,
            authorizationSha256 = authorization.authorizationSha256,
            resolutionProofSha256 = authorization.resolutionProofSha256,
            credentialResolutionConsumptionReceiptSha256 =
                authorization.credentialResolutionConsumptionReceiptSha256,
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
            credentialStoreImplementation = authorization.credentialStoreImplementation,
            sshConnectionFactoryImplementation = authorization.sshConnectionFactoryImplementation,
            exactSessionRegistryImplementation = authorization.exactSessionRegistryImplementation,
            consumedAtEpochMillis = consumedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorization.authorizationExpiresAtEpochMillis,
            sshSessionAcquisitionConsumptionReceiptSha256 = "",
        )
        return base.copy(
            sshSessionAcquisitionConsumptionReceiptSha256 = receiptSha256(base),
        ).also(::validateReceipt)
    }

    fun validateReceipt(
        receipt: SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionReceipt,
    ) {
        require(receipt.contractVersion == CONTRACT_VERSION)
        require(
            receipt.status ==
                SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionStatus
                    .DURABLY_CONSUMED_AWAITING_SEPARATE_REAL_VPS_SSH_SESSION_ACQUISITION_EXECUTION_BOUNDARY,
        )
        require(receipt.singleUseConsumed)
        require(!receipt.credentialLeaseMaterialRead)
        require(!receipt.productionNetworkTouched)
        require(!receipt.hostKeyPinVerifiedAgainstRemote)
        require(!receipt.authorizesNetworkAccess)
        require(!receipt.authorizesSshSessionAcquisition)
        require(!receipt.authorizesSftpChannelOpen)
        require(!receipt.authorizesReadOnlyPreflightExecution)
        require(!receipt.authorizesMutation)
        require(!receipt.authorizesCoordinatorInvocation)
        require(!receipt.exposesDeployUiAction)
        require(!receipt.realVpsAccessAllowed)
        require(receipt.requiresLiveRemoteHostKeyVerification)
        require(receipt.requiresSeparateSshSessionAcquisitionExecutionBoundary)
        require(receipt.requiresSeparateSftpChannelOpenBoundary)
        require(receipt.requiresSeparateReadOnlyExecutionBoundary)
        require(receipt.requiresSeparateMutationBoundary)
        require(receipt.consumedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis)
        require(receipt.remoteHostIdentity.isNotBlank())
        require(receipt.remotePort in 1..65535)
        require(receipt.username.isNotBlank())
        require(receipt.secretReferenceType == "password" || receipt.secretReferenceType == "private-key")
        require(receipt.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        require(receipt.sshConnectionFactoryImplementation == JschSshConnectionFactory::class.java.name)
        require(receipt.exactSessionRegistryImplementation == ExactSessionRegistry::class.java.name)
        validateHashes(
            receipt.authorizationSha256,
            receipt.resolutionProofSha256,
            receipt.credentialResolutionConsumptionReceiptSha256,
            receipt.serverAccessBindingSha256,
            receipt.requestSha256,
            receipt.capabilityProfileSha256,
            receipt.pinnedHostKeySha256,
            receipt.secretReferenceSha256,
            receipt.sshSessionAcquisitionConsumptionReceiptSha256,
        )
        require(
            receipt.sshSessionAcquisitionConsumptionReceiptSha256 ==
                receiptSha256(receipt.copy(sshSessionAcquisitionConsumptionReceiptSha256 = "")),
        ) { "Real-VPS SSH-session-acquisition handoff receipt SHA-256 mismatch" }
    }

    private fun receiptSha256(
        receipt: SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionReceipt,
    ): String = sha256(
        buildString {
            append("phase=11.43\n")
            append("contractVersion=").append(receipt.contractVersion).append('\n')
            append("status=").append(receipt.status.name).append('\n')
            append("singleUseConsumed=").append(receipt.singleUseConsumed).append('\n')
            append("credentialLeaseMaterialRead=").append(receipt.credentialLeaseMaterialRead).append('\n')
            append("productionNetworkTouched=").append(receipt.productionNetworkTouched).append('\n')
            append("hostKeyPinVerifiedAgainstRemote=").append(receipt.hostKeyPinVerifiedAgainstRemote).append('\n')
            append("authorizesNetworkAccess=").append(receipt.authorizesNetworkAccess).append('\n')
            append("authorizesSshSessionAcquisition=").append(receipt.authorizesSshSessionAcquisition).append('\n')
            append("authorizesSftpChannelOpen=").append(receipt.authorizesSftpChannelOpen).append('\n')
            append("authorizesReadOnlyPreflightExecution=").append(receipt.authorizesReadOnlyPreflightExecution).append('\n')
            append("authorizesMutation=").append(receipt.authorizesMutation).append('\n')
            append("authorizesCoordinatorInvocation=").append(receipt.authorizesCoordinatorInvocation).append('\n')
            append("exposesDeployUiAction=").append(receipt.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(receipt.realVpsAccessAllowed).append('\n')
            append("requiresLiveRemoteHostKeyVerification=")
                .append(receipt.requiresLiveRemoteHostKeyVerification).append('\n')
            append("requiresSeparateSshSessionAcquisitionExecutionBoundary=")
                .append(receipt.requiresSeparateSshSessionAcquisitionExecutionBoundary).append('\n')
            append("requiresSeparateSftpChannelOpenBoundary=")
                .append(receipt.requiresSeparateSftpChannelOpenBoundary).append('\n')
            append("requiresSeparateReadOnlyExecutionBoundary=")
                .append(receipt.requiresSeparateReadOnlyExecutionBoundary).append('\n')
            append("requiresSeparateMutationBoundary=")
                .append(receipt.requiresSeparateMutationBoundary).append('\n')
            append("authorizationAttemptId=").append(receipt.authorizationAttemptId).append('\n')
            append("authorizationSha256=").append(receipt.authorizationSha256).append('\n')
            append("resolutionProofSha256=").append(receipt.resolutionProofSha256).append('\n')
            append("credentialResolutionConsumptionReceiptSha256=")
                .append(receipt.credentialResolutionConsumptionReceiptSha256).append('\n')
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
            append("credentialStoreImplementation=").append(receipt.credentialStoreImplementation).append('\n')
            append("sshConnectionFactoryImplementation=")
                .append(receipt.sshConnectionFactoryImplementation).append('\n')
            append("exactSessionRegistryImplementation=")
                .append(receipt.exactSessionRegistryImplementation).append('\n')
            append("consumedAtEpochMillis=").append(receipt.consumedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=")
                .append(receipt.authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS SSH-session-acquisition handoff hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
