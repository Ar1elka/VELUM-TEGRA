package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionPort
import java.security.MessageDigest

/**
 * Phase 11.32 durable consume-once boundary for the exact Phase 11.31 SSH-session-acquisition handoff.
 *
 * It burns only the exact Phase 11.31 authorization SHA-256 into a dedicated app-private replay
 * namespace and emits a typed non-network receipt. It does not receive/read the ephemeral credential
 * lease, invoke JSch/ExactSessionRegistry, acquire SSH, open SFTP, invoke the coordinator, expose a
 * deploy action, or access a real VPS. Actual SSH acquisition remains a separate later boundary.
 */
internal object SiteProductionDeploymentAndroidSshSessionAcquisitionHandoffConsumptionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun consume(
        authorization: SiteProductionDeploymentSshSessionAcquisitionAuthorization,
        consumedAtEpochMillis: Long,
        consumptionPort: SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionPort,
    ): SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt {
        SiteProductionDeploymentAndroidSshSessionAcquisitionAuthorizationBoundary
            .validateAuthorization(authorization)
        require(authorization.authorizesSingleSshSessionAcquisitionHandoff) {
            "SSH-session acquisition authorization does not authorize a single handoff"
        }
        require(!authorization.authorizesSshSessionAcquisition) {
            "Phase 11.31 handoff authorization must not authorize actual SSH acquisition"
        }
        require(authorization.requiresDurableOneShotConsumptionBeforeSshSessionAcquisition) {
            "SSH-session acquisition handoff must require durable one-shot consumption"
        }
        require(authorization.requiresSeparateSshSessionAcquisitionExecutionBoundary) {
            "SSH-session acquisition execution must remain a separate boundary"
        }
        require(consumedAtEpochMillis >= authorization.evaluatedAtEpochMillis) {
            "SSH-session acquisition handoff cannot be consumed before authorization evaluation"
        }
        require(consumedAtEpochMillis <= authorization.authorizationExpiresAtEpochMillis) {
            "SSH-session acquisition handoff authorization expired before durable consumption"
        }

        require(consumptionPort.consumeOnce(authorization.authorizationSha256)) {
            "SSH-session acquisition handoff was already consumed or replay fence failed closed"
        }

        val base = SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_SSH_SESSION_ACQUISITION_EXECUTION_BOUNDARY,
            singleUseConsumed = true,
            credentialLeaseMaterialRead = false,
            productionTransportEnabled = false,
            authorizesTransport = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresSeparateSshSessionAcquisitionExecutionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            authorizationAttemptId = authorization.authorizationAttemptId,
            authorizationSha256 = authorization.authorizationSha256,
            resolutionProofSha256 = authorization.resolutionProofSha256,
            credentialResolutionConsumptionReceiptSha256 =
                authorization.credentialResolutionConsumptionReceiptSha256,
            serverIdentitySha256 = authorization.serverIdentitySha256,
            compositionDescriptorSha256 = authorization.compositionDescriptorSha256,
            serverAccessBindingSha256 = authorization.serverAccessBindingSha256,
            serverAccessId = authorization.serverAccessId,
            runtimeSessionId = authorization.runtimeSessionId,
            remoteHostIdentity = authorization.remoteHostIdentity,
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
        receipt: SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt,
    ) {
        require(receipt.contractVersion == CONTRACT_VERSION) {
            "Unsupported SSH-session acquisition handoff consumption contract"
        }
        require(
            receipt.status ==
                SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionStatus
                    .DURABLY_CONSUMED_AWAITING_SEPARATE_SSH_SESSION_ACQUISITION_EXECUTION_BOUNDARY,
        ) { "SSH-session acquisition handoff consumption receipt has invalid status" }
        require(receipt.singleUseConsumed) {
            "SSH-session acquisition receipt must prove durable one-shot consumption"
        }
        require(!receipt.credentialLeaseMaterialRead) {
            "SSH-session acquisition handoff consumption must not read credential lease material"
        }
        require(!receipt.productionTransportEnabled)
        require(!receipt.authorizesTransport)
        require(!receipt.authorizesSshSessionAcquisition)
        require(!receipt.authorizesSftpChannelOpen)
        require(!receipt.authorizesCoordinatorInvocation)
        require(!receipt.exposesDeployUiAction)
        require(!receipt.realVpsAccessAllowed)
        require(receipt.requiresSeparateSshSessionAcquisitionExecutionBoundary) {
            "A separate SSH-session acquisition execution boundary must remain mandatory"
        }
        require(receipt.requiresSeparateSftpChannelOpenBoundary) {
            "A separate SFTP-channel-open boundary must remain mandatory"
        }
        require(receipt.consumedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis) {
            "SSH-session acquisition handoff was consumed after authorization expiry"
        }
        require(receipt.secretReferenceType == "password" || receipt.secretReferenceType == "private-key") {
            "SSH-session acquisition receipt secret reference type is invalid"
        }
        validateHashes(
            receipt.authorizationSha256,
            receipt.resolutionProofSha256,
            receipt.credentialResolutionConsumptionReceiptSha256,
            receipt.serverIdentitySha256,
            receipt.compositionDescriptorSha256,
            receipt.serverAccessBindingSha256,
            receipt.secretReferenceSha256,
            receipt.sshSessionAcquisitionConsumptionReceiptSha256,
        )
        require(
            receipt.sshSessionAcquisitionConsumptionReceiptSha256 ==
                receiptSha256(receipt.copy(sshSessionAcquisitionConsumptionReceiptSha256 = "")),
        ) { "SSH-session acquisition handoff consumption receipt SHA-256 mismatch" }
    }

    private fun receiptSha256(
        receipt: SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt,
    ): String = sha256(
        buildString {
            append("contractVersion=").append(receipt.contractVersion).append('\n')
            append("status=").append(receipt.status.name).append('\n')
            append("singleUseConsumed=").append(receipt.singleUseConsumed).append('\n')
            append("credentialLeaseMaterialRead=").append(receipt.credentialLeaseMaterialRead).append('\n')
            append("productionTransportEnabled=").append(receipt.productionTransportEnabled).append('\n')
            append("authorizesTransport=").append(receipt.authorizesTransport).append('\n')
            append("authorizesSshSessionAcquisition=").append(receipt.authorizesSshSessionAcquisition).append('\n')
            append("authorizesSftpChannelOpen=").append(receipt.authorizesSftpChannelOpen).append('\n')
            append("authorizesCoordinatorInvocation=").append(receipt.authorizesCoordinatorInvocation).append('\n')
            append("exposesDeployUiAction=").append(receipt.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(receipt.realVpsAccessAllowed).append('\n')
            append("requiresSeparateSshSessionAcquisitionExecutionBoundary=")
                .append(receipt.requiresSeparateSshSessionAcquisitionExecutionBoundary).append('\n')
            append("requiresSeparateSftpChannelOpenBoundary=")
                .append(receipt.requiresSeparateSftpChannelOpenBoundary).append('\n')
            append("authorizationAttemptId=").append(receipt.authorizationAttemptId).append('\n')
            append("authorizationSha256=").append(receipt.authorizationSha256).append('\n')
            append("resolutionProofSha256=").append(receipt.resolutionProofSha256).append('\n')
            append("credentialResolutionConsumptionReceiptSha256=")
                .append(receipt.credentialResolutionConsumptionReceiptSha256).append('\n')
            append("serverIdentitySha256=").append(receipt.serverIdentitySha256).append('\n')
            append("compositionDescriptorSha256=").append(receipt.compositionDescriptorSha256).append('\n')
            append("serverAccessBindingSha256=").append(receipt.serverAccessBindingSha256).append('\n')
            append("serverAccessId=").append(receipt.serverAccessId).append('\n')
            append("runtimeSessionId=").append(receipt.runtimeSessionId).append('\n')
            append("remoteHostIdentity=").append(receipt.remoteHostIdentity).append('\n')
            append("secretReferenceType=").append(receipt.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(receipt.secretReferenceSha256).append('\n')
            append("credentialStoreImplementation=").append(receipt.credentialStoreImplementation).append('\n')
            append("sshConnectionFactoryImplementation=")
                .append(receipt.sshConnectionFactoryImplementation).append('\n')
            append("exactSessionRegistryImplementation=")
                .append(receipt.exactSessionRegistryImplementation).append('\n')
            append("consumedAtEpochMillis=").append(receipt.consumedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=").append(receipt.authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256::matches)) {
            "SSH-session acquisition handoff consumption hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
