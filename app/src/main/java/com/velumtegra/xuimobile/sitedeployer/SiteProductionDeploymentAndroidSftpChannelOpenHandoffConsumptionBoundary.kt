package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentSftpChannelOpenHandoffConsumptionPort
import java.security.MessageDigest

/** Durable one-shot consumption of an exact Phase 11.34 SFTP channel-open authorization. */
internal object SiteProductionDeploymentAndroidSftpChannelOpenHandoffConsumptionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")

    fun consume(
        authorization: SiteProductionDeploymentSftpChannelOpenAuthorization,
        consumedAtEpochMillis: Long,
        consumptionPort: SiteProductionDeploymentSftpChannelOpenHandoffConsumptionPort,
    ): SiteProductionDeploymentSftpChannelOpenHandoffConsumptionReceipt {
        SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.validateAuthorization(authorization)
        require(authorization.authorizesSingleSftpChannelOpenHandoff) {
            "Phase 11.34 authorization does not admit a single SFTP channel-open handoff"
        }
        require(authorization.requiresDurableOneShotConsumptionBeforeExecution)
        require(authorization.requiresSeparateSftpChannelOpenExecutionBoundary)
        require(consumedAtEpochMillis >= authorization.evaluatedAtEpochMillis)
        require(consumedAtEpochMillis <= authorization.authorizationExpiresAtEpochMillis) {
            "SFTP channel-open authorization expired before durable consumption"
        }
        require(consumptionPort.consumeOnce(authorization.authorizationSha256)) {
            "SFTP channel-open handoff was already consumed or replay fence failed closed"
        }
        val base = SiteProductionDeploymentSftpChannelOpenHandoffConsumptionReceipt(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentSftpChannelOpenHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_SFTP_CHANNEL_OPEN_EXECUTION_BOUNDARY,
            singleUseConsumed = true,
            fixtureEndpointRequired = true,
            credentialLeaseMaterialRead = false,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresSeparateSftpChannelOpenExecutionBoundary = true,
            requiresSeparateBoundedSftpOperationsBoundary = true,
            requiresSeparateCoordinatorInvocationBoundary = true,
            authorizationSha256 = authorization.authorizationSha256,
            sshSessionAcquisitionConsumptionReceiptSha256 = authorization.sshSessionAcquisitionConsumptionReceiptSha256,
            resolutionProofSha256 = authorization.resolutionProofSha256,
            serverAccessBindingSha256 = authorization.serverAccessBindingSha256,
            serverAccessId = authorization.serverAccessId,
            remoteHostIdentity = authorization.remoteHostIdentity,
            remotePort = authorization.remotePort,
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

    fun validateReceipt(receipt: SiteProductionDeploymentSftpChannelOpenHandoffConsumptionReceipt) {
        require(receipt.contractVersion == CONTRACT_VERSION)
        require(receipt.status == SiteProductionDeploymentSftpChannelOpenHandoffConsumptionStatus
            .DURABLY_CONSUMED_AWAITING_SEPARATE_SFTP_CHANNEL_OPEN_EXECUTION_BOUNDARY)
        require(receipt.singleUseConsumed && receipt.fixtureEndpointRequired)
        require(!receipt.credentialLeaseMaterialRead)
        require(!receipt.authorizesSftpChannelOpen)
        require(!receipt.authorizesCoordinatorInvocation && !receipt.exposesDeployUiAction && !receipt.realVpsAccessAllowed)
        require(receipt.requiresSeparateSftpChannelOpenExecutionBoundary)
        require(receipt.requiresSeparateBoundedSftpOperationsBoundary)
        require(receipt.requiresSeparateCoordinatorInvocationBoundary)
        require(receipt.remoteHostIdentity == SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.FIXTURE_LOOPBACK_HOST)
        require(receipt.remotePort in 1..65535)
        require(receipt.consumedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis)
        validateHashes(
            receipt.authorizationSha256,
            receipt.sshSessionAcquisitionConsumptionReceiptSha256,
            receipt.resolutionProofSha256,
            receipt.serverAccessBindingSha256,
            receipt.secretReferenceSha256,
            receipt.sftpChannelOpenConsumptionReceiptSha256,
        )
        require(receipt.sftpChannelOpenConsumptionReceiptSha256 ==
            receiptSha256(receipt.copy(sftpChannelOpenConsumptionReceiptSha256 = ""))) {
            "SFTP channel-open consumption receipt SHA-256 mismatch"
        }
    }

    private fun receiptSha256(receipt: SiteProductionDeploymentSftpChannelOpenHandoffConsumptionReceipt): String = sha256(buildString {
        append("contractVersion=").append(receipt.contractVersion).append('\n')
        append("status=").append(receipt.status.name).append('\n')
        append("authorizationSha256=").append(receipt.authorizationSha256).append('\n')
        append("sshReceipt=").append(receipt.sshSessionAcquisitionConsumptionReceiptSha256).append('\n')
        append("resolutionProof=").append(receipt.resolutionProofSha256).append('\n')
        append("serverAccessBinding=").append(receipt.serverAccessBindingSha256).append('\n')
        append("serverAccessId=").append(receipt.serverAccessId).append('\n')
        append("host=").append(receipt.remoteHostIdentity).append('\n')
        append("port=").append(receipt.remotePort).append('\n')
        append("secretReferenceType=").append(receipt.secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(receipt.secretReferenceSha256).append('\n')
        append("sshFactory=").append(receipt.sshConnectionFactoryImplementation).append('\n')
        append("registry=").append(receipt.exactSessionRegistryImplementation).append('\n')
        append("sftpProbe=").append(receipt.sftpLifecycleProbeImplementation).append('\n')
        append("consumedAt=").append(receipt.consumedAtEpochMillis).append('\n')
        append("expiresAt=").append(receipt.authorizationExpiresAtEpochMillis).append('\n')
    })

    private fun validateHashes(vararg values: String) = require(values.all(sha256Pattern::matches)) {
        "SFTP channel-open handoff hashes must be lowercase SHA-256"
    }
    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
