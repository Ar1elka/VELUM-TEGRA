package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionPort
import java.security.MessageDigest

internal object SiteProductionDeploymentAndroidSftpReadOnlyPreflightHandoffConsumptionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")

    fun consume(
        authorization: SiteProductionDeploymentSftpReadOnlyPreflightAuthorization,
        consumedAtEpochMillis: Long,
        consumptionPort: SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionPort,
    ): SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionReceipt {
        SiteProductionDeploymentAndroidSftpReadOnlyPreflightAuthorizationBoundary.validateAuthorization(authorization)
        require(authorization.authorizesSingleReadOnlyPreflightHandoff)
        require(consumedAtEpochMillis >= authorization.evaluatedAtEpochMillis && consumedAtEpochMillis <= authorization.authorizationExpiresAtEpochMillis)
        require(consumptionPort.consumeOnce(authorization.authorizationSha256)) { "Read-only SFTP preflight handoff was already consumed or replay fence failed closed" }
        val base = SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionReceipt(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionStatus.DURABLY_CONSUMED_AWAITING_SEPARATE_READ_ONLY_PREFLIGHT_EXECUTION,
            singleUseConsumed = true, fixtureEndpointRequired = true, credentialLeaseMaterialRead = false,
            authorizesReadOnlyPreflightExecution = false, authorizesMutation = false, authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false, realVpsAccessAllowed = false, requiresSeparateMutationBoundary = true,
            authorizationSha256 = authorization.authorizationSha256,
            sftpChannelOpenConsumptionReceiptSha256 = authorization.sftpChannelOpenConsumptionReceiptSha256,
            serverAccessBindingSha256 = authorization.serverAccessBindingSha256, serverAccessId = authorization.serverAccessId,
            remoteHostIdentity = authorization.remoteHostIdentity, remotePort = authorization.remotePort,
            secretReferenceType = authorization.secretReferenceType, secretReferenceSha256 = authorization.secretReferenceSha256,
            sftpReadOnlyProbeImplementation = authorization.sftpReadOnlyProbeImplementation,
            targetRoot = authorization.targetRoot, stagingRoot = authorization.stagingRoot, backupRoot = authorization.backupRoot,
            expectedTargetEntryNames = authorization.expectedTargetEntryNames, requestSha256 = authorization.requestSha256,
            consumedAtEpochMillis = consumedAtEpochMillis, authorizationExpiresAtEpochMillis = authorization.authorizationExpiresAtEpochMillis,
            consumptionReceiptSha256 = "",
        )
        return base.copy(consumptionReceiptSha256 = receiptSha256(base)).also(::validateReceipt)
    }

    fun validateReceipt(r: SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionReceipt) {
        require(r.contractVersion == CONTRACT_VERSION)
        require(r.status == SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionStatus.DURABLY_CONSUMED_AWAITING_SEPARATE_READ_ONLY_PREFLIGHT_EXECUTION)
        require(r.singleUseConsumed && r.fixtureEndpointRequired && !r.credentialLeaseMaterialRead)
        require(!r.authorizesReadOnlyPreflightExecution && !r.authorizesMutation && !r.authorizesCoordinatorInvocation && !r.exposesDeployUiAction && !r.realVpsAccessAllowed)
        require(r.requiresSeparateMutationBoundary)
        require(r.remoteHostIdentity == SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.FIXTURE_LOOPBACK_HOST && r.remotePort in 1..65535)
        require(r.consumedAtEpochMillis <= r.authorizationExpiresAtEpochMillis)
        validateHashes(r.authorizationSha256, r.sftpChannelOpenConsumptionReceiptSha256, r.serverAccessBindingSha256,
            r.secretReferenceSha256, r.requestSha256, r.consumptionReceiptSha256)
        require(r.consumptionReceiptSha256 == receiptSha256(r.copy(consumptionReceiptSha256 = "")))
    }

    private fun receiptSha256(r: SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionReceipt) = sha256(buildString {
        append("contractVersion=").append(r.contractVersion).append('\n'); append("status=").append(r.status.name).append('\n')
        append("authorization=").append(r.authorizationSha256).append('\n'); append("sftpReceipt=").append(r.sftpChannelOpenConsumptionReceiptSha256).append('\n')
        append("binding=").append(r.serverAccessBindingSha256).append('\n'); append("serverAccessId=").append(r.serverAccessId).append('\n')
        append("host=").append(r.remoteHostIdentity).append('\n'); append("port=").append(r.remotePort).append('\n')
        append("secretType=").append(r.secretReferenceType).append('\n'); append("secretSha=").append(r.secretReferenceSha256).append('\n')
        append("probe=").append(r.sftpReadOnlyProbeImplementation).append('\n'); append("request=").append(r.requestSha256).append('\n')
        append("consumedAt=").append(r.consumedAtEpochMillis).append('\n'); append("expiresAt=").append(r.authorizationExpiresAtEpochMillis).append('\n')
    })
    private fun validateHashes(vararg values: String) = require(values.all(sha256Pattern::matches))
    private fun sha256(value: String) = MessageDigest.getInstance("SHA-256").digest(value.encodeToByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
