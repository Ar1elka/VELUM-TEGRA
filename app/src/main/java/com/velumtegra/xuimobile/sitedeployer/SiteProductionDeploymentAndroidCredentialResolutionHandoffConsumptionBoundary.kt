package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentCredentialResolutionHandoffConsumptionPort
import java.security.MessageDigest

/**
 * Phase 11.29 durable consume-once boundary for the Phase 11.28 credential-resolution handoff.
 *
 * Consumption burns only the exact Phase 11.28 authorization SHA-256 into the app-private replay
 * fence and emits a typed receipt. It does not instantiate/read SecretStore, resolve credentials,
 * acquire SSH/SFTP, invoke SiteDeploymentCoordinator, expose deploy UI, or access a real VPS.
 */
internal object SiteProductionDeploymentAndroidCredentialResolutionHandoffConsumptionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun consume(
        authorization: SiteProductionDeploymentCredentialResolutionAuthorization,
        consumedAtEpochMillis: Long,
        consumptionPort: SiteProductionDeploymentCredentialResolutionHandoffConsumptionPort,
    ): SiteProductionDeploymentCredentialResolutionHandoffConsumptionReceipt {
        SiteProductionDeploymentAndroidCredentialResolutionAuthorizationBoundary
            .validateAuthorization(authorization)
        require(authorization.authorizesSingleCredentialResolutionHandoff) {
            "Credential-resolution authorization does not authorize a single handoff"
        }
        require(!authorization.authorizesCredentialResolution) {
            "Phase 11.28 authorization must not authorize actual credential resolution"
        }
        require(authorization.requiresDurableOneShotConsumptionBeforeCredentialResolution) {
            "Credential-resolution handoff must require durable one-shot consumption"
        }
        require(consumedAtEpochMillis >= authorization.evaluatedAtEpochMillis) {
            "Credential-resolution handoff cannot be consumed before authorization evaluation"
        }
        require(consumedAtEpochMillis <= authorization.authorizationExpiresAtEpochMillis) {
            "Credential-resolution handoff authorization expired before durable consumption"
        }

        require(consumptionPort.consumeOnce(authorization.authorizationSha256)) {
            "Credential-resolution handoff was already consumed or replay fence failed closed"
        }

        val base = SiteProductionDeploymentCredentialResolutionHandoffConsumptionReceipt(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentCredentialResolutionHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_CREDENTIAL_RESOLUTION_EXECUTION_BOUNDARY,
            singleUseConsumed = true,
            credentialReferenceBound = true,
            secretStoreReadPerformed = false,
            productionTransportEnabled = false,
            authorizesTransport = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresSeparateCredentialResolutionExecutionBoundary = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            authorizationAttemptId = authorization.authorizationAttemptId,
            authorizationSha256 = authorization.authorizationSha256,
            admissionSha256 = authorization.admissionSha256,
            consumptionReceiptSha256 = authorization.consumptionReceiptSha256,
            serverIdentitySha256 = authorization.serverIdentitySha256,
            serverAccessId = authorization.serverAccessId,
            secretReferenceType = authorization.secretReferenceType,
            secretReferenceSha256 = authorization.secretReferenceSha256,
            credentialStoreImplementation = authorization.credentialStoreImplementation,
            consumedAtEpochMillis = consumedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorization.authorizationExpiresAtEpochMillis,
            credentialResolutionConsumptionReceiptSha256 = "",
        )
        return base.copy(
            credentialResolutionConsumptionReceiptSha256 = receiptSha256(base),
        ).also(::validateReceipt)
    }

    fun validateReceipt(
        receipt: SiteProductionDeploymentCredentialResolutionHandoffConsumptionReceipt,
    ) {
        require(receipt.contractVersion == CONTRACT_VERSION) {
            "Unsupported credential-resolution handoff consumption contract"
        }
        require(
            receipt.status ==
                SiteProductionDeploymentCredentialResolutionHandoffConsumptionStatus
                    .DURABLY_CONSUMED_AWAITING_SEPARATE_CREDENTIAL_RESOLUTION_EXECUTION_BOUNDARY,
        ) { "Credential-resolution handoff consumption receipt has invalid status" }
        require(receipt.singleUseConsumed) {
            "Credential-resolution handoff receipt must prove durable one-shot consumption"
        }
        require(receipt.credentialReferenceBound) {
            "Credential-resolution handoff receipt must retain the exact hashed credential reference"
        }
        require(!receipt.secretStoreReadPerformed) {
            "Credential-resolution handoff consumption must not read SecretStore"
        }
        require(!receipt.productionTransportEnabled) {
            "Credential-resolution handoff consumption must not enable production transport"
        }
        require(!receipt.authorizesTransport) {
            "Credential-resolution handoff consumption must not authorize transport"
        }
        require(!receipt.authorizesCredentialResolution) {
            "Credential-resolution handoff consumption must not authorize actual credential resolution"
        }
        require(!receipt.authorizesSshSessionAcquisition) {
            "Credential-resolution handoff consumption must not authorize SSH acquisition"
        }
        require(!receipt.authorizesSftpChannelOpen) {
            "Credential-resolution handoff consumption must not authorize SFTP open"
        }
        require(!receipt.authorizesCoordinatorInvocation) {
            "Credential-resolution handoff consumption must not authorize coordinator invocation"
        }
        require(!receipt.exposesDeployUiAction) {
            "Credential-resolution handoff consumption must not expose deploy UI"
        }
        require(!receipt.realVpsAccessAllowed) {
            "Credential-resolution handoff consumption must not permit real VPS access"
        }
        require(receipt.requiresSeparateCredentialResolutionExecutionBoundary) {
            "A separate credential-resolution execution boundary must remain mandatory"
        }
        require(receipt.requiresSeparateSshSessionAcquisitionBoundary) {
            "A separate SSH-session acquisition boundary must remain mandatory"
        }
        require(receipt.requiresSeparateSftpChannelOpenBoundary) {
            "A separate SFTP-channel boundary must remain mandatory"
        }
        require(receipt.consumedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis) {
            "Credential-resolution handoff consumption occurred after authorization expiry"
        }
        require(receipt.secretReferenceType == "password" || receipt.secretReferenceType == "private-key") {
            "Credential-resolution handoff secret reference type is invalid"
        }
        validateHashes(
            receipt.authorizationSha256,
            receipt.admissionSha256,
            receipt.consumptionReceiptSha256,
            receipt.serverIdentitySha256,
            receipt.secretReferenceSha256,
            receipt.credentialResolutionConsumptionReceiptSha256,
        )
        require(
            receipt.credentialResolutionConsumptionReceiptSha256 ==
                receiptSha256(receipt.copy(credentialResolutionConsumptionReceiptSha256 = "")),
        ) { "Credential-resolution handoff consumption receipt SHA-256 mismatch" }
    }

    private fun receiptSha256(
        receipt: SiteProductionDeploymentCredentialResolutionHandoffConsumptionReceipt,
    ): String = sha256(
        buildString {
            append("contractVersion=").append(receipt.contractVersion).append('\n')
            append("status=").append(receipt.status.name).append('\n')
            append("singleUseConsumed=").append(receipt.singleUseConsumed).append('\n')
            append("credentialReferenceBound=").append(receipt.credentialReferenceBound).append('\n')
            append("secretStoreReadPerformed=").append(receipt.secretStoreReadPerformed).append('\n')
            append("productionTransportEnabled=").append(receipt.productionTransportEnabled).append('\n')
            append("authorizesTransport=").append(receipt.authorizesTransport).append('\n')
            append("authorizesCredentialResolution=").append(receipt.authorizesCredentialResolution).append('\n')
            append("authorizesSshSessionAcquisition=").append(receipt.authorizesSshSessionAcquisition).append('\n')
            append("authorizesSftpChannelOpen=").append(receipt.authorizesSftpChannelOpen).append('\n')
            append("authorizesCoordinatorInvocation=").append(receipt.authorizesCoordinatorInvocation).append('\n')
            append("exposesDeployUiAction=").append(receipt.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(receipt.realVpsAccessAllowed).append('\n')
            append("requiresSeparateCredentialResolutionExecutionBoundary=")
                .append(receipt.requiresSeparateCredentialResolutionExecutionBoundary).append('\n')
            append("requiresSeparateSshSessionAcquisitionBoundary=")
                .append(receipt.requiresSeparateSshSessionAcquisitionBoundary).append('\n')
            append("requiresSeparateSftpChannelOpenBoundary=")
                .append(receipt.requiresSeparateSftpChannelOpenBoundary).append('\n')
            append("authorizationAttemptId=").append(receipt.authorizationAttemptId).append('\n')
            append("authorizationSha256=").append(receipt.authorizationSha256).append('\n')
            append("admissionSha256=").append(receipt.admissionSha256).append('\n')
            append("consumptionReceiptSha256=").append(receipt.consumptionReceiptSha256).append('\n')
            append("serverIdentitySha256=").append(receipt.serverIdentitySha256).append('\n')
            append("serverAccessId=").append(receipt.serverAccessId).append('\n')
            append("secretReferenceType=").append(receipt.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(receipt.secretReferenceSha256).append('\n')
            append("credentialStoreImplementation=").append(receipt.credentialStoreImplementation).append('\n')
            append("consumedAtEpochMillis=").append(receipt.consumedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=").append(receipt.authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256::matches)) {
            "Credential-resolution handoff consumption hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
