package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionPort
import java.security.MessageDigest

/**
 * Phase 11.40 durable consume-once boundary for one exact Phase 11.39 real-VPS
 * credential-resolution authorization.
 *
 * The only side effect is an app-private replay-fence marker. It does not instantiate/read the
 * SecretStore, read credential material, touch production network, verify a live remote host key,
 * acquire SSH/SFTP, execute any remote operation, mutate remote state, invoke the coordinator, or
 * expose deploy UI.
 */
internal object SiteProductionDeploymentAndroidRealVpsCredentialResolutionHandoffConsumptionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")

    fun consume(
        authorization: SiteProductionDeploymentRealVpsCredentialResolutionAuthorization,
        consumedAtEpochMillis: Long,
        consumptionPort: SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionPort,
    ): SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionReceipt {
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionAuthorizationBoundary
            .validateAuthorization(authorization)
        require(authorization.authorizesSingleCredentialResolutionHandoff) {
            "Real-VPS credential-resolution authorization does not authorize one handoff"
        }
        require(!authorization.authorizesCredentialResolution) {
            "Phase 11.39 must not authorize actual credential resolution"
        }
        require(authorization.requiresDurableOneShotConsumptionBeforeCredentialResolution) {
            "Real-VPS credential-resolution handoff must require durable one-shot consumption"
        }
        require(consumedAtEpochMillis >= authorization.evaluatedAtEpochMillis) {
            "Real-VPS credential-resolution handoff cannot be consumed before authorization evaluation"
        }
        require(consumedAtEpochMillis <= authorization.authorizationExpiresAtEpochMillis) {
            "Real-VPS credential-resolution authorization expired before durable consumption"
        }
        require(consumptionPort.consumeOnce(authorization.authorizationSha256)) {
            "Real-VPS credential-resolution handoff was already consumed or replay fence failed closed"
        }

        val base = SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionReceipt(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_CREDENTIAL_RESOLUTION_EXECUTION_BOUNDARY,
            singleUseConsumed = true,
            credentialReferenceBound = true,
            secretStoreReadPerformed = false,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemote = false,
            authorizesNetworkAccess = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresSeparateCredentialResolutionExecutionBoundary = true,
            requiresLiveRemoteHostKeyVerification = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            authorizationAttemptId = authorization.authorizationAttemptId,
            authorizationSha256 = authorization.authorizationSha256,
            handoffConsumptionReceiptSha256 = authorization.handoffConsumptionReceiptSha256,
            sourceAuthorizationSha256 = authorization.sourceAuthorizationSha256,
            admissionSha256 = authorization.admissionSha256,
            serverAccessBindingSha256 = authorization.serverAccessBindingSha256,
            requestSha256 = authorization.requestSha256,
            capabilityProfileSha256 = authorization.capabilityProfileSha256,
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
        receipt: SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionReceipt,
    ) {
        require(receipt.contractVersion == CONTRACT_VERSION)
        require(
            receipt.status ==
                SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionStatus
                    .DURABLY_CONSUMED_AWAITING_SEPARATE_CREDENTIAL_RESOLUTION_EXECUTION_BOUNDARY,
        )
        require(receipt.singleUseConsumed)
        require(receipt.credentialReferenceBound)
        require(!receipt.secretStoreReadPerformed)
        require(!receipt.credentialLeaseMaterialRead)
        require(!receipt.productionNetworkTouched)
        require(!receipt.hostKeyPinVerifiedAgainstRemote)
        require(!receipt.authorizesNetworkAccess)
        require(!receipt.authorizesCredentialResolution)
        require(!receipt.authorizesSshSessionAcquisition)
        require(!receipt.authorizesSftpChannelOpen)
        require(!receipt.authorizesReadOnlyPreflightExecution)
        require(!receipt.authorizesMutation)
        require(!receipt.authorizesCoordinatorInvocation)
        require(!receipt.exposesDeployUiAction)
        require(!receipt.realVpsAccessAllowed)
        require(receipt.requiresSeparateCredentialResolutionExecutionBoundary)
        require(receipt.requiresLiveRemoteHostKeyVerification)
        require(receipt.requiresSeparateSshSessionAcquisitionBoundary)
        require(receipt.requiresSeparateSftpChannelOpenBoundary)
        require(receipt.requiresSeparateReadOnlyExecutionBoundary)
        require(receipt.requiresSeparateMutationBoundary)
        require(receipt.consumedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis)
        require(receipt.secretReferenceType == "password" || receipt.secretReferenceType == "private-key")
        require(receipt.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name)
        validateHashes(
            receipt.authorizationSha256,
            receipt.handoffConsumptionReceiptSha256,
            receipt.sourceAuthorizationSha256,
            receipt.admissionSha256,
            receipt.serverAccessBindingSha256,
            receipt.requestSha256,
            receipt.capabilityProfileSha256,
            receipt.secretReferenceSha256,
            receipt.credentialResolutionConsumptionReceiptSha256,
        )
        require(
            receipt.credentialResolutionConsumptionReceiptSha256 ==
                receiptSha256(receipt.copy(credentialResolutionConsumptionReceiptSha256 = "")),
        ) { "Real-VPS credential-resolution handoff receipt SHA-256 mismatch" }
    }

    private fun receiptSha256(
        receipt: SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionReceipt,
    ): String = sha256(
        buildString {
            append("phase=11.40\n")
            append("contractVersion=").append(receipt.contractVersion).append('\n')
            append("status=").append(receipt.status.name).append('\n')
            append("singleUseConsumed=").append(receipt.singleUseConsumed).append('\n')
            append("credentialReferenceBound=").append(receipt.credentialReferenceBound).append('\n')
            append("secretStoreReadPerformed=").append(receipt.secretStoreReadPerformed).append('\n')
            append("credentialLeaseMaterialRead=").append(receipt.credentialLeaseMaterialRead).append('\n')
            append("productionNetworkTouched=").append(receipt.productionNetworkTouched).append('\n')
            append("hostKeyPinVerifiedAgainstRemote=").append(receipt.hostKeyPinVerifiedAgainstRemote).append('\n')
            append("authorizesNetworkAccess=").append(receipt.authorizesNetworkAccess).append('\n')
            append("authorizesCredentialResolution=").append(receipt.authorizesCredentialResolution).append('\n')
            append("authorizesSshSessionAcquisition=").append(receipt.authorizesSshSessionAcquisition).append('\n')
            append("authorizesSftpChannelOpen=").append(receipt.authorizesSftpChannelOpen).append('\n')
            append("authorizesReadOnlyPreflightExecution=").append(receipt.authorizesReadOnlyPreflightExecution).append('\n')
            append("authorizesMutation=").append(receipt.authorizesMutation).append('\n')
            append("authorizesCoordinatorInvocation=").append(receipt.authorizesCoordinatorInvocation).append('\n')
            append("exposesDeployUiAction=").append(receipt.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(receipt.realVpsAccessAllowed).append('\n')
            append("requiresSeparateCredentialResolutionExecutionBoundary=")
                .append(receipt.requiresSeparateCredentialResolutionExecutionBoundary).append('\n')
            append("requiresLiveRemoteHostKeyVerification=")
                .append(receipt.requiresLiveRemoteHostKeyVerification).append('\n')
            append("requiresSeparateSshSessionAcquisitionBoundary=")
                .append(receipt.requiresSeparateSshSessionAcquisitionBoundary).append('\n')
            append("requiresSeparateSftpChannelOpenBoundary=")
                .append(receipt.requiresSeparateSftpChannelOpenBoundary).append('\n')
            append("requiresSeparateReadOnlyExecutionBoundary=")
                .append(receipt.requiresSeparateReadOnlyExecutionBoundary).append('\n')
            append("requiresSeparateMutationBoundary=")
                .append(receipt.requiresSeparateMutationBoundary).append('\n')
            append("authorizationAttemptId=").append(receipt.authorizationAttemptId).append('\n')
            append("authorizationSha256=").append(receipt.authorizationSha256).append('\n')
            append("handoffReceipt=").append(receipt.handoffConsumptionReceiptSha256).append('\n')
            append("sourceAuthorization=").append(receipt.sourceAuthorizationSha256).append('\n')
            append("admission=").append(receipt.admissionSha256).append('\n')
            append("binding=").append(receipt.serverAccessBindingSha256).append('\n')
            append("request=").append(receipt.requestSha256).append('\n')
            append("profile=").append(receipt.capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(receipt.serverAccessId).append('\n')
            append("secretReferenceType=").append(receipt.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(receipt.secretReferenceSha256).append('\n')
            append("credentialStoreImplementation=").append(receipt.credentialStoreImplementation).append('\n')
            append("consumedAtEpochMillis=").append(receipt.consumedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=").append(receipt.authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS credential-resolution handoff hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
