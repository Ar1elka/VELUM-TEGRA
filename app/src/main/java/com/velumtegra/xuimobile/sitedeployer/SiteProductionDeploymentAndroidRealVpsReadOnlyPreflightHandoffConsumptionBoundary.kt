package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionPort
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpReadOnlyPreflightProbe
import java.security.MessageDigest

/**
 * Phase 11.38 durable consume-once boundary for one exact Phase 11.37 real-VPS read-only preflight
 * authorization.
 *
 * The only side effect is an app-private replay-fence marker. No credential material is read, no
 * network is touched, no host key is verified against a remote, no SSH/SFTP operation is performed,
 * and no coordinator or deploy UI capability is exposed.
 */
internal object SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightHandoffConsumptionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")

    fun consume(
        authorization: SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorization,
        consumedAtEpochMillis: Long,
        consumptionPort: SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionPort,
    ): SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionReceipt {
        SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAuthorizationBoundary
            .validateAuthorization(authorization)
        require(authorization.authorizesSingleRealVpsReadOnlyPreflightHandoff) {
            "Real-VPS read-only preflight authorization does not authorize a single handoff"
        }
        require(authorization.requiresDurableOneShotConsumptionBeforeAnyNetworkAccess) {
            "Durable one-shot consumption must precede any real-VPS network-capable boundary"
        }
        require(!authorization.authorizesNetworkAccess)
        require(!authorization.authorizesCredentialResolution)
        require(!authorization.authorizesSshSessionAcquisition)
        require(!authorization.authorizesSftpChannelOpen)
        require(!authorization.authorizesReadOnlyPreflightExecution)
        require(consumedAtEpochMillis >= authorization.evaluatedAtEpochMillis) {
            "Real-VPS read-only preflight handoff cannot be consumed before authorization evaluation"
        }
        require(consumedAtEpochMillis <= authorization.authorizationExpiresAtEpochMillis) {
            "Real-VPS read-only preflight authorization expired before durable consumption"
        }
        require(consumptionPort.consumeOnce(authorization.authorizationSha256)) {
            "Real-VPS read-only preflight handoff was already consumed or replay fence failed closed"
        }

        val base = SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionReceipt(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_CREDENTIAL_AND_TRANSPORT_BOUNDARIES,
            singleUseConsumed = true,
            productionNetworkTouched = false,
            credentialLeaseMaterialRead = false,
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
            requiresLiveRemoteHostKeyVerification = true,
            requiresSeparateCredentialResolutionBoundary = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            authorizationSha256 = authorization.authorizationSha256,
            admissionSha256 = authorization.admissionSha256,
            serverAccessBindingSha256 = authorization.serverAccessBindingSha256,
            requestSha256 = authorization.requestSha256,
            capabilityProfileSha256 = authorization.capabilityProfileSha256,
            serverAccessId = authorization.serverAccessId,
            remoteHostIdentity = authorization.remoteHostIdentity,
            remotePort = authorization.remotePort,
            pinnedHostKeySha256 = authorization.pinnedHostKeySha256,
            targetRoot = authorization.targetRoot,
            stagingRoot = authorization.stagingRoot,
            backupRoot = authorization.backupRoot,
            expectedTargetEntryNames = authorization.expectedTargetEntryNames,
            approvedReadOnlyOperationVocabulary = authorization.approvedReadOnlyOperationVocabulary,
            maxTargetEntries = authorization.maxTargetEntries,
            sftpReadOnlyProbeImplementation = authorization.sftpReadOnlyProbeImplementation,
            authorizationAttemptId = authorization.authorizationAttemptId,
            consumedAtEpochMillis = consumedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorization.authorizationExpiresAtEpochMillis,
            consumptionReceiptSha256 = "",
        )
        return base.copy(consumptionReceiptSha256 = receiptSha256(base)).also(::validateReceipt)
    }

    fun validateReceipt(
        receipt: SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionReceipt,
    ) {
        require(receipt.contractVersion == CONTRACT_VERSION)
        require(
            receipt.status ==
                SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionStatus
                    .DURABLY_CONSUMED_AWAITING_SEPARATE_CREDENTIAL_AND_TRANSPORT_BOUNDARIES,
        )
        require(receipt.singleUseConsumed)
        require(!receipt.productionNetworkTouched)
        require(!receipt.credentialLeaseMaterialRead)
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
        require(receipt.requiresLiveRemoteHostKeyVerification)
        require(receipt.requiresSeparateCredentialResolutionBoundary)
        require(receipt.requiresSeparateSshSessionAcquisitionBoundary)
        require(receipt.requiresSeparateSftpChannelOpenBoundary)
        require(receipt.requiresSeparateReadOnlyExecutionBoundary)
        require(receipt.requiresSeparateMutationBoundary)
        require(receipt.remotePort in 1..65535)
        require(receipt.consumedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis)
        require(
            receipt.approvedReadOnlyOperationVocabulary ==
                SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
                    .EXACT_READ_ONLY_OPERATION_VOCABULARY,
        )
        require(receipt.maxTargetEntries == SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(receipt.sftpReadOnlyProbeImplementation == SiteRemoteSftpReadOnlyPreflightProbe::class.java.name)
        validateHashes(
            receipt.authorizationSha256,
            receipt.admissionSha256,
            receipt.serverAccessBindingSha256,
            receipt.requestSha256,
            receipt.capabilityProfileSha256,
            receipt.pinnedHostKeySha256,
            receipt.consumptionReceiptSha256,
        )
        require(
            receipt.consumptionReceiptSha256 ==
                receiptSha256(receipt.copy(consumptionReceiptSha256 = "")),
        ) { "Real-VPS read-only preflight handoff consumption receipt SHA-256 mismatch" }
    }

    private fun receiptSha256(
        receipt: SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionReceipt,
    ): String = sha256(
        buildString {
            append("phase=11.38\n")
            append("status=").append(receipt.status.name).append('\n')
            append("singleUseConsumed=").append(receipt.singleUseConsumed).append('\n')
            append("authorization=").append(receipt.authorizationSha256).append('\n')
            append("admission=").append(receipt.admissionSha256).append('\n')
            append("binding=").append(receipt.serverAccessBindingSha256).append('\n')
            append("request=").append(receipt.requestSha256).append('\n')
            append("profile=").append(receipt.capabilityProfileSha256).append('\n')
            append("serverAccessId=").append(receipt.serverAccessId).append('\n')
            append("host=").append(receipt.remoteHostIdentity).append('\n')
            append("port=").append(receipt.remotePort).append('\n')
            append("hostKey=").append(receipt.pinnedHostKeySha256).append('\n')
            append("target=").append(receipt.targetRoot).append('\n')
            append("staging=").append(receipt.stagingRoot).append('\n')
            append("backup=").append(receipt.backupRoot).append('\n')
            receipt.expectedTargetEntryNames.forEach { append("entry=").append(it).append('\n') }
            receipt.approvedReadOnlyOperationVocabulary.forEach {
                append("operation=").append(it).append('\n')
            }
            append("maxTargetEntries=").append(receipt.maxTargetEntries).append('\n')
            append("probe=").append(receipt.sftpReadOnlyProbeImplementation).append('\n')
            append("attempt=").append(receipt.authorizationAttemptId).append('\n')
            append("consumedAt=").append(receipt.consumedAtEpochMillis).append('\n')
            append("expiresAt=").append(receipt.authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS read-only preflight consumption hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
