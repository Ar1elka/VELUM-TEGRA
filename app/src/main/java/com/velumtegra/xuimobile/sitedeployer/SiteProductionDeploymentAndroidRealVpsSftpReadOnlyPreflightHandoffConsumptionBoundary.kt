package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionPort
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpReadOnlyPreflightProbe
import java.security.MessageDigest

/**
 * Phase 11.49 durable consume-once boundary for one exact Phase 11.48 real-VPS bounded SFTP
 * read-only-preflight authorization.
 *
 * Marker creation in the dedicated app-private replay namespace is the only side effect. This
 * boundary does not read credential material, touch production network, acquire SSH, open SFTP,
 * perform any SFTP path operation/read, dispatch a remote command, mutate remote state, invoke the
 * coordinator, or expose deploy UI. A later execution boundary must resolve a fresh credential,
 * establish a fresh pinned SSH session, open a fresh SFTP channel and then perform only the exact
 * bounded read-only vocabulary already reviewed by Phase 11.48.
 */
internal object SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightHandoffConsumptionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")

    fun consume(
        authorization: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization,
        consumedAtEpochMillis: Long,
        consumptionPort: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionPort,
    ): SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionReceipt {
        SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightAuthorizationBoundary
            .validateAuthorization(authorization)
        require(authorization.authorizesSingleReadOnlyPreflightHandoff) {
            "Real-VPS SFTP read-only preflight authorization does not authorize one durable handoff"
        }
        require(!authorization.authorizesNetworkAccess)
        require(!authorization.authorizesReadOnlyPreflightExecution)
        require(!authorization.authorizesMutation)
        require(authorization.requiresDurableOneShotConsumptionBeforeReadOnlyPreflight) {
            "Real-VPS SFTP read-only preflight handoff must be durably consumed before execution"
        }
        require(authorization.requiresFreshCredentialResolutionBeforeReadOnlyExecution)
        require(authorization.requiresFreshSshSessionAcquisitionBeforeReadOnlyExecution)
        require(authorization.requiresFreshSftpChannelOpenBeforeReadOnlyExecution)
        require(authorization.requiresSeparateReadOnlyExecutionBoundary)
        require(consumedAtEpochMillis >= authorization.evaluatedAtEpochMillis) {
            "Real-VPS SFTP read-only preflight handoff cannot be consumed before authorization evaluation"
        }
        require(consumedAtEpochMillis <= authorization.authorizationExpiresAtEpochMillis) {
            "Real-VPS SFTP read-only preflight authorization expired before durable consumption"
        }
        require(consumptionPort.consumeOnce(authorization.authorizationSha256)) {
            "Real-VPS SFTP read-only preflight handoff was already consumed or replay fence failed closed"
        }

        val base = SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionReceipt(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_FRESH_CREDENTIAL_SSH_SFTP_AND_SEPARATE_READ_ONLY_EXECUTION_BOUNDARY,
            singleUseConsumed = true,
            credentialLeaseMaterialRead = false,
            productionNetworkTouched = false,
            hostKeyPinVerifiedAgainstRemoteByPriorProof = true,
            priorSftpChannelOpenedAndClosedWithoutOperation = true,
            authorizesNetworkAccess = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresFreshCredentialResolutionBeforeReadOnlyExecution = true,
            requiresFreshSshSessionAcquisitionBeforeReadOnlyExecution = true,
            requiresFreshLiveRemoteHostKeyVerificationBeforeReadOnlyExecution = true,
            requiresFreshSftpChannelOpenBeforeReadOnlyExecution = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            authorizationAttemptId = authorization.authorizationAttemptId,
            authorizationSha256 = authorization.authorizationSha256,
            priorSftpExecutionProofSha256 = authorization.priorSftpExecutionProofSha256,
            priorSftpExecutionReceiptSha256 = authorization.priorSftpExecutionReceiptSha256,
            preflightHandoffConsumptionReceiptSha256 = authorization.preflightHandoffConsumptionReceiptSha256,
            sourcePreflightAuthorizationSha256 = authorization.sourcePreflightAuthorizationSha256,
            admissionSha256 = authorization.admissionSha256,
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
            targetRoot = authorization.targetRoot,
            stagingRoot = authorization.stagingRoot,
            backupRoot = authorization.backupRoot,
            expectedTargetEntryNames = authorization.expectedTargetEntryNames,
            approvedReadOnlyOperationVocabulary = authorization.approvedReadOnlyOperationVocabulary,
            maxTargetEntries = authorization.maxTargetEntries,
            sftpReadOnlyProbeImplementation = authorization.sftpReadOnlyProbeImplementation,
            consumedAtEpochMillis = consumedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorization.authorizationExpiresAtEpochMillis,
            readOnlyPreflightConsumptionReceiptSha256 = "",
        )
        return base.copy(
            readOnlyPreflightConsumptionReceiptSha256 = receiptSha256(base),
        ).also(::validateReceipt)
    }

    fun validateReceipt(
        receipt: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionReceipt,
    ) {
        require(receipt.contractVersion == CONTRACT_VERSION)
        require(
            receipt.status ==
                SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionStatus
                    .DURABLY_CONSUMED_AWAITING_FRESH_CREDENTIAL_SSH_SFTP_AND_SEPARATE_READ_ONLY_EXECUTION_BOUNDARY,
        )
        require(receipt.singleUseConsumed)
        require(!receipt.credentialLeaseMaterialRead)
        require(!receipt.productionNetworkTouched)
        require(receipt.hostKeyPinVerifiedAgainstRemoteByPriorProof)
        require(receipt.priorSftpChannelOpenedAndClosedWithoutOperation)
        require(!receipt.authorizesNetworkAccess)
        require(!receipt.authorizesCredentialResolution)
        require(!receipt.authorizesSshSessionAcquisition)
        require(!receipt.authorizesSftpChannelOpen)
        require(!receipt.authorizesReadOnlyPreflightExecution)
        require(!receipt.authorizesMutation)
        require(!receipt.authorizesCoordinatorInvocation)
        require(!receipt.exposesDeployUiAction)
        require(!receipt.realVpsAccessAllowed)
        require(receipt.requiresFreshCredentialResolutionBeforeReadOnlyExecution)
        require(receipt.requiresFreshSshSessionAcquisitionBeforeReadOnlyExecution)
        require(receipt.requiresFreshLiveRemoteHostKeyVerificationBeforeReadOnlyExecution)
        require(receipt.requiresFreshSftpChannelOpenBeforeReadOnlyExecution)
        require(receipt.requiresSeparateReadOnlyExecutionBoundary)
        require(receipt.requiresSeparateMutationBoundary)
        require(receipt.remoteHostIdentity.isNotBlank())
        require(receipt.remotePort in 1..65535)
        require(receipt.username.isNotBlank())
        require(receipt.secretReferenceType == "password" || receipt.secretReferenceType == "private-key")
        require(receipt.expectedTargetEntryNames.isNotEmpty())
        require(receipt.expectedTargetEntryNames == receipt.expectedTargetEntryNames.sorted())
        require(receipt.expectedTargetEntryNames.size <= receipt.maxTargetEntries)
        require(
            receipt.approvedReadOnlyOperationVocabulary ==
                SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
                    .EXACT_READ_ONLY_OPERATION_VOCABULARY,
        )
        require(receipt.maxTargetEntries == SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(receipt.sftpReadOnlyProbeImplementation == SiteRemoteSftpReadOnlyPreflightProbe::class.java.name)
        require(receipt.consumedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis)
        validateHashes(
            receipt.authorizationSha256,
            receipt.priorSftpExecutionProofSha256,
            receipt.priorSftpExecutionReceiptSha256,
            receipt.preflightHandoffConsumptionReceiptSha256,
            receipt.sourcePreflightAuthorizationSha256,
            receipt.admissionSha256,
            receipt.serverAccessBindingSha256,
            receipt.requestSha256,
            receipt.capabilityProfileSha256,
            receipt.pinnedHostKeySha256,
            receipt.secretReferenceSha256,
            receipt.readOnlyPreflightConsumptionReceiptSha256,
        )
        require(
            receipt.readOnlyPreflightConsumptionReceiptSha256 ==
                receiptSha256(receipt.copy(readOnlyPreflightConsumptionReceiptSha256 = "")),
        ) { "Real-VPS SFTP read-only preflight handoff receipt SHA-256 mismatch" }
    }

    private fun receiptSha256(
        receipt: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionReceipt,
    ): String = sha256(buildString {
        append("phase=11.49\n")
        append("contractVersion=").append(receipt.contractVersion).append('\n')
        append("status=").append(receipt.status.name).append('\n')
        append("singleUseConsumed=").append(receipt.singleUseConsumed).append('\n')
        append("credentialLeaseMaterialRead=").append(receipt.credentialLeaseMaterialRead).append('\n')
        append("productionNetworkTouched=").append(receipt.productionNetworkTouched).append('\n')
        append("authorizationSha256=").append(receipt.authorizationSha256).append('\n')
        append("priorSftpExecutionProofSha256=").append(receipt.priorSftpExecutionProofSha256).append('\n')
        append("priorSftpExecutionReceiptSha256=").append(receipt.priorSftpExecutionReceiptSha256).append('\n')
        append("preflightHandoffConsumptionReceiptSha256=").append(receipt.preflightHandoffConsumptionReceiptSha256).append('\n')
        append("sourcePreflightAuthorizationSha256=").append(receipt.sourcePreflightAuthorizationSha256).append('\n')
        append("admissionSha256=").append(receipt.admissionSha256).append('\n')
        append("serverAccessBindingSha256=").append(receipt.serverAccessBindingSha256).append('\n')
        append("requestSha256=").append(receipt.requestSha256).append('\n')
        append("capabilityProfileSha256=").append(receipt.capabilityProfileSha256).append('\n')
        append("serverAccessId=").append(receipt.serverAccessId).append('\n')
        append("host=").append(receipt.remoteHostIdentity).append('\n')
        append("port=").append(receipt.remotePort).append('\n')
        append("username=").append(receipt.username).append('\n')
        append("pinnedHostKeySha256=").append(receipt.pinnedHostKeySha256).append('\n')
        append("secretReferenceType=").append(receipt.secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(receipt.secretReferenceSha256).append('\n')
        append("targetRoot=").append(receipt.targetRoot).append('\n')
        append("stagingRoot=").append(receipt.stagingRoot).append('\n')
        append("backupRoot=").append(receipt.backupRoot).append('\n')
        receipt.expectedTargetEntryNames.forEach { append("entry=").append(it).append('\n') }
        receipt.approvedReadOnlyOperationVocabulary.forEach { append("operation=").append(it).append('\n') }
        append("maxTargetEntries=").append(receipt.maxTargetEntries).append('\n')
        append("probe=").append(receipt.sftpReadOnlyProbeImplementation).append('\n')
        append("attemptId=").append(receipt.authorizationAttemptId).append('\n')
        append("consumedAt=").append(receipt.consumedAtEpochMillis).append('\n')
        append("expiresAt=").append(receipt.authorizationExpiresAtEpochMillis).append('\n')
    })

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS SFTP read-only preflight consumption hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
