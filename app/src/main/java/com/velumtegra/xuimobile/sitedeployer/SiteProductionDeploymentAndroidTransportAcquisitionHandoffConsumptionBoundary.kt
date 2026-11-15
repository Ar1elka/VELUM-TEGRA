package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentTransportAcquisitionHandoffConsumptionPort
import java.security.MessageDigest

/**
 * Durable consume-once boundary for the Phase 11.25 transport-acquisition handoff authorization.
 *
 * Consumption only burns the exact handoff authorization into the app-private replay fence and
 * emits a typed receipt. It deliberately does not resolve credentials, acquire SSH, open SFTP,
 * invoke SiteDeploymentCoordinator, expose deploy UI, or permit real-VPS access.
 */
internal object SiteProductionDeploymentAndroidTransportAcquisitionHandoffConsumptionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun consume(
        authorization: SiteProductionDeploymentTransportAcquisitionAuthorization,
        consumedAtEpochMillis: Long,
        consumptionPort: SiteProductionDeploymentTransportAcquisitionHandoffConsumptionPort,
    ): SiteProductionDeploymentTransportAcquisitionHandoffConsumptionReceipt {
        SiteProductionDeploymentAndroidTransportAcquisitionAuthorizationBoundary
            .validateAuthorization(authorization)
        require(authorization.authorizesSingleTransportAcquisitionHandoff) {
            "Transport-acquisition authorization does not authorize a single handoff"
        }
        require(authorization.requiresDurableOneShotConsumptionBeforeAcquisition) {
            "Transport-acquisition handoff must require durable one-shot consumption"
        }
        require(consumedAtEpochMillis >= authorization.evaluatedAtEpochMillis) {
            "Transport-acquisition handoff cannot be consumed before authorization evaluation"
        }
        require(consumedAtEpochMillis <= authorization.authorizationExpiresAtEpochMillis) {
            "Transport-acquisition handoff authorization expired before durable consumption"
        }

        require(consumptionPort.consumeOnce(authorization.authorizationSha256)) {
            "Transport-acquisition handoff was already consumed or replay fence failed closed"
        }

        val base = SiteProductionDeploymentTransportAcquisitionHandoffConsumptionReceipt(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentTransportAcquisitionHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_ACQUISITION_BOUNDARY,
            singleUseConsumed = true,
            productionTransportEnabled = false,
            authorizesTransport = false,
            authorizesTransportAcquisitionExecution = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresSeparateAcquisitionExecutionBoundary = true,
            authorizationAttemptId = authorization.authorizationAttemptId,
            authorizationSha256 = authorization.authorizationSha256,
            readinessSha256 = authorization.readinessSha256,
            compositionDescriptorSha256 = authorization.compositionDescriptorSha256,
            serverIdentitySha256 = authorization.serverIdentitySha256,
            runtimeSessionId = authorization.runtimeSessionId,
            remoteHostIdentity = authorization.remoteHostIdentity,
            executionAttemptId = authorization.executionAttemptId,
            coordinatorInvocationId = authorization.coordinatorInvocationId,
            runtimeMutationPermitSha256 = authorization.runtimeMutationPermitSha256,
            candidateTransportAuthorizationSha256 = authorization.candidateTransportAuthorizationSha256,
            boundedSftpImplementationId = authorization.boundedSftpImplementationId,
            boundedSftpCapabilityProfileSha256 = authorization.boundedSftpCapabilityProfileSha256,
            consumedAtEpochMillis = consumedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorization.authorizationExpiresAtEpochMillis,
            consumptionReceiptSha256 = "",
        )
        return base.copy(consumptionReceiptSha256 = receiptSha256(base)).also(::validateReceipt)
    }

    fun validateReceipt(receipt: SiteProductionDeploymentTransportAcquisitionHandoffConsumptionReceipt) {
        require(receipt.contractVersion == CONTRACT_VERSION) {
            "Unsupported transport-acquisition handoff consumption contract"
        }
        require(receipt.status == SiteProductionDeploymentTransportAcquisitionHandoffConsumptionStatus
            .DURABLY_CONSUMED_AWAITING_SEPARATE_ACQUISITION_BOUNDARY) {
            "Transport-acquisition handoff consumption receipt has invalid status"
        }
        require(receipt.singleUseConsumed) {
            "Transport-acquisition handoff consumption receipt must prove durable one-shot consumption"
        }
        require(!receipt.productionTransportEnabled) { "Handoff consumption must not enable production transport" }
        require(!receipt.authorizesTransport) { "Handoff consumption must not authorize transport" }
        require(!receipt.authorizesTransportAcquisitionExecution) {
            "Handoff consumption must not authorize transport acquisition execution"
        }
        require(!receipt.authorizesCredentialResolution) {
            "Handoff consumption must not authorize credential resolution"
        }
        require(!receipt.authorizesSshSessionAcquisition) { "Handoff consumption must not authorize SSH acquisition" }
        require(!receipt.authorizesSftpChannelOpen) { "Handoff consumption must not authorize SFTP open" }
        require(!receipt.authorizesCoordinatorInvocation) {
            "Handoff consumption must not authorize coordinator invocation"
        }
        require(!receipt.exposesDeployUiAction) { "Handoff consumption must not expose deploy UI" }
        require(!receipt.realVpsAccessAllowed) { "Handoff consumption must not allow real VPS access" }
        require(receipt.requiresSeparateAcquisitionExecutionBoundary) {
            "A separate transport-acquisition execution boundary must remain mandatory"
        }
        require(receipt.consumedAtEpochMillis <= receipt.authorizationExpiresAtEpochMillis) {
            "Transport-acquisition handoff consumption occurred after authorization expiry"
        }
        validateHashes(
            receipt.authorizationSha256,
            receipt.readinessSha256,
            receipt.compositionDescriptorSha256,
            receipt.serverIdentitySha256,
            receipt.runtimeMutationPermitSha256,
            receipt.candidateTransportAuthorizationSha256,
            receipt.boundedSftpCapabilityProfileSha256,
            receipt.consumptionReceiptSha256,
        )
        require(receipt.consumptionReceiptSha256 ==
            receiptSha256(receipt.copy(consumptionReceiptSha256 = ""))) {
            "Transport-acquisition handoff consumption receipt SHA-256 mismatch"
        }
    }

    private fun receiptSha256(
        receipt: SiteProductionDeploymentTransportAcquisitionHandoffConsumptionReceipt,
    ): String = sha256(
        buildString {
            append("contractVersion=").append(receipt.contractVersion).append('\n')
            append("status=").append(receipt.status.name).append('\n')
            append("singleUseConsumed=").append(receipt.singleUseConsumed).append('\n')
            append("productionTransportEnabled=").append(receipt.productionTransportEnabled).append('\n')
            append("authorizesTransport=").append(receipt.authorizesTransport).append('\n')
            append("authorizesTransportAcquisitionExecution=")
                .append(receipt.authorizesTransportAcquisitionExecution).append('\n')
            append("authorizesCredentialResolution=").append(receipt.authorizesCredentialResolution).append('\n')
            append("authorizesSshSessionAcquisition=").append(receipt.authorizesSshSessionAcquisition).append('\n')
            append("authorizesSftpChannelOpen=").append(receipt.authorizesSftpChannelOpen).append('\n')
            append("authorizesCoordinatorInvocation=").append(receipt.authorizesCoordinatorInvocation).append('\n')
            append("exposesDeployUiAction=").append(receipt.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(receipt.realVpsAccessAllowed).append('\n')
            append("requiresSeparateAcquisitionExecutionBoundary=")
                .append(receipt.requiresSeparateAcquisitionExecutionBoundary).append('\n')
            append("authorizationAttemptId=").append(receipt.authorizationAttemptId).append('\n')
            append("authorizationSha256=").append(receipt.authorizationSha256).append('\n')
            append("readinessSha256=").append(receipt.readinessSha256).append('\n')
            append("compositionDescriptorSha256=").append(receipt.compositionDescriptorSha256).append('\n')
            append("serverIdentitySha256=").append(receipt.serverIdentitySha256).append('\n')
            append("runtimeSessionId=").append(receipt.runtimeSessionId).append('\n')
            append("remoteHostIdentity=").append(receipt.remoteHostIdentity).append('\n')
            append("executionAttemptId=").append(receipt.executionAttemptId).append('\n')
            append("coordinatorInvocationId=").append(receipt.coordinatorInvocationId).append('\n')
            append("runtimeMutationPermitSha256=").append(receipt.runtimeMutationPermitSha256).append('\n')
            append("candidateTransportAuthorizationSha256=")
                .append(receipt.candidateTransportAuthorizationSha256).append('\n')
            append("boundedSftpImplementationId=").append(receipt.boundedSftpImplementationId).append('\n')
            append("boundedSftpCapabilityProfileSha256=")
                .append(receipt.boundedSftpCapabilityProfileSha256).append('\n')
            append("consumedAtEpochMillis=").append(receipt.consumedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=").append(receipt.authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256::matches)) {
            "Transport-acquisition handoff consumption hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
