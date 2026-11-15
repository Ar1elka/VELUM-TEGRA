package com.velumtegra.xuimobile.sitedeployer

import java.security.MessageDigest

internal enum class SiteProductionDeploymentPostCoordinatorHttpsServingStatus {
    COMPLETE_EXISTING_CERTIFICATE_HTTPS_TLS_SERVING_PATH_VERIFIED,
}

/**
 * Phase 11.98 release receipt. It binds the accepted exact-static-tree coordinator result to the
 * validated existing-certificate composition, the exact Phase 11.91 reload, the fresh post-reload
 * certificate proof and the final Phase 11.97 TLS/HTTPS verification result.
 */
internal data class SiteProductionDeploymentPostCoordinatorHttpsServingReceipt(
    val contractVersion: Int,
    val status: SiteProductionDeploymentPostCoordinatorHttpsServingStatus,
    val preparationSha256: String,
    val phase1180AdmissionSha256: String,
    val phase1180ExecutionResultSha256: String,
    val initialCertificateEligibilityExecutionProofSha256: String,
    val certificateCompositionSha256: String,
    val servingPolicySelectionSha256: String,
    val phase1191ExecutionResultSha256: String,
    val freshPostReloadCertificateEligibilityExecutionProofSha256: String,
    val phase1197VerificationPlanSha256: String,
    val phase1197ExecutionResultSha256: String,
    val publicationPlanSha256: String,
    val remoteHostIdentity: String,
    val domain: String,
    val port: Int,
    val tlsProtocol: String,
    val peerLeafCertificateDerSha256: String,
    val exactBodySha256: String,
    val completeHttpsTlsServingPathVerified: Boolean,
    val finalVerificationRemoteMutationPerformed: Boolean,
    val certificateMutationPerformed: Boolean,
    val privateKeyContentReadPerformed: Boolean,
    val coordinatorReinvoked: Boolean,
    val staticPublicationReplayPerformed: Boolean,
    val automaticRetryPerformed: Boolean,
    val silentProtocolDowngradePerformed: Boolean,
    val completedAtEpochMillis: Long,
    val receiptSha256: String,
)

internal object SiteProductionDeploymentAndroidPostCoordinatorHttpsServingReceiptBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun completeAfterValidatedChain(
        preparationSha256: String,
        phase1180AdmissionSha256: String,
        phase1180ExecutionResultSha256: String,
        initialCertificateEligibilityExecutionProofSha256: String,
        certificateCompositionSha256: String,
        servingPolicySelectionSha256: String,
        phase1191ExecutionResultSha256: String,
        freshPostReloadCertificateEligibilityExecutionProofSha256: String,
        verificationPlan: SiteProductionDeploymentHttpsTlsServingVerificationPlan,
        verificationResult: SiteProductionDeploymentHttpsTlsServingVerificationResult,
        completedAtEpochMillis: Long,
    ): SiteProductionDeploymentPostCoordinatorHttpsServingReceipt {
        SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.validatePlan(verificationPlan)
        SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.validateResult(verificationResult)
        listOf(
            preparationSha256,
            phase1180AdmissionSha256,
            phase1180ExecutionResultSha256,
            initialCertificateEligibilityExecutionProofSha256,
            certificateCompositionSha256,
            servingPolicySelectionSha256,
            phase1191ExecutionResultSha256,
            freshPostReloadCertificateEligibilityExecutionProofSha256,
        ).forEach { require(sha256.matches(it)) }
        require(verificationPlan.preparationSha256 == preparationSha256)
        require(verificationPlan.certificateCompositionSha256 == certificateCompositionSha256)
        require(verificationPlan.servingPolicySelectionSha256 == servingPolicySelectionSha256)
        require(verificationPlan.postCoordinatorNginxReloadExecutionResultSha256 == phase1191ExecutionResultSha256)
        require(
            verificationPlan.freshCertificateEligibilityExecutionProofSha256 ==
                freshPostReloadCertificateEligibilityExecutionProofSha256,
        )
        require(verificationResult.verificationPlanSha256 == verificationPlan.verificationPlanSha256)
        require(verificationResult.preparationSha256 == preparationSha256)
        require(verificationResult.certificateCompositionSha256 == certificateCompositionSha256)
        require(verificationResult.servingPolicySelectionSha256 == servingPolicySelectionSha256)
        require(verificationResult.postCoordinatorNginxReloadExecutionResultSha256 == phase1191ExecutionResultSha256)
        require(
            verificationResult.freshCertificateEligibilityExecutionProofSha256 ==
                freshPostReloadCertificateEligibilityExecutionProofSha256,
        )
        require(
            verificationResult.status ==
                SiteProductionDeploymentHttpsTlsServingVerificationStatus
                    .HTTPS_TLS_IDENTITY_AND_EXACT_INDEX_VERIFIED,
        )
        require(verificationResult.publicationPlanSha256 == verificationPlan.publicationPlanSha256)
        require(verificationResult.remoteHostIdentity == verificationPlan.remoteHostIdentity)
        require(verificationResult.domain == verificationPlan.domain)
        require(verificationResult.port == verificationPlan.port)
        require(verificationResult.exactBodySha256Verified)
        require(verificationResult.observedBodySha256 == verificationPlan.expectedBodySha256)
        require(!verificationResult.remoteMutationPerformed)
        require(!verificationResult.certificateMutationPerformed)
        require(!verificationResult.privateKeyContentReadPerformed)
        require(!verificationResult.coordinatorReinvoked)
        require(!verificationResult.staticPublicationReplayPerformed)
        require(!verificationResult.automaticRetryPerformed)
        require(completedAtEpochMillis >= verificationResult.executedAtEpochMillis)

        val base = SiteProductionDeploymentPostCoordinatorHttpsServingReceipt(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPostCoordinatorHttpsServingStatus
                .COMPLETE_EXISTING_CERTIFICATE_HTTPS_TLS_SERVING_PATH_VERIFIED,
            preparationSha256 = preparationSha256,
            phase1180AdmissionSha256 = phase1180AdmissionSha256,
            phase1180ExecutionResultSha256 = phase1180ExecutionResultSha256,
            initialCertificateEligibilityExecutionProofSha256 = initialCertificateEligibilityExecutionProofSha256,
            certificateCompositionSha256 = certificateCompositionSha256,
            servingPolicySelectionSha256 = servingPolicySelectionSha256,
            phase1191ExecutionResultSha256 = phase1191ExecutionResultSha256,
            freshPostReloadCertificateEligibilityExecutionProofSha256 =
                freshPostReloadCertificateEligibilityExecutionProofSha256,
            phase1197VerificationPlanSha256 = verificationPlan.verificationPlanSha256,
            phase1197ExecutionResultSha256 = verificationResult.executionResultSha256,
            publicationPlanSha256 = verificationPlan.publicationPlanSha256,
            remoteHostIdentity = verificationPlan.remoteHostIdentity,
            domain = verificationPlan.domain,
            port = verificationPlan.port,
            tlsProtocol = verificationResult.tlsProtocol,
            peerLeafCertificateDerSha256 = verificationResult.peerLeafCertificateDerSha256,
            exactBodySha256 = verificationResult.observedBodySha256,
            completeHttpsTlsServingPathVerified = true,
            finalVerificationRemoteMutationPerformed = false,
            certificateMutationPerformed = false,
            privateKeyContentReadPerformed = false,
            coordinatorReinvoked = false,
            staticPublicationReplayPerformed = false,
            automaticRetryPerformed = false,
            silentProtocolDowngradePerformed = false,
            completedAtEpochMillis = completedAtEpochMillis,
            receiptSha256 = "",
        )
        return base.copy(receiptSha256 = receiptSha256(base)).also(::validate)
    }

    fun validate(receipt: SiteProductionDeploymentPostCoordinatorHttpsServingReceipt) {
        require(receipt.contractVersion == CONTRACT_VERSION)
        require(
            receipt.status == SiteProductionDeploymentPostCoordinatorHttpsServingStatus
                .COMPLETE_EXISTING_CERTIFICATE_HTTPS_TLS_SERVING_PATH_VERIFIED,
        )
        listOf(
            receipt.preparationSha256,
            receipt.phase1180AdmissionSha256,
            receipt.phase1180ExecutionResultSha256,
            receipt.initialCertificateEligibilityExecutionProofSha256,
            receipt.certificateCompositionSha256,
            receipt.servingPolicySelectionSha256,
            receipt.phase1191ExecutionResultSha256,
            receipt.freshPostReloadCertificateEligibilityExecutionProofSha256,
            receipt.phase1197VerificationPlanSha256,
            receipt.phase1197ExecutionResultSha256,
            receipt.publicationPlanSha256,
            receipt.peerLeafCertificateDerSha256,
            receipt.exactBodySha256,
            receipt.receiptSha256,
        ).forEach { require(sha256.matches(it)) }
        require(receipt.remoteHostIdentity.isNotBlank())
        require(receipt.domain.isNotBlank())
        require(receipt.port in 1..65535)
        require(receipt.tlsProtocol == "TLSv1.3" || receipt.tlsProtocol == "TLSv1.2")
        require(receipt.completeHttpsTlsServingPathVerified)
        require(!receipt.finalVerificationRemoteMutationPerformed)
        require(!receipt.certificateMutationPerformed)
        require(!receipt.privateKeyContentReadPerformed)
        require(!receipt.coordinatorReinvoked)
        require(!receipt.staticPublicationReplayPerformed)
        require(!receipt.automaticRetryPerformed)
        require(!receipt.silentProtocolDowngradePerformed)
        require(receipt.completedAtEpochMillis > 0L)
        require(receipt.receiptSha256 == receiptSha256(receipt.copy(receiptSha256 = ""))) {
            "Phase 11.98 HTTPS serving receipt SHA-256 mismatch"
        }
    }

    private fun receiptSha256(
        value: SiteProductionDeploymentPostCoordinatorHttpsServingReceipt,
    ): String = digest(buildString {
        append("phase=11.98\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("preparation=").append(value.preparationSha256).append('\n')
        append("phase1180Admission=").append(value.phase1180AdmissionSha256).append('\n')
        append("phase1180Execution=").append(value.phase1180ExecutionResultSha256).append('\n')
        append("initialCertificateProof=").append(value.initialCertificateEligibilityExecutionProofSha256).append('\n')
        append("certificateComposition=").append(value.certificateCompositionSha256).append('\n')
        append("servingPolicySelection=").append(value.servingPolicySelectionSha256).append('\n')
        append("phase1191Execution=").append(value.phase1191ExecutionResultSha256).append('\n')
        append("freshPostReloadCertificateProof=")
            .append(value.freshPostReloadCertificateEligibilityExecutionProofSha256).append('\n')
        append("phase1197Plan=").append(value.phase1197VerificationPlanSha256).append('\n')
        append("phase1197Execution=").append(value.phase1197ExecutionResultSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("host=").append(value.remoteHostIdentity).append('\n')
        append("domain=").append(value.domain).append('\n')
        append("port=").append(value.port).append('\n')
        append("tlsProtocol=").append(value.tlsProtocol).append('\n')
        append("peerLeafDer=").append(value.peerLeafCertificateDerSha256).append('\n')
        append("exactBody=").append(value.exactBodySha256).append('\n')
        append("completeHttpsTlsServingPathVerified=").append(value.completeHttpsTlsServingPathVerified).append('\n')
        append("finalVerificationRemoteMutationPerformed=")
            .append(value.finalVerificationRemoteMutationPerformed).append('\n')
        append("certificateMutationPerformed=").append(value.certificateMutationPerformed).append('\n')
        append("privateKeyContentReadPerformed=").append(value.privateKeyContentReadPerformed).append('\n')
        append("coordinatorReinvoked=").append(value.coordinatorReinvoked).append('\n')
        append("staticPublicationReplayPerformed=").append(value.staticPublicationReplayPerformed).append('\n')
        append("automaticRetryPerformed=").append(value.automaticRetryPerformed).append('\n')
        append("silentProtocolDowngradePerformed=").append(value.silentProtocolDowngradePerformed).append('\n')
        append("completedAt=").append(value.completedAtEpochMillis).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
