package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteExactDomainCertificateReuseBindingBoundary
import com.velumtegra.xuimobile.core.site.SiteExactDomainCertificateReuseBindingStatus
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityReport
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanRequest
import com.velumtegra.xuimobile.core.site.SiteWebServingStrategy
import java.security.MessageDigest

/**
 * Phase 11.67: non-executing production composition gate that requires a validated Phase 11.65
 * real-VPS proof, consumes the Phase 11.66 exact-domain binding result, and only then may select the
 * already-reviewed Phase 11.56 HTTPS publication-plan logic.
 *
 * This object has no SSH/session/coordinator dependency and performs no network or remote mutation.
 */
internal object SiteProductionDeploymentAndroidCertificatePublicationCompositionGate {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun compose(
        preparation: SiteDeployerLocalPreparationResult,
        staticPublicationEvidence: SiteStaticPublicationEvidence,
        eligibilityExecutionProof: SiteProductionDeploymentRealVpsExisting3xUiCertificateReuseEligibilityExecutionProof,
        strategy: SiteWebServingStrategy = SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1,
    ): SiteProductionDeploymentCertificatePublicationCompositionResult {
        SiteProductionDeploymentAndroidRealVpsExisting3xUiCertificateReuseEligibilityExecutionBoundary
            .validateProof(eligibilityExecutionProof)
        SiteDeployerLocalPreparationBoundary.validate(preparation)

        require(eligibilityExecutionProof.remoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity) {
            "Phase 11.67 real-VPS certificate proof belongs to a different deployment host"
        }
        val expectedEligibilityPlan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare(
            preparation.remoteDeployPlan.remoteHostIdentity,
        )
        require(eligibilityExecutionProof.eligibilityPlanSha256 == expectedEligibilityPlan.eligibilityPlanSha256) {
            "Phase 11.67 real-VPS proof is not bound to the current Phase 11.65 eligibility plan"
        }

        return composeValidated(
            preparation = preparation,
            staticPublicationEvidence = staticPublicationEvidence,
            eligibilityReport = eligibilityExecutionProof.eligibilityReport,
            observedRemoteHostIdentity = eligibilityExecutionProof.remoteHostIdentity,
            realVpsExecutionProofSha256 = eligibilityExecutionProof.executionProofSha256,
            strategy = strategy,
        )
    }

    /**
     * Internal deterministic seam used after the caller has validated the Phase 11.65 execution
     * proof. It exists so the positive composition path can be regression-tested without networking.
     */
    internal fun composeValidated(
        preparation: SiteDeployerLocalPreparationResult,
        staticPublicationEvidence: SiteStaticPublicationEvidence,
        eligibilityReport: SiteExisting3xUiCertificateReuseEligibilityReport,
        observedRemoteHostIdentity: String,
        realVpsExecutionProofSha256: String,
        strategy: SiteWebServingStrategy = SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1,
    ): SiteProductionDeploymentCertificatePublicationCompositionResult {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteExisting3xUiCertificateReuseEligibilityBoundary.validateReport(eligibilityReport)
        require(sha256.matches(realVpsExecutionProofSha256)) {
            "Phase 11.67 real-VPS execution-proof SHA-256 is invalid"
        }
        validateStaticPublicationEvidence(preparation, staticPublicationEvidence)

        val binding = SiteExactDomainCertificateReuseBindingBoundary.evaluate(
            preparation = preparation,
            eligibilityReport = eligibilityReport,
            observedRemoteHostIdentity = observedRemoteHostIdentity,
        )

        val publicationPlan = when (binding.status) {
            SiteExactDomainCertificateReuseBindingStatus.BOUND_FOR_EXACT_DOMAIN_HTTPS_PLANNING ->
                SiteWebServingPublicationPlanBoundary.prepare(
                    SiteWebServingPublicationPlanRequest(
                        preparation = preparation,
                        staticPublicationEvidence = staticPublicationEvidence,
                        strategy = strategy,
                        certificateReference = requireNotNull(binding.certificateReference),
                    ),
                )
            SiteExactDomainCertificateReuseBindingStatus.BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE,
            SiteExactDomainCertificateReuseBindingStatus.BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN,
            SiteExactDomainCertificateReuseBindingStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION -> null
        }

        val status = when (binding.status) {
            SiteExactDomainCertificateReuseBindingStatus.BOUND_FOR_EXACT_DOMAIN_HTTPS_PLANNING ->
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .HTTPS_PUBLICATION_PLAN_READY_FROM_VALIDATED_EXISTING_3X_UI_CERTIFICATE
            SiteExactDomainCertificateReuseBindingStatus.BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE ->
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE
            SiteExactDomainCertificateReuseBindingStatus.BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN ->
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN
            SiteExactDomainCertificateReuseBindingStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION ->
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION
        }

        publicationPlan?.let { plan ->
            require(plan.protocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE)
            require(plan.remoteHostIdentity == observedRemoteHostIdentity)
            require(plan.preparationSha256 == preparation.preparationSha256)
            require(plan.domain == binding.requiredDomain)
            require(plan.certificateSha256 == binding.certificateReference?.certificateSha256)
            require(plan.certificatePath == binding.certificateReference?.certificatePath)
            require(plan.privateKeyPath == binding.certificateReference?.privateKeyPath)
        }

        val base = SiteProductionDeploymentCertificatePublicationCompositionResult(
            contractVersion = CONTRACT_VERSION,
            status = status,
            preparationSha256 = preparation.preparationSha256,
            staticTargetTreeSha256 = staticPublicationEvidence.finalTargetTreeSha256,
            realVpsExecutionProofSha256 = realVpsExecutionProofSha256,
            eligibilityReportSha256 = eligibilityReport.eligibilityReportSha256,
            bindingReport = binding,
            strategy = strategy,
            publicationPlan = publicationPlan,
            realVpsExecutionProofValidated = true,
            publicationPlanSelected = publicationPlan != null,
            productionNetworkTouchedByComposition = false,
            remoteMutationPerformed = false,
            certificateMutationAuthorized = false,
            tlsConfigurationAuthorized = false,
            nginxMutationAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            privateKeyContentReadAuthorized = false,
            automaticRetryAuthorized = false,
            coordinatorInvoked = false,
            exposesDeployUiAction = false,
            compositionSha256 = "",
        )
        return base.copy(compositionSha256 = compositionSha256(base)).also(::validate)
    }

    fun validate(result: SiteProductionDeploymentCertificatePublicationCompositionResult) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(result.preparationSha256))
        require(sha256.matches(result.staticTargetTreeSha256))
        require(sha256.matches(result.realVpsExecutionProofSha256))
        require(sha256.matches(result.eligibilityReportSha256))
        SiteExactDomainCertificateReuseBindingBoundary.validate(result.bindingReport)
        require(result.bindingReport.preparationSha256 == result.preparationSha256)
        require(result.bindingReport.eligibilityReportSha256 == result.eligibilityReportSha256)
        require(result.realVpsExecutionProofValidated)
        require(!result.productionNetworkTouchedByComposition)
        require(!result.remoteMutationPerformed)
        require(!result.certificateMutationAuthorized)
        require(!result.tlsConfigurationAuthorized)
        require(!result.nginxMutationAuthorized)
        require(!result.dnsMutationAuthorized)
        require(!result.firewallMutationAuthorized)
        require(!result.packageInstallAuthorized)
        require(!result.privateKeyContentReadAuthorized)
        require(!result.automaticRetryAuthorized)
        require(!result.coordinatorInvoked)
        require(!result.exposesDeployUiAction)

        when (result.status) {
            SiteProductionDeploymentCertificatePublicationCompositionStatus
                .HTTPS_PUBLICATION_PLAN_READY_FROM_VALIDATED_EXISTING_3X_UI_CERTIFICATE -> {
                require(
                    result.bindingReport.status ==
                        SiteExactDomainCertificateReuseBindingStatus.BOUND_FOR_EXACT_DOMAIN_HTTPS_PLANNING,
                )
                val plan = requireNotNull(result.publicationPlan)
                SiteWebServingPublicationPlanBoundary.validate(plan)
                require(result.publicationPlanSelected)
                require(plan.protocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE)
                require(plan.publicationPlanSha256.isNotBlank())
            }
            SiteProductionDeploymentCertificatePublicationCompositionStatus
                .BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE -> {
                require(
                    result.bindingReport.status ==
                        SiteExactDomainCertificateReuseBindingStatus.BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE,
                )
                require(result.publicationPlan == null && !result.publicationPlanSelected)
            }
            SiteProductionDeploymentCertificatePublicationCompositionStatus
                .BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN -> {
                require(
                    result.bindingReport.status ==
                        SiteExactDomainCertificateReuseBindingStatus.BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN,
                )
                require(result.publicationPlan == null && !result.publicationPlanSelected)
            }
            SiteProductionDeploymentCertificatePublicationCompositionStatus
                .BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION -> {
                require(
                    result.bindingReport.status ==
                        SiteExactDomainCertificateReuseBindingStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
                )
                require(result.publicationPlan == null && !result.publicationPlanSelected)
            }
        }
        require(result.compositionSha256 == compositionSha256(result.copy(compositionSha256 = "")))
    }

    private fun validateStaticPublicationEvidence(
        preparation: SiteDeployerLocalPreparationResult,
        evidence: SiteStaticPublicationEvidence,
    ) {
        require(evidence.preparationSha256 == preparation.preparationSha256)
        require(evidence.remoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity)
        require(evidence.targetRoot == preparation.remoteDeployPlan.publish.targetRoot)
        require(evidence.finalTargetTreeSha256 == preparation.remoteDeployPlan.sourceTreeSha256)
        require(evidence.committedClean)
        require(evidence.remoteResidualStateClean)
        require(!preparation.serviceBinding.appliedByCurrentDeployContract)
    }

    private fun compositionSha256(
        result: SiteProductionDeploymentCertificatePublicationCompositionResult,
    ): String = digest(buildString {
        append("phase=11.67\n")
        append("contractVersion=").append(result.contractVersion).append('\n')
        append("status=").append(result.status.name).append('\n')
        append("preparation=").append(result.preparationSha256).append('\n')
        append("staticTargetTree=").append(result.staticTargetTreeSha256).append('\n')
        append("executionProof=").append(result.realVpsExecutionProofSha256).append('\n')
        append("eligibilityReport=").append(result.eligibilityReportSha256).append('\n')
        append("bindingReport=").append(result.bindingReport.bindingReportSha256).append('\n')
        append("bindingStatus=").append(result.bindingReport.status.name).append('\n')
        append("strategy=").append(result.strategy.name).append('\n')
        append("publicationPlan=").append(result.publicationPlan?.publicationPlanSha256 ?: "").append('\n')
        append("realVpsExecutionProofValidated=").append(result.realVpsExecutionProofValidated).append('\n')
        append("publicationPlanSelected=").append(result.publicationPlanSelected).append('\n')
        append("productionNetworkTouchedByComposition=").append(result.productionNetworkTouchedByComposition).append('\n')
        append("remoteMutationPerformed=").append(result.remoteMutationPerformed).append('\n')
        append("certificateMutationAuthorized=").append(result.certificateMutationAuthorized).append('\n')
        append("tlsConfigurationAuthorized=").append(result.tlsConfigurationAuthorized).append('\n')
        append("nginxMutationAuthorized=").append(result.nginxMutationAuthorized).append('\n')
        append("dnsMutationAuthorized=").append(result.dnsMutationAuthorized).append('\n')
        append("firewallMutationAuthorized=").append(result.firewallMutationAuthorized).append('\n')
        append("packageInstallAuthorized=").append(result.packageInstallAuthorized).append('\n')
        append("privateKeyContentReadAuthorized=").append(result.privateKeyContentReadAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(result.automaticRetryAuthorized).append('\n')
        append("coordinatorInvoked=").append(result.coordinatorInvoked).append('\n')
        append("exposesDeployUiAction=").append(result.exposesDeployUiAction).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
