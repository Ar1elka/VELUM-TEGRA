package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanRequest
import com.velumtegra.xuimobile.core.site.SiteWebServingStrategy
import java.security.MessageDigest

/**
 * Phase 11.68: non-executing serving-policy boundary that preserves the exact Site Deployer
 * certificate-reuse intent.
 *
 * NONE selects the already-supported HTTP plan directly.
 * REUSE_EXISTING_3X_UI_IF_PROVEN requires the validated Phase 11.67 composition result. A blocked
 * reuse result stays blocked; this boundary never silently downgrades a requested reuse/HTTPS path
 * to HTTP.
 */
internal object SiteProductionDeploymentAndroidServingPolicySelectionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun select(
        preparation: SiteDeployerLocalPreparationResult,
        staticPublicationEvidence: SiteStaticPublicationEvidence,
        certificateComposition:
            SiteProductionDeploymentCertificatePublicationCompositionResult? = null,
        strategy: SiteWebServingStrategy = SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1,
    ): SiteProductionDeploymentServingPolicySelectionResult {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        validateStaticPublicationEvidence(preparation, staticPublicationEvidence)

        val mode = preparation.remoteDeployPlan.certificate.mode
        val result = when (mode) {
            SiteCertificateReuseMode.NONE -> {
                require(certificateComposition == null) {
                    "Phase 11.68 certificate composition must be absent when certificate reuse was not requested"
                }
                val plan = SiteWebServingPublicationPlanBoundary.prepare(
                    SiteWebServingPublicationPlanRequest(
                        preparation = preparation,
                        staticPublicationEvidence = staticPublicationEvidence,
                        strategy = strategy,
                        certificateReference = null,
                    ),
                )
                require(plan.protocol == SiteWebServingProtocol.HTTP)
                baseResult(
                    preparation = preparation,
                    staticPublicationEvidence = staticPublicationEvidence,
                    strategy = strategy,
                    status = SiteProductionDeploymentServingPolicySelectionStatus
                        .HTTP_PUBLICATION_PLAN_READY_EXPLICIT_NO_CERTIFICATE_REUSE,
                    selectedProtocol = SiteWebServingProtocol.HTTP,
                    certificateCompositionSha256 = null,
                    publicationPlan = plan,
                )
            }

            SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN -> {
                val composition = requireNotNull(certificateComposition) {
                    "Phase 11.68 validated Phase 11.67 certificate composition is mandatory when reuse was requested"
                }
                SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.validate(composition)
                require(composition.preparationSha256 == preparation.preparationSha256) {
                    "Phase 11.68 certificate composition belongs to another preparation"
                }
                require(composition.staticTargetTreeSha256 == staticPublicationEvidence.finalTargetTreeSha256) {
                    "Phase 11.68 certificate composition belongs to another static publication tree"
                }
                require(composition.strategy == strategy) {
                    "Phase 11.68 certificate composition strategy differs from requested serving strategy"
                }

                when (composition.status) {
                    SiteProductionDeploymentCertificatePublicationCompositionStatus
                        .HTTPS_PUBLICATION_PLAN_READY_FROM_VALIDATED_EXISTING_3X_UI_CERTIFICATE -> {
                        val plan = requireNotNull(composition.publicationPlan)
                        require(plan.protocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE)
                        baseResult(
                            preparation = preparation,
                            staticPublicationEvidence = staticPublicationEvidence,
                            strategy = strategy,
                            status = SiteProductionDeploymentServingPolicySelectionStatus
                                .HTTPS_PUBLICATION_PLAN_READY_EXPLICIT_EXISTING_CERTIFICATE_REUSE,
                            selectedProtocol = SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE,
                            certificateCompositionSha256 = composition.compositionSha256,
                            publicationPlan = plan,
                        )
                    }

                    SiteProductionDeploymentCertificatePublicationCompositionStatus
                        .BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE ->
                        baseResult(
                            preparation = preparation,
                            staticPublicationEvidence = staticPublicationEvidence,
                            strategy = strategy,
                            status = SiteProductionDeploymentServingPolicySelectionStatus
                                .BLOCKED_REUSE_REQUESTED_NO_CONFIGURED_CERTIFICATE,
                            selectedProtocol = null,
                            certificateCompositionSha256 = composition.compositionSha256,
                            publicationPlan = null,
                        )

                    SiteProductionDeploymentCertificatePublicationCompositionStatus
                        .BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN ->
                        baseResult(
                            preparation = preparation,
                            staticPublicationEvidence = staticPublicationEvidence,
                            strategy = strategy,
                            status = SiteProductionDeploymentServingPolicySelectionStatus
                                .BLOCKED_REUSE_REQUESTED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN,
                            selectedProtocol = null,
                            certificateCompositionSha256 = composition.compositionSha256,
                            publicationPlan = null,
                        )

                    SiteProductionDeploymentCertificatePublicationCompositionStatus
                        .BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION ->
                        baseResult(
                            preparation = preparation,
                            staticPublicationEvidence = staticPublicationEvidence,
                            strategy = strategy,
                            status = SiteProductionDeploymentServingPolicySelectionStatus
                                .BLOCKED_REUSE_REQUESTED_REQUIRES_REVIEW_OR_RECONCILIATION,
                            selectedProtocol = null,
                            certificateCompositionSha256 = composition.compositionSha256,
                            publicationPlan = null,
                        )
                }
            }
        }

        return result.copy(selectionSha256 = selectionSha256(result)).also(::validate)
    }

    fun validate(result: SiteProductionDeploymentServingPolicySelectionResult) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(result.preparationSha256))
        require(sha256.matches(result.staticTargetTreeSha256))
        require(result.explicitUserIntentPreserved)
        require(!result.silentProtocolDowngradePerformed)
        require(!result.productionNetworkTouchedBySelection)
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
            SiteProductionDeploymentServingPolicySelectionStatus
                .HTTP_PUBLICATION_PLAN_READY_EXPLICIT_NO_CERTIFICATE_REUSE -> {
                require(result.requestedCertificateReuseMode == SiteCertificateReuseMode.NONE)
                require(result.requestedDomain == null)
                require(result.certificateCompositionSha256 == null)
                require(result.selectedProtocol == SiteWebServingProtocol.HTTP)
                val plan = requireNotNull(result.publicationPlan)
                SiteWebServingPublicationPlanBoundary.validate(plan)
                require(plan.protocol == SiteWebServingProtocol.HTTP)
                require(result.publicationPlanSelected)
            }

            SiteProductionDeploymentServingPolicySelectionStatus
                .HTTPS_PUBLICATION_PLAN_READY_EXPLICIT_EXISTING_CERTIFICATE_REUSE -> {
                require(result.requestedCertificateReuseMode == SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN)
                require(result.requestedDomain != null)
                require(result.certificateCompositionSha256?.matches(sha256) == true)
                require(result.selectedProtocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE)
                val plan = requireNotNull(result.publicationPlan)
                SiteWebServingPublicationPlanBoundary.validate(plan)
                require(plan.protocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE)
                require(result.publicationPlanSelected)
            }

            SiteProductionDeploymentServingPolicySelectionStatus
                .BLOCKED_REUSE_REQUESTED_NO_CONFIGURED_CERTIFICATE,
            SiteProductionDeploymentServingPolicySelectionStatus
                .BLOCKED_REUSE_REQUESTED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN,
            SiteProductionDeploymentServingPolicySelectionStatus
                .BLOCKED_REUSE_REQUESTED_REQUIRES_REVIEW_OR_RECONCILIATION -> {
                require(result.requestedCertificateReuseMode == SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN)
                require(result.requestedDomain != null)
                require(result.certificateCompositionSha256?.matches(sha256) == true)
                require(result.selectedProtocol == null)
                require(result.publicationPlan == null)
                require(!result.publicationPlanSelected)
            }
        }

        require(result.selectionSha256 == selectionSha256(result.copy(selectionSha256 = ""))) {
            "Phase 11.68 serving-policy selection SHA-256 mismatch"
        }
    }

    private fun baseResult(
        preparation: SiteDeployerLocalPreparationResult,
        staticPublicationEvidence: SiteStaticPublicationEvidence,
        strategy: SiteWebServingStrategy,
        status: SiteProductionDeploymentServingPolicySelectionStatus,
        selectedProtocol: SiteWebServingProtocol?,
        certificateCompositionSha256: String?,
        publicationPlan: com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan?,
    ) = SiteProductionDeploymentServingPolicySelectionResult(
        contractVersion = CONTRACT_VERSION,
        status = status,
        preparationSha256 = preparation.preparationSha256,
        staticTargetTreeSha256 = staticPublicationEvidence.finalTargetTreeSha256,
        requestedCertificateReuseMode = preparation.remoteDeployPlan.certificate.mode,
        requestedDomain = preparation.remoteDeployPlan.certificate.requiredDomain,
        strategy = strategy,
        selectedProtocol = selectedProtocol,
        certificateCompositionSha256 = certificateCompositionSha256,
        publicationPlan = publicationPlan,
        publicationPlanSelected = publicationPlan != null,
        explicitUserIntentPreserved = true,
        silentProtocolDowngradePerformed = false,
        productionNetworkTouchedBySelection = false,
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
        selectionSha256 = "",
    )

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

    private fun selectionSha256(
        result: SiteProductionDeploymentServingPolicySelectionResult,
    ): String = digest(buildString {
        append("phase=11.68\n")
        append("contractVersion=").append(result.contractVersion).append('\n')
        append("status=").append(result.status.name).append('\n')
        append("preparation=").append(result.preparationSha256).append('\n')
        append("staticTargetTree=").append(result.staticTargetTreeSha256).append('\n')
        append("reuseMode=").append(result.requestedCertificateReuseMode.name).append('\n')
        append("requestedDomain=").append(result.requestedDomain ?: "").append('\n')
        append("strategy=").append(result.strategy.name).append('\n')
        append("selectedProtocol=").append(result.selectedProtocol?.name ?: "").append('\n')
        append("certificateComposition=").append(result.certificateCompositionSha256 ?: "").append('\n')
        append("publicationPlan=").append(result.publicationPlan?.publicationPlanSha256 ?: "").append('\n')
        append("publicationPlanSelected=").append(result.publicationPlanSelected).append('\n')
        append("explicitUserIntentPreserved=").append(result.explicitUserIntentPreserved).append('\n')
        append("silentProtocolDowngradePerformed=").append(result.silentProtocolDowngradePerformed).append('\n')
        append("productionNetworkTouchedBySelection=").append(result.productionNetworkTouchedBySelection).append('\n')
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
