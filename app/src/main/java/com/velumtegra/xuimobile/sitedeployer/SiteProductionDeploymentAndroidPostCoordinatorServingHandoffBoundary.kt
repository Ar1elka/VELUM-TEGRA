package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingStrategy
import java.security.MessageDigest

/**
 * Phase 11.83 closes the first post-coordinator composition gap without adding live authority.
 *
 * The accepted Phase 11.80 coordinator result is the only source from which production static
 * publication evidence may be projected. A clean rollback remains blocked. A committed exact tree
 * may be passed into the existing Phase 11.68 explicit serving-policy selector, but this handoff
 * still cannot resolve credentials, open SSH, mutate nginx, reload a service or retry anything.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun prepare(
        preparation: SiteDeployerLocalPreparationResult,
        coordinatorAdmission: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission,
        coordinatorExecution: SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionResult,
        certificateComposition: SiteProductionDeploymentCertificatePublicationCompositionResult? = null,
        strategy: SiteWebServingStrategy = SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1,
    ): SiteProductionDeploymentPostCoordinatorServingHandoff {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
            .validateExecutionResult(coordinatorExecution, coordinatorAdmission, preparation)

        val handoff = when (coordinatorExecution.status) {
            SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                .COORDINATOR_ROLLED_BACK_CLEAN -> {
                require(certificateComposition == null) {
                    "Certificate composition is irrelevant after a clean coordinator rollback"
                }
                base(
                    status = SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                        .BLOCKED_COORDINATOR_ROLLED_BACK_CLEAN,
                    preparation = preparation,
                    coordinatorAdmission = coordinatorAdmission,
                    coordinatorExecution = coordinatorExecution,
                    staticPublicationEvidence = null,
                    servingPolicySelection = null,
                    requiresFreshPolicyBoundWebServingPreflight = false,
                )
            }

            SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                .COORDINATOR_COMMITTED_EXACT_STATIC_TREE -> {
                val evidence = committedEvidence(preparation, coordinatorExecution)
                when (preparation.remoteDeployPlan.certificate.mode) {
                    SiteCertificateReuseMode.NONE -> {
                        require(certificateComposition == null) {
                            "Certificate composition must be absent when reuse was not requested"
                        }
                        val selection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                            preparation = preparation,
                            staticPublicationEvidence = evidence,
                            strategy = strategy,
                        )
                        require(selection.publicationPlanSelected) {
                            "Explicit no-reuse serving policy must produce a publication plan"
                        }
                        base(
                            status = SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                                .READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT,
                            preparation = preparation,
                            coordinatorAdmission = coordinatorAdmission,
                            coordinatorExecution = coordinatorExecution,
                            staticPublicationEvidence = evidence,
                            servingPolicySelection = selection,
                            requiresFreshPolicyBoundWebServingPreflight = true,
                        )
                    }

                    SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN -> {
                        if (certificateComposition == null) {
                            base(
                                status = SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                                    .BLOCKED_CERTIFICATE_REUSE_REQUIRES_VALIDATED_COMPOSITION,
                                preparation = preparation,
                                coordinatorAdmission = coordinatorAdmission,
                                coordinatorExecution = coordinatorExecution,
                                staticPublicationEvidence = evidence,
                                servingPolicySelection = null,
                                requiresFreshPolicyBoundWebServingPreflight = false,
                            )
                        } else {
                            val selection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                                preparation = preparation,
                                staticPublicationEvidence = evidence,
                                certificateComposition = certificateComposition,
                                strategy = strategy,
                            )
                            val ready = selection.publicationPlanSelected
                            base(
                                status = if (ready) {
                                    SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                                        .READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT
                                } else {
                                    SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                                        .BLOCKED_BY_EXPLICIT_SERVING_POLICY
                                },
                                preparation = preparation,
                                coordinatorAdmission = coordinatorAdmission,
                                coordinatorExecution = coordinatorExecution,
                                staticPublicationEvidence = evidence,
                                servingPolicySelection = selection,
                                requiresFreshPolicyBoundWebServingPreflight = ready,
                            )
                        }
                    }
                }
            }
        }

        return handoff.copy(handoffSha256 = handoffSha256(handoff)).also(::validate)
    }

    fun validate(handoff: SiteProductionDeploymentPostCoordinatorServingHandoff) {
        require(handoff.contractVersion == CONTRACT_VERSION)
        listOf(
            handoff.phase1180AdmissionSha256,
            handoff.phase1180ExecutionResultSha256,
            handoff.localPreparationSha256,
            handoff.sourceTreeSha256,
            handoff.handoffSha256,
        ).forEach { require(sha256.matches(it)) }
        require(handoff.remoteHostIdentity.isNotBlank())
        require(handoff.targetRoot.startsWith("/"))
        require(!handoff.authorizesWebServingNetworkExecution)
        require(!handoff.authorizesWebServingMutation)
        require(!handoff.authorizesCoordinatorReinvocation)
        require(!handoff.automaticRetryAuthorized)

        when (handoff.status) {
            SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                .READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT -> {
                val evidence = requireNotNull(handoff.staticPublicationEvidence)
                val selection = requireNotNull(handoff.servingPolicySelection)
                SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
                require(handoff.servingPolicySelectionSha256 == selection.selectionSha256)
                require(selection.publicationPlanSelected)
                require(handoff.requiresFreshPolicyBoundWebServingPreflight)
                validateEvidenceBinding(handoff, evidence)
            }

            SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                .BLOCKED_COORDINATOR_ROLLED_BACK_CLEAN -> {
                require(handoff.staticPublicationEvidence == null)
                require(handoff.servingPolicySelection == null)
                require(handoff.servingPolicySelectionSha256 == null)
                require(!handoff.requiresFreshPolicyBoundWebServingPreflight)
            }

            SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                .BLOCKED_CERTIFICATE_REUSE_REQUIRES_VALIDATED_COMPOSITION -> {
                val evidence = requireNotNull(handoff.staticPublicationEvidence)
                require(handoff.servingPolicySelection == null)
                require(handoff.servingPolicySelectionSha256 == null)
                require(!handoff.requiresFreshPolicyBoundWebServingPreflight)
                validateEvidenceBinding(handoff, evidence)
            }

            SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                .BLOCKED_BY_EXPLICIT_SERVING_POLICY -> {
                val evidence = requireNotNull(handoff.staticPublicationEvidence)
                val selection = requireNotNull(handoff.servingPolicySelection)
                SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
                require(handoff.servingPolicySelectionSha256 == selection.selectionSha256)
                require(!selection.publicationPlanSelected)
                require(!handoff.requiresFreshPolicyBoundWebServingPreflight)
                validateEvidenceBinding(handoff, evidence)
            }
        }

        require(handoff.handoffSha256 == handoffSha256(handoff.copy(handoffSha256 = ""))) {
            "Phase 11.83 post-coordinator serving handoff SHA-256 mismatch"
        }
    }

    internal fun handoffSha256ForTest(
        handoffWithoutSha: SiteProductionDeploymentPostCoordinatorServingHandoff,
    ): String = handoffSha256(handoffWithoutSha.copy(handoffSha256 = ""))

    private fun committedEvidence(
        preparation: SiteDeployerLocalPreparationResult,
        execution: SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionResult,
    ): SiteStaticPublicationEvidence {
        val transaction = execution.staticFileTransactionResult
        val finalTree = requireNotNull(transaction.finalTargetTreeSha256) {
            "Committed Phase 11.80 result must expose the exact final target tree"
        }
        require(finalTree == preparation.remoteDeployPlan.sourceTreeSha256)
        require(transaction.remoteResidualStateClean)
        return SiteStaticPublicationEvidence(
            preparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            finalTargetTreeSha256 = finalTree,
            committedClean = true,
            remoteResidualStateClean = true,
        )
    }

    private fun base(
        status: SiteProductionDeploymentPostCoordinatorServingHandoffStatus,
        preparation: SiteDeployerLocalPreparationResult,
        coordinatorAdmission: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission,
        coordinatorExecution: SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionResult,
        staticPublicationEvidence: SiteStaticPublicationEvidence?,
        servingPolicySelection: SiteProductionDeploymentServingPolicySelectionResult?,
        requiresFreshPolicyBoundWebServingPreflight: Boolean,
    ) = SiteProductionDeploymentPostCoordinatorServingHandoff(
        contractVersion = CONTRACT_VERSION,
        status = status,
        phase1180AdmissionSha256 = coordinatorAdmission.admissionSha256,
        phase1180ExecutionResultSha256 = coordinatorExecution.executionResultSha256,
        localPreparationSha256 = preparation.preparationSha256,
        sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
        remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
        targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
        staticPublicationEvidence = staticPublicationEvidence,
        servingPolicySelection = servingPolicySelection,
        servingPolicySelectionSha256 = servingPolicySelection?.selectionSha256,
        requiresFreshPolicyBoundWebServingPreflight = requiresFreshPolicyBoundWebServingPreflight,
        authorizesWebServingNetworkExecution = false,
        authorizesWebServingMutation = false,
        authorizesCoordinatorReinvocation = false,
        automaticRetryAuthorized = false,
        handoffSha256 = "",
    )

    private fun validateEvidenceBinding(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        evidence: SiteStaticPublicationEvidence,
    ) {
        require(evidence.preparationSha256 == handoff.localPreparationSha256)
        require(evidence.remoteHostIdentity == handoff.remoteHostIdentity)
        require(evidence.targetRoot == handoff.targetRoot)
        require(evidence.finalTargetTreeSha256 == handoff.sourceTreeSha256)
        require(evidence.committedClean)
        require(evidence.remoteResidualStateClean)
    }

    private fun handoffSha256(
        value: SiteProductionDeploymentPostCoordinatorServingHandoff,
    ): String = digest(buildString {
        append("phase=11.83\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1180Admission=").append(value.phase1180AdmissionSha256).append('\n')
        append("phase1180Execution=").append(value.phase1180ExecutionResultSha256).append('\n')
        append("localPreparation=").append(value.localPreparationSha256).append('\n')
        append("sourceTree=").append(value.sourceTreeSha256).append('\n')
        append("remoteHost=").append(value.remoteHostIdentity).append('\n')
        append("targetRoot=").append(value.targetRoot).append('\n')
        append("staticEvidencePreparation=")
            .append(value.staticPublicationEvidence?.preparationSha256 ?: "").append('\n')
        append("staticEvidenceTree=")
            .append(value.staticPublicationEvidence?.finalTargetTreeSha256 ?: "").append('\n')
        append("staticEvidenceCommittedClean=")
            .append(value.staticPublicationEvidence?.committedClean ?: false).append('\n')
        append("staticEvidenceResidualClean=")
            .append(value.staticPublicationEvidence?.remoteResidualStateClean ?: false).append('\n')
        append("servingPolicySelection=").append(value.servingPolicySelectionSha256 ?: "").append('\n')
        append("requiresFreshPreflight=").append(value.requiresFreshPolicyBoundWebServingPreflight).append('\n')
        append("authorizesNetwork=").append(value.authorizesWebServingNetworkExecution).append('\n')
        append("authorizesMutation=").append(value.authorizesWebServingMutation).append('\n')
        append("authorizesCoordinatorReinvocation=").append(value.authorizesCoordinatorReinvocation).append('\n')
        append("automaticRetryAuthorized=").append(value.automaticRetryAuthorized).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
