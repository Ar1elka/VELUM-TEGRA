package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightReport
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightStatus
import java.security.MessageDigest

/**
 * Phase 11.70: pure local gate immediately before the old Phase 11.58 mutation-preparation
 * boundary. Production callers must provide the exact validated Phase 11.69 policy-bound preflight
 * execution result; a raw plan + raw preflight report is not enough on this path.
 *
 * READY creates only the deterministic rollback-aware Phase 11.58 transaction preparation.
 * BLOCKED creates no transaction preparation. Neither outcome grants config-write or nginx-reload
 * authority.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val transactionId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution:
            SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        mutationTransactionId: String,
    ): SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult {
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
            .validateExecutionResult(policyBoundPreflightExecution)
        require(selection.publicationPlanSelected)
        val plan = requireNotNull(selection.publicationPlan)
        val selectedProtocol = requireNotNull(selection.selectedProtocol)
        require(plan.protocol == selectedProtocol)
        require(
            policyBoundPreflightExecution.servingPolicySelectionSha256 ==
                selection.selectionSha256,
        ) { "Phase 11.70 preflight proof belongs to another serving-policy selection" }
        require(policyBoundPreflightExecution.publicationPlanSha256 == plan.publicationPlanSha256) {
            "Phase 11.70 preflight proof belongs to another publication plan"
        }
        require(policyBoundPreflightExecution.selectedProtocol == selectedProtocol) {
            "Phase 11.70 preflight proof belongs to another selected protocol"
        }

        val admission =
            SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                .admit(selection)
        require(
            admission.status ==
                SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_READ_ONLY_PREFLIGHT_EXECUTION,
        )
        require(admission.admissionSha256 == policyBoundPreflightExecution.admissionSha256) {
            "Phase 11.70 preflight proof belongs to another policy-bound admission"
        }

        val report = policyBoundPreflightExecution.preflightExecutionProof.preflightReport
        require(report.preflightSha256 ==
            policyBoundPreflightExecution.preflightExecutionProof.preflightReport.preflightSha256)
        require(report.publicationPlanSha256 == plan.publicationPlanSha256)

        return prepareValidated(
            selection = selection,
            admission = admission,
            readOnlyPreflight = report,
            policyBoundPreflightExecutionResultSha256 =
                policyBoundPreflightExecution.executionResultSha256,
            mutationTransactionId = mutationTransactionId,
        ).also {
            validateAgainst(it, selection, policyBoundPreflightExecution)
        }
    }

    /**
     * Deterministic seam used after the Phase 11.69 execution proof has already been validated.
     * It never opens a session or performs remote work.
     */
    internal fun prepareValidated(
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        admission: SiteProductionDeploymentPolicyBoundWebServingPreflightAdmission,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
        policyBoundPreflightExecutionResultSha256: String,
        mutationTransactionId: String,
    ): SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult {
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
            .validateAdmission(admission)
        SiteWebServingReadOnlyPreflightBoundary.validateReport(readOnlyPreflight)
        require(transactionId.matches(mutationTransactionId)) {
            "Phase 11.70 mutation transaction id must be canonical"
        }
        require(sha256.matches(policyBoundPreflightExecutionResultSha256)) {
            "Phase 11.70 policy-bound preflight execution SHA-256 is invalid"
        }
        require(
            admission.status ==
                SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_READ_ONLY_PREFLIGHT_EXECUTION,
        )
        require(admission.servingPolicySelectionSha256 == selection.selectionSha256)
        require(selection.publicationPlanSelected)
        val plan = requireNotNull(selection.publicationPlan)
        val selectedProtocol = requireNotNull(selection.selectedProtocol)
        require(plan.protocol == selectedProtocol)
        require(admission.publicationPlanSha256 == plan.publicationPlanSha256)
        require(admission.selectedProtocol == selectedProtocol)
        require(readOnlyPreflight.publicationPlanSha256 == plan.publicationPlanSha256)

        val mutationPreparation =
            if (readOnlyPreflight.status ==
                SiteWebServingReadOnlyPreflightStatus.READY_FOR_SEPARATE_CONFIG_MUTATION_BOUNDARY
            ) {
                SiteWebServingConfigMutationPreparationBoundary.prepare(
                    SiteWebServingConfigMutationPreparationRequest(
                        publicationPlan = plan,
                        readOnlyPreflight = readOnlyPreflight,
                        mutationTransactionId = mutationTransactionId,
                    ),
                )
            } else {
                null
            }

        val status = if (mutationPreparation != null) {
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                .READY_FOR_SEPARATE_CONFIG_MUTATION_AUTHORITY_BOUNDARY
        } else {
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                .BLOCKED_BY_LIVE_WEB_SERVING_PREFLIGHT
        }

        val base = SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult(
            contractVersion = CONTRACT_VERSION,
            status = status,
            servingPolicySelectionSha256 = selection.selectionSha256,
            policyBoundPreflightAdmissionSha256 = admission.admissionSha256,
            policyBoundPreflightExecutionResultSha256 =
                policyBoundPreflightExecutionResultSha256,
            publicationPlanSha256 = plan.publicationPlanSha256,
            selectedProtocol = selectedProtocol,
            readOnlyPreflightSha256 = readOnlyPreflight.preflightSha256,
            readOnlyPreflightStatus = readOnlyPreflight.status,
            mutationTransactionId = mutationTransactionId,
            mutationPreparation = mutationPreparation,
            exactPolicyPreflightBindingVerified = true,
            mutationPreparationCreated = mutationPreparation != null,
            productionNetworkTouchedByPreparation = false,
            remoteMutationPerformed = false,
            configMutationAuthorized = false,
            webServerReloadAuthorized = false,
            certificateMutationAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            privateKeyContentReadAuthorized = false,
            automaticRetryAuthorized = false,
            coordinatorInvoked = false,
            exposesDeployUiAction = false,
            preparationResultSha256 = "",
        )
        return base.copy(preparationResultSha256 = preparationResultSha256(base)).also(::validate)
    }

    fun validate(
        result: SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(result.servingPolicySelectionSha256))
        require(sha256.matches(result.policyBoundPreflightAdmissionSha256))
        require(sha256.matches(result.policyBoundPreflightExecutionResultSha256))
        require(sha256.matches(result.publicationPlanSha256))
        require(sha256.matches(result.readOnlyPreflightSha256))
        require(transactionId.matches(result.mutationTransactionId))
        require(result.exactPolicyPreflightBindingVerified)
        require(!result.productionNetworkTouchedByPreparation)
        require(!result.remoteMutationPerformed)
        require(!result.configMutationAuthorized)
        require(!result.webServerReloadAuthorized)
        require(!result.certificateMutationAuthorized)
        require(!result.dnsMutationAuthorized)
        require(!result.firewallMutationAuthorized)
        require(!result.packageInstallAuthorized)
        require(!result.privateKeyContentReadAuthorized)
        require(!result.automaticRetryAuthorized)
        require(!result.coordinatorInvoked)
        require(!result.exposesDeployUiAction)

        when (result.status) {
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                .READY_FOR_SEPARATE_CONFIG_MUTATION_AUTHORITY_BOUNDARY -> {
                require(
                    result.readOnlyPreflightStatus ==
                        SiteWebServingReadOnlyPreflightStatus
                            .READY_FOR_SEPARATE_CONFIG_MUTATION_BOUNDARY,
                )
                require(result.mutationPreparationCreated)
                val preparation = requireNotNull(result.mutationPreparation)
                SiteWebServingConfigMutationPreparationBoundary.validate(preparation)
                require(preparation.mutationTransactionId == result.mutationTransactionId)
                require(preparation.publicationPlanSha256 == result.publicationPlanSha256)
                require(preparation.readOnlyPreflightSha256 == result.readOnlyPreflightSha256)
                require(!preparation.configMutationAuthorized)
                require(!preparation.webServerReloadAuthorized)
            }

            SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                .BLOCKED_BY_LIVE_WEB_SERVING_PREFLIGHT -> {
                require(
                    result.readOnlyPreflightStatus ==
                        SiteWebServingReadOnlyPreflightStatus
                            .BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
                )
                require(!result.mutationPreparationCreated)
                require(result.mutationPreparation == null)
            }
        }

        require(
            result.preparationResultSha256 ==
                preparationResultSha256(result.copy(preparationResultSha256 = "")),
        ) { "Phase 11.70 preparation-result SHA-256 mismatch" }
    }

    fun validateAgainst(
        result: SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution:
            SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
    ) {
        validate(result)
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
            .validateExecutionResult(policyBoundPreflightExecution)
        val plan = requireNotNull(selection.publicationPlan)
        require(result.servingPolicySelectionSha256 == selection.selectionSha256)
        require(result.policyBoundPreflightExecutionResultSha256 ==
            policyBoundPreflightExecution.executionResultSha256)
        require(result.policyBoundPreflightAdmissionSha256 ==
            policyBoundPreflightExecution.admissionSha256)
        require(result.publicationPlanSha256 == plan.publicationPlanSha256)
        require(result.selectedProtocol == policyBoundPreflightExecution.selectedProtocol)
        require(result.readOnlyPreflightSha256 ==
            policyBoundPreflightExecution.preflightExecutionProof.preflightReport.preflightSha256)
        require(result.readOnlyPreflightStatus == policyBoundPreflightExecution.preflightStatus)
    }

    private fun preparationResultSha256(
        result: SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
    ): String = digest(buildString {
        append("phase=11.70\n")
        append("contractVersion=").append(result.contractVersion).append('\n')
        append("status=").append(result.status.name).append('\n')
        append("selection=").append(result.servingPolicySelectionSha256).append('\n')
        append("preflightAdmission=").append(result.policyBoundPreflightAdmissionSha256).append('\n')
        append("preflightExecution=").append(result.policyBoundPreflightExecutionResultSha256).append('\n')
        append("publicationPlan=").append(result.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(result.selectedProtocol.name).append('\n')
        append("readOnlyPreflight=").append(result.readOnlyPreflightSha256).append('\n')
        append("readOnlyPreflightStatus=").append(result.readOnlyPreflightStatus.name).append('\n')
        append("mutationTransactionId=").append(result.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(
            result.mutationPreparation?.mutationPreparationSha256 ?: "",
        ).append('\n')
        append("exactPolicyPreflightBindingVerified=").append(result.exactPolicyPreflightBindingVerified).append('\n')
        append("mutationPreparationCreated=").append(result.mutationPreparationCreated).append('\n')
        append("productionNetworkTouchedByPreparation=").append(result.productionNetworkTouchedByPreparation).append('\n')
        append("remoteMutationPerformed=").append(result.remoteMutationPerformed).append('\n')
        append("configMutationAuthorized=").append(result.configMutationAuthorized).append('\n')
        append("webServerReloadAuthorized=").append(result.webServerReloadAuthorized).append('\n')
        append("certificateMutationAuthorized=").append(result.certificateMutationAuthorized).append('\n')
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
