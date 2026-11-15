package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightReport
import java.security.MessageDigest

/**
 * Phase 11.71: pure local production-chain gate immediately before the old Phase 11.59
 * staging/syntax authority preparation.
 *
 * A caller cannot hand a raw Phase 11.58 preparation directly to this production path. The exact
 * validated Phase 11.70 result must be supplied and bound to the exact Phase 11.69 proof and
 * Phase 11.68 serving-policy selection.
 *
 * READY may create only the existing Phase 11.59 operation-owned staging/validation execution
 * plan. BLOCKED creates no plan. Exact production config activation and nginx reload remain false.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val transactionId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution:
            SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation:
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
    ): SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult {
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
            .validateExecutionResult(policyBoundPreflightExecution)
        SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary.validateAgainst(
            policyBoundConfigMutationPreparation,
            selection,
            policyBoundPreflightExecution,
        )

        val readOnlyPreflight =
            policyBoundPreflightExecution.preflightExecutionProof.preflightReport

        return prepareValidated(
            selection = selection,
            policyBoundPreflightExecutionResultSha256 =
                policyBoundPreflightExecution.executionResultSha256,
            policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
            readOnlyPreflight = readOnlyPreflight,
        ).also {
            validateAgainst(
                result = it,
                selection = selection,
                policyBoundPreflightExecution = policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
            )
        }
    }

    /**
     * Deterministic zero-network seam used after the earlier production-chain proof objects have
     * already been validated. It exists for local verification only and performs no remote work.
     */
    internal fun prepareValidated(
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecutionResultSha256: String,
        policyBoundConfigMutationPreparation:
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
    ): SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult {
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
            .validate(policyBoundConfigMutationPreparation)
        SiteWebServingReadOnlyPreflightBoundary.validateReport(readOnlyPreflight)
        require(sha256.matches(policyBoundPreflightExecutionResultSha256)) {
            "Phase 11.71 policy-bound preflight execution SHA-256 is invalid"
        }
        require(selection.publicationPlanSelected)
        val publicationPlan = requireNotNull(selection.publicationPlan)
        val selectedProtocol = requireNotNull(selection.selectedProtocol)
        require(publicationPlan.protocol == selectedProtocol)

        require(
            policyBoundConfigMutationPreparation.servingPolicySelectionSha256 ==
                selection.selectionSha256,
        ) { "Phase 11.71 preparation belongs to another serving-policy selection" }
        require(
            policyBoundConfigMutationPreparation.policyBoundPreflightExecutionResultSha256 ==
                policyBoundPreflightExecutionResultSha256,
        ) { "Phase 11.71 preparation belongs to another Phase 11.69 execution proof" }
        require(
            policyBoundConfigMutationPreparation.publicationPlanSha256 ==
                publicationPlan.publicationPlanSha256,
        ) { "Phase 11.71 preparation belongs to another publication plan" }
        require(
            policyBoundConfigMutationPreparation.selectedProtocol == selectedProtocol,
        ) { "Phase 11.71 preparation belongs to another selected protocol" }
        require(
            policyBoundConfigMutationPreparation.readOnlyPreflightSha256 ==
                readOnlyPreflight.preflightSha256,
        ) { "Phase 11.71 preparation belongs to another live preflight" }
        require(
            policyBoundConfigMutationPreparation.readOnlyPreflightStatus ==
                readOnlyPreflight.status,
        )
        require(readOnlyPreflight.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(transactionId.matches(policyBoundConfigMutationPreparation.mutationTransactionId))

        val executionPlan =
            when (policyBoundConfigMutationPreparation.status) {
                SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                    .READY_FOR_SEPARATE_CONFIG_MUTATION_AUTHORITY_BOUNDARY -> {
                    val mutationPreparation =
                        requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation)
                    SiteWebServingConfigStagingSyntaxExecutionBoundary.prepare(
                        preparation = mutationPreparation,
                        publicationPlan = publicationPlan,
                        readOnlyPreflight = readOnlyPreflight,
                    )
                }

                SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                    .BLOCKED_BY_LIVE_WEB_SERVING_PREFLIGHT -> null
            }

        val status =
            if (executionPlan != null) {
                SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION
            } else {
                SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                    .BLOCKED_BY_POLICY_BOUND_CONFIG_MUTATION_PREPARATION
            }

        val base = SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult(
            contractVersion = CONTRACT_VERSION,
            status = status,
            servingPolicySelectionSha256 = selection.selectionSha256,
            policyBoundPreflightExecutionResultSha256 =
                policyBoundPreflightExecutionResultSha256,
            policyBoundConfigMutationPreparationResultSha256 =
                policyBoundConfigMutationPreparation.preparationResultSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            selectedProtocol = selectedProtocol,
            readOnlyPreflightSha256 = readOnlyPreflight.preflightSha256,
            readOnlyPreflightStatus = readOnlyPreflight.status,
            mutationTransactionId =
                policyBoundConfigMutationPreparation.mutationTransactionId,
            mutationPreparationSha256 =
                policyBoundConfigMutationPreparation.mutationPreparation
                    ?.mutationPreparationSha256,
            stagingSyntaxExecutionPlan = executionPlan,
            exactPolicyPreparationBindingVerified = true,
            stagingSyntaxExecutionPlanCreated = executionPlan != null,
            productionNetworkTouchedByAuthorityPreparation = false,
            remoteMutationPerformed = false,
            stagingConfigWriteAuthorized = executionPlan?.stagingConfigWriteAuthorized == true,
            validationConfigWriteAuthorized = executionPlan?.validationConfigWriteAuthorized == true,
            isolatedNginxSyntaxValidationAuthorized =
                executionPlan?.isolatedNginxSyntaxValidationAuthorized == true,
            exactConfigActivationAuthorized = false,
            webServerReloadAuthorized = false,
            certificateMutationAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            privateKeyContentReadAuthorized = false,
            automaticRetryAuthorized = false,
            coordinatorInvoked = false,
            exposesDeployUiAction = false,
            authorityPreparationResultSha256 = "",
        )
        return base.copy(
            authorityPreparationResultSha256 = authorityPreparationResultSha256(base),
        ).also(::validate)
    }

    fun validate(
        result: SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(result.servingPolicySelectionSha256))
        require(sha256.matches(result.policyBoundPreflightExecutionResultSha256))
        require(sha256.matches(result.policyBoundConfigMutationPreparationResultSha256))
        require(sha256.matches(result.publicationPlanSha256))
        require(sha256.matches(result.readOnlyPreflightSha256))
        require(transactionId.matches(result.mutationTransactionId))
        require(
            result.mutationPreparationSha256 == null ||
                sha256.matches(result.mutationPreparationSha256),
        )
        require(result.exactPolicyPreparationBindingVerified)
        require(!result.productionNetworkTouchedByAuthorityPreparation)
        require(!result.remoteMutationPerformed)
        require(!result.exactConfigActivationAuthorized)
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
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION -> {
                require(result.stagingSyntaxExecutionPlanCreated)
                val executionPlan = requireNotNull(result.stagingSyntaxExecutionPlan)
                SiteWebServingConfigStagingSyntaxExecutionBoundary.validate(executionPlan)
                require(result.mutationPreparationSha256 != null)
                require(
                    executionPlan.mutationPreparationSha256 ==
                        result.mutationPreparationSha256,
                )
                require(executionPlan.mutationTransactionId == result.mutationTransactionId)
                require(executionPlan.publicationPlanSha256 == result.publicationPlanSha256)
                require(executionPlan.readOnlyPreflightSha256 == result.readOnlyPreflightSha256)
                require(result.stagingConfigWriteAuthorized)
                require(result.validationConfigWriteAuthorized)
                require(result.isolatedNginxSyntaxValidationAuthorized)
                require(!executionPlan.exactConfigActivationAuthorized)
                require(!executionPlan.webServerReloadAuthorized)
                require(!executionPlan.dnsMutationAuthorized)
                require(!executionPlan.firewallMutationAuthorized)
                require(!executionPlan.packageInstallAuthorized)
                require(!executionPlan.automaticRetryAuthorized)
            }

            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                .BLOCKED_BY_POLICY_BOUND_CONFIG_MUTATION_PREPARATION -> {
                require(!result.stagingSyntaxExecutionPlanCreated)
                require(result.stagingSyntaxExecutionPlan == null)
                require(result.mutationPreparationSha256 == null)
                require(!result.stagingConfigWriteAuthorized)
                require(!result.validationConfigWriteAuthorized)
                require(!result.isolatedNginxSyntaxValidationAuthorized)
            }
        }

        require(
            result.authorityPreparationResultSha256 ==
                authorityPreparationResultSha256(
                    result.copy(authorityPreparationResultSha256 = ""),
                ),
        ) { "Phase 11.71 authority-preparation SHA-256 mismatch" }
    }

    fun validateAgainst(
        result: SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution:
            SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation:
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
    ) {
        validate(result)
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
            .validateExecutionResult(policyBoundPreflightExecution)
        SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary.validateAgainst(
            policyBoundConfigMutationPreparation,
            selection,
            policyBoundPreflightExecution,
        )

        val publicationPlan = requireNotNull(selection.publicationPlan)
        val readOnlyPreflight =
            policyBoundPreflightExecution.preflightExecutionProof.preflightReport

        require(result.servingPolicySelectionSha256 == selection.selectionSha256)
        require(
            result.policyBoundPreflightExecutionResultSha256 ==
                policyBoundPreflightExecution.executionResultSha256,
        )
        require(
            result.policyBoundConfigMutationPreparationResultSha256 ==
                policyBoundConfigMutationPreparation.preparationResultSha256,
        )
        require(result.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(result.selectedProtocol == policyBoundPreflightExecution.selectedProtocol)
        require(result.readOnlyPreflightSha256 == readOnlyPreflight.preflightSha256)
        require(result.readOnlyPreflightStatus == readOnlyPreflight.status)
        require(
            result.mutationTransactionId ==
                policyBoundConfigMutationPreparation.mutationTransactionId,
        )
        require(
            result.mutationPreparationSha256 ==
                policyBoundConfigMutationPreparation.mutationPreparation
                    ?.mutationPreparationSha256,
        )

        result.stagingSyntaxExecutionPlan?.let { executionPlan ->
            val mutationPreparation =
                requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation)
            SiteWebServingConfigStagingSyntaxExecutionBoundary.validateAgainst(
                plan = executionPlan,
                preparation = mutationPreparation,
                publicationPlan = publicationPlan,
                readOnlyPreflight = readOnlyPreflight,
            )
        }
    }

    private fun authorityPreparationResultSha256(
        result: SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
    ): String = digest(buildString {
        append("phase=11.71\n")
        append("contractVersion=").append(result.contractVersion).append('\n')
        append("status=").append(result.status.name).append('\n')
        append("selection=").append(result.servingPolicySelectionSha256).append('\n')
        append("preflightExecution=").append(result.policyBoundPreflightExecutionResultSha256).append('\n')
        append("configMutationPreparation=").append(
            result.policyBoundConfigMutationPreparationResultSha256,
        ).append('\n')
        append("publicationPlan=").append(result.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(result.selectedProtocol.name).append('\n')
        append("readOnlyPreflight=").append(result.readOnlyPreflightSha256).append('\n')
        append("readOnlyPreflightStatus=").append(result.readOnlyPreflightStatus.name).append('\n')
        append("mutationTransactionId=").append(result.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(result.mutationPreparationSha256 ?: "").append('\n')
        append("stagingSyntaxExecutionPlan=").append(
            result.stagingSyntaxExecutionPlan?.executionPlanSha256 ?: "",
        ).append('\n')
        append("exactPolicyPreparationBindingVerified=").append(result.exactPolicyPreparationBindingVerified).append('\n')
        append("stagingSyntaxExecutionPlanCreated=").append(result.stagingSyntaxExecutionPlanCreated).append('\n')
        append("productionNetworkTouchedByAuthorityPreparation=").append(result.productionNetworkTouchedByAuthorityPreparation).append('\n')
        append("remoteMutationPerformed=").append(result.remoteMutationPerformed).append('\n')
        append("stagingConfigWriteAuthorized=").append(result.stagingConfigWriteAuthorized).append('\n')
        append("validationConfigWriteAuthorized=").append(result.validationConfigWriteAuthorized).append('\n')
        append("isolatedNginxSyntaxValidationAuthorized=").append(result.isolatedNginxSyntaxValidationAuthorized).append('\n')
        append("exactConfigActivationAuthorized=").append(result.exactConfigActivationAuthorized).append('\n')
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
