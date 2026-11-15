package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightReport
import java.security.MessageDigest

/**
 * Phase 11.73: pure local production-chain gate immediately before the old Phase 11.60 exact
 * config-activation execution boundary.
 *
 * A caller cannot hand a raw Phase 11.59 plan/proof directly to this production path. The exact
 * validated Phase 11.72 result must be supplied and bound to the exact Phase 11.68-11.71 chain.
 * READY creates only the existing Phase 11.60 activation plan. No network or remote mutation is
 * performed here, and nginx reload remains unauthorized.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val transactionId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution:
            SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation:
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        stagingSyntaxAuthorityPreparation:
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        stagingSyntaxExecution:
            SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
    ): SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult {
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
            .validateExecutionResult(policyBoundPreflightExecution)
        SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary.validateAgainst(
            policyBoundConfigMutationPreparation,
            selection,
            policyBoundPreflightExecution,
        )
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
            .validateAgainst(
                stagingSyntaxAuthorityPreparation,
                selection,
                policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation,
            )
        val executionAdmission =
            SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary.admit(
                stagingSyntaxAuthorityPreparation,
            )
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
            .validateExecutionResultAgainst(
                stagingSyntaxExecution,
                executionAdmission,
                selection,
                policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation,
            )

        val readOnlyPreflight =
            policyBoundPreflightExecution.preflightExecutionProof.preflightReport
        return prepareValidated(
            selection = selection,
            policyBoundPreflightExecutionResultSha256 =
                policyBoundPreflightExecution.executionResultSha256,
            policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
            stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
            policyBoundStagingSyntaxExecutionResultSha256 =
                stagingSyntaxExecution.executionResultSha256,
            phase11_59ExecutionProofSha256 =
                stagingSyntaxExecution.phase11_59ExecutionProof.executionProofSha256,
            readOnlyPreflight = readOnlyPreflight,
        ).also {
            validateAgainst(
                result = it,
                selection = selection,
                policyBoundPreflightExecution = policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
                stagingSyntaxExecution = stagingSyntaxExecution,
            )
        }
    }

    /**
     * Deterministic zero-network seam for local verification after the prior production-chain
     * objects have already been validated by their owning boundaries.
     */
    internal fun prepareValidated(
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecutionResultSha256: String,
        policyBoundConfigMutationPreparation:
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        stagingSyntaxAuthorityPreparation:
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        policyBoundStagingSyntaxExecutionResultSha256: String,
        phase11_59ExecutionProofSha256: String,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
    ): SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult {
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
            .validate(policyBoundConfigMutationPreparation)
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
            .validate(stagingSyntaxAuthorityPreparation)
        SiteWebServingReadOnlyPreflightBoundary.validateReport(readOnlyPreflight)
        require(sha256.matches(policyBoundPreflightExecutionResultSha256))
        require(sha256.matches(policyBoundStagingSyntaxExecutionResultSha256))
        require(sha256.matches(phase11_59ExecutionProofSha256))
        require(selection.publicationPlanSelected)

        val publicationPlan = requireNotNull(selection.publicationPlan)
        val selectedProtocol = requireNotNull(selection.selectedProtocol)
        val mutationPreparation =
            requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation)
        val stagingSyntaxPlan =
            requireNotNull(stagingSyntaxAuthorityPreparation.stagingSyntaxExecutionPlan)

        require(publicationPlan.protocol == selectedProtocol)
        require(
            policyBoundConfigMutationPreparation.servingPolicySelectionSha256 ==
                selection.selectionSha256,
        )
        require(
            policyBoundConfigMutationPreparation.policyBoundPreflightExecutionResultSha256 ==
                policyBoundPreflightExecutionResultSha256,
        )
        require(
            stagingSyntaxAuthorityPreparation.servingPolicySelectionSha256 ==
                selection.selectionSha256,
        )
        require(
            stagingSyntaxAuthorityPreparation.policyBoundPreflightExecutionResultSha256 ==
                policyBoundPreflightExecutionResultSha256,
        )
        require(
            stagingSyntaxAuthorityPreparation.policyBoundConfigMutationPreparationResultSha256 ==
                policyBoundConfigMutationPreparation.preparationResultSha256,
        )
        require(
            stagingSyntaxAuthorityPreparation.publicationPlanSha256 ==
                publicationPlan.publicationPlanSha256,
        )
        require(
            stagingSyntaxAuthorityPreparation.readOnlyPreflightSha256 ==
                readOnlyPreflight.preflightSha256,
        )
        require(
            stagingSyntaxAuthorityPreparation.mutationPreparationSha256 ==
                mutationPreparation.mutationPreparationSha256,
        )
        require(
            stagingSyntaxAuthorityPreparation.status ==
                SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
        )
        require(readOnlyPreflight.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(transactionId.matches(policyBoundConfigMutationPreparation.mutationTransactionId))

        val activationPlan = SiteWebServingConfigActivationExecutionBoundary.prepare(
            mutationPreparation = mutationPreparation,
            stagingSyntaxPlan = stagingSyntaxPlan,
            publicationPlan = publicationPlan,
            readOnlyPreflight = readOnlyPreflight,
        )

        val base = SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
            policyBoundStagingSyntaxExecutionResultSha256 =
                policyBoundStagingSyntaxExecutionResultSha256,
            policyBoundStagingSyntaxAuthorityPreparationResultSha256 =
                stagingSyntaxAuthorityPreparation.authorityPreparationResultSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            policyBoundPreflightExecutionResultSha256 =
                policyBoundPreflightExecutionResultSha256,
            policyBoundConfigMutationPreparationResultSha256 =
                policyBoundConfigMutationPreparation.preparationResultSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            selectedProtocol = selectedProtocol,
            readOnlyPreflightSha256 = readOnlyPreflight.preflightSha256,
            mutationTransactionId =
                policyBoundConfigMutationPreparation.mutationTransactionId,
            mutationPreparationSha256 = mutationPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = stagingSyntaxPlan.executionPlanSha256,
            phase11_59ExecutionProofSha256 = phase11_59ExecutionProofSha256,
            activationExecutionPlan = activationPlan,
            exactProductionChainBindingVerified = true,
            successfulStagingSyntaxExecutionProofValidated = true,
            activationExecutionPlanCreated = true,
            productionNetworkTouchedByAuthorityPreparation = false,
            remoteMutationPerformed = false,
            stagingConfigWriteAuthorized = activationPlan.stagingConfigWriteAuthorized,
            exactConfigActivationAuthorized = activationPlan.exactConfigActivationAuthorized,
            nginxSyntaxValidationAuthorized = activationPlan.nginxSyntaxValidationAuthorized,
            webServerReloadAuthorized = activationPlan.webServerReloadAuthorized,
            certificateMutationAuthorized = false,
            dnsMutationAuthorized = activationPlan.dnsMutationAuthorized,
            firewallMutationAuthorized = activationPlan.firewallMutationAuthorized,
            packageInstallAuthorized = activationPlan.packageInstallAuthorized,
            privateKeyContentReadAuthorized = false,
            automaticRetryAuthorized = activationPlan.automaticRetryAuthorized,
            coordinatorInvoked = false,
            exposesDeployUiAction = false,
            authorityPreparationResultSha256 = "",
        )
        return base.copy(
            authorityPreparationResultSha256 = authorityPreparationResultSha256(base),
        ).also(::validate)
    }

    fun validate(
        result: SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(
            result.status ==
                SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
        )
        listOf(
            result.policyBoundStagingSyntaxExecutionResultSha256,
            result.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            result.servingPolicySelectionSha256,
            result.policyBoundPreflightExecutionResultSha256,
            result.policyBoundConfigMutationPreparationResultSha256,
            result.publicationPlanSha256,
            result.readOnlyPreflightSha256,
            result.mutationPreparationSha256,
            result.stagingSyntaxExecutionPlanSha256,
            result.phase11_59ExecutionProofSha256,
            result.authorityPreparationResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(transactionId.matches(result.mutationTransactionId))
        SiteWebServingConfigActivationExecutionBoundary.validate(result.activationExecutionPlan)
        require(result.exactProductionChainBindingVerified)
        require(result.successfulStagingSyntaxExecutionProofValidated)
        require(result.activationExecutionPlanCreated)
        require(!result.productionNetworkTouchedByAuthorityPreparation)
        require(!result.remoteMutationPerformed)
        require(result.stagingConfigWriteAuthorized)
        require(result.exactConfigActivationAuthorized)
        require(result.nginxSyntaxValidationAuthorized)
        require(!result.webServerReloadAuthorized)
        require(!result.certificateMutationAuthorized)
        require(!result.dnsMutationAuthorized)
        require(!result.firewallMutationAuthorized)
        require(!result.packageInstallAuthorized)
        require(!result.privateKeyContentReadAuthorized)
        require(!result.automaticRetryAuthorized)
        require(!result.coordinatorInvoked)
        require(!result.exposesDeployUiAction)
        require(
            result.activationExecutionPlan.mutationTransactionId ==
                result.mutationTransactionId,
        )
        require(
            result.activationExecutionPlan.mutationPreparationSha256 ==
                result.mutationPreparationSha256,
        )
        require(
            result.activationExecutionPlan.stagingSyntaxExecutionPlanSha256 ==
                result.stagingSyntaxExecutionPlanSha256,
        )
        require(
            result.activationExecutionPlan.publicationPlanSha256 ==
                result.publicationPlanSha256,
        )
        require(
            result.activationExecutionPlan.readOnlyPreflightSha256 ==
                result.readOnlyPreflightSha256,
        )
        require(
            result.authorityPreparationResultSha256 ==
                authorityPreparationResultSha256(
                    result.copy(authorityPreparationResultSha256 = ""),
                ),
        ) { "Phase 11.73 activation-authority preparation SHA-256 mismatch" }
    }

    fun validateAgainst(
        result: SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution:
            SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation:
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        stagingSyntaxAuthorityPreparation:
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        stagingSyntaxExecution:
            SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
    ) {
        validate(result)
        val executionAdmission =
            SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary.admit(
                stagingSyntaxAuthorityPreparation,
            )
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
            .validateExecutionResultAgainst(
                stagingSyntaxExecution,
                executionAdmission,
                selection,
                policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation,
            )

        val publicationPlan = requireNotNull(selection.publicationPlan)
        val readOnlyPreflight =
            policyBoundPreflightExecution.preflightExecutionProof.preflightReport
        val mutationPreparation =
            requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation)
        val stagingSyntaxPlan =
            requireNotNull(stagingSyntaxAuthorityPreparation.stagingSyntaxExecutionPlan)

        require(
            result.policyBoundStagingSyntaxExecutionResultSha256 ==
                stagingSyntaxExecution.executionResultSha256,
        )
        require(
            result.policyBoundStagingSyntaxAuthorityPreparationResultSha256 ==
                stagingSyntaxAuthorityPreparation.authorityPreparationResultSha256,
        )
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
        require(result.selectedProtocol == requireNotNull(selection.selectedProtocol))
        require(result.readOnlyPreflightSha256 == readOnlyPreflight.preflightSha256)
        require(
            result.mutationTransactionId ==
                policyBoundConfigMutationPreparation.mutationTransactionId,
        )
        require(
            result.mutationPreparationSha256 ==
                mutationPreparation.mutationPreparationSha256,
        )
        require(
            result.stagingSyntaxExecutionPlanSha256 ==
                stagingSyntaxPlan.executionPlanSha256,
        )
        require(
            result.phase11_59ExecutionProofSha256 ==
                stagingSyntaxExecution.phase11_59ExecutionProof.executionProofSha256,
        )
        SiteWebServingConfigActivationExecutionBoundary.validateAgainst(
            plan = result.activationExecutionPlan,
            mutationPreparation = mutationPreparation,
            stagingSyntaxPlan = stagingSyntaxPlan,
            publicationPlan = publicationPlan,
            readOnlyPreflight = readOnlyPreflight,
        )
    }

    private fun authorityPreparationResultSha256(
        result: SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
    ): String = digest(buildString {
        append("phase=11.73\n")
        append("contractVersion=").append(result.contractVersion).append('\n')
        append("status=").append(result.status.name).append('\n')
        append("stagingSyntaxExecution=").append(result.policyBoundStagingSyntaxExecutionResultSha256).append('\n')
        append("stagingSyntaxAuthority=").append(result.policyBoundStagingSyntaxAuthorityPreparationResultSha256).append('\n')
        append("selection=").append(result.servingPolicySelectionSha256).append('\n')
        append("preflightExecution=").append(result.policyBoundPreflightExecutionResultSha256).append('\n')
        append("configMutationPreparation=").append(result.policyBoundConfigMutationPreparationResultSha256).append('\n')
        append("publicationPlan=").append(result.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(result.selectedProtocol.name).append('\n')
        append("readOnlyPreflight=").append(result.readOnlyPreflightSha256).append('\n')
        append("mutationTransactionId=").append(result.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(result.mutationPreparationSha256).append('\n')
        append("stagingSyntaxPlan=").append(result.stagingSyntaxExecutionPlanSha256).append('\n')
        append("phase11_59Proof=").append(result.phase11_59ExecutionProofSha256).append('\n')
        append("activationPlan=").append(result.activationExecutionPlan.activationPlanSha256).append('\n')
        append("exactProductionChainBindingVerified=").append(result.exactProductionChainBindingVerified).append('\n')
        append("successfulStagingSyntaxExecutionProofValidated=").append(result.successfulStagingSyntaxExecutionProofValidated).append('\n')
        append("activationExecutionPlanCreated=").append(result.activationExecutionPlanCreated).append('\n')
        append("productionNetworkTouchedByAuthorityPreparation=").append(result.productionNetworkTouchedByAuthorityPreparation).append('\n')
        append("remoteMutationPerformed=").append(result.remoteMutationPerformed).append('\n')
        append("stagingConfigWriteAuthorized=").append(result.stagingConfigWriteAuthorized).append('\n')
        append("exactConfigActivationAuthorized=").append(result.exactConfigActivationAuthorized).append('\n')
        append("nginxSyntaxValidationAuthorized=").append(result.nginxSyntaxValidationAuthorized).append('\n')
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

    private fun digest(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.encodeToByteArray())
            .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
