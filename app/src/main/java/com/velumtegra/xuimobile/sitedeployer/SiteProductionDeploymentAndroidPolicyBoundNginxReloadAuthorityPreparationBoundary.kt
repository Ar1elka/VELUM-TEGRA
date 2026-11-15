package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionBoundary
import java.security.MessageDigest

/**
 * Phase 11.75: pure local production-chain gate immediately before the old Phase 11.61 nginx
 * reload execution boundary.
 *
 * A caller cannot hand a raw Phase 11.60 activation proof directly to this production path. The
 * exact validated Phase 11.74 result must be supplied and bound to the exact Phase 11.68-11.73
 * chain. READY creates only the existing Phase 11.61 reload plan. No network, config mutation or
 * nginx reload/restart is performed here, and the durable Phase 11.61 replay fence is not consumed.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary {
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
        activationAuthorityPreparation:
            SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
        activationExecution:
            SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult,
    ): SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult {
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
        val stagingAdmission =
            SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary.admit(
                stagingSyntaxAuthorityPreparation,
            )
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
            .validateExecutionResultAgainst(
                stagingSyntaxExecution,
                stagingAdmission,
                selection,
                policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation,
            )
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
            .validateAgainst(
                activationAuthorityPreparation,
                selection,
                policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation,
                stagingSyntaxExecution,
            )
        val activationAdmission =
            SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary.admit(
                activationAuthorityPreparation,
            )
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
            .validateExecutionResultAgainst(
                result = activationExecution,
                admission = activationAdmission,
                selection = selection,
                policyBoundPreflightExecution = policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
                stagingSyntaxExecution = stagingSyntaxExecution,
                activationAuthorityPreparation = activationAuthorityPreparation,
            )

        return prepareValidated(
            selection = selection,
            activationAuthorityPreparation = activationAuthorityPreparation,
            policyBoundConfigActivationExecutionResultSha256 =
                activationExecution.executionResultSha256,
            phase11_60ExecutionProofSha256 =
                activationExecution.phase11_60ExecutionProof.executionProofSha256,
        ).also {
            validateAgainst(
                result = it,
                selection = selection,
                policyBoundPreflightExecution = policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
                stagingSyntaxExecution = stagingSyntaxExecution,
                activationAuthorityPreparation = activationAuthorityPreparation,
                activationExecution = activationExecution,
            )
        }
    }

    /** Deterministic zero-network seam after prior chain objects were validated by their owners. */
    internal fun prepareValidated(
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        activationAuthorityPreparation:
            SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
        policyBoundConfigActivationExecutionResultSha256: String,
        phase11_60ExecutionProofSha256: String,
    ): SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult {
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
            .validate(activationAuthorityPreparation)
        require(sha256.matches(policyBoundConfigActivationExecutionResultSha256))
        require(sha256.matches(phase11_60ExecutionProofSha256))
        require(selection.publicationPlanSelected)

        val publicationPlan = requireNotNull(selection.publicationPlan)
        val selectedProtocol = requireNotNull(selection.selectedProtocol)
        val activationPlan = activationAuthorityPreparation.activationExecutionPlan
        require(publicationPlan.protocol == selectedProtocol)
        require(
            activationAuthorityPreparation.servingPolicySelectionSha256 ==
                selection.selectionSha256,
        )
        require(
            activationAuthorityPreparation.publicationPlanSha256 ==
                publicationPlan.publicationPlanSha256,
        )
        require(
            activationAuthorityPreparation.status ==
                SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
        )
        require(transactionId.matches(activationAuthorityPreparation.mutationTransactionId))

        val reloadPlan = SiteWebServingNginxReloadExecutionBoundary.prepare(
            activationPlan = activationPlan,
            publicationPlan = publicationPlan,
        )

        val base = SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_NGINX_RELOAD_EXECUTION,
            policyBoundConfigActivationExecutionResultSha256 =
                policyBoundConfigActivationExecutionResultSha256,
            policyBoundConfigActivationAuthorityPreparationResultSha256 =
                activationAuthorityPreparation.authorityPreparationResultSha256,
            policyBoundStagingSyntaxExecutionResultSha256 =
                activationAuthorityPreparation.policyBoundStagingSyntaxExecutionResultSha256,
            policyBoundStagingSyntaxAuthorityPreparationResultSha256 =
                activationAuthorityPreparation
                    .policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            policyBoundPreflightExecutionResultSha256 =
                activationAuthorityPreparation.policyBoundPreflightExecutionResultSha256,
            policyBoundConfigMutationPreparationResultSha256 =
                activationAuthorityPreparation.policyBoundConfigMutationPreparationResultSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            selectedProtocol = selectedProtocol,
            readOnlyPreflightSha256 = activationAuthorityPreparation.readOnlyPreflightSha256,
            mutationTransactionId = activationAuthorityPreparation.mutationTransactionId,
            mutationPreparationSha256 = activationAuthorityPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 =
                activationAuthorityPreparation.stagingSyntaxExecutionPlanSha256,
            phase11_59ExecutionProofSha256 =
                activationAuthorityPreparation.phase11_59ExecutionProofSha256,
            activationExecutionPlanSha256 = activationPlan.activationPlanSha256,
            phase11_60ExecutionProofSha256 = phase11_60ExecutionProofSha256,
            nginxReloadExecutionPlan = reloadPlan,
            exactProductionChainBindingVerified = true,
            successfulConfigActivationExecutionProofValidated = true,
            nginxReloadExecutionPlanCreated = true,
            productionNetworkTouchedByAuthorityPreparation = false,
            remoteMutationPerformed = false,
            exactConfigActivationPerformedByAuthorityPreparation = false,
            nginxReloadExecutionAuthorized = true,
            nginxReloadPerformed = false,
            configMutationAuthorized = false,
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
        result: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(
            result.status ==
                SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_NGINX_RELOAD_EXECUTION,
        )
        listOf(
            result.policyBoundConfigActivationExecutionResultSha256,
            result.policyBoundConfigActivationAuthorityPreparationResultSha256,
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
            result.activationExecutionPlanSha256,
            result.phase11_60ExecutionProofSha256,
            result.authorityPreparationResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(transactionId.matches(result.mutationTransactionId))
        SiteWebServingNginxReloadExecutionBoundary.validate(result.nginxReloadExecutionPlan)
        require(result.nginxReloadExecutionPlan.activationPlanSha256 == result.activationExecutionPlanSha256)
        require(result.nginxReloadExecutionPlan.publicationPlanSha256 == result.publicationPlanSha256)
        require(result.exactProductionChainBindingVerified)
        require(result.successfulConfigActivationExecutionProofValidated)
        require(result.nginxReloadExecutionPlanCreated)
        require(!result.productionNetworkTouchedByAuthorityPreparation)
        require(!result.remoteMutationPerformed)
        require(!result.exactConfigActivationPerformedByAuthorityPreparation)
        require(result.nginxReloadExecutionAuthorized)
        require(!result.nginxReloadPerformed)
        require(!result.configMutationAuthorized)
        require(!result.certificateMutationAuthorized)
        require(!result.dnsMutationAuthorized)
        require(!result.firewallMutationAuthorized)
        require(!result.packageInstallAuthorized)
        require(!result.privateKeyContentReadAuthorized)
        require(!result.automaticRetryAuthorized)
        require(!result.coordinatorInvoked)
        require(!result.exposesDeployUiAction)
        require(result.nginxReloadExecutionPlan.reloadNginxOnceAuthorized)
        require(!result.nginxReloadExecutionPlan.configMutationAuthorized)
        require(!result.nginxReloadExecutionPlan.dnsMutationAuthorized)
        require(!result.nginxReloadExecutionPlan.firewallMutationAuthorized)
        require(!result.nginxReloadExecutionPlan.packageInstallAuthorized)
        require(!result.nginxReloadExecutionPlan.automaticRetryAuthorized)
        require(
            result.authorityPreparationResultSha256 ==
                authorityPreparationResultSha256(
                    result.copy(authorityPreparationResultSha256 = ""),
                ),
        ) { "Phase 11.75 nginx-reload authority preparation SHA-256 mismatch" }
    }

    fun validateAgainst(
        result: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution:
            SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation:
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        stagingSyntaxAuthorityPreparation:
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        stagingSyntaxExecution:
            SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
        activationAuthorityPreparation:
            SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult,
        activationExecution:
            SiteProductionDeploymentPolicyBoundConfigActivationExecutionResult,
    ) {
        validate(result)
        val activationAdmission =
            SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary.admit(
                activationAuthorityPreparation,
            )
        SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
            .validateExecutionResultAgainst(
                result = activationExecution,
                admission = activationAdmission,
                selection = selection,
                policyBoundPreflightExecution = policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation = policyBoundConfigMutationPreparation,
                stagingSyntaxAuthorityPreparation = stagingSyntaxAuthorityPreparation,
                stagingSyntaxExecution = stagingSyntaxExecution,
                activationAuthorityPreparation = activationAuthorityPreparation,
            )
        val publicationPlan = requireNotNull(selection.publicationPlan)
        require(
            result.policyBoundConfigActivationExecutionResultSha256 ==
                activationExecution.executionResultSha256,
        )
        require(
            result.policyBoundConfigActivationAuthorityPreparationResultSha256 ==
                activationAuthorityPreparation.authorityPreparationResultSha256,
        )
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
        require(
            result.readOnlyPreflightSha256 ==
                policyBoundPreflightExecution.preflightExecutionProof.preflightReport.preflightSha256,
        )
        require(
            result.mutationTransactionId ==
                policyBoundConfigMutationPreparation.mutationTransactionId,
        )
        require(
            result.mutationPreparationSha256 ==
                requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation)
                    .mutationPreparationSha256,
        )
        require(
            result.stagingSyntaxExecutionPlanSha256 ==
                requireNotNull(stagingSyntaxAuthorityPreparation.stagingSyntaxExecutionPlan)
                    .executionPlanSha256,
        )
        require(
            result.phase11_59ExecutionProofSha256 ==
                stagingSyntaxExecution.phase11_59ExecutionProof.executionProofSha256,
        )
        require(
            result.activationExecutionPlanSha256 ==
                activationAuthorityPreparation.activationExecutionPlan.activationPlanSha256,
        )
        require(
            result.phase11_60ExecutionProofSha256 ==
                activationExecution.phase11_60ExecutionProof.executionProofSha256,
        )
        SiteWebServingNginxReloadExecutionBoundary.validateAgainst(
            plan = result.nginxReloadExecutionPlan,
            activationPlan = activationAuthorityPreparation.activationExecutionPlan,
            publicationPlan = publicationPlan,
        )
    }

    private fun authorityPreparationResultSha256(
        result: SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult,
    ): String = digest(buildString {
        append("phase=11.75\n")
        append("contractVersion=").append(result.contractVersion).append('\n')
        append("status=").append(result.status.name).append('\n')
        append("activationExecution=").append(result.policyBoundConfigActivationExecutionResultSha256).append('\n')
        append("activationAuthority=").append(result.policyBoundConfigActivationAuthorityPreparationResultSha256).append('\n')
        append("stagingExecution=").append(result.policyBoundStagingSyntaxExecutionResultSha256).append('\n')
        append("stagingAuthority=").append(result.policyBoundStagingSyntaxAuthorityPreparationResultSha256).append('\n')
        append("selection=").append(result.servingPolicySelectionSha256).append('\n')
        append("preflightExecution=").append(result.policyBoundPreflightExecutionResultSha256).append('\n')
        append("configMutationPreparation=").append(result.policyBoundConfigMutationPreparationResultSha256).append('\n')
        append("publicationPlan=").append(result.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(result.selectedProtocol.name).append('\n')
        append("readOnlyPreflight=").append(result.readOnlyPreflightSha256).append('\n')
        append("mutationTransactionId=").append(result.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(result.mutationPreparationSha256).append('\n')
        append("stagingPlan=").append(result.stagingSyntaxExecutionPlanSha256).append('\n')
        append("phase11_59Proof=").append(result.phase11_59ExecutionProofSha256).append('\n')
        append("activationPlan=").append(result.activationExecutionPlanSha256).append('\n')
        append("phase11_60Proof=").append(result.phase11_60ExecutionProofSha256).append('\n')
        append("reloadPlan=").append(result.nginxReloadExecutionPlan.reloadPlanSha256).append('\n')
        append("exactProductionChainBindingVerified=").append(result.exactProductionChainBindingVerified).append('\n')
        append("successfulConfigActivationExecutionProofValidated=").append(result.successfulConfigActivationExecutionProofValidated).append('\n')
        append("nginxReloadExecutionPlanCreated=").append(result.nginxReloadExecutionPlanCreated).append('\n')
        append("productionNetworkTouchedByAuthorityPreparation=").append(result.productionNetworkTouchedByAuthorityPreparation).append('\n')
        append("remoteMutationPerformed=").append(result.remoteMutationPerformed).append('\n')
        append("exactConfigActivationPerformedByAuthorityPreparation=").append(result.exactConfigActivationPerformedByAuthorityPreparation).append('\n')
        append("nginxReloadExecutionAuthorized=").append(result.nginxReloadExecutionAuthorized).append('\n')
        append("nginxReloadPerformed=").append(result.nginxReloadPerformed).append('\n')
        append("configMutationAuthorized=").append(result.configMutationAuthorized).append('\n')
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
