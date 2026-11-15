package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionUsePort
import java.security.MessageDigest

/**
 * Phase 11.72 makes the exact READY Phase 11.71 production-chain result mandatory before the
 * existing Phase 11.59 live staging/syntax executor may run.
 *
 * This boundary grants no authority beyond Phase 11.59: operation-owned staging/validation writes,
 * isolated nginx syntax validation and exact cleanup are allowed; exact production config
 * activation and nginx reload remain forbidden.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun admit(
        authorityPreparation:
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
    ): SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmission {
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
            .validate(authorityPreparation)

        val ready =
            authorityPreparation.status ==
                SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                    .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION

        val executionPlanSha256 =
            if (ready) {
                requireNotNull(authorityPreparation.stagingSyntaxExecutionPlan)
                    .executionPlanSha256
            } else {
                null
            }

        val base = SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmission(
            contractVersion = CONTRACT_VERSION,
            status =
                if (ready) {
                    SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                        .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION
                } else {
                    SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                        .BLOCKED_BY_POLICY_BOUND_STAGING_SYNTAX_AUTHORITY_PREPARATION
                },
            policyBoundStagingSyntaxAuthorityPreparationResultSha256 =
                authorityPreparation.authorityPreparationResultSha256,
            servingPolicySelectionSha256 =
                authorityPreparation.servingPolicySelectionSha256,
            policyBoundPreflightExecutionResultSha256 =
                authorityPreparation.policyBoundPreflightExecutionResultSha256,
            policyBoundConfigMutationPreparationResultSha256 =
                authorityPreparation.policyBoundConfigMutationPreparationResultSha256,
            publicationPlanSha256 = authorityPreparation.publicationPlanSha256,
            selectedProtocol = authorityPreparation.selectedProtocol,
            readOnlyPreflightSha256 = authorityPreparation.readOnlyPreflightSha256,
            mutationTransactionId = authorityPreparation.mutationTransactionId,
            mutationPreparationSha256 = authorityPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = executionPlanSha256,
            requiresFreshCredentialResolution = ready,
            requiresLiveRemoteHostKeyVerification = ready,
            realVpsExecutionEligible = ready,
            exactConfigActivationAuthorized = false,
            webServerReloadAuthorized = false,
            certificateMutationAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            automaticRetryAuthorized = false,
            coordinatorInvoked = false,
            exposesDeployUiAction = false,
            admissionSha256 = "",
        )
        return base.copy(admissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    suspend fun executeOnce(
        admission: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmission,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution:
            SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation:
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        authorityPreparation:
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort:
            SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionUsePort,
    ): SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult {
        require(canonicalId.matches(executionAttemptId)) {
            "Phase 11.72 execution attempt id must be canonical"
        }
        validateAdmission(admission)
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
                authorityPreparation,
                selection,
                policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation,
            )

        val expectedAdmission = admit(authorityPreparation)
        require(admission.admissionSha256 == expectedAdmission.admissionSha256) {
            "Phase 11.72 admission does not match the exact Phase 11.71 result"
        }
        require(
            admission.status ==
                SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
        ) { "Phase 11.72 blocked admission cannot touch the network" }
        require(admission.realVpsExecutionEligible)
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)

        val publicationPlan = requireNotNull(selection.publicationPlan)
        val readOnlyPreflight =
            policyBoundPreflightExecution.preflightExecutionProof.preflightReport
        val mutationPreparation =
            requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation)
        val executionPlan =
            requireNotNull(authorityPreparation.stagingSyntaxExecutionPlan)

        require(
            authorityPreparation.authorityPreparationResultSha256 ==
                admission.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
        )
        require(selection.selectionSha256 == admission.servingPolicySelectionSha256)
        require(
            policyBoundPreflightExecution.executionResultSha256 ==
                admission.policyBoundPreflightExecutionResultSha256,
        )
        require(
            policyBoundConfigMutationPreparation.preparationResultSha256 ==
                admission.policyBoundConfigMutationPreparationResultSha256,
        )
        require(publicationPlan.publicationPlanSha256 == admission.publicationPlanSha256)
        require(selection.selectedProtocol == admission.selectedProtocol)
        require(readOnlyPreflight.preflightSha256 == admission.readOnlyPreflightSha256)
        require(
            policyBoundConfigMutationPreparation.mutationTransactionId ==
                admission.mutationTransactionId,
        )
        require(
            mutationPreparation.mutationPreparationSha256 ==
                admission.mutationPreparationSha256,
        )
        require(executionPlan.executionPlanSha256 == admission.stagingSyntaxExecutionPlanSha256)

        val phase1159Proof =
            SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary
                .executeOnce(
                    publicationPlan = publicationPlan,
                    readOnlyPreflight = readOnlyPreflight,
                    mutationPreparation = mutationPreparation,
                    executionPlan = executionPlan,
                    freshResolutionProof = freshResolutionProof,
                    freshCredentialLease = freshCredentialLease,
                    serverAccess = serverAccess,
                    executionAttemptId = executionAttemptId,
                    executedAtEpochMillis = executedAtEpochMillis,
                    executionUsePort = executionUsePort,
                )
        SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary
            .validateProof(phase1159Proof)

        require(phase1159Proof.executionPlanSha256 == executionPlan.executionPlanSha256)
        require(
            phase1159Proof.mutationPreparationSha256 ==
                mutationPreparation.mutationPreparationSha256,
        )
        require(phase1159Proof.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(phase1159Proof.readOnlyPreflightSha256 == readOnlyPreflight.preflightSha256)
        require(
            phase1159Proof.freshCredentialResolutionProofSha256 ==
                freshResolutionProof.resolutionProofSha256,
        )

        val base = SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionStatus
                    .EXECUTED_AND_CLEANED_WITHOUT_EXACT_CONFIG_ACTIVATION_OR_RELOAD,
            admissionSha256 = admission.admissionSha256,
            policyBoundStagingSyntaxAuthorityPreparationResultSha256 =
                authorityPreparation.authorityPreparationResultSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            policyBoundPreflightExecutionResultSha256 =
                policyBoundPreflightExecution.executionResultSha256,
            policyBoundConfigMutationPreparationResultSha256 =
                policyBoundConfigMutationPreparation.preparationResultSha256,
            publicationPlanSha256 = publicationPlan.publicationPlanSha256,
            selectedProtocol = requireNotNull(selection.selectedProtocol),
            readOnlyPreflightSha256 = readOnlyPreflight.preflightSha256,
            mutationTransactionId =
                policyBoundConfigMutationPreparation.mutationTransactionId,
            mutationPreparationSha256 = mutationPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = executionPlan.executionPlanSha256,
            phase11_59ExecutionProof = phase1159Proof,
            freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
            exactProductionChainBindingVerified = true,
            durableBaselineCheckpointRecorded =
                phase1159Proof.durableBaselineCheckpointRecorded,
            credentialLeaseMaterialConsumed =
                phase1159Proof.credentialLeaseMaterialConsumed,
            productionNetworkTouched = phase1159Proof.productionNetworkTouched,
            liveHostKeyPinVerified = phase1159Proof.hostKeyPinVerifiedAgainstRemote,
            operationOwnedStagingWritePerformed =
                phase1159Proof.stagingConfigWritePerformed,
            operationOwnedValidationWritePerformed =
                phase1159Proof.validationConfigWritePerformed,
            nginxSyntaxValidationPassed = phase1159Proof.nginxSyntaxValidationPassed,
            operationOwnedCleanupVerified =
                phase1159Proof.stagingConfigAbsentAfterCleanup &&
                    phase1159Proof.validationConfigAbsentAfterCleanup &&
                    phase1159Proof.validationPidAbsentAfterCleanup,
            exactConfigActivationPerformed =
                phase1159Proof.exactConfigActivationPerformed,
            webServerReloadPerformed = phase1159Proof.webServerReloadPerformed,
            certificateMutationPerformed = false,
            dnsMutationPerformed = phase1159Proof.dnsMutationPerformed,
            firewallMutationPerformed = phase1159Proof.firewallMutationPerformed,
            packageInstallPerformed = phase1159Proof.packageInstallPerformed,
            privateKeyContentReadPerformed =
                phase1159Proof.privateKeyContentReadPerformed,
            automaticRetryPerformed = phase1159Proof.automaticRetryPerformed,
            coordinatorInvoked = phase1159Proof.coordinatorInvoked,
            exposesDeployUiAction = phase1159Proof.exposesDeployUiAction,
            executionResultSha256 = "",
        )
        return base.copy(
            executionResultSha256 = executionResultSha256(base),
        ).also {
            validateExecutionResult(it)
            validateExecutionResultAgainst(
                it,
                admission,
                selection,
                policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation,
                authorityPreparation,
            )
        }
    }

    fun validateAdmission(
        admission: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmission,
    ) {
        require(admission.contractVersion == CONTRACT_VERSION)
        listOf(
            admission.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            admission.servingPolicySelectionSha256,
            admission.policyBoundPreflightExecutionResultSha256,
            admission.policyBoundConfigMutationPreparationResultSha256,
            admission.publicationPlanSha256,
            admission.readOnlyPreflightSha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(admission.mutationTransactionId))
        require(
            admission.mutationPreparationSha256 == null ||
                sha256.matches(admission.mutationPreparationSha256),
        )
        require(
            admission.stagingSyntaxExecutionPlanSha256 == null ||
                sha256.matches(admission.stagingSyntaxExecutionPlanSha256),
        )
        require(!admission.exactConfigActivationAuthorized)
        require(!admission.webServerReloadAuthorized)
        require(!admission.certificateMutationAuthorized)
        require(!admission.dnsMutationAuthorized)
        require(!admission.firewallMutationAuthorized)
        require(!admission.packageInstallAuthorized)
        require(!admission.automaticRetryAuthorized)
        require(!admission.coordinatorInvoked)
        require(!admission.exposesDeployUiAction)

        when (admission.status) {
            SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION -> {
                require(admission.realVpsExecutionEligible)
                require(admission.requiresFreshCredentialResolution)
                require(admission.requiresLiveRemoteHostKeyVerification)
                require(admission.mutationPreparationSha256 != null)
                require(admission.stagingSyntaxExecutionPlanSha256 != null)
            }

            SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                .BLOCKED_BY_POLICY_BOUND_STAGING_SYNTAX_AUTHORITY_PREPARATION -> {
                require(!admission.realVpsExecutionEligible)
                require(!admission.requiresFreshCredentialResolution)
                require(!admission.requiresLiveRemoteHostKeyVerification)
                require(admission.mutationPreparationSha256 == null)
                require(admission.stagingSyntaxExecutionPlanSha256 == null)
            }
        }

        require(
            admission.admissionSha256 ==
                admissionSha256(admission.copy(admissionSha256 = "")),
        ) { "Phase 11.72 admission SHA-256 mismatch" }
    }

    fun validateExecutionResult(
        result: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(
            result.status ==
                SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionStatus
                    .EXECUTED_AND_CLEANED_WITHOUT_EXACT_CONFIG_ACTIVATION_OR_RELOAD,
        )
        listOf(
            result.admissionSha256,
            result.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
            result.servingPolicySelectionSha256,
            result.policyBoundPreflightExecutionResultSha256,
            result.policyBoundConfigMutationPreparationResultSha256,
            result.publicationPlanSha256,
            result.readOnlyPreflightSha256,
            result.mutationPreparationSha256,
            result.stagingSyntaxExecutionPlanSha256,
            result.freshCredentialResolutionProofSha256,
            result.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(result.mutationTransactionId))
        SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary
            .validateProof(result.phase11_59ExecutionProof)
        require(result.exactProductionChainBindingVerified)
        require(result.durableBaselineCheckpointRecorded)
        require(result.credentialLeaseMaterialConsumed)
        require(result.productionNetworkTouched)
        require(result.liveHostKeyPinVerified)
        require(result.operationOwnedStagingWritePerformed)
        require(result.operationOwnedValidationWritePerformed)
        require(result.nginxSyntaxValidationPassed)
        require(result.operationOwnedCleanupVerified)
        require(!result.exactConfigActivationPerformed)
        require(!result.webServerReloadPerformed)
        require(!result.certificateMutationPerformed)
        require(!result.dnsMutationPerformed)
        require(!result.firewallMutationPerformed)
        require(!result.packageInstallPerformed)
        require(!result.privateKeyContentReadPerformed)
        require(!result.automaticRetryPerformed)
        require(!result.coordinatorInvoked)
        require(!result.exposesDeployUiAction)
        require(
            result.executionResultSha256 ==
                executionResultSha256(result.copy(executionResultSha256 = "")),
        ) { "Phase 11.72 execution-result SHA-256 mismatch" }
    }

    fun validateExecutionResultAgainst(
        result: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
        admission: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmission,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        policyBoundPreflightExecution:
            SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
        policyBoundConfigMutationPreparation:
            SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult,
        authorityPreparation:
            SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult,
    ) {
        validateExecutionResult(result)
        validateAdmission(admission)
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
            .validateAgainst(
                authorityPreparation,
                selection,
                policyBoundPreflightExecution,
                policyBoundConfigMutationPreparation,
            )
        val publicationPlan = requireNotNull(selection.publicationPlan)
        val readOnlyPreflight =
            policyBoundPreflightExecution.preflightExecutionProof.preflightReport
        val mutationPreparation =
            requireNotNull(policyBoundConfigMutationPreparation.mutationPreparation)
        val executionPlan =
            requireNotNull(authorityPreparation.stagingSyntaxExecutionPlan)

        require(result.admissionSha256 == admission.admissionSha256)
        require(
            result.policyBoundStagingSyntaxAuthorityPreparationResultSha256 ==
                authorityPreparation.authorityPreparationResultSha256,
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
                executionPlan.executionPlanSha256,
        )
        require(
            result.phase11_59ExecutionProof.executionPlanSha256 ==
                executionPlan.executionPlanSha256,
        )
        require(
            result.phase11_59ExecutionProof.mutationPreparationSha256 ==
                mutationPreparation.mutationPreparationSha256,
        )
        require(
            result.phase11_59ExecutionProof.publicationPlanSha256 ==
                publicationPlan.publicationPlanSha256,
        )
        require(
            result.phase11_59ExecutionProof.readOnlyPreflightSha256 ==
                readOnlyPreflight.preflightSha256,
        )
    }

    private fun admissionSha256(
        admission: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmission,
    ): String = digest(buildString {
        append("phase=11.72-admission\n")
        append("contractVersion=").append(admission.contractVersion).append('\n')
        append("status=").append(admission.status.name).append('\n')
        append("authorityPreparation=").append(
            admission.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
        ).append('\n')
        append("selection=").append(admission.servingPolicySelectionSha256).append('\n')
        append("preflightExecution=").append(admission.policyBoundPreflightExecutionResultSha256).append('\n')
        append("configMutationPreparation=").append(
            admission.policyBoundConfigMutationPreparationResultSha256,
        ).append('\n')
        append("publicationPlan=").append(admission.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(admission.selectedProtocol.name).append('\n')
        append("readOnlyPreflight=").append(admission.readOnlyPreflightSha256).append('\n')
        append("mutationTransactionId=").append(admission.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(admission.mutationPreparationSha256 ?: "").append('\n')
        append("executionPlan=").append(admission.stagingSyntaxExecutionPlanSha256 ?: "").append('\n')
        append("requiresFreshCredentialResolution=").append(admission.requiresFreshCredentialResolution).append('\n')
        append("requiresLiveRemoteHostKeyVerification=").append(admission.requiresLiveRemoteHostKeyVerification).append('\n')
        append("realVpsExecutionEligible=").append(admission.realVpsExecutionEligible).append('\n')
        append("exactConfigActivationAuthorized=").append(admission.exactConfigActivationAuthorized).append('\n')
        append("webServerReloadAuthorized=").append(admission.webServerReloadAuthorized).append('\n')
        append("certificateMutationAuthorized=").append(admission.certificateMutationAuthorized).append('\n')
        append("dnsMutationAuthorized=").append(admission.dnsMutationAuthorized).append('\n')
        append("firewallMutationAuthorized=").append(admission.firewallMutationAuthorized).append('\n')
        append("packageInstallAuthorized=").append(admission.packageInstallAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(admission.automaticRetryAuthorized).append('\n')
        append("coordinatorInvoked=").append(admission.coordinatorInvoked).append('\n')
        append("exposesDeployUiAction=").append(admission.exposesDeployUiAction).append('\n')
    })

    private fun executionResultSha256(
        result: SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionResult,
    ): String = digest(buildString {
        append("phase=11.72-execution\n")
        append("contractVersion=").append(result.contractVersion).append('\n')
        append("status=").append(result.status.name).append('\n')
        append("admission=").append(result.admissionSha256).append('\n')
        append("authorityPreparation=").append(
            result.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
        ).append('\n')
        append("selection=").append(result.servingPolicySelectionSha256).append('\n')
        append("preflightExecution=").append(result.policyBoundPreflightExecutionResultSha256).append('\n')
        append("configMutationPreparation=").append(
            result.policyBoundConfigMutationPreparationResultSha256,
        ).append('\n')
        append("publicationPlan=").append(result.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(result.selectedProtocol.name).append('\n')
        append("readOnlyPreflight=").append(result.readOnlyPreflightSha256).append('\n')
        append("mutationTransactionId=").append(result.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(result.mutationPreparationSha256).append('\n')
        append("executionPlan=").append(result.stagingSyntaxExecutionPlanSha256).append('\n')
        append("phase11_59Proof=").append(
            result.phase11_59ExecutionProof.executionProofSha256,
        ).append('\n')
        append("freshCredentialResolutionProof=").append(
            result.freshCredentialResolutionProofSha256,
        ).append('\n')
        append("exactProductionChainBindingVerified=").append(result.exactProductionChainBindingVerified).append('\n')
        append("durableBaselineCheckpointRecorded=").append(result.durableBaselineCheckpointRecorded).append('\n')
        append("credentialLeaseMaterialConsumed=").append(result.credentialLeaseMaterialConsumed).append('\n')
        append("productionNetworkTouched=").append(result.productionNetworkTouched).append('\n')
        append("liveHostKeyPinVerified=").append(result.liveHostKeyPinVerified).append('\n')
        append("operationOwnedStagingWritePerformed=").append(result.operationOwnedStagingWritePerformed).append('\n')
        append("operationOwnedValidationWritePerformed=").append(result.operationOwnedValidationWritePerformed).append('\n')
        append("nginxSyntaxValidationPassed=").append(result.nginxSyntaxValidationPassed).append('\n')
        append("operationOwnedCleanupVerified=").append(result.operationOwnedCleanupVerified).append('\n')
        append("exactConfigActivationPerformed=").append(result.exactConfigActivationPerformed).append('\n')
        append("webServerReloadPerformed=").append(result.webServerReloadPerformed).append('\n')
        append("certificateMutationPerformed=").append(result.certificateMutationPerformed).append('\n')
        append("dnsMutationPerformed=").append(result.dnsMutationPerformed).append('\n')
        append("firewallMutationPerformed=").append(result.firewallMutationPerformed).append('\n')
        append("packageInstallPerformed=").append(result.packageInstallPerformed).append('\n')
        append("privateKeyContentReadPerformed=").append(result.privateKeyContentReadPerformed).append('\n')
        append("automaticRetryPerformed=").append(result.automaticRetryPerformed).append('\n')
        append("coordinatorInvoked=").append(result.coordinatorInvoked).append('\n')
        append("exposesDeployUiAction=").append(result.exposesDeployUiAction).append('\n')
    })

    private fun digest(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.encodeToByteArray())
            .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
