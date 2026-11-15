package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionUsePort
import java.security.MessageDigest

/**
 * Phase 11.87 consumes the exact Phase 11.86 post-coordinator authority preparation and delegates
 * exactly once to the already accepted Phase 11.72 policy-bound staging/syntax execution boundary.
 *
 * The only live mutation remains the bounded Phase 11.59 operation-owned staging/validation
 * transaction plus isolated nginx syntax validation and exact cleanup. Production config activation,
 * nginx reload, coordinator/static-publication replay and automatic retry remain forbidden.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun admit(
        authorityPreparation: SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
    ): SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmission {
        SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
            .validate(authorityPreparation)

        val phase1172Admission =
            SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
                .admit(authorityPreparation.phase1171AuthorityPreparation)
        val ready =
            authorityPreparation.status ==
                SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
                    .READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION

        require(
            ready ==
                (phase1172Admission.status ==
                    SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                        .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION),
        ) { "Phase 11.87 post-coordinator readiness diverged from Phase 11.72 admission" }

        val base = SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmission(
            contractVersion = CONTRACT_VERSION,
            status =
                if (ready) {
                    SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus
                        .READY_FOR_FRESH_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION
                } else {
                    SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus
                        .BLOCKED_BY_POST_COORDINATOR_STAGING_SYNTAX_AUTHORITY_PREPARATION
                },
            phase1186AuthorityPreparationResultSha256 =
                authorityPreparation.authorityPreparationResultSha256,
            phase1183HandoffSha256 = authorityPreparation.phase1183HandoffSha256,
            phase1184ExecutionResultSha256 = authorityPreparation.phase1184ExecutionResultSha256,
            phase1185PreparationResultSha256 = authorityPreparation.phase1185PreparationResultSha256,
            phase1180ExecutionResultSha256 = authorityPreparation.phase1180ExecutionResultSha256,
            servingPolicySelectionSha256 = authorityPreparation.servingPolicySelectionSha256,
            phase1169ExecutionResultSha256 = authorityPreparation.phase1169ExecutionResultSha256,
            phase1170PreparationResultSha256 = authorityPreparation.phase1170PreparationResultSha256,
            phase1171AuthorityPreparationResultSha256 =
                authorityPreparation.phase1171AuthorityPreparation.authorityPreparationResultSha256,
            phase1172Admission = phase1172Admission,
            publicationPlanSha256 = authorityPreparation.publicationPlanSha256,
            selectedProtocol = authorityPreparation.selectedProtocol,
            mutationTransactionId = authorityPreparation.mutationTransactionId,
            mutationPreparationSha256 = authorityPreparation.mutationPreparationSha256,
            stagingSyntaxExecutionPlanSha256 = authorityPreparation.stagingSyntaxExecutionPlanSha256,
            requiresFreshCredentialResolution = ready,
            requiresLiveRemoteHostKeyVerification = ready,
            realVpsExecutionEligible = ready,
            exactConfigActivationAuthorized = false,
            webServerReloadAuthorized = false,
            coordinatorReinvocationAuthorized = false,
            staticPublicationReplayAuthorized = false,
            automaticRetryAuthorized = false,
            admissionSha256 = "",
        )
        return base.copy(admissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    suspend fun executeOnce(
        admission: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmission,
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        executionUsePort:
            SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionUsePort,
    ): SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult {
        require(canonicalId.matches(executionAttemptId)) {
            "Phase 11.87 execution attempt id must be canonical"
        }
        validateAdmission(admission)
        validateChain(
            handoff = handoff,
            phase1184Execution = phase1184Execution,
            phase1185Preparation = phase1185Preparation,
            phase1186AuthorityPreparation = phase1186AuthorityPreparation,
        )
        val expectedAdmission = admit(phase1186AuthorityPreparation)
        require(expectedAdmission.admissionSha256 == admission.admissionSha256) {
            "Phase 11.87 admission no longer matches the exact Phase 11.86 authority preparation"
        }
        require(
            admission.status ==
                SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus
                    .READY_FOR_FRESH_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION,
        ) {
            val failedChecks = phase1184Execution.phase1169ExecutionResult.preflightExecutionProof
                .preflightReport.checks.filterNot { it.passed }.joinToString("; ") { it.detail }
            "Файлы сайта уже записаны. Настройка веб-сервера остановлена: " +
                failedChecks.ifEmpty { "не получено разрешение на подготовку конфигурации Nginx" }
        }
        require(admission.realVpsExecutionEligible)
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(serverAccess.endpoint.host == handoff.remoteHostIdentity)

        val selection = requireNotNull(handoff.servingPolicySelection)
        val phase1172Execution =
            SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary.executeOnce(
                admission = admission.phase1172Admission,
                selection = selection,
                policyBoundPreflightExecution = phase1184Execution.phase1169ExecutionResult,
                policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                authorityPreparation = phase1186AuthorityPreparation.phase1171AuthorityPreparation,
                freshResolutionProof = freshResolutionProof,
                freshCredentialLease = freshCredentialLease,
                serverAccess = serverAccess,
                executionAttemptId = executionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis,
                executionUsePort = executionUsePort,
            )
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
            .validateExecutionResultAgainst(
                result = phase1172Execution,
                admission = admission.phase1172Admission,
                selection = selection,
                policyBoundPreflightExecution = phase1184Execution.phase1169ExecutionResult,
                policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                authorityPreparation = phase1186AuthorityPreparation.phase1171AuthorityPreparation,
            )
        require(!phase1172Execution.exactConfigActivationPerformed)
        require(!phase1172Execution.webServerReloadPerformed)
        require(!phase1172Execution.automaticRetryPerformed)
        require(!phase1172Execution.coordinatorInvoked)

        val base = SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionStatus
                    .EXECUTED_AND_CLEANED_WITHOUT_CONFIG_ACTIVATION_OR_COORDINATOR_REPLAY,
            phase1187AdmissionSha256 = admission.admissionSha256,
            phase1186AuthorityPreparationResultSha256 =
                phase1186AuthorityPreparation.authorityPreparationResultSha256,
            phase1183HandoffSha256 = handoff.handoffSha256,
            phase1184ExecutionResultSha256 = phase1184Execution.executionResultSha256,
            phase1185PreparationResultSha256 = phase1185Preparation.preparationResultSha256,
            phase1180ExecutionResultSha256 = handoff.phase1180ExecutionResultSha256,
            servingPolicySelectionSha256 = admission.servingPolicySelectionSha256,
            phase1169ExecutionResultSha256 =
                phase1184Execution.phase1169ExecutionResult.executionResultSha256,
            phase1170PreparationResultSha256 =
                phase1185Preparation.phase1170Preparation.preparationResultSha256,
            phase1171AuthorityPreparationResultSha256 =
                phase1186AuthorityPreparation.phase1171AuthorityPreparation
                    .authorityPreparationResultSha256,
            phase1172ExecutionResult = phase1172Execution,
            freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
            publicationPlanSha256 = admission.publicationPlanSha256,
            selectedProtocol = admission.selectedProtocol,
            mutationTransactionId = admission.mutationTransactionId,
            mutationPreparationSha256 = requireNotNull(admission.mutationPreparationSha256),
            stagingSyntaxExecutionPlanSha256 =
                requireNotNull(admission.stagingSyntaxExecutionPlanSha256),
            exactPostCoordinatorChainBindingVerified = true,
            durableBaselineCheckpointRecorded = phase1172Execution.durableBaselineCheckpointRecorded,
            credentialLeaseMaterialConsumed = phase1172Execution.credentialLeaseMaterialConsumed,
            productionNetworkTouched = phase1172Execution.productionNetworkTouched,
            liveHostKeyPinVerified = phase1172Execution.liveHostKeyPinVerified,
            operationOwnedStagingWritePerformed = phase1172Execution.operationOwnedStagingWritePerformed,
            operationOwnedValidationWritePerformed =
                phase1172Execution.operationOwnedValidationWritePerformed,
            nginxSyntaxValidationPassed = phase1172Execution.nginxSyntaxValidationPassed,
            operationOwnedCleanupVerified = phase1172Execution.operationOwnedCleanupVerified,
            exactConfigActivationPerformed = false,
            webServerReloadPerformed = false,
            coordinatorReinvoked = false,
            staticPublicationReplayPerformed = false,
            automaticRetryPerformed = false,
            executionResultSha256 = "",
        )
        return base.copy(executionResultSha256 = executionResultSha256(base)).also {
            validateExecutionResult(it)
            validateExecutionResultAgainst(
                result = it,
                admission = admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185Preparation,
                phase1186AuthorityPreparation = phase1186AuthorityPreparation,
            )
        }
    }

    fun validateAdmission(
        admission: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmission,
    ) {
        require(admission.contractVersion == CONTRACT_VERSION)
        listOf(
            admission.phase1186AuthorityPreparationResultSha256,
            admission.phase1183HandoffSha256,
            admission.phase1184ExecutionResultSha256,
            admission.phase1185PreparationResultSha256,
            admission.phase1180ExecutionResultSha256,
            admission.servingPolicySelectionSha256,
            admission.phase1169ExecutionResultSha256,
            admission.phase1170PreparationResultSha256,
            admission.phase1171AuthorityPreparationResultSha256,
            admission.publicationPlanSha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(admission.mutationTransactionId))
        admission.mutationPreparationSha256?.let { require(sha256.matches(it)) }
        admission.stagingSyntaxExecutionPlanSha256?.let { require(sha256.matches(it)) }
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
            .validateAdmission(admission.phase1172Admission)
        require(
            admission.phase1172Admission.policyBoundStagingSyntaxAuthorityPreparationResultSha256 ==
                admission.phase1171AuthorityPreparationResultSha256,
        )
        require(
            admission.phase1172Admission.servingPolicySelectionSha256 ==
                admission.servingPolicySelectionSha256,
        )
        require(admission.phase1172Admission.publicationPlanSha256 == admission.publicationPlanSha256)
        require(admission.phase1172Admission.selectedProtocol == admission.selectedProtocol)
        require(admission.phase1172Admission.mutationTransactionId == admission.mutationTransactionId)
        require(admission.phase1172Admission.mutationPreparationSha256 == admission.mutationPreparationSha256)
        require(
            admission.phase1172Admission.stagingSyntaxExecutionPlanSha256 ==
                admission.stagingSyntaxExecutionPlanSha256,
        )
        require(!admission.exactConfigActivationAuthorized)
        require(!admission.webServerReloadAuthorized)
        require(!admission.coordinatorReinvocationAuthorized)
        require(!admission.staticPublicationReplayAuthorized)
        require(!admission.automaticRetryAuthorized)

        when (admission.status) {
            SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus
                .READY_FOR_FRESH_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION -> {
                require(admission.realVpsExecutionEligible)
                require(admission.requiresFreshCredentialResolution)
                require(admission.requiresLiveRemoteHostKeyVerification)
                require(admission.mutationPreparationSha256 != null)
                require(admission.stagingSyntaxExecutionPlanSha256 != null)
                require(
                    admission.phase1172Admission.status ==
                        SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                            .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
                )
            }
            SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus
                .BLOCKED_BY_POST_COORDINATOR_STAGING_SYNTAX_AUTHORITY_PREPARATION -> {
                require(!admission.realVpsExecutionEligible)
                require(!admission.requiresFreshCredentialResolution)
                require(!admission.requiresLiveRemoteHostKeyVerification)
                require(admission.mutationPreparationSha256 == null)
                require(admission.stagingSyntaxExecutionPlanSha256 == null)
                require(
                    admission.phase1172Admission.status ==
                        SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                            .BLOCKED_BY_POLICY_BOUND_STAGING_SYNTAX_AUTHORITY_PREPARATION,
                )
            }
        }
        require(
            admission.admissionSha256 ==
                admissionSha256(admission.copy(admissionSha256 = "")),
        ) { "Phase 11.87 admission SHA-256 mismatch" }
    }

    fun validateExecutionResult(
        result: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(
            result.status ==
                SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionStatus
                    .EXECUTED_AND_CLEANED_WITHOUT_CONFIG_ACTIVATION_OR_COORDINATOR_REPLAY,
        )
        listOf(
            result.phase1187AdmissionSha256,
            result.phase1186AuthorityPreparationResultSha256,
            result.phase1183HandoffSha256,
            result.phase1184ExecutionResultSha256,
            result.phase1185PreparationResultSha256,
            result.phase1180ExecutionResultSha256,
            result.servingPolicySelectionSha256,
            result.phase1169ExecutionResultSha256,
            result.phase1170PreparationResultSha256,
            result.phase1171AuthorityPreparationResultSha256,
            result.freshCredentialResolutionProofSha256,
            result.publicationPlanSha256,
            result.mutationPreparationSha256,
            result.stagingSyntaxExecutionPlanSha256,
            result.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        require(canonicalId.matches(result.mutationTransactionId))
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
            .validateExecutionResult(result.phase1172ExecutionResult)
        require(result.exactPostCoordinatorChainBindingVerified)
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
        require(!result.coordinatorReinvoked)
        require(!result.staticPublicationReplayPerformed)
        require(!result.automaticRetryPerformed)
        require(
            result.executionResultSha256 ==
                executionResultSha256(result.copy(executionResultSha256 = "")),
        ) { "Phase 11.87 execution-result SHA-256 mismatch" }
    }

    fun validateExecutionResultAgainst(
        result: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult,
        admission: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmission,
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
    ) {
        validateExecutionResult(result)
        validateAdmission(admission)
        validateChain(handoff, phase1184Execution, phase1185Preparation, phase1186AuthorityPreparation)
        require(result.phase1187AdmissionSha256 == admission.admissionSha256)
        require(
            result.phase1186AuthorityPreparationResultSha256 ==
                phase1186AuthorityPreparation.authorityPreparationResultSha256,
        )
        require(result.phase1183HandoffSha256 == handoff.handoffSha256)
        require(result.phase1184ExecutionResultSha256 == phase1184Execution.executionResultSha256)
        require(result.phase1185PreparationResultSha256 == phase1185Preparation.preparationResultSha256)
        require(result.phase1180ExecutionResultSha256 == handoff.phase1180ExecutionResultSha256)
        require(result.servingPolicySelectionSha256 == admission.servingPolicySelectionSha256)
        require(
            result.phase1169ExecutionResultSha256 ==
                phase1184Execution.phase1169ExecutionResult.executionResultSha256,
        )
        require(
            result.phase1170PreparationResultSha256 ==
                phase1185Preparation.phase1170Preparation.preparationResultSha256,
        )
        require(
            result.phase1171AuthorityPreparationResultSha256 ==
                phase1186AuthorityPreparation.phase1171AuthorityPreparation
                    .authorityPreparationResultSha256,
        )
        require(result.publicationPlanSha256 == admission.publicationPlanSha256)
        require(result.selectedProtocol == admission.selectedProtocol)
        require(result.mutationTransactionId == admission.mutationTransactionId)
        require(result.mutationPreparationSha256 == admission.mutationPreparationSha256)
        require(result.stagingSyntaxExecutionPlanSha256 == admission.stagingSyntaxExecutionPlanSha256)
        require(result.phase1172ExecutionResult.admissionSha256 == admission.phase1172Admission.admissionSha256)
        require(result.phase1172ExecutionResult.freshCredentialResolutionProofSha256 == result.freshCredentialResolutionProofSha256)
        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
            .validateExecutionResultAgainst(
                result = result.phase1172ExecutionResult,
                admission = admission.phase1172Admission,
                selection = requireNotNull(handoff.servingPolicySelection),
                policyBoundPreflightExecution = phase1184Execution.phase1169ExecutionResult,
                policyBoundConfigMutationPreparation = phase1185Preparation.phase1170Preparation,
                authorityPreparation = phase1186AuthorityPreparation.phase1171AuthorityPreparation,
            )
    }

    private fun validateChain(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        phase1184Execution: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
        phase1185Preparation: SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult,
        phase1186AuthorityPreparation:
            SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult,
    ) {
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
            .validateExecutionResult(phase1184Execution)
        SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary.validateAgainst(
            result = phase1185Preparation,
            handoff = handoff,
            phase1184Execution = phase1184Execution,
        )
        SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
            .validateAgainst(
                result = phase1186AuthorityPreparation,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185Preparation,
            )
        require(phase1186AuthorityPreparation.phase1183HandoffSha256 == handoff.handoffSha256)
        require(
            phase1186AuthorityPreparation.phase1184ExecutionResultSha256 ==
                phase1184Execution.executionResultSha256,
        )
        require(
            phase1186AuthorityPreparation.phase1185PreparationResultSha256 ==
                phase1185Preparation.preparationResultSha256,
        )
    }

    private fun admissionSha256(
        value: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmission,
    ): String = digest(buildString {
        append("phase=11.87-admission\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1186AuthorityPreparation=").append(value.phase1186AuthorityPreparationResultSha256).append('\n')
        append("phase1183Handoff=").append(value.phase1183HandoffSha256).append('\n')
        append("phase1184Execution=").append(value.phase1184ExecutionResultSha256).append('\n')
        append("phase1185Preparation=").append(value.phase1185PreparationResultSha256).append('\n')
        append("phase1180Execution=").append(value.phase1180ExecutionResultSha256).append('\n')
        append("selection=").append(value.servingPolicySelectionSha256).append('\n')
        append("phase1169Execution=").append(value.phase1169ExecutionResultSha256).append('\n')
        append("phase1170Preparation=").append(value.phase1170PreparationResultSha256).append('\n')
        append("phase1171AuthorityPreparation=").append(value.phase1171AuthorityPreparationResultSha256).append('\n')
        append("phase1172Admission=").append(value.phase1172Admission.admissionSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
        append("mutationTransactionId=").append(value.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(value.mutationPreparationSha256 ?: "").append('\n')
        append("stagingSyntaxExecutionPlan=").append(value.stagingSyntaxExecutionPlanSha256 ?: "").append('\n')
        append("requiresFreshCredentialResolution=").append(value.requiresFreshCredentialResolution).append('\n')
        append("requiresLiveRemoteHostKeyVerification=").append(value.requiresLiveRemoteHostKeyVerification).append('\n')
        append("realVpsExecutionEligible=").append(value.realVpsExecutionEligible).append('\n')
        append("exactConfigActivationAuthorized=").append(value.exactConfigActivationAuthorized).append('\n')
        append("webServerReloadAuthorized=").append(value.webServerReloadAuthorized).append('\n')
        append("coordinatorReinvocationAuthorized=").append(value.coordinatorReinvocationAuthorized).append('\n')
        append("staticPublicationReplayAuthorized=").append(value.staticPublicationReplayAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(value.automaticRetryAuthorized).append('\n')
    })

    private fun executionResultSha256(
        value: SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionResult,
    ): String = digest(buildString {
        append("phase=11.87-result\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1187Admission=").append(value.phase1187AdmissionSha256).append('\n')
        append("phase1186AuthorityPreparation=").append(value.phase1186AuthorityPreparationResultSha256).append('\n')
        append("phase1183Handoff=").append(value.phase1183HandoffSha256).append('\n')
        append("phase1184Execution=").append(value.phase1184ExecutionResultSha256).append('\n')
        append("phase1185Preparation=").append(value.phase1185PreparationResultSha256).append('\n')
        append("phase1180Execution=").append(value.phase1180ExecutionResultSha256).append('\n')
        append("selection=").append(value.servingPolicySelectionSha256).append('\n')
        append("phase1169Execution=").append(value.phase1169ExecutionResultSha256).append('\n')
        append("phase1170Preparation=").append(value.phase1170PreparationResultSha256).append('\n')
        append("phase1171AuthorityPreparation=").append(value.phase1171AuthorityPreparationResultSha256).append('\n')
        append("phase1172Execution=").append(value.phase1172ExecutionResult.executionResultSha256).append('\n')
        append("freshCredentialResolution=").append(value.freshCredentialResolutionProofSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
        append("mutationTransactionId=").append(value.mutationTransactionId).append('\n')
        append("mutationPreparation=").append(value.mutationPreparationSha256).append('\n')
        append("stagingSyntaxExecutionPlan=").append(value.stagingSyntaxExecutionPlanSha256).append('\n')
        append("exactPostCoordinatorChainBindingVerified=").append(value.exactPostCoordinatorChainBindingVerified).append('\n')
        append("durableBaselineCheckpointRecorded=").append(value.durableBaselineCheckpointRecorded).append('\n')
        append("credentialLeaseMaterialConsumed=").append(value.credentialLeaseMaterialConsumed).append('\n')
        append("productionNetworkTouched=").append(value.productionNetworkTouched).append('\n')
        append("liveHostKeyPinVerified=").append(value.liveHostKeyPinVerified).append('\n')
        append("operationOwnedStagingWritePerformed=").append(value.operationOwnedStagingWritePerformed).append('\n')
        append("operationOwnedValidationWritePerformed=").append(value.operationOwnedValidationWritePerformed).append('\n')
        append("nginxSyntaxValidationPassed=").append(value.nginxSyntaxValidationPassed).append('\n')
        append("operationOwnedCleanupVerified=").append(value.operationOwnedCleanupVerified).append('\n')
        append("exactConfigActivationPerformed=").append(value.exactConfigActivationPerformed).append('\n')
        append("webServerReloadPerformed=").append(value.webServerReloadPerformed).append('\n')
        append("coordinatorReinvoked=").append(value.coordinatorReinvoked).append('\n')
        append("staticPublicationReplayPerformed=").append(value.staticPublicationReplayPerformed).append('\n')
        append("automaticRetryPerformed=").append(value.automaticRetryPerformed).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
