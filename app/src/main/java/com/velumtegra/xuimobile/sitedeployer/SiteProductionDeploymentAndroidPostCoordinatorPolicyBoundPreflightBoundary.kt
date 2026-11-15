package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import java.security.MessageDigest

/**
 * Phase 11.84 consumes only a validated READY Phase 11.83 handoff and delegates one fresh
 * policy-bound read-only web-serving preflight to the already accepted Phase 11.69 boundary.
 *
 * It never reinvokes the coordinator/static publication path and grants no web-serving mutation
 * or retry authority. Live network access is possible only in [observeOnce], after the caller
 * supplies a newly resolved one-shot credential proof/lease and the exact ServerAccess binding.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun admit(
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
    ): SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmission {
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        require(
            handoff.status ==
                SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                    .READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT,
        ) { "Phase 11.84 accepts only a READY Phase 11.83 post-coordinator handoff" }
        require(handoff.requiresFreshPolicyBoundWebServingPreflight)
        require(!handoff.authorizesWebServingNetworkExecution)
        require(!handoff.authorizesWebServingMutation)
        require(!handoff.authorizesCoordinatorReinvocation)
        require(!handoff.automaticRetryAuthorized)

        val selection = requireNotNull(handoff.servingPolicySelection)
        require(handoff.servingPolicySelectionSha256 == selection.selectionSha256)
        require(selection.preparationSha256 == handoff.localPreparationSha256)
        require(selection.staticTargetTreeSha256 == handoff.sourceTreeSha256)
        require(selection.publicationPlanSelected)

        val phase1169Admission =
            SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary.admit(selection)
        require(
            phase1169Admission.status ==
                SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_READ_ONLY_PREFLIGHT_EXECUTION,
        ) { "READY Phase 11.83 handoff must map to a READY Phase 11.69 admission" }
        require(phase1169Admission.servingPolicySelectionSha256 == selection.selectionSha256)
        require(phase1169Admission.preparationSha256 == handoff.localPreparationSha256)
        require(phase1169Admission.staticTargetTreeSha256 == handoff.sourceTreeSha256)
        require(phase1169Admission.remoteHostIdentity == handoff.remoteHostIdentity)

        val base = SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmission(
            contractVersion = CONTRACT_VERSION,
            status = SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmissionStatus
                .READY_FOR_FRESH_POLICY_BOUND_READ_ONLY_PREFLIGHT,
            phase1183HandoffSha256 = handoff.handoffSha256,
            phase1180ExecutionResultSha256 = handoff.phase1180ExecutionResultSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            phase1169Admission = phase1169Admission,
            publicationPlanSha256 = requireNotNull(phase1169Admission.publicationPlanSha256),
            selectedProtocol = requireNotNull(phase1169Admission.selectedProtocol),
            remoteHostIdentity = requireNotNull(phase1169Admission.remoteHostIdentity),
            requiresFreshCredentialResolution = true,
            requiresLiveHostKeyVerification = true,
            authorizesCoordinatorReinvocation = false,
            authorizesStaticPublicationReplay = false,
            authorizesWebServingMutation = false,
            automaticRetryAuthorized = false,
            admissionSha256 = "",
        )
        return base.copy(admissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    suspend fun observeOnce(
        admission: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmission,
        handoff: SiteProductionDeploymentPostCoordinatorServingHandoff,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult {
        validateAdmission(admission)
        SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.validate(handoff)
        val expectedAdmission = admit(handoff)
        require(expectedAdmission.admissionSha256 == admission.admissionSha256) {
            "Phase 11.84 admission no longer matches the exact Phase 11.83 handoff"
        }

        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
            .validateProof(freshResolutionProof)
        require(
            freshResolutionProof.status ==
                SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus
                    .RESOLVED_TO_EPHEMERAL_LEASE,
        ) { "Phase 11.84 requires a freshly resolved ephemeral credential lease" }
        require(freshResolutionProof.serverAccessId == serverAccess.id.value)
        require(freshCredentialLease.serverAccessId == serverAccess.id.value)
        require(
            freshCredentialLease.credentialResolutionConsumptionReceiptSha256 ==
                freshResolutionProof.credentialResolutionConsumptionReceiptSha256,
        ) { "Credential lease/proof binding changed before Phase 11.84 preflight" }
        require(executedAtEpochMillis >= freshResolutionProof.resolvedAtEpochMillis)
        require(executedAtEpochMillis <= freshResolutionProof.authorizationExpiresAtEpochMillis)
        require(serverAccess.endpoint.host == admission.remoteHostIdentity)

        val selection = requireNotNull(handoff.servingPolicySelection)
        val phase1169Execution =
            SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary.observeOnce(
                admission = admission.phase1169Admission,
                selection = selection,
                freshResolutionProof = freshResolutionProof,
                freshCredentialLease = freshCredentialLease,
                serverAccess = serverAccess,
                executionAttemptId = executionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis,
            )
        SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
            .validateExecutionResult(phase1169Execution)
        require(!phase1169Execution.coordinatorInvoked)
        require(!phase1169Execution.remoteMutationPerformed)
        require(!phase1169Execution.automaticRetryPerformed)

        val base = SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult(
            contractVersion = CONTRACT_VERSION,
            phase1184AdmissionSha256 = admission.admissionSha256,
            phase1183HandoffSha256 = handoff.handoffSha256,
            phase1180ExecutionResultSha256 = handoff.phase1180ExecutionResultSha256,
            servingPolicySelectionSha256 = admission.servingPolicySelectionSha256,
            phase1169AdmissionSha256 = admission.phase1169Admission.admissionSha256,
            phase1169ExecutionResult = phase1169Execution,
            freshCredentialResolutionProofSha256 = freshResolutionProof.resolutionProofSha256,
            publicationPlanSha256 = admission.publicationPlanSha256,
            selectedProtocol = admission.selectedProtocol,
            preflightStatus = phase1169Execution.preflightStatus,
            productionNetworkTouched = phase1169Execution.preflightExecutionProof.productionNetworkTouched,
            remoteMutationPerformed = false,
            coordinatorReinvoked = false,
            staticPublicationReplayPerformed = false,
            automaticRetryPerformed = false,
            executionResultSha256 = "",
        )
        return base.copy(executionResultSha256 = executionResultSha256(base)).also(::validateExecutionResult)
    }

    fun validateAdmission(
        admission: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmission,
    ) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(admission.status == SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmissionStatus
            .READY_FOR_FRESH_POLICY_BOUND_READ_ONLY_PREFLIGHT)
        listOf(
            admission.phase1183HandoffSha256,
            admission.phase1180ExecutionResultSha256,
            admission.servingPolicySelectionSha256,
            admission.publicationPlanSha256,
            admission.admissionSha256,
        ).forEach { require(sha256.matches(it)) }
        require(admission.remoteHostIdentity.isNotBlank())
        SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
            .validateAdmission(admission.phase1169Admission)
        require(
            admission.phase1169Admission.status ==
                SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_READ_ONLY_PREFLIGHT_EXECUTION,
        )
        require(admission.phase1169Admission.servingPolicySelectionSha256 == admission.servingPolicySelectionSha256)
        require(admission.phase1169Admission.publicationPlanSha256 == admission.publicationPlanSha256)
        require(admission.phase1169Admission.selectedProtocol == admission.selectedProtocol)
        require(admission.phase1169Admission.remoteHostIdentity == admission.remoteHostIdentity)
        require(admission.requiresFreshCredentialResolution)
        require(admission.requiresLiveHostKeyVerification)
        require(!admission.authorizesCoordinatorReinvocation)
        require(!admission.authorizesStaticPublicationReplay)
        require(!admission.authorizesWebServingMutation)
        require(!admission.automaticRetryAuthorized)
        require(admission.admissionSha256 == admissionSha256(admission.copy(admissionSha256 = ""))) {
            "Phase 11.84 admission SHA-256 mismatch"
        }
    }

    fun validateExecutionResult(
        result: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        listOf(
            result.phase1184AdmissionSha256,
            result.phase1183HandoffSha256,
            result.phase1180ExecutionResultSha256,
            result.servingPolicySelectionSha256,
            result.phase1169AdmissionSha256,
            result.freshCredentialResolutionProofSha256,
            result.publicationPlanSha256,
            result.executionResultSha256,
        ).forEach { require(sha256.matches(it)) }
        SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
            .validateExecutionResult(result.phase1169ExecutionResult)
        require(result.phase1169ExecutionResult.admissionSha256 == result.phase1169AdmissionSha256)
        require(result.phase1169ExecutionResult.servingPolicySelectionSha256 == result.servingPolicySelectionSha256)
        require(result.phase1169ExecutionResult.publicationPlanSha256 == result.publicationPlanSha256)
        require(result.phase1169ExecutionResult.selectedProtocol == result.selectedProtocol)
        require(result.phase1169ExecutionResult.preflightStatus == result.preflightStatus)
        require(result.productionNetworkTouched)
        require(result.phase1169ExecutionResult.preflightExecutionProof.sessionClosed)
        require(!result.remoteMutationPerformed)
        require(!result.coordinatorReinvoked)
        require(!result.staticPublicationReplayPerformed)
        require(!result.automaticRetryPerformed)
        require(result.executionResultSha256 == executionResultSha256(result.copy(executionResultSha256 = ""))) {
            "Phase 11.84 execution-result SHA-256 mismatch"
        }
    }

    private fun admissionSha256(
        value: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightAdmission,
    ): String = digest(buildString {
        append("phase=11.84-admission\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("status=").append(value.status.name).append('\n')
        append("phase1183Handoff=").append(value.phase1183HandoffSha256).append('\n')
        append("phase1180Execution=").append(value.phase1180ExecutionResultSha256).append('\n')
        append("selection=").append(value.servingPolicySelectionSha256).append('\n')
        append("phase1169Admission=").append(value.phase1169Admission.admissionSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
        append("remoteHost=").append(value.remoteHostIdentity).append('\n')
        append("requiresFreshCredentialResolution=").append(value.requiresFreshCredentialResolution).append('\n')
        append("requiresLiveHostKeyVerification=").append(value.requiresLiveHostKeyVerification).append('\n')
        append("authorizesCoordinatorReinvocation=").append(value.authorizesCoordinatorReinvocation).append('\n')
        append("authorizesStaticPublicationReplay=").append(value.authorizesStaticPublicationReplay).append('\n')
        append("authorizesWebServingMutation=").append(value.authorizesWebServingMutation).append('\n')
        append("automaticRetryAuthorized=").append(value.automaticRetryAuthorized).append('\n')
    })

    private fun executionResultSha256(
        value: SiteProductionDeploymentPostCoordinatorPolicyBoundPreflightExecutionResult,
    ): String = digest(buildString {
        append("phase=11.84-execution\n")
        append("contractVersion=").append(value.contractVersion).append('\n')
        append("phase1184Admission=").append(value.phase1184AdmissionSha256).append('\n')
        append("phase1183Handoff=").append(value.phase1183HandoffSha256).append('\n')
        append("phase1180Execution=").append(value.phase1180ExecutionResultSha256).append('\n')
        append("selection=").append(value.servingPolicySelectionSha256).append('\n')
        append("phase1169Admission=").append(value.phase1169AdmissionSha256).append('\n')
        append("phase1169Execution=").append(value.phase1169ExecutionResult.executionResultSha256).append('\n')
        append("freshCredentialProof=").append(value.freshCredentialResolutionProofSha256).append('\n')
        append("publicationPlan=").append(value.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(value.selectedProtocol.name).append('\n')
        append("preflightStatus=").append(value.preflightStatus.name).append('\n')
        append("productionNetworkTouched=").append(value.productionNetworkTouched).append('\n')
        append("remoteMutationPerformed=").append(value.remoteMutationPerformed).append('\n')
        append("coordinatorReinvoked=").append(value.coordinatorReinvoked).append('\n')
        append("staticPublicationReplayPerformed=").append(value.staticPublicationReplayPerformed).append('\n')
        append("automaticRetryPerformed=").append(value.automaticRetryPerformed).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
