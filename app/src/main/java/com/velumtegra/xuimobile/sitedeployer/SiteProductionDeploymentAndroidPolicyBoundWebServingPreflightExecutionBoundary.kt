package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import java.security.MessageDigest

/**
 * Phase 11.69: binds the explicit Phase 11.68 serving-policy decision to the already reviewed
 * Phase 11.57 real-VPS read-only web-serving preflight execution path.
 *
 * Admission is local-only. A selected publication plan does not itself open SSH: a separate
 * observeOnce call still requires the fresh credential-resolution proof/lease and the existing
 * live host-key verification path. Blocked Phase 11.68 results fail before any network call.
 */
internal object SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun admit(
        selection: SiteProductionDeploymentServingPolicySelectionResult,
    ): SiteProductionDeploymentPolicyBoundWebServingPreflightAdmission {
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)

        val ready = selection.publicationPlanSelected
        val plan = selection.publicationPlan
        if (ready) {
            requireNotNull(plan)
            requireNotNull(selection.selectedProtocol)
            require(plan.protocol == selection.selectedProtocol)
        } else {
            require(plan == null)
            require(selection.selectedProtocol == null)
        }

        val base = SiteProductionDeploymentPolicyBoundWebServingPreflightAdmission(
            contractVersion = CONTRACT_VERSION,
            status = if (ready) {
                SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_READ_ONLY_PREFLIGHT_EXECUTION
            } else {
                SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                    .BLOCKED_BY_EXPLICIT_SERVING_POLICY
            },
            servingPolicySelectionSha256 = selection.selectionSha256,
            preparationSha256 = selection.preparationSha256,
            staticTargetTreeSha256 = selection.staticTargetTreeSha256,
            selectedProtocol = selection.selectedProtocol,
            publicationPlanSha256 = plan?.publicationPlanSha256,
            remoteHostIdentity = plan?.remoteHostIdentity,
            readOnlyPreflightExecutionEligible = ready,
            freshCredentialResolutionRequired = ready,
            liveHostKeyVerificationRequired = ready,
            productionNetworkTouchedByAdmission = false,
            remoteMutationAuthorized = false,
            configMutationAuthorized = false,
            webServerReloadAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            privateKeyContentReadAuthorized = false,
            automaticRetryAuthorized = false,
            coordinatorInvoked = false,
            exposesDeployUiAction = false,
            admissionSha256 = "",
        )
        return base.copy(admissionSha256 = admissionSha256(base)).also(::validateAdmission)
    }

    suspend fun observeOnce(
        admission: SiteProductionDeploymentPolicyBoundWebServingPreflightAdmission,
        selection: SiteProductionDeploymentServingPolicySelectionResult,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult {
        validateAdmission(admission)
        SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
        require(admission.servingPolicySelectionSha256 == selection.selectionSha256) {
            "Phase 11.69 admission belongs to a different serving-policy selection"
        }
        require(
            admission.status ==
                SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_READ_ONLY_PREFLIGHT_EXECUTION,
        ) { "Blocked Phase 11.68 serving policy cannot execute real-VPS web-serving preflight" }
        require(admission.readOnlyPreflightExecutionEligible)
        require(admission.freshCredentialResolutionRequired)
        require(admission.liveHostKeyVerificationRequired)

        val plan = requireNotNull(selection.publicationPlan)
        val protocol = requireNotNull(selection.selectedProtocol)
        require(selection.publicationPlanSelected)
        require(plan.protocol == protocol)
        require(admission.publicationPlanSha256 == plan.publicationPlanSha256)
        require(admission.selectedProtocol == protocol)
        require(admission.remoteHostIdentity == plan.remoteHostIdentity)
        require(serverAccess.endpoint.host == plan.remoteHostIdentity) {
            "Phase 11.69 server access belongs to a different publication host"
        }

        val proof =
            SiteProductionDeploymentAndroidRealVpsWebServingReadOnlyPreflightExecutionBoundary.observeOnce(
                plan = plan,
                freshResolutionProof = freshResolutionProof,
                freshCredentialLease = freshCredentialLease,
                serverAccess = serverAccess,
                executionAttemptId = executionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis,
            )
        SiteProductionDeploymentAndroidRealVpsWebServingReadOnlyPreflightExecutionBoundary.validateProof(proof)
        require(proof.publicationPlanSha256 == plan.publicationPlanSha256)

        val base = SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult(
            contractVersion = CONTRACT_VERSION,
            servingPolicySelectionSha256 = selection.selectionSha256,
            admissionSha256 = admission.admissionSha256,
            publicationPlanSha256 = plan.publicationPlanSha256,
            selectedProtocol = protocol,
            preflightStatus = proof.preflightReport.status,
            preflightExecutionProof = proof,
            exactPolicyPlanBindingVerified = true,
            freshCredentialProofRequired = true,
            liveHostKeyVerified = proof.hostKeyPinVerifiedAgainstRemote,
            remoteMutationPerformed = false,
            configMutationAuthorized = false,
            webServerReloadAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            privateKeyContentReadPerformed = false,
            automaticRetryPerformed = false,
            coordinatorInvoked = false,
            exposesDeployUiAction = false,
            executionResultSha256 = "",
        )
        return base.copy(executionResultSha256 = executionResultSha256(base)).also(::validateExecutionResult)
    }

    fun validateAdmission(
        admission: SiteProductionDeploymentPolicyBoundWebServingPreflightAdmission,
    ) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(admission.servingPolicySelectionSha256))
        require(sha256.matches(admission.preparationSha256))
        require(sha256.matches(admission.staticTargetTreeSha256))
        require(!admission.productionNetworkTouchedByAdmission)
        require(!admission.remoteMutationAuthorized)
        require(!admission.configMutationAuthorized)
        require(!admission.webServerReloadAuthorized)
        require(!admission.dnsMutationAuthorized)
        require(!admission.firewallMutationAuthorized)
        require(!admission.packageInstallAuthorized)
        require(!admission.privateKeyContentReadAuthorized)
        require(!admission.automaticRetryAuthorized)
        require(!admission.coordinatorInvoked)
        require(!admission.exposesDeployUiAction)

        when (admission.status) {
            SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                .READY_FOR_SEPARATE_REAL_VPS_READ_ONLY_PREFLIGHT_EXECUTION -> {
                require(admission.readOnlyPreflightExecutionEligible)
                require(admission.freshCredentialResolutionRequired)
                require(admission.liveHostKeyVerificationRequired)
                requireNotNull(admission.selectedProtocol)
                require(admission.publicationPlanSha256?.matches(sha256) == true)
                require(!admission.remoteHostIdentity.isNullOrBlank())
            }
            SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                .BLOCKED_BY_EXPLICIT_SERVING_POLICY -> {
                require(!admission.readOnlyPreflightExecutionEligible)
                require(!admission.freshCredentialResolutionRequired)
                require(!admission.liveHostKeyVerificationRequired)
                require(admission.selectedProtocol == null)
                require(admission.publicationPlanSha256 == null)
                require(admission.remoteHostIdentity == null)
            }
        }

        require(
            admission.admissionSha256 ==
                admissionSha256(admission.copy(admissionSha256 = "")),
        ) { "Phase 11.69 admission SHA-256 mismatch" }
    }

    fun validateExecutionResult(
        result: SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
    ) {
        require(result.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(result.servingPolicySelectionSha256))
        require(sha256.matches(result.admissionSha256))
        require(sha256.matches(result.publicationPlanSha256))
        SiteProductionDeploymentAndroidRealVpsWebServingReadOnlyPreflightExecutionBoundary
            .validateProof(result.preflightExecutionProof)
        require(
            result.preflightExecutionProof.publicationPlanSha256 == result.publicationPlanSha256,
        )
        require(result.preflightExecutionProof.preflightReport.status == result.preflightStatus)
        require(result.exactPolicyPlanBindingVerified)
        require(result.freshCredentialProofRequired)
        require(result.liveHostKeyVerified)
        require(result.preflightExecutionProof.productionNetworkTouched)
        require(result.preflightExecutionProof.sessionClosed)
        require(result.preflightExecutionProof.preflightReport.publicationPlanSha256 == result.publicationPlanSha256)
        require(!result.remoteMutationPerformed)
        require(!result.configMutationAuthorized)
        require(!result.webServerReloadAuthorized)
        require(!result.dnsMutationAuthorized)
        require(!result.firewallMutationAuthorized)
        require(!result.packageInstallAuthorized)
        require(!result.privateKeyContentReadPerformed)
        require(!result.automaticRetryPerformed)
        require(!result.coordinatorInvoked)
        require(!result.exposesDeployUiAction)
        require(result.executionResultSha256 == executionResultSha256(result.copy(executionResultSha256 = ""))) {
            "Phase 11.69 execution-result SHA-256 mismatch"
        }
    }

    private fun admissionSha256(
        admission: SiteProductionDeploymentPolicyBoundWebServingPreflightAdmission,
    ): String = digest(buildString {
        append("phase=11.69-admission\n")
        append("contractVersion=").append(admission.contractVersion).append('\n')
        append("status=").append(admission.status.name).append('\n')
        append("selection=").append(admission.servingPolicySelectionSha256).append('\n')
        append("preparation=").append(admission.preparationSha256).append('\n')
        append("staticTargetTree=").append(admission.staticTargetTreeSha256).append('\n')
        append("selectedProtocol=").append(admission.selectedProtocol?.name ?: "").append('\n')
        append("publicationPlan=").append(admission.publicationPlanSha256 ?: "").append('\n')
        append("remoteHostIdentity=").append(admission.remoteHostIdentity ?: "").append('\n')
        append("readOnlyPreflightExecutionEligible=").append(admission.readOnlyPreflightExecutionEligible).append('\n')
        append("freshCredentialResolutionRequired=").append(admission.freshCredentialResolutionRequired).append('\n')
        append("liveHostKeyVerificationRequired=").append(admission.liveHostKeyVerificationRequired).append('\n')
        append("productionNetworkTouchedByAdmission=").append(admission.productionNetworkTouchedByAdmission).append('\n')
        append("remoteMutationAuthorized=").append(admission.remoteMutationAuthorized).append('\n')
        append("configMutationAuthorized=").append(admission.configMutationAuthorized).append('\n')
        append("webServerReloadAuthorized=").append(admission.webServerReloadAuthorized).append('\n')
        append("dnsMutationAuthorized=").append(admission.dnsMutationAuthorized).append('\n')
        append("firewallMutationAuthorized=").append(admission.firewallMutationAuthorized).append('\n')
        append("packageInstallAuthorized=").append(admission.packageInstallAuthorized).append('\n')
        append("privateKeyContentReadAuthorized=").append(admission.privateKeyContentReadAuthorized).append('\n')
        append("automaticRetryAuthorized=").append(admission.automaticRetryAuthorized).append('\n')
        append("coordinatorInvoked=").append(admission.coordinatorInvoked).append('\n')
        append("exposesDeployUiAction=").append(admission.exposesDeployUiAction).append('\n')
    })

    private fun executionResultSha256(
        result: SiteProductionDeploymentPolicyBoundWebServingPreflightExecutionResult,
    ): String = digest(buildString {
        append("phase=11.69-execution\n")
        append("contractVersion=").append(result.contractVersion).append('\n')
        append("selection=").append(result.servingPolicySelectionSha256).append('\n')
        append("admission=").append(result.admissionSha256).append('\n')
        append("publicationPlan=").append(result.publicationPlanSha256).append('\n')
        append("selectedProtocol=").append(result.selectedProtocol.name).append('\n')
        append("preflightStatus=").append(result.preflightStatus.name).append('\n')
        append("preflightExecutionProof=").append(result.preflightExecutionProof.executionProofSha256).append('\n')
        append("exactPolicyPlanBindingVerified=").append(result.exactPolicyPlanBindingVerified).append('\n')
        append("freshCredentialProofRequired=").append(result.freshCredentialProofRequired).append('\n')
        append("liveHostKeyVerified=").append(result.liveHostKeyVerified).append('\n')
        append("remoteMutationPerformed=").append(result.remoteMutationPerformed).append('\n')
        append("configMutationAuthorized=").append(result.configMutationAuthorized).append('\n')
        append("webServerReloadAuthorized=").append(result.webServerReloadAuthorized).append('\n')
        append("dnsMutationAuthorized=").append(result.dnsMutationAuthorized).append('\n')
        append("firewallMutationAuthorized=").append(result.firewallMutationAuthorized).append('\n')
        append("packageInstallAuthorized=").append(result.packageInstallAuthorized).append('\n')
        append("privateKeyContentReadPerformed=").append(result.privateKeyContentReadPerformed).append('\n')
        append("automaticRetryPerformed=").append(result.automaticRetryPerformed).append('\n')
        append("coordinatorInvoked=").append(result.coordinatorInvoked).append('\n')
        append("exposesDeployUiAction=").append(result.exposesDeployUiAction).append('\n')
    })

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
