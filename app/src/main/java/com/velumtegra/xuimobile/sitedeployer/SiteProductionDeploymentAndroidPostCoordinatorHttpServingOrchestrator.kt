package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentDurableReplayFence
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol

/**
 * Fresh credential purposes for the accepted post-coordinator serving chains. These purposes
 * are deliberately separate from the Phase 11.55 static-file transaction steps: one credential
 * lease may never be silently reused across static publication and nginx serving operations.
 */
internal enum class SiteProductionDeploymentPostCoordinatorCredentialPurpose {
    CERTIFICATE_PRE_SERVING,
    READ_ONLY_PREFLIGHT,
    STAGING_SYNTAX,
    CONFIG_ACTIVATION,
    NGINX_RELOAD,
    SERVING_VERIFICATION,
    CERTIFICATE_POST_RELOAD,
    CADDY_APPLY,
    CADDY_VERIFY,
    CADDY_ROLLBACK,
}

/**
 * Phase 11.94/11.98 input capability. Each call must return a newly resolved one-shot credential lease
 * bound to the reviewed server. The orchestrator never retries a failed purpose automatically.
 */
internal fun interface SiteProductionDeploymentPostCoordinatorFreshExecutionCredentialProvider {
    suspend fun acquire(
        purpose: SiteProductionDeploymentPostCoordinatorCredentialPurpose,
    ): SiteProductionDeploymentRealVpsExecutionCredential
}

/**
 * Phase 11.94 composes the already accepted Phase 11.83 -> 11.92 boundaries after one successful
 * Phase 11.80 exact-static-tree commit. It adds no primitive SSH/SFTP/command authority. HTTP-only
 * is explicit: certificate reuse / HTTPS stays fail-closed until a separate TLS verifier exists.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorHttpServingOrchestrator {
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun executeOnce(
        preparation: SiteDeployerLocalPreparationResult,
        coordinatorAdmission: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission,
        coordinatorExecution: SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionResult,
        serverAccess: ServerAccess,
        credentialProvider: SiteProductionDeploymentPostCoordinatorFreshExecutionCredentialProvider,
        replayFence: SiteProductionDeploymentDurableReplayFence,
    ): SiteProductionDeploymentPostCoordinatorServingPathVerificationResult {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
            .validateExecutionResult(coordinatorExecution, coordinatorAdmission, preparation)
        require(
            coordinatorExecution.status ==
                SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                    .COORDINATOR_COMMITTED_EXACT_STATIC_TREE,
        ) { "Post-coordinator serving cannot run after a clean coordinator rollback" }
        require(preparation.remoteDeployPlan.certificate.mode == SiteCertificateReuseMode.NONE) {
            "Phase 11.94 HTTP orchestration blocks certificate reuse until TLS verification authority exists"
        }
        require(serverAccess.endpoint.host == preparation.remoteDeployPlan.remoteHostIdentity) {
            "Post-coordinator serving host differs from exact local preparation"
        }

        val handoff = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.prepare(
            preparation = preparation,
            coordinatorAdmission = coordinatorAdmission,
            coordinatorExecution = coordinatorExecution,
        )
        val selection = requireNotNull(handoff.servingPolicySelection) {
            "Committed coordinator result did not yield a serving-policy selection"
        }
        require(selection.selectedProtocol == SiteWebServingProtocol.HTTP) {
            "Phase 11.94 accepts only the already verified HTTP serving path"
        }

        val preflightCredential = credentialProvider.acquireFresh(
            SiteProductionDeploymentPostCoordinatorCredentialPurpose.READ_ONLY_PREFLIGHT,
        )
        val phase1184Admission =
            SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary.admit(handoff)
        val phase1184Execution =
            SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary.observeOnce(
                admission = phase1184Admission,
                handoff = handoff,
                freshResolutionProof = preflightCredential.proof,
                freshCredentialLease = preflightCredential.lease,
                serverAccess = serverAccess,
                executionAttemptId = preflightCredential.executionAttemptId,
                executedAtEpochMillis = preflightCredential.executedAtEpochMillis,
            )
        SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
            .validateExecutionResult(phase1184Execution)

        val phase1185 = SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary.prepare(
            handoff = handoff,
            phase1184Execution = phase1184Execution,
            mutationTransactionId = "phase11_94_cfg_${handoff.handoffSha256.take(24)}",
        )
        val phase1186 =
            SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary.prepare(
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
            )
        val phase1187Admission =
            SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary.admit(phase1186)
        val stagingCredential = credentialProvider.acquireFresh(
            SiteProductionDeploymentPostCoordinatorCredentialPurpose.STAGING_SYNTAX,
        )
        val phase1187Execution =
            SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary.executeOnce(
                admission = phase1187Admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
                phase1186AuthorityPreparation = phase1186,
                freshResolutionProof = stagingCredential.proof,
                freshCredentialLease = stagingCredential.lease,
                serverAccess = serverAccess,
                executionAttemptId = stagingCredential.executionAttemptId,
                executedAtEpochMillis = stagingCredential.executedAtEpochMillis,
                executionUsePort = replayFence.realVpsWebServingConfigStagingSyntaxExecutionUsePort(),
            )
        SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
            .validateExecutionResultAgainst(
                result = phase1187Execution,
                admission = phase1187Admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
                phase1186AuthorityPreparation = phase1186,
            )

        val phase1188 =
            SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary.prepare(
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
                phase1186AuthorityPreparation = phase1186,
                phase1187Execution = phase1187Execution,
            )
        val phase1189Admission =
            SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary.admit(phase1188)
        val activationCredential = credentialProvider.acquireFresh(
            SiteProductionDeploymentPostCoordinatorCredentialPurpose.CONFIG_ACTIVATION,
        )
        val phase1189Execution =
            SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary.executeOnce(
                admission = phase1189Admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
                phase1186AuthorityPreparation = phase1186,
                phase1187Execution = phase1187Execution,
                phase1188AuthorityPreparation = phase1188,
                freshResolutionProof = activationCredential.proof,
                freshCredentialLease = activationCredential.lease,
                serverAccess = serverAccess,
                executionAttemptId = activationCredential.executionAttemptId,
                executedAtEpochMillis = activationCredential.executedAtEpochMillis,
                executionUsePort = replayFence.realVpsWebServingConfigActivationExecutionUsePort(),
            )
        SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary
            .validateExecutionResultAgainst(
                result = phase1189Execution,
                admission = phase1189Admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
                phase1186AuthorityPreparation = phase1186,
                phase1187Execution = phase1187Execution,
                phase1188AuthorityPreparation = phase1188,
            )

        val phase1190 =
            SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundary.prepare(
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
                phase1186AuthorityPreparation = phase1186,
                phase1187Execution = phase1187Execution,
                phase1188AuthorityPreparation = phase1188,
                phase1189Execution = phase1189Execution,
            )
        val phase1191Admission =
            SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary.admit(phase1190)
        val reloadCredential = credentialProvider.acquireFresh(
            SiteProductionDeploymentPostCoordinatorCredentialPurpose.NGINX_RELOAD,
        )
        val phase1191Execution =
            SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary.executeOnce(
                admission = phase1191Admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
                phase1186AuthorityPreparation = phase1186,
                phase1187Execution = phase1187Execution,
                phase1188AuthorityPreparation = phase1188,
                phase1189Execution = phase1189Execution,
                phase1190AuthorityPreparation = phase1190,
                freshResolutionProof = reloadCredential.proof,
                freshCredentialLease = reloadCredential.lease,
                serverAccess = serverAccess,
                executionAttemptId = reloadCredential.executionAttemptId,
                executedAtEpochMillis = reloadCredential.executedAtEpochMillis,
                executionUsePort = replayFence.realVpsWebServingNginxReloadExecutionUsePort(),
            )
        SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary
            .validateExecutionResultAgainst(
                result = phase1191Execution,
                admission = phase1191Admission,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
                phase1186AuthorityPreparation = phase1186,
                phase1187Execution = phase1187Execution,
                phase1188AuthorityPreparation = phase1188,
                phase1189Execution = phase1189Execution,
                phase1190AuthorityPreparation = phase1190,
            )

        val phase1192Admission =
            SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary.admit(
                preparation = preparation,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
                phase1186AuthorityPreparation = phase1186,
                phase1187Execution = phase1187Execution,
                phase1188AuthorityPreparation = phase1188,
                phase1189Execution = phase1189Execution,
                phase1190AuthorityPreparation = phase1190,
                phase1191Admission = phase1191Admission,
                phase1191Execution = phase1191Execution,
            )
        val verificationCredential = credentialProvider.acquireFresh(
            SiteProductionDeploymentPostCoordinatorCredentialPurpose.SERVING_VERIFICATION,
        )
        val phase1192Execution =
            SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary.executeOnce(
                admission = phase1192Admission,
                preparation = preparation,
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
                phase1186AuthorityPreparation = phase1186,
                phase1187Execution = phase1187Execution,
                phase1188AuthorityPreparation = phase1188,
                phase1189Execution = phase1189Execution,
                phase1190AuthorityPreparation = phase1190,
                phase1191Admission = phase1191Admission,
                phase1191Execution = phase1191Execution,
                freshResolutionProof = verificationCredential.proof,
                freshCredentialLease = verificationCredential.lease,
                serverAccess = serverAccess,
                loopbackExecutionAttemptId = verificationCredential.childAttemptId("loopback"),
                externalExecutionAttemptId = verificationCredential.childAttemptId("external"),
                domainExecutionAttemptId = verificationCredential.childAttemptId("domain"),
                executedAtEpochMillis = verificationCredential.executedAtEpochMillis,
            )
        SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary
            .validateExecutionResultAgainst(
                value = phase1192Execution,
                admission = phase1192Admission,
                phase1191Execution = phase1191Execution,
            )
        require(
            phase1192Execution.status ==
                SiteProductionDeploymentPostCoordinatorServingPathVerificationStatus
                    .COMPLETE_SERVING_PATH_VERIFIED_LOOPBACK_EXTERNAL_IPV4_AND_DOMAIN_DNS_EXACT_BODY,
        ) { "Phase 11.94 requires the exact accepted complete HTTP serving-path outcome" }
        require(!phase1192Execution.remoteMutationPerformed)
        require(!phase1192Execution.coordinatorReinvoked)
        require(!phase1192Execution.staticPublicationReplayPerformed)
        require(!phase1192Execution.automaticRetryPerformed)
        return phase1192Execution
    }

    private suspend fun SiteProductionDeploymentPostCoordinatorFreshExecutionCredentialProvider.acquireFresh(
        purpose: SiteProductionDeploymentPostCoordinatorCredentialPurpose,
    ): SiteProductionDeploymentRealVpsExecutionCredential = acquire(purpose).also { credential ->
        require(canonicalId.matches(credential.executionAttemptId)) {
            "Post-coordinator credential executionAttemptId must be canonical"
        }
        require(credential.executedAtEpochMillis >= credential.proof.resolvedAtEpochMillis) {
            "Post-coordinator execution cannot predate fresh credential resolution"
        }
    }

    private fun SiteProductionDeploymentRealVpsExecutionCredential.childAttemptId(suffix: String): String {
        val child = "${executionAttemptId.take(96)}_$suffix"
        require(canonicalId.matches(child)) { "Derived serving verification attempt id is not canonical" }
        return child
    }
}
