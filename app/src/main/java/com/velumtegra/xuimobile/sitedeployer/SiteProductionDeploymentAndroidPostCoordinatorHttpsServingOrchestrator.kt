package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentDurableReplayFence
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol

/**
 * Phase 11.98 release HTTPS orchestration. It reuses only already accepted primitives:
 * Phase 11.65 read-only certificate observation, Phase 11.67/11.68 local selection,
 * Phase 11.83-11.91 serving activation, and Phase 11.97 final TLS/HTTPS verification.
 *
 * There is no HTTP fallback, coordinator replay, static-publication replay or automatic retry.
 */
internal object SiteProductionDeploymentAndroidPostCoordinatorHttpsServingOrchestrator {
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    suspend fun executeOnce(
        preparation: SiteDeployerLocalPreparationResult,
        coordinatorAdmission: SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission,
        coordinatorExecution: SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionResult,
        serverAccess: ServerAccess,
        credentialProvider: SiteProductionDeploymentPostCoordinatorFreshExecutionCredentialProvider,
        replayFence: SiteProductionDeploymentDurableReplayFence,
    ): SiteProductionDeploymentPostCoordinatorHttpsServingReceipt {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
            .validateExecutionResult(coordinatorExecution, coordinatorAdmission, preparation)
        require(
            coordinatorExecution.status ==
                SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                    .COORDINATOR_COMMITTED_EXACT_STATIC_TREE,
        ) { "Post-coordinator HTTPS serving cannot run after a clean coordinator rollback" }
        require(
            preparation.remoteDeployPlan.certificate.mode ==
                SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
        ) { "Phase 11.98 HTTPS orchestration requires explicit existing 3x-ui certificate reuse intent" }
        require(serverAccess.endpoint.host == preparation.remoteDeployPlan.remoteHostIdentity) {
            "Post-coordinator HTTPS serving host differs from exact local preparation"
        }

        val eligibilityPlan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare(
            preparation.remoteDeployPlan.remoteHostIdentity,
        )
        val initialCertificateCredential = credentialProvider.acquireFreshForHttps(
            SiteProductionDeploymentPostCoordinatorCredentialPurpose.CERTIFICATE_PRE_SERVING,
        )
        val initialCertificateProof =
            SiteProductionDeploymentAndroidRealVpsExisting3xUiCertificateReuseEligibilityExecutionBoundary.observeOnce(
                plan = eligibilityPlan,
                freshResolutionProof = initialCertificateCredential.proof,
                freshCredentialLease = initialCertificateCredential.lease,
                serverAccess = serverAccess,
                executionAttemptId = initialCertificateCredential.executionAttemptId,
                executedAtEpochMillis = initialCertificateCredential.executedAtEpochMillis,
            )
        SiteProductionDeploymentAndroidRealVpsExisting3xUiCertificateReuseEligibilityExecutionBoundary
            .validateProof(initialCertificateProof)

        val staticEvidence = committedEvidence(preparation, coordinatorExecution)
        val certificateComposition =
            SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.compose(
                preparation = preparation,
                staticPublicationEvidence = staticEvidence,
                eligibilityExecutionProof = initialCertificateProof,
            )
        require(
            certificateComposition.status ==
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .HTTPS_PUBLICATION_PLAN_READY_FROM_VALIDATED_EXISTING_3X_UI_CERTIFICATE,
        ) {
            "Existing-certificate HTTPS release is blocked by Phase 11.67: ${certificateComposition.status}"
        }

        val handoff = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary.prepare(
            preparation = preparation,
            coordinatorAdmission = coordinatorAdmission,
            coordinatorExecution = coordinatorExecution,
            certificateComposition = certificateComposition,
        )
        val selection = requireNotNull(handoff.servingPolicySelection) {
            "Validated certificate composition did not yield a serving-policy selection"
        }
        require(
            selection.status == SiteProductionDeploymentServingPolicySelectionStatus
                .HTTPS_PUBLICATION_PLAN_READY_EXPLICIT_EXISTING_CERTIFICATE_REUSE,
        ) { "Phase 11.98 requires the exact Phase 11.68 HTTPS selection" }
        require(selection.selectedProtocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE)
        require(!selection.silentProtocolDowngradePerformed)

        val preflightCredential = credentialProvider.acquireFreshForHttps(
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
            mutationTransactionId = "phase11_98_cfg_${handoff.handoffSha256.take(24)}",
        )
        val phase1186 =
            SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary.prepare(
                handoff = handoff,
                phase1184Execution = phase1184Execution,
                phase1185Preparation = phase1185,
            )
        val phase1187Admission =
            SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary.admit(phase1186)
        val stagingCredential = credentialProvider.acquireFreshForHttps(
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
        val activationCredential = credentialProvider.acquireFreshForHttps(
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
        val reloadCredential = credentialProvider.acquireFreshForHttps(
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

        val postReloadCertificateCredential = credentialProvider.acquireFreshForHttps(
            SiteProductionDeploymentPostCoordinatorCredentialPurpose.CERTIFICATE_POST_RELOAD,
        )
        val postReloadCertificateProof =
            SiteProductionDeploymentAndroidRealVpsExisting3xUiCertificateReuseEligibilityExecutionBoundary.observeOnce(
                plan = eligibilityPlan,
                freshResolutionProof = postReloadCertificateCredential.proof,
                freshCredentialLease = postReloadCertificateCredential.lease,
                serverAccess = serverAccess,
                executionAttemptId = postReloadCertificateCredential.executionAttemptId,
                executedAtEpochMillis = postReloadCertificateCredential.executedAtEpochMillis,
            )
        SiteProductionDeploymentAndroidRealVpsExisting3xUiCertificateReuseEligibilityExecutionBoundary
            .validateProof(postReloadCertificateProof)
        require(postReloadCertificateProof.executionProofSha256 != initialCertificateProof.executionProofSha256) {
            "Phase 11.98 requires a distinct fresh post-reload Phase 11.65 execution proof"
        }

        val verificationPlan = SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.prepare(
            preparation = preparation,
            certificateComposition = certificateComposition,
            selection = selection,
            phase1191Execution = phase1191Execution,
            freshCertificateEligibilityProof = postReloadCertificateProof,
        )
        val verificationExecutedAt = System.currentTimeMillis()
            .coerceAtLeast(postReloadCertificateProof.certificateEvaluatedAtEpochMillis)
        val verificationResult = SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.executeOnce(
            plan = verificationPlan,
            executionAttemptId = postReloadCertificateCredential.childAttemptIdForHttps("https_tls"),
            executedAtEpochMillis = verificationExecutedAt,
        )
        SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.validateResult(verificationResult)
        require(
            verificationResult.status ==
                SiteProductionDeploymentHttpsTlsServingVerificationStatus
                    .HTTPS_TLS_IDENTITY_AND_EXACT_INDEX_VERIFIED,
        )
        require(!verificationResult.remoteMutationPerformed)
        require(!verificationResult.coordinatorReinvoked)
        require(!verificationResult.staticPublicationReplayPerformed)
        require(!verificationResult.automaticRetryPerformed)

        return SiteProductionDeploymentAndroidPostCoordinatorHttpsServingReceiptBoundary.completeAfterValidatedChain(
            preparationSha256 = preparation.preparationSha256,
            phase1180AdmissionSha256 = coordinatorAdmission.admissionSha256,
            phase1180ExecutionResultSha256 = coordinatorExecution.executionResultSha256,
            initialCertificateEligibilityExecutionProofSha256 = initialCertificateProof.executionProofSha256,
            certificateCompositionSha256 = certificateComposition.compositionSha256,
            servingPolicySelectionSha256 = selection.selectionSha256,
            phase1191ExecutionResultSha256 = phase1191Execution.executionResultSha256,
            freshPostReloadCertificateEligibilityExecutionProofSha256 =
                postReloadCertificateProof.executionProofSha256,
            verificationPlan = verificationPlan,
            verificationResult = verificationResult,
            completedAtEpochMillis = System.currentTimeMillis().coerceAtLeast(verificationResult.executedAtEpochMillis),
        )
    }

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

    private suspend fun SiteProductionDeploymentPostCoordinatorFreshExecutionCredentialProvider.acquireFreshForHttps(
        purpose: SiteProductionDeploymentPostCoordinatorCredentialPurpose,
    ): SiteProductionDeploymentRealVpsExecutionCredential = acquire(purpose).also { credential ->
        require(canonicalId.matches(credential.executionAttemptId)) {
            "Post-coordinator HTTPS credential executionAttemptId must be canonical"
        }
        require(credential.executedAtEpochMillis >= credential.proof.resolvedAtEpochMillis) {
            "Post-coordinator HTTPS execution cannot predate fresh credential resolution"
        }
    }

    private fun SiteProductionDeploymentRealVpsExecutionCredential.childAttemptIdForHttps(suffix: String): String {
        val child = "${executionAttemptId.take(96)}_$suffix"
        require(canonicalId.matches(child)) { "Derived HTTPS verification attempt id is not canonical" }
        return child
    }
}
