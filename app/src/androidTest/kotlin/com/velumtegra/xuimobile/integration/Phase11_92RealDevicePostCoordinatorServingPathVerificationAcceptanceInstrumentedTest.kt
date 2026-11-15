package com.velumtegra.xuimobile.integration

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.StrictMode
import android.util.Base64
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorServingPathVerificationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsStaticFileTransactionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsExecutionCredential
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsStaticFileTransactionOutcome
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsStaticFileTransactionRequest
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsStaticFileTransactionStep
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingNginxReloadExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidServingPolicySelectionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmissionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorConfigActivationExecutionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmissionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorNginxReloadExecutionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorServingHandoff
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorServingHandoffStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Arrays
import java.time.Duration
import java.util.Comparator
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_92RealDevicePostCoordinatorServingPathVerificationAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() =
        context.applicationContext as VelumTegraApplication

    @Test
    fun postCoordinatorCompleteServingPathVerifiesLoopbackExternalIpv4AndDomainDnsWithoutReplay() =
        runBlocking {
            val nonce = requiredRunNonce()
            mark("STEP_01_TEST_START")
            assertInternetPermissionDeclared()
            val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
            require(configFile.isFile) { "Phase 11.92 one-shot real-VPS acceptance config is missing" }
            val config = OneShotPhase11_92Config.readAndDelete(configFile)
            val secretStore = AndroidKeystoreSecretStore(context)
            val secretId = SecretId("phase11_92_acceptance_credential")
            val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_92-")
            var publicationConfigPath: String? = null
            var publicationConfigSha: String? = null
            try {
                secretStore.delete(secretId)
                val access = ServerAccess(
                    id = ServerAccessId("phase11_92_access_$nonce"),
                    serverId = ServerId("phase11_92_server_$nonce"),
                    endpoint = SshEndpoint(config.host, config.port),
                    username = config.username,
                    auth = SshAuthRef.Password(secretId),
                    pinnedHostKey = HostKeyFingerprint(config.hostKeySha256),
                )
                val material = config.toSecretMaterial()
                try {
                    assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material))
                } finally {
                    material.close()
                    config.closeSensitiveBytes()
                }
                mark("STEP_02_SECRET_CREATED")

                val preparation = prepare(
                    root = localRoot,
                    host = config.host,
                    targetRoot = "/tmp/velum-p1192-${nonce.take(16)}",
                )
                var staticCredentialSequence = 0
                val staticTransaction =
                    application.siteProductionDeploymentExecuteRealVpsStaticFileTransactionOnce(
                        request = SiteProductionDeploymentRealVpsStaticFileTransactionRequest(
                            preparation = preparation,
                            serverAccess = access,
                        ),
                        credentialProvider =
                            object : SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider {
                                override suspend fun acquire(
                                    step: SiteProductionDeploymentRealVpsStaticFileTransactionStep,
                                ): SiteProductionDeploymentRealVpsExecutionCredential {
                                    staticCredentialSequence += 1
                                    val resolved = resolveFreshCredential(
                                        access = access,
                                        nonce = nonce,
                                        suffix = "static$staticCredentialSequence",
                                        base = 100_000L + staticCredentialSequence * 5_000L,
                                    )
                                    return SiteProductionDeploymentRealVpsExecutionCredential(
                                        proof = resolved.proof,
                                        lease = resolved.lease,
                                        executionAttemptId =
                                            "phase11_92_static_${staticCredentialSequence}_${nonce.take(12)}",
                                        executedAtEpochMillis = resolved.proof.resolvedAtEpochMillis + 10L,
                                    )
                                }
                            },
                    ).also(SiteProductionDeploymentAndroidRealVpsStaticFileTransactionBoundary::validateResult)
                assertEquals(
                    SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.COMMITTED_CLEAN,
                    staticTransaction.outcome,
                )
                assertEquals(preparation.bundle.manifest.treeSha256, staticTransaction.finalTargetTreeSha256)
                assertTrue(staticTransaction.remoteResidualStateClean)
                assertFalse(staticTransaction.automaticRetryPerformed)
                assertFalse(staticTransaction.coordinatorInvoked)
                assertFalse(staticTransaction.exposesDeployUiAction)
                mark("STEP_03_STATIC_PUBLICATION_COMMITTED_CLEAN")

                val handoff = readyHandoff(
                    preparation = preparation,
                    finalTargetTreeSha256 = requireNotNull(staticTransaction.finalTargetTreeSha256),
                )
                val phase1184Admission =
                    SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
                        .admit(handoff)
                val preflightCredential = resolveFreshCredential(access, nonce, "preflight", 170_000L)
                val phase1184Execution =
                    SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
                        .observeOnce(
                            admission = phase1184Admission,
                            handoff = handoff,
                            freshResolutionProof = preflightCredential.proof,
                            freshCredentialLease = preflightCredential.lease,
                            serverAccess = access,
                            executionAttemptId = "phase11_92_web_preflight_${nonce.take(16)}",
                            executedAtEpochMillis = preflightCredential.proof.resolvedAtEpochMillis + 10L,
                        )
                SiteProductionDeploymentAndroidPostCoordinatorPolicyBoundPreflightBoundary
                    .validateExecutionResult(phase1184Execution)
                assertTrue(phase1184Execution.productionNetworkTouched)
                assertFalse(phase1184Execution.remoteMutationPerformed)
                assertFalse(phase1184Execution.coordinatorReinvoked)
                assertFalse(phase1184Execution.staticPublicationReplayPerformed)
                mark("STEP_03_EXACT_PHASE1183_TO_PHASE1184_PREFLIGHT_PROOF_READY")

                val priorPolicy = StrictMode.getThreadPolicy()
                val phase1185: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorConfigMutationPreparationResult
                val phase1186: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationResult
                val phase1187Admission: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmission
                try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    phase1185 =
                        SiteProductionDeploymentAndroidPostCoordinatorConfigMutationPreparationBoundary
                            .prepare(
                                handoff = handoff,
                                phase1184Execution = phase1184Execution,
                                mutationTransactionId = "phase11_92_tx_${nonce.take(16)}",
                            )
                    phase1186 =
                        SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxAuthorityPreparationBoundary
                            .prepare(
                                handoff = handoff,
                                phase1184Execution = phase1184Execution,
                                phase1185Preparation = phase1185,
                            )
                    phase1187Admission =
                        SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
                            .admit(phase1186)
                } finally {
                    StrictMode.setThreadPolicy(priorPolicy)
                }
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorStagingSyntaxAuthorityPreparationStatus
                        .READY_FOR_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION,
                    phase1186.status,
                )
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionAdmissionStatus
                        .READY_FOR_FRESH_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION,
                    phase1187Admission.status,
                )
                assertTrue(phase1187Admission.realVpsExecutionEligible)
                assertTrue(phase1187Admission.requiresFreshCredentialResolution)
                assertTrue(phase1187Admission.requiresLiveRemoteHostKeyVerification)
                assertFalse(phase1187Admission.exactConfigActivationAuthorized)
                assertFalse(phase1187Admission.webServerReloadAuthorized)
                assertFalse(phase1187Admission.coordinatorReinvocationAuthorized)
                assertFalse(phase1187Admission.staticPublicationReplayAuthorized)
                assertFalse(phase1187Admission.automaticRetryAuthorized)
                mark("STEP_04_PHASE1185_PHASE1186_PHASE1187_LOCAL_BINDING_COMPLETE")

                val beforeFence = application.siteProductionDeploymentReplayFence.snapshot()
                val stageCredential = resolveFreshCredential(access, nonce, "stage", 180_000L)
                val execution =
                    SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
                        .executeOnce(
                            admission = phase1187Admission,
                            handoff = handoff,
                            phase1184Execution = phase1184Execution,
                            phase1185Preparation = phase1185,
                            phase1186AuthorityPreparation = phase1186,
                            freshResolutionProof = stageCredential.proof,
                            freshCredentialLease = stageCredential.lease,
                            serverAccess = access,
                            executionAttemptId = "phase11_92_stage_syntax_${nonce.take(16)}",
                            executedAtEpochMillis = stageCredential.proof.resolvedAtEpochMillis + 10L,
                            executionUsePort =
                                application.siteProductionDeploymentReplayFence
                                    .realVpsWebServingConfigStagingSyntaxExecutionUsePort(),
                        )
                SiteProductionDeploymentAndroidPostCoordinatorStagingSyntaxExecutionBoundary
                    .validateExecutionResultAgainst(
                        result = execution,
                        admission = phase1187Admission,
                        handoff = handoff,
                        phase1184Execution = phase1184Execution,
                        phase1185Preparation = phase1185,
                        phase1186AuthorityPreparation = phase1186,
                    )
                SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary
                    .validateProof(execution.phase1172ExecutionResult.phase11_59ExecutionProof)
                val afterFence = application.siteProductionDeploymentReplayFence.snapshot()
                assertEquals(
                    beforeFence.realVpsWebServingConfigStagingSyntaxExecutionReceiptMarkerCount + 1,
                    afterFence.realVpsWebServingConfigStagingSyntaxExecutionReceiptMarkerCount,
                )
                mark("STEP_05_ONE_POST_COORDINATOR_STAGING_SYNTAX_EXECUTION_COMPLETE")

                assertEquals(
                    SiteProductionDeploymentPostCoordinatorStagingSyntaxExecutionStatus
                        .EXECUTED_AND_CLEANED_WITHOUT_CONFIG_ACTIVATION_OR_COORDINATOR_REPLAY,
                    execution.status,
                )
                assertEquals(phase1187Admission.admissionSha256, execution.phase1187AdmissionSha256)
                assertEquals(phase1186.authorityPreparationResultSha256, execution.phase1186AuthorityPreparationResultSha256)
                assertEquals(handoff.handoffSha256, execution.phase1183HandoffSha256)
                assertEquals(phase1184Execution.executionResultSha256, execution.phase1184ExecutionResultSha256)
                assertEquals(phase1185.preparationResultSha256, execution.phase1185PreparationResultSha256)
                assertEquals(SiteWebServingProtocol.HTTP, execution.selectedProtocol)
                assertTrue(execution.exactPostCoordinatorChainBindingVerified)
                assertTrue(execution.durableBaselineCheckpointRecorded)
                assertTrue(execution.credentialLeaseMaterialConsumed)
                assertTrue(execution.productionNetworkTouched)
                assertTrue(execution.liveHostKeyPinVerified)
                assertTrue(execution.operationOwnedStagingWritePerformed)
                assertTrue(execution.operationOwnedValidationWritePerformed)
                assertTrue(execution.nginxSyntaxValidationPassed)
                assertTrue(execution.operationOwnedCleanupVerified)
                assertFalse(execution.exactConfigActivationPerformed)
                assertFalse(execution.webServerReloadPerformed)
                assertFalse(execution.coordinatorReinvoked)
                assertFalse(execution.staticPublicationReplayPerformed)
                assertFalse(execution.automaticRetryPerformed)
                assertEquals(7, execution.phase1172ExecutionResult.phase11_59ExecutionProof.remoteCommandCount)
                assertTrue(execution.phase1172ExecutionResult.phase11_59ExecutionProof.exactConfigPathAbsentAfterValidation)
                assertTrue(execution.phase1172ExecutionResult.phase11_59ExecutionProof.listenerStillFreeAfterValidation)
                assertTrue(execution.phase1172ExecutionResult.phase11_59ExecutionProof.stagingConfigAbsentAfterCleanup)
                assertTrue(execution.phase1172ExecutionResult.phase11_59ExecutionProof.validationConfigAbsentAfterCleanup)
                assertTrue(execution.phase1172ExecutionResult.phase11_59ExecutionProof.validationPidAbsentAfterCleanup)
                println("PHASE11_89_STAGING_EXECUTION_STATUS=${execution.status.name}")
                mark("STEP_06_EXACT_POST_COORDINATOR_CHAIN_DURABLE_FENCE_AND_CLEANUP_VERIFIED")

                val priorActivationPolicy = StrictMode.getThreadPolicy()
                val phase1188 = try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorActivationPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    SiteProductionDeploymentAndroidPostCoordinatorConfigActivationAuthorityPreparationBoundary
                        .prepare(
                            handoff = handoff,
                            phase1184Execution = phase1184Execution,
                            phase1185Preparation = phase1185,
                            phase1186AuthorityPreparation = phase1186,
                            phase1187Execution = execution,
                        )
                } finally {
                    StrictMode.setThreadPolicy(priorActivationPolicy)
                }
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorConfigActivationAuthorityPreparationStatus
                        .READY_FOR_POST_COORDINATOR_CONFIG_ACTIVATION_EXECUTION,
                    phase1188.status,
                )
                assertTrue(phase1188.exactConfigActivationAuthorized)
                assertFalse(phase1188.webServerReloadAuthorized)
                assertFalse(phase1188.coordinatorReinvocationAuthorized)
                assertFalse(phase1188.staticPublicationReplayAuthorized)
                assertFalse(phase1188.automaticRetryAuthorized)

                val phase1189Admission =
                    SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary
                        .admit(phase1188)
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorConfigActivationExecutionAdmissionStatus
                        .READY_FOR_FRESH_POST_COORDINATOR_CONFIG_ACTIVATION_EXECUTION,
                    phase1189Admission.status,
                )
                assertTrue(phase1189Admission.realVpsExecutionEligible)
                assertTrue(phase1189Admission.requiresFreshCredentialResolution)
                assertTrue(phase1189Admission.exactConfigActivationAuthorized)
                assertFalse(phase1189Admission.webServerReloadAuthorized)
                mark("STEP_07_PHASE1188_AUTHORITY_AND_PHASE1189_ADMISSION_BOUND")

                val beforeActivationFence = application.siteProductionDeploymentReplayFence.snapshot()
                val activationCredential = resolveFreshCredential(access, nonce, "activate", 210_000L)
                val publicationPlan = requireNotNull(requireNotNull(handoff.servingPolicySelection).publicationPlan)
                publicationConfigPath = publicationPlan.configPath
                publicationConfigSha = publicationPlan.desiredConfigSha256
                val activationExecution =
                    SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary
                        .executeOnce(
                            admission = phase1189Admission,
                            handoff = handoff,
                            phase1184Execution = phase1184Execution,
                            phase1185Preparation = phase1185,
                            phase1186AuthorityPreparation = phase1186,
                            phase1187Execution = execution,
                            phase1188AuthorityPreparation = phase1188,
                            freshResolutionProof = activationCredential.proof,
                            freshCredentialLease = activationCredential.lease,
                            serverAccess = access,
                            executionAttemptId = "phase11_92_activate_${nonce.take(16)}",
                            executedAtEpochMillis = activationCredential.proof.resolvedAtEpochMillis + 10L,
                            executionUsePort =
                                application.siteProductionDeploymentReplayFence
                                    .realVpsWebServingConfigActivationExecutionUsePort(),
                        )
                SiteProductionDeploymentAndroidPostCoordinatorConfigActivationExecutionBoundary
                    .validateExecutionResultAgainst(
                        result = activationExecution,
                        admission = phase1189Admission,
                        handoff = handoff,
                        phase1184Execution = phase1184Execution,
                        phase1185Preparation = phase1185,
                        phase1186AuthorityPreparation = phase1186,
                        phase1187Execution = execution,
                        phase1188AuthorityPreparation = phase1188,
                    )
                SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary
                    .validateProof(activationExecution.phase1174ExecutionResult.phase11_60ExecutionProof)
                val afterActivationFence = application.siteProductionDeploymentReplayFence.snapshot()
                assertEquals(
                    beforeActivationFence.realVpsWebServingConfigActivationExecutionReceiptMarkerCount + 1,
                    afterActivationFence.realVpsWebServingConfigActivationExecutionReceiptMarkerCount,
                )
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorConfigActivationExecutionStatus
                        .EXACT_CONFIG_ACTIVATED_SHA_VERIFIED_SYNTAX_VALIDATED_WITHOUT_RELOAD_OR_COORDINATOR_REPLAY,
                    activationExecution.status,
                )
                assertTrue(activationExecution.exactPostCoordinatorChainBindingVerified)
                assertTrue(activationExecution.durablePreactivationCheckpointRecorded)
                assertTrue(activationExecution.credentialLeaseMaterialConsumed)
                assertTrue(activationExecution.productionNetworkTouched)
                assertTrue(activationExecution.liveHostKeyPinVerified)
                assertTrue(activationExecution.exactConfigActivationPerformed)
                assertTrue(activationExecution.exactConfigSha256Verified)
                assertTrue(activationExecution.nginxSyntaxValidationPassed)
                assertTrue(activationExecution.exactConfigPathPresentAfterActivation)
                assertTrue(activationExecution.stagingConfigAbsentAfterActivation)
                assertTrue(activationExecution.listenerStillFreeAfterActivation)
                assertFalse(activationExecution.rollbackToAbsentPerformed)
                assertFalse(activationExecution.webServerReloadPerformed)
                assertFalse(activationExecution.coordinatorReinvoked)
                assertFalse(activationExecution.staticPublicationReplayPerformed)
                assertFalse(activationExecution.automaticRetryPerformed)
                assertEquals(7, activationExecution.phase1174ExecutionResult.phase11_60ExecutionProof.remoteCommandCount)
                mark("STEP_08_ONE_POST_COORDINATOR_EXACT_CONFIG_ACTIVATION_COMPLETE_WITHOUT_RELOAD")

                val priorReloadAuthorityPolicy = StrictMode.getThreadPolicy()
                val phase1190 = try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorReloadAuthorityPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    SiteProductionDeploymentAndroidPostCoordinatorNginxReloadAuthorityPreparationBoundary
                        .prepare(
                            handoff = handoff,
                            phase1184Execution = phase1184Execution,
                            phase1185Preparation = phase1185,
                            phase1186AuthorityPreparation = phase1186,
                            phase1187Execution = execution,
                            phase1188AuthorityPreparation = phase1188,
                            phase1189Execution = activationExecution,
                        )
                } finally {
                    StrictMode.setThreadPolicy(priorReloadAuthorityPolicy)
                }
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorNginxReloadAuthorityPreparationStatus
                        .READY_FOR_POST_COORDINATOR_NGINX_RELOAD_EXECUTION,
                    phase1190.status,
                )
                assertTrue(phase1190.nginxReloadExecutionAuthorized)
                assertFalse(phase1190.nginxReloadPerformed)
                assertFalse(phase1190.coordinatorReinvocationAuthorized)
                assertFalse(phase1190.staticPublicationReplayAuthorized)
                assertFalse(phase1190.automaticRetryAuthorized)

                val phase1191Admission =
                    SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary
                        .admit(phase1190)
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorNginxReloadExecutionAdmissionStatus
                        .READY_FOR_FRESH_POST_COORDINATOR_NGINX_RELOAD_EXECUTION,
                    phase1191Admission.status,
                )
                assertTrue(phase1191Admission.realVpsExecutionEligible)
                assertTrue(phase1191Admission.requiresFreshCredentialResolution)
                assertTrue(phase1191Admission.requiresLiveRemoteHostKeyVerification)
                assertTrue(phase1191Admission.nginxReloadAuthorized)
                assertFalse(phase1191Admission.configMutationAuthorized)
                assertFalse(phase1191Admission.coordinatorReinvocationAuthorized)
                assertFalse(phase1191Admission.staticPublicationReplayAuthorized)
                assertFalse(phase1191Admission.automaticRetryAuthorized)
                mark("STEP_09_PHASE1190_AUTHORITY_AND_PHASE1191_ADMISSION_BOUND")

                val beforeReloadFence = application.siteProductionDeploymentReplayFence.snapshot()
                val reloadCredential = resolveFreshCredential(access, nonce, "reload", 230_000L)
                val reloadExecution =
                    SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary
                        .executeOnce(
                            admission = phase1191Admission,
                            handoff = handoff,
                            phase1184Execution = phase1184Execution,
                            phase1185Preparation = phase1185,
                            phase1186AuthorityPreparation = phase1186,
                            phase1187Execution = execution,
                            phase1188AuthorityPreparation = phase1188,
                            phase1189Execution = activationExecution,
                            phase1190AuthorityPreparation = phase1190,
                            freshResolutionProof = reloadCredential.proof,
                            freshCredentialLease = reloadCredential.lease,
                            serverAccess = access,
                            executionAttemptId = "phase11_92_reload_${nonce.take(16)}",
                            executedAtEpochMillis = reloadCredential.proof.resolvedAtEpochMillis + 10L,
                            executionUsePort =
                                application.siteProductionDeploymentReplayFence
                                    .realVpsWebServingNginxReloadExecutionUsePort(),
                        )
                SiteProductionDeploymentAndroidPostCoordinatorNginxReloadExecutionBoundary
                    .validateExecutionResultAgainst(
                        result = reloadExecution,
                        admission = phase1191Admission,
                        handoff = handoff,
                        phase1184Execution = phase1184Execution,
                        phase1185Preparation = phase1185,
                        phase1186AuthorityPreparation = phase1186,
                        phase1187Execution = execution,
                        phase1188AuthorityPreparation = phase1188,
                        phase1189Execution = activationExecution,
                        phase1190AuthorityPreparation = phase1190,
                    )
                SiteProductionDeploymentAndroidRealVpsWebServingNginxReloadExecutionBoundary
                    .validateProof(reloadExecution.phase1176ExecutionResult.phase11_61ExecutionProof)
                val afterReloadFence = application.siteProductionDeploymentReplayFence.snapshot()
                assertEquals(
                    beforeReloadFence.realVpsWebServingNginxReloadExecutionReceiptMarkerCount + 1,
                    afterReloadFence.realVpsWebServingNginxReloadExecutionReceiptMarkerCount,
                )
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorNginxReloadExecutionStatus
                        .NGINX_RELOADED_ONCE_EXACT_CONFIG_PRESERVED_EXPECTED_LISTENER_LIVE_WITHOUT_COORDINATOR_REPLAY,
                    reloadExecution.status,
                )
                assertEquals(3, reloadExecution.phase1176ExecutionResult.phase11_61ExecutionProof.remoteCommandCount)
                assertTrue(reloadExecution.exactPostCoordinatorChainBindingVerified)
                assertTrue(reloadExecution.successfulPostCoordinatorConfigActivationExecutionProofValidated)
                assertTrue(reloadExecution.durablePreReloadCheckpointRecorded)
                assertTrue(reloadExecution.credentialLeaseMaterialConsumed)
                assertTrue(reloadExecution.productionNetworkTouched)
                assertTrue(reloadExecution.liveHostKeyPinVerified)
                assertTrue(reloadExecution.nginxReloadPerformed)
                assertTrue(reloadExecution.exactConfigSha256VerifiedBeforeReload)
                assertTrue(reloadExecution.nginxSyntaxValidationPassedBeforeReload)
                assertTrue(reloadExecution.listenerFreeBeforeReload)
                assertTrue(reloadExecution.exactConfigSha256VerifiedAfterReload)
                assertTrue(reloadExecution.nginxMasterRunningAfterReload)
                assertTrue(reloadExecution.expectedListenerLiveAfterReload)
                assertFalse(reloadExecution.configMutationPerformed)
                assertFalse(reloadExecution.coordinatorReinvoked)
                assertFalse(reloadExecution.staticPublicationReplayPerformed)
                assertFalse(reloadExecution.automaticRetryPerformed)
                mark("STEP_10_ONE_POST_COORDINATOR_NGINX_RELOAD_COMPLETE_LISTENER_LIVE")

                val phase1192Admission =
                    SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary.admit(
                        preparation = preparation,
                        handoff = handoff,
                        phase1184Execution = phase1184Execution,
                        phase1185Preparation = phase1185,
                        phase1186AuthorityPreparation = phase1186,
                        phase1187Execution = execution,
                        phase1188AuthorityPreparation = phase1188,
                        phase1189Execution = activationExecution,
                        phase1190AuthorityPreparation = phase1190,
                        phase1191Admission = phase1191Admission,
                        phase1191Execution = reloadExecution,
                    )
                val verificationCredential = resolveFreshCredential(access, nonce, "verify", 240_000L)
                val phase1192Execution =
                    SiteProductionDeploymentAndroidPostCoordinatorServingPathVerificationBoundary.executeOnce(
                        admission = phase1192Admission,
                        preparation = preparation,
                        handoff = handoff,
                        phase1184Execution = phase1184Execution,
                        phase1185Preparation = phase1185,
                        phase1186AuthorityPreparation = phase1186,
                        phase1187Execution = execution,
                        phase1188AuthorityPreparation = phase1188,
                        phase1189Execution = activationExecution,
                        phase1190AuthorityPreparation = phase1190,
                        phase1191Admission = phase1191Admission,
                        phase1191Execution = reloadExecution,
                        freshResolutionProof = verificationCredential.proof,
                        freshCredentialLease = verificationCredential.lease,
                        serverAccess = access,
                        loopbackExecutionAttemptId = "phase11_92_loopback_${nonce.take(16)}",
                        externalExecutionAttemptId = "phase11_92_external_${nonce.take(16)}",
                        domainExecutionAttemptId = "phase11_92_domain_${nonce.take(16)}",
                        executedAtEpochMillis = verificationCredential.proof.resolvedAtEpochMillis + 10L,
                    )
                assertEquals(
                    SiteProductionDeploymentPostCoordinatorServingPathVerificationStatus
                        .COMPLETE_SERVING_PATH_VERIFIED_LOOPBACK_EXTERNAL_IPV4_AND_DOMAIN_DNS_EXACT_BODY,
                    phase1192Execution.status,
                )
                assertTrue(phase1192Execution.exactPostCoordinatorChainBindingVerified)
                assertTrue(phase1192Execution.successfulNginxReloadExecutionProofValidated)
                assertTrue(phase1192Execution.loopbackHttpGetPerformed)
                assertEquals(200, phase1192Execution.loopbackHttpStatusCode)
                assertTrue(phase1192Execution.loopbackExactBodySha256Verified)
                assertTrue(phase1192Execution.externalIpv4TcpConnectPerformed)
                assertTrue(phase1192Execution.externalIpv4HttpGetPerformed)
                assertEquals(200, phase1192Execution.externalIpv4HttpStatusCode)
                assertTrue(phase1192Execution.externalIpv4ExactBodySha256Verified)
                assertTrue(phase1192Execution.externalIpv4ReachabilityProved)
                assertTrue(phase1192Execution.dnsResolutionPerformed)
                assertEquals(1, phase1192Execution.dnsResolutionInvocationCount)
                assertTrue(phase1192Execution.resolvedAddressSetContainsAcceptedIpv4)
                assertTrue(phase1192Execution.domainAddressedTcpConnectPerformed)
                assertTrue(phase1192Execution.domainAddressedHttpGetPerformed)
                assertEquals(200, phase1192Execution.domainHttpStatusCode)
                assertTrue(phase1192Execution.domainExactBodySha256Verified)
                assertTrue(phase1192Execution.externalDomainHttpReachabilityProved)
                assertEquals(phase1192Execution.expectedBodySha256, phase1192Execution.observedBodySha256)
                assertFalse(phase1192Execution.remoteMutationPerformed)
                assertFalse(phase1192Execution.coordinatorReinvoked)
                assertFalse(phase1192Execution.staticPublicationReplayPerformed)
                assertFalse(phase1192Execution.automaticRetryPerformed)
                mark("STEP_11_FINAL_LOOPBACK_EXTERNAL_IPV4_DOMAIN_DNS_EXACT_BODY_VERIFIED")

                val cleanupCredential = resolveFreshCredential(access, nonce, "cleanup", 260_000L)
                cleanupReloadedConfigForAcceptance(
                    access = access,
                    resolved = cleanupCredential,
                    configPath = publicationPlan.configPath,
                    desiredSha256 = publicationPlan.desiredConfigSha256,
                    port = publicationPlan.port,
                    nonce = nonce,
                )
                publicationConfigPath = null
                publicationConfigSha = null
                mark("STEP_12_ACCEPTANCE_ONLY_REMOVE_CONFIG_RELOAD_AND_RESTORE_ABSENT")
            } finally {
                if (publicationConfigPath != null && publicationConfigSha != null) {
                    Log.e("Phase11_92Diag", "REMOTE_EXACT_CONFIG_MAY_REQUIRE_RECONCILIATION=$publicationConfigPath")
                }
                val delete = secretStore.delete(secretId)
                assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
                config.closeSensitiveBytes()
                deleteTree(localRoot)
                runCatching { configFile.delete() }
                mark("STEP_13_LOCAL_CLEANUP_COMPLETE")
            }
        }

    private suspend fun resolveFreshCredential(
        access: ServerAccess,
        nonce: String,
        suffix: String,
        base: Long,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved {
        require(Regex("^[a-z][a-z0-9_-]{2,15}$").matches(suffix))
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = "/etc/skel",
            stagingRoot = "/etc/skel-stage",
            backupRoot = "/etc/skel-backup",
            expectedTargetEntryNames = listOf(".bash_logout", ".bashrc", ".profile"),
            admissionAttemptId = "phase11_92_${suffix}_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_92_${suffix}_preflight_$nonce",
            evaluatedAtEpochMillis = base + 10L,
            requestedAuthorizationLifetimeMillis = 10_000L,
        )
        val preflightAuthorization = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
            preflightDraft,
            SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                preflightDraft.approvalChallengeSha256,
                true,
            ),
        )
        val preflightReceipt = application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
            preflightAuthorization,
            base + 11L,
        )
        val credentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
            receipt = preflightReceipt,
            serverAccess = access,
            authorizationAttemptId = "phase11_92_${suffix}_credential_$nonce",
            evaluatedAtEpochMillis = base + 20L,
            requestedAuthorizationLifetimeMillis = 10_000L,
        )
        val credentialAuthorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
            credentialDraft,
            SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                credentialDraft.approvalChallengeSha256,
                true,
            ),
        )
        val credentialHandoff = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
            credentialAuthorization,
            base + 21L,
        )
        return (application.siteProductionDeploymentResolveRealVpsCredentialOnce(
            credentialHandoff,
            access,
            base + 22L,
        ) as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved).also {
            SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(it.proof)
        }
    }


    private suspend fun cleanupReloadedConfigForAcceptance(
        access: ServerAccess,
        resolved: SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved,
        configPath: String,
        desiredSha256: String,
        port: Int,
        nonce: String,
    ) {
        val owner = SessionOwner.Operation(OperationId("phase11_92_cleanup_${nonce.take(20)}"))
        val sessionId = SessionId("phase11_92_cleanup_session_${nonce.take(16)}")
        val leaseStore = OneShotPhase11_92AcceptanceCleanupLeaseSecretStore(access.auth.secretId, resolved.lease)
        val factory = JschSshConnectionFactory(secretStore = leaseStore, sessionIdFactory = { sessionId })
        var connectedHandle: VerifiedHostKeySshSessionHandle? = null
        try {
            val connectResult = factory.connect(
                access = access,
                owner = owner,
                config = SshTransportConfig(
                    tcpConnectTimeout = Duration.ofSeconds(8),
                    handshakeAndAuthTimeout = Duration.ofSeconds(12),
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(8),
                    stdoutCaptureLimitBytes = 16 * 1024,
                    stderrCaptureLimitBytes = 32 * 1024,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: throw IllegalArgumentException("Phase 11.92 acceptance cleanup SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                throw IllegalArgumentException("Phase 11.92 acceptance cleanup lacks verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.binding.serverAccessId == access.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == sessionId)
            require(verified.isOpen)
            val qPath = shellQuote(configPath)
            val qSha = shellQuote(desiredSha256)
            val qFilter = shellQuote("sport = :$port")
            val raw = "test -f $qPath; test ! -L $qPath; " +
                "test \"\$(sha256sum -- $qPath | cut -d' ' -f1)\" = $qSha; rm -- $qPath; " +
                "test ! -e $qPath; test ! -L $qPath; nginx -t >/dev/null 2>&1; nginx -s reload; " +
                "i=0; while [ \$i -lt 40 ]; do out=\$(ss -H -ltn $qFilter 2>/dev/null); code=\$?; " +
                "if [ \$code -eq 0 ] && [ -z \"\$out\" ]; then printf 'ABSENT\\n'; exit 0; fi; " +
                "i=\$((i+1)); sleep 0.1; done; exit 1"
            val commandResult = verified.execute(
                RemoteCommand.create(raw, "phase11-91-acceptance-only-cleanup-reload-to-absent"),
                SshTransportConfig(
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(8),
                    stdoutCaptureLimitBytes = 16 * 1024,
                    stderrCaptureLimitBytes = 32 * 1024,
                ),
            )
            require(commandResult.dispatchState == CommandDispatchState.DISPATCHED)
            require(commandResult.completion == CommandCompletion.ConfirmedSuccess)
            require(!commandResult.stdout.truncated && !commandResult.stderr.truncated)
            require(commandResult.stdout.copyBytes().toString(StandardCharsets.UTF_8).trim() == "ABSENT")
        } finally {
            runCatching { connectedHandle?.close() }
            resolved.lease.close()
        }
    }

    private fun shellQuote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' })
        return "'$value'"
    }

    private fun prepare(
        root: Path,
        host: String,
        targetRoot: String,
    ) = SiteDeployerLocalPreparationBoundary.prepare(
        SiteDeployerLocalPreparationRequest(
            rootSeed = DesignSeed(11920L),
            domain = "${host.replace('.', '-')}.nip.io",
            servicePort = 58492,
            remoteHostIdentity = host,
            targetRoot = targetRoot,
            owner = "root",
            group = "root",
            reuseExisting3xUiCertificate = false,
        ),
        root,
    )

    private fun readyHandoff(
        preparation: SiteDeployerLocalPreparationResult,
        finalTargetTreeSha256: String,
    ): SiteProductionDeploymentPostCoordinatorServingHandoff {
        val evidence = SiteStaticPublicationEvidence(
            preparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            finalTargetTreeSha256 = finalTargetTreeSha256,
            committedClean = true,
            remoteResidualStateClean = true,
        )
        val selection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
            preparation = preparation,
            staticPublicationEvidence = evidence,
        )
        val base = SiteProductionDeploymentPostCoordinatorServingHandoff(
            contractVersion = 1,
            status = SiteProductionDeploymentPostCoordinatorServingHandoffStatus
                .READY_FOR_POLICY_BOUND_WEB_SERVING_PREFLIGHT,
            phase1180AdmissionSha256 = "a".repeat(64),
            phase1180ExecutionResultSha256 = "b".repeat(64),
            localPreparationSha256 = preparation.preparationSha256,
            sourceTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            staticPublicationEvidence = evidence,
            servingPolicySelection = selection,
            servingPolicySelectionSha256 = selection.selectionSha256,
            requiresFreshPolicyBoundWebServingPreflight = true,
            authorizesWebServingNetworkExecution = false,
            authorizesWebServingMutation = false,
            authorizesCoordinatorReinvocation = false,
            automaticRetryAuthorized = false,
            handoffSha256 = "",
        )
        return base.copy(
            handoffSha256 = SiteProductionDeploymentAndroidPostCoordinatorServingHandoffBoundary
                .handoffSha256ForTest(base),
        )
    }

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS,
        )
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_92_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun mark(step: String) { Log.i("Phase11_92Diag", step) }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_92_post_coordinator_serving_path_verification_acceptance.properties"
    }
}


private class OneShotPhase11_92AcceptanceCleanupLeaseSecretStore(
    private val expectedSecretId: SecretId,
    private val credentialLease: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentEphemeralCredentialLease,
) : SecretStore {
    private val readStarted = AtomicBoolean(false)

    override suspend fun read(secretId: SecretId): SecretReadResult {
        if (secretId != expectedSecretId) return SecretReadResult.NotFound
        if (!readStarted.compareAndSet(false, true)) {
            return SecretReadResult.Unavailable("Phase 11.92 cleanup credential lease is single-use")
        }
        val copy = credentialLease.useMaterialOnce { material ->
            material.useBytes { SecretMaterial.fromBytes(it) }
        }
        return SecretReadResult.Found(copy)
    }

    override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
        SecretCreateResult.StorageFailure("Phase 11.92 cleanup lease adapter is read-only")

    override suspend fun delete(secretId: SecretId): SecretDeleteResult =
        SecretDeleteResult.StorageFailure("Phase 11.92 cleanup lease adapter is read-only")

    override suspend fun listIds(): SecretListResult =
        SecretListResult.StorageFailure("Phase 11.92 cleanup lease adapter does not enumerate secrets")
}

private class OneShotPhase11_92Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(
            password ?: error("Phase 11.92 password material is closed"),
        )

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_92Config {
            val bytes = file.readBytes()
            try {
                require(bytes.size in 1..MAX_CONFIG_BYTES)
                val values = bytes.toString(StandardCharsets.US_ASCII).lineSequence()
                    .map { it.trimEnd('\r') }
                    .filter { it.isNotBlank() }
                    .associate { line ->
                        val i = line.indexOf('=')
                        require(i > 0)
                        line.substring(0, i) to line.substring(i + 1)
                    }
                require(values["version"] == "1" && values["auth"] == "password")
                val host = decodeUtf8(values.getValue("host_b64"))
                val username = decodeUtf8(values.getValue("username_b64"))
                val hostKey = decodeUtf8(values.getValue("hostkey_b64"))
                val port = values.getValue("port").toInt()
                val password = Base64.decode(values.getValue("password_b64"), Base64.NO_WRAP)
                require(
                    host.isNotBlank() &&
                        username.isNotBlank() &&
                        hostKey.startsWith("SHA256:") &&
                        port in 1..65535,
                )
                require(password.isNotEmpty() && password.size <= 65536)
                return OneShotPhase11_92Config(host, port, username, hostKey, password)
            } finally {
                Arrays.fill(bytes, 0)
                runCatching { file.delete() }
            }
        }

        private fun decodeUtf8(value: String): String {
            val bytes = Base64.decode(value, Base64.NO_WRAP)
            return try {
                bytes.toString(StandardCharsets.UTF_8)
            } finally {
                Arrays.fill(bytes, 0)
            }
        }
    }
}
