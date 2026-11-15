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
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.CommandCompletion
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
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingNginxReloadExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidServingPolicySelectionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmissionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundConfigActivationExecutionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundNginxReloadExecutionAdmissionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundNginxReloadExecutionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentEphemeralCredentialLease
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Arrays
import java.util.Comparator
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_76RealDevicePolicyBoundNginxReloadExecutionAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() =
        context.applicationContext as VelumTegraApplication

    @Test
    fun completedPhase1175MustGateOneRealVpsNginxReloadWithDurableFenceAndLiveListener() =
        runBlocking {
            val nonce = requiredRunNonce()
            mark("STEP_01_TEST_START")
            assertInternetPermissionDeclared()
            val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
            require(configFile.isFile) { "Phase 11.76 one-shot real-VPS reload execution acceptance config is missing" }
            val config = OneShotPhase11_76Config.readAndDelete(configFile)
            val secretStore = AndroidKeystoreSecretStore(context)
            val secretId = SecretId("phase11_76_acceptance_credential")
            val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_76-")
            var publicationConfigPath: String? = null
            var publicationConfigSha: String? = null
            try {
                secretStore.delete(secretId)
                val access = ServerAccess(
                    id = ServerAccessId("phase11_76_access_$nonce"),
                    serverId = ServerId("phase11_76_server_$nonce"),
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
                    port = 58486,
                    targetRoot = "/tmp/velum-p1175-${nonce.take(16)}",
                )
                val evidence = evidence(preparation)
                val selection =
                    SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                        preparation = preparation,
                        staticPublicationEvidence = evidence,
                    )
                val admission =
                    SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                        .admit(selection)
                assertTrue(admission.readOnlyPreflightExecutionEligible)
                mark("STEP_03_EXACT_POLICY_SELECTION_AND_PREFLIGHT_ADMISSION_READY")

                val resolved = resolveFreshCredential(access, nonce, "preflight", 150_000L)
                val execution =
                    SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                        .observeOnce(
                            admission = admission,
                            selection = selection,
                            freshResolutionProof = resolved.proof,
                            freshCredentialLease = resolved.lease,
                            serverAccess = access,
                            executionAttemptId = "phase11_76_web_preflight_${nonce.take(16)}",
                            executedAtEpochMillis = resolved.proof.resolvedAtEpochMillis + 10L,
                        )
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                    .validateExecutionResult(execution)
                mark("STEP_04_POLICY_BOUND_REAL_VPS_READ_ONLY_PREFLIGHT_COMPLETE")

                val priorPolicy = StrictMode.getThreadPolicy()
                val phase1170: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundConfigMutationPreparationResult
                val result: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationResult
                try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    phase1170 =
                        SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                            .prepare(
                                selection = selection,
                                policyBoundPreflightExecution = execution,
                                mutationTransactionId = "phase11_76_tx_${nonce.take(16)}",
                            )
                    SiteProductionDeploymentAndroidPolicyBoundConfigMutationPreparationBoundary
                        .validateAgainst(phase1170, selection, execution)
                    result =
                        SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                            .prepare(
                                selection = selection,
                                policyBoundPreflightExecution = execution,
                                policyBoundConfigMutationPreparation = phase1170,
                            )
                } finally {
                    StrictMode.setThreadPolicy(priorPolicy)
                }
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxAuthorityPreparationBoundary
                    .validateAgainst(result, selection, execution, phase1170)
                mark("STEP_05_PHASE11_70_IDENTITY_BOUND_TO_ZERO_NETWORK_STAGING_SYNTAX_AUTHORITY_PREPARATION")

                assertEquals(
                    SiteProductionDeploymentPolicyBoundConfigMutationPreparationStatus
                        .READY_FOR_SEPARATE_CONFIG_MUTATION_AUTHORITY_BOUNDARY,
                    phase1170.status,
                )
                assertEquals(
                    SiteProductionDeploymentPolicyBoundStagingSyntaxAuthorityPreparationStatus
                        .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
                    result.status,
                )
                assertEquals(selection.selectionSha256, result.servingPolicySelectionSha256)
                assertEquals(
                    execution.executionResultSha256,
                    result.policyBoundPreflightExecutionResultSha256,
                )
                assertEquals(
                    phase1170.preparationResultSha256,
                    result.policyBoundConfigMutationPreparationResultSha256,
                )
                assertEquals(execution.publicationPlanSha256, result.publicationPlanSha256)
                assertEquals(execution.selectedProtocol, result.selectedProtocol)
                assertEquals(
                    execution.preflightExecutionProof.preflightReport.preflightSha256,
                    result.readOnlyPreflightSha256,
                )
                assertEquals(phase1170.mutationTransactionId, result.mutationTransactionId)
                assertEquals(
                    phase1170.mutationPreparation?.mutationPreparationSha256,
                    result.mutationPreparationSha256,
                )
                assertTrue(result.exactPolicyPreparationBindingVerified)
                assertTrue(result.stagingSyntaxExecutionPlanCreated)
                assertFalse(result.productionNetworkTouchedByAuthorityPreparation)
                assertFalse(result.remoteMutationPerformed)
                assertTrue(result.stagingConfigWriteAuthorized)
                assertTrue(result.validationConfigWriteAuthorized)
                assertTrue(result.isolatedNginxSyntaxValidationAuthorized)
                assertFalse(result.exactConfigActivationAuthorized)
                assertFalse(result.webServerReloadAuthorized)
                assertFalse(result.certificateMutationAuthorized)
                assertFalse(result.dnsMutationAuthorized)
                assertFalse(result.firewallMutationAuthorized)
                assertFalse(result.packageInstallAuthorized)
                assertFalse(result.privateKeyContentReadAuthorized)
                assertFalse(result.automaticRetryAuthorized)
                assertFalse(result.coordinatorInvoked)
                assertFalse(result.exposesDeployUiAction)

                val plan = requireNotNull(result.stagingSyntaxExecutionPlan)
                val mutation = requireNotNull(phase1170.mutationPreparation)
                SiteWebServingConfigMutationPreparationBoundary.validate(mutation)
                SiteWebServingConfigStagingSyntaxExecutionBoundary.validateAgainst(
                    plan = plan,
                    preparation = mutation,
                    publicationPlan = requireNotNull(selection.publicationPlan),
                    readOnlyPreflight = execution.preflightExecutionProof.preflightReport,
                )
                assertEquals(result.mutationTransactionId, plan.mutationTransactionId)
                assertEquals(result.mutationPreparationSha256, plan.mutationPreparationSha256)
                assertTrue(plan.stagingConfigWriteAuthorized)
                assertTrue(plan.validationConfigWriteAuthorized)
                assertTrue(plan.isolatedNginxSyntaxValidationAuthorized)
                assertFalse(plan.exactConfigActivationAuthorized)
                assertFalse(plan.webServerReloadAuthorized)
                println("PHASE11_75_STAGING_AUTHORITY_STATUS=${result.status.name}")
                mark("STEP_06_READY_PHASE11_70_PRODUCED_EXACT_BOUNDED_PHASE11_59_EXECUTION_PLAN")

                val executionAdmission =
                    SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
                        .admit(result)
                assertEquals(
                    SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionAdmissionStatus
                        .READY_FOR_SEPARATE_REAL_VPS_STAGING_SYNTAX_EXECUTION,
                    executionAdmission.status,
                )
                assertTrue(executionAdmission.realVpsExecutionEligible)
                assertTrue(executionAdmission.requiresFreshCredentialResolution)
                assertTrue(executionAdmission.requiresLiveRemoteHostKeyVerification)
                assertEquals(
                    result.authorityPreparationResultSha256,
                    executionAdmission.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
                )
                assertEquals(
                    plan.executionPlanSha256,
                    executionAdmission.stagingSyntaxExecutionPlanSha256,
                )
                mark("STEP_07_PHASE11_71_READY_ADMISSION_BOUND_EXACT_EXECUTION_PLAN")

                val beforeFence = application.siteProductionDeploymentReplayFence.snapshot()
                val writeCredential =
                    resolveFreshCredential(access, nonce, "stage", 160_000L)
                val executionResult =
                    SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
                        .executeOnce(
                            admission = executionAdmission,
                            selection = selection,
                            policyBoundPreflightExecution = execution,
                            policyBoundConfigMutationPreparation = phase1170,
                            authorityPreparation = result,
                            freshResolutionProof = writeCredential.proof,
                            freshCredentialLease = writeCredential.lease,
                            serverAccess = access,
                            executionAttemptId = "phase11_76_stage_syntax_${nonce.take(16)}",
                            executedAtEpochMillis =
                                writeCredential.proof.resolvedAtEpochMillis + 10L,
                            executionUsePort =
                                application.siteProductionDeploymentReplayFence
                                    .realVpsWebServingConfigStagingSyntaxExecutionUsePort(),
                        )
                SiteProductionDeploymentAndroidPolicyBoundStagingSyntaxExecutionBoundary
                    .validateExecutionResultAgainst(
                        executionResult,
                        executionAdmission,
                        selection,
                        execution,
                        phase1170,
                        result,
                    )
                SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary
                    .validateProof(executionResult.phase11_59ExecutionProof)
                val afterFence = application.siteProductionDeploymentReplayFence.snapshot()
                assertEquals(
                    beforeFence.realVpsWebServingConfigStagingSyntaxExecutionReceiptMarkerCount + 1,
                    afterFence.realVpsWebServingConfigStagingSyntaxExecutionReceiptMarkerCount,
                )
                mark("STEP_08_ONE_POLICY_BOUND_REAL_VPS_STAGING_SYNTAX_EXECUTION_COMPLETE")

                assertEquals(
                    SiteProductionDeploymentPolicyBoundStagingSyntaxExecutionStatus
                        .EXECUTED_AND_CLEANED_WITHOUT_EXACT_CONFIG_ACTIVATION_OR_RELOAD,
                    executionResult.status,
                )
                assertEquals(
                    result.authorityPreparationResultSha256,
                    executionResult.policyBoundStagingSyntaxAuthorityPreparationResultSha256,
                )
                assertEquals(
                    execution.executionResultSha256,
                    executionResult.policyBoundPreflightExecutionResultSha256,
                )
                assertEquals(
                    phase1170.preparationResultSha256,
                    executionResult.policyBoundConfigMutationPreparationResultSha256,
                )
                assertEquals(plan.executionPlanSha256, executionResult.stagingSyntaxExecutionPlanSha256)
                assertTrue(executionResult.exactProductionChainBindingVerified)
                assertTrue(executionResult.durableBaselineCheckpointRecorded)
                assertTrue(executionResult.credentialLeaseMaterialConsumed)
                assertTrue(executionResult.productionNetworkTouched)
                assertTrue(executionResult.liveHostKeyPinVerified)
                assertTrue(executionResult.operationOwnedStagingWritePerformed)
                assertTrue(executionResult.operationOwnedValidationWritePerformed)
                assertTrue(executionResult.nginxSyntaxValidationPassed)
                assertTrue(executionResult.operationOwnedCleanupVerified)
                assertFalse(executionResult.exactConfigActivationPerformed)
                assertFalse(executionResult.webServerReloadPerformed)
                assertFalse(executionResult.certificateMutationPerformed)
                assertFalse(executionResult.dnsMutationPerformed)
                assertFalse(executionResult.firewallMutationPerformed)
                assertFalse(executionResult.packageInstallPerformed)
                assertFalse(executionResult.privateKeyContentReadPerformed)
                assertFalse(executionResult.automaticRetryPerformed)
                assertFalse(executionResult.coordinatorInvoked)
                assertFalse(executionResult.exposesDeployUiAction)
                assertEquals(7, executionResult.phase11_59ExecutionProof.remoteCommandCount)
                assertTrue(executionResult.phase11_59ExecutionProof.exactConfigPathAbsentAfterValidation)
                assertTrue(executionResult.phase11_59ExecutionProof.listenerStillFreeAfterValidation)
                assertTrue(executionResult.phase11_59ExecutionProof.stagingConfigAbsentAfterCleanup)
                assertTrue(executionResult.phase11_59ExecutionProof.validationConfigAbsentAfterCleanup)
                assertTrue(executionResult.phase11_59ExecutionProof.validationPidAbsentAfterCleanup)
                println("PHASE11_75_STAGING_EXECUTION_STATUS=${executionResult.status.name}")
                mark("STEP_09_EXACT_CHAIN_DURABLE_FENCE_AND_OPERATION_OWNED_CLEANUP_VERIFIED")

                val beforeActivationPreparationFence =
                    application.siteProductionDeploymentReplayFence.snapshot()
                val priorActivationPolicy = StrictMode.getThreadPolicy()
                val activationAuthority: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationResult
                try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorActivationPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    activationAuthority =
                        SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
                            .prepare(
                                selection = selection,
                                policyBoundPreflightExecution = execution,
                                policyBoundConfigMutationPreparation = phase1170,
                                stagingSyntaxAuthorityPreparation = result,
                                stagingSyntaxExecution = executionResult,
                            )
                } finally {
                    StrictMode.setThreadPolicy(priorActivationPolicy)
                }
                SiteProductionDeploymentAndroidPolicyBoundConfigActivationAuthorityPreparationBoundary
                    .validateAgainst(
                        activationAuthority,
                        selection,
                        execution,
                        phase1170,
                        result,
                        executionResult,
                    )
                val afterActivationPreparationFence =
                    application.siteProductionDeploymentReplayFence.snapshot()
                assertEquals(
                    beforeActivationPreparationFence.realVpsWebServingConfigActivationExecutionReceiptMarkerCount,
                    afterActivationPreparationFence.realVpsWebServingConfigActivationExecutionReceiptMarkerCount,
                )

                assertEquals(
                    SiteProductionDeploymentPolicyBoundConfigActivationAuthorityPreparationStatus
                        .READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
                    activationAuthority.status,
                )
                assertEquals(
                    executionResult.executionResultSha256,
                    activationAuthority.policyBoundStagingSyntaxExecutionResultSha256,
                )
                assertEquals(
                    executionResult.phase11_59ExecutionProof.executionProofSha256,
                    activationAuthority.phase11_59ExecutionProofSha256,
                )
                assertTrue(activationAuthority.exactProductionChainBindingVerified)
                assertTrue(activationAuthority.successfulStagingSyntaxExecutionProofValidated)
                assertTrue(activationAuthority.activationExecutionPlanCreated)
                assertFalse(activationAuthority.productionNetworkTouchedByAuthorityPreparation)
                assertFalse(activationAuthority.remoteMutationPerformed)
                assertTrue(activationAuthority.stagingConfigWriteAuthorized)
                assertTrue(activationAuthority.exactConfigActivationAuthorized)
                assertTrue(activationAuthority.nginxSyntaxValidationAuthorized)
                assertFalse(activationAuthority.webServerReloadAuthorized)
                assertFalse(activationAuthority.certificateMutationAuthorized)
                assertFalse(activationAuthority.dnsMutationAuthorized)
                assertFalse(activationAuthority.firewallMutationAuthorized)
                assertFalse(activationAuthority.packageInstallAuthorized)
                assertFalse(activationAuthority.privateKeyContentReadAuthorized)
                assertFalse(activationAuthority.automaticRetryAuthorized)
                assertFalse(activationAuthority.coordinatorInvoked)
                assertFalse(activationAuthority.exposesDeployUiAction)
                val activationPlan = activationAuthority.activationExecutionPlan
                SiteWebServingConfigActivationExecutionBoundary.validateAgainst(
                    activationPlan,
                    requireNotNull(phase1170.mutationPreparation),
                    plan,
                    requireNotNull(selection.publicationPlan),
                    execution.preflightExecutionProof.preflightReport,
                )
                assertTrue(activationPlan.exactConfigActivationAuthorized)
                assertFalse(activationPlan.webServerReloadAuthorized)
                println("PHASE11_75_ACTIVATION_AUTHORITY_STATUS=${activationAuthority.status.name}")
                mark("STEP_10_PHASE11_60_ACTIVATION_AUTHORITY_PREPARED_LOCALLY_WITHOUT_REMOTE_MUTATION")


                val activationAdmission =
                    SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
                        .admit(activationAuthority)
                assertEquals(
                    SiteProductionDeploymentPolicyBoundConfigActivationExecutionAdmissionStatus
                        .READY_FOR_SEPARATE_REAL_VPS_CONFIG_ACTIVATION_EXECUTION,
                    activationAdmission.status,
                )
                assertTrue(activationAdmission.realVpsExecutionEligible)
                assertTrue(activationAdmission.requiresFreshCredentialResolution)
                assertTrue(activationAdmission.requiresLiveRemoteHostKeyVerification)
                assertTrue(activationAdmission.exactConfigActivationAuthorized)
                assertFalse(activationAdmission.webServerReloadAuthorized)
                assertEquals(
                    activationAuthority.authorityPreparationResultSha256,
                    activationAdmission.policyBoundConfigActivationAuthorityPreparationResultSha256,
                )
                assertEquals(
                    activationAuthority.activationExecutionPlan.activationPlanSha256,
                    activationAdmission.activationExecutionPlanSha256,
                )
                mark("STEP_11_PHASE11_73_READY_ADMISSION_BOUND_EXACT_ACTIVATION_PLAN")

                val beforeActivationFence =
                    application.siteProductionDeploymentReplayFence.snapshot()
                val activationCredential =
                    resolveFreshCredential(access, nonce, "activate", 170_000L)
                val publicationPlan = requireNotNull(selection.publicationPlan)
                publicationConfigPath = publicationPlan.configPath
                publicationConfigSha = publicationPlan.desiredConfigSha256
                val activationExecution =
                    SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
                        .executeOnce(
                            admission = activationAdmission,
                            selection = selection,
                            policyBoundPreflightExecution = execution,
                            policyBoundConfigMutationPreparation = phase1170,
                            stagingSyntaxAuthorityPreparation = result,
                            stagingSyntaxExecution = executionResult,
                            activationAuthorityPreparation = activationAuthority,
                            freshResolutionProof = activationCredential.proof,
                            freshCredentialLease = activationCredential.lease,
                            serverAccess = access,
                            executionAttemptId = "phase11_76_activate_${nonce.take(16)}",
                            executedAtEpochMillis =
                                activationCredential.proof.resolvedAtEpochMillis + 10L,
                            executionUsePort =
                                application.siteProductionDeploymentReplayFence
                                    .realVpsWebServingConfigActivationExecutionUsePort(),
                        )
                SiteProductionDeploymentAndroidPolicyBoundConfigActivationExecutionBoundary
                    .validateExecutionResultAgainst(
                        result = activationExecution,
                        admission = activationAdmission,
                        selection = selection,
                        policyBoundPreflightExecution = execution,
                        policyBoundConfigMutationPreparation = phase1170,
                        stagingSyntaxAuthorityPreparation = result,
                        stagingSyntaxExecution = executionResult,
                        activationAuthorityPreparation = activationAuthority,
                    )
                SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary
                    .validateProof(activationExecution.phase11_60ExecutionProof)
                val afterActivationFence =
                    application.siteProductionDeploymentReplayFence.snapshot()
                assertEquals(
                    beforeActivationFence.realVpsWebServingConfigActivationExecutionReceiptMarkerCount + 1,
                    afterActivationFence.realVpsWebServingConfigActivationExecutionReceiptMarkerCount,
                )
                assertEquals(
                    SiteProductionDeploymentPolicyBoundConfigActivationExecutionStatus
                        .EXACT_CONFIG_ACTIVATED_SHA_VERIFIED_SYNTAX_VALIDATED_WITHOUT_RELOAD,
                    activationExecution.status,
                )
                assertTrue(activationExecution.exactProductionChainBindingVerified)
                assertTrue(activationExecution.successfulStagingSyntaxExecutionProofValidated)
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
                assertFalse(activationExecution.certificateMutationPerformed)
                assertFalse(activationExecution.dnsMutationPerformed)
                assertFalse(activationExecution.firewallMutationPerformed)
                assertFalse(activationExecution.packageInstallPerformed)
                assertFalse(activationExecution.privateKeyContentReadPerformed)
                assertFalse(activationExecution.automaticRetryPerformed)
                assertFalse(activationExecution.coordinatorInvoked)
                assertFalse(activationExecution.exposesDeployUiAction)
                assertEquals(7, activationExecution.phase11_60ExecutionProof.remoteCommandCount)
                mark("STEP_12_ONE_POLICY_BOUND_REAL_VPS_EXACT_CONFIG_ACTIVATION_COMPLETE_WITHOUT_RELOAD")

                val beforeReloadAuthorityFence =
                    application.siteProductionDeploymentReplayFence.snapshot()
                val priorReloadAuthorityPolicy = StrictMode.getThreadPolicy()
                val reloadAuthority: com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationResult
                try {
                    StrictMode.setThreadPolicy(
                        StrictMode.ThreadPolicy.Builder(priorReloadAuthorityPolicy)
                            .detectNetwork()
                            .penaltyDeath()
                            .build(),
                    )
                    reloadAuthority =
                        SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary
                            .prepare(
                                selection = selection,
                                policyBoundPreflightExecution = execution,
                                policyBoundConfigMutationPreparation = phase1170,
                                stagingSyntaxAuthorityPreparation = result,
                                stagingSyntaxExecution = executionResult,
                                activationAuthorityPreparation = activationAuthority,
                                activationExecution = activationExecution,
                            )
                } finally {
                    StrictMode.setThreadPolicy(priorReloadAuthorityPolicy)
                }
                SiteProductionDeploymentAndroidPolicyBoundNginxReloadAuthorityPreparationBoundary
                    .validateAgainst(
                        result = reloadAuthority,
                        selection = selection,
                        policyBoundPreflightExecution = execution,
                        policyBoundConfigMutationPreparation = phase1170,
                        stagingSyntaxAuthorityPreparation = result,
                        stagingSyntaxExecution = executionResult,
                        activationAuthorityPreparation = activationAuthority,
                        activationExecution = activationExecution,
                    )
                val afterReloadAuthorityFence =
                    application.siteProductionDeploymentReplayFence.snapshot()
                assertEquals(
                    beforeReloadAuthorityFence.realVpsWebServingNginxReloadExecutionReceiptMarkerCount,
                    afterReloadAuthorityFence.realVpsWebServingNginxReloadExecutionReceiptMarkerCount,
                )
                assertEquals(
                    SiteProductionDeploymentPolicyBoundNginxReloadAuthorityPreparationStatus
                        .READY_FOR_SEPARATE_REAL_VPS_NGINX_RELOAD_EXECUTION,
                    reloadAuthority.status,
                )
                mark("STEP_13_PHASE11_61_RELOAD_AUTHORITY_PREPARED_LOCALLY_WITHOUT_RELOAD")

                val reloadAdmission =
                    SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary
                        .admit(reloadAuthority)
                assertEquals(
                    SiteProductionDeploymentPolicyBoundNginxReloadExecutionAdmissionStatus
                        .READY_FOR_SEPARATE_REAL_VPS_NGINX_RELOAD_EXECUTION,
                    reloadAdmission.status,
                )
                assertTrue(reloadAdmission.requiresFreshCredentialResolution)
                assertTrue(reloadAdmission.requiresLiveRemoteHostKeyVerification)
                assertTrue(reloadAdmission.realVpsExecutionEligible)
                assertTrue(reloadAdmission.nginxReloadAuthorized)
                assertFalse(reloadAdmission.configMutationAuthorized)
                assertFalse(reloadAdmission.certificateMutationAuthorized)
                assertFalse(reloadAdmission.dnsMutationAuthorized)
                assertFalse(reloadAdmission.firewallMutationAuthorized)
                assertFalse(reloadAdmission.packageInstallAuthorized)
                assertFalse(reloadAdmission.privateKeyContentReadAuthorized)
                assertFalse(reloadAdmission.automaticRetryAuthorized)
                assertFalse(reloadAdmission.coordinatorInvoked)
                assertFalse(reloadAdmission.exposesDeployUiAction)

                val beforeReloadFence =
                    application.siteProductionDeploymentReplayFence.snapshot()
                val reloadCredential =
                    resolveFreshCredential(access, nonce, "reload", 180_000L)
                val reloadExecution =
                    SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary
                        .executeOnce(
                            admission = reloadAdmission,
                            selection = selection,
                            policyBoundPreflightExecution = execution,
                            policyBoundConfigMutationPreparation = phase1170,
                            stagingSyntaxAuthorityPreparation = result,
                            stagingSyntaxExecution = executionResult,
                            activationAuthorityPreparation = activationAuthority,
                            activationExecution = activationExecution,
                            reloadAuthorityPreparation = reloadAuthority,
                            freshResolutionProof = reloadCredential.proof,
                            freshCredentialLease = reloadCredential.lease,
                            serverAccess = access,
                            executionAttemptId = "phase11_76_reload_${nonce.take(16)}",
                            executedAtEpochMillis = reloadCredential.proof.resolvedAtEpochMillis + 10L,
                            executionUsePort = application.siteProductionDeploymentReplayFence
                                .realVpsWebServingNginxReloadExecutionUsePort(),
                        )
                SiteProductionDeploymentAndroidPolicyBoundNginxReloadExecutionBoundary
                    .validateExecutionResultAgainst(
                        result = reloadExecution,
                        admission = reloadAdmission,
                        selection = selection,
                        policyBoundPreflightExecution = execution,
                        policyBoundConfigMutationPreparation = phase1170,
                        stagingSyntaxAuthorityPreparation = result,
                        stagingSyntaxExecution = executionResult,
                        activationAuthorityPreparation = activationAuthority,
                        activationExecution = activationExecution,
                        reloadAuthorityPreparation = reloadAuthority,
                    )
                SiteProductionDeploymentAndroidRealVpsWebServingNginxReloadExecutionBoundary
                    .validateProof(reloadExecution.phase11_61ExecutionProof)
                val afterReloadFence =
                    application.siteProductionDeploymentReplayFence.snapshot()
                assertEquals(
                    beforeReloadFence.realVpsWebServingNginxReloadExecutionReceiptMarkerCount + 1,
                    afterReloadFence.realVpsWebServingNginxReloadExecutionReceiptMarkerCount,
                )
                assertEquals(
                    SiteProductionDeploymentPolicyBoundNginxReloadExecutionStatus
                        .NGINX_RELOADED_ONCE_EXACT_CONFIG_PRESERVED_EXPECTED_LISTENER_LIVE,
                    reloadExecution.status,
                )
                assertEquals(3, reloadExecution.phase11_61ExecutionProof.remoteCommandCount)
                assertTrue(reloadExecution.exactProductionChainBindingVerified)
                assertTrue(reloadExecution.successfulConfigActivationExecutionProofValidated)
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
                assertFalse(reloadExecution.certificateMutationPerformed)
                assertFalse(reloadExecution.dnsMutationPerformed)
                assertFalse(reloadExecution.firewallMutationPerformed)
                assertFalse(reloadExecution.packageInstallPerformed)
                assertFalse(reloadExecution.privateKeyContentReadPerformed)
                assertFalse(reloadExecution.automaticRetryPerformed)
                assertFalse(reloadExecution.coordinatorInvoked)
                assertFalse(reloadExecution.exposesDeployUiAction)
                println("PHASE11_76_NGINX_RELOAD_EXECUTION_STATUS=${reloadExecution.status.name}")
                mark("STEP_14_ONE_POLICY_BOUND_REAL_VPS_NGINX_RELOAD_COMPLETE_LISTENER_LIVE")

                val cleanupCredential =
                    resolveFreshCredential(access, nonce, "cleanup", 190_000L)
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
                mark("STEP_15_ACCEPTANCE_ONLY_REMOVE_CONFIG_RELOAD_AND_RESTORE_ABSENT")
            } finally {
                if (publicationConfigPath != null && publicationConfigSha != null) {
                    Log.e("Phase11_76Diag", "REMOTE_EXACT_CONFIG_MAY_REQUIRE_RECONCILIATION=$publicationConfigPath")
                }
                val delete = secretStore.delete(secretId)
                assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
                config.closeSensitiveBytes()
                deleteTree(localRoot)
                runCatching { configFile.delete() }
                mark("STEP_16_LOCAL_CLEANUP_COMPLETE")
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
            admissionAttemptId = "phase11_76_${suffix}_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft =
            application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
                admission = admission,
                authorizationAttemptId = "phase11_76_${suffix}_preflight_$nonce",
                evaluatedAtEpochMillis = base + 10L,
                requestedAuthorizationLifetimeMillis = 10_000L,
            )
        val preflightAuthorization =
            application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
                preflightDraft,
                SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                    preflightDraft.approvalChallengeSha256,
                    true,
                ),
            )
        val preflightReceipt =
            application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
                preflightAuthorization,
                base + 11L,
            )
        val credentialDraft =
            application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
                receipt = preflightReceipt,
                serverAccess = access,
                authorizationAttemptId = "phase11_76_${suffix}_credential_$nonce",
                evaluatedAtEpochMillis = base + 20L,
                requestedAuthorizationLifetimeMillis = 10_000L,
            )
        val credentialAuthorization =
            application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
                credentialDraft,
                SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                    credentialDraft.approvalChallengeSha256,
                    true,
                ),
            )
        val credentialHandoff =
            application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
                credentialAuthorization,
                base + 21L,
            )
        return (application.siteProductionDeploymentResolveRealVpsCredentialOnce(
            credentialHandoff,
            access,
            base + 22L,
        ) as SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved).also {
            SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
                .validateProof(it.proof)
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
        val owner = SessionOwner.Operation(OperationId("phase11_76_cleanup_${nonce.take(20)}"))
        val sessionId = SessionId("phase11_76_cleanup_session_${nonce.take(16)}")
        val leaseStore =
            OneShotPhase11_76AcceptanceCleanupLeaseSecretStore(access.auth.secretId, resolved.lease)
        val factory = JschSshConnectionFactory(
            secretStore = leaseStore,
            sessionIdFactory = { sessionId },
        )
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
                ?: throw IllegalArgumentException("Phase 11.76 acceptance cleanup SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                throw IllegalArgumentException("Phase 11.76 acceptance cleanup lacks verified host-key evidence")
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
                RemoteCommand.create(raw, "phase11-76-acceptance-only-cleanup-reload-to-absent"),
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
            require(
                commandResult.stdout.copyBytes().toString(StandardCharsets.UTF_8).trim() ==
                    "ABSENT",
            )
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
        port: Int,
        targetRoot: String,
    ) = SiteDeployerLocalPreparationBoundary.prepare(
        SiteDeployerLocalPreparationRequest(
            rootSeed = DesignSeed(1176L),
            domain = "phase1176.example.com",
            servicePort = port,
            remoteHostIdentity = host,
            targetRoot = targetRoot,
            owner = "root",
            group = "root",
            reuseExisting3xUiCertificate = false,
        ),
        root,
    )

    private fun evidence(preparation: SiteDeployerLocalPreparationResult) =
        SiteStaticPublicationEvidence(
            preparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            committedClean = true,
            remoteResidualStateClean = true,
        )

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS,
        )
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun requiredRunNonce(): String {
        val nonce =
            InstrumentationRegistry.getArguments()
                .getString("phase11_76_run_nonce")
                ?.trim()
                .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun mark(step: String) { Log.i("Phase11_76Diag", step) }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_76_policy_bound_nginx_reload_execution_acceptance.properties"
    }
}

private class OneShotPhase11_76AcceptanceCleanupLeaseSecretStore(
    private val expectedSecretId: SecretId,
    private val credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
) : SecretStore {
    private val readStarted = AtomicBoolean(false)

    override suspend fun read(secretId: SecretId): SecretReadResult {
        if (secretId != expectedSecretId) return SecretReadResult.NotFound
        if (!readStarted.compareAndSet(false, true)) {
            return SecretReadResult.Unavailable("Phase 11.76 cleanup credential lease is single-use")
        }
        val copy = credentialLease.useMaterialOnce { material ->
            material.useBytes { SecretMaterial.fromBytes(it) }
        }
        return SecretReadResult.Found(copy)
    }

    override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
        SecretCreateResult.StorageFailure("Phase 11.76 cleanup lease adapter is read-only")

    override suspend fun delete(secretId: SecretId): SecretDeleteResult =
        SecretDeleteResult.StorageFailure("Phase 11.76 cleanup lease adapter is read-only")

    override suspend fun listIds(): SecretListResult =
        SecretListResult.StorageFailure("Phase 11.76 cleanup lease adapter does not enumerate secrets")
}

private class OneShotPhase11_76Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(
            password ?: error("Phase 11.76 password material is closed"),
        )

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_76Config {
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
                return OneShotPhase11_76Config(host, port, username, hostKey, password)
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
