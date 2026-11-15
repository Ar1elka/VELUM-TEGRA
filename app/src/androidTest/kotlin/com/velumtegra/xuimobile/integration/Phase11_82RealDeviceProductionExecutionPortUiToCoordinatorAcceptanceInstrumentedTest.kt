package com.velumtegra.xuimobile.integration

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.util.Base64
import android.util.Log
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.lifecycle.ViewModelProvider
import com.velumtegra.xuimobile.MainActivity
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
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
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteDeploymentCoordinatorRequest
import com.velumtegra.xuimobile.core.site.SiteExportFormat
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentExecutionApproval
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentExecutionRequest
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReadinessBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReadinessRequest
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeIdentity
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationApproval
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationRequest
import com.velumtegra.xuimobile.core.site.SiteProductionObservationFreshnessPolicy
import com.velumtegra.xuimobile.core.site.SiteProductionOperatorApproval
import com.velumtegra.xuimobile.core.site.SiteProductionServiceBindingIntent
import com.velumtegra.xuimobile.core.site.SiteProductionServiceBindingObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployRequest
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPath
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import com.velumtegra.xuimobile.core.site.SiteRemoteOwnershipObservation
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightObservation
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightPolicy
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightTrust
import com.velumtegra.xuimobile.core.site.SiteRemoteServerObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportPolicy
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportTreeEntrySpec
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SiteRemoteReadOnlyObservationSshAdapter
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpPrimitiveFactory
import com.velumtegra.xuimobile.sitedeployer.SiteDeployerReviewViewModel
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidProductionExecutionContext
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentEphemeralCredentialLease
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsExecutionCredential
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsStaticFileTransactionStep
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentUiExecutionStatus
import kotlinx.coroutines.runBlocking
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.Arrays
import java.util.Comparator
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_82RealDeviceProductionExecutionPortUiToCoordinatorAcceptanceInstrumentedTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() =
        context.applicationContext as VelumTegraApplication

    @Test
    fun realUiConfirmationsReachExistingCoordinatorExactlyOnce() {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.82 one-shot UI-to-coordinator acceptance config is missing" }
        val config = OneShotPhase11_82Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_82_acceptance_credential")
        val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_82-local-")
        val coordinatorRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_82-coordinator-")
        val credentialSequence = AtomicInteger(0)

        try {
            runBlocking { secretStore.delete(secretId) }
            val access = ServerAccess(
                id = ServerAccessId("phase11_82_access_$nonce"),
                serverId = ServerId("phase11_82_server_$nonce"),
                endpoint = SshEndpoint(config.host, config.port),
                username = config.username,
                auth = SshAuthRef.Password(secretId),
                pinnedHostKey = HostKeyFingerprint(config.hostKeySha256),
            )
            val material = config.toSecretMaterial()
            try {
                assertEquals(SecretCreateResult.Created, runBlocking { secretStore.create(secretId, material) })
            } finally {
                material.close()
                config.closeSensitiveBytes()
            }
            mark("STEP_02_SECRET_CREATED")

            // Deep recovery classification is also deliberately read-only. It first identifies the
            // single retained Phase 11.82 target from the ambiguous prior run, then reconstructs
            // the deterministic expected bundle locally and compares the exact target/staging state
            // through the already accepted pinned-key read-only SSH observation path. No remote
            // mutation primitive is reachable from this branch.
            if (requiredReadOnlyOutcomeClassificationMode()) {
                val residue = runBlocking { observePriorPhase1182Residue(access, nonce) }
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_RESIDUE_COUNT=${residue.size}")
                require(residue.size == 1) {
                    "Phase 11.82 outcome classification requires exactly one retained target"
                }
                val residueTarget = residue.single()
                require(Regex("^/tmp/velum-p1182-[0-9a-f]{16}$").matches(residueTarget)) {
                    "Phase 11.82 retained target is outside the fixed nonce-scoped namespace"
                }
                val expected = SiteDeployerLocalPreparationBoundary.prepare(
                    SiteDeployerLocalPreparationRequest(
                        rootSeed = DesignSeed(1182L),
                        domain = ACCEPTANCE_DOMAIN,
                        servicePort = ACCEPTANCE_SERVICE_PORT,
                        exportFormat = SiteExportFormat.ZIP,
                        remoteHostIdentity = config.host,
                        targetRoot = residueTarget,
                        owner = "root",
                        group = "root",
                        reuseExisting3xUiCertificate = false,
                    ),
                    localRoot,
                )
                SiteDeployerLocalPreparationBoundary.validate(expected)
                val classification = runBlocking {
                    classifyPriorPhase1182Outcome(access, nonce, expected)
                }
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_TARGET=$residueTarget")
                Log.i(
                    "Phase11_82Diag",
                    "READ_ONLY_CLASSIFICATION_EXPECTED_TREE_SHA256=${expected.remoteDeployPlan.sourceTreeSha256}",
                )
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_TARGET_TYPE=${classification.targetType.name}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_STAGING_ROOT=${expected.remoteDeployPlan.publish.stagingRoot}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_STAGING_TYPE=${classification.stagingType.name}")
                Log.i(
                    "Phase11_82Diag",
                    "READ_ONLY_CLASSIFICATION_TARGET_TREE_SHA256=${classification.targetTreeSha256 ?: "ABSENT"}",
                )
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_TARGET_TREE_EXACT=${classification.targetTreeExact}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_EXPECTED_FILE_COUNT=${expected.remoteDeployPlan.fileCount}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_TARGET_FILE_COUNT=${classification.targetTreeFileCount ?: -1}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_EXPECTED_TOTAL_BYTES=${expected.remoteDeployPlan.totalBytes}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_TARGET_TOTAL_BYTES=${classification.targetTreeTotalBytes ?: -1}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_LISTING_EXACT=${classification.listingExact}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_EXPECTED_LISTING_COUNT=${classification.expectedListingCount}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_ACTUAL_LISTING_COUNT=${classification.actualListingCount}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_MISSING_COUNT=${classification.missingListing.size}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_UNEXPECTED_COUNT=${classification.unexpectedListing.size}")
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_UNSAFE_ACTUAL_COUNT=${classification.unsafeActualListingCount}")
                Log.i(
                    "Phase11_82Diag",
                    "READ_ONLY_CLASSIFICATION_MISSING_SAFE=${classification.missingListing.take(8).joinToString("|").ifEmpty { "ABSENT" }}",
                )
                Log.i(
                    "Phase11_82Diag",
                    "READ_ONLY_CLASSIFICATION_UNEXPECTED_SAFE=${classification.unexpectedListing.take(8).joinToString("|").ifEmpty { "ABSENT" }}",
                )
                Log.i("Phase11_82Diag", "READ_ONLY_CLASSIFICATION_OUTCOME=${classification.outcome}")
                mark("STEP_02D_READ_ONLY_OUTCOME_CLASSIFICATION_COMPLETE")
                return
            }

            // Recovery mode is deliberately read-only. After an ambiguous prior real-device run,
            // it observes the fixed Phase 11.82 /tmp namespace and exits before local preparation,
            // UI admission, coordinator invocation, staging, commit or cleanup. This is the
            // action -> consequence -> counteraction fence: classify the prior remote consequence
            // before any later mutation can be considered.
            if (requiredReadOnlyReconciliationMode()) {
                val residue = runBlocking { observePriorPhase1182Residue(access, nonce) }
                Log.i("Phase11_82Diag", "READ_ONLY_OUTCOME_RESIDUE_COUNT=${residue.size}")
                Log.i(
                    "Phase11_82Diag",
                    "READ_ONLY_OUTCOME_RESIDUE=${if (residue.isEmpty()) "ABSENT" else residue.joinToString(",")}",
                )
                mark("STEP_02C_READ_ONLY_OUTCOME_RECONCILIATION_COMPLETE")
                return
            }

            // Reconcile the previous failed Phase 11.82 attempt before authorizing any new mutation.
            // This is read-only: one verified SSH/SFTP session lists /tmp with a hard bound and
            // fails closed if any Phase 11.82 target/staging residue remains. No cleanup/retry is
            // performed by this reconciliation step.
            runBlocking { reconcilePriorPhase1182Residue(access, nonce) }
            mark("STEP_02B_PRIOR_REMOTE_RESIDUE_ABSENT")

            val preparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(1182L),
                    domain = ACCEPTANCE_DOMAIN,
                    servicePort = ACCEPTANCE_SERVICE_PORT,
                    exportFormat = SiteExportFormat.ZIP,
                    remoteHostIdentity = config.host,
                    targetRoot = "/tmp/velum-p1182-${nonce.take(16)}",
                    owner = "root",
                    group = "root",
                    reuseExisting3xUiCertificate = false,
                ),
                localRoot,
            )
            SiteDeployerLocalPreparationBoundary.validate(preparation)
            mark("STEP_03_EXACT_LOCAL_PREPARATION_READY")

            val trustedKey = when (val parsed = CanonicalHostKeyFingerprint.parse(access.pinnedHostKey)) {
                is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
                is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
            }
            val remoteRequest = SiteRemoteDeployRequest(
                remoteHostIdentity = config.host,
                targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
                owner = "root",
                group = "root",
                certificateReuse = SiteCertificateReuseRequest(),
            )
            val base = System.currentTimeMillis() - 1_000L
            val observedAt = base
            val readinessRequest = SiteProductionDeploymentReadinessRequest(
                exportPlan = preparation.previewExport.export,
                localReceipt = preparation.localExportReceipt,
                remoteRequest = remoteRequest,
                trust = SiteRemotePreflightTrust(trustedKey),
                remoteObservation = SiteRemotePreflightObservation(
                    server = SiteRemoteServerObservation(config.host, trustedKey),
                    target = SiteRemoteObservedPath(
                        preparation.remoteDeployPlan.publish.targetRoot,
                        SiteRemoteObservedPathType.ABSENT,
                    ),
                    staging = SiteRemoteObservedPath(
                        preparation.remoteDeployPlan.publish.stagingRoot,
                        SiteRemoteObservedPathType.ABSENT,
                    ),
                    backup = null,
                    availableBytes = SiteRemotePreflightPolicy.requiredAvailableBytes(preparation.remoteDeployPlan) + 4096L,
                    ownership = SiteRemoteOwnershipObservation(true, true, true, true),
                ),
                remoteObservationObservedAtEpochMillis = observedAt,
                serviceBindingIntent = SiteProductionServiceBindingIntent(
                    preparation.serviceBinding.domain,
                    preparation.serviceBinding.port,
                ),
                serviceBindingObservation = SiteProductionServiceBindingObservation(
                    remoteHostIdentity = config.host,
                    serverKeySha256 = trustedKey,
                    domain = preparation.serviceBinding.domain,
                    port = preparation.serviceBinding.port,
                    configured = true,
                    observedAtEpochMillis = observedAt,
                ),
                freshnessPolicy = SiteProductionObservationFreshnessPolicy(
                    evaluatedAtEpochMillis = base + 10L,
                    maxAgeMillis = 300_000L,
                ),
            )
            val readinessDraft = SiteProductionDeploymentReadinessBoundary.prepare(readinessRequest)
            val readyRecord = SiteProductionDeploymentReadinessBoundary.approve(
                readinessDraft,
                SiteProductionOperatorApproval(readinessDraft.operatorApprovalChallengeSha256, true),
            )
            val executionRequest = SiteProductionDeploymentExecutionRequest(
                readyRecord = readyRecord,
                readinessRequest = readinessRequest,
                coordinatorRequest = SiteDeploymentCoordinatorRequest(
                    exportPlan = preparation.previewExport.export,
                    localOutputRoot = coordinatorRoot,
                    remoteRequest = remoteRequest,
                    trust = readinessRequest.trust,
                ),
                transportCapabilities = SiteRemoteSftpPrimitiveFactory.CAPABILITIES,
                executionAttemptId = "phase11_82_attempt_${nonce.take(16)}",
                evaluatedAtEpochMillis = base + 20L,
            )
            val executionDraft = SiteProductionDeploymentExecutionBoundary.prepare(executionRequest)
            val executionAuthorization = SiteProductionDeploymentExecutionBoundary.authorize(
                executionDraft,
                SiteProductionDeploymentExecutionApproval(
                    executionDraft.executionApprovalChallengeSha256,
                    true,
                ),
            )
            val runtimeMutationRequest = SiteProductionDeploymentRuntimeMutationRequest(
                executionAuthorization = executionAuthorization,
                executionRequest = executionRequest,
                runtimeIdentity = SiteProductionDeploymentRuntimeIdentity(
                    runtimeSessionId = "phase11_82_runtime_${nonce.take(16)}",
                    remoteHostIdentity = config.host,
                    transportImplementationId = SiteRemoteSftpPrimitiveFactory.CAPABILITIES.implementationId,
                    capabilityProfileSha256 = SiteRemoteTransportPolicy.capabilityProfileSha256(
                        SiteRemoteSftpPrimitiveFactory.CAPABILITIES,
                    ),
                ),
                coordinatorInvocationId = "phase11_82_invoke_${nonce.take(16)}",
                evaluatedAtEpochMillis = base + 30L,
                requestedPermitLifetimeMillis = 60_000L,
            )
            val runtimeDraft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(runtimeMutationRequest)
            val runtimePermit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
                runtimeDraft,
                SiteProductionDeploymentRuntimeMutationApproval(
                    runtimeDraft.runtimeMutationApprovalChallengeSha256,
                    true,
                ),
            )
            val invocationAuthorization = SiteProductionDeploymentRuntimeMutationBoundary
                .consumeForSingleCoordinatorInvocation(
                    permit = runtimePermit,
                    request = runtimeMutationRequest,
                    consumedAtEpochMillis = base + 40L,
                    consumptionPort = application.siteProductionDeploymentReplayFence
                        .runtimeMutationConsumptionPort(),
                )
            val coordinatorAdmission =
                SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary.admit(
                    invocationAuthorization = invocationAuthorization,
                    runtimeMutationRequest = runtimeMutationRequest,
                    preparation = preparation,
                    serverAccess = access,
                    evaluatedAtEpochMillis = base + 50L,
                )
            mark("STEP_04_PHASE11_80_CONTEXT_READY")

            val provider = object : SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider {
                override suspend fun acquire(
                    step: SiteProductionDeploymentRealVpsStaticFileTransactionStep,
                ): SiteProductionDeploymentRealVpsExecutionCredential {
                    val sequence = credentialSequence.incrementAndGet()
                    val resolved = resolveFreshCredential(
                        access = access,
                        nonce = nonce,
                        suffix = "ui$sequence",
                        base = System.currentTimeMillis(),
                    )
                    return SiteProductionDeploymentRealVpsExecutionCredential(
                        proof = resolved.proof,
                        lease = resolved.lease,
                        executionAttemptId = "phase11_82_ui_${sequence}_${nonce.take(12)}",
                        executedAtEpochMillis = resolved.proof.resolvedAtEpochMillis + 10L,
                    )
                }
            }
            application.publishSiteDeployerProductionExecutionContext(
                SiteProductionDeploymentAndroidProductionExecutionContext(
                    preparation = preparation,
                    coordinatorAdmission = coordinatorAdmission,
                    invocationAuthorization = invocationAuthorization,
                    runtimeMutationRequest = runtimeMutationRequest,
                    serverAccess = access,
                    credentialProvider = provider,
                    uiPreparedAtEpochMillis = base + 60L,
                ),
            )
            mark("STEP_05_CONCRETE_PRODUCTION_PORT_CONTEXT_PUBLISHED")

            // Exercise the real MainActivity composition. The Activity was created with the
            // concrete production port factory; publishing the exact context above performs no
            // network work. Opening the screen and editing the review causes the ViewModel to
            // request a fresh Phase 11.81 admission from that concrete app port.
            compose.onNodeWithTag("home_site_deployer_review").performClick()
            compose.onNodeWithTag("site_deployer_review_root").fetchSemanticsNode()
            val viewModel = ViewModelProvider(compose.activity)[SiteDeployerReviewViewModel::class.java]

            // Drive the real reviewed form into the exact source/domain/port bound by Phase 11.80.
            compose.onNodeWithTag("site_deployer_seed").performScrollTo().performTextReplacement("1182")
            compose.onNodeWithTag("site_deployer_domain").performScrollTo().performTextReplacement(ACCEPTANCE_DOMAIN)
            compose.onNodeWithTag("site_deployer_port").performScrollTo()
                .performTextReplacement(ACCEPTANCE_SERVICE_PORT.toString())
            compose.waitUntil(timeoutMillis = 10_000L) {
                viewModel.uiState.value.productionAdmission != null
            }
            val uiAdmission = requireNotNull(viewModel.uiState.value.productionAdmission)
            assertEquals(config.host, uiAdmission.remoteHostIdentity)
            assertEquals(preparation.remoteDeployPlan.publish.targetRoot, uiAdmission.targetRoot)
            assertEquals(preparation.remoteDeployPlan.sourceTreeSha256, uiAdmission.sourceTreeSha256)
            assertEquals(coordinatorAdmission.admissionSha256, uiAdmission.phase1180AdmissionSha256)

            val deploy = compose.onNodeWithTag("site_deployer_production_deploy")
            deploy.performScrollTo().assertIsNotEnabled()
            compose.onNodeWithTag("site_deployer_confirm_exact_target").performScrollTo().performClick()
            deploy.assertIsNotEnabled()
            compose.onNodeWithTag("site_deployer_confirm_real_mutation").performScrollTo().performClick()
            deploy.assertIsNotEnabled()
            compose.onNodeWithTag("site_deployer_confirm_no_retry").performScrollTo().performClick()
            deploy.assertIsEnabled()
            mark("STEP_06_REAL_UI_THREE_CONFIRMATIONS_ACCEPTED")

            val before = application.siteProductionDeploymentReplayFence.snapshot()
            deploy.performClick()
            compose.waitUntil(timeoutMillis = 180_000L) {
                val state = viewModel.uiState.value
                state.productionExecutionReceipt != null || state.productionExecutionError != null
            }
            val state = viewModel.uiState.value
            check(state.productionExecutionError == null) { state.productionExecutionError ?: "unknown UI execution failure" }
            val receipt = requireNotNull(state.productionExecutionReceipt)
            assertEquals(
                SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_EXACT_STATIC_TREE,
                receipt.status,
            )
            assertTrue(state.productionAttemptConsumed)
            assertFalse(state.productionExecutionInProgress)
            assertEquals(1, receipt.existingCoordinatorInvocationCount)
            assertTrue(receipt.acceptedPhase1155TransactionDelegated)
            assertFalse(receipt.automaticRetryPerformed)
            assertEquals(2, credentialSequence.get())
            compose.onNodeWithTag("site_deployer_production_result").performScrollTo()
            deploy.assertIsNotEnabled()

            val after = application.siteProductionDeploymentReplayFence.snapshot()
            assertEquals(
                before.coordinatorInvocationAuthorizationMarkerCount + 1,
                after.coordinatorInvocationAuthorizationMarkerCount,
            )
            assertEquals(
                before.realVpsStagingWriteExecutionReceiptMarkerCount + 1,
                after.realVpsStagingWriteExecutionReceiptMarkerCount,
            )
            assertEquals(
                before.realVpsCommitTransactionExecutionReceiptMarkerCount + 1,
                after.realVpsCommitTransactionExecutionReceiptMarkerCount,
            )
            assertEquals(
                before.realVpsPostTransactionCleanupExecutionReceiptMarkerCount,
                after.realVpsPostTransactionCleanupExecutionReceiptMarkerCount,
            )
            mark("STEP_07_REAL_UI_REACHED_EXISTING_COORDINATOR_EXACTLY_ONCE")
        } finally {
            application.clearSiteDeployerProductionExecutionContext()
            val delete = runBlocking { secretStore.delete(secretId) }
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            deleteTree(localRoot)
            deleteTree(coordinatorRoot)
            runCatching { configFile.delete() }
            mark("STEP_08_LOCAL_CLEANUP_COMPLETE_REMOTE_NONCE_TARGET_RETAINED")
        }
    }

    private suspend fun classifyPriorPhase1182Outcome(
        access: ServerAccess,
        nonce: String,
        expected: SiteDeployerLocalPreparationResult,
    ): ReadOnlyOutcomeClassification {
        val resolved = resolveFreshCredential(
            access = access,
            nonce = nonce,
            suffix = "classify",
            base = System.currentTimeMillis(),
        )
        val owner = SessionOwner.Operation(OperationId("phase11_82_classify_${nonce.take(20)}"))
        val sessionId = SessionId("phase11_82_classify_session_${nonce.take(16)}")
        val leaseStore = OneShotPhase1182ReconciliationLeaseSecretStore(access.auth.secretId, resolved.lease)
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
                    stdoutCaptureLimitBytes = 64 * 1024,
                    stderrCaptureLimitBytes = 16 * 1024,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: error("Phase 11.82 read-only classification SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                error("Phase 11.82 read-only classification lacks verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.binding.serverAccessId == access.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == sessionId)
            require(verified.isOpen)

            val plan = expected.remoteDeployPlan
            val observer = SiteRemoteReadOnlyObservationSshAdapter()
            val preflight = observer.collectPreflight(plan, access, verified)
            val targetType = preflight.target.type
            val stagingType = preflight.staging.type
            val expectedFiles = expected.bundle.documents.sortedBy { it.path }
            val specs = expectedFiles.map { SiteRemoteTransportTreeEntrySpec(it.path, it.mediaType) }

            var targetTreeSha256: String? = null
            var targetTreeExact = false
            var targetTreeFileCount: Int? = null
            var targetTreeTotalBytes: Long? = null
            var listingExact = false
            var expectedListingCount = 0
            var actualListingCount = 0
            var missingListing: List<String> = emptyList()
            var unexpectedListing: List<String> = emptyList()
            var unsafeActualListingCount = 0
            if (targetType == SiteRemoteObservedPathType.DIRECTORY) {
                val expectedDirectories = expectedFiles
                    .mapNotNull { it.path.substringBeforeLast('/', missingDelimiterValue = "").ifBlank { null } }
                    .flatMap { parent ->
                        val segments = parent.split('/')
                        segments.indices.map { index -> segments.take(index + 1).joinToString("/") }
                    }
                    .distinct()
                val expectedListing = buildList {
                    expectedDirectories.forEach { add("$it\td") }
                    expectedFiles.forEach { add("${it.path}\tf") }
                }.sorted()
                val targetRoot = plan.publish.targetRoot
                require(Regex("^/tmp/velum-p1182-[0-9a-f]{16}$").matches(targetRoot))
                val listingResult = verified.execute(
                    RemoteCommand.create(
                        "find '$targetRoot' -mindepth 1 -printf '%P\\t%y\\n' | sort",
                        "phase11-82-read-only-exact-target-listing",
                    ),
                    SshTransportConfig(
                        channelOpenTimeout = Duration.ofSeconds(5),
                        commandExecutionTimeout = Duration.ofSeconds(8),
                        stdoutCaptureLimitBytes = 64 * 1024,
                        stderrCaptureLimitBytes = 16 * 1024,
                    ),
                )
                require(listingResult.dispatchState == CommandDispatchState.DISPATCHED)
                require(listingResult.completion == CommandCompletion.ConfirmedSuccess)
                require(!listingResult.stdout.truncated && !listingResult.stderr.truncated)
                val actualListing = listingResult.stdout.copyBytes().toString(StandardCharsets.UTF_8)
                    .lineSequence()
                    .map { it.trimEnd() }
                    .filter { it.isNotEmpty() }
                    .toList()
                expectedListingCount = expectedListing.size
                actualListingCount = actualListing.size
                val safeListingEntry = Regex("^[A-Za-z0-9._/-]+\\t[a-zA-Z]$")
                unsafeActualListingCount = actualListing.count { !safeListingEntry.matches(it) }
                val expectedSet = expectedListing.toSet()
                val actualSet = actualListing.toSet()
                // GNU sort follows the remote locale while Kotlin sorted() uses Unicode code-point
                // order. Exactness is semantic set equality, not presentation order; keep the
                // count and safe-entry fences so duplicates or malformed rows still fail closed.
                listingExact = unsafeActualListingCount == 0 &&
                    actualListing.size == expectedListing.size &&
                    actualSet == expectedSet
                missingListing = (expectedSet - actualSet).sorted()
                unexpectedListing = (actualSet - expectedSet)
                    .filter(safeListingEntry::matches)
                    .sorted()
                val treeObservation = runCatching { observer.observeTree(targetRoot, specs, verified) }.getOrNull()
                targetTreeSha256 = treeObservation?.treeSha256
                targetTreeFileCount = treeObservation?.fileCount
                targetTreeTotalBytes = treeObservation?.totalBytes
                targetTreeExact = listingExact &&
                    treeObservation != null &&
                    treeObservation.treeSha256 == plan.sourceTreeSha256 &&
                    treeObservation.fileCount == plan.fileCount &&
                    treeObservation.totalBytes == plan.totalBytes
            }

            val outcome = when {
                targetType == SiteRemoteObservedPathType.DIRECTORY &&
                    stagingType == SiteRemoteObservedPathType.ABSENT && targetTreeExact -> "COMMITTED_EXACT_TREE"
                targetType == SiteRemoteObservedPathType.ABSENT &&
                    stagingType == SiteRemoteObservedPathType.DIRECTORY -> "STAGED_NOT_COMMITTED"
                targetType == SiteRemoteObservedPathType.ABSENT &&
                    stagingType == SiteRemoteObservedPathType.ABSENT -> "NO_REMOTE_TREE"
                else -> "AMBIGUOUS_REMOTE_STATE"
            }
            return ReadOnlyOutcomeClassification(
                targetType = targetType,
                stagingType = stagingType,
                targetTreeSha256 = targetTreeSha256,
                targetTreeExact = targetTreeExact,
                targetTreeFileCount = targetTreeFileCount,
                targetTreeTotalBytes = targetTreeTotalBytes,
                listingExact = listingExact,
                expectedListingCount = expectedListingCount,
                actualListingCount = actualListingCount,
                missingListing = missingListing,
                unexpectedListing = unexpectedListing,
                unsafeActualListingCount = unsafeActualListingCount,
                outcome = outcome,
            )
        } finally {
            runCatching { connectedHandle?.close() }
            resolved.lease.close()
        }
    }

    private suspend fun reconcilePriorPhase1182Residue(
        access: ServerAccess,
        nonce: String,
    ) {
        val residue = observePriorPhase1182Residue(access, nonce)
        if (residue.isNotEmpty()) {
            Log.e("Phase11_82Diag", "RECONCILIATION_REMOTE_RESIDUE=${residue.joinToString(",")}")
            error("Prior Phase 11.82 remote residue is present; no new deployment was attempted")
        }
    }

    private suspend fun observePriorPhase1182Residue(
        access: ServerAccess,
        nonce: String,
    ): List<String> {
        mark("STEP_02A_PRIOR_REMOTE_RECONCILIATION_START")
        val resolved = resolveFreshCredential(
            access = access,
            nonce = nonce,
            suffix = "reconcile",
            base = System.currentTimeMillis(),
        )
        val owner = SessionOwner.Operation(OperationId("phase11_82_reconcile_${nonce.take(20)}"))
        val sessionId = SessionId("phase11_82_reconcile_session_${nonce.take(16)}")
        val leaseStore = OneShotPhase1182ReconciliationLeaseSecretStore(access.auth.secretId, resolved.lease)
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
                    commandExecutionTimeout = Duration.ofSeconds(5),
                    stdoutCaptureLimitBytes = 4096,
                    stderrCaptureLimitBytes = 4096,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: error("Phase 11.82 read-only reconciliation SSH acquisition failed closed")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                error("Phase 11.82 read-only reconciliation lacks verified host-key evidence")
            }
            connectedHandle = verified
            require(verified.binding.serverAccessId == access.id)
            require(verified.binding.owner == owner)
            require(verified.binding.sessionId == sessionId)
            require(verified.isOpen)
            // Test-only reconciliation command: exact fixed read-only vocabulary, no user input and
            // no production authority. It only enumerates Phase 11.82 nonce-scoped paths in /tmp.
            val result = verified.execute(
                RemoteCommand.create(
                    "find /tmp -mindepth 1 -maxdepth 1 -name 'velum-p1182-*' -print | sort",
                    "phase11-82-read-only-residue-reconciliation",
                ),
                SshTransportConfig(
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(5),
                    stdoutCaptureLimitBytes = 16 * 1024,
                    stderrCaptureLimitBytes = 16 * 1024,
                ),
            )
            require(result.dispatchState == CommandDispatchState.DISPATCHED)
            require(result.completion == CommandCompletion.ConfirmedSuccess)
            require(!result.stdout.truncated && !result.stderr.truncated)
            val residue = result.stdout.copyBytes().toString(StandardCharsets.UTF_8)
                .lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toList()
            return residue
        } finally {
            runCatching { connectedHandle?.close() }
            resolved.lease.close()
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
            admissionAttemptId = "phase11_82_${suffix}_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_82_${suffix}_preflight_$nonce",
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
            authorizationAttemptId = "phase11_82_${suffix}_credential_$nonce",
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

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS,
        )
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString("phase11_82_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun requiredReadOnlyOutcomeClassificationMode(): Boolean =
        InstrumentationRegistry.getArguments()
            .getString("phase11_82_classify_residue_only")
            ?.trim()
            ?.equals("true", ignoreCase = true) == true

    private fun requiredReadOnlyReconciliationMode(): Boolean =
        InstrumentationRegistry.getArguments()
            .getString("phase11_82_reconcile_only")
            ?.trim()
            ?.equals("true", ignoreCase = true) == true

    private fun mark(step: String) { Log.i("Phase11_82Diag", step) }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private data class ReadOnlyOutcomeClassification(
        val targetType: SiteRemoteObservedPathType,
        val stagingType: SiteRemoteObservedPathType,
        val targetTreeSha256: String?,
        val targetTreeExact: Boolean,
        val targetTreeFileCount: Int?,
        val targetTreeTotalBytes: Long?,
        val listingExact: Boolean,
        val expectedListingCount: Int,
        val actualListingCount: Int,
        val missingListing: List<String>,
        val unexpectedListing: List<String>,
        val unsafeActualListingCount: Int,
        val outcome: String,
    )

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_82_production_execution_port_ui_to_coordinator_acceptance.properties"
        private const val ACCEPTANCE_DOMAIN = "192-0-2-169.nip.io"
        private const val ACCEPTANCE_SERVICE_PORT = 58488
    }
}

private class OneShotPhase1182ReconciliationLeaseSecretStore(
    private val expectedSecretId: SecretId,
    private val credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
) : SecretStore {
    private val readStarted = AtomicBoolean(false)

    override suspend fun read(secretId: SecretId): SecretReadResult {
        if (secretId != expectedSecretId) return SecretReadResult.NotFound
        if (!readStarted.compareAndSet(false, true)) {
            return SecretReadResult.Unavailable("Phase 11.82 reconciliation credential lease is single-use")
        }
        val copy = credentialLease.useMaterialOnce { material ->
            material.useBytes { SecretMaterial.fromBytes(it) }
        }
        return SecretReadResult.Found(copy)
    }

    override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
        SecretCreateResult.StorageFailure("Phase 11.82 reconciliation lease adapter is read-only")

    override suspend fun delete(secretId: SecretId): SecretDeleteResult =
        SecretDeleteResult.StorageFailure("Phase 11.82 reconciliation lease adapter is read-only")

    override suspend fun listIds(): SecretListResult =
        SecretListResult.StorageFailure("Phase 11.82 reconciliation lease adapter does not enumerate secrets")
}

private class OneShotPhase11_82Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.82 password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_82Config {
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
                require(host.isNotBlank() && username.isNotBlank() && hostKey.startsWith("SHA256:") && port in 1..65535)
                require(password.isNotEmpty() && password.size <= 65536)
                return OneShotPhase11_82Config(host, port, username, hostKey, password)
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
