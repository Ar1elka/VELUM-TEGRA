package com.velumtegra.xuimobile.integration

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.util.Base64
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
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
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpPrimitiveFactory
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsExecutionCredential
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsStaticFileTransactionOutcome
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsStaticFileTransactionStep
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Arrays
import java.util.Comparator
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_80RealDevicePolicyBoundCoordinatorInvocationAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication get() =
        context.applicationContext as VelumTegraApplication

    @Test
    fun oneExistingCoordinatorInvocationMustDelegateToAcceptedPhase1155Transaction() = runBlocking {
        val nonce = requiredRunNonce()
        mark("STEP_01_TEST_START")
        assertInternetPermissionDeclared()
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        require(configFile.isFile) { "Phase 11.80 one-shot coordinator acceptance config is missing" }
        val config = OneShotPhase11_80Config.readAndDelete(configFile)
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11_80_acceptance_credential")
        val localRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_80-local-")
        val coordinatorRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_80-coordinator-")
        try {
            secretStore.delete(secretId)
            val access = ServerAccess(
                id = ServerAccessId("phase11_80_access_$nonce"),
                serverId = ServerId("phase11_80_server_$nonce"),
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

            val preparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(1180L),
                    domain = "192-0-2-169.nip.io",
                    servicePort = 58488,
                    exportFormat = SiteExportFormat.DIRECTORY,
                    remoteHostIdentity = config.host,
                    targetRoot = "/tmp/velum-p1180-${nonce.take(16)}",
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
            val observedAt = 1_000_000L
            val readinessEvaluatedAt = 1_001_000L
            val remoteObservation = SiteRemotePreflightObservation(
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
            )
            val readinessRequest = SiteProductionDeploymentReadinessRequest(
                exportPlan = preparation.previewExport.export,
                localReceipt = preparation.localExportReceipt,
                remoteRequest = remoteRequest,
                trust = SiteRemotePreflightTrust(trustedKey),
                remoteObservation = remoteObservation,
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
                    evaluatedAtEpochMillis = readinessEvaluatedAt,
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
                executionAttemptId = "phase11_80_attempt_${nonce.take(16)}",
                evaluatedAtEpochMillis = 1_002_000L,
            )
            val executionDraft = SiteProductionDeploymentExecutionBoundary.prepare(executionRequest)
            val executionAuthorization = SiteProductionDeploymentExecutionBoundary.authorize(
                executionDraft,
                SiteProductionDeploymentExecutionApproval(
                    executionDraft.executionApprovalChallengeSha256,
                    true,
                ),
            )
            val runtimeIdentity = SiteProductionDeploymentRuntimeIdentity(
                runtimeSessionId = "phase11_80_runtime_${nonce.take(16)}",
                remoteHostIdentity = config.host,
                transportImplementationId = SiteRemoteSftpPrimitiveFactory.CAPABILITIES.implementationId,
                capabilityProfileSha256 = SiteRemoteTransportPolicy.capabilityProfileSha256(
                    SiteRemoteSftpPrimitiveFactory.CAPABILITIES,
                ),
            )
            val runtimeMutationRequest = SiteProductionDeploymentRuntimeMutationRequest(
                executionAuthorization = executionAuthorization,
                executionRequest = executionRequest,
                runtimeIdentity = runtimeIdentity,
                coordinatorInvocationId = "phase11_80_invoke_${nonce.take(16)}",
                evaluatedAtEpochMillis = 1_003_000L,
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
                    consumedAtEpochMillis = 1_004_000L,
                    consumptionPort = application.siteProductionDeploymentReplayFence
                        .runtimeMutationConsumptionPort(),
                )
            mark("STEP_04_PHASE11_18_19_EXACT_COORDINATOR_AUTHORIZATION_CONSUMED")

            val admission = SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary.admit(
                invocationAuthorization = invocationAuthorization,
                runtimeMutationRequest = runtimeMutationRequest,
                preparation = preparation,
                serverAccess = access,
                evaluatedAtEpochMillis = 1_005_000L,
            )
            assertTrue(admission.requiresDurableCoordinatorInvocationFence)
            assertTrue(admission.delegatesToExistingCoordinator)
            assertTrue(admission.delegatesTransportToAcceptedPhase1155Transaction)
            assertFalse(admission.addsNewRemoteMutationPrimitive)
            assertFalse(admission.automaticRetryAuthorized)
            assertFalse(admission.arbitraryCommandAuthorized)
            assertFalse(admission.exposesDeployUiAction)
            mark("STEP_05_POLICY_BOUND_COORDINATOR_ADMISSION_READY")

            val before = application.siteProductionDeploymentReplayFence.snapshot()
            var credentialSequence = 0
            val result = SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary.executeOnce(
                admission = admission,
                invocationAuthorization = invocationAuthorization,
                runtimeMutationRequest = runtimeMutationRequest,
                preparation = preparation,
                serverAccess = access,
                credentialProvider = object : SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider {
                    override suspend fun acquire(
                        step: SiteProductionDeploymentRealVpsStaticFileTransactionStep,
                    ): SiteProductionDeploymentRealVpsExecutionCredential {
                        credentialSequence += 1
                        val resolved = resolveFreshCredential(
                            access = access,
                            nonce = nonce,
                            suffix = "coord$credentialSequence",
                            base = 200_000L + credentialSequence * 10_000L,
                        )
                        return SiteProductionDeploymentRealVpsExecutionCredential(
                            proof = resolved.proof,
                            lease = resolved.lease,
                            executionAttemptId = "phase11_80_coord_${credentialSequence}_${nonce.take(12)}",
                            executedAtEpochMillis = resolved.proof.resolvedAtEpochMillis + 10L,
                        )
                    }
                },
                replayFence = application.siteProductionDeploymentReplayFence,
                executedAtEpochMillis = 1_006_000L,
            )
            SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
                .validateExecutionResult(result, admission, preparation)
            val after = application.siteProductionDeploymentReplayFence.snapshot()

            assertEquals(
                SiteProductionDeploymentPolicyBoundCoordinatorInvocationExecutionStatus
                    .COORDINATOR_COMMITTED_EXACT_STATIC_TREE,
                result.status,
            )
            assertEquals(
                SiteProductionDeploymentRealVpsStaticFileTransactionOutcome.COMMITTED_CLEAN,
                result.staticFileTransactionResult.outcome,
            )
            assertEquals(
                preparation.remoteDeployPlan.sourceTreeSha256,
                result.staticFileTransactionResult.finalTargetTreeSha256,
            )
            assertTrue(result.coordinatorInvocationFenceConsumed)
            assertTrue(result.coordinatorInvoked)
            assertEquals(1, result.existingCoordinatorInvocationCount)
            assertTrue(result.acceptedPhase1155TransactionDelegated)
            assertFalse(result.newRemoteMutationPrimitiveAdded)
            assertFalse(result.automaticRetryPerformed)
            assertFalse(result.arbitraryCommandInputAccepted)
            assertFalse(result.exposesDeployUiAction)
            assertEquals(2, credentialSequence)
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
            println("PHASE11_80_COORDINATOR_STATUS=${result.status.name}")
            mark("STEP_06_ONE_EXISTING_COORDINATOR_INVOCATION_COMMITTED_EXACT_TREE")
        } finally {
            val delete = secretStore.delete(secretId)
            assertTrue(delete == SecretDeleteResult.Deleted || delete == SecretDeleteResult.AlreadyAbsent)
            config.closeSensitiveBytes()
            deleteTree(localRoot)
            deleteTree(coordinatorRoot)
            runCatching { configFile.delete() }
            mark("STEP_07_LOCAL_CLEANUP_COMPLETE_REMOTE_NONCE_TARGET_RETAINED")
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
            admissionAttemptId = "phase11_80_${suffix}_admission_$nonce",
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = "phase11_80_${suffix}_preflight_$nonce",
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
            authorizationAttemptId = "phase11_80_${suffix}_credential_$nonce",
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
            .getString("phase11_80_run_nonce")
            ?.trim()
            .orEmpty()
        require(Regex("^[0-9a-f]{32}$").matches(nonce))
        return nonce
    }

    private fun mark(step: String) { Log.i("Phase11_80Diag", step) }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    companion object {
        private const val CONFIG_FILE_NAME =
            "phase11_80_policy_bound_coordinator_invocation_acceptance.properties"
    }
}

private class OneShotPhase11_80Config private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    private var password: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial =
        SecretMaterial.fromBytes(password ?: error("Phase 11.80 password material is closed"))

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        password = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 256 * 1024

        fun readAndDelete(file: File): OneShotPhase11_80Config {
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
                return OneShotPhase11_80Config(host, port, username, hostKey, password)
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
