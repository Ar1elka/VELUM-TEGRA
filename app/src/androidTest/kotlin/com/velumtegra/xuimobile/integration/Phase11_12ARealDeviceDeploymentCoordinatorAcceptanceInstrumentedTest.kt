package com.velumtegra.xuimobile.integration

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
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
import com.velumtegra.xuimobile.core.site.SiteBuildRequest
import com.velumtegra.xuimobile.core.site.SiteBuilder
import com.velumtegra.xuimobile.core.site.SiteDeploymentCancellationSignal
import com.velumtegra.xuimobile.core.site.SiteDeploymentCoordinator
import com.velumtegra.xuimobile.core.site.SiteDeploymentCoordinatorRequest
import com.velumtegra.xuimobile.core.site.SiteDeploymentCoordinatorResult
import com.velumtegra.xuimobile.core.site.SiteDeploymentCoordinatorStage
import com.velumtegra.xuimobile.core.site.SiteDeploymentCoordinatorState
import com.velumtegra.xuimobile.core.site.SiteDeploymentStateSink
import com.velumtegra.xuimobile.core.site.SiteDesignGenerator
import com.velumtegra.xuimobile.core.site.SiteDesignRequest
import com.velumtegra.xuimobile.core.site.SiteDesignSeeds
import com.velumtegra.xuimobile.core.site.SiteExportFormat
import com.velumtegra.xuimobile.core.site.SitePreviewExportBoundary
import com.velumtegra.xuimobile.core.site.SitePreviewExportRequest
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployRequest
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightStatus
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightTrust
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportOutcome
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSshDeploymentRuntime
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_12ARealDeviceDeploymentCoordinatorAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun coordinatorEndToEndCommitBlockedCancellationAndRollback() = runBlocking {
        assertInternetPermissionDeclared()
        val port = arg(ARG_PORT)?.toIntOrNull()?.takeIf { it in 1..65535 } ?: error("invalid fixture port")
        val fingerprint = arg(ARG_FINGERPRINT)?.takeIf { it.startsWith("SHA256:") } ?: error("invalid fingerprint")
        val hostKeyHex = arg(ARG_HOST_KEY_HEX)?.takeIf { it.matches(Regex("[0-9a-f]{64}")) } ?: error("invalid host key")
        val runTag = arg(ARG_RUN_TAG)?.takeIf { it.matches(Regex("[a-f0-9]{12}")) } ?: error("invalid run tag")
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11-12a-secret-$runTag")
        val access = ServerAccess(
            id = ServerAccessId("phase11-12a-access-$runTag"),
            serverId = ServerId("phase11-12a-server-$runTag"),
            endpoint = SshEndpoint(HOST, port),
            username = USER,
            auth = SshAuthRef.Password(secretId),
            pinnedHostKey = HostKeyFingerprint(fingerprint),
        )
        val sessionCounter = AtomicInteger(0)
        val factory = JschSshConnectionFactory(secretStore) {
            SessionId("phase11-12a-session-${sessionCounter.incrementAndGet()}-$runTag")
        }
        try {
            secretStore.delete(secretId)
            val material = SecretMaterial.fromBytes(PASSWORD.toByteArray(StandardCharsets.UTF_8))
            try { assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material)) } finally { material.close() }

            runScenario(factory, access, hostKeyHex, runTag, "commit", 111120L, "/var/www/phase1112a-commit", SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT) { request, runtime, states ->
                val result = SiteDeploymentCoordinator.deploy(request, runtime, stateSink = SiteDeploymentStateSink { states += it.state })
                assertTrue(result is SiteDeploymentCoordinatorResult.Committed)
                result as SiteDeploymentCoordinatorResult.Committed
                assertEquals(SiteRemotePreflightStatus.READY, result.preflight.status)
                assertEquals(SiteRemoteTransportOutcome.COMMITTED, result.transport.outcome)
                assertTrue(result.receipt.verified)
                assertTrue(SiteDeploymentCoordinatorState.EXPORTED in states)
                assertTrue(SiteDeploymentCoordinatorState.PREFLIGHT_READY in states)
                assertTrue(SiteDeploymentCoordinatorState.AUTHORIZED in states)
                assertTrue(SiteDeploymentCoordinatorState.DEPLOYING in states)
                assertEquals(SiteDeploymentCoordinatorState.COMMITTED, states.last())
            }

            runScenario(factory, access, hostKeyHex, runTag, "blocked", 111121L, "/var/www/phase1112a-blocked", SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT) { request, runtime, states ->
                val result = SiteDeploymentCoordinator.deploy(request, runtime, stateSink = SiteDeploymentStateSink { states += it.state })
                assertTrue(result is SiteDeploymentCoordinatorResult.Blocked)
                result as SiteDeploymentCoordinatorResult.Blocked
                assertEquals(SiteRemotePreflightStatus.BLOCKED, result.preflight.status)
                assertFalse(SiteDeploymentCoordinatorState.DEPLOYING in states)
                assertEquals(SiteDeploymentCoordinatorState.PREFLIGHT_BLOCKED, states.last())
            }

            runScenario(factory, access, hostKeyHex, runTag, "cancel", 111122L, "/var/www/phase1112a-cancel", SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT) { request, runtime, states ->
                var checks = 0
                val cancellation = SiteDeploymentCancellationSignal {
                    checks += 1
                    checks >= 5
                }
                val result = SiteDeploymentCoordinator.deploy(
                    request,
                    runtime,
                    cancellation = cancellation,
                    stateSink = SiteDeploymentStateSink { states += it.state },
                )
                assertTrue(result is SiteDeploymentCoordinatorResult.Cancelled)
                result as SiteDeploymentCoordinatorResult.Cancelled
                assertEquals(SiteDeploymentCoordinatorStage.TRANSPORT, result.beforeStage)
                assertTrue(result.authorization != null)
                assertFalse(SiteDeploymentCoordinatorState.DEPLOYING in states)
                assertEquals(SiteDeploymentCoordinatorState.CANCELLED, states.last())
            }

            runScenario(factory, access, hostKeyHex, runTag, "rollback", 111123L, "/var/www/phase1112a-rollback", SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE) { request, runtime, states ->
                val result = SiteDeploymentCoordinator.deploy(request, runtime, stateSink = SiteDeploymentStateSink { states += it.state })
                assertTrue(result is SiteDeploymentCoordinatorResult.RolledBack)
                result as SiteDeploymentCoordinatorResult.RolledBack
                assertEquals(SiteRemotePreflightStatus.READY, result.preflight.status)
                assertEquals(SiteRemoteTransportOutcome.ROLLED_BACK, result.transport.outcome)
                assertTrue(result.transport.rollbackPerformed)
                assertTrue(SiteDeploymentCoordinatorState.DEPLOYING in states)
                assertEquals(SiteDeploymentCoordinatorState.ROLLED_BACK, states.last())
            }

            assertEquals(4, sessionCounter.get())
        } finally {
            secretStore.delete(secretId)
        }
    }

    private suspend fun runScenario(
        factory: JschSshConnectionFactory,
        access: ServerAccess,
        hostKeyHex: String,
        runTag: String,
        label: String,
        seed: Long,
        targetRoot: String,
        policy: SiteRemoteExistingTargetPolicy,
        block: suspend (SiteDeploymentCoordinatorRequest, SiteRemoteSshDeploymentRuntime, MutableList<SiteDeploymentCoordinatorState>) -> Unit,
    ) {
        val connected = factory.connect(access, SessionOwner.Operation(OperationId("phase11-12a-$label-$runTag"))) as? SshConnectResult.Connected
            ?: throw AssertionError("exact SSH connect failed: $label")
        val session = connected.handle as? VerifiedHostKeySshSessionHandle
            ?: throw AssertionError("verified host-key evidence missing: $label")
        assertEquals(hostKeyHex, session.verifiedHostKeySha256)
        val outputRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase1112a-$label-")
        try {
            val export = SitePreviewExportBoundary.prepare(
                SiteBuilder.build(
                    SiteBuildRequest(
                        SiteDesignGenerator.generate(
                            SiteDesignRequest(
                                seeds = SiteDesignSeeds.fromRoot(DesignSeed(seed)),
                                siteName = "Phase 11.12A $label",
                            ),
                        ),
                    ),
                ),
                SitePreviewExportRequest(
                    format = SiteExportFormat.DIRECTORY,
                    requestedBaseName = "phase1112a-$label",
                ),
            ).export
            val request = SiteDeploymentCoordinatorRequest(
                exportPlan = export,
                localOutputRoot = outputRoot,
                remoteRequest = SiteRemoteDeployRequest(
                    remoteHostIdentity = HOST,
                    targetRoot = targetRoot,
                    owner = "root",
                    group = "root",
                    existingTargetPolicy = policy,
                ),
                trust = SiteRemotePreflightTrust(hostKeyHex),
            )
            val states = mutableListOf<SiteDeploymentCoordinatorState>()
            block(request, SiteRemoteSshDeploymentRuntime(access, session), states)
        } finally {
            session.close()
            assertFalse(session.isOpen)
            deleteTree(outputRoot)
        }
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun arg(key: String): String? = InstrumentationRegistry.getArguments().getString(key)

    private companion object {
        const val HOST = "127.0.0.1"
        const val USER = "velum-phase1112a"
        const val PASSWORD = "VELUM-phase1112a-test-only-password"
        const val ARG_PORT = "phase1112a.fixturePort"
        const val ARG_FINGERPRINT = "phase1112a.fixtureFingerprint"
        const val ARG_HOST_KEY_HEX = "phase1112a.fixtureHostKeyHex"
        const val ARG_RUN_TAG = "phase1112a.runTag"
    }
}
