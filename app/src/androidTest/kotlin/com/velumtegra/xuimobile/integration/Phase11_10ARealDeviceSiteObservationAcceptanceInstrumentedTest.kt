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
import com.velumtegra.xuimobile.core.site.SiteDesignGenerator
import com.velumtegra.xuimobile.core.site.SiteDesignRequest
import com.velumtegra.xuimobile.core.site.SiteDesignSeeds
import com.velumtegra.xuimobile.core.site.SiteExportFormat
import com.velumtegra.xuimobile.core.site.SiteLocalExportReceipt
import com.velumtegra.xuimobile.core.site.SitePreviewExportBoundary
import com.velumtegra.xuimobile.core.site.SitePreviewExportRequest
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployBoundary
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPreflight
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployRequest
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightStatus
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightTrust
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportTreeEntrySpec
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteReadOnlyObservationSshAdapter
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.nio.charset.StandardCharsets
import java.nio.file.Paths
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 11.10A acceptance proves the concrete Site read-only observation adapter on a real Android
 * device while every remote exec is witnessed by a host-only Apache MINA fixture.
 */
@RunWith(AndroidJUnit4::class)
class Phase11_10ARealDeviceSiteObservationAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun readOnlySiteObservationProducesReadyBlockedAndExactDigests() = runBlocking {
        assertInternetPermissionDeclared()
        val fixturePort = readFixturePort()
        val fixtureFingerprint = readFixtureFingerprint()
        val expectedHostKeyHex = readFixtureHostKeyHex()
        val runTag = readRunTag()

        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11-10a-secret-$runTag")
        val accessId = ServerAccessId("phase11-10a-access-$runTag")
        val access = ServerAccess(
            id = accessId,
            serverId = ServerId("phase11-10a-server-$runTag"),
            endpoint = SshEndpoint(LOOPBACK_HOST, fixturePort),
            username = FIXTURE_USERNAME,
            auth = SshAuthRef.Password(secretId),
            pinnedHostKey = HostKeyFingerprint(fixtureFingerprint),
        )
        val planAndBundle = canonicalPlanAndBundle()
        val plan = planAndBundle.first
        val bundle = planAndBundle.second
        val adapter = SiteRemoteReadOnlyObservationSshAdapter()
        val factoryCounter = AtomicInteger(0)
        val connectionFactory = JschSshConnectionFactory(secretStore) {
            SessionId("phase11-10a-session-${factoryCounter.incrementAndGet()}-$runTag")
        }

        try {
            secretStore.delete(secretId)
            val material = SecretMaterial.fromBytes(FIXTURE_PASSWORD.toByteArray(StandardCharsets.UTF_8))
            try {
                assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material))
            } finally {
                material.close()
            }

            val first = connectExact(
                connectionFactory = connectionFactory,
                access = access,
                owner = SessionOwner.Operation(OperationId("phase11-10a-ready-$runTag")),
                expectedHostKeyHex = expectedHostKeyHex,
            )
            try {
                val readyObservation = adapter.collectPreflight(plan, access, first)
                assertEquals(expectedHostKeyHex, readyObservation.server.serverKeySha256)
                val readyReport = SiteRemoteDeployPreflight.evaluate(
                    plan,
                    SiteRemotePreflightTrust(expectedHostKeyHex),
                    readyObservation,
                )
                assertEquals(SiteRemotePreflightStatus.READY, readyReport.status)
                assertTrue(readyReport.checks.all { it.passed })

                val firstDocument = bundle.documents.first()
                assertEquals(
                    firstDocument.sha256,
                    adapter.observeFileSha256("${plan.publish.targetRoot}/${firstDocument.path}", first),
                )

                val treeEntries = bundle.documents.map {
                    SiteRemoteTransportTreeEntrySpec(relativePath = it.path, mediaType = it.mediaType)
                }
                val tree = adapter.observeTree(plan.publish.targetRoot, treeEntries, first)
                assertEquals(bundle.manifest.treeSha256, tree.treeSha256)
                assertEquals(bundle.documents.size, tree.fileCount)
                assertEquals(bundle.manifest.totalBytes, tree.totalBytes)
            } finally {
                first.close()
                assertFalse(first.isOpen)
            }

            val second = connectExact(
                connectionFactory = connectionFactory,
                access = access,
                owner = SessionOwner.Operation(OperationId("phase11-10a-blocked-$runTag")),
                expectedHostKeyHex = expectedHostKeyHex,
            )
            try {
                val blockedObservation = adapter.collectPreflight(plan, access, second)
                assertEquals(expectedHostKeyHex, blockedObservation.server.serverKeySha256)
                val blockedReport = SiteRemoteDeployPreflight.evaluate(
                    plan,
                    SiteRemotePreflightTrust(expectedHostKeyHex),
                    blockedObservation,
                )
                assertEquals(SiteRemotePreflightStatus.BLOCKED, blockedReport.status)
                assertFalse(blockedReport.checks.first { it.code.name == "TARGET_STATE" }.passed)
                assertTrue(blockedReport.checks.filterNot { it.code.name == "TARGET_STATE" }.all { it.passed })
            } finally {
                second.close()
                assertFalse(second.isOpen)
            }

            assertEquals(2, factoryCounter.get())
        } finally {
            secretStore.delete(secretId)
        }
    }

    private suspend fun connectExact(
        connectionFactory: JschSshConnectionFactory,
        access: ServerAccess,
        owner: SessionOwner.Operation,
        expectedHostKeyHex: String,
    ): VerifiedHostKeySshSessionHandle {
        val connected = connectionFactory.connect(access, owner) as? SshConnectResult.Connected
            ?: throw AssertionError("Phase 11.10A exact SSH connect failed")
        val verified = connected.handle as? VerifiedHostKeySshSessionHandle
            ?: throw AssertionError("Phase 11.10A session did not expose verified host-key evidence")
        assertTrue(verified.isOpen)
        assertEquals(access.id, verified.binding.serverAccessId)
        assertEquals(owner, verified.binding.owner)
        assertEquals(expectedHostKeyHex, verified.verifiedHostKeySha256)
        return verified
    }

    private fun canonicalPlanAndBundle() = SiteBuilder.build(
        SiteBuildRequest(
            SiteDesignGenerator.generate(
                SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(SITE_SEED))),
            ),
        ),
    ).let { bundle ->
        val export = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY),
        ).export
        val receipt = SiteLocalExportReceipt(
            format = SiteExportFormat.DIRECTORY,
            outputName = export.manifest.outputName,
            outputPath = Paths.get("/tmp/${export.manifest.outputName}"),
            fileCount = export.manifest.fileCount,
            totalBytes = export.manifest.totalBytes,
            sourceTreeSha256 = export.manifest.sourceTreeSha256,
            planSha256 = export.manifest.planSha256,
            artifactSha256 = null,
            verified = true,
        )
        SiteRemoteDeployBoundary.prepare(
            export,
            receipt,
            SiteRemoteDeployRequest(
                remoteHostIdentity = LOOPBACK_HOST,
                targetRoot = TARGET_ROOT,
                owner = "root",
                group = "root",
                existingTargetPolicy = SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT,
            ),
        ) to bundle
    }

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        assertTrue(
            "Target debug app must declare android.permission.INTERNET before SSH acceptance",
            info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true,
        )
    }

    private fun readFixturePort(): Int = InstrumentationRegistry.getArguments().getString(ARG_FIXTURE_PORT)
        ?.toIntOrNull()?.takeIf { it in 1..65535 }
        ?: throw AssertionError("Runner provided invalid Phase 11.10A fixture port")

    private fun readFixtureFingerprint(): String = InstrumentationRegistry.getArguments().getString(ARG_FIXTURE_FINGERPRINT)
        ?.takeIf { it.startsWith("SHA256:") && it.length > 7 }
        ?: throw AssertionError("Runner provided invalid Phase 11.10A fingerprint")

    private fun readFixtureHostKeyHex(): String = InstrumentationRegistry.getArguments().getString(ARG_FIXTURE_HOST_KEY_HEX)
        ?.takeIf { it.matches(Regex("[0-9a-f]{64}")) }
        ?: throw AssertionError("Runner provided invalid Phase 11.10A host-key hex digest")

    private fun readRunTag(): String = InstrumentationRegistry.getArguments().getString(ARG_RUN_TAG)
        ?.takeIf { it.matches(Regex("[a-f0-9]{12}")) }
        ?: throw AssertionError("Runner provided invalid Phase 11.10A run tag")

    private companion object {
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-phase1110a"
        const val FIXTURE_PASSWORD = "VELUM-phase1110a-test-only-password"
        const val TARGET_ROOT = "/var/www/velum-phase1110a"
        const val SITE_SEED = 111010L
        const val ARG_FIXTURE_PORT = "phase1110a.fixturePort"
        const val ARG_FIXTURE_FINGERPRINT = "phase1110a.fixtureFingerprint"
        const val ARG_FIXTURE_HOST_KEY_HEX = "phase1110a.fixtureHostKeyHex"
        const val ARG_RUN_TAG = "phase1110a.runTag"
    }
}
