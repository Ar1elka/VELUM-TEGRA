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
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPath
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import com.velumtegra.xuimobile.core.site.SiteRemoteOwnershipObservation
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightObservation
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightStatus
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightTrust
import com.velumtegra.xuimobile.core.site.SiteRemoteServerObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportBoundary
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportExecutor
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportOutcome
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportSource
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpPrimitiveFactory
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.nio.charset.StandardCharsets
import java.nio.file.Paths
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_11ARealDeviceBoundedSftpAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun boundedSftpCommitRollbackUnexpectedEntryAndConfinement() = runBlocking {
        assertInternetPermissionDeclared()
        val port = arg(ARG_PORT)?.toIntOrNull()?.takeIf { it in 1..65535 } ?: error("invalid fixture port")
        val fingerprint = arg(ARG_FINGERPRINT)?.takeIf { it.startsWith("SHA256:") } ?: error("invalid fingerprint")
        val hostKeyHex = arg(ARG_HOST_KEY_HEX)?.takeIf { it.matches(Regex("[0-9a-f]{64}")) } ?: error("invalid host key")
        val runTag = arg(ARG_RUN_TAG)?.takeIf { it.matches(Regex("[a-f0-9]{12}")) } ?: error("invalid run tag")
        val secretStore = AndroidKeystoreSecretStore(context)
        val secretId = SecretId("phase11-11a-secret-$runTag")
        val access = ServerAccess(
            id = ServerAccessId("phase11-11a-access-$runTag"),
            serverId = ServerId("phase11-11a-server-$runTag"),
            endpoint = SshEndpoint(HOST, port),
            username = USER,
            auth = SshAuthRef.Password(secretId),
            pinnedHostKey = HostKeyFingerprint(fingerprint),
        )
        val sessionCounter = AtomicInteger(0)
        val factory = JschSshConnectionFactory(secretStore) {
            SessionId("phase11-11a-session-${sessionCounter.incrementAndGet()}-$runTag")
        }
        try {
            secretStore.delete(secretId)
            val material = SecretMaterial.fromBytes(PASSWORD.toByteArray(StandardCharsets.UTF_8))
            try { assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material)) } finally { material.close() }

            val commit = prepared("/var/www/phase1111a-commit", SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT, false, 111110L, hostKeyHex, access)
            withSession(factory, access, hostKeyHex, "commit-$runTag") { session ->
                val primitive = SiteRemoteSftpPrimitiveFactory().open(commit.authorization, access, session)
                try {
                    assertNotNull(runCatching { primitive.statPath("/etc/passwd") }.exceptionOrNull())
                    assertNotNull(runCatching { primitive.uploadFile("/escape.txt", byteArrayOf(1)) }.exceptionOrNull())
                    val result = SiteRemoteTransportExecutor(primitive).execute(commit.authorization, commit.source)
                    assertEquals(SiteRemoteTransportOutcome.COMMITTED, result.outcome)
                    assertEquals(commit.fileCount, result.uploadedFileCount)
                    assertEquals(commit.totalBytes, result.uploadedBytes)
                    assertEquals(commit.treeSha256, result.publishedTreeSha256)
                } finally { (primitive as AutoCloseable).close() }
            }

            val rollback = prepared("/var/www/phase1111a-rollback", SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE, true, 111111L, hostKeyHex, access)
            withSession(factory, access, hostKeyHex, "rollback-$runTag") { session ->
                val primitive = SiteRemoteSftpPrimitiveFactory().open(rollback.authorization, access, session)
                try {
                    val result = SiteRemoteTransportExecutor(primitive).execute(rollback.authorization, rollback.source)
                    assertEquals(SiteRemoteTransportOutcome.ROLLED_BACK, result.outcome)
                    assertTrue(result.rollbackPerformed)
                } finally { (primitive as AutoCloseable).close() }
            }

            val extra = prepared("/var/www/phase1111a-extra", SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT, false, 111112L, hostKeyHex, access)
            withSession(factory, access, hostKeyHex, "extra-$runTag") { session ->
                val primitive = SiteRemoteSftpPrimitiveFactory().open(extra.authorization, access, session)
                try {
                    val result = SiteRemoteTransportExecutor(primitive).execute(extra.authorization, extra.source)
                    assertEquals(SiteRemoteTransportOutcome.ROLLED_BACK, result.outcome)
                    assertTrue(result.rollbackPerformed)
                } finally { (primitive as AutoCloseable).close() }
            }

            val symlink = prepared("/symlink-root/phase1111a-symlink", SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT, false, 111113L, hostKeyHex, access)
            withSession(factory, access, hostKeyHex, "symlink-$runTag") { session ->
                val failure = runCatching { SiteRemoteSftpPrimitiveFactory().open(symlink.authorization, access, session) }.exceptionOrNull()
                assertNotNull("symlink ancestry must fail closed before transport mutation", failure)
            }
            assertEquals(4, sessionCounter.get())
        } finally {
            secretStore.delete(secretId)
        }
    }

    private suspend fun withSession(
        factory: JschSshConnectionFactory,
        access: ServerAccess,
        hostKeyHex: String,
        label: String,
        block: suspend (VerifiedHostKeySshSessionHandle) -> Unit,
    ) {
        val connected = factory.connect(access, SessionOwner.Operation(OperationId("phase11-11a-$label"))) as? SshConnectResult.Connected
            ?: throw AssertionError("exact SSH connect failed: $label")
        val session = connected.handle as? VerifiedHostKeySshSessionHandle
            ?: throw AssertionError("verified host-key evidence missing: $label")
        assertEquals(hostKeyHex, session.verifiedHostKeySha256)
        try { block(session) } finally { session.close(); assertFalse(session.isOpen) }
    }

    private fun prepared(
        targetRoot: String,
        policy: SiteRemoteExistingTargetPolicy,
        targetExists: Boolean,
        seed: Long,
        hostKeyHex: String,
        access: ServerAccess,
    ): Prepared {
        val bundle = SiteBuilder.build(SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(seed))))))
        val export = SitePreviewExportBoundary.prepare(bundle, SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY)).export
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
        val plan = SiteRemoteDeployBoundary.prepare(
            export,
            receipt,
            SiteRemoteDeployRequest(
                remoteHostIdentity = HOST,
                targetRoot = targetRoot,
                owner = "root",
                group = "root",
                existingTargetPolicy = policy,
            ),
        )
        val observation = SiteRemotePreflightObservation(
            server = SiteRemoteServerObservation(HOST, hostKeyHex),
            target = SiteRemoteObservedPath(plan.publish.targetRoot, if (targetExists) SiteRemoteObservedPathType.DIRECTORY else SiteRemoteObservedPathType.ABSENT, 0),
            staging = SiteRemoteObservedPath(plan.publish.stagingRoot, SiteRemoteObservedPathType.ABSENT, 0),
            backup = plan.publish.backupRoot?.let { SiteRemoteObservedPath(it, SiteRemoteObservedPathType.ABSENT, 0) },
            availableBytes = 64L * 1024 * 1024,
            ownership = SiteRemoteOwnershipObservation(true, true, true, true),
            certificate = null,
        )
        val preflight = SiteRemoteDeployPreflight.evaluate(plan, SiteRemotePreflightTrust(hostKeyHex), observation)
        assertEquals(SiteRemotePreflightStatus.READY, preflight.status)
        val auth = SiteRemoteTransportBoundary.authorize(plan, preflight, SiteRemoteSftpPrimitiveFactory.CAPABILITIES)
        val bytes = export.entries.associate { it.path to it.content.encodeToByteArray() }
        return Prepared(auth, SiteRemoteTransportSource { path -> requireNotNull(bytes[path]).copyOf() }, export.manifest.fileCount, export.manifest.totalBytes, export.manifest.sourceTreeSha256)
    }

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        assertTrue(info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true)
    }

    private fun arg(key: String): String? = InstrumentationRegistry.getArguments().getString(key)

    private data class Prepared(
        val authorization: com.velumtegra.xuimobile.core.site.SiteRemoteTransportAuthorization,
        val source: SiteRemoteTransportSource,
        val fileCount: Int,
        val totalBytes: Long,
        val treeSha256: String,
    )

    private companion object {
        const val HOST = "127.0.0.1"
        const val USER = "velum-phase1111a"
        const val PASSWORD = "VELUM-phase1111a-test-only-password"
        const val ARG_PORT = "phase1111a.fixturePort"
        const val ARG_FINGERPRINT = "phase1111a.fixtureFingerprint"
        const val ARG_HOST_KEY_HEX = "phase1111a.fixtureHostKeyHex"
        const val ARG_RUN_TAG = "phase1111a.runTag"
    }
}
