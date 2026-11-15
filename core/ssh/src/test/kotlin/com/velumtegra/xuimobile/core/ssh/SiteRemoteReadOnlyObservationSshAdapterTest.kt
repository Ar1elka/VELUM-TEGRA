package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.site.*
import java.nio.file.Path
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class SiteRemoteReadOnlyObservationSshAdapterTest {
    @Test
    fun `preflight observation is gathered only through finite read only commands`() = runBlocking {
        val plan = plan()
        val session = FakeSession(
            responses = ArrayDeque(listOf(
                ok("ABSENT\t0\n"),
                ok("ABSENT\t0\n"),
                ok("1048576\n"),
                ok(""),
                ok(""),
                ok("0\nroot\nroot wheel www-data\n"),
            )),
        )
        val observation = SiteRemoteReadOnlyObservationSshAdapter().collectPreflight(plan, access(), session)
        val report = SiteRemoteDeployPreflight.evaluate(plan, SiteRemotePreflightTrust(SERVER_KEY), observation)

        assertEquals(SiteRemotePreflightStatus.READY, report.status)
        assertEquals(SERVER_KEY, observation.server.serverKeySha256)
        assertTrue(session.rawCommands.all(::isReadOnlyCommand))
        assertEquals(6, session.rawCommands.size)
    }

    @Test
    fun `tree observation rebuilds canonical tree digest from exact authorized files`() = runBlocking {
        val bundle = SiteBuilder.build(SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(9090L))))))
        val entries = bundle.documents.map { SiteRemoteTransportTreeEntrySpec(it.path, it.mediaType) }
        val session = FakeSession(ArrayDeque(bundle.documents.map { ok(it.content) }))

        val observed = SiteRemoteReadOnlyObservationSshAdapter().observeTree("/var/www/site", entries, session)

        assertEquals(bundle.manifest.treeSha256, observed.treeSha256)
        assertEquals(bundle.documents.size, observed.fileCount)
        assertTrue(session.rawCommands.all { it.startsWith("cat -- '") })
    }

    @Test
    fun `certificate reuse fails closed because certificate evidence is not yet implemented`() = runBlocking {
        val base = plan(certificate = true)
        val failure = runCatching {
            SiteRemoteReadOnlyObservationSshAdapter().collectPreflight(base, access(), FakeSession(ArrayDeque()))
        }.exceptionOrNull()
        assertNotNull(failure)
        assertTrue(failure!!.message!!.contains("Certificate reuse evidence"))
    }

    private fun plan(certificate: Boolean = false): SiteRemoteDeployPlan {
        val bundle = SiteBuilder.build(SiteBuildRequest(SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(8080L))))))
        val export = SitePreviewExportBoundary.prepare(bundle, SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY)).export
        val receipt = SiteLocalExportReceipt(
            format = SiteExportFormat.DIRECTORY,
            outputName = export.manifest.outputName,
            outputPath = Path.of("/tmp/${export.manifest.outputName}"),
            fileCount = export.manifest.fileCount,
            totalBytes = export.manifest.totalBytes,
            sourceTreeSha256 = export.manifest.sourceTreeSha256,
            planSha256 = export.manifest.planSha256,
            artifactSha256 = null,
            verified = true,
        )
        return SiteRemoteDeployBoundary.prepare(
            export,
            receipt,
            SiteRemoteDeployRequest(
                remoteHostIdentity = "vps-01.example.net",
                targetRoot = "/var/www/site",
                owner = "www-data",
                group = "www-data",
                existingTargetPolicy = SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT,
                certificateReuse = if (certificate) SiteCertificateReuseRequest(
                    mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                    requestedDomain = "site.example.net",
                ) else SiteCertificateReuseRequest(),
            ),
        )
    }

    private fun access() = ServerAccess(
        id = ACCESS_ID,
        serverId = ServerId("server-1"),
        endpoint = SshEndpoint("vps-01.example.net", 22),
        username = "root",
        auth = SshAuthRef.Password(SecretId("secret-1")),
        pinnedHostKey = HostKeyFingerprint("SHA256:" + "A".repeat(43)),
    )

    private class FakeSession(
        private val responses: ArrayDeque<SshCommandResult>,
    ) : VerifiedHostKeySshSessionHandle {
        override val binding = SessionBinding(SessionId("session-1"), ACCESS_ID, SessionOwner.Operation(OperationId("op-1")))
        override val verifiedHostKeySha256: String = SERVER_KEY
        override val isOpen: Boolean = true
        val rawCommands = mutableListOf<String>()
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            rawCommands += command.rawForTransport()
            return responses.removeFirst()
        }
        override fun close() = Unit
    }

    private fun ok(text: String) = SshCommandResult(
        dispatchState = CommandDispatchState.DISPATCHED,
        completion = CommandCompletion.ConfirmedSuccess,
        stdout = CapturedOutput.of(text.encodeToByteArray(), false),
        stderr = CapturedOutput.EMPTY,
    )

    private fun isReadOnlyCommand(raw: String): Boolean {
        val lowered = raw.lowercase()
        return listOf("rm ", "mv ", "mkdir", "chmod", "chown", "scp", "sftp", "tee ", "> ").none(lowered::contains)
    }

    private companion object {
        val ACCESS_ID = ServerAccessId("access-1")
        val SERVER_KEY = "7".repeat(64)
    }
}
