package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
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
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPlan
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
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportAuthorization
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportBoundary
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportExecutor
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportOutcome
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportSource
import java.nio.file.Path
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteRemoteSftpPrimitiveAdapterTest {
    @Test
    fun `bounded SFTP primitive commits exact authorized tree and uses only read only identity exec`() = runBlocking {
        val fixture = fixture(11110L)
        val channel = FakeSftpChannel()
        val session = FakeSftpSession(channel)
        val port = SiteRemoteSftpPrimitiveFactory().open(fixture.authorization, fixture.access, session)
        val result = port.use {
            SiteRemoteTransportExecutor(it).execute(fixture.authorization, fixture.source)
        }

        assertEquals(SiteRemoteTransportOutcome.COMMITTED, result.outcome)
        assertEquals(fixture.plan.fileCount, result.uploadedFileCount)
        assertEquals(fixture.plan.totalBytes, result.uploadedBytes)
        assertEquals(fixture.plan.sourceTreeSha256, result.publishedTreeSha256)
        assertFalse(channel.exists(fixture.plan.publish.stagingRoot))
        assertTrue(channel.exists(fixture.plan.publish.targetRoot))
        fixture.plan.entries.forEach { entry ->
            assertEquals(entry.byteSize.toLong(), channel.fileSize("${fixture.plan.publish.targetRoot}/${entry.path}"))
        }
        assertEquals(
            listOf("getent passwd 'root'", "getent group 'root'"),
            session.rawCommands,
        )
        assertTrue(session.rawCommands.none(::isMutationExec))
    }

    @Test
    fun `protocol dot entries are ignored during exact tree verification`() = runBlocking {
        val fixture = fixture(11116L)
        val channel = FakeSftpChannel(includeProtocolDotEntries = true)
        val port = SiteRemoteSftpPrimitiveFactory().open(fixture.authorization, fixture.access, FakeSftpSession(channel))
        val result = port.use {
            SiteRemoteTransportExecutor(it).execute(fixture.authorization, fixture.source)
        }

        assertEquals(SiteRemoteTransportOutcome.COMMITTED, result.outcome)
        assertTrue(channel.exists(fixture.plan.publish.targetRoot))
        assertFalse(channel.exists(fixture.plan.publish.stagingRoot))
    }

    @Test
    fun `primitive rejects arbitrary path and refuses cleanup before transaction ownership`() = runBlocking {
        val fixture = fixture(11111L)
        val channel = FakeSftpChannel()
        val port = SiteRemoteSftpPrimitiveFactory().open(fixture.authorization, fixture.access, FakeSftpSession(channel))
        port.use {
            assertNotNull(runCatching { it.uploadFile("/tmp/escape.txt", byteArrayOf(1)) }.exceptionOrNull())
            assertNotNull(runCatching { it.removeTransactionTree(fixture.plan.publish.targetRoot) }.exceptionOrNull())
        }
    }

    @Test
    fun `unexpected file in staging fails exact tree verification and rolls back owned staging`() = runBlocking {
        val fixture = fixture(11112L)
        val channel = FakeSftpChannel(injectExtraFileOnFirstStagingList = true)
        val port = SiteRemoteSftpPrimitiveFactory().open(fixture.authorization, fixture.access, FakeSftpSession(channel))
        val result = port.use {
            SiteRemoteTransportExecutor(it).execute(fixture.authorization, fixture.source)
        }

        assertEquals(SiteRemoteTransportOutcome.ROLLED_BACK, result.outcome)
        assertTrue(result.rollbackPerformed)
        assertFalse(channel.exists(fixture.plan.publish.stagingRoot))
        assertFalse(channel.exists(fixture.plan.publish.targetRoot))
    }

    @Test
    fun `rename applied remotely then failed locally is reconciled and rolled back without deleting foreign tree`() = runBlocking {
        val fixture = fixture(11113L)
        val channel = FakeSftpChannel(failAfterPublishRename = true)
        val port = SiteRemoteSftpPrimitiveFactory().open(fixture.authorization, fixture.access, FakeSftpSession(channel))
        val result = port.use {
            SiteRemoteTransportExecutor(it).execute(fixture.authorization, fixture.source)
        }

        assertEquals(SiteRemoteTransportOutcome.ROLLED_BACK, result.outcome)
        assertFalse(channel.exists(fixture.plan.publish.stagingRoot))
        assertFalse(channel.exists(fixture.plan.publish.targetRoot))
    }


    @Test
    fun `backup replace restores original target after publish response is lost`() = runBlocking {
        val fixture = fixture(11115L, SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE)
        val channel = FakeSftpChannel(failAfterPublishRename = true, seedExistingTarget = true)
        val port = SiteRemoteSftpPrimitiveFactory().open(fixture.authorization, fixture.access, FakeSftpSession(channel))
        val result = port.use {
            SiteRemoteTransportExecutor(it).execute(fixture.authorization, fixture.source)
        }

        assertEquals(SiteRemoteTransportOutcome.ROLLED_BACK, result.outcome)
        assertTrue(channel.exists(fixture.plan.publish.targetRoot))
        assertEquals("original", channel.fileText("${fixture.plan.publish.targetRoot}/original.txt"))
        assertFalse(channel.exists(requireNotNull(fixture.plan.publish.backupRoot)))
        assertFalse(channel.exists(fixture.plan.publish.stagingRoot))
    }

    @Test
    fun `symlink in mutable root ancestry fails closed before any mutation`() = runBlocking {
        val fixture = fixture(11114L)
        val channel = FakeSftpChannel(symlinkVarWww = true)
        val failure = runCatching {
            SiteRemoteSftpPrimitiveFactory().open(fixture.authorization, fixture.access, FakeSftpSession(channel))
        }.exceptionOrNull()

        assertNotNull(failure)
        assertEquals(0, channel.mutationCount)
    }

    private fun fixture(seed: Long, policy: SiteRemoteExistingTargetPolicy = SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT): Fixture {
        val bundle = SiteBuilder.build(
            SiteBuildRequest(
                SiteDesignGenerator.generate(
                    SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(seed))),
                ),
            ),
        )
        val export = SitePreviewExportBoundary.prepare(
            bundle,
            SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY),
        ).export
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
        val plan = SiteRemoteDeployBoundary.prepare(
            export,
            receipt,
            SiteRemoteDeployRequest(
                remoteHostIdentity = HOST,
                targetRoot = "/var/www/site",
                owner = "root",
                group = "root",
                existingTargetPolicy = policy,
            ),
        )
        val observation = SiteRemotePreflightObservation(
            server = SiteRemoteServerObservation(HOST, SERVER_KEY_HEX),
            target = SiteRemoteObservedPath(
                plan.publish.targetRoot,
                if (policy == SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT) SiteRemoteObservedPathType.ABSENT else SiteRemoteObservedPathType.DIRECTORY,
                0,
            ),
            staging = SiteRemoteObservedPath(plan.publish.stagingRoot, SiteRemoteObservedPathType.ABSENT, 0),
            backup = plan.publish.backupRoot?.let { SiteRemoteObservedPath(it, SiteRemoteObservedPathType.ABSENT, 0) },
            availableBytes = 64L * 1024 * 1024,
            ownership = SiteRemoteOwnershipObservation(
                ownerExists = true,
                groupExists = true,
                ownershipChangeApplicable = true,
                modeChangeApplicable = true,
            ),
            certificate = null,
        )
        val preflight = SiteRemoteDeployPreflight.evaluate(plan, SiteRemotePreflightTrust(SERVER_KEY_HEX), observation)
        assertEquals(SiteRemotePreflightStatus.READY, preflight.status)
        val authorization = SiteRemoteTransportBoundary.authorize(
            plan,
            preflight,
            SiteRemoteSftpPrimitiveFactory.CAPABILITIES,
        )
        val sourceBytes = export.entries.associate { it.path to it.content.encodeToByteArray() }
        return Fixture(
            plan = plan,
            authorization = authorization,
            access = access(),
            source = SiteRemoteTransportSource { path -> requireNotNull(sourceBytes[path]).copyOf() },
        )
    }

    private fun access() = ServerAccess(
        id = ACCESS_ID,
        serverId = ServerId("server-1"),
        endpoint = SshEndpoint(HOST, 22),
        username = "root",
        auth = SshAuthRef.Password(SecretId("secret-1")),
        pinnedHostKey = HostKeyFingerprint(SERVER_KEY_MODEL),
    )

    private data class Fixture(
        val plan: SiteRemoteDeployPlan,
        val authorization: SiteRemoteTransportAuthorization,
        val access: ServerAccess,
        val source: SiteRemoteTransportSource,
    )

    private class FakeSftpSession(
        private val channel: FakeSftpChannel,
    ) : SiteRemoteSftpCapableSessionHandle {
        override val binding = SessionBinding(SessionId("session-1"), ACCESS_ID, SessionOwner.Operation(OperationId("op-1")))
        override val verifiedHostKeySha256: String = SERVER_KEY_HEX
        override val isOpen: Boolean = true
        val rawCommands = mutableListOf<String>()

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            val raw = command.rawForTransport()
            rawCommands += raw
            val text = when (raw) {
                "getent passwd 'root'" -> "root:x:0:0:root:/root:/bin/sh\n"
                "getent group 'root'" -> "root:x:0:\n"
                else -> error("Unexpected exec in SFTP factory: $raw")
            }
            return SshCommandResult(
                dispatchState = CommandDispatchState.DISPATCHED,
                completion = CommandCompletion.ConfirmedSuccess,
                stdout = CapturedOutput.of(text.encodeToByteArray(), false),
                stderr = CapturedOutput.EMPTY,
            )
        }

        override fun openSiteRemoteSftpChannel(channelOpenTimeout: java.time.Duration): SiteRemoteSftpChannelHandle = channel
        override fun close() = Unit
    }

    private class FakeSftpChannel(
        private val injectExtraFileOnFirstStagingList: Boolean = false,
        private val failAfterPublishRename: Boolean = false,
        private val includeProtocolDotEntries: Boolean = false,
        symlinkVarWww: Boolean = false,
        seedExistingTarget: Boolean = false,
    ) : SiteRemoteSftpChannelHandle {
        private data class Node(
            var type: SiteRemoteObservedPathType,
            var bytes: ByteArray = ByteArray(0),
            var uid: Int = 0,
            var gid: Int = 0,
            var permissions: Int = 448,
        )

        private val nodes = linkedMapOf(
            "/" to Node(SiteRemoteObservedPathType.DIRECTORY),
            "/var" to Node(SiteRemoteObservedPathType.DIRECTORY),
            "/var/www" to Node(if (symlinkVarWww) SiteRemoteObservedPathType.SYMLINK else SiteRemoteObservedPathType.DIRECTORY),
        ).apply {
            if (seedExistingTarget && !symlinkVarWww) {
                put("/var/www/site", Node(SiteRemoteObservedPathType.DIRECTORY, permissions = 493))
                put("/var/www/site/original.txt", Node(SiteRemoteObservedPathType.FILE, "original".encodeToByteArray(), permissions = 420))
            }
        }
        private var open = true
        private var injected = false
        var mutationCount: Int = 0
            private set

        override val isOpen: Boolean get() = open

        override fun lstat(path: String): SiteRemoteSftpPathObservation = nodes[path]?.let(::observe)
            ?: SiteRemoteSftpPathObservation(SiteRemoteObservedPathType.ABSENT, 0, -1, -1, 0)

        override fun mkdir(path: String) {
            mutationCount++
            require(path !in nodes)
            require(nodes[parent(path)]?.type == SiteRemoteObservedPathType.DIRECTORY)
            nodes[path] = Node(SiteRemoteObservedPathType.DIRECTORY)
        }

        override fun writeFile(path: String, payload: ByteArray) {
            mutationCount++
            require(nodes[parent(path)]?.type == SiteRemoteObservedPathType.DIRECTORY)
            nodes[path] = Node(SiteRemoteObservedPathType.FILE, payload.copyOf(), permissions = 384)
        }

        override fun readFile(path: String, maxBytes: Int): ByteArray {
            val node = requireNotNull(nodes[path])
            require(node.type == SiteRemoteObservedPathType.FILE)
            require(node.bytes.size <= maxBytes)
            return node.bytes.copyOf()
        }

        override fun listDirectory(path: String, maxEntries: Int): List<SiteRemoteSftpDirectoryEntry> {
            if (injectExtraFileOnFirstStagingList && !injected && path.contains(".velum-stage-")) {
                injected = true
                nodes["$path/evil.txt"] = Node(SiteRemoteObservedPathType.FILE, "evil".encodeToByteArray())
            }
            require(nodes[path]?.type == SiteRemoteObservedPathType.DIRECTORY)
            val result = buildList {
                if (includeProtocolDotEntries) {
                    add(SiteRemoteSftpDirectoryEntry(".", requireNotNull(nodes[path]).let(::observe)))
                    add(SiteRemoteSftpDirectoryEntry("..", requireNotNull(nodes[parent(path)]).let(::observe)))
                }
                addAll(
                    nodes.entries
                        .filter { (candidate, _) -> candidate != path && parent(candidate) == path }
                        .map { (candidate, node) -> SiteRemoteSftpDirectoryEntry(candidate.substringAfterLast('/'), observe(node)) },
                )
            }
            require(result.size <= maxEntries) { "synthetic list overflow" }
            return result
        }

        override fun chmod(path: String, permissions: Int) {
            mutationCount++
            requireNotNull(nodes[path]).permissions = permissions
        }

        override fun chown(path: String, uid: Int) {
            mutationCount++
            requireNotNull(nodes[path]).uid = uid
        }

        override fun chgrp(path: String, gid: Int) {
            mutationCount++
            requireNotNull(nodes[path]).gid = gid
        }

        override fun rename(fromPath: String, toPath: String) {
            mutationCount++
            require(fromPath in nodes && toPath !in nodes)
            val moving = nodes.keys.filter { it == fromPath || it.startsWith("$fromPath/") }.sortedBy { it.length }
            moving.forEach { old ->
                val node = requireNotNull(nodes.remove(old))
                val suffix = old.removePrefix(fromPath)
                nodes[toPath + suffix] = node
            }
            if (failAfterPublishRename && fromPath.contains(".velum-stage-") && toPath == "/var/www/site") {
                throw IllegalStateException("synthetic lost response after applied rename")
            }
        }

        override fun removeFile(path: String) {
            mutationCount++
            val node = requireNotNull(nodes[path])
            require(node.type == SiteRemoteObservedPathType.FILE || node.type == SiteRemoteObservedPathType.SYMLINK)
            nodes.remove(path)
        }

        override fun removeDirectory(path: String) {
            mutationCount++
            require(nodes[path]?.type == SiteRemoteObservedPathType.DIRECTORY)
            require(nodes.keys.none { it != path && parent(it) == path })
            nodes.remove(path)
        }

        override fun close() { open = false }

        fun exists(path: String): Boolean = path in nodes
        fun fileSize(path: String): Long = requireNotNull(nodes[path]).bytes.size.toLong()
        fun fileText(path: String): String = requireNotNull(nodes[path]).bytes.decodeToString()

        private fun observe(node: Node) = SiteRemoteSftpPathObservation(
            node.type,
            if (node.type == SiteRemoteObservedPathType.FILE) node.bytes.size.toLong() else 0,
            node.uid,
            node.gid,
            node.permissions,
        )

        private fun parent(path: String): String = path.substringBeforeLast('/').ifBlank { "/" }
    }

    private fun isMutationExec(raw: String): Boolean {
        val lower = raw.lowercase()
        return listOf("mkdir", "rm ", "mv ", "chmod", "chown", "chgrp", "tee ", ">", "scp", "sftp").any(lower::contains)
    }

    private companion object {
        const val HOST = "vps-01.example.net"
        val ACCESS_ID = ServerAccessId("access-1")
        val SERVER_KEY_DIGEST = ByteArray(32) { 0x11 }
        val SERVER_KEY_HEX = SERVER_KEY_DIGEST.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val SERVER_KEY_MODEL = "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(SERVER_KEY_DIGEST)
    }
}
