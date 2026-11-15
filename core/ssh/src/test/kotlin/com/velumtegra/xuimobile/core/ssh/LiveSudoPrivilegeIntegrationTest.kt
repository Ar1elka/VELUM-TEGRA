package com.velumtegra.xuimobile.core.ssh

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
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Opt-in live check against a real VPS (skipped unless VELUM_LIVE_SUDO_HOST is set). Exercises the
 * production factory as a normal user with sudo, the way Yandex Cloud / AWS images are set up.
 *
 * VELUM_LIVE_SUDO_HOST, VELUM_LIVE_SUDO_PIN (SHA256:...), VELUM_LIVE_SUDO_KEY_USER + VELUM_LIVE_SUDO_KEY_FILE,
 * optional VELUM_LIVE_SUDO_PW_USER + VELUM_LIVE_SUDO_PW_FILE.
 */
class LiveSudoPrivilegeIntegrationTest {
    private val host = System.getenv("VELUM_LIVE_SUDO_HOST")
    private val pin = System.getenv("VELUM_LIVE_SUDO_PIN")

    @Test fun `key user with passwordless sudo runs commands and site files as root`() = runBlocking {
        assumeTrue(host != null && pin != null && System.getenv("VELUM_LIVE_SUDO_KEY_FILE") != null)
        val key = File(System.getenv("VELUM_LIVE_SUDO_KEY_FILE")).readBytes()
        val handle = connect(System.getenv("VELUM_LIVE_SUDO_KEY_USER"), SshAuthRef.PrivateKey(SECRET), PrivateKeySecretEnvelopeCodec.encode(key))
        handle.use { session ->
            assertEquals(RemotePrivilegeMode.SUDO_NOPASSWD, (session as PrivilegeAwareSshSessionHandle).privilegeMode)
            exerciseAsRoot(session)
        }
    }

    @Test fun `password user whose sudo asks for the login password`() = runBlocking {
        assumeTrue(host != null && pin != null && System.getenv("VELUM_LIVE_SUDO_PW_FILE") != null)
        val password = File(System.getenv("VELUM_LIVE_SUDO_PW_FILE")).readText().trim().encodeToByteArray()
        val handle = connect(System.getenv("VELUM_LIVE_SUDO_PW_USER"), SshAuthRef.Password(SECRET), password)
        handle.use { session ->
            assertEquals(RemotePrivilegeMode.SUDO_PASSWORD, (session as PrivilegeAwareSshSessionHandle).privilegeMode)
            exerciseAsRoot(session)
        }
    }

    private suspend fun exerciseAsRoot(session: SshSessionHandle) {
        // Multi-line command with quotes, $vars and an exit code: must arrive byte-exact and run as root.
        val probe = session.execute(RemoteCommand.create("set -u\nx='it'\"'\"'s'; printf '%s|%s\\n' \"\$(id -u)\" \"\$x\"\nexit 0", "live-sudo-probe"))
        assertEquals(CommandCompletion.ConfirmedSuccess, probe.completion)
        assertEquals("0|it's\n", probe.stdout.copyBytes().decodeToString())
        val failing = session.execute(RemoteCommand.create("exit 7", "live-sudo-exit"))
        assertEquals(7, (failing.completion as CommandCompletion.ConfirmedFailure).exitCode)

        // Site file channel: must write where only root can (a root-owned 0700 directory).
        val base = "/root/velum-sudo-selftest-" + System.nanoTime()
        val channel = (session as SiteRemoteSftpCapableSessionHandle).openSiteRemoteSftpChannel()
        try {
            channel.mkdir(base)
            val payload = "hello\nwith 'quotes' and \u0000 byte".encodeToByteArray()
            channel.writeFile("$base/a.txt", payload)
            val stat = channel.lstat("$base/a.txt")
            assertEquals(com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.FILE, stat.type)
            assertEquals(payload.size.toLong(), stat.sizeBytes)
            assertEquals(0, stat.uid)
            channel.chmod("$base/a.txt", "640".toInt(8))
            assertEquals("640".toInt(8), channel.lstat("$base/a.txt").permissions)
            assertArrayEquals(payload, channel.readFile("$base/a.txt", 1024))
            channel.rename("$base/a.txt", "$base/b.txt")
            channel.writeFile("$base/c.txt", byteArrayOf(1))
            val renameOver = runCatching { channel.rename("$base/c.txt", "$base/b.txt") }
            assertTrue("rename must not replace an existing file", renameOver.isFailure)
            assertEquals(setOf("b.txt", "c.txt"), channel.listDirectory(base, 10).map { it.name }.toSet())
            assertEquals(
                com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.ABSENT,
                channel.lstat("$base/a.txt").type,
            )
            channel.removeFile("$base/b.txt")
            channel.removeFile("$base/c.txt")
            channel.removeDirectory(base)
            assertEquals(com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.ABSENT, channel.lstat(base).type)
        } finally {
            channel.close()
        }
    }

    private suspend fun connect(user: String, auth: SshAuthRef, secret: ByteArray): SshSessionHandle {
        val access = ServerAccess(
            id = ServerAccessId("live-sudo-$user"),
            serverId = ServerId("live-sudo"),
            endpoint = SshEndpoint(host, 22),
            username = user,
            auth = auth,
            pinnedHostKey = HostKeyFingerprint(pin),
        )
        val result = JschSshConnectionFactory(OneSecret(secret)).connect(access, SessionOwner.Operation(OperationId("live-sudo")))
        check(result is SshConnectResult.Connected) { "Live SSH connection failed: $result" }
        return result.handle
    }

    private class OneSecret(private val bytes: ByteArray) : SecretStore {
        override suspend fun create(secretId: SecretId, material: SecretMaterial) = SecretCreateResult.StorageFailure("read-only")
        override suspend fun read(secretId: SecretId): SecretReadResult =
            if (secretId == SECRET) SecretReadResult.Found(SecretMaterial.fromBytes(bytes.copyOf())) else SecretReadResult.NotFound
        override suspend fun delete(secretId: SecretId) = SecretDeleteResult.StorageFailure("read-only")
        override suspend fun listIds(): SecretListResult = SecretListResult.Success(setOf(SECRET))
    }

    private companion object {
        val SECRET = SecretId("live-sudo-secret")
    }
}
