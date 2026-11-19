package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.JSch
import com.jcraft.jsch.KeyPair as JschKeyPair
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.time.Duration
import java.util.Arrays
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.apache.sshd.common.config.keys.KeyUtils
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Real Ed25519 public-key authentication against a loopback-only Apache MINA SSHD fixture.
 *
 * The second test forces JSch's BouncyCastle (`bc.*`) classes, which is what Android uses because its
 * `java.version` is below 15 — so the Android signing path is exercised on the JVM too.
 */
class JschEd25519LoopbackFixtureTest {
    @Test
    fun `passphrase protected ed25519 key authenticates with the default JVM provider`() = runBlocking {
        authenticateAndAssert()
    }

    @Test
    fun `ed25519 key authenticates through the bouncycastle path used on android`() = runBlocking {
        val saved = listOf("keypairgen.eddsa", "ssh-ed25519").associateWith { JSch.getConfig(it) }
        try {
            JSch.setConfig("keypairgen.eddsa", "com.jcraft.jsch.bc.KeyPairGenEdDSA")
            JSch.setConfig("ssh-ed25519", "com.jcraft.jsch.bc.SignatureEd25519")
            authenticateAndAssert()
        } finally {
            saved.forEach { (key, value) -> JSch.setConfig(key, value) }
        }
    }

    @Test
    fun `capability probe reports ed25519 available on this classpath and rejects a missing class`() {
        assertTrue(SshKeyCapabilities.ed25519UserKeys)
        assertTrue(!SshKeyCapabilities.classesPresent(listOf("org.bouncycastle.crypto.signers.Ed25519Signer", "x.Missing")))
    }

    private fun authenticateAndAssert() = runBlocking {
        Ed25519Fixture().use { fixture ->
            val result = JschSshConnectionFactory(
                StaticBytesSecretStore(KEY_SECRET_ID, fixture.client.envelope),
                detectPrivilege = false,
            ).connect(fixture.access(), fixture.owner(), TEST_CONFIG)

            assertTrue(
                "expected Connected but was $result; attempts=${fixture.publicKeyAttempts.get()} " +
                    "presented=${fixture.presentedFingerprints} expected=${fixture.client.fingerprint}",
                result is SshConnectResult.Connected,
            )
            val handle = (result as SshConnectResult.Connected).handle
            assertTrue(handle.isOpen)
            assertTrue(fixture.publicKeyAttempts.get() >= 1)
            assertTrue(fixture.presentedFingerprints.all { it == fixture.client.fingerprint })
            assertEquals(0, fixture.passwordAttempts.get())
            handle.close()
        }
    }

    private class Ed25519Fixture : AutoCloseable {
        val client = GeneratedEd25519Key("VELUM-ed25519-fixture-passphrase")
        val publicKeyAttempts = AtomicInteger(0)
        val passwordAttempts = AtomicInteger(0)
        val presentedFingerprints = CopyOnWriteArrayList<String>()
        private val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        private val server = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK_HOST
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            userAuthFactories = listOf(UserAuthPublicKeyFactory.INSTANCE, UserAuthPasswordFactory.INSTANCE)
            publickeyAuthenticator = org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator { username, key, _ ->
                publicKeyAttempts.incrementAndGet()
                val fingerprint = KeyUtils.getFingerPrint(key)
                presentedFingerprints += fingerprint
                username == FIXTURE_USERNAME && fingerprint == client.fingerprint
            }
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { _, _, _ ->
                passwordAttempts.incrementAndGet()
                true // makes any password fallback observable
            }
        }

        init {
            server.start()
            check(server.port in 1..65535)
        }

        fun access(): ServerAccess = ServerAccess(
            id = ServerAccessId("ed25519-fixture-access-${server.port}"),
            serverId = ServerId("ed25519-fixture-server"),
            endpoint = SshEndpoint(LOOPBACK_HOST, server.port),
            username = FIXTURE_USERNAME,
            auth = SshAuthRef.PrivateKey(KEY_SECRET_ID),
            pinnedHostKey = HostKeyFingerprint(KeyUtils.getFingerPrint(hostKey.public)),
        )

        fun owner(): SessionOwner.Management = SessionOwner.Management(
            installationId = XuiInstallationId("ed25519-fixture-installation"),
            serverAccessId = ServerAccessId("ed25519-fixture-access-${server.port}"),
        )

        override fun close() {
            runCatching { server.stop() }
            client.close()
        }
    }

    private class GeneratedEd25519Key(passphraseText: String) : AutoCloseable {
        private val pair = JschKeyPair.genKeyPair(JSch(), JschKeyPair.ED25519)
        /** OpenSSH-style SHA256 fingerprint of the public blob, the same format Apache's KeyUtils prints. */
        val fingerprint: String = "SHA256:" + java.util.Base64.getEncoder().withoutPadding()
            .encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(pair.publicKeyBlob))
        val encryptedPrivateKey: ByteArray
        val envelope: ByteArray

        init {
            val passphrase = passphraseText.encodeToByteArray()
            encryptedPrivateKey = ByteArrayOutputStream().use { out ->
                // Ed25519 has no legacy PEM form; JSch writes the OpenSSH v1 container (bcrypt + aes256-ctr).
                pair.writeOpenSSHv1PrivateKey(out, passphrase)
                out.toByteArray()
            }
            check(String(encryptedPrivateKey, Charsets.ISO_8859_1).startsWith("-----BEGIN OPENSSH PRIVATE KEY-----"))
            envelope = PrivateKeySecretEnvelopeCodec.encode(encryptedPrivateKey, passphrase)
            Arrays.fill(passphrase, 0)
        }

        override fun close() {
            Arrays.fill(encryptedPrivateKey, 0)
            Arrays.fill(envelope, 0)
        }
    }

    private class StaticBytesSecretStore(private val id: SecretId, bytes: ByteArray) : SecretStore {
        private val stored = bytes.copyOf()
        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            SecretCreateResult.StorageFailure("Fixture store is read-only")
        override suspend fun read(secretId: SecretId): SecretReadResult =
            if (secretId == id) SecretReadResult.Found(SecretMaterial.fromBytes(stored)) else SecretReadResult.NotFound
        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Fixture store is read-only")
        override suspend fun listIds(): SecretListResult = SecretListResult.Success(setOf(id))
    }

    private companion object {
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-ed25519-fixture"
        val KEY_SECRET_ID = SecretId("fixture-ed25519-key-secret")
        val TEST_CONFIG = SshTransportConfig(
            tcpConnectTimeout = Duration.ofSeconds(5),
            handshakeAndAuthTimeout = Duration.ofSeconds(10),
            channelOpenTimeout = Duration.ofSeconds(5),
            commandExecutionTimeout = Duration.ofSeconds(5),
            stdoutCaptureLimitBytes = 4 * 1024,
            stderrCaptureLimitBytes = 4 * 1024,
        )
    }
}
