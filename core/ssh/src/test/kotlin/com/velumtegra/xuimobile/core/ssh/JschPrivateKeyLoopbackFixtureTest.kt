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
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Real SSH public-key authentication against a loopback-only Apache MINA SSHD fixture. */
class JschPrivateKeyLoopbackFixtureTest {
    @Test
    fun `exact encrypted private key and passphrase authenticate with no password fallback`() = runBlocking {
        PrivateKeySshFixture().use { fixture ->
            val result = JschSshConnectionFactory(
                StaticBytesSecretStore(PRIVATE_KEY_SECRET_ID, fixture.accepted.envelope),
                detectPrivilege = false,
            ).connect(fixture.access(fixture.hostFingerprint), fixture.owner(), TEST_CONFIG)

            assertTrue(result is SshConnectResult.Connected)
            val handle = (result as SshConnectResult.Connected).handle
            assertTrue(handle.isOpen)
            assertTrue(fixture.publicKeyAttempts.get() >= 1)
            assertTrue(fixture.presentedPublicKeyFingerprints.all { it == fixture.accepted.publicKeyFingerprint })
            assertEquals(0, fixture.passwordAttempts.get())
            handle.close()
            assertFalse(handle.isOpen)
        }
    }

    @Test
    fun `wrong private key is authentication rejected and never falls back to password`() = runBlocking {
        PrivateKeySshFixture().use { fixture ->
            GeneratedClientKey("wrong-key-passphrase").use { wrong ->
                val result = JschSshConnectionFactory(
                    StaticBytesSecretStore(PRIVATE_KEY_SECRET_ID, wrong.envelope),
                    detectPrivilege = false,
                ).connect(fixture.access(fixture.hostFingerprint), fixture.owner(), TEST_CONFIG)

                assertTrue(result is SshConnectResult.Failed)
                assertEquals(SshConnectFailure.AuthenticationRejected, (result as SshConnectResult.Failed).failure)
                assertTrue(fixture.publicKeyAttempts.get() >= 1)
                assertTrue(fixture.presentedPublicKeyFingerprints.all { it == wrong.publicKeyFingerprint })
                assertEquals(0, fixture.passwordAttempts.get())
            }
        }
    }

    @Test
    fun `wrong host pin blocks private key authentication before credential proof`() = runBlocking {
        PrivateKeySshFixture().use { fixture ->
            val wrongPin = CanonicalHostKeyFingerprint
                .fromRawHostKey("wrong-host-key".encodeToByteArray())
                .asString()
            val result = JschSshConnectionFactory(
                StaticBytesSecretStore(PRIVATE_KEY_SECRET_ID, fixture.accepted.envelope),
                detectPrivilege = false,
            ).connect(fixture.access(wrongPin), fixture.owner(), TEST_CONFIG)

            assertTrue(result is SshConnectResult.Failed)
            assertTrue((result as SshConnectResult.Failed).failure is SshConnectFailure.HostIdentityMismatch)
            assertEquals(0, fixture.publicKeyAttempts.get())
            assertEquals(0, fixture.passwordAttempts.get())
        }
    }

    @Test
    fun `wrong private key passphrase fails locally before any server auth attempt`() = runBlocking {
        PrivateKeySshFixture().use { fixture ->
            val wrongPassphraseEnvelope = PrivateKeySecretEnvelopeCodec.encode(
                fixture.accepted.encryptedPrivateKey,
                "definitely-wrong-passphrase".encodeToByteArray(),
            )
            try {
                val result = JschSshConnectionFactory(
                    StaticBytesSecretStore(PRIVATE_KEY_SECRET_ID, wrongPassphraseEnvelope),
                    detectPrivilege = false,
                ).connect(fixture.access(fixture.hostFingerprint), fixture.owner(), TEST_CONFIG)

                assertTrue(result is SshConnectResult.Failed)
                assertTrue((result as SshConnectResult.Failed).failure is SshConnectFailure.SecretCorrupt)
                assertEquals(0, fixture.publicKeyAttempts.get())
                assertEquals(0, fixture.passwordAttempts.get())
            } finally {
                Arrays.fill(wrongPassphraseEnvelope, 0)
            }
        }
    }

    @Test
    fun `malformed private key envelope fails closed before network authentication`() = runBlocking {
        PrivateKeySshFixture().use { fixture ->
            val result = JschSshConnectionFactory(
                StaticBytesSecretStore(PRIVATE_KEY_SECRET_ID, "malformed-key-secret".encodeToByteArray()),
                detectPrivilege = false,
            ).connect(fixture.access(fixture.hostFingerprint), fixture.owner(), TEST_CONFIG)

            assertTrue(result is SshConnectResult.Failed)
            assertTrue((result as SshConnectResult.Failed).failure is SshConnectFailure.SecretCorrupt)
            assertEquals(0, fixture.publicKeyAttempts.get())
            assertEquals(0, fixture.passwordAttempts.get())
        }
    }

    private class PrivateKeySshFixture : AutoCloseable {
        val accepted = GeneratedClientKey("VELUM-fixture-key-passphrase")
        val publicKeyAttempts = AtomicInteger(0)
        val passwordAttempts = AtomicInteger(0)
        val presentedPublicKeyFingerprints = CopyOnWriteArrayList<String>()

        private val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        private val server = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK_HOST
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            userAuthFactories = listOf(UserAuthPublicKeyFactory.INSTANCE, UserAuthPasswordFactory.INSTANCE)
            publickeyAuthenticator = org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator { username, key, _ ->
                publicKeyAttempts.incrementAndGet()
                presentedPublicKeyFingerprints += KeyUtils.getFingerPrint(key)
                username == FIXTURE_USERNAME && accepted.publicKey.encoded.contentEquals(key.encoded)
            }
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { _, _, _ ->
                passwordAttempts.incrementAndGet()
                true // If the client ever falls back to password, this makes the regression observable.
            }
        }

        val hostFingerprint: String

        init {
            hostFingerprint = KeyUtils.getFingerPrint(hostKey.public)
            server.start()
            check(server.port in 1..65535)
        }

        fun access(pin: String): ServerAccess = ServerAccess(
            id = ServerAccessId("private-key-fixture-access-${server.port}"),
            serverId = ServerId("private-key-fixture-server"),
            endpoint = SshEndpoint(LOOPBACK_HOST, server.port),
            username = FIXTURE_USERNAME,
            auth = SshAuthRef.PrivateKey(PRIVATE_KEY_SECRET_ID),
            pinnedHostKey = HostKeyFingerprint(pin),
        )

        fun owner(): SessionOwner.Management = SessionOwner.Management(
            installationId = XuiInstallationId("private-key-fixture-installation"),
            serverAccessId = ServerAccessId("private-key-fixture-access-${server.port}"),
        )

        override fun close() {
            runCatching { server.stop() }
            accepted.close()
        }
    }

    private class GeneratedClientKey(passphraseText: String) : AutoCloseable {
        private val jschKeyPair = JschKeyPair.genKeyPair(JSch(), JschKeyPair.RSA, 3072)
        val publicKey: PublicKey = rsaPublicKeyFromSshBlob(jschKeyPair.publicKeyBlob)
        val publicKeyFingerprint: String = KeyUtils.getFingerPrint(publicKey)
        val encryptedPrivateKey: ByteArray
        val envelope: ByteArray

        init {
            val passphrase = passphraseText.encodeToByteArray()
            encryptedPrivateKey = ByteArrayOutputStream().use { out ->
                jschKeyPair.writePrivateKey(out, passphrase)
                out.toByteArray()
            }
            envelope = PrivateKeySecretEnvelopeCodec.encode(encryptedPrivateKey, passphrase)
            Arrays.fill(passphrase, 0)
        }

        override fun close() {
            Arrays.fill(encryptedPrivateKey, 0)
            Arrays.fill(envelope, 0)
        }
    }

    private class StaticBytesSecretStore(
        private val id: SecretId,
        bytes: ByteArray,
    ) : SecretStore {
        private val stored = bytes.copyOf()

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            SecretCreateResult.StorageFailure("Fixture store is read-only")

        override suspend fun read(secretId: SecretId): SecretReadResult = if (secretId == id) {
            SecretReadResult.Found(SecretMaterial.fromBytes(stored))
        } else {
            SecretReadResult.NotFound
        }

        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Fixture store is read-only")

        override suspend fun listIds(): SecretListResult = SecretListResult.Success(setOf(id))
    }

    private companion object {
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_USERNAME = "velum-key-fixture"
        val PRIVATE_KEY_SECRET_ID = SecretId("fixture-private-key-secret")
        val TEST_CONFIG = SshTransportConfig(
            tcpConnectTimeout = Duration.ofSeconds(5),
            handshakeAndAuthTimeout = Duration.ofSeconds(5),
            channelOpenTimeout = Duration.ofSeconds(5),
            commandExecutionTimeout = Duration.ofSeconds(5),
            stdoutCaptureLimitBytes = 4 * 1024,
            stderrCaptureLimitBytes = 4 * 1024,
        )

        fun rsaPublicKeyFromSshBlob(blob: ByteArray): PublicKey {
            val buffer = ByteBuffer.wrap(blob).order(ByteOrder.BIG_ENDIAN)
            fun field(): ByteArray {
                require(buffer.remaining() >= Int.SIZE_BYTES)
                val length = buffer.int
                require(length >= 0 && length <= buffer.remaining())
                return ByteArray(length).also { buffer.get(it) }
            }

            val type = field().decodeToString()
            require(type == "ssh-rsa") { "Expected RSA SSH public key, got $type" }
            val exponent = BigInteger(1, field())
            val modulus = BigInteger(1, field())
            require(!buffer.hasRemaining()) { "Unexpected trailing SSH public-key bytes" }
            return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent))
        }
    }
}
