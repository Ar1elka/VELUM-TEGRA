package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class JschSshConnectionFactoryPreflightTest {
    @Test
    fun `malformed pin fails before secret store is read`() = runBlocking {
        val secrets = RecordingSecretStore(SecretReadResult.NotFound)
        val factory = JschSshConnectionFactory(secrets)
        val access = passwordAccess(pin = HostKeyFingerprint("SHA256:not-valid"))

        val result = factory.connect(access, SessionOwner.Operation(OperationId("op")))

        assertTrue(result is SshConnectResult.Failed)
        assertTrue((result as SshConnectResult.Failed).failure is SshConnectFailure.InvalidConfiguration)
        assertEquals(0, secrets.readCount)
    }

    @Test
    fun `private key auth reads configured secret once and preserves unavailable failure`() = runBlocking {
        val secrets = RecordingSecretStore(SecretReadResult.NotFound)
        val factory = JschSshConnectionFactory(secrets)
        val access = passwordAccess().copy(auth = SshAuthRef.PrivateKey(SecretId("key-secret")))

        val result = factory.connect(access, SessionOwner.Operation(OperationId("op")))

        assertTrue(result is SshConnectResult.Failed)
        assertTrue((result as SshConnectResult.Failed).failure is SshConnectFailure.SecretUnavailable)
        assertEquals(1, secrets.readCount)
    }

    @Test
    fun `management owner pinned to another access is rejected before secret read`() = runBlocking {
        val secrets = RecordingSecretStore(SecretReadResult.NotFound)
        val factory = JschSshConnectionFactory(secrets)
        val access = passwordAccess()
        val owner = SessionOwner.Management(
            installationId = XuiInstallationId("xui"),
            serverAccessId = ServerAccessId("different-access"),
        )

        val result = factory.connect(access, owner)

        assertTrue(result is SshConnectResult.Failed)
        assertTrue((result as SshConnectResult.Failed).failure is SshConnectFailure.InvalidConfiguration)
        assertEquals(0, secrets.readCount)
    }

    @Test
    fun `secret store outcomes preserve typed failure category without network attempt`() = runBlocking {
        val access = passwordAccess()
        val owner = SessionOwner.Operation(OperationId("op"))
        val cases = listOf(
            SecretReadResult.NotFound to SshConnectFailure.SecretUnavailable::class.java,
            SecretReadResult.Unavailable("locked") to SshConnectFailure.SecretUnavailable::class.java,
            SecretReadResult.Corrupt("bad envelope") to SshConnectFailure.SecretCorrupt::class.java,
            SecretReadResult.StorageFailure("io") to SshConnectFailure.SecretStorageFailure::class.java,
        )

        cases.forEach { (secretResult, expectedClass) ->
            val secrets = RecordingSecretStore(secretResult)
            val result = JschSshConnectionFactory(secrets).connect(access, owner)
            assertTrue(result is SshConnectResult.Failed)
            assertEquals(expectedClass, (result as SshConnectResult.Failed).failure.javaClass)
            assertEquals(1, secrets.readCount)
        }
    }

    private fun passwordAccess(
        pin: HostKeyFingerprint = HostKeyFingerprint(
            CanonicalHostKeyFingerprint.fromRawHostKey("fixture-key".encodeToByteArray()).asString(),
        ),
    ): ServerAccess = ServerAccess(
        id = ServerAccessId("access"),
        serverId = ServerId("server"),
        endpoint = SshEndpoint("127.0.0.1", 22),
        username = "root",
        auth = SshAuthRef.Password(SecretId("password")),
        pinnedHostKey = pin,
    )

    private class RecordingSecretStore(
        private val readResult: SecretReadResult,
    ) : SecretStore {
        var readCount: Int = 0

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            error("not used")

        override suspend fun read(secretId: SecretId): SecretReadResult {
            readCount += 1
            return readResult
        }

        override suspend fun delete(secretId: SecretId): SecretDeleteResult = error("not used")

        override suspend fun listIds(): SecretListResult = error("not used")
    }
}
