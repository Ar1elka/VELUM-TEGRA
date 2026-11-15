package com.velumtegra.xuimobile.readiness

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalSshReadinessPolicyTest {
    private val pin = "SHA256:" + "A".repeat(43)
    private fun access(
        id: String = "access-B", owner: String = "server-B", fingerprint: String = pin,
        auth: SshAuthRef = SshAuthRef.PrivateKey(SecretId("secret-1")),
    ) = ServerAccess(
        id = ServerAccessId(id), serverId = ServerId(owner),
        endpoint = SshEndpoint("example.org", 22), username = "operator",
        auth = auth, pinnedHostKey = HostKeyFingerprint(fingerprint),
    )

    @Test fun `only the exact selected access for the selected server may pass`() {
        assertTrue(LocalSshReadinessPolicy.inspect("server-B", "access-B", access()) is LocalSshReadinessResult.MetadataPresent)
        assertTrue(LocalSshReadinessPolicy.inspect("server-A", "access-B", access()) is LocalSshReadinessResult.Blocked)
        assertTrue(LocalSshReadinessPolicy.inspect("server-B", "access-A", access()) is LocalSshReadinessResult.Blocked)
        assertTrue(LocalSshReadinessPolicy.inspect("", "access-B", access()) is LocalSshReadinessResult.Blocked)
        assertTrue(LocalSshReadinessPolicy.inspect("server-B", "", access()) is LocalSshReadinessResult.Blocked)
        assertTrue(LocalSshReadinessPolicy.inspect("server-B", "access-B", null) is LocalSshReadinessResult.Blocked)
    }

    @Test fun `invalid pin is blocked and private key material never appears in preview`() {
        assertTrue(LocalSshReadinessPolicy.inspect("server-B", "access-B", access(fingerprint="SHA256:bad")) is LocalSshReadinessResult.Blocked)
        val result = LocalSshReadinessPolicy.inspect("server-B", "access-B", access())
        assertTrue(result is LocalSshReadinessResult.MetadataPresent)
        val details = (result as LocalSshReadinessResult.MetadataPresent).summary
        assertEquals("Приватный ключ (ссылка на секрет)", details.authLabel)
        assertEquals("example.org", details.host)
        assertEquals(pin, details.savedFingerprint)
        assertFalse(details.toString().contains("secret-1"))
    }

    @Test fun `password and key refs are displayed as metadata not authenticated connection`() {
        val password = access(auth=SshAuthRef.Password(SecretId("secret-password")))
        val result = LocalSshReadinessPolicy.inspect("server-B", "access-B", password)
        assertTrue(result is LocalSshReadinessResult.MetadataPresent)
        assertEquals("Пароль (ссылка на секрет)", (result as LocalSshReadinessResult.MetadataPresent).summary.authLabel)
    }
}
