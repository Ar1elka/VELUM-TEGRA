package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteExisting3xUiCertificateReuseEligibilitySshAdapterTest {
    @Test
    fun `adapter uses finite read only commands and never reads private key bytes`() = runBlocking {
        val session = FakeSession(ArrayDeque(listOf(
            ok("DB=FILE\nSQLITE=PRESENT\nCERT=/etc/ssl/x-ui/fullchain.pem\nKEY=/etc/ssl/x-ui/privkey.pem\n"),
            ok(
                "TYPE=FILE\nSHA256=${"a".repeat(64)}\n" +
                    "notBefore=Sep  1 12:00:00 2026 GMT\n" +
                    "notAfter=Dec  1 12:00:00 2026 GMT\n" +
                    "X509v3 Subject Alternative Name:\n    DNS:panel.example.com, DNS:www.example.com\n",
            ),
            ok("FILE\n"),
        )))
        val observation = SiteExisting3xUiCertificateReuseEligibilitySshAdapter().observe(
            SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare("vps-01.example.net"),
            access(),
            session,
        )

        assertEquals(3, observation.remoteCommandCount)
        assertEquals(SiteWebServingObservedPathType.FILE, observation.databasePathType)
        assertEquals(SiteWebServingObservedPathType.FILE, observation.certificatePathType)
        assertEquals(SiteWebServingObservedPathType.FILE, observation.privateKeyPathType)
        assertEquals(listOf("panel.example.com", "www.example.com"), observation.certificateDnsNames)
        assertTrue(observation.sqliteReadOnlyAvailable)
        assertFalse(observation.privateKeyContentReadPerformed)
        assertTrue(session.rawCommands.any { "webCertFile" in it && "webKeyFile" in it })
        val discovery = session.rawCommands.first { "webCertFile" in it && "webKeyFile" in it }
        assertTrue("sqlite3 -readonly" in discovery)
        assertTrue("command -v python3" in discovery)
        assertTrue("?mode=ro" in discovery)
        assertTrue("PRAGMA query_only=ON" in discovery)
        assertTrue(session.rawCommands.any { "openssl x509" in it })
        assertTrue(session.rawCommands.none { "openssl pkey" in it || "cat -- '/etc/ssl/x-ui/privkey.pem'" in it })
        assertTrue(session.rawCommands.all(::isReadOnlyCommand))
    }

    @Test
    fun `unsafe derived key path is not retained or dispatched`() = runBlocking {
        val session = FakeSession(ArrayDeque(listOf(
            ok("DB=FILE\nSQLITE=PRESENT\nCERT=/etc/ssl/x-ui/fullchain.pem\nKEY=../../secret.key\n"),
            ok(
                "TYPE=FILE\nSHA256=${"b".repeat(64)}\n" +
                    "notBefore=Sep  1 12:00:00 2026 GMT\n" +
                    "notAfter=Dec  1 12:00:00 2026 GMT\n" +
                    "X509v3 Subject Alternative Name:\n    DNS:panel.example.com\n",
            ),
        )))
        val observation = SiteExisting3xUiCertificateReuseEligibilitySshAdapter().observe(
            SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare("vps-01.example.net"),
            access(),
            session,
        )

        assertNull(observation.privateKeyPath)
        assertNull(observation.privateKeyPathType)
        assertEquals(2, observation.remoteCommandCount)
        assertTrue(session.rawCommands.none { "secret.key" in it })
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
        return listOf("rm ", "mv ", "mkdir", "chmod", "chown", "scp", "sftp", "tee ", "> ", "apt ", "systemctl").none(lowered::contains)
    }

    private companion object {
        val ACCESS_ID = ServerAccessId("access-1")
        val SERVER_KEY = "7".repeat(64)
    }
}
