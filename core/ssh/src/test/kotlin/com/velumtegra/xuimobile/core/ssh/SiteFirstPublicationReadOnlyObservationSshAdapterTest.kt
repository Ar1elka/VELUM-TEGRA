package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteFirstPublicationReadOnlyObservationSshAdapterTest {
    @Test
    fun `unconfigured endpoint is proven by one finite read only command`() = runBlocking {
        val session = FakeSession(ok("UNCONFIGURED\n"))
        val adapter = SiteFirstPublicationReadOnlyObservationSshAdapter()
        val configPath = adapter.exactFutureConfigPath(
            remoteHostIdentity = "server-1.example",
            targetRoot = "/srv/www/site",
            domain = "site.example.com",
            port = 58431,
        )

        assertFalse(adapter.observeConfigured(configPath, 58431, session))
        assertEquals(1, session.rawCommands.size)
        val command = session.rawCommands.single()
        assertTrue("[ -e '/etc/nginx/conf.d/velum-tegra-" in command)
        assertTrue("[ -L '/etc/nginx/conf.d/velum-tegra-" in command)
        assertTrue("ss -H -ltn 'sport = :58431'" in command)
        assertTrue("command -v nginx" in command)
        assertTrue("[ -L /etc/nginx/conf.d ] || [ ! -d /etc/nginx/conf.d ]" in command)
        assertTrue(listOf("rm ", "mv ", "mkdir", "chmod", "chown", "tee ", "systemctl", "nginx -s").none {
            it in command.lowercase()
        })
    }

    @Test
    fun `missing nginx prerequisites block publication with a specific reason`() {
        val adapter = SiteFirstPublicationReadOnlyObservationSshAdapter()
        val path = adapter.exactFutureConfigPath("server-1.example", "/srv/www/site", "site.example.com", 2092)

        val nginxMissing = assertThrows(IllegalStateException::class.java) {
            runBlocking { adapter.observeConfigured(path, 2092, FakeSession(ok("NGINX_MISSING\n"))) }
        }
        assertTrue(nginxMissing.message.orEmpty().contains("Nginx"))
        val directoryInvalid = assertThrows(IllegalStateException::class.java) {
            runBlocking { adapter.observeConfigured(path, 2092, FakeSession(ok("NGINX_CONF_D_INVALID\n"))) }
        }
        assertTrue(directoryInvalid.message.orEmpty().contains("/etc/nginx/conf.d"))
    }

    @Test
    fun `configured endpoint returns true and unknown state fails closed`() {
        runBlocking {
            val adapter = SiteFirstPublicationReadOnlyObservationSshAdapter()
            val path = adapter.exactFutureConfigPath("server-1.example", "/srv/www/site", "site.example.com", 58431)
            assertTrue(adapter.observeConfigured(path, 58431, FakeSession(ok("CONFIGURED\n"))))
            assertThrows(IllegalStateException::class.java) {
                runBlocking { adapter.observeConfigured(path, 58431, FakeSession(ok("UNKNOWN\n"))) }
            }
        }
    }

    @Test
    fun `malformed or unverified evidence fails closed`() {
        val adapter = SiteFirstPublicationReadOnlyObservationSshAdapter()
        val path = adapter.exactFutureConfigPath("server-1.example", "/srv/www/site", "site.example.com", 58431)
        assertThrows(IllegalStateException::class.java) {
            runBlocking { adapter.observeConfigured(path, 58431, FakeSession(ok("maybe\n"))) }
        }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { adapter.observeConfigured("/tmp/not-nginx.conf", 58431, FakeSession(ok("UNCONFIGURED\n"))) }
        }
    }

    private class FakeSession(
        private val response: SshCommandResult,
    ) : VerifiedHostKeySshSessionHandle {
        override val binding = SessionBinding(
            SessionId("phase11-100-session"),
            ServerAccessId("access-1"),
            SessionOwner.Operation(OperationId("phase11-100-op")),
        )
        override val verifiedHostKeySha256: String = "7".repeat(64)
        override val isOpen: Boolean = true
        val rawCommands = mutableListOf<String>()

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            rawCommands += command.rawForTransport()
            return response
        }

        override fun close() = Unit
    }

    private fun ok(text: String) = SshCommandResult(
        dispatchState = CommandDispatchState.DISPATCHED,
        completion = CommandCompletion.ConfirmedSuccess,
        stdout = CapturedOutput.of(text.encodeToByteArray(), false),
        stderr = CapturedOutput.EMPTY,
    )
}
