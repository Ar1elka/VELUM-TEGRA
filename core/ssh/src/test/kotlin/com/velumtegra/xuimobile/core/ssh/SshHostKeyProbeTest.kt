package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.HostKeyRepository
import java.security.KeyPairGenerator
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SshHostKeyProbeTest {
    @Test fun observedButAlwaysRejectedWithoutPinnedTrust() {
        val raw = byteArrayOf(0, 0, 0, 3, 115, 115, 104)
        val repo = ObserveAndRejectHostKeyRepository("[host.example]:2222")
        assertEquals(HostKeyRepository.CHANGED, repo.check("wrong.example", raw))
        assertEquals(null, repo.observed())
        assertEquals(HostKeyRepository.CHANGED, repo.check("[host.example]:2222", raw))
        // Invalid raw key type never becomes trusted; repository remains empty.
        assertTrue(repo.getHostKey().isEmpty())
    }

    @Test fun loopbackHandshakeObtainsPublicKeyWithoutAuthentication() = runBlocking {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val attempts = AtomicInteger(0)
        val fixture = SshServer.setUpDefaultServer().apply {
            host = "127.0.0.1"
            port = 0
            keyPairProvider = KeyPairProvider.wrap(keyPair)
            userAuthFactories = listOf(UserAuthPasswordFactory.INSTANCE)
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { _, _, _ ->
                attempts.incrementAndGet(); false
            }
        }
        try {
            fixture.start()
            val observation = JschSshHostKeyProbe().observe("127.0.0.1", fixture.port)
            assertTrue("expected SSH public host key, got $observation", observation is SshHostKeyObservation.Presented)
            val presented = observation as SshHostKeyObservation.Presented
            assertTrue(presented.fingerprint.startsWith("SHA256:"))
            assertEquals(0, attempts.get())
        } finally { fixture.stop() }
    }
}
