package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.JSch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class JschPasswordSessionPolicyTest {
    @Test
    fun `session policy is strict single password strategy with audited algorithms`() {
        val session = JSch().getSession("user", "localhost", 22)
        JschPasswordSessionPolicy.applyTo(session)

        assertEquals("yes", session.getConfig("StrictHostKeyChecking"))
        assertEquals("password", session.getConfig("PreferredAuthentications"))
        assertEquals("1", session.getConfig("MaxAuthTries"))
        assertEquals(VelumSshAlgorithmPolicy.keyExchange.joinToString(","), session.getConfig("kex"))
        assertEquals(VelumSshAlgorithmPolicy.serverHostKey.joinToString(","), session.getConfig("server_host_key"))
        assertEquals(VelumSshAlgorithmPolicy.ciphers.joinToString(","), session.getConfig("cipher.c2s"))
        assertEquals(VelumSshAlgorithmPolicy.ciphers.joinToString(","), session.getConfig("cipher.s2c"))
        assertEquals(VelumSshAlgorithmPolicy.macs.joinToString(","), session.getConfig("mac.c2s"))
        assertEquals(VelumSshAlgorithmPolicy.macs.joinToString(","), session.getConfig("mac.s2c"))
        assertEquals("none", session.getConfig("compression.c2s"))
        assertEquals("none", session.getConfig("compression.s2c"))
        assertFalse(session.getConfig("kex").contains("group-exchange"))
    }
}
