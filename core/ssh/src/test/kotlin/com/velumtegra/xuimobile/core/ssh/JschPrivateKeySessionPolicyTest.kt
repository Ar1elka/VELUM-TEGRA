package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.JSch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class JschPrivateKeySessionPolicyTest {
    @Test
    fun `private key policy is exact publickey only with audited signature algorithms`() {
        val session = JSch().getSession("user", "localhost", 22)
        JschPrivateKeySessionPolicy.applyTo(session)

        assertEquals("yes", session.getConfig("StrictHostKeyChecking"))
        assertEquals("publickey", session.getConfig("PreferredAuthentications"))
        assertEquals("1", session.getConfig("MaxAuthTries"))
        assertEquals(VelumSshAlgorithmPolicy.userPublicKey.joinToString(","), session.getConfig("PubkeyAcceptedAlgorithms"))
        assertEquals("no", session.getConfig("try_additional_pubkey_algorithms"))
        assertFalse(session.getConfig("PubkeyAcceptedAlgorithms").contains("ssh-rsa"))
        assertFalse(session.getConfig("PubkeyAcceptedAlgorithms").contains("ssh-dss"))
        assertFalse(session.getConfig("PreferredAuthentications").contains("password"))
        assertFalse(session.getConfig("PreferredAuthentications").contains("keyboard-interactive"))
    }
}
