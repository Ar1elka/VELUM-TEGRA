package com.velumtegra.xuimobile.core.ssh

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SshAlgorithmPolicyTest {
    @Test
    fun `policy contains no group exchange sha1 cbc dsa or ssh-rsa downgrade`() {
        assertTrue(VelumSshAlgorithmPolicy.keyExchange.isNotEmpty())
        assertTrue(VelumSshAlgorithmPolicy.serverHostKey.isNotEmpty())
        assertTrue(VelumSshAlgorithmPolicy.userPublicKey.isNotEmpty())
        assertTrue(VelumSshAlgorithmPolicy.ciphers.isNotEmpty())
        assertTrue(VelumSshAlgorithmPolicy.macs.isNotEmpty())

        assertFalse(VelumSshAlgorithmPolicy.keyExchange.any { "group-exchange" in it })
        assertFalse(VelumSshAlgorithmPolicy.keyExchange.any { "sha1" in it })
        assertFalse(VelumSshAlgorithmPolicy.serverHostKey.any { it == "ssh-rsa" || "dss" in it })
        assertFalse(VelumSshAlgorithmPolicy.userPublicKey.any { it == "ssh-rsa" || "dss" in it })
        assertFalse(VelumSshAlgorithmPolicy.ciphers.any { "cbc" in it || "3des" in it })
        assertFalse(VelumSshAlgorithmPolicy.macs.any { "sha1" in it || "md5" in it })
        assertTrue(VelumSshAlgorithmPolicy.compression == "none")
    }
}
