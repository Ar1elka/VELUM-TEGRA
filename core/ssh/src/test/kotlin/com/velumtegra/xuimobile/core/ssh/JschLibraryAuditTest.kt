package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.JSch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class JschLibraryAuditTest {
    @Test
    fun `audited JSch version is exact`() {
        assertEquals("2.28.7", JSch.VERSION)
    }

    @Test
    fun `every VELUM allowlisted algorithm is implemented by selected JSch`() {
        val all = buildList {
            addAll(VelumSshAlgorithmPolicy.keyExchange)
            addAll(VelumSshAlgorithmPolicy.serverHostKey)
            addAll(VelumSshAlgorithmPolicy.ciphers)
            addAll(VelumSshAlgorithmPolicy.macs)
        }
        all.forEach { algorithm ->
            assertNotNull("JSch has no implementation mapping for $algorithm", JSch.getConfig(algorithm))
        }
    }
}
