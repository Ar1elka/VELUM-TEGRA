package com.velumtegra.xuimobile.sshport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SshPortPolicyTest {
    @Test fun acceptsOnlyValidNonDefaultTcpPorts() {
        assertEquals(1, SshPortPolicy.parse("1"))
        assertEquals(65_535, SshPortPolicy.parse("65535"))
        assertEquals(21_578, SshPortPolicy.parse(" 21578 "))
        listOf("22", "00022", "0", "65536", "-1", "1; id", "", "１").forEach {
            assertNull(it, SshPortPolicy.parse(it))
        }
    }

    @Test fun randomPortsStayInsideTheHighPortRange() {
        repeat(256) {
            assertTrue(SshPortPolicy.randomPort() in 49_152..65_535)
        }
    }
}
