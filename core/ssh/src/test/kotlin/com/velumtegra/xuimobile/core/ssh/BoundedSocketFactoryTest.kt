package com.velumtegra.xuimobile.core.ssh

import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket

class BoundedSocketFactoryTest {
    @Test
    fun `local DNS and TCP establish inside explicit budget`() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val accept = Thread {
                runCatching { server.accept().use { } }
            }.apply {
                isDaemon = true
                start()
            }

            val factory = BoundedSocketFactory(tcpConnectTimeoutMillis = 2_000)
            factory.createSocket(InetAddress.getLoopbackAddress().hostAddress, server.localPort).use { socket ->
                assertTrue(socket.isConnected)
                assertTrue(factory.tcpWasEstablished())
            }
            accept.join(2_000)
        }
    }
}
