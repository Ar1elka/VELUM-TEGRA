package com.velumtegra.xuimobile.core.ssh

import com.sun.net.httpserver.HttpServer
import com.velumtegra.xuimobile.core.site.SiteServingFailureCategory
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.UnknownHostException
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteExternalReachabilityProbeTest {
    private val loopback = InetAddress.getByName("127.0.0.1")
    private val resolver = SiteHostResolver { host ->
        when (host) {
            "site.example.com", "198.51.100.10" -> listOf(loopback)
            "elsewhere.example.com" -> listOf(InetAddress.getByName("203.0.113.9"))
            else -> throw UnknownHostException(host)
        }
    }

    @Test
    fun `dns check requires the domain to point at the selected server`() {
        val probe = SiteExternalReachabilityProbe(resolver)
        assertTrue(probe.checkDns("site.example.com", "198.51.100.10").pointsToServer)
        val wrong = probe.checkDns("elsewhere.example.com", "198.51.100.10")
        assertFalse(wrong.pointsToServer)
        assertTrue(wrong.failureMessage!!.contains("A-запись"))
        val missing = probe.checkDns("missing.example.com", "198.51.100.10")
        assertFalse(missing.pointsToServer)
        assertTrue(missing.failureMessage!!.contains("не найден"))
    }

    @Test
    fun `plain http page is verified by exact body`() {
        val body = "<!doctype html><h1>VELUM</h1>".toByteArray()
        val server = HttpServer.create(InetSocketAddress(loopback, 0), 0).apply {
            createContext("/index.html") { exchange ->
                exchange.sendResponseHeaders(200, body.size.toLong())
                exchange.responseBody.use { it.write(body) }
            }
            start()
        }
        try {
            val probe = SiteExternalReachabilityProbe(resolver)
            val url = "http://site.example.com:${server.address.port}/index.html"
            assertTrue(probe.fetch(url, sha256(body)).reachable)
            val mismatch = probe.fetch(url, "0".repeat(64))
            assertFalse(mismatch.reachable)
            assertEquals(SiteServingFailureCategory.SERVING_VERIFICATION, mismatch.failureCategory)
            val notFound = probe.fetch("http://site.example.com:${server.address.port}/missing.html", sha256(body))
            assertEquals(404, notFound.httpStatus)
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `closed port and unknown domain are categorised`() {
        val probe = SiteExternalReachabilityProbe(resolver, connectTimeoutMillis = 2_000, readTimeoutMillis = 2_000)
        val freePort = ServerSocket(0, 1, loopback).use { it.localPort }
        val closed = probe.fetch("http://site.example.com:$freePort/index.html", "0".repeat(64))
        assertEquals(SiteServingFailureCategory.EXTERNAL_UNREACHABLE, closed.failureCategory)
        val dns = probe.fetch("http://missing.example.com:8080/index.html", "0".repeat(64))
        assertEquals(SiteServingFailureCategory.DNS, dns.failureCategory)
    }

    @Test
    fun `chunked responses are decoded before comparison`() {
        val probe = SiteExternalReachabilityProbe(resolver)
        val body = "hello world".toByteArray()
        val raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".toByteArray()
        assertTrue(probe.parsePlainHttpResponse(raw, "http://x", sha256(body)).reachable)
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
