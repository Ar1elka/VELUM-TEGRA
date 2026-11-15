package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.SocketFactory
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Gives DNS + TCP establishment one total bounded budget. JSch's later Session.connect(timeout)
 * applies the independent handshake/auth SO_TIMEOUT to the established socket.
 *
 * Java name resolution itself has no portable timeout API, so resolution runs on a short-lived daemon
 * worker and the transport stops waiting when the TCP budget expires. Cancellation is best-effort for
 * the platform resolver; the daemon worker can never keep the app/JVM alive.
 */
internal class BoundedSocketFactory(
    private val tcpConnectTimeoutMillis: Int,
) : SocketFactory {
    private val connected = AtomicBoolean(false)

    override fun createSocket(host: String, port: Int): Socket {
        val started = System.nanoTime()
        val addresses = resolveBounded(host, tcpConnectTimeoutMillis)
        val address = addresses.firstOrNull() ?: throw UnknownHostException(host)
        val remaining = remainingMillis(started, tcpConnectTimeoutMillis)
        if (remaining <= 0) {
            throw SocketTimeoutException("DNS/TCP connect budget expired before socket connect")
        }

        val socket = Socket()
        try {
            socket.connect(InetSocketAddress(address, port), remaining)
            connected.set(true)
            return socket
        } catch (failure: Throwable) {
            runCatching { socket.close() }
            throw failure
        }
    }

    override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()

    override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()

    fun tcpWasEstablished(): Boolean = connected.get()

    private fun resolveBounded(host: String, timeoutMillis: Int): Array<InetAddress> {
        val executor = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "velum-ssh-dns").apply { isDaemon = true }
        }
        val future = executor.submit<Array<InetAddress>> { InetAddress.getAllByName(host) }
        return try {
            future.get(timeoutMillis.toLong(), TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            future.cancel(true)
            throw SocketTimeoutException("DNS resolution exceeded TCP connect budget")
        } catch (failure: ExecutionException) {
            val cause = failure.cause
            when (cause) {
                is UnknownHostException -> throw cause
                is IOException -> throw cause
                else -> throw IOException("DNS resolution failed", cause ?: failure)
            }
        } catch (_: InterruptedException) {
            future.cancel(true)
            Thread.currentThread().interrupt()
            throw InterruptedIOException("DNS resolution interrupted")
        } finally {
            executor.shutdownNow()
        }
    }

    private fun remainingMillis(startedNanos: Long, budgetMillis: Int): Int {
        val elapsedNanos = System.nanoTime() - startedNanos
        val elapsedMillisCeil = (elapsedNanos + 999_999L) / 1_000_000L
        val remaining = budgetMillis.toLong() - elapsedMillisCeil
        return remaining.coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
    }
}
