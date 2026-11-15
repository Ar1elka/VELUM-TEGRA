package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.ChannelExec
import java.io.Closeable
import java.io.InputStreamReader
import java.io.OutputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible

/** A dedicated session for the installed x-ui menu. It has no arbitrary SSH command entry point. */
interface XuiServerMenuSession : SshSessionHandle {
    suspend fun openXuiServerMenu(): XuiServerMenuChannel?
}

interface XuiServerMenuChannel : Closeable {
    /** An empty string means no output is ready. Null means the channel has ended. */
    suspend fun readAvailable(): String?
    suspend fun sendLine(value: String)
    suspend fun interrupt()
}

internal class JschXuiServerMenuChannel(
    private val channel: ChannelExec,
    private val input: InputStreamReader,
    private val output: OutputStream,
) : XuiServerMenuChannel {
    private val buffer = CharArray(4_096)

    override suspend fun readAvailable(): String? = runInterruptible(Dispatchers.IO) {
        if (input.ready()) {
            val count = input.read(buffer)
            if (count < 0) null else String(buffer, 0, count)
        } else if (!channel.isConnected || channel.isClosed) null else ""
    }

    override suspend fun sendLine(value: String) {
        require(value.length <= 1_024 && value.none { it.isISOControl() })
        send((value + "\n").toByteArray(Charsets.UTF_8))
    }

    override suspend fun interrupt() = send(byteArrayOf(3))

    private suspend fun send(bytes: ByteArray) = runInterruptible(Dispatchers.IO) {
        check(channel.isConnected && !channel.isClosed)
        try {
            output.write(bytes)
            output.flush()
        } finally {
            bytes.fill(0)
        }
    }

    override fun close() {
        channel.disconnect()
    }
}
