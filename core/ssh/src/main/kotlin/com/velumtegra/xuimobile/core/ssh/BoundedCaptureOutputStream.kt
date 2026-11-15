package com.velumtegra.xuimobile.core.ssh

import java.io.OutputStream

/**
 * Non-blocking in-memory sink for JSch's session reader thread.
 *
 * It retains at most [limitBytes], discards all excess bytes, and records truncation. The sink is
 * synchronized because transport callbacks and result snapshotting may race during timeout/cancel
 * cleanup. Raw content is exposed only through [snapshot] and is never rendered by toString().
 */
internal class BoundedCaptureOutputStream(
    private val limitBytes: Int,
) : OutputStream() {
    private val buffer = ByteArray(limitBytes)
    private var count = 0
    private var didTruncate = false

    init {
        require(limitBytes > 0) { "Capture limit must be positive" }
    }

    @Synchronized
    override fun write(value: Int) {
        if (count < limitBytes) {
            buffer[count++] = value.toByte()
        } else {
            didTruncate = true
        }
    }

    @Synchronized
    override fun write(source: ByteArray, offset: Int, length: Int) {
        require(offset >= 0 && length >= 0 && offset + length <= source.size) {
            "Invalid output write range"
        }
        if (length == 0) return

        val remaining = limitBytes - count
        val retained = minOf(remaining, length)
        if (retained > 0) {
            source.copyInto(
                destination = buffer,
                destinationOffset = count,
                startIndex = offset,
                endIndex = offset + retained,
            )
            count += retained
        }
        if (retained < length) {
            didTruncate = true
        }
    }

    @Synchronized
    fun snapshot(): CapturedOutput = CapturedOutput.of(
        source = buffer.copyOf(count),
        truncated = didTruncate,
    )

    override fun toString(): String = "BoundedCaptureOutputStream(limitBytes=$limitBytes, content=[REDACTED])"
}
