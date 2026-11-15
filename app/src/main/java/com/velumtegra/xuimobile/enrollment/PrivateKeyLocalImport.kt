package com.velumtegra.xuimobile.enrollment

import java.io.InputStream
import java.util.Arrays

/** Bounds imported key material before it can be kept in transient UI memory. No disk copy. */
object BoundedPrivateKeyDocumentReader {
    const val MAX_KEY_BYTES = 1024 * 1024

    /** Caller owns the returned bytes. InputStream ownership remains with caller. */
    fun read(input: InputStream): ByteArray? {
        val scratch = ByteArray(MAX_KEY_BYTES + 1)
        return try {
            var total = 0
            while (total < scratch.size) {
                val n = input.read(scratch, total, scratch.size - total)
                if (n == -1) break
                if (n == 0) {
                    val one = input.read()
                    if (one == -1) break
                    scratch[total++] = one.toByte()
                } else {
                    total += n
                }
            }
            if (total !in 1..MAX_KEY_BYTES) null else scratch.copyOf(total)
        } finally {
            Arrays.fill(scratch, 0)
        }
    }
}

/** Sensitive imported key bytes must not survive the screen or a changed exact target. */
class TransientPrivateKeySelection : AutoCloseable {
    private var selected: ByteArray? = null
    private var closed = false

    fun replace(next: ByteArray) {
        if (closed) {
            Arrays.fill(next, 0)
            error("Key selection is closed")
        }
        selected?.let { Arrays.fill(it, 0) }
        selected = next // Takes ownership. Caller must not retain/mutate it.
    }

    fun copyForSubmission(): ByteArray? = if (closed) null else selected?.copyOf()

    fun clear() {
        selected?.let { Arrays.fill(it, 0) }
        selected = null
    }

    override fun close() {
        closed = true
        clear()
    }
}
