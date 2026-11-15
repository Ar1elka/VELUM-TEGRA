package com.velumtegra.xuimobile.core.ssh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BoundedCaptureOutputStreamTest {
    @Test
    fun `capture retains exact prefix and marks overflow as truncated`() {
        val sink = BoundedCaptureOutputStream(4)
        sink.write(byteArrayOf(1, 2, 3), 0, 3)
        sink.write(byteArrayOf(4, 5, 6), 0, 3)
        val captured = sink.snapshot()
        assertEquals(4, captured.sizeBytes)
        assertTrue(captured.truncated)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), captured.copyBytes())
    }

    @Test
    fun `capture at exact limit is not truncated`() {
        val sink = BoundedCaptureOutputStream(3)
        sink.write(byteArrayOf(7, 8, 9))
        val captured = sink.snapshot()
        assertEquals(3, captured.sizeBytes)
        assertFalse(captured.truncated)
        assertArrayEquals(byteArrayOf(7, 8, 9), captured.copyBytes())
    }

    @Test
    fun `single byte overflow is discarded`() {
        val sink = BoundedCaptureOutputStream(1)
        sink.write(0x41)
        sink.write(0x42)
        val captured = sink.snapshot()
        assertEquals(1, captured.sizeBytes)
        assertTrue(captured.truncated)
        assertArrayEquals(byteArrayOf(0x41), captured.copyBytes())
    }
}
