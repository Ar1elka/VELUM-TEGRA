package com.velumtegra.xuimobile.core.ssh

import org.junit.Assert.assertEquals
import org.junit.Test
import java.time.Duration

class JschTimeoutConversionTest {
    @Test
    fun `positive sub millisecond timeout never becomes unbounded zero`() {
        assertEquals(1, Duration.ofNanos(1).toJschTimeoutMillis())
        assertEquals(1, Duration.ofMillis(1).toJschTimeoutMillis())
        assertEquals(10_000, Duration.ofSeconds(10).toJschTimeoutMillis())
    }
}
