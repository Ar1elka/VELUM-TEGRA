package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.model.OperationId
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Test

class OperationRuntimeLeaseRegistryTest {
    @Test
    fun `first exact operation acquire succeeds and duplicate is rejected`() {
        val registry = OperationRuntimeLeaseRegistry()
        val operationId = OperationId("op-a")

        assertTrue(registry.tryAcquire(operationId) is OperationRuntimeAcquireResult.Acquired)
        assertEquals(OperationRuntimeAcquireResult.AlreadyOwned, registry.tryAcquire(operationId))
    }

    @Test
    fun `different operation ids do not block each other`() {
        val registry = OperationRuntimeLeaseRegistry()

        assertTrue(registry.tryAcquire(OperationId("op-a")) is OperationRuntimeAcquireResult.Acquired)
        assertTrue(registry.tryAcquire(OperationId("op-b")) is OperationRuntimeAcquireResult.Acquired)
    }

    @Test
    fun `exact release permits a later fresh lease`() {
        val registry = OperationRuntimeLeaseRegistry()
        val operationId = OperationId("op-a")
        val first = registry.acquireLease(operationId)

        assertEquals(OperationRuntimeReleaseResult.RELEASED, registry.release(first))
        val second = registry.acquireLease(operationId)

        assertNotSame(first, second)
    }

    @Test
    fun `stale release cannot remove a newer lease`() {
        val registry = OperationRuntimeLeaseRegistry()
        val operationId = OperationId("op-a")
        val first = registry.acquireLease(operationId)
        assertEquals(OperationRuntimeReleaseResult.RELEASED, registry.release(first))
        registry.acquireLease(operationId)

        assertEquals(
            OperationRuntimeReleaseResult.STALE_OR_ALREADY_RELEASED,
            registry.release(first),
        )
        assertEquals(OperationRuntimeAcquireResult.AlreadyOwned, registry.tryAcquire(operationId))
    }

    @Test
    fun `double release is idempotent and cannot affect other ownership`() {
        val registry = OperationRuntimeLeaseRegistry()
        val first = registry.acquireLease(OperationId("op-a"))
        registry.acquireLease(OperationId("op-b"))

        assertEquals(OperationRuntimeReleaseResult.RELEASED, registry.release(first))
        assertEquals(
            OperationRuntimeReleaseResult.STALE_OR_ALREADY_RELEASED,
            registry.release(first),
        )
        assertEquals(
            OperationRuntimeAcquireResult.AlreadyOwned,
            registry.tryAcquire(OperationId("op-b")),
        )
    }

    @Test
    fun `release of one exact operation never affects another operation`() {
        val registry = OperationRuntimeLeaseRegistry()
        val first = registry.acquireLease(OperationId("op-a"))
        registry.acquireLease(OperationId("op-b"))

        assertEquals(OperationRuntimeReleaseResult.RELEASED, registry.release(first))
        assertTrue(registry.tryAcquire(OperationId("op-a")) is OperationRuntimeAcquireResult.Acquired)
        assertEquals(
            OperationRuntimeAcquireResult.AlreadyOwned,
            registry.tryAcquire(OperationId("op-b")),
        )
    }

    @Test
    fun `concurrent duplicate acquire has exactly one winner`() {
        val registry = OperationRuntimeLeaseRegistry()
        val operationId = OperationId("op-race")
        val workers = 24
        val ready = CountDownLatch(workers)
        val start = CountDownLatch(1)
        val done = CountDownLatch(workers)
        val acquired = AtomicInteger(0)
        val executor = Executors.newFixedThreadPool(workers)

        try {
            repeat(workers) {
                executor.execute {
                    ready.countDown()
                    try {
                        check(start.await(5, TimeUnit.SECONDS))
                        if (registry.tryAcquire(operationId) is OperationRuntimeAcquireResult.Acquired) {
                            acquired.incrementAndGet()
                        }
                    } finally {
                        done.countDown()
                    }
                }
            }

            assertTrue("workers did not become ready", ready.await(5, TimeUnit.SECONDS))
            start.countDown()
            assertTrue("workers did not finish", done.await(5, TimeUnit.SECONDS))
            assertEquals(1, acquired.get())
        } finally {
            executor.shutdownNow()
        }
    }

    private fun OperationRuntimeLeaseRegistry.acquireLease(operationId: OperationId): OperationRuntimeLease {
        val result = tryAcquire(operationId)
        assertTrue(result is OperationRuntimeAcquireResult.Acquired)
        return (result as OperationRuntimeAcquireResult.Acquired).lease
    }
}
