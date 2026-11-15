package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerId
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerMutationLeaseRegistryTest {
    @Test
    fun `first mutation acquire stores exact server and operation ownership`() {
        val registry = ServerMutationLeaseRegistry()
        val serverId = ServerId("server-a")
        val operationId = OperationId("op-a")

        val lease = registry.acquireLease(serverId, operationId)

        assertEquals(serverId, lease.serverId)
        assertEquals(operationId, lease.operationId)
    }

    @Test
    fun `different operations cannot concurrently mutate the same server`() {
        val registry = ServerMutationLeaseRegistry()
        val serverId = ServerId("server-a")

        registry.acquireLease(serverId, OperationId("op-a"))

        assertEquals(
            ServerMutationAcquireResult.AlreadyOwned,
            registry.tryAcquire(serverId, OperationId("op-b")),
        )
    }

    @Test
    fun `duplicate acquire by the same operation is rejected rather than reentrant`() {
        val registry = ServerMutationLeaseRegistry()
        val serverId = ServerId("server-a")
        val operationId = OperationId("op-a")

        registry.acquireLease(serverId, operationId)

        assertEquals(
            ServerMutationAcquireResult.AlreadyOwned,
            registry.tryAcquire(serverId, operationId),
        )
    }

    @Test
    fun `different servers do not block each other`() {
        val registry = ServerMutationLeaseRegistry()

        assertTrue(
            registry.tryAcquire(ServerId("server-a"), OperationId("op-a"))
                is ServerMutationAcquireResult.Acquired,
        )
        assertTrue(
            registry.tryAcquire(ServerId("server-b"), OperationId("op-b"))
                is ServerMutationAcquireResult.Acquired,
        )
    }

    @Test
    fun `exact release permits a later fresh mutation lease`() {
        val registry = ServerMutationLeaseRegistry()
        val serverId = ServerId("server-a")
        val first = registry.acquireLease(serverId, OperationId("op-a"))

        assertEquals(ServerMutationReleaseResult.RELEASED, registry.release(first))
        val second = registry.acquireLease(serverId, OperationId("op-b"))

        assertNotSame(first, second)
        assertEquals(OperationId("op-b"), second.operationId)
    }

    @Test
    fun `stale cleanup cannot release a newer mutation owner`() {
        val registry = ServerMutationLeaseRegistry()
        val serverId = ServerId("server-a")
        val first = registry.acquireLease(serverId, OperationId("op-a"))
        assertEquals(ServerMutationReleaseResult.RELEASED, registry.release(first))
        registry.acquireLease(serverId, OperationId("op-b"))

        assertEquals(
            ServerMutationReleaseResult.STALE_OR_ALREADY_RELEASED,
            registry.release(first),
        )
        assertEquals(
            ServerMutationAcquireResult.AlreadyOwned,
            registry.tryAcquire(serverId, OperationId("op-c")),
        )
    }

    @Test
    fun `stale cleanup cannot release a fresh lease reacquired by the same operation`() {
        val registry = ServerMutationLeaseRegistry()
        val serverId = ServerId("server-a")
        val operationId = OperationId("op-a")
        val first = registry.acquireLease(serverId, operationId)
        assertEquals(ServerMutationReleaseResult.RELEASED, registry.release(first))
        val second = registry.acquireLease(serverId, operationId)

        assertNotSame(first, second)
        assertEquals(
            ServerMutationReleaseResult.STALE_OR_ALREADY_RELEASED,
            registry.release(first),
        )
        assertEquals(
            ServerMutationAcquireResult.AlreadyOwned,
            registry.tryAcquire(serverId, OperationId("op-b")),
        )
    }

    @Test
    fun `double release is idempotent and cannot affect another server`() {
        val registry = ServerMutationLeaseRegistry()
        val first = registry.acquireLease(ServerId("server-a"), OperationId("op-a"))
        registry.acquireLease(ServerId("server-b"), OperationId("op-b"))

        assertEquals(ServerMutationReleaseResult.RELEASED, registry.release(first))
        assertEquals(
            ServerMutationReleaseResult.STALE_OR_ALREADY_RELEASED,
            registry.release(first),
        )
        assertEquals(
            ServerMutationAcquireResult.AlreadyOwned,
            registry.tryAcquire(ServerId("server-b"), OperationId("op-c")),
        )
    }

    @Test
    fun `concurrent mutations for one server have exactly one winner`() {
        val registry = ServerMutationLeaseRegistry()
        val serverId = ServerId("server-race")
        val workers = 24
        val ready = CountDownLatch(workers)
        val start = CountDownLatch(1)
        val done = CountDownLatch(workers)
        val acquired = AtomicInteger(0)
        val executor = Executors.newFixedThreadPool(workers)

        try {
            repeat(workers) { index ->
                executor.execute {
                    ready.countDown()
                    try {
                        check(start.await(5, TimeUnit.SECONDS))
                        if (
                            registry.tryAcquire(serverId, OperationId("op-$index"))
                                is ServerMutationAcquireResult.Acquired
                        ) {
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

    private fun ServerMutationLeaseRegistry.acquireLease(
        serverId: ServerId,
        operationId: OperationId,
    ): ServerMutationLease {
        val result = tryAcquire(serverId, operationId)
        assertTrue(result is ServerMutationAcquireResult.Acquired)
        return (result as ServerMutationAcquireResult.Acquired).lease
    }
}
