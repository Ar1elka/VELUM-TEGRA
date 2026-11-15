package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.OperationId
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectivityReconnectPermitGateTest {
    @Test
    fun `initial UNKNOWN remains attempt capable for exact private endpoint`() {
        val gate = ConnectivityReconnectPermitGate()
        val observation = gate.snapshot()

        val result = gate.tryPermit(OperationId("op-a"), observation)

        assertTrue(result is ReconnectPermitResult.Permitted)
        val permit = (result as ReconnectPermitResult.Permitted).permit
        assertEquals(0L, permit.generation)
        assertEquals(ConnectivityState.UNKNOWN, permit.connectivityState)
    }

    @Test
    fun `OFFLINE waits and does not grant reconnect permit`() {
        val gate = ConnectivityReconnectPermitGate()
        val offline = gate.observe(ConnectivityState.OFFLINE)

        assertEquals(
            ReconnectPermitResult.WaitForNetwork,
            gate.tryPermit(OperationId("op-a"), offline),
        )
    }

    @Test
    fun `ONLINE grants scheduling permit but only as connectivity evidence`() {
        val gate = ConnectivityReconnectPermitGate()
        val online = gate.observe(ConnectivityState.ONLINE)

        val result = gate.tryPermit(OperationId("op-a"), online)

        assertTrue(result is ReconnectPermitResult.Permitted)
        val permit = (result as ReconnectPermitResult.Permitted).permit
        assertEquals(ConnectivityState.ONLINE, permit.connectivityState)
        assertEquals(online.generation, permit.generation)
    }

    @Test
    fun `one operation receives at most one permit in one generation`() {
        val gate = ConnectivityReconnectPermitGate()
        val observation = gate.observe(ConnectivityState.ONLINE)
        val operationId = OperationId("op-a")

        assertTrue(gate.tryPermit(operationId, observation) is ReconnectPermitResult.Permitted)
        assertEquals(
            ReconnectPermitResult.AlreadyPermittedForGeneration,
            gate.tryPermit(operationId, observation),
        )
    }

    @Test
    fun `different operations can receive permits in the same generation`() {
        val gate = ConnectivityReconnectPermitGate()
        val observation = gate.observe(ConnectivityState.UNKNOWN)

        assertTrue(
            gate.tryPermit(OperationId("op-a"), observation) is ReconnectPermitResult.Permitted,
        )
        assertTrue(
            gate.tryPermit(OperationId("op-b"), observation) is ReconnectPermitResult.Permitted,
        )
    }

    @Test
    fun `new connectivity generation permits the same operation once again`() {
        val gate = ConnectivityReconnectPermitGate()
        val operationId = OperationId("op-a")
        val first = gate.observe(ConnectivityState.ONLINE)
        assertTrue(gate.tryPermit(operationId, first) is ReconnectPermitResult.Permitted)

        val second = gate.observe(ConnectivityState.UNKNOWN)

        assertTrue(gate.tryPermit(operationId, second) is ReconnectPermitResult.Permitted)
        assertTrue(second.generation > first.generation)
    }

    @Test
    fun `stale scheduled generation cannot acquire a permit after a newer observation`() {
        val gate = ConnectivityReconnectPermitGate()
        val old = gate.observe(ConnectivityState.ONLINE)
        gate.observe(ConnectivityState.OFFLINE)

        assertEquals(
            ReconnectPermitResult.StaleGeneration,
            gate.tryPermit(OperationId("op-a"), old),
        )
    }

    @Test
    fun `new observation invalidates an already granted old reconnect permit`() {
        val gate = ConnectivityReconnectPermitGate()
        val old = gate.observe(ConnectivityState.ONLINE)
        val result = gate.tryPermit(OperationId("op-a"), old)
        assertTrue(result is ReconnectPermitResult.Permitted)
        val permit = (result as ReconnectPermitResult.Permitted).permit
        assertEquals(ReconnectPermitStatus.CURRENT, gate.status(permit))

        gate.observe(ConnectivityState.UNKNOWN)

        assertEquals(ReconnectPermitStatus.STALE_GENERATION, gate.status(permit))
    }

    @Test
    fun `fast flap leaves only latest generation eligible`() {
        val gate = ConnectivityReconnectPermitGate()
        val operationId = OperationId("op-a")
        val firstOnline = gate.observe(ConnectivityState.ONLINE)
        gate.observe(ConnectivityState.OFFLINE)
        val latestOnline = gate.observe(ConnectivityState.ONLINE)

        assertEquals(
            ReconnectPermitResult.StaleGeneration,
            gate.tryPermit(operationId, firstOnline),
        )
        assertTrue(
            gate.tryPermit(operationId, latestOnline) is ReconnectPermitResult.Permitted,
        )
        assertEquals(
            ReconnectPermitResult.AlreadyPermittedForGeneration,
            gate.tryPermit(operationId, latestOnline),
        )
    }

    @Test
    fun `every accepted connectivity event advances generation even when state repeats`() {
        val gate = ConnectivityReconnectPermitGate(ConnectivityState.ONLINE)
        val before = gate.snapshot()

        val after = gate.observe(ConnectivityState.ONLINE)

        assertEquals(before.generation + 1L, after.generation)
        assertEquals(ConnectivityState.ONLINE, after.state)
    }

    @Test
    fun `snapshot returns exact current observation token`() {
        val gate = ConnectivityReconnectPermitGate()
        val observation = gate.observe(ConnectivityState.UNKNOWN)

        assertTrue(observation === gate.snapshot())
    }

    @Test
    fun `concurrent duplicate schedulers have exactly one permit winner`() {
        val gate = ConnectivityReconnectPermitGate()
        val observation = gate.observe(ConnectivityState.ONLINE)
        val operationId = OperationId("op-race")
        val workers = 24
        val ready = CountDownLatch(workers)
        val start = CountDownLatch(1)
        val done = CountDownLatch(workers)
        val permitted = AtomicInteger(0)
        val executor = Executors.newFixedThreadPool(workers)

        try {
            repeat(workers) {
                executor.execute {
                    ready.countDown()
                    try {
                        check(start.await(5, TimeUnit.SECONDS))
                        if (gate.tryPermit(operationId, observation) is ReconnectPermitResult.Permitted) {
                            permitted.incrementAndGet()
                        }
                    } finally {
                        done.countDown()
                    }
                }
            }

            assertTrue("workers did not become ready", ready.await(5, TimeUnit.SECONDS))
            start.countDown()
            assertTrue("workers did not finish", done.await(5, TimeUnit.SECONDS))
            assertEquals(1, permitted.get())
        } finally {
            executor.shutdownNow()
        }
    }
}
