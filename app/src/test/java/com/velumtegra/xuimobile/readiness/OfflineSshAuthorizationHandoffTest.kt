package com.velumtegra.xuimobile.readiness

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class OfflineSshAuthorizationHandoffTest {
    private val summary = LocalSshAccessSummary(
        "access-7", "node.example", 22, "operator", "Пароль (ссылка на секрет)", "SHA256:" + "A".repeat(43),
    )
    private val present = LocalSshReadinessResult.MetadataPresent(summary)
    private val target = "operator@node.example:22"
    private val draft = (OfflineSshConnectionDraftPolicy.prepare(
        "server-7", "access-7", present, present, target, true,
    ) as OfflineSshConnectionDraftResult.Prepared).draft

    private fun armed(gate: OfflineSshConsentRehearsal) = (gate.arm(
        draft, present, target, true, 1_000L, "marker",
    ) as OfflineSshConsentResult.Armed).receipt

    @Test fun `successful handoff consumes once and exposes no execution capability`() {
        val gate = OfflineSshConsentRehearsal()
        val receipt = armed(gate)
        val boundary = OfflineSshAuthorizationHandoff(gate)
        val first = boundary.inspectOnce(receipt, "server-7", "access-7", present, target, true, 1_001L)
        assertTrue(first is OfflineSshHandoffResult.Inspected)
        val inspected = first as OfflineSshHandoffResult.Inspected
        assertEquals("server-7", inspected.serverId)
        assertEquals("access-7", inspected.accessId)
        assertFalse(inspected.authorizesNetwork)
        assertFalse(inspected.authorizesSecretRead)
        assertFalse(inspected.authorizesSshSession)
        assertFalse(inspected.authorizesVpsCommands)
        assertTrue(boundary.inspectOnce(receipt, "server-7", "access-7", present, target, true, 1_002L)
            is OfflineSshHandoffResult.Blocked)
    }

    @Test fun `wrong server consumes receipt and cannot be retried`() {
        val gate = OfflineSshConsentRehearsal()
        val receipt = armed(gate)
        val boundary = OfflineSshAuthorizationHandoff(gate)
        assertTrue(boundary.inspectOnce(receipt, "server-8", "access-7", present, target, true, 1_001)
            is OfflineSshHandoffResult.Blocked)
        assertTrue(boundary.inspectOnce(receipt, "server-7", "access-7", present, target, true, 1_002)
            is OfflineSshHandoffResult.Blocked)
    }

    @Test fun `changed pin changed access expired and revoked receipts fail closed`() {
        val gate = OfflineSshConsentRehearsal()
        val boundary = OfflineSshAuthorizationHandoff(gate)
        val changedPin = LocalSshReadinessResult.MetadataPresent(
            summary.copy(savedFingerprint = "SHA256:" + "B".repeat(43)),
        )
        assertTrue(boundary.inspectOnce(armed(gate), "server-7", "access-7", changedPin, target, true, 1_010)
            is OfflineSshHandoffResult.Blocked)
        assertTrue(boundary.inspectOnce(armed(gate), "server-7", "access-8", present, target, true, 1_010)
            is OfflineSshHandoffResult.Blocked)
        assertTrue(boundary.inspectOnce(armed(gate), "server-7", "access-7", present, target, true, 61_001)
            is OfflineSshHandoffResult.Blocked)
        val cancelled = armed(gate)
        gate.revoke()
        assertTrue(boundary.inspectOnce(cancelled, "server-7", "access-7", present, target, true, 1_010)
            is OfflineSshHandoffResult.Blocked)
    }

    @Test fun `mismatched target and missing final confirmation cannot authorize`() {
        val gate = OfflineSshConsentRehearsal()
        val boundary = OfflineSshAuthorizationHandoff(gate)
        assertTrue(boundary.inspectOnce(armed(gate), "server-7", "access-7", present, "wrong", true, 1_010)
            is OfflineSshHandoffResult.Blocked)
        assertTrue(boundary.inspectOnce(armed(gate), "server-7", "access-7", present, target, false, 1_010)
            is OfflineSshHandoffResult.Blocked)
    }

    @Test fun `parallel handoff attempts cannot both consume one receipt`() {
        val gate = OfflineSshConsentRehearsal()
        val receipt = armed(gate)
        val boundary = OfflineSshAuthorizationHandoff(gate)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val ready = CountDownLatch(2)
            val start = CountDownLatch(1)
            val tasks = (1..2).map {
                pool.submit<OfflineSshHandoffResult> {
                    ready.countDown()
                    if (!start.await(2, TimeUnit.SECONDS)) throw AssertionError("test latch timeout")
                    boundary.inspectOnce(receipt, "server-7", "access-7", present, target, true, 1_010)
                }
            }
            assertTrue(ready.await(2, TimeUnit.SECONDS))
            start.countDown()
            val results = tasks.map { it.get(2, TimeUnit.SECONDS) }
            assertEquals(1, results.count { it is OfflineSshHandoffResult.Inspected })
            assertEquals(1, results.count { it is OfflineSshHandoffResult.Blocked })
        } finally {
            pool.shutdownNow()
        }
    }
}
