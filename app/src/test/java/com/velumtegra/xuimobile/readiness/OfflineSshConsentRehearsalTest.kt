package com.velumtegra.xuimobile.readiness

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OfflineSshConsentRehearsalTest {
    private val summary = LocalSshAccessSummary(
        "access-7", "node.example", 22, "operator", "Пароль (ссылка на секрет)", "SHA256:" + "A".repeat(43),
    )
    private val metadata = LocalSshReadinessResult.MetadataPresent(summary)
    private val draft = (OfflineSshConnectionDraftPolicy.prepare(
        "server-7", "access-7", metadata, metadata, "operator@node.example:22", true,
    ) as OfflineSshConnectionDraftResult.Prepared).draft

    @Test fun `time-bounded receipt is not a permission and can be consumed only once`() {
        val gate = OfflineSshConsentRehearsal()
        val armed = gate.arm(draft, metadata, "operator@node.example:22", true, 1000, "rehearsal-one")
        assertTrue(armed is OfflineSshConsentResult.Armed)
        val receipt = (armed as OfflineSshConsentResult.Armed).receipt
        assertEquals(61_000L, receipt.expiresAtElapsedMs)
        assertFalse(receipt.permitsNetwork)
        assertFalse(receipt.permitsSecretRead)
        assertFalse(receipt.permitsSshAuthentication)
        assertFalse(receipt.permitsVpsCommands)
        assertTrue(gate.simulateOneTimeUse(receipt, metadata, "operator@node.example:22", true, 1200)
            is OfflineSshConsentResult.SimulatedOnce)
        assertTrue(gate.simulateOneTimeUse(receipt, metadata, "operator@node.example:22", true, 1201)
            is OfflineSshConsentResult.Blocked)
    }

    @Test fun `fresh metadata mismatch blocks arming and use and consumes failed receipt`() {
        val gate = OfflineSshConsentRehearsal()
        val changedPin = LocalSshReadinessResult.MetadataPresent(summary.copy(savedFingerprint = "SHA256:" + "B".repeat(43)))
        assertTrue(gate.arm(draft, changedPin, "operator@node.example:22", true, 1000, "marker")
            is OfflineSshConsentResult.Blocked)
        val receipt = (gate.arm(draft, metadata, "operator@node.example:22", true, 1000, "marker")
            as OfflineSshConsentResult.Armed).receipt
        assertTrue(gate.simulateOneTimeUse(receipt, changedPin, "operator@node.example:22", true, 1200)
            is OfflineSshConsentResult.Blocked)
        assertTrue(gate.simulateOneTimeUse(receipt, metadata, "operator@node.example:22", true, 1201)
            is OfflineSshConsentResult.Blocked)
    }

    @Test fun `expired revoked and backward-clock receipts fail closed`() {
        val gate = OfflineSshConsentRehearsal()
        val expired = (gate.arm(draft, metadata, "operator@node.example:22", true, 1000, "one")
            as OfflineSshConsentResult.Armed).receipt
        assertTrue(gate.simulateOneTimeUse(expired, metadata, "operator@node.example:22", true, 61001)
            is OfflineSshConsentResult.Blocked)
        val backwards = (gate.arm(draft, metadata, "operator@node.example:22", true, 1000, "two")
            as OfflineSshConsentResult.Armed).receipt
        assertTrue(gate.simulateOneTimeUse(backwards, metadata, "operator@node.example:22", true, 999)
            is OfflineSshConsentResult.Blocked)
        val revoked = (gate.arm(draft, metadata, "operator@node.example:22", true, 2000, "three")
            as OfflineSshConsentResult.Armed).receipt
        gate.revoke()
        assertTrue(gate.simulateOneTimeUse(revoked, metadata, "operator@node.example:22", true, 2001)
            is OfflineSshConsentResult.Blocked)
    }

    @Test fun `target mismatch missing consent and invalid time never arm`() {
        val gate = OfflineSshConsentRehearsal()
        assertTrue(gate.arm(draft, metadata, "wrong", true, 1000, "marker") is OfflineSshConsentResult.Blocked)
        assertTrue(gate.arm(draft, metadata, "operator@node.example:22", false, 1000, "marker") is OfflineSshConsentResult.Blocked)
        assertTrue(gate.arm(draft, metadata, "operator@node.example:22", true, -1, "marker") is OfflineSshConsentResult.Blocked)
        assertTrue(gate.arm(draft, metadata, "operator@node.example:22", true, Long.MAX_VALUE, "marker") is OfflineSshConsentResult.Blocked)
        assertTrue(gate.arm(draft, metadata, "operator@node.example:22", true, 1000, "") is OfflineSshConsentResult.Blocked)
        assertTrue(gate.arm(draft, LocalSshReadinessResult.Blocked("not found"),
            "operator@node.example:22", true, 1000, "marker") is OfflineSshConsentResult.Blocked)
    }
}
