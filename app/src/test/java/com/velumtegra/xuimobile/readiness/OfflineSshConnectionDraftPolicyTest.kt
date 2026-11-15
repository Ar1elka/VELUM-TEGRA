package com.velumtegra.xuimobile.readiness

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OfflineSshConnectionDraftPolicyTest {
    private fun summary(
        id: String = "access-7",
        host: String = "node.example",
        pin: String = "SHA256:" + "A".repeat(43),
        auth: String = "Пароль (ссылка на секрет)",
    ) = LocalSshAccessSummary(id, host, 22, "operator", auth, pin)
    private fun found(s: LocalSshAccessSummary) = LocalSshReadinessResult.MetadataPresent(s)
    private fun evaluate(
        reviewed: LocalSshReadinessResult? = found(summary()),
        latest: LocalSshReadinessResult = found(summary()),
        target: String = "operator@node.example:22",
        consent: Boolean = true,
        server: String = "server-7",
        access: String = "access-7",
    ) = OfflineSshConnectionDraftPolicy.prepare(server, access, reviewed, latest, target, consent)

    @Test fun `exact fresh metadata and second acknowledgement produce only a no-network draft`() {
        val result = evaluate()
        assertTrue(result is OfflineSshConnectionDraftResult.Prepared)
        val value = (result as OfflineSshConnectionDraftResult.Prepared).draft
        assertEquals("server-7", value.serverId)
        assertEquals("access-7", value.accessId)
        assertEquals("node.example", value.host)
        assertFalse(value.authorizesNetworkAccess)
        assertFalse(value.authorizesSshAuthentication)
        assertFalse(value.authorizesVpsMutation)
        assertFalse(value.toString().contains("SecretId"))
    }

    @Test fun `stale host pin access or endpoint differences fail closed`() {
        assertTrue(evaluate(latest = found(summary(id = "access-other"))) is OfflineSshConnectionDraftResult.Blocked)
        assertTrue(evaluate(latest = found(summary(host = "changed.example"))) is OfflineSshConnectionDraftResult.Blocked)
        assertTrue(evaluate(latest = found(summary(pin = "SHA256:" + "B".repeat(43)))) is OfflineSshConnectionDraftResult.Blocked)
        assertTrue(evaluate(access = "access-other") is OfflineSshConnectionDraftResult.Blocked)
        assertTrue(evaluate(server = "") is OfflineSshConnectionDraftResult.Blocked)
    }

    @Test fun `blocked state forged summary invalid confirmation and missing consent cannot proceed`() {
        assertTrue(evaluate(reviewed = null) is OfflineSshConnectionDraftResult.Blocked)
        assertTrue(evaluate(latest = LocalSshReadinessResult.Blocked("not found")) is OfflineSshConnectionDraftResult.Blocked)
        assertTrue(evaluate(consent = false) is OfflineSshConnectionDraftResult.Blocked)
        assertTrue(evaluate(target = "operator@wrong.example:22") is OfflineSshConnectionDraftResult.Blocked)
        assertTrue(evaluate(latest = found(summary(pin = "SHA256:bad")), reviewed = found(summary(pin = "SHA256:bad"))) is OfflineSshConnectionDraftResult.Blocked)
        assertTrue(evaluate(latest = found(summary(auth = "unexpected")), reviewed = found(summary(auth = "unexpected"))) is OfflineSshConnectionDraftResult.Blocked)
    }
}
