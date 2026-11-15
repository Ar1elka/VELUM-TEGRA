package com.velumtegra.xuimobile.readiness

import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Phase14.2H: changed NON-SECRET reference IDs invalidate ALL offline confirmation stages. */
class OfflineSshCredentialReferenceBoundaryTest {
    private val target = "operator@node.example:22"
    private val digestA = LocalSshReadinessPolicy.credentialRefDigest(SshAuthRef.Password(SecretId("credential-a")))!!
    private val digestB = LocalSshReadinessPolicy.credentialRefDigest(SshAuthRef.Password(SecretId("credential-b")))!!
    private val original = LocalSshAccessSummary(
        "access-7", "node.example", 22, "operator", "Пароль (ссылка на секрет)",
        "SHA256:" + "A".repeat(43), digestA,
    )
    private val inspected = LocalSshReadinessResult.MetadataPresent(original)
    private val changed = LocalSshReadinessResult.MetadataPresent(original.copy(credentialRefDigest = digestB))
    private fun draft(): OfflineSshConnectionDraft = (OfflineSshConnectionDraftPolicy.prepare(
        "server-7", "access-7", inspected, inspected, target, true,
    ) as OfflineSshConnectionDraftResult.Prepared).draft

    @Test fun `credential reference digest is stable and distinguishes different ids and methods`() {
        assertEquals(digestA, LocalSshReadinessPolicy.credentialRefDigest(SshAuthRef.Password(SecretId("credential-a"))))
        assertFalse(digestA == digestB)
        assertFalse(digestA == LocalSshReadinessPolicy.credentialRefDigest(SshAuthRef.PrivateKey(SecretId("credential-a"))))
        assertEquals(64, digestA.length)
        assertFalse(digestA.contains("credential-a"))
        assertEquals(null, LocalSshReadinessPolicy.credentialRefDigest(SshAuthRef.Password(SecretId(""))))
    }

    @Test fun `changed credential reference refuses offline draft with same displayed auth method`() {
        assertTrue(OfflineSshConnectionDraftPolicy.prepare(
            "server-7", "access-7", inspected, changed, target, true,
        ) is OfflineSshConnectionDraftResult.Blocked)
        assertEquals(digestA, draft().credentialRefDigest)
    }

    @Test fun `changed credential reference refuses arming and consumes later simulated attempt`() {
        val gate = OfflineSshConsentRehearsal()
        assertTrue(gate.arm(draft(), changed, target, true, 1_000L, "marker-a") is OfflineSshConsentResult.Blocked)
        val receipt = (gate.arm(draft(), inspected, target, true, 1_000L, "marker-b") as OfflineSshConsentResult.Armed).receipt
        assertTrue(gate.simulateOneTimeUse(receipt, changed, target, true, 1_020L) is OfflineSshConsentResult.Blocked)
        assertTrue(gate.simulateOneTimeUse(receipt, inspected, target, true, 1_021L) is OfflineSshConsentResult.Blocked)
    }

    @Test fun `changed credential reference denies fresh local read and cannot replay receipt`() = runBlocking {
        val gate = OfflineSshConsentRehearsal()
        val receipt = (gate.arm(draft(), inspected, target, true, 1_000L, "marker") as OfflineSshConsentResult.Armed).receipt
        var reads = 0
        val port = object : SshReadinessPort {
            override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(original))
            override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
                assertEquals("server-7", serverId)
                assertEquals("access-7", accessId)
                reads++
                return if (reads == 1) changed else inspected
            }
        }
        val boundary = OfflineSshAuthorizationHandoff(gate)
        assertTrue(boundary.inspectWithFreshLocalRead(receipt, "server-7", "access-7", port,
            target, true) { 1_020L } is OfflineSshHandoffResult.Blocked)
        assertTrue(boundary.inspectWithFreshLocalRead(receipt, "server-7", "access-7", port,
            target, true) { 1_021L } is OfflineSshHandoffResult.Blocked)
        assertEquals(1, reads)
    }
}
