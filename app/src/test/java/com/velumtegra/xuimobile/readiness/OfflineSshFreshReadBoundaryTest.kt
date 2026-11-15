package com.velumtegra.xuimobile.readiness

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** No Android device, sockets, secrets or repository writes: all reads use a fake local port. */
class OfflineSshFreshReadBoundaryTest {
    private val summary = LocalSshAccessSummary(
        "access-7", "node.example", 22, "operator", "Пароль (ссылка на секрет)", "SHA256:" + "A".repeat(43),
    )
    private val latest = LocalSshReadinessResult.MetadataPresent(summary)
    private val target = "operator@node.example:22"
    private val draft = OfflineSshConnectionDraft(
        "server-7", "access-7", summary.host, summary.port,
        summary.username, summary.authLabel, summary.savedFingerprint,
    )
    private fun arm(gate: OfflineSshConsentRehearsal) = (gate.arm(
        draft, latest, target, true, 1_000L, "offline-only",
    ) as OfflineSshConsentResult.Armed).receipt

    private fun port(read: suspend () -> LocalSshReadinessResult): SshReadinessPort = object : SshReadinessPort {
        override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(summary))
        override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
            assertEquals("server-7", serverId)
            assertEquals("access-7", accessId)
            return read()
        }
    }

    @Test fun `fresh read consumes before suspension and never grants network`() = runBlocking {
        val gate = OfflineSshConsentRehearsal()
        val receipt = arm(gate)
        val waiting = CompletableDeferred<LocalSshReadinessResult>()
        var reads = 0
        val boundary = OfflineSshAuthorizationHandoff(gate)
        val task = async {
            boundary.inspectWithFreshLocalRead(receipt, "server-7", "access-7", port {
                reads++
                waiting.await()
            }, target, true) { 1_020L }
        }
        while (reads == 0) yield()
        // A second attempt consumes no new capability and invalidates the pending attempt.
        val replay = boundary.inspectWithFreshLocalRead(receipt, "server-7", "access-7", port { latest }, target, true) { 1_021L }
        assertTrue(replay is OfflineSshHandoffResult.Blocked)
        waiting.complete(latest)
        assertTrue(task.await() is OfflineSshHandoffResult.Blocked)
        assertEquals(1, reads)
    }

    @Test fun `exact fresh metadata is inspected once and cannot be replayed`() = runBlocking {
        val gate = OfflineSshConsentRehearsal()
        val receipt = arm(gate)
        val boundary = OfflineSshAuthorizationHandoff(gate)
        var reads = 0
        val local = port { reads++; latest }
        val inspected = boundary.inspectWithFreshLocalRead(receipt, "server-7", "access-7", local, target, true) { 1_020L }
        assertTrue(inspected is OfflineSshHandoffResult.Inspected)
        val result = inspected as OfflineSshHandoffResult.Inspected
        assertFalse(result.authorizesNetwork)
        assertFalse(result.authorizesSecretRead)
        assertFalse(result.authorizesSshSession)
        assertFalse(result.authorizesVpsCommands)
        assertTrue(boundary.inspectWithFreshLocalRead(receipt, "server-7", "access-7", local, target, true) { 1_021L }
            is OfflineSshHandoffResult.Blocked)
        assertEquals(1, reads)
    }

    @Test fun `revocation during suspended local read blocks returned metadata`() = runBlocking {
        val gate = OfflineSshConsentRehearsal()
        val receipt = arm(gate)
        val deferred = CompletableDeferred<LocalSshReadinessResult>()
        var reads = 0
        val task = async {
            OfflineSshAuthorizationHandoff(gate).inspectWithFreshLocalRead(
                receipt, "server-7", "access-7", port { reads++; deferred.await() }, target, true,
            ) { 1_020L }
        }
        while (reads == 0) yield()
        gate.revoke()
        deferred.complete(latest)
        assertTrue(task.await() is OfflineSshHandoffResult.Blocked)
    }

    @Test fun `late changed pin and repository errors fail closed`() = runBlocking {
        val gate = OfflineSshConsentRehearsal()
        val boundary = OfflineSshAuthorizationHandoff(gate)
        val changed = LocalSshReadinessResult.MetadataPresent(summary.copy(savedFingerprint = "SHA256:" + "B".repeat(43)))
        assertTrue(boundary.inspectWithFreshLocalRead(arm(gate), "server-7", "access-7", port { changed }, target, true) { 1_010L }
            is OfflineSshHandoffResult.Blocked)
        val receipt = arm(gate)
        assertTrue(boundary.inspectWithFreshLocalRead(receipt, "server-7", "access-7", port {
            throw IllegalStateException("local repository error")
        }, target, true) { 1_010L } is OfflineSshHandoffResult.Blocked)
        assertTrue(boundary.inspectWithFreshLocalRead(receipt, "server-7", "access-7", port { latest }, target, true) { 1_010L }
            is OfflineSshHandoffResult.Blocked)
    }

    @Test fun `expired consent and changed selected server skip or block local inspection`() = runBlocking {
        val gate = OfflineSshConsentRehearsal()
        val boundary = OfflineSshAuthorizationHandoff(gate)
        var reads = 0
        val local = port { reads++; latest }
        assertTrue(boundary.inspectWithFreshLocalRead(arm(gate), "server-8", "access-7", local, target, true) { 1_020L }
            is OfflineSshHandoffResult.Blocked)
        assertEquals(0, reads)
        assertTrue(boundary.inspectWithFreshLocalRead(arm(gate), "server-7", "access-7", local, target, true) { 61_001L }
            is OfflineSshHandoffResult.Blocked)
        assertEquals(1, reads)
    }

    @Test fun `cancelled suspended read revokes receipt`() = runBlocking {
        val gate = OfflineSshConsentRehearsal()
        val receipt = arm(gate)
        val waiting = CompletableDeferred<LocalSshReadinessResult>()
        var reads = 0
        val boundary = OfflineSshAuthorizationHandoff(gate)
        val task = async {
            boundary.inspectWithFreshLocalRead(receipt, "server-7", "access-7", port {
                reads++
                waiting.await()
            }, target, true) { 1_020L }
        }
        while (reads == 0) yield()
        task.cancel()
        try { task.await() } catch (_: CancellationException) { /* cancellation is propagated */ }
        assertTrue(boundary.inspectWithFreshLocalRead(receipt, "server-7", "access-7", port { latest }, target, true) { 1_021L }
            is OfflineSshHandoffResult.Blocked)
    }
}
