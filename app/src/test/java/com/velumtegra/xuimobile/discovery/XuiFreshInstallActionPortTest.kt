package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.runtime.InstallerExplicitConsentRegistrationResult
import com.velumtegra.xuimobile.core.runtime.InstallerExplicitInstallConsent
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessPolicy
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostStartResult
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class XuiFreshInstallActionPortTest {
    private val at = Instant.parse("2026-11-06T10:00:00Z")
    private val serverId = ServerId("server-1")
    private val pin = CanonicalHostKeyFingerprint.fromRawHostKey(byteArrayOf(1, 2, 3)).asModel()

    private fun access(user: String = "root", secret: String = "ref-1", id: String = "acc-1", server: ServerId = serverId) = ServerAccess(
        ServerAccessId(id), server, SshEndpoint("203.0.113.5", 22), user, SshAuthRef.Password(SecretId(secret)), pin,
    )

    private fun summary(a: ServerAccess) =
        (LocalSshReadinessPolicy.inspect(a.serverId.value, a.id.value, a) as LocalSshReadinessResult.MetadataPresent).summary

    private class Fixture {
        var currentAccess: ServerAccess? = null
        var serverPresent = true
        var installations: List<VersionedRecord<com.velumtegra.xuimobile.core.model.XuiInstallation>> = emptyList()
        var hostResult = ExactOperationHostStartResult.START_REQUEST_ACCEPTED
        var registerResult: InstallerExplicitConsentRegistrationResult = InstallerExplicitConsentRegistrationResult.Registered
        var onHostStart: (OperationId) -> Unit = {}
        var onRegister: () -> Unit = {}
        val registered = mutableListOf<InstallerExplicitInstallConsent>()
        val discarded = mutableListOf<OperationId>()
        val hostStarts = mutableListOf<OperationId>()
        val rows = mutableListOf<VersionedOperationSnapshot>()
        var counter = 0
    }

    private fun build(f: Fixture, a: ServerAccess): ProductionXuiFreshInstallActionPort {
        f.currentAccess = a
        val journal = object : OperationJournal {
            override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
                val v = VersionedOperationSnapshot(initial, OperationRevision(0)); f.rows += v; return OperationJournalResult.Success(v)
            }
            override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
                f.rows.firstOrNull { it.snapshot.operationId == operationId }?.let { OperationJournalResult.Success(it) } ?: OperationJournalResult.NotFound
            override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
                OperationJournalResult.Success(f.rows.filter { it.snapshot.status !in setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED) })
            override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
                val i = f.rows.indexOfFirst { it.snapshot.operationId == operationId }
                if (i < 0) return OperationJournalResult.NotFound
                if (f.rows[i].revision != expectedRevision) return OperationJournalResult.StaleRevision(expectedRevision, f.rows[i].revision)
                val v = VersionedOperationSnapshot(next, OperationRevision(expectedRevision.value + 1)); f.rows[i] = v
                return OperationJournalResult.Success(v)
            }
            override suspend fun history(operationId: OperationId) = OperationJournalResult.Success(emptyList<OperationJournalEntry>())
        }
        val servers = object : ServerRepository {
            override suspend fun get(serverId: ServerId): RepositoryResult<VersionedRecord<Server>> =
                if (f.serverPresent) RepositoryResult.Success(VersionedRecord(Server(serverId, "S", at), RecordRevision(1))) else RepositoryResult.NotFound
            override suspend fun list() = error("unused")
            override suspend fun create(server: Server) = error("unused")
            override suspend fun update(server: Server, expectedRevision: RecordRevision) = error("unused")
            override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision) = error("unused")
        }
        val accesses = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> =
                f.currentAccess?.takeIf { it.id == serverAccessId }?.let { RepositoryResult.Success(it) } ?: RepositoryResult.NotFound
            override suspend fun listForServer(serverId: ServerId) = error("unused")
            override suspend fun delete(serverAccessId: ServerAccessId) = error("unused")
        }
        val installs = object : XuiInstallationRepository {
            override suspend fun get(installationId: com.velumtegra.xuimobile.core.model.XuiInstallationId) = error("unused")
            override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(f.installations)
            override suspend fun create(installation: com.velumtegra.xuimobile.core.model.XuiInstallation) = error("unused")
            override suspend fun update(installation: com.velumtegra.xuimobile.core.model.XuiInstallation, expectedRevision: RecordRevision) = error("unused")
            override suspend fun delete(installationId: com.velumtegra.xuimobile.core.model.XuiInstallationId, expectedRevision: RecordRevision) = error("unused")
        }
        val runtime = object : XuiFreshInstallConsentRuntime {
            override fun register(consent: InstallerExplicitInstallConsent): InstallerExplicitConsentRegistrationResult {
                f.registered += consent; f.onRegister(); return f.registerResult
            }
            override fun discard(operationId: OperationId): Boolean { f.discarded += operationId; return true }
        }
        return ProductionXuiFreshInstallActionPort(servers, accesses, installs, journal, runtime,
            { id -> f.hostStarts += id; f.onHostStart(id); f.hostResult }, { at }, { "%032x".format(++f.counter) })
    }

    @Test fun `confirmed start creates exact INSTALL row registers one consent and starts the host once`() = runSuspend {
        val f = Fixture(); val a = access(); val p = build(f, a)
        val result = p.startConfirmed("server-1", summary(a)) as XuiFreshInstallStart.Recorded
        val row = f.rows.single().snapshot
        assertEquals(result.operationId, row.operationId.value)
        assertEquals(OperationType.INSTALL, row.type)
        assertEquals(OperationTarget.ServerTarget(serverId, a.id), row.target)
        assertEquals(CheckpointSemantics.MUTATION_NOT_STARTED, row.checkpoint.semantics)
        assertEquals(OperationStatus.RUNNING, row.status)
        val consent = f.registered.single()
        assertEquals(a, consent.access); assertEquals(row.operationId, consent.operationId)
        assertEquals(f.rows.single().revision, consent.expectedRevision)
        assertEquals(1, f.hostStarts.size)
        assertTrue(f.discarded.isEmpty())
    }

    @Test fun `changed profile or missing server blocks before any journal write`() = runSuspend {
        val f = Fixture(); val a = access(); val p = build(f, a)
        val reviewed = summary(a)
        f.currentAccess = access(user = "other")
        assertTrue(p.startConfirmed("server-1", reviewed) is XuiFreshInstallStart.Blocked)
        f.currentAccess = access(secret = "ref-2")
        assertTrue(p.startConfirmed("server-1", reviewed) is XuiFreshInstallStart.Blocked)
        f.currentAccess = a; f.serverPresent = false
        assertTrue(p.startConfirmed("server-1", reviewed) is XuiFreshInstallStart.Blocked)
        assertTrue(f.rows.isEmpty()); assertTrue(f.hostStarts.isEmpty()); assertTrue(f.registered.isEmpty())
    }

    @Test fun `existing local installation or unfinished install on the whole vps blocks`() = runSuspend {
        val f = Fixture(); val a = access(); val p = build(f, a)
        val other = access(id = "acc-2")
        // An unfinished INSTALL through ANOTHER access of the same VPS blocks the new one.
        f.rows += VersionedOperationSnapshot(OperationSnapshot(OperationId("old"), OperationType.INSTALL, OperationTarget.ServerTarget(serverId, other.id),
            OperationStatus.RUNNING, OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, at), at, at), OperationRevision(0))
        assertTrue(p.startConfirmed("server-1", summary(a)) is XuiFreshInstallStart.Blocked)
        assertEquals(1, f.rows.size); assertTrue(f.hostStarts.isEmpty())
    }

    @Test fun `durable uncertain mutation barrier blocks`() = runSuspend {
        val f = Fixture(); val a = access(); val p = build(f, a)
        f.rows += VersionedOperationSnapshot(OperationSnapshot(OperationId("restart"), OperationType.RESTART, OperationTarget.ServerTarget(serverId, a.id),
            OperationStatus.RUNNING, OperationCheckpoint("X", CheckpointSemantics.RESTART_IN_FLIGHT, at), at, at), OperationRevision(0))
        assertTrue(p.startConfirmed("server-1", summary(a)) is XuiFreshInstallStart.Blocked)
        assertTrue(f.hostStarts.isEmpty())
    }

    @Test fun `host rejection fails before dispatch by CAS and discards consent`() = runSuspend {
        val f = Fixture(); val a = access(); f.hostResult = ExactOperationHostStartResult.NOT_ALLOWED_FROM_CURRENT_STATE
        val p = build(f, a)
        p.startConfirmed("server-1", summary(a))
        val row = f.rows.single().snapshot
        assertEquals(OperationStatus.FAILED, row.status); assertEquals("INSTALL_HOST_NOT_STARTED", row.checkpoint.phaseName)
        assertEquals(listOf(row.operationId), f.discarded)
    }

    @Test fun `late host progress is never overwritten by the fail-before-dispatch CAS`() = runSuspend {
        val f = Fixture(); val a = access(); f.hostResult = ExactOperationHostStartResult.SERVICE_UNAVAILABLE
        val p = build(f, a)
        f.onHostStart = { id ->
            // The host already advanced the row (MUTATION_IN_FLIGHT) before the start result came back.
            val cur = f.rows.single()
            f.rows[0] = VersionedOperationSnapshot(cur.snapshot.copy(checkpoint = OperationCheckpoint("DOWNLOADING", CheckpointSemantics.MUTATION_IN_FLIGHT, at)), OperationRevision(1))
        }
        p.startConfirmed("server-1", summary(a))
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, f.rows.single().snapshot.checkpoint.semantics)
        assertEquals(OperationStatus.RUNNING, f.rows.single().snapshot.status)
    }

    @Test fun `consent registration refusal fails before dispatch and never starts the host`() = runSuspend {
        val f = Fixture(); val a = access(); f.registerResult = InstallerExplicitConsentRegistrationResult.Conflict
        val p = build(f, a)
        p.startConfirmed("server-1", summary(a))
        assertEquals(OperationStatus.FAILED, f.rows.single().snapshot.status); assertTrue(f.hostStarts.isEmpty())
    }

    @Test fun `profile changing after consent registration discards it and fails before dispatch`() = runSuspend {
        val f = Fixture(); val a = access(); val p = build(f, a)
        f.onRegister = { f.currentAccess = access(user = "other") }
        p.startConfirmed("server-1", summary(a))
        val row = f.rows.single().snapshot
        assertEquals(OperationStatus.FAILED, row.status)
        assertEquals(listOf(row.operationId), f.discarded)
        assertTrue(f.hostStarts.isEmpty())
    }

    @Test fun `recovery returns only rows bound to the exact profile and counts other profiles as blockers`() = runSuspend {
        val f = Fixture(); val a = access(); val p = build(f, a)
        val own = XuiFreshInstallProfileBinding.operationId("a".repeat(32), "server-1", summary(a))
        val changed = access(secret = "ref-2")  // same access id, different credential reference
        val foreign = XuiFreshInstallProfileBinding.operationId("b".repeat(32), "server-1", summary(changed))
        fun row(id: OperationId, semantics: CheckpointSemantics, acc: ServerAccessId = a.id) = VersionedOperationSnapshot(OperationSnapshot(id, OperationType.INSTALL,
            OperationTarget.ServerTarget(serverId, acc), OperationStatus.RUNNING, OperationCheckpoint("X", semantics, at), at, at), OperationRevision(0))
        f.rows += row(own, CheckpointSemantics.MUTATION_IN_FLIGHT)
        f.rows += row(foreign, CheckpointSemantics.POST_VERIFY_REQUIRED)
        f.rows += row(OperationId("legacy"), CheckpointSemantics.MUTATION_NOT_STARTED)
        val recovery = p.recoverExact("server-1", summary(a))
        assertEquals(listOf(own.value), recovery.own.map { it.operationId })
        assertEquals(2, recovery.otherProfileBlockers)
        // Changed profile cannot see, check or cancel the old row.
        f.currentAccess = changed
        assertTrue(p.recoverExact("server-1", summary(changed)).own.map { it.operationId } == listOf(foreign.value))
        assertNull(p.statusExact(own.value, "server-1", summary(changed)))
        assertTrue(p.checkResultConfirmed(own.value, "server-1", summary(changed)) != null)
        assertTrue(p.cancelBeforeDispatch(own.value, "server-1", summary(changed)) != null)
        assertTrue(f.hostStarts.isEmpty())
    }

    @Test fun `check result starts the host only for dispatched states and never for pending or terminal rows`() = runSuspend {
        val f = Fixture(); val a = access(); val p = build(f, a)
        fun add(n: String, sem: CheckpointSemantics, st: OperationStatus = OperationStatus.RUNNING): String {
            val id = XuiFreshInstallProfileBinding.operationId(n.repeat(32), "server-1", summary(a))
            f.rows += VersionedOperationSnapshot(OperationSnapshot(id, OperationType.INSTALL, OperationTarget.ServerTarget(serverId, a.id), st,
                OperationCheckpoint("X", sem, at), at, at), OperationRevision(0)); return id.value
        }
        val pending = add("1", CheckpointSemantics.MUTATION_NOT_STARTED)
        assertTrue(p.checkResultConfirmed(pending, "server-1", summary(a)) != null)
        for ((n, sem) in listOf("2" to CheckpointSemantics.MUTATION_IN_FLIGHT, "3" to CheckpointSemantics.POST_VERIFY_REQUIRED, "4" to CheckpointSemantics.COMMIT_VERIFIED)) {
            f.hostStarts.clear()
            assertNull(p.checkResultConfirmed(add(n, sem), "server-1", summary(a)))
            assertEquals(1, f.hostStarts.size)
        }
        f.hostStarts.clear()
        val done = add("5", CheckpointSemantics.TERMINAL, OperationStatus.SUCCEEDED)
        assertTrue(p.checkResultConfirmed(done, "server-1", summary(a)) != null)
        assertTrue(f.hostStarts.isEmpty())
    }

    @Test fun `pending can be cancelled by CAS only before dispatch and success needs the verified terminal phase`() = runSuspend {
        val f = Fixture(); val a = access(); val p = build(f, a)
        val started = p.startConfirmed("server-1", summary(a)) as XuiFreshInstallStart.Recorded
        val observed = checkNotNull(p.statusExact(started.operationId, "server-1", summary(a)))
        assertTrue(observed.mayCancelBeforeDispatch); assertFalse(observed.mayCheckReadOnly); assertFalse(observed.succeeded)
        assertNull(p.cancelBeforeDispatch(started.operationId, "server-1", summary(a)))
        assertEquals(OperationStatus.CANCELLED, f.rows.single().snapshot.status)
        assertEquals(listOf(OperationId(started.operationId)), f.discarded)
        // A second cancel (or any relaunch) is refused.
        assertTrue(p.cancelBeforeDispatch(started.operationId, "server-1", summary(a)) != null)

        // Once dispatched, cancellation is impossible and only read-only check is offered.
        val f2 = Fixture(); val p2 = build(f2, a)
        val s2 = p2.startConfirmed("server-1", summary(a)) as XuiFreshInstallStart.Recorded
        val cur = f2.rows.single()
        f2.rows[0] = VersionedOperationSnapshot(cur.snapshot.copy(checkpoint = OperationCheckpoint("VERIFYING", CheckpointSemantics.POST_VERIFY_REQUIRED, at)), OperationRevision(1))
        val flight = checkNotNull(p2.statusExact(s2.operationId, "server-1", summary(a)))
        assertTrue(flight.mayCheckReadOnly); assertFalse(flight.mayCancelBeforeDispatch); assertFalse(flight.terminal); assertFalse(flight.succeeded)
        assertTrue(p2.cancelBeforeDispatch(s2.operationId, "server-1", summary(a)) != null)
        // Only the exact verified-publish terminal phase may show success.
        val cur2 = f2.rows.single()
        f2.rows[0] = VersionedOperationSnapshot(cur2.snapshot.copy(status = OperationStatus.SUCCEEDED, checkpoint = OperationCheckpoint("OTHER", CheckpointSemantics.TERMINAL, at)), OperationRevision(2))
        assertFalse(checkNotNull(p2.statusExact(s2.operationId, "server-1", summary(a))).succeeded)
        f2.rows[0] = VersionedOperationSnapshot(f2.rows[0].snapshot.copy(checkpoint = OperationCheckpoint("INSTALLER_RESULT_SUCCESS", CheckpointSemantics.TERMINAL, at)), OperationRevision(3))
        assertTrue(checkNotNull(p2.statusExact(s2.operationId, "server-1", summary(a))).succeeded)
    }

    @Test fun `operation ids carry a stable profile digest and differ per profile`() {
        val a = summary(access()); val b = summary(access(secret = "ref-2"))
        assertEquals(XuiFreshInstallProfileBinding.digest("server-1", a), XuiFreshInstallProfileBinding.digest("server-1", a))
        assertNotEquals(XuiFreshInstallProfileBinding.digest("server-1", a), XuiFreshInstallProfileBinding.digest("server-1", b))
        assertTrue(XuiFreshInstallProfileBinding.isFeatureId(XuiFreshInstallProfileBinding.operationId("c".repeat(32), "server-1", a)))
        assertFalse(XuiFreshInstallProfileBinding.isFeatureId(OperationId("legacy")))
    }
}

private fun <T> runSuspend(block: suspend () -> T): T {
    var result: Result<T>? = null
    block.startCoroutine(object : Continuation<T> {
        override val context = EmptyCoroutineContext
        override fun resumeWith(value: Result<T>) { result = value }
    })
    return result!!.getOrThrow()
}
