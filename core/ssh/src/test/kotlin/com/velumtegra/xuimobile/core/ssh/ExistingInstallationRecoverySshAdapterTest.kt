package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.nio.charset.StandardCharsets
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ExistingInstallationRecoverySshAdapterTest {
    @Test
    fun `read only diagnosis emits repair authority only for inactive service and absent listener`() = runSuspend {
        val f = Fixture { command, _ ->
            when {
                command.rawForTransport().contains("is-active") -> success("inactive\n")
                command.rawForTransport().contains("ss ") || command.rawForTransport().contains("/proc/net") -> failure(1)
                else -> success()
            }
        }
        val before = f.journal.current
        val result = f.diagnoser.diagnose(f.preflight, before, f.installation, f.session)
            as ExistingInstallationRecoveryDiagnosisResult.Diagnosed
        assertEquals(ExistingInstallationRecoveryDiagnosis.EXACT_SERVICE_INACTIVE_LISTENER_ABSENT, result.evidence.diagnosis)
        assertTrue(result.repairDecision is ExistingInstallationRecoveryRepairPolicyResult.Verified)
        assertEquals(before, f.journal.current)
        assertEquals(0, f.journal.advanceCalls)
        assertTrue(f.session.commands.none { it.rawForTransport().contains("systemctl start") })
    }

    @Test
    fun `healthy diagnosis never creates repair mutation authority`() = runSuspend {
        val f = Fixture { command, _ ->
            when {
                command.rawForTransport().contains("is-active") -> success("active\n")
                else -> success()
            }
        }
        val result = f.diagnoser.diagnose(f.preflight, f.journal.current, f.installation, f.session)
            as ExistingInstallationRecoveryDiagnosisResult.Diagnosed
        assertEquals(ExistingInstallationRecoveryDiagnosis.HEALTHY, result.evidence.diagnosis)
        assertTrue(result.repairDecision is ExistingInstallationRecoveryRepairPolicyResult.NoRepairRequired)
        assertEquals(0, f.journal.advanceCalls)
    }

    @Test
    fun `repair persists mutation in flight before one exact start command`() = runSuspend {
        lateinit var f: Fixture
        f = Fixture { command, _ ->
            when {
                command.rawForTransport().contains("is-active") -> success("inactive\n")
                command.rawForTransport().contains("ss ") || command.rawForTransport().contains("/proc/net") -> failure(1)
                command.rawForTransport() == "systemctl start x-ui.service" -> {
                    assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, f.journal.current.snapshot.checkpoint.semantics)
                    success()
                }
                else -> success()
            }
        }
        val diagnosed = f.diagnoser.diagnose(f.preflight, f.journal.current, f.installation, f.session)
            as ExistingInstallationRecoveryDiagnosisResult.Diagnosed
        val repair = (diagnosed.repairDecision as ExistingInstallationRecoveryRepairPolicyResult.Verified).repair
        f.session.commands.clear()
        val result = f.repair.dispatch(repair, f.journal.current, f.session)
            as ExistingInstallationRecoveryRepairResult.PostVerifyRequired
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, result.durable.snapshot.checkpoint.semantics)
        assertEquals(listOf("systemctl start x-ui.service"), f.session.commands.map { it.rawForTransport() })
    }

    @Test
    fun `unknown after repair dispatch is never replayed and stays mutation in flight`() = runSuspend {
        val f = Fixture { command, _ ->
            when {
                command.rawForTransport().contains("is-active") -> success("inactive\n")
                command.rawForTransport().contains("ss ") || command.rawForTransport().contains("/proc/net") -> failure(1)
                command.rawForTransport() == "systemctl start x-ui.service" -> unknown()
                else -> success()
            }
        }
        val diagnosed = f.diagnoser.diagnose(f.preflight, f.journal.current, f.installation, f.session)
            as ExistingInstallationRecoveryDiagnosisResult.Diagnosed
        val repair = (diagnosed.repairDecision as ExistingInstallationRecoveryRepairPolicyResult.Verified).repair
        f.session.commands.clear()
        val result = f.repair.dispatch(repair, f.journal.current, f.session)
            as ExistingInstallationRecoveryRepairResult.ReconciliationRequired
        assertEquals(ExistingInstallationRecoveryReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH, result.reason)
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, result.durable.snapshot.checkpoint.semantics)
        assertEquals(1, f.session.commands.size)
    }

    private class Fixture(
        behavior: suspend (RemoteCommand, SshTransportConfig) -> SshCommandResult,
    ) {
        val now = Instant.parse("2026-09-13T11:50:00Z")
        val operationId = OperationId("phase95-recovery")
        val serverId = ServerId("phase95-server")
        val accessId = ServerAccessId("phase95-access")
        val installationId = XuiInstallationId("phase95-installation")
        val installation = XuiInstallation(
            installationId,
            serverId,
            InstallationOwnership.ADOPTED,
            InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
            InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", now.minusSeconds(600)),
        )
        val access = ServerAccess(
            accessId,
            serverId,
            SshEndpoint("203.0.113.95", 22),
            "root",
            SshAuthRef.Password(SecretId("phase95-secret")),
            HostKeyFingerprint("SHA256:phase95"),
        )
        val initial = VersionedOperationSnapshot(
            OperationSnapshot(
                operationId,
                OperationType.RECOVERY,
                OperationTarget.InstallationTarget(serverId, accessId, installationId),
                OperationStatus.RUNNING,
                OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, now.minusSeconds(10)),
                now.minusSeconds(60),
                now.minusSeconds(10),
            ),
            OperationRevision(4),
        )
        val journal = FakeJournal(initial)
        val preflight = verifiedPreflight(initial, installation, access, now)
        val binding = SessionBinding(SessionId("phase95-session"), accessId, SessionOwner.Operation(operationId))
        val session = FakeSession(binding, behavior)
        val diagnoser = ExistingInstallationRecoveryDiagnosisSshAdapter { now }
        val repair = ExistingInstallationRecoveryRepairSshAdapter(journal) { now }
    }

    private class FakeJournal(initial: VersionedOperationSnapshot) : OperationJournal {
        var current = initial
        var advanceCalls = 0
        override suspend fun create(initial: OperationSnapshot) = OperationJournalResult.StorageFailure("not used")
        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            if (operationId == current.snapshot.operationId) OperationJournalResult.Success(current) else OperationJournalResult.NotFound
        override suspend fun listNonTerminal() = OperationJournalResult.Success(listOf(current))
        override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
            advanceCalls++
            if (expectedRevision != current.revision) return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            return OperationJournalResult.Success(current)
        }
        override suspend fun history(operationId: OperationId) = OperationJournalResult.Success(emptyList<OperationJournalEntry>())
    }

    private class FakeSession(
        override val binding: SessionBinding,
        private val behavior: suspend (RemoteCommand, SshTransportConfig) -> SshCommandResult,
    ) : SshSessionHandle {
        val commands = mutableListOf<RemoteCommand>()
        override val isOpen = true
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            commands += command
            return behavior(command, config)
        }
        override fun close() = Unit
    }

    companion object {
        private fun verifiedPreflight(
            current: VersionedOperationSnapshot,
            installation: XuiInstallation,
            access: ServerAccess,
            now: Instant,
        ): VerifiedExistingInstallationActionPreflight {
            val proof = InstallationProof(TargetProofId("phase95-proof"), installation.id, installation.serverId, access.id, installation.identity, now.minusSeconds(3), now.plusSeconds(120))
            val target = (TargetProofPolicy.verifyKnownInstallation(installation, access, proof, now) as TargetVerificationResult.Verified).target
            val authorization = (ExistingInstallationActionAuthorizationPolicy.verify(current, installation, target, now) as ExistingInstallationActionAuthorizationResult.Verified).authorization
            val evidence = ExistingInstallationPreflightEvidence(
                ExistingInstallationActionScope(current.snapshot.operationId, current.revision.value, installation.serverId, access.id, installation.id, OperationType.RECOVERY, installation.ownership, null),
                proof,
                ExistingInstallationAccessPathState.EXACT_PINNED_AUTHENTICATED,
                ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1,
                ExistingInstallationPrivilegeCapability.DIRECT_ROOT,
                ExistingInstallationMutationBarrierState.PROVEN_CLEAR,
                now.minusSeconds(2),
                now.plusSeconds(60),
            )
            return (ExistingInstallationActionPreflightPolicy.verify(authorization, current, installation, evidence, now) as ExistingInstallationActionPreflightResult.Verified).preflight
        }
        private fun success(stdout: String = "") = SshCommandResult(
            CommandDispatchState.DISPATCHED,
            CommandCompletion.ConfirmedSuccess,
            CapturedOutput.of(stdout.toByteArray(StandardCharsets.UTF_8), false),
            CapturedOutput.EMPTY,
        )
        private fun failure(code: Int) = SshCommandResult(
            CommandDispatchState.DISPATCHED,
            CommandCompletion.ConfirmedFailure("fixture", code),
            CapturedOutput.EMPTY,
            CapturedOutput.EMPTY,
        )
        private fun unknown() = SshCommandResult(
            CommandDispatchState.DISPATCHED,
            CommandCompletion.Unknown("uncertain"),
            CapturedOutput.EMPTY,
            CapturedOutput.EMPTY,
        )
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
