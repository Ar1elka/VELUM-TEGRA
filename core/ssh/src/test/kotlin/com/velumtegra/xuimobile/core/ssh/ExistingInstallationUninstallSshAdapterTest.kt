package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.nio.charset.StandardCharsets
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ExistingInstallationUninstallSshAdapterTest {
    @Test
    fun `compiler emits one exact official uninstall command and explicitly preserves postgresql`() {
        val fixture = Fixture()
        val compiled = ExistingInstallationUninstallCommandCompiler.compile(fixture.preflight, fixture.plan)
        checkNotNull(compiled)
        assertEquals(
            "[ -x /usr/bin/x-ui ] || exit 42; printf 'y\\nn\\n' | /usr/bin/x-ui uninstall",
            compiled.command.rawForTransport(),
        )
        assertTrue(compiled.command.rawForTransport().contains("printf 'y\\nn\\n'"))
        assertTrue(compiled.command.rawForTransport().endsWith("/usr/bin/x-ui uninstall"))
        assertFalse(compiled.command.rawForTransport().contains("purge"))
        assertFalse(compiled.command.rawForTransport().contains("postgres", ignoreCase = true))
        assertEquals(ReviewedExistingInstallationActionPlanPolicy.UNINSTALL_TIMEOUT, compiled.config.commandExecutionTimeout)
    }

    @Test
    fun `mutation in flight is durable before the single uninstall dispatch`() = runSuspend {
        lateinit var fixture: Fixture
        fixture = Fixture { _, _ ->
            assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, fixture.journal.current.snapshot.checkpoint.semantics)
            assertEquals("UNINSTALL_DISPATCHED", fixture.journal.current.snapshot.checkpoint.phaseName)
            success()
        }

        val result = fixture.adapter.dispatch(fixture.preflight, fixture.plan, fixture.journal.current, fixture.session)
            as ExistingInstallationUninstallDispatchResult.PostVerifyRequired

        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, result.durable.snapshot.checkpoint.semantics)
        assertEquals(1, fixture.session.commands.size)
        assertEquals(1, fixture.journal.advanceCalls)
    }

    @Test
    fun `confirmed nonzero after dispatch still requires absence proof instead of replay`() = runSuspend {
        val fixture = Fixture { _, _ -> failure(1) }

        val result = fixture.adapter.dispatch(fixture.preflight, fixture.plan, fixture.journal.current, fixture.session)

        assertTrue(result is ExistingInstallationUninstallDispatchResult.PostVerifyRequired)
        assertEquals(1, fixture.session.commands.size)
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, fixture.journal.current.snapshot.checkpoint.semantics)
    }

    @Test
    fun `unknown after dispatch is never retried and remains reconciliation required`() = runSuspend {
        val fixture = Fixture { _, _ -> unknown() }

        val result = fixture.adapter.dispatch(fixture.preflight, fixture.plan, fixture.journal.current, fixture.session)
            as ExistingInstallationUninstallDispatchResult.ReconciliationRequired

        assertEquals(ExistingInstallationUninstallReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH, result.reason)
        assertEquals(true, result.reconciliationCheckpointRecorded)
        assertEquals(1, fixture.session.commands.size)
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, fixture.journal.current.snapshot.checkpoint.semantics)
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, fixture.journal.current.snapshot.status)
        assertEquals(2, fixture.journal.advanceCalls)
    }

    @Test
    fun `absence verifier proves only through read only predicates and never mutates`() = runSuspend {
        val fixture = Fixture(
            semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
            status = OperationStatus.RECONCILIATION_REQUIRED,
        )
        val verifier = ExistingInstallationUninstallAbsenceSshAdapter { fixture.now }
        val session = FakeSession(fixture.binding) { _, _ -> failure(1) }

        val result = verifier.verify(fixture.journal.current, fixture.installation, session)

        assertEquals(ExistingInstallationUninstallAbsenceResult.Verified(fixture.now), result)
        assertEquals(0, fixture.journal.advanceCalls)
        assertTrue(session.commands.isNotEmpty())
        assertTrue(session.commands.none { it.rawForTransport().contains("uninstall") })
        assertTrue(session.commands.none { it.rawForTransport().contains(" rm ") })
        assertTrue(session.commands.none { it.rawForTransport().contains("systemctl stop") })
    }

    @Test
    fun `any supported installation evidence still present contradicts absence`() = runSuspend {
        val fixture = Fixture(
            semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
            status = OperationStatus.RECONCILIATION_REQUIRED,
        )
        val verifier = ExistingInstallationUninstallAbsenceSshAdapter { fixture.now }
        var first = true
        val session = FakeSession(fixture.binding) { _, _ ->
            if (first) {
                first = false
                success()
            } else {
                failure(1)
            }
        }

        val result = verifier.verify(fixture.journal.current, fixture.installation, session)

        assertEquals(
            ExistingInstallationUninstallAbsenceResult.Contradicted(
                ExistingInstallationUninstallAbsenceReason.SERVICE_UNIT_PRESENT,
            ),
            result,
        )
        assertEquals(1, session.commands.size)
    }

    private class Fixture(
        semantics: CheckpointSemantics = CheckpointSemantics.MUTATION_NOT_STARTED,
        status: OperationStatus = OperationStatus.RUNNING,
        behavior: (suspend (RemoteCommand, SshTransportConfig) -> SshCommandResult)? = null,
    ) {
        val now: Instant = Instant.parse("2026-09-13T12:30:00Z")
        val operationId = OperationId("phase96-uninstall")
        val serverId = ServerId("phase96-server")
        val accessId = ServerAccessId("phase96-access")
        val installationId = XuiInstallationId("phase96-installation")
        val managedInstallId = ManagedInstallId("v1-0123456789abcdef0123456789abcdef")
        val installation = XuiInstallation(
            id = installationId,
            serverId = serverId,
            ownership = InstallationOwnership.MANAGED,
            identity = InstallationIdentity(
                serviceUnit = "x-ui.service",
                binaryPath = "/usr/local/x-ui/x-ui",
                rootPath = "/usr/local/x-ui",
                databasePath = "/etc/x-ui/x-ui.db",
                managedInstallId = managedInstallId,
            ),
            baseline = InstallationBaseline(
                serviceUnit = "x-ui.service",
                binaryPath = "/usr/local/x-ui/x-ui",
                rootPath = "/usr/local/x-ui",
                databasePath = "/etc/x-ui/x-ui.db",
                panelPort = 2053,
                webBasePath = "/panel/",
                listenAddress = "127.0.0.1",
                capturedAt = now.minusSeconds(600),
            ),
        )
        val access = ServerAccess(
            id = accessId,
            serverId = serverId,
            endpoint = SshEndpoint("203.0.113.96", 22),
            username = "root",
            auth = SshAuthRef.Password(SecretId("phase96-secret")),
            pinnedHostKey = HostKeyFingerprint("SHA256:phase96"),
        )
        val initial = VersionedOperationSnapshot(
            OperationSnapshot(
                operationId = operationId,
                type = OperationType.UNINSTALL,
                target = OperationTarget.InstallationTarget(serverId, accessId, installationId),
                status = status,
                checkpoint = OperationCheckpoint("PREPARING", semantics, now.minusSeconds(10)),
                startedAt = now.minusSeconds(60),
                updatedAt = now.minusSeconds(10),
            ),
            OperationRevision(7),
        )
        val journal = FakeJournal(initial)
        private val authorizationSnapshot = initial.copy(
            snapshot = initial.snapshot.copy(
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint("PREPARING", CheckpointSemantics.MUTATION_NOT_STARTED, now.minusSeconds(10)),
            ),
        )
        val preflight = verifiedPreflight(authorizationSnapshot, installation, access, now)
        val plan = ReviewedExistingInstallationActionPlanPolicy.build(preflight)
        val binding = SessionBinding(SessionId("phase96-session"), accessId, SessionOwner.Operation(operationId))
        val session = FakeSession(binding, behavior ?: { _, _ -> success() })
        val adapter = ExistingInstallationUninstallSshAdapter(journal) { now }
    }

    private class FakeJournal(initial: VersionedOperationSnapshot) : OperationJournal {
        var current = initial
        var advanceCalls = 0
        override suspend fun create(initial: OperationSnapshot) = OperationJournalResult.StorageFailure("not used")
        override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
            if (operationId == current.snapshot.operationId) OperationJournalResult.Success(current) else OperationJournalResult.NotFound
        override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
            OperationJournalResult.Success(listOf(current))
        override suspend fun advance(
            operationId: OperationId,
            expectedRevision: OperationRevision,
            next: OperationSnapshot,
        ): OperationJournalResult<VersionedOperationSnapshot> {
            advanceCalls += 1
            if (operationId != current.snapshot.operationId) return OperationJournalResult.NotFound
            if (expectedRevision != current.revision) return OperationJournalResult.StaleRevision(expectedRevision, current.revision)
            current = VersionedOperationSnapshot(next, OperationRevision(current.revision.value + 1))
            return OperationJournalResult.Success(current)
        }
        override suspend fun history(operationId: OperationId): OperationJournalResult<List<OperationJournalEntry>> =
            OperationJournalResult.Success(emptyList())
    }

    private class FakeSession(
        override val binding: SessionBinding,
        private val behavior: suspend (RemoteCommand, SshTransportConfig) -> SshCommandResult,
    ) : SshSessionHandle {
        val commands = mutableListOf<RemoteCommand>()
        override val isOpen: Boolean = true
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
            val proof = InstallationProof(
                id = TargetProofId("phase96-proof"),
                installationId = installation.id,
                serverId = installation.serverId,
                serverAccessId = access.id,
                observedIdentity = installation.identity,
                observedAt = now.minusSeconds(3),
                validUntil = now.plusSeconds(120),
            )
            val verifiedTarget = (TargetProofPolicy.verifyKnownInstallation(
                installation, access, proof, now,
            ) as TargetVerificationResult.Verified).target
            val authorization = (ExistingInstallationActionAuthorizationPolicy.verify(
                current, installation, verifiedTarget, now,
            ) as ExistingInstallationActionAuthorizationResult.Verified).authorization
            val evidence = ExistingInstallationPreflightEvidence(
                scope = ExistingInstallationActionScope(
                    operationId = current.snapshot.operationId,
                    operationRevision = current.revision.value,
                    serverId = installation.serverId,
                    serverAccessId = access.id,
                    installationId = installation.id,
                    action = OperationType.UNINSTALL,
                    ownership = installation.ownership,
                    managedInstallId = installation.identity.managedInstallId,
                ),
                installationProof = proof,
                accessPathState = ExistingInstallationAccessPathState.EXACT_PINNED_AUTHENTICATED,
                layoutCapability = ExistingInstallationLayoutCapability.STANDARD_3X_UI_SYSTEMD_V1,
                privilegeCapability = ExistingInstallationPrivilegeCapability.DIRECT_ROOT,
                mutationBarrierState = ExistingInstallationMutationBarrierState.PROVEN_CLEAR,
                observedAt = now.minusSeconds(2),
                validUntil = now.plusSeconds(60),
            )
            return (ExistingInstallationActionPreflightPolicy.verify(
                authorization, current, installation, evidence, now,
            ) as ExistingInstallationActionPreflightResult.Verified).preflight
        }

        private fun success(stdout: String = ""): SshCommandResult = SshCommandResult(
            CommandDispatchState.DISPATCHED,
            CommandCompletion.ConfirmedSuccess,
            CapturedOutput.of(stdout.toByteArray(StandardCharsets.UTF_8), false),
            CapturedOutput.EMPTY,
        )

        private fun failure(code: Int): SshCommandResult = SshCommandResult(
            CommandDispatchState.DISPATCHED,
            CommandCompletion.ConfirmedFailure("fixture failure", code),
            CapturedOutput.EMPTY,
            CapturedOutput.EMPTY,
        )

        private fun unknown(): SshCommandResult = SshCommandResult(
            CommandDispatchState.DISPATCHED,
            CommandCompletion.Unknown("transport uncertain"),
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
