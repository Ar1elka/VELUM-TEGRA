package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.nio.charset.StandardCharsets
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ExistingInstallationReinstallSshAdapterTest {
    @Test
    fun `compiler emits exact reviewed uninstall installer marker sequence with operation scoped worker`() {
        val fixture = Fixture()
        val compiled = ExistingInstallationReinstallCommandCompiler.compile(fixture.preflight, fixture.plan)
        checkNotNull(compiled)

        assertEquals(
            listOf(
                ExistingInstallationReinstallStepKind.UNINSTALL,
                ExistingInstallationReinstallStepKind.PREPARE_WORKER,
                ExistingInstallationReinstallStepKind.FETCH_INSTALLER,
                ExistingInstallationReinstallStepKind.EXECUTE_INSTALLER,
                ExistingInstallationReinstallStepKind.WRITE_MANAGED_MARKER,
            ),
            compiled.steps.map { it.kind },
        )
        assertEquals(
            ExistingInstallationUninstallCommandCompiler.EXACT_UNINSTALL_COMMAND,
            compiled.steps[0].command.rawForTransport(),
        )
        assertTrue(compiled.workerDirectory.startsWith("/var/lib/velum-tegra/reinstall/v1/${fixture.managedInstallId.value}/"))
        assertFalse(compiled.workerDirectory.contains(fixture.operationId.value))
        assertTrue(compiled.steps[2].command.rawForTransport().contains(InstallerReviewedCommandCompiler.PINNED_INSTALLER_URL))
        assertTrue(compiled.steps[2].command.rawForTransport().contains(InstallerReviewedCommandCompiler.PINNED_INSTALLER_GIT_BLOB_SHA1))
        assertTrue(compiled.steps[3].command.rawForTransport().contains("XUI_NONINTERACTIVE=1"))
        assertTrue(compiled.steps[3].command.rawForTransport().contains(InstallerReviewedCommandCompiler.PINNED_3X_UI_VERSION))
        assertTrue(compiled.steps[4].command.rawForTransport().contains(ManagedInstallMarkerProtocol.MARKER_PATH))
        assertTrue(compiled.steps[4].command.rawForTransport().contains(fixture.managedInstallId.value))
    }

    @Test
    fun `mutation in flight is durable before first step and success dispatches each step once`() = runBlocking {
        lateinit var fixture: Fixture
        fixture = Fixture { _, _ ->
            assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, fixture.journal.current.snapshot.checkpoint.semantics)
            success()
        }

        val result = fixture.adapter.dispatch(fixture.preflight, fixture.plan, fixture.journal.current, fixture.session)
            as ExistingInstallationReinstallDispatchResult.PostVerifyRequired

        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, result.durable.snapshot.checkpoint.semantics)
        assertEquals(5, fixture.session.commands.size)
        assertEquals(1, fixture.journal.advanceCalls)
    }

    @Test
    fun `confirmed failure stops compound plan without retry and remains reconciliation only`() = runBlocking {
        var execution = 0
        val fixture = Fixture { _, _ ->
            execution += 1
            if (execution == 3) failure(17) else success()
        }

        val result = fixture.adapter.dispatch(fixture.preflight, fixture.plan, fixture.journal.current, fixture.session)
            as ExistingInstallationReinstallDispatchResult.ReconciliationRequired

        assertEquals(ExistingInstallationReinstallReconciliationReason.REMOTE_STEP_FAILED, result.reason)
        assertEquals(3, fixture.session.commands.size)
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, fixture.journal.current.snapshot.status)
        assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, fixture.journal.current.snapshot.checkpoint.semantics)
    }

    @Test
    fun `unknown after any reached step is never retried`() = runBlocking {
        var execution = 0
        val fixture = Fixture { _, _ ->
            execution += 1
            if (execution == 2) unknown() else success()
        }

        val result = fixture.adapter.dispatch(fixture.preflight, fixture.plan, fixture.journal.current, fixture.session)
            as ExistingInstallationReinstallDispatchResult.ReconciliationRequired

        assertEquals(ExistingInstallationReinstallReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH, result.reason)
        assertEquals(2, fixture.session.commands.size)
        assertEquals(2, fixture.journal.advanceCalls)
    }

    @Test
    fun `postverify reads operation scoped worker marker and installation facts without mutation`() = runBlocking {
        val fixture = Fixture(
            semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
            status = OperationStatus.RECONCILIATION_REQUIRED,
        )
        val marker = ManagedInstallMarkerProtocol.encode(fixture.managedInstallId).trim()
        val session = FakeSession(
            fixture.binding,
            responses = ArrayDeque(
                listOf(
                    success("PROCESS=DEAD\nHEARTBEAT=${fixture.now.minusSeconds(3).epochSecond}\nTERMINAL=SUCCESS\n"),
                    success("$marker\n"),
                    success(
                        "SERVICE_PRESENT=1\n" +
                            "BINARY_PRESENT=1\n" +
                            "ROOT_PRESENT=1\n" +
                            "DATABASE_PRESENT=1\n" +
                            "SERVICE_STATE=active\n" +
                            "PORT=24443\n" +
                            "WEB_BASE_PATH=/reinstalled/\n" +
                            "LISTEN_ADDRESS=127.0.0.1\n" +
                            "LISTENER_PRESENT=1\n",
                    ),
                ),
            ),
        )
        val verifier = ExistingInstallationReinstallPostVerifySshAdapter(now = { fixture.now })

        val result = verifier.verify(fixture.journal.current, fixture.managedInstallId, session)
            as ExistingInstallationReinstallPostVerifyResult.Verified

        assertEquals(3, session.commands.size)
        assertEquals(24443, result.verifiedBaseline.panelPort)
        assertEquals("/reinstalled/", result.verifiedBaseline.webBasePath)
        assertEquals("127.0.0.1", result.verifiedBaseline.listenAddress)
        assertEquals(0, fixture.journal.advanceCalls)
        assertTrue(session.commands[0].rawForTransport().contains("/var/lib/velum-tegra/reinstall/v1/"))
        assertFalse(session.commands.any { it.rawForTransport().contains("curl") })
        assertFalse(session.commands.any { it.rawForTransport().contains("uninstall") })
        assertFalse(session.commands.any { it.rawForTransport().contains("nohup") })
    }

    private class Fixture(
        semantics: CheckpointSemantics = CheckpointSemantics.MUTATION_NOT_STARTED,
        status: OperationStatus = OperationStatus.RUNNING,
        behavior: (suspend (RemoteCommand, SshTransportConfig) -> SshCommandResult)? = null,
    ) {
        val now: Instant = Instant.parse("2026-09-14T13:00:00Z")
        val operationId = OperationId("phase97-reinstall-operation")
        val serverId = ServerId("phase97-server")
        val accessId = ServerAccessId("phase97-access")
        val installationId = XuiInstallationId("phase97-installation")
        val managedInstallId = ManagedInstallId("v1-0123456789abcdef0123456789abcdef")
        val installation = XuiInstallation(
            id = installationId,
            serverId = serverId,
            ownership = InstallationOwnership.MANAGED,
            identity = InstallationIdentity(
                serviceUnit = InstallerPostInstallPolicy.SERVICE_UNIT,
                binaryPath = InstallerPostInstallPolicy.BINARY_PATH,
                rootPath = InstallerPostInstallPolicy.ROOT_PATH,
                databasePath = InstallerPostInstallPolicy.DATABASE_PATH,
                managedInstallId = managedInstallId,
            ),
            baseline = InstallationBaseline(
                serviceUnit = InstallerPostInstallPolicy.SERVICE_UNIT,
                binaryPath = InstallerPostInstallPolicy.BINARY_PATH,
                rootPath = InstallerPostInstallPolicy.ROOT_PATH,
                databasePath = InstallerPostInstallPolicy.DATABASE_PATH,
                panelPort = 2053,
                webBasePath = "/panel/",
                listenAddress = "127.0.0.1",
                capturedAt = now.minusSeconds(600),
            ),
        )
        val access = ServerAccess(
            id = accessId,
            serverId = serverId,
            endpoint = SshEndpoint("203.0.113.97", 22),
            username = "root",
            auth = SshAuthRef.Password(SecretId("phase97-secret")),
            pinnedHostKey = HostKeyFingerprint("SHA256:phase97"),
        )
        val initial = VersionedOperationSnapshot(
            OperationSnapshot(
                operationId = operationId,
                type = OperationType.REINSTALL,
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
        val binding = SessionBinding(SessionId("phase97-session"), accessId, SessionOwner.Operation(operationId))
        val session = FakeSession(binding, behavior = behavior ?: { _, _ -> success() })
        val adapter = ExistingInstallationReinstallSshAdapter(journal) { now }
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
        private val behavior: (suspend (RemoteCommand, SshTransportConfig) -> SshCommandResult)? = null,
        private val responses: ArrayDeque<SshCommandResult>? = null,
    ) : SshSessionHandle {
        val commands = mutableListOf<RemoteCommand>()
        override val isOpen: Boolean = true
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            commands += command
            return responses?.removeFirstOrNull() ?: requireNotNull(behavior).invoke(command, config)
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
                id = TargetProofId("phase97-proof"),
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
                    action = OperationType.REINSTALL,
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
