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

class ExistingInstallationRestartSshAdapterTest {
    @Test
    fun `compiler emits only exact canonical restart command`() {
        val fixture = Fixture()
        val compiled = ExistingInstallationRestartCommandCompiler.compile(fixture.preflight, fixture.plan)
        checkNotNull(compiled)
        assertEquals("systemctl restart x-ui.service", compiled.command.rawForTransport())
        assertEquals("phase9-restart-exact-service", compiled.command.redactedLabel)
        assertEquals(ReviewedExistingInstallationActionPlanPolicy.RESTART_TIMEOUT, compiled.config.commandExecutionTimeout)
    }

    @Test
    fun `compiler maps start and stop to the exact same canonical service unit`() {
        val fixture = Fixture()
        val start = ExistingInstallationRestartCommandCompiler.compile(
            fixture.preflight, fixture.plan, ExistingInstallationServiceAction.START,
        )
        val stop = ExistingInstallationRestartCommandCompiler.compile(
            fixture.preflight, fixture.plan, ExistingInstallationServiceAction.STOP,
        )
        assertEquals("systemctl start x-ui.service", checkNotNull(start).command.rawForTransport())
        assertEquals("systemctl stop x-ui.service", checkNotNull(stop).command.rawForTransport())
    }

    @Test
    fun `extended controls use only systemd for the reviewed unit`() {
        val f = Fixture()
        val actions = mapOf(
            ExistingInstallationServiceAction.XRAY_RESTART to "reload",
            ExistingInstallationServiceAction.ENABLE_AUTOSTART to "enable",
            ExistingInstallationServiceAction.DISABLE_AUTOSTART to "disable",
        )
        for ((action, command) in actions) {
            val compiled = checkNotNull(ExistingInstallationRestartCommandCompiler.compile(f.preflight, f.plan, action))
            assertEquals("systemctl $command x-ui.service", compiled.command.rawForTransport())
        }
    }

    @Test
    fun `TLS metadata requires an exact digest and a parsed expiration`() {
        val digest = List(32) { "AB" }.joinToString(":")
        val raw = "notAfter=Aug  7 12:00:00 2027 GMT\nsha256 Fingerprint=$digest\n"
        assertEquals(XuiPanelTlsResult.Observed(Instant.parse("2027-08-07T12:00:00Z"), digest),
            XuiReadOnlyPanelTlsProbe.parseMetadata(raw))
        assertEquals(XuiPanelTlsResult.Unavailable, XuiReadOnlyPanelTlsProbe.parseMetadata(raw + "unexpected\n"))
    }

    @Test
    fun `forged noncanonical plan is rejected before journal write or ssh`() = runSuspend {
        val fixture = Fixture()
        val forged = fixture.plan.copy(steps = fixture.plan.steps.dropLast(1))

        val result = fixture.adapter.dispatch(fixture.preflight, forged, fixture.journal.current, fixture.session)

        assertEquals(
            ExistingInstallationRestartDispatchResult.Rejected(
                ExistingInstallationRestartDispatchFailure.PlanOutsideApprovedPolicy,
            ),
            result,
        )
        assertEquals(0, fixture.journal.advanceCalls)
        assertEquals(0, fixture.session.commands.size)
    }

    @Test
    fun `wrong exact session is rejected before durable restart checkpoint`() = runSuspend {
        val fixture = Fixture()
        val wrong = FakeSession(
            fixture.binding.copy(serverAccessId = ServerAccessId("different-access")),
        ) { _, _ -> success() }

        val result = fixture.adapter.dispatch(fixture.preflight, fixture.plan, fixture.journal.current, wrong)

        assertEquals(
            ExistingInstallationRestartDispatchResult.Rejected(
                ExistingInstallationRestartDispatchFailure.ExactSessionBindingMismatch,
            ),
            result,
        )
        assertEquals(0, fixture.journal.advanceCalls)
        assertEquals(0, wrong.commands.size)
    }

    @Test
    fun `restart in flight is durable before the single remote command and success only requires reconnect`() = runSuspend {
        lateinit var fixture: Fixture
        fixture = Fixture { _, _ ->
            assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT, fixture.journal.current.snapshot.checkpoint.semantics)
            assertEquals("RESTART_DISPATCHED", fixture.journal.current.snapshot.checkpoint.phaseName)
            success()
        }

        val result = fixture.adapter.dispatch(fixture.preflight, fixture.plan, fixture.journal.current, fixture.session)
            as ExistingInstallationRestartDispatchResult.ReconnectRequired

        assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT, result.durable.snapshot.checkpoint.semantics)
        assertEquals(OperationStatus.RUNNING, result.durable.snapshot.status)
        assertEquals(1, fixture.session.commands.size)
        assertEquals("systemctl restart x-ui.service", fixture.session.commands.single().rawForTransport())
        assertEquals(1, fixture.journal.advanceCalls)
    }

    @Test
    fun `unknown after dispatch is never retried and remains restart in flight reconciliation required`() = runSuspend {
        val fixture = Fixture { _, _ -> unknown() }

        val result = fixture.adapter.dispatch(fixture.preflight, fixture.plan, fixture.journal.current, fixture.session)
            as ExistingInstallationRestartDispatchResult.ReconciliationRequired

        assertEquals(ExistingInstallationRestartReconciliationReason.TRANSPORT_UNCERTAIN_AFTER_DISPATCH, result.reason)
        assertEquals(true, result.reconciliationCheckpointRecorded)
        assertEquals(1, fixture.session.commands.size)
        assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT, fixture.journal.current.snapshot.checkpoint.semantics)
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, fixture.journal.current.snapshot.status)
        assertEquals(2, fixture.journal.advanceCalls)
    }

    @Test
    fun `post verify is read only and requires exact identity active service listener and managed marker`() = runSuspend {
        val fixture = Fixture(semantics = CheckpointSemantics.POST_VERIFY_REQUIRED, status = OperationStatus.RECONCILIATION_REQUIRED)
        val beforeRevision = fixture.journal.current.revision
        val verifier = ExistingInstallationRestartPostVerifySshAdapter { fixture.now }
        val session = FakeSession(fixture.binding) { command, _ ->
            when {
                command.redactedLabel.contains("service-live", ignoreCase = true) ||
                    command.rawForTransport().contains("is-active") -> success("active\n")
                command.redactedLabel == "phase9-restart-managed-marker-readback" ->
                    success(ManagedInstallMarkerProtocol.encode(fixture.managedInstallId))
                else -> success()
            }
        }

        val result = verifier.verify(fixture.journal.current, fixture.installation, session)

        assertTrue(result is ExistingInstallationRestartPostVerifyResult.Verified)
        assertEquals(beforeRevision, fixture.journal.current.revision)
        assertEquals(0, fixture.journal.advanceCalls)
        assertTrue(session.commands.none { it.rawForTransport().contains("restart") })
        assertTrue(session.commands.none { it.rawForTransport().contains(" rm ") })
    }

    @Test
    fun `post verify listener contradiction cannot create verified result`() = runSuspend {
        val fixture = Fixture(semantics = CheckpointSemantics.POST_VERIFY_REQUIRED, status = OperationStatus.RECONCILIATION_REQUIRED)
        val verifier = ExistingInstallationRestartPostVerifySshAdapter { fixture.now }
        val session = FakeSession(fixture.binding) { command, _ ->
            when {
                command.rawForTransport().contains("is-active") -> success("active\n")
                command.redactedLabel == "phase9-restart-managed-marker-readback" ->
                    success(ManagedInstallMarkerProtocol.encode(fixture.managedInstallId))
                command.rawForTransport().contains("ss ") || command.rawForTransport().contains("/proc/net") ->
                    failure(1)
                else -> success()
            }
        }

        val result = verifier.verify(fixture.journal.current, fixture.installation, session)
        assertEquals(
            ExistingInstallationRestartPostVerifyResult.Contradicted(
                ExistingInstallationRestartPostVerifyReason.EXPECTED_LISTENER_ABSENT,
            ),
            result,
        )
        assertEquals(0, fixture.journal.advanceCalls)
    }

    private class Fixture(
        semantics: CheckpointSemantics = CheckpointSemantics.MUTATION_NOT_STARTED,
        status: OperationStatus = OperationStatus.RUNNING,
        behavior: (suspend (RemoteCommand, SshTransportConfig) -> SshCommandResult)? = null,
    ) {
        val now: Instant = Instant.parse("2026-09-13T10:30:00Z")
        val operationId = OperationId("phase94-restart")
        val serverId = ServerId("phase94-server")
        val accessId = ServerAccessId("phase94-access")
        val installationId = XuiInstallationId("phase94-installation")
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
            endpoint = SshEndpoint("203.0.113.94", 22),
            username = "root",
            auth = SshAuthRef.Password(SecretId("phase94-secret")),
            pinnedHostKey = HostKeyFingerprint("SHA256:phase94"),
        )
        val initial = VersionedOperationSnapshot(
            OperationSnapshot(
                operationId = operationId,
                type = OperationType.RESTART,
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
        val preflight: VerifiedExistingInstallationActionPreflight = verifiedPreflight(authorizationSnapshot, installation, access, now)
        val plan = ReviewedExistingInstallationActionPlanPolicy.build(preflight)
        val binding = SessionBinding(SessionId("phase94-session"), accessId, SessionOwner.Operation(operationId))
        val session = FakeSession(binding, behavior ?: { _, _ -> success() })
        val adapter = ExistingInstallationRestartSshAdapter(journal) { now }
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
                id = TargetProofId("phase94-proof"),
                installationId = installation.id,
                serverId = installation.serverId,
                serverAccessId = access.id,
                observedIdentity = installation.identity,
                observedAt = now.minusSeconds(3),
                validUntil = now.plusSeconds(120),
            )
            val verifiedTarget = (TargetProofPolicy.verifyKnownInstallation(
                installation,
                access,
                proof,
                now,
            ) as TargetVerificationResult.Verified).target
            val authorization = (ExistingInstallationActionAuthorizationPolicy.verify(
                current,
                installation,
                verifiedTarget,
                now,
            ) as ExistingInstallationActionAuthorizationResult.Verified).authorization
            val evidence = ExistingInstallationPreflightEvidence(
                scope = ExistingInstallationActionScope(
                    operationId = current.snapshot.operationId,
                    operationRevision = current.revision.value,
                    serverId = installation.serverId,
                    serverAccessId = access.id,
                    installationId = installation.id,
                    action = OperationType.RESTART,
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
                authorization,
                current,
                installation,
                evidence,
                now,
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
