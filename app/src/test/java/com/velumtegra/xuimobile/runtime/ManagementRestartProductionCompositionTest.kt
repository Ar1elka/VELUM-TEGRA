package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.*
import com.velumtegra.xuimobile.core.ssh.*
import com.velumtegra.xuimobile.management.*
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.*
import org.junit.Test

/** Actual action port + shared coordinator + production host chain/adapters, with scripted transport.
 * No Android service, credential store, real network or VPS; Android UI has separate device tests. */
class ManagementRestartProductionCompositionTest {
    @Test fun `confirmed request dispatches once then explicit check uses new exact session and commits`() = runSuspend {
        val f = Fixture()
        assertEquals(ManagementRestartStart.Recorded("fixture-operation"), f.actions.startConfirmed(f.review))
        assertEquals(0, f.connects); assertEquals(0, f.restartCommands)
        val first = f.runRestartHost()
        assertTrue((first.restart as ExistingInstallationRestartRuntimeResult.Dispatch).result is ExistingInstallationRestartDispatchResult.ReconnectRequired)
        assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT, f.current!!.snapshot.checkpoint.semantics)
        assertEquals(1, f.closed); assertEquals(1, f.restartCommands)
        assertNull(f.actions.checkResultConfirmed("fixture-operation", f.review))
        val second = f.runRestartHost()
        assertTrue(second.restart is ExistingInstallationRestartRuntimeResult.Completed)
        assertEquals(OperationStatus.SUCCEEDED, f.current!!.snapshot.status)
        assertEquals("RESTART_SUCCEEDED", f.current!!.snapshot.checkpoint.phaseName)
        assertEquals(2, f.connects); assertEquals(2, f.closed); assertEquals(1, f.restartCommands)
        assertEquals(listOf(OperationId("fixture-operation"), OperationId("fixture-operation")), f.hostRequests)
        assertEquals(1, f.labels.count { it == "restart-preflight-effective-uid" })
    }

    @Test fun `start and stop preserve the selected action through a second read only connection`() = runSuspend {
        for (action in listOf(ExistingInstallationServiceAction.START, ExistingInstallationServiceAction.STOP)) {
            val f = Fixture()
            assertEquals(ManagementRestartStart.Recorded("fixture-operation"),
                f.actions.runServiceActionConfirmed(f.review, action))
            assertEquals(action.phaseName("RESTART_USER_CONFIRMED"), f.current!!.snapshot.checkpoint.phaseName)
            assertEquals(0, f.restartCommands)

            val sent = f.runRestartHost()
            assertTrue((sent.restart as ExistingInstallationRestartRuntimeResult.Dispatch).result is
                ExistingInstallationRestartDispatchResult.ReconnectRequired)
            assertEquals(action.phaseName("RESTART_DISPATCHED"), f.current!!.snapshot.checkpoint.phaseName)
            assertNull(f.actions.checkResultConfirmed("fixture-operation", f.review))
            f.observedServiceActive = action == ExistingInstallationServiceAction.START
            assertTrue(f.runRestartHost().restart is ExistingInstallationRestartRuntimeResult.Completed)
            assertEquals(action.phaseName("RESTART_SUCCEEDED"), f.current!!.snapshot.checkpoint.phaseName)
            assertEquals(1, f.restartCommands)
            assertEquals(2, f.connects)
        }
    }

    @Test fun `stop cannot be confirmed while the listener is still present`() = runSuspend {
        val f = Fixture()
        f.actions.runServiceActionConfirmed(f.review, ExistingInstallationServiceAction.STOP)
        f.runRestartHost()
        f.observedServiceActive = false
        f.listenerStillPresent = true
        assertNull(f.actions.checkResultConfirmed("fixture-operation", f.review))
        f.runRestartHost()
        assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, f.current!!.snapshot.checkpoint.semantics)
        assertEquals(1, f.restartCommands)
    }

    @Test fun `xray reload verifies a new child without changing the panel process`() = runSuspend {
        val f = Fixture()
        f.actions.runServiceActionConfirmed(f.review, ExistingInstallationServiceAction.XRAY_RESTART)
        f.runRestartHost()
        val sent = f.current!!.snapshot.checkpoint
        assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT, sent.semantics)
        assertTrue(sent.phaseName.startsWith("SERVICE_XRAY_RESTART_DISPATCHED#"))
        assertNull(f.actions.checkResultConfirmed("fixture-operation", f.review))
        f.xrayPid = 303
        assertTrue(f.runRestartHost().restart is ExistingInstallationRestartRuntimeResult.Completed)
        assertTrue(f.current!!.snapshot.checkpoint.phaseName.startsWith("SERVICE_XRAY_RESTART_SUCCEEDED#"))
        assertEquals(1, f.restartCommands)
    }

    @Test fun `an unrecognized reload never dispatches`() = runSuspend {
        val f = Fixture()
        f.reloadConfig = "{ path=/bin/kill ; argv[]=/bin/kill -HUP " + "${'$'}MAINPID ; ignore_errors=no }"
        f.actions.runServiceActionConfirmed(f.review, ExistingInstallationServiceAction.XRAY_RESTART)
        f.runRestartHost()
        assertEquals(OperationStatus.FAILED, f.current!!.snapshot.status)
        assertEquals(0, f.restartCommands)
    }

    @Test fun `autostart result can be verified with the panel stopped`() = runSuspend {
        val f = Fixture()
        f.actions.runServiceActionConfirmed(f.review, ExistingInstallationServiceAction.ENABLE_AUTOSTART)
        f.runRestartHost()
        f.observedServiceActive = false
        f.autostart = "enabled"
        assertNull(f.actions.checkResultConfirmed("fixture-operation", f.review))
        assertTrue(f.runRestartHost().restart is ExistingInstallationRestartRuntimeResult.Completed)
        assertFalse("management-service-state" in f.labels)
        assertEquals(1, f.restartCommands)
    }

    @Test fun `unknown transport outcome is reconciled read only and never dispatched again`() = runSuspend {
        val f = Fixture(); f.uncertainDispatch = true
        f.actions.startConfirmed(f.review); f.runRestartHost()
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED, f.current!!.snapshot.status)
        assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT, f.current!!.snapshot.checkpoint.semantics)
        assertNull(f.actions.checkResultConfirmed("fixture-operation", f.review)); f.runRestartHost()
        assertEquals(OperationStatus.SUCCEEDED, f.current!!.snapshot.status)
        assertEquals(1, f.restartCommands); assertEquals(2, f.closed)
    }

    @Test fun `observed non root preflight blocks before restart and records terminal failure`() = runSuspend {
        val f = Fixture(); f.uid = "1000\n"
        f.actions.startConfirmed(f.review)
        val result = f.runRestartHost()
        assertEquals(ExistingInstallationRestartPreflightRejection.DIRECT_ROOT_REQUIRED,
            (result.restart as ExistingInstallationRestartRuntimeResult.PreflightRejected).reason)
        assertEquals(OperationStatus.FAILED, f.current!!.snapshot.status)
        assertEquals(0, f.restartCommands); assertEquals(1, f.closed)
    }

    @Test fun `cancel before host execution discards permission and writes only local terminal state`() = runSuspend {
        val f = Fixture(); f.actions.startConfirmed(f.review)
        assertNull(f.actions.cancelBeforeDispatch("fixture-operation", f.review))
        assertEquals(OperationStatus.CANCELLED, f.current!!.snapshot.status)
        assertEquals(CheckpointSemantics.TERMINAL, f.current!!.snapshot.checkpoint.semantics)
        assertFalse(f.coordinator.discardExistingInstallationRestartPreflight(OperationId("fixture-operation")))
        assertEquals(0, f.connects); assertEquals(0, f.restartCommands)
    }

    @Test fun `result check cannot turn a not dispatched request or foreign target into host authority`() = runSuspend {
        val f = Fixture(); f.actions.startConfirmed(f.review)
        assertNotNull(f.actions.checkResultConfirmed("fixture-operation", f.review))
        f.current = f.current!!.copy(snapshot = f.current!!.snapshot.copy(target = OperationTarget.InstallationTarget(
            ServerId("other-server"), f.access.id, f.installation.id)))
        assertNotNull(f.actions.checkResultConfirmed("fixture-operation", f.review))
        assertEquals(1, f.hostRequests.size); assertEquals(0, f.connects)
    }

    @Test fun `changed reviewed metadata blocks before journal creation and host launch`() = runSuspend {
        val f = Fixture(); f.currentReview = f.review.copy(serverName = "Changed target")
        assertTrue(f.actions.startConfirmed(f.review) is ManagementRestartStart.Blocked)
        assertNull(f.current); assertEquals(0, f.hostRequests.size); assertEquals(0, f.connects)
    }

    private class Fixture {
        private val at = Instant.now()
        private val server = ServerId("fixture-server")
        val access = ServerAccess(ServerAccessId("fixture-access"), server, SshEndpoint("fixture.invalid", 22), "operator",
            SshAuthRef.Password(SecretId("fixture-reference")), HostKeyFingerprint("SHA256:fixture"))
        val installation = XuiInstallation(XuiInstallationId("fixture-installation"), server, InstallationOwnership.ADOPTED,
            InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
            InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", at.minusSeconds(60)))
        val review = ManagementRestartReview("Fixture VPS", installation, access)
        var currentReview = review
        var current: VersionedOperationSnapshot? = null
        var uid = "0\n"
        var uncertainDispatch = false
        var observedServiceActive = true
        var listenerStillPresent = false
        var reloadConfig = "{ path=/bin/kill ; argv[]=/bin/kill -USR1 ${'$'}MAINPID ; ignore_errors=no ; pid=0 }"
        var xrayPid = 202
        var autostart = "disabled"
        var connects = 0
        var closed = 0
        var restartCommands = 0
        val labels = mutableListOf<String>()
        val hostRequests = mutableListOf<OperationId>()
        private val journal = object : OperationJournal {
            override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
                check(current == null); current = VersionedOperationSnapshot(initial, OperationRevision(0))
                return OperationJournalResult.Success(checkNotNull(current))
            }
            override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
                current?.takeIf { it.snapshot.operationId == operationId }?.let { OperationJournalResult.Success(it) } ?: OperationJournalResult.NotFound
            override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
                OperationJournalResult.Success(listOfNotNull(current?.takeIf { it.snapshot.checkpoint.semantics != CheckpointSemantics.TERMINAL }))
            override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
                val before = current ?: return OperationJournalResult.NotFound
                if (operationId != before.snapshot.operationId) return OperationJournalResult.NotFound
                if (expectedRevision != before.revision) return OperationJournalResult.StaleRevision(expectedRevision, before.revision)
                current = VersionedOperationSnapshot(next, OperationRevision(before.revision.value + 1))
                return OperationJournalResult.Success(checkNotNull(current))
            }
            override suspend fun history(operationId: OperationId) = OperationJournalResult.Success(emptyList<OperationJournalEntry>())
        }
        private val accesses = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> =
                if (serverAccessId == access.id) RepositoryResult.Success(access) else RepositoryResult.NotFound
            override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(access))
            override suspend fun delete(serverAccessId: ServerAccessId) = error("No credential deletion")
        }
        private val installations = object : XuiInstallationRepository {
            override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> =
                if (installationId == installation.id) RepositoryResult.Success(VersionedRecord(installation, RecordRevision(1))) else RepositoryResult.NotFound
            override suspend fun listForServer(serverId: ServerId) = RepositoryResult.Success(listOf(VersionedRecord(installation, RecordRevision(1))))
            override suspend fun create(installation: XuiInstallation) = error("No installation writes")
            override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision) = error("No installation writes")
            override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision) = error("No installation writes")
        }
        private val management = object : ManagementAccessRepository {
            override suspend fun get(installationId: XuiInstallationId, serverAccessId: ServerAccessId) =
                RepositoryResult.Success(ManagementAccess(installation.id, access.id))
            override suspend fun listForInstallation(installationId: XuiInstallationId) = RepositoryResult.Success(listOf(ManagementAccess(installation.id, access.id)))
            override suspend fun listForServerAccess(serverAccessId: ServerAccessId) = RepositoryResult.Success(listOf(ManagementAccess(installation.id, access.id)))
            override suspend fun create(access: ManagementAccess) = error("No management writes")
            override suspend fun delete(installationId: XuiInstallationId, serverAccessId: ServerAccessId) = error("No management writes")
        }
        private val factory = object : SshConnectionFactory {
            override suspend fun connect(access: ServerAccess, owner: SessionOwner, config: SshTransportConfig): SshConnectResult {
                assertEquals(this@Fixture.access, access); assertEquals(SessionOwner.Operation(OperationId("fixture-operation")), owner)
                connects++
                return SshConnectResult.Connected(object : SshSessionHandle {
                    override val binding = SessionBinding(SessionId("fixture-session-$connects"), access.id, owner)
                    private var sessionOpen = true
                    override val isOpen get() = sessionOpen
                    override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
                        check(sessionOpen); labels += command.redactedLabel
                        val text = when (command.redactedLabel) {
                            "restart-preflight-effective-uid" -> uid
                            "restart-preflight-exact-systemd-executable" -> "{ path=/usr/local/x-ui/x-ui ; argv[]=/usr/local/x-ui/x-ui ; ignore_errors=no ; }\n"
                            "management-panel-settings" -> "PORT=2053\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=127.0.0.1\n"
                            "management-xray-reload-config" -> reloadConfig
                            "management-xray-processes" -> "01234567-89ab-cdef-0123-456789abcdef 101 1000 $xrayPid 2000"
                            "management-autostart-state" -> autostart
                            "management-service-state" -> if (observedServiceActive) "active\n" else "inactive\n"
                            "management-listener-presence" -> {
                                if (!observedServiceActive && !listenerStillPresent) return SshCommandResult(
                                    CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedFailure("fixture listener absent", exitCode = 1),
                                    CapturedOutput.EMPTY, CapturedOutput.EMPTY,
                                )
                                ""
                            }
                            "phase9-restart-exact-service" -> {
                                assertEquals(CheckpointSemantics.RESTART_IN_FLIGHT, current!!.snapshot.checkpoint.semantics)
                                restartCommands++
                                if (uncertainDispatch) return SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.Unknown("fixture connection dropped"), CapturedOutput.EMPTY, CapturedOutput.EMPTY)
                                ""
                            }
                            else -> ""
                        }
                        return SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess,
                            CapturedOutput.of(text.encodeToByteArray(), truncated = false), CapturedOutput.EMPTY)
                    }
                    override fun close() { if (sessionOpen) closed++; sessionOpen = false }
                })
            }
        }
        // Match the complete application graph: the generic host first asks the Installer consumer
        // whether it owns this operation. This capability must exist even for a RESTART-only test.
        private val publisher = object : ManagementEnrollmentPublisher {
            override suspend fun publish(request: ManagementEnrollmentRequest): ManagementEnrollmentPublicationResult =
                error("RESTART must never publish an installation")
            override suspend fun publishInstaller(request: InstallerManagementPublicationRequest): ManagementEnrollmentPublicationResult =
                error("RESTART must never invoke Installer publication")
            override suspend fun republishReinstall(request: ExistingInstallationReinstallPublicationRequest): ExistingInstallationReinstallPublicationResult =
                error("RESTART must never invoke Reinstall publication")
        }
        val coordinator = OperationRuntimeCoordinator(journal, accesses, factory, ExactSessionRegistry(), installations, management, publisher)
        val actions = ProductionManagementRestartActionPort(ManagementRestartLocalPort { _, _, _ -> ManagementRestartLocalReview.Ready(currentReview) },
            journal, coordinator, { id -> hostRequests += id; ExactOperationHostStartResult.START_REQUEST_ACCEPTED },
            operationIdFactory = { OperationId("fixture-operation") })
        suspend fun runHost(): ExactOperationHostTransportSequenceResult {
            val c = checkNotNull(current)
            val action = if (c.snapshot.checkpoint.semantics == CheckpointSemantics.MUTATION_NOT_STARTED) RecoveryAction.RECONNECT_EXACT_OWNER else RecoveryAction.RECONCILE_READ_ONLY
            val plan = ColdStartRecoveryPlan(c.snapshot.operationId, c.snapshot.target, c.revision, action, automaticAllowed = false)
            val admission = (coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED) as RecoveryAdmissionResult.Admitted).admission
            try {
                // Fixture stands in for the next Android callback registration's actual observation.
                coordinator.observeConnectivity(ConnectivityState.ONLINE)
                return ExactOperationHostTransportSequence(ExactOperationHostRuntimeTransportBridge(coordinator)).run(
                    ExactOperationHostRuntimeBinding(c.snapshot.operationId, CoordinatorAdmissionToken(admission)), RetryBudget(1))
            } finally { assertEquals(OperationRuntimeReleaseResult.RELEASED, coordinator.release(admission)) }
        }
        suspend fun runRestartHost(): ExactOperationHostTransportSequenceResult.RestartEnded {
            val result = runHost()
            assertTrue("Expected exact RestartEnded, got $result", result is ExactOperationHostTransportSequenceResult.RestartEnded)
            return result as ExactOperationHostTransportSequenceResult.RestartEnded
        }
    }
}
private fun <T> runSuspend(block: suspend () -> T): T {
    var outcome: Result<T>? = null
    block.startCoroutine(object : Continuation<T> {
        override val context = EmptyCoroutineContext
        override fun resumeWith(result: Result<T>) { outcome = result }
    })
    return checkNotNull(outcome).getOrThrow()
}
