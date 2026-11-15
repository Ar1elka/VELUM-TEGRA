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

/** Actual visible action, shared coordinator, host chain and log parser with scripted transport. */
class ServiceLogProductionCompositionTest {
    @Test fun recordedRequestDoesNotConnectUntilExactHostRunsAndCleansOneSession() = runSuspend {
        val f = Fixture()
        assertTrue(f.actions.start("fixture-server", "fixture-installation", "fixture-access") is ServiceLogStart.Registered)
        assertEquals(0, f.connects)
        val result = f.runHost()
        assertTrue(result is ExactOperationHostTransportSequenceResult.ServiceLogsEnded)
        f.registry.publish(OperationId("fixture-operation"), result.toServiceLogProcessResult())
        val status = f.statuses.read("fixture-server", "fixture-installation", ServiceLogPointer("fixture-operation", "fixture-access"))
        assertTrue(status.terminal)
        assertEquals(ServiceLogCategory.TIMEOUT, status.snapshot!!.entries.single().category)
        assertEquals(1, f.connects); assertEquals(1, f.closed)
        assertEquals(1, f.labels.count { it == "service-log-read-bounded" })
        assertFalse(f.labels.any { "restart" in it || "installer" in it })
    }
    @Test fun wrongExactAccessCannotExposeACompletedSnapshot() = runSuspend {
        val f = Fixture(); f.actions.start("fixture-server", "fixture-installation", "fixture-access")
        f.registry.publish(OperationId("fixture-operation"), f.runHost().toServiceLogProcessResult())
        val result = f.statuses.read("fixture-server", "fixture-installation", ServiceLogPointer("fixture-operation", "foreign"))
        assertNull(result.snapshot)
        assertFalse(result.terminal)
    }
    @Test fun processDeathKeepsOnlyDurableCompletionWithoutInventingLogDetails() = runSuspend {
        val f = Fixture(); f.actions.start("fixture-server", "fixture-installation", "fixture-access"); f.runHost()
        val result = JournalServiceLogStatusPort(f.journal, ServiceLogResultRegistry()).read("fixture-server", "fixture-installation",
            ServiceLogPointer("fixture-operation", "fixture-access"))
        assertTrue(result.terminal); assertNull(result.snapshot)
        assertTrue(result.text.contains("Детали не сохранены"))
    }
    @Test fun staleProcessRevisionCannotSupplyAnOldSnapshot() = runSuspend {
        val f = Fixture(); f.actions.start("fixture-server", "fixture-installation", "fixture-access")
        f.registry.publish(OperationId("fixture-operation"), f.runHost().toServiceLogProcessResult())
        f.current = f.current!!.copy(revision = OperationRevision(20))
        val result = f.statuses.read("fixture-server", "fixture-installation", ServiceLogPointer("fixture-operation", "fixture-access"))
        assertNull(result.snapshot)
        assertTrue(result.terminal)
    }
    private class Fixture {
        private val at = Instant.now()
        private val server = ServerId("fixture-server")
        val access = ServerAccess(ServerAccessId("fixture-access"), server, SshEndpoint("fixture.invalid", 22), "operator",
            SshAuthRef.Password(SecretId("fixture-reference")), HostKeyFingerprint("SHA256:fixture"))
        val installation = XuiInstallation(XuiInstallationId("fixture-installation"), server, InstallationOwnership.ADOPTED,
            InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
            InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", at.minusSeconds(60)))
        val local = ManagementLocalReviewPort { server, install ->
            check(server == "fixture-server" && install == "fixture-installation")
            LocalManagementReview.Ready("Fixture VPS", server, install, "ADOPTED", "x-ui.service", 2053, "/panel/", 1, listOf("fixture-access"))
        }
        val registry = ServiceLogResultRegistry()
        var current: VersionedOperationSnapshot? = null
        var connects = 0
        var closed = 0
        val labels = mutableListOf<String>()
        val hostRequests = mutableListOf<OperationId>()
        val journal = object : OperationJournal {
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
                            "management-panel-settings" -> "PORT=2053\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=127.0.0.1\n"
                            "management-service-state" -> "active\n"
                            "deep-service-definition" -> "LOAD=loaded\nEXEC={ path=/usr/local/x-ui/x-ui ; }\n"
                            "service-log-read-bounded" -> """{"__REALTIME_TIMESTAMP":"1800000000000000","PRIORITY":"4","MESSAGE":"timeout secret=excluded","_SYSTEMD_UNIT":"x-ui.service"}"""
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
        // whether it owns this operation. This capability must exist even for a log-only test.
        private val publisher = object : ManagementEnrollmentPublisher {
            override suspend fun publish(request: ManagementEnrollmentRequest): ManagementEnrollmentPublicationResult =
                error("Service logs must never publish an installation")
            override suspend fun publishInstaller(request: InstallerManagementPublicationRequest): ManagementEnrollmentPublicationResult =
                error("Service logs must never invoke Installer publication")
            override suspend fun republishReinstall(request: ExistingInstallationReinstallPublicationRequest): ExistingInstallationReinstallPublicationResult =
                error("Service logs must never invoke Reinstall publication")
        }
        val coordinator = OperationRuntimeCoordinator(journal, accesses, factory, ExactSessionRegistry(), installations, management, publisher)
        val actions = ProductionServiceLogActionPort(local, journal, registry,
            { id -> hostRequests += id; ExactOperationHostStartResult.START_REQUEST_ACCEPTED }, idFactory = { OperationId("fixture-operation") })
        val statuses = JournalServiceLogStatusPort(journal, registry)
        suspend fun runHost(): ExactOperationHostTransportSequenceResult {
            val c = checkNotNull(current)
            val action = RecoveryAction.RECONNECT_EXACT_OWNER
            val plan = ColdStartRecoveryPlan(c.snapshot.operationId, c.snapshot.target, c.revision, action, automaticAllowed = false)
            val admission = (coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED) as RecoveryAdmissionResult.Admitted).admission
            try {
                // Fixture stands in for the next Android callback registration's actual observation.
                coordinator.observeConnectivity(ConnectivityState.ONLINE)
                return ExactOperationHostTransportSequence(ExactOperationHostRuntimeTransportBridge(coordinator)).run(
                    ExactOperationHostRuntimeBinding(c.snapshot.operationId, CoordinatorAdmissionToken(admission)), RetryBudget(1))
            } finally { assertEquals(OperationRuntimeReleaseResult.RELEASED, coordinator.release(admission)) }
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
