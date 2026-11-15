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

/** Actual production actions, journal, shared coordinator, host, and SSH adapters; scripted remote bytes only. */
class RestoreCheckProductionCompositionTest {
    @Test fun sourceReviewThenOneCopyThenSeparateReadbackUseThreeOwnedSessions() = runSuspend {
        val f=Fixture();assertTrue(f.inspect() is RestoreCheckRuntimeResult.Reviewed);assertEquals(0,f.copyCommands)
        assertTrue(f.copy() is RestoreCheckRuntimeResult.AwaitingVerification)
        assertEquals(0,f.labels.count{it=="restore-check-verify-existing"})
        assertNull(f.actions.checkConfirmed(f.review,"fixture-operation"));assertTrue(f.runRestoreHost() is RestoreCheckRuntimeResult.Completed)
        assertEquals(1,f.copyCommands);assertEquals(3,f.connects);assertEquals(3,f.closed)
        assertEquals(OperationStatus.SUCCEEDED,f.current!!.snapshot.status)
        val o=JournalRestoreCheckStatusPort(f.journal,f.local,f.registry).read(f.review.serverId,f.review.installationId,f.review.accessId,"fixture-operation")!!
        assertEquals(12288L,o.receipt!!.restoredBytes);assertEquals("source-backup",o.sourceOperationId)
    }
    @Test fun sourceInspectionAndReloadNeverStartCopyOrVerifyRestoredFiles() = runSuspend {
        val f=Fixture();f.inspect();assertEquals(listOf("installation-backup-verify-existing"),f.labels)
        assertEquals(0,f.copyCommands);assertEquals(CheckpointSemantics.MUTATION_NOT_STARTED,f.current!!.snapshot.checkpoint.semantics)
    }
    @Test fun invalidSourceProofCannotEnableCopy() = runSuspend {
        val f=Fixture();f.validProof=false;assertTrue(f.inspect() is RestoreCheckRuntimeResult.Failed)
        assertNotNull(f.actions.restoreConfirmed(f.review,"fixture-operation",f.binding));assertEquals(0,f.copyCommands)
    }
    @Test fun mismatchedReviewedHashCannotCreateFreshAuthority() = runSuspend {
        val f=Fixture();f.inspect();assertNotNull(f.actions.restoreConfirmed(f.review,"fixture-operation",f.binding.copy(archiveSha256="f".repeat(64))))
        assertEquals(1,f.connects);assertEquals(0,f.copyCommands)
    }
    @Test fun lostCopyConfirmationBlocksBeforeOpeningAnotherConnection() = runSuspend {
        val f=Fixture();f.inspect();f.actions.restoreConfirmed(f.review,"fixture-operation",f.binding);f.newProcess()
        val r=f.runHost() as ExactOperationHostTransportSequenceResult.RestoreCheckPrepared
        assertEquals(RestoreCheckRuntimeResult.Rejected(RestoreCheckFailure.AUTHORITY_MISSING),r.restore)
        assertEquals(1,f.connects);assertEquals(0,f.copyCommands)
    }
    @Test fun unknownOutcomeCanOnlyReadBackAfterProcessDeath() = runSuspend {
        val f=Fixture();f.inspect();f.uncertainDispatch=true;assertTrue(f.copy() is RestoreCheckRuntimeResult.AwaitingVerification)
        f.newProcess();assertNull(f.actions.checkConfirmed(f.review,"fixture-operation"));assertTrue(f.runRestoreHost() is RestoreCheckRuntimeResult.Completed)
        assertEquals(1,f.copyCommands);assertEquals(3,f.closed)
    }
    @Test fun missingReadbackAfterUnknownCopyKeepsDurableMutationBarrier() = runSuspend {
        val f=Fixture();f.inspect();f.uncertainDispatch=true;f.copy();f.validProof=false;f.newProcess()
        f.actions.checkConfirmed(f.review,"fixture-operation");assertTrue(f.runRestoreHost() is RestoreCheckRuntimeResult.AwaitingVerification)
        assertTrue(f.actions.inspectConfirmed(f.review,"source-backup") is RestoreCheckStart.Blocked);assertEquals(1,f.copyCommands)
    }
    @Test fun confirmedWorkerFailureClosesOnlyAfterExplicitNegativeCheck() = runSuspend {
        val f=Fixture();f.inspect();f.failureCode=81;f.copy();f.validProof=false
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED,f.current!!.snapshot.status)
        f.actions.checkConfirmed(f.review,"fixture-operation");assertTrue(f.runRestoreHost() is RestoreCheckRuntimeResult.Failed);assertEquals(1,f.copyCommands)
    }
    @Test fun timeoutAndAbsentDirectoryDoNotProveWriterStopped() = runSuspend {
        val f=Fixture();f.inspect();f.failureCode=124;f.copy();f.validProof=false
        f.actions.checkConfirmed(f.review,"fixture-operation");assertTrue(f.runRestoreHost() is RestoreCheckRuntimeResult.AwaitingVerification)
        assertEquals(OperationStatus.RECONCILIATION_REQUIRED,f.current!!.snapshot.status)
    }
    @Test fun fullQuotaBlocksBeforeFirstWrite() = runSuspend {
        val f=Fixture();f.inspect();f.slots=4;assertTrue(f.copy() is RestoreCheckRuntimeResult.Failed);assertEquals(0,f.copyCommands)
    }
    @Test fun failedDurableCopyCheckpointCannotDispatch() = runSuspend {
        val f=Fixture();f.inspect();f.rejectCas=true;assertTrue(f.copy() is RestoreCheckRuntimeResult.Rejected);assertEquals(0,f.copyCommands)
    }
    @Test fun pendingCancellationIsLocalAndNeverReplaysSourceOrCopy() = runSuspend {
        val f=Fixture();f.inspect();val count=f.labels.size;assertNull(f.actions.cancelPending(f.review,"fixture-operation"))
        assertEquals(OperationStatus.CANCELLED,f.current!!.snapshot.status);assertEquals(count,f.labels.size);assertEquals(0,f.copyCommands)
    }
    @Test fun accessDriftDuringSpaceReadCannotCrossWriteBoundary() = runSuspend {
        val f=Fixture();f.inspect();f.afterCommand={if(it=="restore-check-storage") f.storedAccess=f.access.copy(username="changed")}
        assertTrue(f.copy() is RestoreCheckRuntimeResult.Rejected);assertEquals(0,f.copyCommands)
    }
    @Test fun parentRevisionDriftDuringSourceReadCannotPublishReview() = runSuspend {
        val f=Fixture();f.afterCommand={if(it=="installation-backup-verify-existing") f.parent=f.parent.copy(revision=OperationRevision(3))}
        assertTrue(f.inspect() is RestoreCheckRuntimeResult.Rejected);assertEquals(0,f.copyCommands)
    }
    @Test fun pinDriftDuringFinalReadbackCannotPublishReceipt() = runSuspend {
        val f=Fixture();f.inspect();f.copy();f.actions.checkConfirmed(f.review,"fixture-operation")
        f.afterCommand={if(it=="restore-check-verify-existing") f.storedAccess=f.access.copy(pinnedHostKey=HostKeyFingerprint("SHA256:changed"))}
        assertTrue(f.runRestoreHost() is RestoreCheckRuntimeResult.Rejected);assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED,f.current!!.snapshot.checkpoint.semantics)
    }
    @Test fun emptyNewProcessRegistryKeepsDurableSourceHashesButCannotInventRestoreBytes() = runSuspend {
        val f=Fixture();f.inspect();f.copy();f.actions.checkConfirmed(f.review,"fixture-operation");f.runRestoreHost();val count=f.labels.size
        val o=JournalRestoreCheckStatusPort(f.journal,f.local,RestoreCheckResultRegistry()).read(f.review.serverId,f.review.installationId,f.review.accessId,"fixture-operation")!!
        assertTrue(o.terminal);assertNull(o.receipt);assertEquals("b".repeat(64),o.sourceProof!!.archiveSha256);assertEquals(count,f.labels.size)
    }
    @Test fun allColdStartPhasesRequireExplicitAction() = runSuspend {
        val f=Fixture();f.inspect()
        for(semantics in listOf(CheckpointSemantics.READ_ONLY,CheckpointSemantics.MUTATION_NOT_STARTED,CheckpointSemantics.MUTATION_IN_FLIGHT,CheckpointSemantics.POST_VERIFY_REQUIRED)) {
            val current=f.current!!.copy(snapshot=f.current!!.snapshot.copy(checkpoint=f.current!!.snapshot.checkpoint.copy(semantics=semantics)))
            val plan=ColdStartRecoveryPlanPolicy.plan(RecoveryPlanInput(current,OperationDurabilityValidation.Valid,RecoveryExitProvenance.PROCESS_DEATH));assertFalse(plan.automaticAllowed)
        }
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
        private val sourceId = OperationId("source-backup")
        private val sourceBinding = InstallationBackupBindingPolicy.bind(sourceId, installation, access, "3.10.0", UpdateServerArchitecture.AMD64)
        var parent = VersionedOperationSnapshot(OperationSnapshot(sourceId, OperationType.INSTALLATION_BACKUP,
            OperationTarget.InstallationTarget(server, access.id, installation.id), OperationStatus.SUCCEEDED,
            OperationCheckpoint(sourceBinding.phaseName(InstallationBackupPhase.VERIFIED), CheckpointSemantics.TERMINAL, at), at, at), OperationRevision(2))
        var current: VersionedOperationSnapshot? = null
        val binding get() = requireNotNull(RestoreCheckBinding.parse(current!!.snapshot.checkpoint.phaseName)).second
        var uid = "0\n"
        var uncertainDispatch = false
        var failureCode: Int? = null
        var connects = 0
        var closed = 0
        var copyCommands = 0
        var slots = 0
        var validProof = true
        var rejectCas = false
        var afterCommand: (String) -> Unit = {}
        var storedAccess = access
        val labels = mutableListOf<String>()
        val hostRequests = mutableListOf<OperationId>()
        val journal = object : OperationJournal {
            override suspend fun create(initial: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
                check(current == null); current = VersionedOperationSnapshot(initial, OperationRevision(0))
                return OperationJournalResult.Success(checkNotNull(current))
            }
            override suspend fun get(operationId: OperationId): OperationJournalResult<VersionedOperationSnapshot> =
                (if (operationId == sourceId) parent else current?.takeIf { it.snapshot.operationId == operationId })
                    ?.let { OperationJournalResult.Success(it) } ?: OperationJournalResult.NotFound
            override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> =
                OperationJournalResult.Success(listOfNotNull(current?.takeIf { it.snapshot.checkpoint.semantics != CheckpointSemantics.TERMINAL }))
            override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot): OperationJournalResult<VersionedOperationSnapshot> {
                val before = current ?: return OperationJournalResult.NotFound
                if (operationId != before.snapshot.operationId) return OperationJournalResult.NotFound
                if (expectedRevision != before.revision) return OperationJournalResult.StaleRevision(expectedRevision, before.revision)
                if (rejectCas) return OperationJournalResult.StorageFailure("fixture CAS rejected")
                current = VersionedOperationSnapshot(next, OperationRevision(before.revision.value + 1))
                return OperationJournalResult.Success(checkNotNull(current))
            }
            override suspend fun history(operationId: OperationId) = OperationJournalResult.Success(emptyList<OperationJournalEntry>())
        }
        private val accesses = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> =
                if (serverAccessId == access.id) RepositoryResult.Success(storedAccess) else RepositoryResult.NotFound
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
                        val b = this@Fixture.binding
                        val sourceProof = "FORMAT=VELUM_KNOWN_INSTALLATION_V1\nSCOPE=${b.source.digest}\nVERSION=3.10.0\nARCH=AMD64\nBYTES=4096\nSHA256=${"b".repeat(64)}\nDATABASE_SHA256=${"c".repeat(64)}\nFILES=3\nINVENTORY_SHA256=${"d".repeat(64)}\n"
                        val proof = "FORMAT=VELUM_RESTORE_FILES_V1\nSCOPE=${b.digest}\nSOURCE_SCOPE=${b.source.digest}\nVERSION=3.10.0\nARCH=AMD64\nBYTES=12288\nSHA256=${"b".repeat(64)}\nDATABASE_SHA256=${"c".repeat(64)}\nFILES=3\nINVENTORY_SHA256=${"d".repeat(64)}\n"
                        val text = when (command.redactedLabel) {
                            "installation-backup-verify-existing" -> if (validProof) sourceProof else "MISSING\n"
                            "restore-check-storage" -> "$slots\n4096000000\n"
                            "restore-check-create-once" -> {
                                assertEquals(CheckpointSemantics.MUTATION_IN_FLIGHT, current!!.snapshot.checkpoint.semantics)
                                copyCommands++
                                failureCode?.let { code -> return SshCommandResult(CommandDispatchState.DISPATCHED,
                                    CommandCompletion.ConfirmedFailure("fixture stopped worker", code), CapturedOutput.EMPTY, CapturedOutput.EMPTY) }
                                if (uncertainDispatch) return SshCommandResult(CommandDispatchState.DISPATCHED,
                                    CommandCompletion.Unknown("fixture connection dropped"), CapturedOutput.EMPTY, CapturedOutput.EMPTY)
                                "RESTORED\n"
                            }
                            "restore-check-verify-existing" -> if (validProof) proof else "MISSING\n"
                            else -> error("Restore-check transport must use only its bounded command labels")
                        }
                        afterCommand(command.redactedLabel)
                        return SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess,
                            CapturedOutput.of(text.encodeToByteArray(), truncated = false), CapturedOutput.EMPTY)
                    }
                    override fun close() { if (sessionOpen) closed++; sessionOpen = false }
                })
            }
        }
        // Match the complete application graph: the generic host first asks the Installer consumer
        // whether it owns this operation. This capability must exist even for a backup-only test.
        private val publisher = object : ManagementEnrollmentPublisher {
            override suspend fun publish(request: ManagementEnrollmentRequest): ManagementEnrollmentPublicationResult =
                error("BACKUP must never publish an installation")
            override suspend fun publishInstaller(request: InstallerManagementPublicationRequest): ManagementEnrollmentPublicationResult =
                error("BACKUP must never invoke Installer publication")
            override suspend fun republishReinstall(request: ExistingInstallationReinstallPublicationRequest): ExistingInstallationReinstallPublicationResult =
                error("BACKUP must never invoke Reinstall publication")
        }
        var coordinator = OperationRuntimeCoordinator(journal, accesses, factory, ExactSessionRegistry(), installations, management, publisher)
        val local = ManagementRestartLocalPort { _, _, _ -> ManagementRestartLocalReview.Ready(currentReview) }
        val registry = RestoreCheckResultRegistry()
        val actions get() = ProductionRestoreCheckActionPort(local, journal, coordinator, registry,
            { id -> hostRequests += id; ExactOperationHostStartResult.START_REQUEST_ACCEPTED }, idFactory = { OperationId("fixture-operation") })
        suspend fun inspect(): RestoreCheckRuntimeResult {
            assertEquals(RestoreCheckStart.Recorded("fixture-operation"), actions.inspectConfirmed(review, "source-backup"))
            return runRestoreHost()
        }
        suspend fun copy(): RestoreCheckRuntimeResult {
            assertNull(actions.restoreConfirmed(review, "fixture-operation", binding))
            return runRestoreHost()
        }
        fun newProcess() { coordinator = OperationRuntimeCoordinator(journal, accesses, factory, ExactSessionRegistry(), installations, management, publisher) }
        suspend fun runHost(): ExactOperationHostTransportSequenceResult {
            val c = checkNotNull(current)
            val action = if (c.snapshot.checkpoint.semantics in setOf(CheckpointSemantics.READ_ONLY, CheckpointSemantics.MUTATION_NOT_STARTED)) RecoveryAction.RECONNECT_EXACT_OWNER else RecoveryAction.RECONCILE_READ_ONLY
            val plan = ColdStartRecoveryPlan(c.snapshot.operationId, c.snapshot.target, c.revision, action, automaticAllowed = false)
            val admission = (coordinator.admitRecovery(plan, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED) as RecoveryAdmissionResult.Admitted).admission
            try {
                // Fixture stands in for the next Android callback registration's actual observation.
                coordinator.observeConnectivity(ConnectivityState.ONLINE)
                return ExactOperationHostTransportSequence(ExactOperationHostRuntimeTransportBridge(coordinator)).run(
                    ExactOperationHostRuntimeBinding(c.snapshot.operationId, CoordinatorAdmissionToken(admission)), RetryBudget(1))
            } finally { assertEquals(OperationRuntimeReleaseResult.RELEASED, coordinator.release(admission)) }
        }
        suspend fun runRestoreHost(): RestoreCheckRuntimeResult {
            val result = runHost()
            assertTrue("Expected exact RestoreCheckEnded, got $result", result is ExactOperationHostTransportSequenceResult.RestoreCheckEnded)
            registry.publish(current!!.snapshot.operationId, result.restoreCheckResult())
            return (result as ExactOperationHostTransportSequenceResult.RestoreCheckEnded).restore
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
