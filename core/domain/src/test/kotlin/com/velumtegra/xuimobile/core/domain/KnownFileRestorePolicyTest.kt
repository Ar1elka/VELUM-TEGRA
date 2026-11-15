package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class KnownFileRestorePolicyTest{
    @Test fun changedStoppedCandidateBindsExactDurableParent(){val f=Fixture();assertNotNull(f.binding());assertTrue(KnownFileRestorePolicy.candidate(f.evidence(),f.at))}
    @Test fun unchangedFilesDoNotCreateMutation(){val f=Fixture();assertFalse(KnownFileRestorePolicy.candidate(f.evidence().copy(changedCommon=0,groups=f.evidence().groups+(RecoveryFileGroup.RUNTIME to RecoveryGroupDifference(2,2,0,0,0))),f.at))}
    @Test fun liveAndUnknownServiceBlock(){val f=Fixture();for(q in listOf(RecoveryQuiescence.REQUIRED,RecoveryQuiescence.UNAVAILABLE))assertFalse(KnownFileRestorePolicy.candidate(f.evidence().copy(quiescence=q),f.at))}
    @Test fun serviceUnitChangesBlockBeforeRemotePreparation(){val f=Fixture();assertFalse(KnownFileRestorePolicy.candidate(f.evidence().copy(groups=f.evidence().groups+(RecoveryFileGroup.SERVICE to RecoveryGroupDifference(1,1,1,0,0))),f.at))}
    @Test fun releaseArchitectureSchemaEndpointAndPageDriftBlock(){val f=Fixture();val e=f.evidence();for(p in listOf(e.copy(currentVersion="3.10.1"),e.copy(currentArchitecture=UpdateServerArchitecture.ARM64),e.copy(currentSchema="9".repeat(64)),e.copy(endpointsMatch=false),e.copy(pageSizesMatch=false)))assertFalse(KnownFileRestorePolicy.candidate(p,f.at))}
    @Test fun exactFreshnessAndClockBoundary(){val f=Fixture();assertNotNull(f.binding());assertNull(f.binding(at=f.at.plusSeconds(90)));assertNull(f.binding(at=f.at.minusSeconds(1)))}
    @Test fun foreignScopeOrRevisionCannotBind(){val f=Fixture();assertNull(f.binding(f.evidence().copy(scope=f.evidence().scope.copy(serverAccessId=ServerAccessId("foreign")))));assertNull(f.binding(f.evidence().copy(comparisonRevision=90)))}
    @Test fun parentRevisionDriftInvalidatesRecord(){val f=Fixture();val c=f.initial();f.comparisonParent=f.comparisonParent.copy(revision=OperationRevision(91));assertFalse(f.matches(c))}
    @Test fun pinAndCredentialDriftInvalidateBinding(){val f=Fixture();val c=f.initial();assertFalse(KnownFileRestorePolicy.matches(c,f.installation,f.access.copy(pinnedHostKey=HostKeyFingerprint("SHA256:foreign")),f.comparisonParent,f.checkedParent,f.backup));assertFalse(KnownFileRestorePolicy.matches(c,f.installation,f.access.copy(auth=SshAuthRef.Password(SecretId("foreign"))),f.comparisonParent,f.checkedParent,f.backup))}
    @Test fun canonicalPhasesRoundTripFullLineage(){val f=Fixture();val b=f.binding()!!;for(p in KnownFileRestorePhase.values())assertEquals(p to b,KnownFileRestoreBinding.parse(b.phaseName(p)))}
    @Test fun noncanonicalAndInjectedPhasesReject(){val f=Fixture();val s=f.binding()!!.phaseName(KnownFileRestorePhase.APPLYING);for(v in listOf(s.replace(":4:",":04:"),s+":extra",s.replace("source-comparison","x;id"),s.replace("KFR1_APPLYING","KFR1_RETRY")))assertNull(KnownFileRestoreBinding.parse(v))}
    @Test fun countsAndHashesCannotInventCoverage(){val f=Fixture();val b=f.binding()!!;assertTrue(runCatching{b.copy(changedFiles=0)}.isFailure);assertTrue(runCatching{b.copy(changedFiles=97)}.isFailure);assertTrue(runCatching{b.copy(currentSetSha256="private path")}.isFailure);assertTrue(runCatching{f.inspection().copy(desiredFiles=1,previousFiles=1)}.isFailure)}
    @Test fun initialRecordIsUncertainAndNeverTerminal(){val f=Fixture();assertTrue(f.matches(f.initial()));assertFalse(f.matches(f.initial().copy(snapshot=f.initial().snapshot.copy(status=OperationStatus.SUCCEEDED))))}
    @Test fun onlyPositiveReadbackTerminalSemanticsMatch(){val f=Fixture();val c=f.initial();val b=f.binding()!!;assertTrue(f.matches(c.copy(snapshot=c.snapshot.copy(status=OperationStatus.SUCCEEDED,checkpoint=OperationCheckpoint(b.phaseName(KnownFileRestorePhase.APPLIED),CheckpointSemantics.TERMINAL,f.at)))));assertFalse(f.matches(c.copy(snapshot=c.snapshot.copy(checkpoint=OperationCheckpoint(b.phaseName(KnownFileRestorePhase.APPLIED),CheckpointSemantics.POST_VERIFY_REQUIRED,f.at)))))}
    @Test fun compensatedTerminalRetainsFailedOriginalMeaning(){val f=Fixture();val c=f.initial();val b=f.binding()!!;assertTrue(f.matches(c.copy(snapshot=c.snapshot.copy(status=OperationStatus.FAILED,checkpoint=OperationCheckpoint(b.phaseName(KnownFileRestorePhase.RETURNED),CheckpointSemantics.TERMINAL,f.at)))))}
    @Test fun dispatchRequiresExactDurableCreateAndOnlyConsumesOnce(){val f=Fixture();val c=f.initial();val d=VerifiedKnownFileRestoreDispatch.afterCreate(c,f.prepared(),f.at,f.at)!!;assertTrue(d.consumeOnce(c,f.at));assertFalse(d.consumeOnce(c,f.at))}
    @Test fun dispatchCannotMintFromAdvancedOrMismatchedCheckpoint(){val f=Fixture();val c=f.initial();assertNull(VerifiedKnownFileRestoreDispatch.afterCreate(c.copy(revision=OperationRevision(1)),f.prepared(),f.at,f.at));assertNull(VerifiedKnownFileRestoreDispatch.afterCreate(c.copy(snapshot=c.snapshot.copy(checkpoint=c.snapshot.checkpoint.copy(recordedAt=f.at.minusSeconds(1)))),f.prepared(),f.at,f.at))}
    @Test fun dispatchExactExpiryAndSnapshotDriftBlock(){val f=Fixture();val c=f.initial();val d=VerifiedKnownFileRestoreDispatch.afterCreate(c,f.prepared(),f.at,f.at)!!;assertFalse(d.consumeOnce(c.copy(revision=OperationRevision(1)),f.at));assertFalse(d.consumeOnce(c,f.at.plusSeconds(30)));assertTrue(d.consumeOnce(c,f.at))}
    @Test fun returnRequiresNextCasRevisionAndFreshIndependentManifest(){val f=Fixture();val c=f.initial();val n=c.copy(snapshot=c.snapshot.copy(checkpoint=OperationCheckpoint(f.binding()!!.phaseName(KnownFileRestorePhase.RETURNING),CheckpointSemantics.POST_VERIFY_REQUIRED,f.at)),revision=OperationRevision(1));val d=VerifiedKnownFileRestoreDispatch.afterReturnCheckpoint(c,n,f.inspection(),f.at,f.at)!!;assertEquals(KnownFileRestoreWrite.RETURN,d.action);assertTrue(d.consumeOnce(n,f.at));assertNull(VerifiedKnownFileRestoreDispatch.afterReturnCheckpoint(c,n.copy(revision=OperationRevision(2)),f.inspection(),f.at,f.at))}
    @Test fun completedApplyCannotMintCompensation(){val f=Fixture();val c=f.initial();val done=c.copy(snapshot=c.snapshot.copy(status=OperationStatus.SUCCEEDED,checkpoint=OperationCheckpoint(f.binding()!!.phaseName(KnownFileRestorePhase.APPLIED),CheckpointSemantics.TERMINAL,f.at)));assertNull(VerifiedKnownFileRestoreDispatch.afterReturnCheckpoint(done,c,f.inspection(),f.at,f.at))}
    @Test fun desiredCompleteProofCannotMintPartialCompensation(){val f=Fixture();val c=f.initial();val n=c.copy(snapshot=c.snapshot.copy(checkpoint=OperationCheckpoint(f.binding()!!.phaseName(KnownFileRestorePhase.RETURNING),CheckpointSemantics.POST_VERIFY_REQUIRED,f.at)),revision=OperationRevision(1));assertNull(VerifiedKnownFileRestoreDispatch.afterReturnCheckpoint(c,n,f.inspection().copy(desiredFiles=1,previousFiles=0),f.at,f.at))}
    private class Fixture{
        var at = Instant.now()
        val server = ServerId("fixture-server")
        val access = ServerAccess(ServerAccessId("fixture-access"), server, SshEndpoint("fixture.invalid", 22), "operator",
            SshAuthRef.Password(SecretId("fixture-reference")), HostKeyFingerprint("SHA256:fixture"))
        val installation = XuiInstallation(XuiInstallationId("fixture-installation"), server, InstallationOwnership.ADOPTED,
            InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
            InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", at.minusSeconds(60)))
        private val sourceId = OperationId("source-backup")
        private val sourceBinding = InstallationBackupBindingPolicy.bind(sourceId, installation, access, "3.10.0", UpdateServerArchitecture.AMD64)
        var backup = VersionedOperationSnapshot(OperationSnapshot(sourceId, OperationType.INSTALLATION_BACKUP,
            OperationTarget.InstallationTarget(server, access.id, installation.id), OperationStatus.SUCCEEDED,
            OperationCheckpoint(sourceBinding.phaseName(InstallationBackupPhase.VERIFIED), CheckpointSemantics.TERMINAL, at), at, at), OperationRevision(2))
        private val checkId = OperationId("source-check")
        private val checkedBinding = RestoreCheckBindingPolicy.bind(checkId, installation, access, backup, "b".repeat(64), "c".repeat(64), "d".repeat(64), 4096, 3)
        var checkedParent = VersionedOperationSnapshot(OperationSnapshot(checkId, OperationType.INSTALLATION_RESTORE_CHECK,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(checkedBinding.phaseName(RestoreCheckPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(3))
        val comparisonId=OperationId("source-comparison")
        val comparisonBinding=RestoreCompatibilityBindingPolicy.bind(comparisonId,installation,access,checkedParent,backup)
        var comparisonParent=VersionedOperationSnapshot(OperationSnapshot(comparisonId,OperationType.RESTORE_COMPATIBILITY,backup.snapshot.target,
            OperationStatus.SUCCEEDED,OperationCheckpoint(comparisonBinding.phaseName(RestoreCompatibilityPhase.OBSERVED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(4))

        fun evidence():RecoveryReadinessEvidence{
            val groups=RecoveryFileGroup.values().associateWith{when(it){RecoveryFileGroup.RUNTIME->RecoveryGroupDifference(2,2,1,0,0);RecoveryFileGroup.SERVICE->RecoveryGroupDifference(1,1,0,0,0);else->RecoveryGroupDifference(0,0,0,0,0)}}
            return RecoveryReadinessEvidence(ManagementScope(comparisonId,server,access.id,installation.id),comparisonBinding,comparisonParent.revision.value,"3.10.0",UpdateServerArchitecture.AMD64,"1".repeat(64),"1".repeat(64),groups,3,3,1,0,0,1024,1024,true,true,RecoveryJournalMode.WAL,RecoveryWalPresence.PRESENT,RecoveryQuiescence.STOPPED,"2".repeat(64),at)
        }
        val id=OperationId("files")
        fun binding(e:RecoveryReadinessEvidence=evidence(),at:Instant=this.at)=KnownFileRestorePolicy.bind(id,installation,access,comparisonParent,checkedParent,backup,e,at)
        fun initial():VersionedOperationSnapshot{val b=binding()!!;return VersionedOperationSnapshot(OperationSnapshot(id,OperationType.KNOWN_FILE_RESTORE,backup.snapshot.target,OperationStatus.RECONCILIATION_REQUIRED,OperationCheckpoint(b.phaseName(KnownFileRestorePhase.APPLYING),CheckpointSemantics.POST_VERIFY_REQUIRED,at),at,at),OperationRevision(0))}
        fun matches(c:VersionedOperationSnapshot)=KnownFileRestorePolicy.matches(c,installation,access,comparisonParent,checkedParent,backup)
        fun prepared()=KnownFileRestorePrepared(ManagementScope(id,server,access.id,installation.id),binding()!!,"3".repeat(64),at)
        fun inspection()=KnownFileRestoreInspection(ManagementScope(id,server,access.id,installation.id),binding()!!,"4".repeat(64),"3".repeat(64),0,1,at)
    }
}
