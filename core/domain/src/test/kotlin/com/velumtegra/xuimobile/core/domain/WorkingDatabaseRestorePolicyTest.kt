package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class WorkingDatabaseRestorePolicyTest {
    private val at=Instant.parse("2026-10-18T06:00:00Z")
    private val installation=XuiInstallation(XuiInstallationId("install"),ServerId("server"),InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",null),
        InstallationBaseline("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",2053,"/panel/",null,at))
    private val access=ServerAccess(ServerAccessId("ssh"),installation.serverId,SshEndpoint("fixture.invalid",22),"root",SshAuthRef.Password(SecretId("ref")),HostKeyFingerprint("SHA256:fixture"))
    private val target=OperationTarget.InstallationTarget(installation.serverId,access.id,installation.id)
    private val source=InstallationBackupBindingPolicy.bind(OperationId("backup"),installation,access,"3.10.0",UpdateServerArchitecture.AMD64)
    private val backup=VersionedOperationSnapshot(OperationSnapshot(OperationId("backup"),OperationType.INSTALLATION_BACKUP,target,OperationStatus.SUCCEEDED,OperationCheckpoint(source.phaseName(InstallationBackupPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(2))
    private val restored=RestoreCheckBindingPolicy.bind(OperationId("check"),installation,access,backup,"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val check=VersionedOperationSnapshot(OperationSnapshot(OperationId("check"),OperationType.INSTALLATION_RESTORE_CHECK,target,OperationStatus.SUCCEEDED,OperationCheckpoint(restored.phaseName(RestoreCheckPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(3))
    private val comparisonBinding=RestoreCompatibilityBindingPolicy.bind(OperationId("compare"),installation,access,check,backup)
    private val comparison=VersionedOperationSnapshot(OperationSnapshot(OperationId("compare"),OperationType.RESTORE_COMPATIBILITY,target,OperationStatus.SUCCEEDED,OperationCheckpoint(comparisonBinding.phaseName(RestoreCompatibilityPhase.OBSERVED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(4))
    private fun report()=RestoreCompatibilityReport(ManagementScope(comparison.snapshot.operationId,installation.serverId,access.id,installation.id),comparisonBinding,"3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64),"a".repeat(64),RestoreFileSetComparison.MATCH,0,1,1,ManagementServiceState.ACTIVE,ManagementBaselineStatus.Matched,at)
    private val binding=WorkingDatabaseRestoreBindingPolicy.bind(OperationId("restore-db"),installation,access,comparison,check,backup)
    private val current=VersionedOperationSnapshot(OperationSnapshot(OperationId("restore-db"),OperationType.WORKING_DATABASE_RESTORE,target,OperationStatus.RUNNING,OperationCheckpoint(binding.phaseName(WorkingDatabaseRestorePhase.PENDING),CheckpointSemantics.MUTATION_NOT_STARTED,at),at,at),OperationRevision(0))
    private fun confirmation(c:VersionedOperationSnapshot=current,r:RestoreCompatibilityReport=report(),time:Instant=at)=WorkingDatabaseRestoreConfirmationPolicy.confirm(c,installation,access,comparison,check,backup,r,time)
    private fun space()=InstallationBackupStorageObservation(ManagementScope(current.snapshot.operationId,installation.serverId,access.id,installation.id),true,true,0,1024L*1024*1024,at)
    @Test fun allPhasesRoundTripExactNestedPointers(){for(p in WorkingDatabaseRestorePhase.values())assertEquals(p to binding,WorkingDatabaseRestoreBinding.parse(binding.phaseName(p)))}
    @Test fun exactThreeParentChainMatches(){assertTrue(WorkingDatabaseRestoreBindingPolicy.matches(current,installation,access,comparison,check,backup))}
    @Test fun changedComparisonRevisionCannotRebind(){assertFalse(WorkingDatabaseRestoreBindingPolicy.matches(current,installation,access,comparison.copy(revision=OperationRevision(5)),check,backup))}
    @Test fun changedCheckOrBackupRejects(){assertFalse(WorkingDatabaseRestoreBindingPolicy.matches(current,installation,access,comparison,check.copy(revision=OperationRevision(9)),backup));assertFalse(WorkingDatabaseRestoreBindingPolicy.matches(current,installation,access,comparison,check,backup.copy(revision=OperationRevision(9))))}
    @Test fun changedPinCredentialAndBaselineReject(){for(a in listOf(access.copy(username="other"),access.copy(pinnedHostKey=HostKeyFingerprint("SHA256:other")),access.copy(auth=SshAuthRef.Password(SecretId("other")))))assertFalse(WorkingDatabaseRestoreBindingPolicy.matches(current,installation,a,comparison,check,backup));assertFalse(WorkingDatabaseRestoreBindingPolicy.matches(current,installation.copy(baseline=installation.baseline.copy(panelPort=9999)),access,comparison,check,backup))}
    @Test fun canonicalEncodingRejectsExtraOrSignedRevision(){assertNull(WorkingDatabaseRestoreBinding.parse(binding.phaseName(WorkingDatabaseRestorePhase.PENDING)+":extra"));assertNull(WorkingDatabaseRestoreBinding.parse(binding.phaseName(WorkingDatabaseRestorePhase.PENDING).replace(":4:",":+4:")))}
    @Test fun exactObservedReportAllowsBoundedConfirmation(){assertNotNull(confirmation());assertEquals(at.plusSeconds(90),confirmation()!!.validUntil)}
    @Test fun differentVersionOrArchitectureRejects(){assertNull(confirmation(r=report().copy(currentVersion="3.10.2")));assertNull(confirmation(r=report().copy(currentArchitecture=UpdateServerArchitecture.ARM64)))}
    @Test fun changedFilesRejectEvenWhenStructuralPrerequisitesMatch(){val r=report().copy(changedFiles=1);assertTrue(r.prerequisitesMatch);assertNull(confirmation(r=r))}
    @Test fun missingSchemaAndWrongSetReject(){assertNull(confirmation(r=report().copy(currentSchemaSha256=null,currentInbounds=null)));assertNull(confirmation(r=report().copy(fileSet=RestoreFileSetComparison.DIFFERENT)))}
    @Test fun foreignScopeCannotAuthorize(){assertNull(confirmation(r=report().copy(scope=report().scope.copy(operationId=OperationId("other")))));assertNull(confirmation(r=report().copy(scope=report().scope.copy(serverId=ServerId("other")))))}
    @Test fun staleFutureAndDurableOnlyEvidenceCannotAuthorize(){assertNull(confirmation(time=at.plusSeconds(300)));assertNull(confirmation(r=report().copy(observedAt=at.plusSeconds(1))))}
    @Test fun inFlightOrCompletedCannotReconstructConsent(){assertNull(confirmation(c=current.copy(snapshot=current.snapshot.copy(checkpoint=OperationCheckpoint(binding.phaseName(WorkingDatabaseRestorePhase.RESTORING),CheckpointSemantics.MUTATION_IN_FLIGHT,at)))));assertNull(confirmation(c=current.copy(snapshot=current.snapshot.copy(status=OperationStatus.SUCCEEDED))))}
    @Test fun dispatchIsConsumedOnceAtTheNextDurableRevision(){val d=WorkingDatabaseRestoreDispatchPolicy.authorize(confirmation()!!,current,space(),at)!!;assertFalse(d.consumeOnce(OperationRevision(0),at));assertTrue(d.consumeOnce(OperationRevision(1),at));assertFalse(d.consumeOnce(OperationRevision(1),at))}
    @Test fun expiredDispatchCannotWrite(){val d=WorkingDatabaseRestoreDispatchPolicy.authorize(confirmation()!!,current,space(),at)!!;assertFalse(d.consumeOnce(OperationRevision(1),at.plusSeconds(90)))}
    @Test fun insufficientSpaceQuotaAndUnknownRootReject(){for(v in listOf(space().copy(availableBytes=0),space().copy(slotsUsed=4),space().copy(safePrivateRoot=false),space().copy(limitedToolsAvailable=false)))assertNull(WorkingDatabaseRestoreDispatchPolicy.authorize(confirmation()!!,current,v,at))}
    @Test fun oldOrForeignStorageObservationRejects(){assertNull(WorkingDatabaseRestoreDispatchPolicy.authorize(confirmation()!!,current,space().copy(observedAt=at.minusSeconds(31)),at));assertNull(WorkingDatabaseRestoreDispatchPolicy.authorize(confirmation()!!,current,space().copy(scope=space().scope.copy(operationId=OperationId("other"))),at))}
    @Test fun endpointDigestChangesWithBaseline(){val b=WorkingDatabaseRestoreBindingPolicy.bind(OperationId("restore-other"),installation,access,comparison,check,backup);assertEquals(binding.endpointSha256,b.endpointSha256);assertNotEquals(binding.digest,b.digest)}
    @Test fun receiptRejectsInventedHashOrByteCount(){try{WorkingDatabaseRestoreReceipt(space().scope,binding,"x","a".repeat(64),"b".repeat(64),1,at);fail("bad hash")}catch(_:IllegalArgumentException){};try{WorkingDatabaseRestoreReceipt(space().scope,binding,"a".repeat(64),"a".repeat(64),"b".repeat(64),0,at);fail("bad bytes")}catch(_:IllegalArgumentException){}}
    @Test fun inactiveServiceWithOnlyAbsentListenerMayRecoverDatabase(){assertNotNull(confirmation(r=report().copy(serviceState=ManagementServiceState.INACTIVE,baselineStatus=ManagementBaselineStatus.Drift(setOf(ManagementBaselineDrift.EXPECTED_LISTENER_ABSENT)))))}
    @Test fun inactiveServiceCannotHideOtherBaselineDrift(){assertNull(confirmation(r=report().copy(serviceState=ManagementServiceState.INACTIVE,baselineStatus=ManagementBaselineStatus.Insufficient(setOf(ManagementEvidenceGap.PANEL_SETTINGS_UNOBSERVED)))))}

}
