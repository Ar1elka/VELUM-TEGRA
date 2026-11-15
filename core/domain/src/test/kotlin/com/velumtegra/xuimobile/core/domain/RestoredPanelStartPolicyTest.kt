package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class RestoredPanelStartPolicyTest {
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
    private val restoredBinding=WorkingDatabaseRestoreBindingPolicy.bind(OperationId("restore-db"),installation,access,comparison,check,backup)
    private val parent=VersionedOperationSnapshot(OperationSnapshot(OperationId("restore-db"),OperationType.WORKING_DATABASE_RESTORE,target,OperationStatus.SUCCEEDED,OperationCheckpoint(restoredBinding.phaseName(WorkingDatabaseRestorePhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(5))
    private val binding=RestoredPanelStartBindingPolicy.bind(OperationId("start-service"),installation,access,parent,comparison,check,backup)
    private val current=VersionedOperationSnapshot(OperationSnapshot(OperationId("start-service"),OperationType.RESTORED_PANEL_START,target,OperationStatus.RUNNING,OperationCheckpoint(binding.phaseName(RestoredPanelStartPhase.PENDING),CheckpointSemantics.MUTATION_NOT_STARTED,at),at,at),OperationRevision(0))
    private fun confirmation(c:VersionedOperationSnapshot=current,time:Instant=at)=RestoredPanelStartConfirmationPolicy.confirm(c,installation,access,parent,comparison,check,backup,time)
    private fun ready()=RestoredPanelStartReady(ManagementScope(current.snapshot.operationId,installation.serverId,access.id,installation.id),binding,at)
    @Test fun exactFourParentChainMatches(){assertTrue(RestoredPanelStartBindingPolicy.matches(current,installation,access,parent,comparison,check,backup))}
    @Test fun allPhasesRoundTripNestedSource(){for(p in RestoredPanelStartPhase.values())assertEquals(p to binding,RestoredPanelStartBinding.parse(binding.phaseName(p)))}
    @Test fun signedRevisionAndTrailingDataReject(){assertNull(RestoredPanelStartBinding.parse(binding.phaseName(RestoredPanelStartPhase.PENDING)+":x"));assertNull(RestoredPanelStartBinding.parse(binding.phaseName(RestoredPanelStartPhase.PENDING).replace(":5:",":+5:")))}
    @Test fun unverifiedRestoreCannotAuthorizeServiceStart(){val bad=parent.copy(snapshot=parent.snapshot.copy(status=OperationStatus.RECONCILIATION_REQUIRED));assertFalse(RestoredPanelStartBindingPolicy.parentMatches(bad,comparison,check,backup,installation,access))}
    @Test fun parentAndComparisonRevisionsFenceChild(){assertFalse(RestoredPanelStartBindingPolicy.matches(current,installation,access,parent.copy(revision=OperationRevision(6)),comparison,check,backup));assertFalse(RestoredPanelStartBindingPolicy.matches(current,installation,access,parent,comparison.copy(revision=OperationRevision(6)),check,backup))}
    @Test fun originalBackupRevisionCannotChange(){assertFalse(RestoredPanelStartBindingPolicy.matches(current,installation,access,parent,comparison,check,backup.copy(revision=OperationRevision(8))))}
    @Test fun changedPinCredentialsAndBaselineReject(){for(a in listOf(access.copy(username="other"),access.copy(pinnedHostKey=HostKeyFingerprint("SHA256:other")),access.copy(auth=SshAuthRef.Password(SecretId("other")))))assertFalse(RestoredPanelStartBindingPolicy.matches(current,installation,a,parent,comparison,check,backup));assertFalse(RestoredPanelStartBindingPolicy.matches(current,installation.copy(baseline=installation.baseline.copy(panelPort=9999)),access,parent,comparison,check,backup))}
    @Test fun explicitConsentBoundedToNinetySeconds(){assertEquals(at.plusSeconds(90),confirmation()!!.validUntil);assertNull(confirmation(time=at.plusSeconds(300)));assertNull(confirmation(time=at.minusSeconds(1)))}
    @Test fun unsafePhaseCannotReconstructStartConsent(){assertNull(confirmation(current.copy(snapshot=current.snapshot.copy(checkpoint=OperationCheckpoint(binding.phaseName(RestoredPanelStartPhase.STARTING),CheckpointSemantics.MUTATION_IN_FLIGHT,at)))))}
    @Test fun terminalCannotAuthorizeStartAgain(){assertNull(confirmation(current.copy(snapshot=current.snapshot.copy(status=OperationStatus.SUCCEEDED))))}
    @Test fun typedReadyEvidenceIsNecessaryAndExact(){val c=confirmation()!!;assertNotNull(RestoredPanelStartDispatchPolicy.authorize(c,current,ready(),at));assertNull(RestoredPanelStartDispatchPolicy.authorize(c,current,ready().copy(scope=ready().scope.copy(operationId=OperationId("other"))),at))}
    @Test fun preflightAgeAndFutureFenceDispatch(){assertNull(RestoredPanelStartDispatchPolicy.authorize(confirmation()!!,current,ready().copy(observedAt=at.minusSeconds(31)),at));assertNull(RestoredPanelStartDispatchPolicy.authorize(confirmation()!!,current,ready().copy(observedAt=at.plusSeconds(1)),at))}
    @Test fun dispatchOnlyNextCasAndOnlyOnce(){val d=RestoredPanelStartDispatchPolicy.authorize(confirmation()!!,current,ready(),at)!!;assertFalse(d.consumeOnce(OperationRevision(0),at));assertTrue(d.consumeOnce(OperationRevision(1),at));assertFalse(d.consumeOnce(OperationRevision(1),at))}
    @Test fun expiredDispatchCannotStart(){val d=RestoredPanelStartDispatchPolicy.authorize(confirmation()!!,current,ready(),at)!!;assertFalse(d.consumeOnce(OperationRevision(1),at.plusSeconds(90)))}
    @Test fun receiptMustMatchReleaseAndBoundedFacts(){try{RestoredPanelStartReceipt(ready().scope,binding,"3.10.2",UpdateServerArchitecture.AMD64,"a".repeat(64),1,at);fail("release")}catch(_:IllegalArgumentException){};try{RestoredPanelStartReceipt(ready().scope,binding,"3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64),257,at);fail("count")}catch(_:IllegalArgumentException){}}
    @Test fun childIdChangesDigestButKeepsExactSource(){val other=RestoredPanelStartBindingPolicy.bind(OperationId("other"),installation,access,parent,comparison,check,backup);assertNotEquals(binding.digest,other.digest);assertEquals(binding.restored,other.restored)}
}
