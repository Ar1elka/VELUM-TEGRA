package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class CompensatedPanelStartPolicyTest {
    private val at=Instant.parse("2026-10-18T06:00:00Z")
    private val scope=ManagementScope(OperationId("compare"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val comparison=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private val binding=WorkingDatabaseRestoreBinding(OperationId("compare"),4,comparison,"9".repeat(64),"8".repeat(64))

    private fun original()=VersionedOperationSnapshot(OperationSnapshot(scope.operationId,OperationType.WORKING_DATABASE_RESTORE,
        OperationTarget.InstallationTarget(scope.serverId,scope.serverAccessId,scope.installationId),OperationStatus.RECONCILIATION_REQUIRED,
        OperationCheckpoint(binding.phaseName(WorkingDatabaseRestorePhase.UNCERTAIN),CheckpointSemantics.POST_VERIFY_REQUIRED,at),at,at),OperationRevision(5))
    private fun evidence()=BeforeCopyEvidence(scope,binding,"1".repeat(64),"2".repeat(64),4096,BeforeCopyService.INACTIVE,BeforeCopyCurrent.DIFFERENT,BeforeCopyStructure.MATCH,BeforeCopyCompletion.PARTIAL,at)
    private fun bound()=requireNotNull(BeforeCopyReturnPolicy.bind(original(),evidence(),at))
    private fun returned():VersionedOperationSnapshot{val c=original();return c.copy(revision=OperationRevision(7),snapshot=c.snapshot.copy(checkpoint=OperationCheckpoint(bound().phaseName(BeforeCopyReturnPhase.READBACK_VERIFIED),CheckpointSemantics.POST_VERIFY_REQUIRED,at)))}
    private fun startBinding()=requireNotNull(CompensatedPanelStartPolicy.bind(returned()))
    private fun checkpoint():VersionedOperationSnapshot{val c=returned();return c.copy(revision=OperationRevision(8),snapshot=c.snapshot.copy(checkpoint=OperationCheckpoint(startBinding().phaseName(CompensatedPanelStartPhase.STARTING),CheckpointSemantics.POST_VERIFY_REQUIRED,at)))}
    private fun receipt()=BeforeCopyReturnReceipt(scope,bound(),"3".repeat(64),4096,at)
    private fun dispatch()=VerifiedCompensatedPanelStartDispatch.afterCheckpoint(returned(),checkpoint(),receipt(),at,at)
    @Test fun onlyVerifiedStoppedReturnCanBind(){assertNotNull(CompensatedPanelStartPolicy.bind(returned()));assertNull(CompensatedPanelStartPolicy.bind(original()))}
    @Test fun unfinishedReturnCannotAuthorizeStart(){val c=returned();for(p in listOf(BeforeCopyReturnPhase.RETURNING,BeforeCopyReturnPhase.AWAITING_READBACK))assertNull(CompensatedPanelStartPolicy.bind(c.copy(snapshot=c.snapshot.copy(checkpoint=c.snapshot.checkpoint.copy(phaseName=bound().phaseName(p))))))}
    @Test fun terminalSourceCannotReopen(){val c=returned();assertNull(CompensatedPanelStartPolicy.bind(c.copy(snapshot=c.snapshot.copy(status=OperationStatus.SUCCEEDED,checkpoint=c.snapshot.checkpoint.copy(semantics=CheckpointSemantics.TERMINAL)))))}
    @Test fun bindingRoundTripKeepsExactReturnAndRevision(){for(p in CompensatedPanelStartPhase.values())assertEquals(p to startBinding(),CompensatedPanelStartBinding.parse(startBinding().phaseName(p)))}
    @Test fun nonCanonicalRevisionAndOtherPrefixRejected(){val p=startBinding().phaseName(CompensatedPanelStartPhase.STARTING);assertNull(CompensatedPanelStartBinding.parse(p.replace(":7:",":07:")));assertNull(CompensatedPanelStartBinding.parse(p.replace("CPS1_","OTHER_")))}
    @Test fun differentSourceRevisionChangesBinding(){assertNotEquals(startBinding(),CompensatedPanelStartPolicy.bind(returned().copy(revision=OperationRevision(8))))}
    @Test fun oldCopyAndStartConsumersCannotParseNewAuthority(){assertNull(BeforeCopyReturnBinding.parse(checkpoint().snapshot.checkpoint.phaseName));assertNull(WorkingDatabaseRestoreBinding.parse(checkpoint().snapshot.checkpoint.phaseName));assertNull(RestoredPanelStartBinding.parse(checkpoint().snapshot.checkpoint.phaseName))}
    @Test fun onlyNextExactDurableCheckpointMintsDispatch(){assertNotNull(dispatch());assertNull(VerifiedCompensatedPanelStartDispatch.afterCheckpoint(returned(),returned(),receipt(),at,at));assertNull(VerifiedCompensatedPanelStartDispatch.afterCheckpoint(returned(),checkpoint().copy(revision=OperationRevision(9)),receipt(),at,at))}
    @Test fun freshReadbackMustMatchExactScope(){assertNull(VerifiedCompensatedPanelStartDispatch.afterCheckpoint(returned(),checkpoint(),receipt().copy(scope=scope.copy(serverAccessId=ServerAccessId("foreign"))),at,at))}
    @Test fun expiredOrFutureObservationCannotMint(){assertNull(VerifiedCompensatedPanelStartDispatch.afterCheckpoint(returned(),checkpoint(),receipt().copy(verifiedAt=at.minusSeconds(1)),at,at));assertNull(VerifiedCompensatedPanelStartDispatch.afterCheckpoint(returned(),checkpoint(),receipt().copy(verifiedAt=at.plusSeconds(1)),at,at))}
    @Test fun expiredConsentCannotMint(){assertNull(VerifiedCompensatedPanelStartDispatch.afterCheckpoint(returned(),checkpoint(),receipt(),at.minusSeconds(90),at))}
    @Test fun consumedDispatchCannotReplay(){val d=dispatch()!!;assertTrue(d.consumeOnce(checkpoint(),at));assertFalse(d.consumeOnce(checkpoint(),at))}
    @Test fun dispatchExpiresAtThirtySeconds(){assertFalse(dispatch()!!.consumeOnce(checkpoint(),at.plusSeconds(30)))}
    @Test fun wrongJournalRevisionCannotConsume(){val d=dispatch()!!;assertFalse(d.consumeOnce(checkpoint().copy(revision=OperationRevision(9)),at));assertTrue(d.consumeOnce(checkpoint(),at))}
    @Test fun consentExpiryCapsDispatch(){val d=VerifiedCompensatedPanelStartDispatch.afterCheckpoint(returned(),checkpoint(),receipt(),at.minusSeconds(89),at)!!;assertFalse(d.consumeOnce(checkpoint(),at.plusSeconds(1)))}
    @Test fun everyStartPhaseRetainsNonterminalJournalSemantics(){for(p in CompensatedPanelStartPhase.values()){val c=checkpoint().snapshot.copy(checkpoint=OperationCheckpoint(startBinding().phaseName(p),CheckpointSemantics.POST_VERIFY_REQUIRED,at));assertEquals(OperationSnapshotValidation.Valid,OperationJournalContractPolicy.validateAdvance(returned().snapshot,c));assertEquals(OperationStatus.RECONCILIATION_REQUIRED,c.status)}}
}
