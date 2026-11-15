package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class BeforeCopyReturnPolicyTest {
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
    private fun checkpoint(c:VersionedOperationSnapshot=original(),b:BeforeCopyReturnBinding=bound())=c.copy(revision=OperationRevision(6),snapshot=c.snapshot.copy(status=OperationStatus.RECONCILIATION_REQUIRED,checkpoint=OperationCheckpoint(b.phaseName(BeforeCopyReturnPhase.RETURNING),CheckpointSemantics.POST_VERIFY_REQUIRED,at)))
    @Test fun uncertainSourceCanBindExactEvidence(){assertNotNull(BeforeCopyReturnPolicy.bind(original(),evidence(),at))}
    @Test fun pendingOriginalCannotAuthorizeReturn(){val c=original();assertFalse(BeforeCopyReturnPolicy.uncertain(c.copy(snapshot=c.snapshot.copy(checkpoint=c.snapshot.checkpoint.copy(phaseName=binding.phaseName(WorkingDatabaseRestorePhase.PENDING))))))}
    @Test fun verifiedTerminalSourceCannotBeReopened(){val c=original();assertNull(BeforeCopyReturnPolicy.bind(c.copy(snapshot=c.snapshot.copy(status=OperationStatus.SUCCEEDED,checkpoint=OperationCheckpoint(binding.phaseName(WorkingDatabaseRestorePhase.VERIFIED),CheckpointSemantics.TERMINAL,at))),evidence(),at))}
    @Test fun activeServiceCannotAuthorizeReturn(){assertNull(BeforeCopyReturnPolicy.bind(original(),evidence().copy(service=BeforeCopyService.ACTIVE,current=BeforeCopyCurrent.UNAVAILABLE),at))}
    @Test fun sameOrUnavailableCurrentDbCannotAuthorizeCopy(){for(v in listOf(BeforeCopyCurrent.SAME,BeforeCopyCurrent.UNAVAILABLE))assertNull(BeforeCopyReturnPolicy.bind(original(),evidence().copy(current=v),at))}
    @Test fun changedOrUnknownStructureCannotAuthorizeCopy(){for(v in listOf(BeforeCopyStructure.DIFFERENT,BeforeCopyStructure.UNAVAILABLE))assertNull(BeforeCopyReturnPolicy.bind(original(),evidence().copy(structure=v),at))}
    @Test fun staleOrFutureEvidenceRejected(){assertNull(BeforeCopyReturnPolicy.bind(original(),evidence(),at.plusSeconds(300)));assertNull(BeforeCopyReturnPolicy.bind(original(),evidence().copy(observedAt=at.plusSeconds(1)),at))}
    @Test fun foreignTargetEvidenceRejected(){assertNull(BeforeCopyReturnPolicy.bind(original(),evidence().copy(scope=scope.copy(serverAccessId=ServerAccessId("other"))),at))}
    @Test fun foreignSourceBindingRejected(){assertNull(BeforeCopyReturnPolicy.bind(original(),evidence().copy(binding=binding.copy(digest="0".repeat(64))),at))}
    @Test fun phaseBindingRoundTripKeepsOriginalSourceAndHashes(){for(v in BeforeCopyReturnPhase.values()){val b=bound();assertEquals(v to b,BeforeCopyReturnBinding.parse(b.phaseName(v)))}}
    @Test fun nonCanonicalAndForeignPhaseReject(){val s=bound().phaseName(BeforeCopyReturnPhase.RETURNING);assertNull(BeforeCopyReturnBinding.parse(s.replace(":5:",":05:")));assertNull(BeforeCopyReturnBinding.parse(s.replace("BCR1_","OTHER_")))}
    @Test fun onlyDurableNextRevisionMintsDispatch(){assertNotNull(VerifiedBeforeCopyReturnDispatch.afterCheckpoint(original(),checkpoint(),evidence(),at))}
    @Test fun missingCasAndWrongCheckpointCannotMint(){assertNull(VerifiedBeforeCopyReturnDispatch.afterCheckpoint(original(),original(),evidence(),at));assertNull(VerifiedBeforeCopyReturnDispatch.afterCheckpoint(original(),checkpoint().copy(revision=OperationRevision(7)),evidence(),at))}
    @Test fun dispatchIsConsumedExactlyOnce(){val d=VerifiedBeforeCopyReturnDispatch.afterCheckpoint(original(),checkpoint(),evidence(),at)!!;assertTrue(d.consumeOnce(checkpoint(),at));assertFalse(d.consumeOnce(checkpoint(),at))}
    @Test fun expiredAndWrongRevisionCannotConsume(){val d=VerifiedBeforeCopyReturnDispatch.afterCheckpoint(original(),checkpoint(),evidence(),at)!!;assertFalse(d.consumeOnce(checkpoint(),at.plusSeconds(30)));assertFalse(d.consumeOnce(checkpoint().copy(revision=OperationRevision(7)),at));assertTrue(d.consumeOnce(checkpoint(),at))}
    @Test fun returnCheckpointKeepsDurableMutationBarrier(){val c=checkpoint();assertEquals(OperationSnapshotValidation.Valid,OperationJournalContractPolicy.validateAdvance(original().snapshot,c.snapshot));assertEquals(OperationStatus.RECONCILIATION_REQUIRED,c.snapshot.status);assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED,c.snapshot.checkpoint.semantics);assertNull(WorkingDatabaseRestoreBinding.parse(c.snapshot.checkpoint.phaseName))}
}
