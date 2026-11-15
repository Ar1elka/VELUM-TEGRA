package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class RestoreCheckPolicyTest {
    private val at = Instant.parse("2026-10-18T06:00:00Z")
    private val access = ServerAccess(ServerAccessId("ssh"), ServerId("server"), SshEndpoint("fixture.invalid",22), "root",
        SshAuthRef.Password(SecretId("fixture-ref")), HostKeyFingerprint("SHA256:fixture"))
    private val installation = XuiInstallation(XuiInstallationId("install"), access.serverId, InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",null),
        InstallationBaseline("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",2053,"/panel/",null,at.minusSeconds(60)))
    private val sourceId = OperationId("source-backup")
    private val source = InstallationBackupBindingPolicy.bind(sourceId, installation, access, "3.10.0", UpdateServerArchitecture.AMD64)
    private val parent = VersionedOperationSnapshot(OperationSnapshot(sourceId,OperationType.INSTALLATION_BACKUP,
        OperationTarget.InstallationTarget(installation.serverId,access.id,installation.id),OperationStatus.SUCCEEDED,
        OperationCheckpoint(source.phaseName(InstallationBackupPhase.VERIFIED),CheckpointSemantics.TERMINAL,at),at,at),OperationRevision(2))
    private val id = OperationId("restore-check")
    private val binding = RestoreCheckBindingPolicy.bind(id,installation,access,parent,"b".repeat(64),"c".repeat(64),"d".repeat(64),40960,3)
    private val current = VersionedOperationSnapshot(OperationSnapshot(id,OperationType.INSTALLATION_RESTORE_CHECK,parent.snapshot.target,OperationStatus.RUNNING,
        OperationCheckpoint(binding.phaseName(RestoreCheckPhase.REVIEWED),CheckpointSemantics.MUTATION_NOT_STARTED,at),at,at),OperationRevision(1))
    private val scope = ManagementScope(id,installation.serverId,access.id,installation.id)
    private val space = InstallationBackupStorageObservation(scope,true,true,0,4096000000L,at)
    private val confirmation get() = requireNotNull(RestoreCheckConfirmationPolicy.confirm(current,installation,access,parent,at))
    private fun authorize(c: VersionedOperationSnapshot=current,s: InstallationBackupStorageObservation=space,n: Instant=at) =
        RestoreCheckDispatchPolicy.authorize(confirmation,c,s,n)

    @Test fun exactParentAndAllPhasesRoundTripWithoutPrivateMetadata() {
        assertTrue(RestoreCheckBindingPolicy.matches(current,installation,access,parent))
        RestoreCheckPhase.values().forEach {
            val b = if (it == RestoreCheckPhase.SOURCE_PENDING) RestoreCheckBindingPolicy.bind(id,installation,access,parent) else binding
            assertEquals(it to b,RestoreCheckBinding.parse(b.phaseName(it)))
        }
        assertFalse(binding.phaseName(RestoreCheckPhase.REVIEWED).contains("fixture.invalid"));assertFalse(binding.phaseName(RestoreCheckPhase.REVIEWED).contains("fixture-ref"))
    }
    @Test fun sourceReadRequestCannotBecomeWriteConsent() {
        val b=RestoreCheckBindingPolicy.bind(id,installation,access,parent)
        val pending=current.copy(snapshot=current.snapshot.copy(checkpoint=OperationCheckpoint(b.phaseName(RestoreCheckPhase.SOURCE_PENDING),CheckpointSemantics.READ_ONLY,at)))
        assertNull(RestoreCheckConfirmationPolicy.confirm(pending,installation,access,parent,at));assertFalse(b.hasSourceProof)
    }
    @Test fun phaseAndProofCoherenceCannotBeForgedByJournalText() {
        val b=RestoreCheckBindingPolicy.bind(id,installation,access,parent)
        val pending=b.phaseName(RestoreCheckPhase.SOURCE_PENDING)
        assertNull(RestoreCheckBinding.parse(pending.replace("RCB1_SOURCE_PENDING","RCB1_COPYING")))
        assertNull(RestoreCheckBinding.parse(binding.phaseName(RestoreCheckPhase.REVIEWED).replace("RCB1_REVIEWED","RCB1_SOURCE_PENDING")))
        assertNull(RestoreCheckBinding.parse(binding.phaseName(RestoreCheckPhase.REVIEWED).replace(":2:",":+2:")))
    }
    @Test fun onlyTerminalVerifiedInstallationBackupIsAValidParent() {
        for(p in listOf(parent.copy(snapshot=parent.snapshot.copy(type=OperationType.DATABASE_BACKUP)),
            parent.copy(snapshot=parent.snapshot.copy(status=OperationStatus.FAILED)),
            parent.copy(snapshot=parent.snapshot.copy(checkpoint=parent.snapshot.checkpoint.copy(phaseName=source.phaseName(InstallationBackupPhase.FAILED))))))
            assertFalse(RestoreCheckBindingPolicy.parentMatches(p,installation,access))
    }
    @Test fun sourceRevisionOrPointerChangeInvalidatesBinding() {
        assertFalse(RestoreCheckBindingPolicy.matches(current,installation,access,parent.copy(revision=OperationRevision(3))))
        assertFalse(RestoreCheckBindingPolicy.matches(current,installation,access,parent.copy(snapshot=parent.snapshot.copy(operationId=OperationId("other")))))
    }
    @Test fun endpointCredentialPinAndUsernameRemainExact() {
        for(a in listOf(access.copy(endpoint=SshEndpoint("other.invalid",22)),access.copy(username="other"),
            access.copy(auth=SshAuthRef.Password(SecretId("other"))),access.copy(pinnedHostKey=HostKeyFingerprint("SHA256:changed"))))
            assertFalse(RestoreCheckBindingPolicy.matches(current,installation,a,parent))
    }
    @Test fun changedInstallationOrOperationCannotBorrowSourceProof() {
        assertFalse(RestoreCheckBindingPolicy.matches(current,installation.copy(baseline=installation.baseline.copy(panelPort=9999)),access,parent))
        assertFalse(RestoreCheckBindingPolicy.matches(current.copy(snapshot=current.snapshot.copy(operationId=OperationId("other"))),installation,access,parent))
    }
    @Test fun changingArchiveProofWithoutRebindingIsRejected() {
        val changed=current.copy(snapshot=current.snapshot.copy(checkpoint=current.snapshot.checkpoint.copy(phaseName=binding.copy(archiveSha256="e".repeat(64)).phaseName(RestoreCheckPhase.REVIEWED))))
        assertFalse(RestoreCheckBindingPolicy.matches(changed,installation,access,parent))
        assertNull(RestoreCheckConfirmationPolicy.confirm(changed,installation,access,parent,at))
    }
    @Test fun staleOrFutureReviewCannotCreateConfirmation() {
        assertNull(RestoreCheckConfirmationPolicy.confirm(current,installation,access,parent,at.plusSeconds(300)))
        assertNull(RestoreCheckConfirmationPolicy.confirm(current,installation,access,parent,at.minusSeconds(1)))
    }
    @Test fun expiredConfirmationCannotAuthorizeOrConsume() {
        assertNull(authorize(n=at.plusSeconds(90)));assertNull(authorize(n=at.minusSeconds(1)))
        val permit=requireNotNull(authorize());assertFalse(permit.consumeOnce(OperationRevision(2),at.plusSeconds(90)))
        assertFalse(permit.consumeOnce(OperationRevision(2),at.minusSeconds(1)))
    }
    @Test fun dispatchRequiresExactRevisionAndIsConsumedOnce() {
        val permit=requireNotNull(authorize());assertFalse(permit.consumeOnce(OperationRevision(1),at));assertTrue(permit.consumeOnce(OperationRevision(2),at));assertFalse(permit.consumeOnce(OperationRevision(2),at))
        assertNull(authorize(c=current.copy(revision=OperationRevision(2))))
    }
    @Test fun copyingOrTerminalCheckpointCannotDispatchAgain() {
        assertNull(authorize(c=current.copy(snapshot=current.snapshot.copy(checkpoint=current.snapshot.checkpoint.copy(semantics=CheckpointSemantics.MUTATION_IN_FLIGHT)))))
        assertNull(RestoreCheckConfirmationPolicy.confirm(current.copy(snapshot=current.snapshot.copy(status=OperationStatus.SUCCEEDED,
            checkpoint=current.snapshot.checkpoint.copy(semantics=CheckpointSemantics.TERMINAL))),installation,access,parent,at))
    }
    @Test fun quotaMissingToolsPrivateRootAndCapacityGateBeforeCopy() {
        listOf(space.copy(slotsUsed=4),space.copy(limitedToolsAvailable=false),space.copy(safePrivateRoot=false),space.copy(availableBytes=1)).forEach {assertNull(authorize(s=it))}
    }
    @Test fun foreignOrStaleStorageObservationCannotAuthorize() {
        listOf(space.copy(scope=scope.copy(operationId=OperationId("foreign"))),space.copy(observedAt=at.minusSeconds(31)),space.copy(observedAt=at.plusSeconds(1))).forEach {assertNull(authorize(s=it))}
    }
    @Test fun injectedSourcePointerAndMalformedProofNeverBecomeCommandArguments() {
        assertThrows(IllegalArgumentException::class.java){binding.copy(sourceOperationId=OperationId("../../escape"))}
        assertNull(RestoreCheckBinding.parse(binding.phaseName(RestoreCheckPhase.REVIEWED)+":extra"))
        assertNull(RestoreCheckBinding.parse(binding.phaseName(RestoreCheckPhase.REVIEWED).replace("AMD64","FOREIGN")))
        assertThrows(IllegalArgumentException::class.java){binding.copy(archiveBytes=0)}
    }
    @Test fun restoreReceiptHasFiniteByteBoundAndDoesNotAuthorizeNewDispatch() {
        assertEquals(binding,RestoreCheckReceipt(scope,binding,4096,at).binding)
        assertThrows(IllegalArgumentException::class.java){RestoreCheckReceipt(scope,binding,RestoreCheckBinding.MAX_RESTORED_BYTES+1,at)}
    }
}
