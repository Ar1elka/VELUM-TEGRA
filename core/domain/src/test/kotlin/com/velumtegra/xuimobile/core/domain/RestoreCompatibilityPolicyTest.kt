package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class RestoreCompatibilityPolicyTest {
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
    private val binding=RestoreCompatibilityBindingPolicy.bind(OperationId("compare"),installation,access,check,backup)
    private val current=VersionedOperationSnapshot(OperationSnapshot(OperationId("compare"),OperationType.RESTORE_COMPATIBILITY,target,OperationStatus.RUNNING,OperationCheckpoint(binding.phaseName(RestoreCompatibilityPhase.PENDING),CheckpointSemantics.READ_ONLY,at),at,at),OperationRevision(0))
    private fun report()=RestoreCompatibilityReport(ManagementScope(current.snapshot.operationId,installation.serverId,access.id,installation.id),binding,"3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64),"a".repeat(64),RestoreFileSetComparison.MATCH,0,1,1,ManagementServiceState.ACTIVE,ManagementBaselineStatus.Matched,at)
    @Test fun exactVerifiedChainMatchesAndRoundTripsAllReadOnlyPhases(){assertTrue(RestoreCompatibilityBindingPolicy.matches(current,installation,access,check,backup));for(p in RestoreCompatibilityPhase.values())assertEquals(p to binding,RestoreCompatibilityBinding.parse(binding.phaseName(p)))}
    @Test fun changedCheckRevisionCannotReuseBinding(){assertFalse(RestoreCompatibilityBindingPolicy.matches(current,installation,access,check.copy(revision=OperationRevision(4)),backup))}
    @Test fun originalBackupMustRemainVerified(){val b=backup.copy(snapshot=backup.snapshot.copy(status=OperationStatus.FAILED));assertFalse(RestoreCompatibilityBindingPolicy.matches(current,installation,access,check,b))}
    @Test fun incompleteRestoreDoesNotQualifyAsSource(){val c=check.copy(snapshot=check.snapshot.copy(status=OperationStatus.RECONCILIATION_REQUIRED));assertFalse(RestoreCompatibilityBindingPolicy.parentMatches(c,backup,installation,access))}
    @Test fun changedUsernamePinAndCredentialReferenceRejectExactChain(){for(a in listOf(access.copy(username="other"),access.copy(pinnedHostKey=HostKeyFingerprint("SHA256:other")),access.copy(auth=SshAuthRef.Password(SecretId("other")))))assertFalse(RestoreCompatibilityBindingPolicy.matches(current,installation,a,check,backup))}
    @Test fun changedBaselineOrInstallationCannotRebindSource(){assertFalse(RestoreCompatibilityBindingPolicy.matches(current,installation.copy(baseline=installation.baseline.copy(panelPort=8443)),access,check,backup));assertFalse(RestoreCompatibilityBindingPolicy.matches(current,installation.copy(id=XuiInstallationId("other")),access,check,backup))}
    @Test fun wrongOperationTypeAndTargetReject(){assertFalse(RestoreCompatibilityBindingPolicy.matches(current.copy(snapshot=current.snapshot.copy(type=OperationType.UPDATE_PREFLIGHT)),installation,access,check,backup));assertFalse(RestoreCompatibilityBindingPolicy.matches(current.copy(snapshot=current.snapshot.copy(target=target.copy(serverId=ServerId("other")))),installation,access,check,backup))}
    @Test fun malformedCheckpointEncodingsNeverRoundTrip(){for(raw in listOf(binding.phaseName(RestoreCompatibilityPhase.PENDING).replace(":3:",":+3:"),binding.phaseName(RestoreCompatibilityPhase.PENDING)+":extra","RCP1_PENDING:bad"))assertNull(RestoreCompatibilityBinding.parse(raw))}
    @Test fun equalObservedPrerequisitesAreNotExecutionAuthority(){assertTrue(report().prerequisitesMatch);assertEquals(OperationType.RESTORE_COMPATIBILITY,current.snapshot.type);assertEquals(CheckpointSemantics.READ_ONLY,current.snapshot.checkpoint.semantics)}
    @Test fun differentVersionNeverClaimsMigrationCompatibility(){assertFalse(report().copy(currentVersion="3.10.2").prerequisitesMatch)}
    @Test fun differentArchitectureNeverQualifies(){assertFalse(report().copy(currentArchitecture=UpdateServerArchitecture.ARM64).prerequisitesMatch)}
    @Test fun changedOrMissingSchemaNeverQualifies(){assertFalse(report().copy(currentSchemaSha256="f".repeat(64)).prerequisitesMatch);assertFalse(report().copy(currentSchemaSha256=null,currentInbounds=null).prerequisitesMatch)}
    @Test fun unknownOrDifferentKnownFileSetNeverQualifies(){assertFalse(report().copy(fileSet=RestoreFileSetComparison.UNAVAILABLE,changedFiles=null).prerequisitesMatch);assertFalse(report().copy(fileSet=RestoreFileSetComparison.DIFFERENT).prerequisitesMatch)}
    @Test fun transitionOrUnobservedServiceStateBlocksPrerequisites(){for(v in listOf(ManagementServiceState.UNKNOWN,ManagementServiceState.ACTIVATING,ManagementServiceState.RELOADING))assertFalse(report().copy(serviceState=v).prerequisitesMatch)}
}
