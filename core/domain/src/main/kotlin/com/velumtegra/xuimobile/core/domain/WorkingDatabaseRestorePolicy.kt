package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import java.security.MessageDigest

object WorkingDatabaseRestoreBindingPolicy{
    fun parentMatches(comparison:VersionedOperationSnapshot,check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot,
        installation:XuiInstallation,access:ServerAccess)=comparison.snapshot.status==OperationStatus.SUCCEEDED &&
        comparison.snapshot.checkpoint.semantics==CheckpointSemantics.TERMINAL &&
        RestoreCompatibilityBinding.parse(comparison.snapshot.checkpoint.phaseName)?.first==RestoreCompatibilityPhase.OBSERVED &&
        RestoreCompatibilityBindingPolicy.matches(comparison,installation,access,check,backup)
    fun bind(id:OperationId,installation:XuiInstallation,access:ServerAccess,comparison:VersionedOperationSnapshot,
        check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot):WorkingDatabaseRestoreBinding{
        require(parentMatches(comparison,check,backup,installation,access))
        require(id !in setOf(comparison.snapshot.operationId,check.snapshot.operationId,backup.snapshot.operationId))
        val c=RestoreCompatibilityBinding.parse(comparison.snapshot.checkpoint.phaseName)!!.second
        val seed=InstallationBackupBindingPolicy.bind(id,installation,access,c.source.source.version,c.source.source.architecture).digest
        val raw=listOf("WORKING_DATABASE_RESTORE_V1",seed,comparison.snapshot.operationId.value,comparison.revision.value.toString(),c.phaseName(RestoreCompatibilityPhase.OBSERVED)).joinToString(""){"${it.length}:$it"}
        val digest=MessageDigest.getInstance("SHA-256").digest(raw.toByteArray()).joinToString(""){"%02x".format(it.toInt() and 255)}
        val endpoint=listOf(installation.baseline.panelPort.toString(),installation.baseline.webBasePath,installation.baseline.listenAddress?:"").joinToString(""){"${it.toByteArray(Charsets.UTF_8).size}:$it"}
        val endpointHash=MessageDigest.getInstance("SHA-256").digest(endpoint.toByteArray(Charsets.UTF_8)).joinToString(""){"%02x".format(it.toInt() and 255)}
        return WorkingDatabaseRestoreBinding(comparison.snapshot.operationId,comparison.revision.value,c,endpointHash,digest)
    }
    fun matches(current:VersionedOperationSnapshot,installation:XuiInstallation,access:ServerAccess,comparison:VersionedOperationSnapshot,
        check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot):Boolean{
        val b=WorkingDatabaseRestoreBinding.parse(current.snapshot.checkpoint.phaseName)?.second?:return false
        if(current.snapshot.type!=OperationType.WORKING_DATABASE_RESTORE || current.snapshot.target!=comparison.snapshot.target)return false
        return try{b==bind(current.snapshot.operationId,installation,access,comparison,check,backup)}catch(_:IllegalArgumentException){false}
    }
}
class WorkingDatabaseRestoreConfirmation internal constructor(val operationId:OperationId,val revision:OperationRevision,
    val installation:XuiInstallation,val access:ServerAccess,val binding:WorkingDatabaseRestoreBinding,val validUntil:Instant){
    val target:OperationTarget.InstallationTarget get()=OperationTarget.InstallationTarget(installation.serverId,access.id,installation.id)
}
object WorkingDatabaseRestoreConfirmationPolicy{
    fun structuralReady(report:RestoreCompatibilityReport):Boolean {
        val baselineOkay=report.baselineStatus==ManagementBaselineStatus.Matched ||
            (report.serviceState==ManagementServiceState.INACTIVE && report.baselineStatus==ManagementBaselineStatus.Drift(setOf(ManagementBaselineDrift.EXPECTED_LISTENER_ABSENT)))
        return report.sameVersion && report.sameArchitecture && report.sameSchema && report.fileSet==RestoreFileSetComparison.MATCH && report.changedFiles==0 &&
            baselineOkay && report.serviceState in setOf(ManagementServiceState.ACTIVE,ManagementServiceState.INACTIVE)
    }
    fun eligible(report:RestoreCompatibilityReport,comparison:VersionedOperationSnapshot,now:Instant):Boolean=
        report.scope.operationId==comparison.snapshot.operationId && structuralReady(report) &&
        RestoreCompatibilityBinding.parse(comparison.snapshot.checkpoint.phaseName)?.second==report.binding &&
        !report.observedAt.isBefore(comparison.snapshot.startedAt) && !now.isBefore(report.observedAt) && now.epochSecond-report.observedAt.epochSecond<300
    fun confirm(current:VersionedOperationSnapshot,installation:XuiInstallation,access:ServerAccess,comparison:VersionedOperationSnapshot,
        check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot,report:RestoreCompatibilityReport,now:Instant):WorkingDatabaseRestoreConfirmation?{
        val s=current.snapshot;val b=WorkingDatabaseRestoreBinding.parse(s.checkpoint.phaseName)?:return null
        if(s.status!=OperationStatus.RUNNING || s.checkpoint.semantics!=CheckpointSemantics.MUTATION_NOT_STARTED || b.first!=WorkingDatabaseRestorePhase.PENDING ||
            now.isBefore(s.updatedAt) || now.epochSecond-s.updatedAt.epochSecond>=300 || !eligible(report,comparison,now) ||
            report.scope.serverId!=installation.serverId || report.scope.installationId!=installation.id || report.scope.serverAccessId!=access.id ||
            !WorkingDatabaseRestoreBindingPolicy.matches(current,installation,access,comparison,check,backup))return null
        return WorkingDatabaseRestoreConfirmation(s.operationId,current.revision,installation,access,b.second,now.plusSeconds(90))
    }
}
class VerifiedWorkingDatabaseRestoreDispatch internal constructor(val scope:ManagementScope,val binding:WorkingDatabaseRestoreBinding,
    val expectedRevision:OperationRevision,val validFrom:Instant,val validUntil:Instant){
    private val consumed=java.util.concurrent.atomic.AtomicBoolean(false)
    fun consumeOnce(revision:OperationRevision,at:Instant)=!at.isBefore(validFrom) && at.isBefore(validUntil) &&
        revision.value==expectedRevision.value+1 && consumed.compareAndSet(false,true)
}
object WorkingDatabaseRestoreDispatchPolicy{
    fun authorize(c:WorkingDatabaseRestoreConfirmation,current:VersionedOperationSnapshot,space:InstallationBackupStorageObservation,now:Instant):VerifiedWorkingDatabaseRestoreDispatch?{
        val s=current.snapshot;val t=s.target as? OperationTarget.InstallationTarget?:return null
        val scope=ManagementScope(s.operationId,t.serverId,t.serverAccessId,t.installationId)
        if(s.operationId!=c.operationId || current.revision!=c.revision || s.type!=OperationType.WORKING_DATABASE_RESTORE ||
            t.serverId!=c.installation.serverId || t.installationId!=c.installation.id || t.serverAccessId!=c.access.id || s.status!=OperationStatus.RUNNING ||
            s.checkpoint.semantics!=CheckpointSemantics.MUTATION_NOT_STARTED || s.checkpoint.phaseName!=c.binding.phaseName(WorkingDatabaseRestorePhase.PENDING) ||
            now.isBefore(s.updatedAt) || !now.isBefore(c.validUntil) || space.scope!=scope || !space.safePrivateRoot || !space.limitedToolsAvailable ||
            space.slotsUsed !in 0..3 || space.availableBytes<2*DatabaseBackupBinding.MAX_BYTES+64L*1024*1024 ||
            space.observedAt.isAfter(now) || now.epochSecond-space.observedAt.epochSecond>30)return null
        return VerifiedWorkingDatabaseRestoreDispatch(scope,c.binding,current.revision,now,c.validUntil)
    }
}
