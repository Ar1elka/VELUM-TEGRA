package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import java.security.MessageDigest

object RestoredPanelStartBindingPolicy{
    fun parentMatches(restore:VersionedOperationSnapshot,comparison:VersionedOperationSnapshot,check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot,
        installation:XuiInstallation,access:ServerAccess)=restore.snapshot.status==OperationStatus.SUCCEEDED && restore.snapshot.checkpoint.semantics==CheckpointSemantics.TERMINAL &&
        WorkingDatabaseRestoreBinding.parse(restore.snapshot.checkpoint.phaseName)?.first==WorkingDatabaseRestorePhase.VERIFIED &&
        WorkingDatabaseRestoreBindingPolicy.matches(restore,installation,access,comparison,check,backup)
    fun bind(id:OperationId,installation:XuiInstallation,access:ServerAccess,restore:VersionedOperationSnapshot,comparison:VersionedOperationSnapshot,
        check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot):RestoredPanelStartBinding{
        require(parentMatches(restore,comparison,check,backup,installation,access))
        require(id !in setOf(restore.snapshot.operationId,comparison.snapshot.operationId,check.snapshot.operationId,backup.snapshot.operationId))
        val b=WorkingDatabaseRestoreBinding.parse(restore.snapshot.checkpoint.phaseName)!!.second
        val seed=InstallationBackupBindingPolicy.bind(id,installation,access,b.source.source.version,b.source.source.architecture).digest
        val raw=listOf("RESTORED_PANEL_START_V1",seed,restore.snapshot.operationId.value,restore.revision.value.toString(),b.phaseName(WorkingDatabaseRestorePhase.VERIFIED)).joinToString(""){"${it.length}:$it"}
        val digest=MessageDigest.getInstance("SHA-256").digest(raw.toByteArray()).joinToString(""){"%02x".format(it.toInt() and 255)}
        return RestoredPanelStartBinding(restore.snapshot.operationId,restore.revision.value,b,digest)
    }
    fun matches(current:VersionedOperationSnapshot,installation:XuiInstallation,access:ServerAccess,restore:VersionedOperationSnapshot,comparison:VersionedOperationSnapshot,
        check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot):Boolean{
        val b=RestoredPanelStartBinding.parse(current.snapshot.checkpoint.phaseName)?.second?:return false
        if(current.snapshot.type!=OperationType.RESTORED_PANEL_START || current.snapshot.target!=restore.snapshot.target)return false
        return try{b==bind(current.snapshot.operationId,installation,access,restore,comparison,check,backup)}catch(_:IllegalArgumentException){false}
    }
}
class RestoredPanelStartConfirmation internal constructor(val operationId:OperationId,val revision:OperationRevision,val installation:XuiInstallation,
    val access:ServerAccess,val binding:RestoredPanelStartBinding,val validUntil:Instant){
    val target:OperationTarget.InstallationTarget get()=OperationTarget.InstallationTarget(installation.serverId,access.id,installation.id)
}
object RestoredPanelStartConfirmationPolicy{
    fun confirm(current:VersionedOperationSnapshot,installation:XuiInstallation,access:ServerAccess,restore:VersionedOperationSnapshot,comparison:VersionedOperationSnapshot,
        check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot,now:Instant):RestoredPanelStartConfirmation?{
        val s=current.snapshot;val b=RestoredPanelStartBinding.parse(s.checkpoint.phaseName)?:return null
        if(s.status!=OperationStatus.RUNNING || s.checkpoint.semantics!=CheckpointSemantics.MUTATION_NOT_STARTED || b.first!=RestoredPanelStartPhase.PENDING ||
            now.isBefore(s.updatedAt) || now.epochSecond-s.updatedAt.epochSecond>=300 ||
            !RestoredPanelStartBindingPolicy.matches(current,installation,access,restore,comparison,check,backup))return null
        return RestoredPanelStartConfirmation(s.operationId,current.revision,installation,access,b.second,now.plusSeconds(90))
    }
}
class VerifiedRestoredPanelStartDispatch internal constructor(val scope:ManagementScope,val binding:RestoredPanelStartBinding,
    val expectedRevision:OperationRevision,val validFrom:Instant,val validUntil:Instant){
    private val consumed=java.util.concurrent.atomic.AtomicBoolean(false)
    fun consumeOnce(revision:OperationRevision,at:Instant)=!at.isBefore(validFrom) && at.isBefore(validUntil) &&
        revision.value==expectedRevision.value+1 && consumed.compareAndSet(false,true)
}
object RestoredPanelStartDispatchPolicy{
    fun authorize(c:RestoredPanelStartConfirmation,current:VersionedOperationSnapshot,ready:RestoredPanelStartReady,now:Instant):VerifiedRestoredPanelStartDispatch?{
        val s=current.snapshot;val t=s.target as? OperationTarget.InstallationTarget?:return null;val scope=ManagementScope(s.operationId,t.serverId,t.serverAccessId,t.installationId)
        if(s.operationId!=c.operationId || current.revision!=c.revision || s.type!=OperationType.RESTORED_PANEL_START || t!=c.target || s.status!=OperationStatus.RUNNING ||
            s.checkpoint.semantics!=CheckpointSemantics.MUTATION_NOT_STARTED || s.checkpoint.phaseName!=c.binding.phaseName(RestoredPanelStartPhase.PENDING) ||
            now.isBefore(s.updatedAt) || !now.isBefore(c.validUntil) || ready.scope!=scope || ready.binding!=c.binding ||
            ready.observedAt.isAfter(now) || now.epochSecond-ready.observedAt.epochSecond>30)return null
        return VerifiedRestoredPanelStartDispatch(scope,c.binding,current.revision,now,c.validUntil)
    }
}
