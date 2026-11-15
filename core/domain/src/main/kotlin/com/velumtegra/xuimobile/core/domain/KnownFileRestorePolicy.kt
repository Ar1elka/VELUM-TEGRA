package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.security.MessageDigest
import java.time.Instant
object KnownFileRestorePolicy{
    fun candidate(e:RecoveryReadinessEvidence,at:Instant)=RecoveryReadinessPolicy.fresh(e,at) && e.changedCommon>0 &&
        e.currentVersion==e.binding.source.source.version && e.currentArchitecture==e.binding.source.source.architecture && e.sourceSchema==e.currentSchema &&
        e.endpointsMatch && e.pageSizesMatch && e.quiescence==RecoveryQuiescence.STOPPED && e.added==0 && e.missing==0 && e.groups.values.all{it.added==0 && it.missing==0} &&
        e.groups.getValue(RecoveryFileGroup.SERVICE).changedCommon==0
    fun bind(id:OperationId,i:XuiInstallation,a:ServerAccess,c:VersionedOperationSnapshot,check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot,e:RecoveryReadinessEvidence,at:Instant):KnownFileRestoreBinding?{
        if(!RecoveryReadinessPolicy.source(c,check,backup,i,a) || !candidate(e,at) || e.scope!=ManagementScope(c.snapshot.operationId,i.serverId,a.id,i.id) ||
            e.comparisonRevision!=c.revision.value || RestoreCompatibilityBinding.parse(c.snapshot.checkpoint.phaseName)?.second!=e.binding || e.observedAt.isBefore(c.snapshot.updatedAt) ||
            id in setOf(c.snapshot.operationId,check.snapshot.operationId,backup.snapshot.operationId))return null
        return make(id,i,a,c,e.currentSetSha256,e.changedCommon)
    }
    private fun make(id:OperationId,i:XuiInstallation,a:ServerAccess,c:VersionedOperationSnapshot,set:String,count:Int):KnownFileRestoreBinding{
        val b=RestoreCompatibilityBinding.parse(c.snapshot.checkpoint.phaseName)!!.second
        val seed=InstallationBackupBindingPolicy.bind(id,i,a,b.source.source.version,b.source.source.architecture).digest
        val raw=listOf("KNOWN_FILE_RESTORE_V1",seed,c.snapshot.operationId.value,c.revision.value.toString(),b.phaseName(RestoreCompatibilityPhase.OBSERVED),set,count.toString()).joinToString(""){"${it.length}:$it"}
        val hash=MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(Charsets.UTF_8)).joinToString(""){"%02x".format(it.toInt() and 255)}
        return KnownFileRestoreBinding(c.snapshot.operationId,c.revision.value,b,set,count,hash)
    }
    fun matches(current:VersionedOperationSnapshot,i:XuiInstallation,a:ServerAccess,c:VersionedOperationSnapshot,check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot):Boolean{
        val p=KnownFileRestoreBinding.parse(current.snapshot.checkpoint.phaseName)?:return false;val b=p.second;val s=current.snapshot
        if(s.type!=OperationType.KNOWN_FILE_RESTORE || s.target!=c.snapshot.target || !RecoveryReadinessPolicy.source(c,check,backup,i,a))return false
        if(b!=make(s.operationId,i,a,c,b.currentSetSha256,b.changedFiles))return false
        return when(p.first){KnownFileRestorePhase.APPLIED->s.status==OperationStatus.SUCCEEDED && s.checkpoint.semantics==CheckpointSemantics.TERMINAL
            KnownFileRestorePhase.RETURNED->s.status==OperationStatus.FAILED && s.checkpoint.semantics==CheckpointSemantics.TERMINAL
            else->s.status==OperationStatus.RECONCILIATION_REQUIRED && s.checkpoint.semantics==CheckpointSemantics.POST_VERIFY_REQUIRED}
    }
}
/** Minted after durable create/CAS. Consent and dispatch cannot be reconstructed from the journal. */
class VerifiedKnownFileRestoreDispatch private constructor(val scope:ManagementScope,val binding:KnownFileRestoreBinding,val revision:OperationRevision,
    val action:KnownFileRestoreWrite,val beforeManifestSha256:String,val validFrom:Instant,val validUntil:Instant){
    private val consumed=java.util.concurrent.atomic.AtomicBoolean(false)
    fun consumeOnce(c:VersionedOperationSnapshot,at:Instant):Boolean = c.snapshot.operationId==scope.operationId && c.revision==revision &&
        c.snapshot.target==OperationTarget.InstallationTarget(scope.serverId,scope.serverAccessId,scope.installationId) && c.snapshot.type==OperationType.KNOWN_FILE_RESTORE &&
        c.snapshot.status==OperationStatus.RECONCILIATION_REQUIRED && c.snapshot.checkpoint.semantics==CheckpointSemantics.POST_VERIFY_REQUIRED &&
        c.snapshot.checkpoint.phaseName==binding.phaseName(if(action==KnownFileRestoreWrite.APPLY)KnownFileRestorePhase.APPLYING else KnownFileRestorePhase.RETURNING) &&
        !at.isBefore(validFrom) && at.isBefore(validUntil) && consumed.compareAndSet(false,true)
    companion object{
        fun afterCreate(c:VersionedOperationSnapshot,p:KnownFileRestorePrepared,reviewedAt:Instant,at:Instant):VerifiedKnownFileRestoreDispatch?{
            if(c.revision.value!=0L || c.snapshot.startedAt!=c.snapshot.updatedAt || c.snapshot.checkpoint.recordedAt!=c.snapshot.updatedAt || c.snapshot.updatedAt.isBefore(p.observedAt) || p.scope.operationId!=c.snapshot.operationId || p.observedAt.isBefore(reviewedAt) ||
                p.observedAt.isAfter(at) || at.isBefore(c.snapshot.updatedAt))return null
            return mint(c,p.scope,p.binding,KnownFileRestoreWrite.APPLY,"0".repeat(64),reviewedAt,at)
        }
        fun afterReturnCheckpoint(before:VersionedOperationSnapshot,c:VersionedOperationSnapshot,p:KnownFileRestoreInspection,reviewedAt:Instant,at:Instant):VerifiedKnownFileRestoreDispatch?{
            val phase=KnownFileRestoreBinding.parse(before.snapshot.checkpoint.phaseName)?.first?:return null
            if(phase !in setOf(KnownFileRestorePhase.APPLYING,KnownFileRestorePhase.NEEDS_CHECK) || p.desiredComplete ||
                KnownFileRestoreBinding.parse(before.snapshot.checkpoint.phaseName)?.second!=p.binding || p.observedAt.isBefore(before.snapshot.updatedAt) ||
                c.snapshot.updatedAt.isBefore(p.observedAt) || c.revision.value!=before.revision.value+1 ||
                c.snapshot!=before.snapshot.copy(checkpoint=OperationCheckpoint(p.binding.phaseName(KnownFileRestorePhase.RETURNING),CheckpointSemantics.POST_VERIFY_REQUIRED,c.snapshot.updatedAt),updatedAt=c.snapshot.updatedAt) ||
                p.observedAt.isBefore(reviewedAt) || p.observedAt.isAfter(at) || at.isBefore(c.snapshot.updatedAt))return null
            return mint(c,p.scope,p.binding,KnownFileRestoreWrite.RETURN,p.beforeManifestSha256,reviewedAt,at)
        }
        private fun mint(c:VersionedOperationSnapshot,scope:ManagementScope,b:KnownFileRestoreBinding,action:KnownFileRestoreWrite,manifest:String,reviewed:Instant,at:Instant):VerifiedKnownFileRestoreDispatch?{
            if(at.isBefore(reviewed) || !at.isBefore(reviewed.plusSeconds(90)) || c.snapshot.type!=OperationType.KNOWN_FILE_RESTORE ||
                c.snapshot.operationId!=scope.operationId || c.snapshot.target!=OperationTarget.InstallationTarget(scope.serverId,scope.serverAccessId,scope.installationId) ||
                c.snapshot.status!=OperationStatus.RECONCILIATION_REQUIRED || c.snapshot.checkpoint.semantics!=CheckpointSemantics.POST_VERIFY_REQUIRED ||
                c.snapshot.checkpoint.phaseName!=b.phaseName(if(action==KnownFileRestoreWrite.APPLY)KnownFileRestorePhase.APPLYING else KnownFileRestorePhase.RETURNING))return null
            val until=minOf(at.plusSeconds(30),reviewed.plusSeconds(90));return VerifiedKnownFileRestoreDispatch(scope,b,c.revision,action,manifest,at,until)
        }
    }
}
