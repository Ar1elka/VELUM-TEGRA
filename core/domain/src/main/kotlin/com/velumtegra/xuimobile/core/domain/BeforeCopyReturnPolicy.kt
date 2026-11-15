package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.security.MessageDigest
import java.time.Instant
object BeforeCopyReturnPolicy{
    fun uncertain(c:VersionedOperationSnapshot):Boolean{
        val phase=WorkingDatabaseRestoreBinding.parse(c.snapshot.checkpoint.phaseName)?.first?:return false
        return c.snapshot.type==OperationType.WORKING_DATABASE_RESTORE && when(c.snapshot.checkpoint.semantics){
            CheckpointSemantics.MUTATION_IN_FLIGHT->c.snapshot.status==OperationStatus.RUNNING && phase==WorkingDatabaseRestorePhase.RESTORING
            CheckpointSemantics.POST_VERIFY_REQUIRED->c.snapshot.status==OperationStatus.RECONCILIATION_REQUIRED && phase in setOf(WorkingDatabaseRestorePhase.FINISHED,WorkingDatabaseRestorePhase.UNCERTAIN)
            else->false
        }
    }
    fun bind(c:VersionedOperationSnapshot,e:BeforeCopyEvidence,now:Instant):BeforeCopyReturnBinding?{
        val t=c.snapshot.target as? OperationTarget.InstallationTarget?:return null
        if(!uncertain(c) || e.scope!=ManagementScope(c.snapshot.operationId,t.serverId,t.serverAccessId,t.installationId) ||
            WorkingDatabaseRestoreBinding.parse(c.snapshot.checkpoint.phaseName)?.second!=e.binding ||
            e.service!=BeforeCopyService.INACTIVE || e.current!=BeforeCopyCurrent.DIFFERENT || e.structure!=BeforeCopyStructure.MATCH ||
            now.isBefore(e.observedAt) || now.epochSecond-e.observedAt.epochSecond>=300 || e.observedAt.isBefore(c.snapshot.updatedAt))return null
        return BeforeCopyReturnBinding(c.snapshot.checkpoint.phaseName,c.revision.value,e.databaseSha256,e.logicalSha256,e.bytes,
            digest(c.snapshot.operationId,c.snapshot.checkpoint.phaseName,c.revision.value,e.databaseSha256,e.logicalSha256,e.bytes))
    }
    private fun digest(id:OperationId,phase:String,revision:Long,db:String,logical:String,bytes:Long):String{
        val raw=listOf("BEFORE_COPY_RETURN_V1",id.value,phase,revision.toString(),db,logical,bytes.toString()).joinToString(""){"${it.length}:$it"}
        return MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(Charsets.UTF_8)).joinToString(""){"%02x".format(it.toInt() and 255)}
    }
    fun matches(c:VersionedOperationSnapshot,b:BeforeCopyReturnBinding,installation:XuiInstallation,access:ServerAccess,
        comparison:VersionedOperationSnapshot,check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot):Boolean{
        if(c.snapshot.type!=OperationType.WORKING_DATABASE_RESTORE || c.snapshot.status!=OperationStatus.RECONCILIATION_REQUIRED ||
            c.snapshot.checkpoint.semantics!=CheckpointSemantics.POST_VERIFY_REQUIRED || c.revision.value<=b.originalRevision ||
            BeforeCopyReturnBinding.parse(c.snapshot.checkpoint.phaseName)?.second!=b ||
            b.digest!=digest(c.snapshot.operationId,b.originalPhaseName,b.originalRevision,b.beforeDatabaseSha256,b.beforeLogicalSha256,b.beforeBytes))return false
        val original=c.copy(snapshot=c.snapshot.copy(checkpoint=c.snapshot.checkpoint.copy(phaseName=b.originalPhaseName)))
        return WorkingDatabaseRestoreBindingPolicy.matches(original,installation,access,comparison,check,backup)
    }
}
/** One unforgeable in-process dispatch minted only after the exact durable CAS. */
class VerifiedBeforeCopyReturnDispatch private constructor(val scope:ManagementScope,val binding:BeforeCopyReturnBinding,
    val revision:OperationRevision,val validFrom:Instant,val validUntil:Instant){
    private val consumed=java.util.concurrent.atomic.AtomicBoolean(false)
    fun consumeOnce(current:VersionedOperationSnapshot,at:Instant):Boolean=
        current.snapshot.operationId==scope.operationId && current.snapshot.target==OperationTarget.InstallationTarget(scope.serverId,scope.serverAccessId,scope.installationId) &&
        current.snapshot.type==OperationType.WORKING_DATABASE_RESTORE && current.revision==revision &&
        current.snapshot.status==OperationStatus.RECONCILIATION_REQUIRED && current.snapshot.checkpoint.semantics==CheckpointSemantics.POST_VERIFY_REQUIRED &&
        current.snapshot.checkpoint.phaseName==binding.phaseName(BeforeCopyReturnPhase.RETURNING) && !at.isBefore(validFrom) && at.isBefore(validUntil) && consumed.compareAndSet(false,true)
    companion object{
        fun afterCheckpoint(before:VersionedOperationSnapshot,current:VersionedOperationSnapshot,evidence:BeforeCopyEvidence,at:Instant,confirmationUntil:Instant=at.plusSeconds(30)):VerifiedBeforeCopyReturnDispatch?{
            val b=BeforeCopyReturnPolicy.bind(before,evidence,at)?:return null
            if(!at.isBefore(confirmationUntil) || at.isBefore(current.snapshot.updatedAt) || current.snapshot.updatedAt.isBefore(before.snapshot.updatedAt) || current.revision.value!=before.revision.value+1 || current.snapshot!=before.snapshot.copy(status=OperationStatus.RECONCILIATION_REQUIRED,
                checkpoint=OperationCheckpoint(b.phaseName(BeforeCopyReturnPhase.RETURNING),CheckpointSemantics.POST_VERIFY_REQUIRED,current.snapshot.updatedAt),updatedAt=current.snapshot.updatedAt))return null
            val d=VerifiedBeforeCopyReturnDispatch(evidence.scope,b,current.revision,at,if(confirmationUntil.isBefore(at.plusSeconds(30)))confirmationUntil else at.plusSeconds(30))
            return d
        }
    }
}
