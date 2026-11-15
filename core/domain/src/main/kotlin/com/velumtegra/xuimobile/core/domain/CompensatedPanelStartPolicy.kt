package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import java.security.MessageDigest
object CompensatedPanelStartPolicy{
    fun bind(c:VersionedOperationSnapshot):CompensatedPanelStartBinding?{
        val p=BeforeCopyReturnBinding.parse(c.snapshot.checkpoint.phaseName)?.takeIf{it.first==BeforeCopyReturnPhase.READBACK_VERIFIED}?:return null
        if(c.snapshot.type!=OperationType.WORKING_DATABASE_RESTORE || c.snapshot.status!=OperationStatus.RECONCILIATION_REQUIRED ||
            c.snapshot.checkpoint.semantics!=CheckpointSemantics.POST_VERIFY_REQUIRED || c.revision.value<=p.second.originalRevision)return null
        val raw=listOf("COMPENSATED_PANEL_START_V1",c.snapshot.operationId.value,c.revision.value.toString(),p.second.phaseName(BeforeCopyReturnPhase.READBACK_VERIFIED)).joinToString(""){"${it.length}:$it"}
        val hash=MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(Charsets.UTF_8)).joinToString(""){"%02x".format(it.toInt() and 255)}
        return CompensatedPanelStartBinding(p.second,c.revision.value,hash)
    }
    fun matches(c:VersionedOperationSnapshot,b:CompensatedPanelStartBinding,i:XuiInstallation,a:ServerAccess,
        comparison:VersionedOperationSnapshot,check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot):Boolean{
        if(c.snapshot.type!=OperationType.WORKING_DATABASE_RESTORE || c.snapshot.status!=OperationStatus.RECONCILIATION_REQUIRED ||
            c.snapshot.checkpoint.semantics!=CheckpointSemantics.POST_VERIFY_REQUIRED || c.revision.value<=b.returnRevision ||
            CompensatedPanelStartBinding.parse(c.snapshot.checkpoint.phaseName)?.second!=b)return false
        val parent=c.copy(snapshot=c.snapshot.copy(checkpoint=c.snapshot.checkpoint.copy(phaseName=b.returned.phaseName(BeforeCopyReturnPhase.READBACK_VERIFIED))),revision=OperationRevision(b.returnRevision))
        return bind(parent)==b && BeforeCopyReturnPolicy.matches(parent,b.returned,i,a,comparison,check,backup)
    }
}
/** Minted only after durable CAS and fresh stopped exact-return readback. */
class VerifiedCompensatedPanelStartDispatch private constructor(val scope:ManagementScope,val binding:CompensatedPanelStartBinding,
    val revision:OperationRevision,val validFrom:Instant,val validUntil:Instant){
    private val used=java.util.concurrent.atomic.AtomicBoolean(false)
    fun consumeOnce(c:VersionedOperationSnapshot,at:Instant)=c.snapshot.operationId==scope.operationId &&
        c.snapshot.target==OperationTarget.InstallationTarget(scope.serverId,scope.serverAccessId,scope.installationId) &&
        c.snapshot.type==OperationType.WORKING_DATABASE_RESTORE && c.snapshot.status==OperationStatus.RECONCILIATION_REQUIRED &&
        c.snapshot.checkpoint.semantics==CheckpointSemantics.POST_VERIFY_REQUIRED && c.revision==revision &&
        c.snapshot.checkpoint.phaseName==binding.phaseName(CompensatedPanelStartPhase.STARTING) &&
        !at.isBefore(validFrom) && at.isBefore(validUntil) && used.compareAndSet(false,true)
    companion object{
        fun afterCheckpoint(before:VersionedOperationSnapshot,current:VersionedOperationSnapshot,receipt:BeforeCopyReturnReceipt,
            reviewedAt:Instant,at:Instant):VerifiedCompensatedPanelStartDispatch?{
            val b=CompensatedPanelStartPolicy.bind(before)?:return null
            val target=before.snapshot.target as? OperationTarget.InstallationTarget?:return null
            val scope=ManagementScope(before.snapshot.operationId,target.serverId,target.serverAccessId,target.installationId)
            if(receipt.scope!=scope || receipt.binding!=b.returned || receipt.verifiedAt.isBefore(reviewedAt) || receipt.verifiedAt.isAfter(at) ||
                at.isBefore(reviewedAt) || !at.isBefore(reviewedAt.plusSeconds(90)) || at.epochSecond-receipt.verifiedAt.epochSecond>=30 ||
                current.revision.value!=before.revision.value+1 || at.isBefore(current.snapshot.updatedAt) || current.snapshot.updatedAt.isBefore(before.snapshot.updatedAt) ||
                current.snapshot!=before.snapshot.copy(checkpoint=OperationCheckpoint(b.phaseName(CompensatedPanelStartPhase.STARTING),CheckpointSemantics.POST_VERIFY_REQUIRED,current.snapshot.updatedAt),updatedAt=current.snapshot.updatedAt))return null
            val until=minOf(at.plusSeconds(30),reviewedAt.plusSeconds(90))
            return VerifiedCompensatedPanelStartDispatch(scope,b,current.revision,at,until)
        }
    }
}
