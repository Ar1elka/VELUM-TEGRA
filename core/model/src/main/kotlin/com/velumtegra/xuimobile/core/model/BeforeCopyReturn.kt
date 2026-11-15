package com.velumtegra.xuimobile.core.model
import java.time.Instant
/** A compensating attempt remains the SAME nonterminal restore row; it never clears its barrier. */
enum class BeforeCopyReturnPhase { RETURNING, AWAITING_READBACK, READBACK_VERIFIED }
data class BeforeCopyReturnBinding(val originalPhaseName:String,val originalRevision:Long,val beforeDatabaseSha256:String,
    val beforeLogicalSha256:String,val beforeBytes:Long,val digest:String){
    init{
        require(originalRevision>=0 && beforeBytes in 1..DatabaseBackupBinding.MAX_BYTES)
        require(listOf(beforeDatabaseSha256,beforeLogicalSha256,digest).all{Regex("[0-9a-f]{64}").matches(it)})
        require(WorkingDatabaseRestoreBinding.parse(originalPhaseName)?.first in setOf(WorkingDatabaseRestorePhase.RESTORING,WorkingDatabaseRestorePhase.FINISHED,WorkingDatabaseRestorePhase.UNCERTAIN))
    }
    val original:WorkingDatabaseRestoreBinding get()=WorkingDatabaseRestoreBinding.parse(originalPhaseName)!!.second
    fun phaseName(phase:BeforeCopyReturnPhase)=listOf("BCR1_${phase.name}",originalRevision.toString(),digest,beforeDatabaseSha256,beforeLogicalSha256,beforeBytes.toString(),originalPhaseName).joinToString(":")
    companion object{
        fun parse(value:String):Pair<BeforeCopyReturnPhase,BeforeCopyReturnBinding>?{
            val p=value.split(':',limit=7);if(p.size!=7)return null
            val phase=BeforeCopyReturnPhase.values().singleOrNull{"BCR1_${it.name}"==p[0]}?:return null
            return try{val b=BeforeCopyReturnBinding(p[6],p[1].toLong(),p[3],p[4],p[5].toLong(),p[2]);if(b.phaseName(phase)==value)phase to b else null}catch(_:IllegalArgumentException){null}
        }
    }
}
data class BeforeCopyReturnReceipt(val scope:ManagementScope,val binding:BeforeCopyReturnBinding,val displacedDatabaseSha256:String,
    val displacedBytes:Long,val verifiedAt:Instant){
    init{require(Regex("[0-9a-f]{64}").matches(displacedDatabaseSha256) && displacedBytes in 1..DatabaseBackupBinding.MAX_BYTES)}
}
