package com.velumtegra.xuimobile.core.model
import java.time.Instant
enum class KnownFileRestorePhase { APPLYING, NEEDS_CHECK, APPLIED, RETURNING, RETURN_NEEDS_CHECK, RETURNED }
enum class KnownFileRestoreWrite { APPLY, RETURN }
data class KnownFileRestoreBinding(val comparisonOperationId:OperationId,val comparisonRevision:Long,val comparison:RestoreCompatibilityBinding,
    val currentSetSha256:String,val changedFiles:Int,val digest:String){
    init{require(Regex("[A-Za-z0-9._-]{1,96}").matches(comparisonOperationId.value) && comparisonRevision>=0 && changedFiles in 1..96)
        require(listOf(currentSetSha256,digest).all{Regex("[0-9a-f]{64}").matches(it)})}
    fun phaseName(p:KnownFileRestorePhase)=listOf("KFR1_${p.name}",comparisonOperationId.value,comparisonRevision.toString(),currentSetSha256,changedFiles.toString(),digest,comparison.phaseName(RestoreCompatibilityPhase.OBSERVED)).joinToString(":")
    companion object{
        fun parse(value:String):Pair<KnownFileRestorePhase,KnownFileRestoreBinding>?{
            val p=value.split(':',limit=7);if(p.size!=7)return null
            val phase=KnownFileRestorePhase.values().singleOrNull{"KFR1_${it.name}"==p[0]}?:return null
            val source=RestoreCompatibilityBinding.parse(p[6])?.takeIf{it.first==RestoreCompatibilityPhase.OBSERVED}?.second?:return null
            return try{val b=KnownFileRestoreBinding(OperationId(p[1]),p[2].toLong(),source,p[3],p[4].toInt(),p[5]);if(b.phaseName(phase)==value)phase to b else null}catch(_:IllegalArgumentException){null}
        }
    }
}
data class KnownFileRestorePrepared(val scope:ManagementScope,val binding:KnownFileRestoreBinding,val databaseLogicalSha256:String,val observedAt:Instant){
    init{require(Regex("[0-9a-f]{64}").matches(databaseLogicalSha256))}
}
/** A positively observed mixed/prior/source file set under cooperating-writer locks. No absent-artifact inference. */
data class KnownFileRestoreInspection(val scope:ManagementScope,val binding:KnownFileRestoreBinding,val beforeManifestSha256:String,
    val databaseLogicalSha256:String,val desiredFiles:Int,val previousFiles:Int,val observedAt:Instant){
    init{require(listOf(beforeManifestSha256,databaseLogicalSha256).all{Regex("[0-9a-f]{64}").matches(it)})
        require(desiredFiles in 0..binding.changedFiles && previousFiles in 0..binding.changedFiles && desiredFiles+previousFiles==binding.changedFiles)}
    val desiredComplete:Boolean get()=desiredFiles==binding.changedFiles
    val previousComplete:Boolean get()=previousFiles==binding.changedFiles
}
