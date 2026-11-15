package com.velumtegra.xuimobile.core.model
import java.time.Instant

enum class RestoredPanelStartPhase { PENDING, STARTING, FINISHED, UNCERTAIN, VERIFIED, FAILED, CANCELLED }
data class RestoredPanelStartBinding(val restoreOperationId:OperationId,val restoreRevision:Long,val restored:WorkingDatabaseRestoreBinding,val digest:String){
    init { require(Regex("[A-Za-z0-9._-]{1,96}").matches(restoreOperationId.value) && restoreRevision>=0);require(Regex("[0-9a-f]{64}").matches(digest)) }
    val source:RestoreCheckBinding get()=restored.source
    fun phaseName(phase:RestoredPanelStartPhase)=listOf("RPS1_${phase.name}",restoreOperationId.value,restoreRevision.toString(),digest,restored.phaseName(WorkingDatabaseRestorePhase.VERIFIED)).joinToString(":")
    companion object{
        fun parse(value:String):Pair<RestoredPanelStartPhase,RestoredPanelStartBinding>?{
            val p=value.split(':',limit=5);if(p.size!=5)return null
            val phase=RestoredPanelStartPhase.values().singleOrNull{"RPS1_${it.name}"==p[0]}?:return null
            val b=WorkingDatabaseRestoreBinding.parse(p[4])?.takeIf{it.first==WorkingDatabaseRestorePhase.VERIFIED}?.second?:return null
            return try{val result=RestoredPanelStartBinding(OperationId(p[1]),p[2].toLong(),b,p[3]);if(result.phaseName(phase)==value)phase to result else null}catch(_:IllegalArgumentException){null}
        }
    }
}
/** Momentary service evidence; never authentication, VPN availability or full recovery proof. */
data class RestoredPanelStartReceipt(val scope:ManagementScope,val binding:RestoredPanelStartBinding,val version:String,
    val architecture:UpdateServerArchitecture,val schemaSha256:String,val inbounds:Int,val observedAt:Instant){
    init{require(version==binding.source.source.version && architecture==binding.source.source.architecture)
        require(Regex("[0-9a-f]{64}").matches(schemaSha256) && inbounds in 0..256)}
}
data class RestoredPanelStartReady(val scope:ManagementScope,val binding:RestoredPanelStartBinding,val observedAt:Instant)
enum class RestoredPanelStartFailure { EXACT_TARGET, SOURCE, AUTHORITY_MISSING, JOURNAL, SESSION, PRECHECK, CAPACITY, PROOF_UNAVAILABLE }
