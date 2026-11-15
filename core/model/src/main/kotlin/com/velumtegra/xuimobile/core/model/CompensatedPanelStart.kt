package com.velumtegra.xuimobile.core.model
import java.time.Instant
/** Same uncertain restore row. Active evidence never terminalizes or clears its mutation barrier. */
enum class CompensatedPanelStartPhase { STARTING, AWAITING_READBACK, ACTIVE_VERIFIED }
data class CompensatedPanelStartBinding(val returned:BeforeCopyReturnBinding,val returnRevision:Long,val digest:String){
    init{require(returnRevision>returned.originalRevision && Regex("[0-9a-f]{64}").matches(digest))}
    fun phaseName(p:CompensatedPanelStartPhase)=listOf("CPS1_${p.name}",returnRevision.toString(),digest,returned.phaseName(BeforeCopyReturnPhase.READBACK_VERIFIED)).joinToString(":")
    companion object{
        fun parse(value:String):Pair<CompensatedPanelStartPhase,CompensatedPanelStartBinding>?{
            val p=value.split(':',limit=4);if(p.size!=4)return null
            val phase=CompensatedPanelStartPhase.values().singleOrNull{"CPS1_${it.name}"==p[0]}?:return null
            val b=BeforeCopyReturnBinding.parse(p[3])?.takeIf{it.first==BeforeCopyReturnPhase.READBACK_VERIFIED}?.second?:return null
            return try{val v=CompensatedPanelStartBinding(b,p[1].toLong(),p[2]);if(v.phaseName(phase)==value)phase to v else null}catch(_:IllegalArgumentException){null}
        }
    }
}
data class CompensatedPanelStartReceipt(val scope:ManagementScope,val binding:CompensatedPanelStartBinding,val schemaSha256:String,
    val inbounds:Int,val observedAt:Instant){
    init{require(Regex("[0-9a-f]{64}").matches(schemaSha256) && inbounds in 0..256)}
}
