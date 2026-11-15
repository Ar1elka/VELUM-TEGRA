package com.velumtegra.xuimobile.core.model
import java.time.Instant

enum class WorkingDatabaseRestorePhase { PENDING, RESTORING, FINISHED, UNCERTAIN, VERIFIED, FAILED, CANCELLED }
/** Exact comparison/check/backup pointers and public hashes. Not consent by itself. */
data class WorkingDatabaseRestoreBinding(val comparisonOperationId:OperationId,val comparisonRevision:Long,
    val comparison:RestoreCompatibilityBinding,val endpointSha256:String,val digest:String){
    init{require(Regex("[A-Za-z0-9._-]{1,96}").matches(comparisonOperationId.value) && comparisonRevision>=0)
        require(listOf(digest,endpointSha256).all{Regex("[0-9a-f]{64}").matches(it)});require(comparisonOperationId!=comparison.checkOperationId && comparisonOperationId!=comparison.source.sourceOperationId)}
    val source:RestoreCheckBinding get()=comparison.source
    fun phaseName(phase:WorkingDatabaseRestorePhase)=listOf("WDB1_${phase.name}",comparisonOperationId.value,comparisonRevision.toString(),digest,endpointSha256,comparison.phaseName(RestoreCompatibilityPhase.OBSERVED)).joinToString(":")
    companion object{
        const val ROOT="/root/.velum-tegra-working-db-restores"
        fun parse(value:String):Pair<WorkingDatabaseRestorePhase,WorkingDatabaseRestoreBinding>?{
            val p=value.split(':',limit=6);if(p.size!=6)return null
            val phase=WorkingDatabaseRestorePhase.values().singleOrNull{"WDB1_${it.name}"==p[0]}?:return null
            val c=RestoreCompatibilityBinding.parse(p[5])?.takeIf{it.first==RestoreCompatibilityPhase.OBSERVED}?.second?:return null
            return try{val b=WorkingDatabaseRestoreBinding(OperationId(p[1]),p[2].toLong(),c,p[4],p[3]);if(b.phaseName(phase)==value)phase to b else null}catch(_:IllegalArgumentException){null}
        }
    }
}
/** Actual readback only; restored database is not proof of a running panel, migration or full-file restore. */
data class WorkingDatabaseRestoreReceipt(val scope:ManagementScope,val binding:WorkingDatabaseRestoreBinding,
    val restoredLogicalSha256:String,val previousDatabaseSha256:String,val previousLogicalSha256:String,
    val previousBytes:Long,val verifiedAt:Instant){
    init{require(listOf(restoredLogicalSha256,previousDatabaseSha256,previousLogicalSha256).all{Regex("[0-9a-f]{64}").matches(it)})
        require(previousBytes in 1..DatabaseBackupBinding.MAX_BYTES)}
}

enum class WorkingDatabaseRestoreFailure { EXACT_TARGET, SOURCE, AUTHORITY_MISSING, JOURNAL, SESSION, PRECHECK, CAPACITY, PROOF_UNAVAILABLE }
