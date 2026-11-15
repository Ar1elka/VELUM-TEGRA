package com.velumtegra.xuimobile.core.model
import java.time.Instant

enum class RecoveryQuiescence { STOPPED, REQUIRED, UNAVAILABLE }
enum class RecoveryJournalMode { DELETE, WAL }
enum class RecoveryWalPresence { ABSENT, EMPTY, PRESENT }
/** Group memberships overlap: a runtime file may also be an Xray resource. */
data class RecoveryGroupDifference(val sourceFiles:Int,val currentFiles:Int,val changedCommon:Int,val added:Int,val missing:Int){
    init {require(listOf(sourceFiles,currentFiles,changedCommon,added,missing).all{it in 0..96})
        require(sourceFiles-missing==currentFiles-added && changedCommon<=sourceFiles-missing)}
}
/** Exact process-local observation. Neither migration proof nor any dispatch permission. */
data class RecoveryReadinessEvidence(val scope:ManagementScope,val binding:RestoreCompatibilityBinding,val comparisonRevision:Long,
    val currentVersion:String,val currentArchitecture:UpdateServerArchitecture,val sourceSchema:String,val currentSchema:String,
    val groups:Map<RecoveryFileGroup,RecoveryGroupDifference>,val sourceFiles:Int,val currentFiles:Int,val changedCommon:Int,
    val added:Int,val missing:Int,val sourceBytes:Long,val currentBytes:Long,val endpointsMatch:Boolean,val pageSizesMatch:Boolean,
    val journalMode:RecoveryJournalMode,val wal:RecoveryWalPresence,val quiescence:RecoveryQuiescence,
    val currentSetSha256:String,val observedAt:Instant){
    init {require(comparisonRevision>=0 && Regex("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}").matches(currentVersion))
        require(listOf(sourceSchema,currentSchema,currentSetSha256).all{Regex("[0-9a-f]{64}").matches(it)})
        require(groups.keys==RecoveryFileGroup.values().toSet())
        RecoveryGroupDifference(sourceFiles,currentFiles,changedCommon,added,missing)
        require(sourceFiles==binding.source.fileCount && sourceFiles>0 && currentFiles>0)
        require(sourceBytes in 1..RecoveryFileInventory.MAX_TOTAL_BYTES && currentBytes in 1..RecoveryFileInventory.MAX_TOTAL_BYTES)
        require(groups.values.all{it.sourceFiles<=sourceFiles && it.currentFiles<=currentFiles && it.changedCommon<=changedCommon})
        require(groups.values.sumOf{it.sourceFiles}>=sourceFiles && groups.values.sumOf{it.currentFiles}>=currentFiles)
        require(groups.values.sumOf{it.changedCommon}>=changedCommon && groups.values.sumOf{it.added}>=added && groups.values.sumOf{it.missing}>=missing)
        require(groups.getValue(RecoveryFileGroup.RUNTIME).sourceFiles>=2 && groups.getValue(RecoveryFileGroup.SERVICE).sourceFiles>=1)
        require(groups.getValue(RecoveryFileGroup.RUNTIME).currentFiles>=2 && groups.getValue(RecoveryFileGroup.SERVICE).currentFiles>=1)
        require(journalMode==RecoveryJournalMode.WAL || wal!=RecoveryWalPresence.PRESENT)
    }
}
