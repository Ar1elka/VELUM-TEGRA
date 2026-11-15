package com.velumtegra.xuimobile.core.model
import java.time.Instant

enum class BeforeCopyCurrent { SAME, DIFFERENT, UNAVAILABLE }
enum class BeforeCopyStructure { MATCH, DIFFERENT, UNAVAILABLE }
enum class BeforeCopyService { ACTIVE, INACTIVE }
enum class BeforeCopyCompletion { COMPLETE, PARTIAL }
/** An observation, never permission to restore, clear an uncertainty barrier or start a service. */
data class BeforeCopyEvidence(val scope:ManagementScope,val binding:WorkingDatabaseRestoreBinding,
    val databaseSha256:String,val logicalSha256:String,val bytes:Long,val service:BeforeCopyService,
    val current:BeforeCopyCurrent,val structure:BeforeCopyStructure,val completion:BeforeCopyCompletion,val observedAt:Instant){
    init{require(listOf(databaseSha256,logicalSha256).all{Regex("[0-9a-f]{64}").matches(it)});require(bytes in 1..DatabaseBackupBinding.MAX_BYTES);require(service!=BeforeCopyService.ACTIVE || current==BeforeCopyCurrent.UNAVAILABLE)}
}
