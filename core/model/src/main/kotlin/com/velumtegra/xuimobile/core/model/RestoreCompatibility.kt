package com.velumtegra.xuimobile.core.model

import java.time.Instant

enum class RestoreCompatibilityPhase { PENDING, OBSERVED, FAILED, CANCELLED }
enum class RestoreFileSetComparison { MATCH, DIFFERENT, UNAVAILABLE }
/** Exact durable pointers and public source evidence; never restoration or migration authority. */
data class RestoreCompatibilityBinding(val checkOperationId: OperationId, val checkRevision: Long,
    val source: RestoreCheckBinding, val digest: String) {
    init {
        require(Regex("[A-Za-z0-9._-]{1,96}").matches(checkOperationId.value) && checkRevision >= 0)
        require(source.hasSourceProof && Regex("[0-9a-f]{64}").matches(digest))
        require(checkOperationId != source.sourceOperationId)
    }
    fun phaseName(phase: RestoreCompatibilityPhase): String = listOf("RCP1_${phase.name}", checkOperationId.value,
        checkRevision.toString(), digest, source.phaseName(RestoreCheckPhase.VERIFIED)).joinToString(":")
    companion object {
        fun parse(value: String): Pair<RestoreCompatibilityPhase, RestoreCompatibilityBinding>? {
            val p=value.split(':',limit=5); if(p.size!=5)return null
            val phase=RestoreCompatibilityPhase.values().singleOrNull{"RCP1_${it.name}"==p[0]}?:return null
            val source=RestoreCheckBinding.parse(p[4])?.takeIf{it.first==RestoreCheckPhase.VERIFIED}?.second?:return null
            return try { val b=RestoreCompatibilityBinding(OperationId(p[1]),p[2].toLong(),source,p[3]); if(b.phaseName(phase)==value)phase to b else null }
            catch(_:IllegalArgumentException){null}
        }
    }
}
/** Finite read-only observations. Matching prerequisites do not prove working recovery or cross-version compatibility. */
data class RestoreCompatibilityReport(val scope: ManagementScope, val binding: RestoreCompatibilityBinding,
    val currentVersion: String, val currentArchitecture: UpdateServerArchitecture,
    val sourceSchemaSha256: String?, val currentSchemaSha256: String?, val fileSet: RestoreFileSetComparison,
    val changedFiles: Int?, val sourceInbounds: Int?, val currentInbounds: Int?,
    val serviceState: ManagementServiceState, val baselineStatus: ManagementBaselineStatus, val observedAt: Instant) {
    init {
        require(Regex("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}").matches(currentVersion))
        listOf(sourceSchemaSha256,currentSchemaSha256).filterNotNull().forEach{require(Regex("[0-9a-f]{64}").matches(it))}
        require(changedFiles==null || changedFiles in 0..RecoveryFileInventory.MAX_FILES)
        require((fileSet==RestoreFileSetComparison.UNAVAILABLE)==(changedFiles==null))
        require((sourceSchemaSha256==null)==(sourceInbounds==null) && (currentSchemaSha256==null)==(currentInbounds==null))
        listOf(sourceInbounds,currentInbounds).filterNotNull().forEach{require(it in 0..256)}
    }
    val sameVersion: Boolean get()=currentVersion==binding.source.source.version
    val sameArchitecture: Boolean get()=currentArchitecture==binding.source.source.architecture
    val sameSchema: Boolean get()=sourceSchemaSha256!=null && sourceSchemaSha256==currentSchemaSha256
    val prerequisitesMatch: Boolean get()=sameVersion && sameArchitecture && sameSchema && fileSet==RestoreFileSetComparison.MATCH &&
        baselineStatus==ManagementBaselineStatus.Matched && serviceState in setOf(ManagementServiceState.ACTIVE,ManagementServiceState.INACTIVE)
}
