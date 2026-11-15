package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant

enum class RecoveryReadinessBlocker { VERSION, ARCHITECTURE, DATABASE_SCHEMA, ENDPOINT, PAGE_SIZE, FILE_MEMBERSHIP,
    SERVICE_RUNNING, SERVICE_UNVERIFIED, MIGRATION_UNVERIFIED, FILE_WRITE_PROTOCOL_UNVERIFIED }
object RecoveryReadinessPolicy {
    fun blockers(p:RecoveryReadinessEvidence):Set<RecoveryReadinessBlocker> = buildSet {
        if(p.currentVersion!=p.binding.source.source.version)add(RecoveryReadinessBlocker.VERSION)
        if(p.currentArchitecture!=p.binding.source.source.architecture)add(RecoveryReadinessBlocker.ARCHITECTURE)
        if(p.sourceSchema!=p.currentSchema)add(RecoveryReadinessBlocker.DATABASE_SCHEMA)
        if(!p.endpointsMatch)add(RecoveryReadinessBlocker.ENDPOINT)
        if(!p.pageSizesMatch)add(RecoveryReadinessBlocker.PAGE_SIZE)
        if(p.added!=0 || p.missing!=0 || p.groups.values.any{it.added!=0 || it.missing!=0})add(RecoveryReadinessBlocker.FILE_MEMBERSHIP)
        when(p.quiescence){RecoveryQuiescence.REQUIRED->add(RecoveryReadinessBlocker.SERVICE_RUNNING)
            RecoveryQuiescence.UNAVAILABLE->add(RecoveryReadinessBlocker.SERVICE_UNVERIFIED);else->Unit}
        // Equal numeric release and literal schema are insufficient to attest application migrations.
        add(RecoveryReadinessBlocker.MIGRATION_UNVERIFIED);add(RecoveryReadinessBlocker.FILE_WRITE_PROTOCOL_UNVERIFIED)
    }
    fun fresh(p:RecoveryReadinessEvidence,at:Instant)=!at.isBefore(p.observedAt) && at.isBefore(p.observedAt.plusSeconds(90))
    fun source(c:VersionedOperationSnapshot,check:VersionedOperationSnapshot,backup:VersionedOperationSnapshot,
        installation:XuiInstallation,access:ServerAccess):Boolean =
        c.snapshot.status==OperationStatus.SUCCEEDED && c.snapshot.checkpoint.semantics==CheckpointSemantics.TERMINAL &&
        RestoreCompatibilityBinding.parse(c.snapshot.checkpoint.phaseName)?.first==RestoreCompatibilityPhase.OBSERVED &&
        RestoreCompatibilityBindingPolicy.matches(c,installation,access,check,backup)
}
