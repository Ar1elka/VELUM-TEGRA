package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

sealed interface RestoreCompatibilityRuntimeResult {
    data object NotRestoreCompatibilityOperation:RestoreCompatibilityRuntimeResult
    data object TransportRequired:RestoreCompatibilityRuntimeResult
    data class Rejected(val failure:RestoreCheckFailure):RestoreCompatibilityRuntimeResult
    data class Failed(val revision:OperationRevision):RestoreCompatibilityRuntimeResult
    data class Completed(val report:RestoreCompatibilityReport,val revision:OperationRevision,
        val installation:VersionedRecord<XuiInstallation>,val access:ServerAccess):RestoreCompatibilityRuntimeResult
}
fun interface RestoreCompatibilityReadPort {
    suspend fun read(scope:ManagementScope,binding:RestoreCompatibilityBinding,installation:XuiInstallation,session:SshSessionHandle):RestoreCompatibilityReport?
}
/** Explicit read-only consumer; no confirmation reconstruction, mutation phase, backup writer or executor. */
class RestoreCompatibilityRuntimeCoordinator(private val journal:OperationJournal,private val installations:XuiInstallationRepository?,
    private val links:ManagementAccessRepository?,private val accesses:ServerAccessRepository,
    private val runtimeRegistry:OperationRuntimeLeaseRegistry,private val sessions:ExactSessionRegistry,
    private val mutations:ServerMutationLeaseRegistry,private val now:()->Instant=Instant::now,
    private val reader:RestoreCompatibilityReadPort=RestoreCompatibilityReadPort{scope,b,i,session->RestoreCompatibilitySshReader().read(scope,b,i,session)}) {
    suspend fun prepare(admission:RecoveryRuntimeAdmission):RestoreCompatibilityRuntimeResult {
        val c=read(admission)?:return reject(RestoreCheckFailure.JOURNAL)
        if(c.snapshot.type!=OperationType.RESTORE_COMPATIBILITY)return RestoreCompatibilityRuntimeResult.NotRestoreCompatibilityOperation
        return if(records(c)!=null)RestoreCompatibilityRuntimeResult.TransportRequired else reject(RestoreCheckFailure.EXACT_TARGET)
    }
    suspend fun execute(admission:RecoveryRuntimeAdmission,binding:SessionBinding):RestoreCompatibilityRuntimeResult {
        val c=read(admission)?:return reject(RestoreCheckFailure.JOURNAL)
        if(c.snapshot.type!=OperationType.RESTORE_COMPATIBILITY)return RestoreCompatibilityRuntimeResult.NotRestoreCompatibilityOperation
        val r=records(c)?:return reject(RestoreCheckFailure.EXACT_TARGET)
        val t=c.snapshot.target as OperationTarget.InstallationTarget
        val scope=ManagementScope(c.snapshot.operationId,t.serverId,t.serverAccessId,t.installationId)
        val session=sessions.find(SessionOwner.Operation(scope.operationId),scope.serverAccessId)?.takeIf{it.isOpen && it.binding==binding}?:return reject(RestoreCheckFailure.SESSION)
        if(!valid(admission,c,r,session,binding))return reject(RestoreCheckFailure.EXACT_TARGET)
        val lease=mutations.tryAcquire(scope.serverId,scope.operationId) as? ServerMutationAcquireResult.Acquired?:return reject(RestoreCheckFailure.PRECHECK)
        try {
            val all=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return reject(RestoreCheckFailure.JOURNAL)
            if(DurableServerMutationBarrierPolicy.evaluate(scope.serverId,all.map{it.snapshot})!=ServerMutationBarrierDecision.Allowed)return reject(RestoreCheckFailure.PRECHECK)
            val b=RestoreCompatibilityBinding.parse(c.snapshot.checkpoint.phaseName)?.second?:return reject(RestoreCheckFailure.JOURNAL)
            val result=reader.read(scope,b,r.installation.value,session)
            if(!valid(admission,c,r,session,binding))return reject(RestoreCheckFailure.EXACT_TARGET)
            val at=now()
            if(at.isBefore(c.snapshot.updatedAt))return reject(RestoreCheckFailure.JOURNAL)
            val okay=result!=null && result.scope==scope && result.binding==b && !result.observedAt.isBefore(c.snapshot.updatedAt) && !result.observedAt.isAfter(at)
            val terminal=c.snapshot.copy(status=if(okay)OperationStatus.SUCCEEDED else OperationStatus.FAILED,
                checkpoint=OperationCheckpoint(b.phaseName(if(okay)RestoreCompatibilityPhase.OBSERVED else RestoreCompatibilityPhase.FAILED),CheckpointSemantics.TERMINAL,at),updatedAt=at)
            val committed=(journal.advance(c.snapshot.operationId,c.revision,terminal) as? OperationJournalResult.Success)?.value?:return reject(RestoreCheckFailure.JOURNAL)
            return if(okay)RestoreCompatibilityRuntimeResult.Completed(requireNotNull(result),committed.revision,r.installation,r.access) else RestoreCompatibilityRuntimeResult.Failed(committed.revision)
        }finally{mutations.release(lease.lease)}
    }
    private data class Records(val installation:VersionedRecord<XuiInstallation>,val access:ServerAccess,
        val check:VersionedOperationSnapshot,val backup:VersionedOperationSnapshot)
    private suspend fun records(c:VersionedOperationSnapshot):Records? {
        val s=c.snapshot; val parsed=RestoreCompatibilityBinding.parse(s.checkpoint.phaseName)?:return null
        if(s.status!=OperationStatus.RUNNING || s.checkpoint.semantics!=CheckpointSemantics.READ_ONLY || parsed.first!=RestoreCompatibilityPhase.PENDING)return null
        val t=s.target as? OperationTarget.InstallationTarget?:return null
        val i=(installations?.get(t.installationId) as? RepositoryResult.Success)?.value?:return null
        val a=(accesses.get(t.serverAccessId) as? RepositoryResult.Success)?.value?:return null
        val link=(links?.get(t.installationId,t.serverAccessId) as? RepositoryResult.Success)?.value?:return null
        if(link.installationId!=t.installationId || link.serverAccessId!=t.serverAccessId)return null
        val check=(journal.get(parsed.second.checkOperationId) as? OperationJournalResult.Success)?.value?:return null
        val backup=(journal.get(parsed.second.source.sourceOperationId) as? OperationJournalResult.Success)?.value?:return null
        return Records(i,a,check,backup).takeIf{RestoreCompatibilityBindingPolicy.matches(c,i.value,a,check,backup)}
    }
    private suspend fun read(a:RecoveryRuntimeAdmission):VersionedOperationSnapshot? {
        if(!runtimeRegistry.isCurrent(a.runtimeLease))return null
        return (journal.get(a.plan.operationId) as? OperationJournalResult.Success)?.value?.takeIf{it.revision==a.plan.expectedRevision && it.snapshot.target==a.plan.target}
    }
    private suspend fun valid(a:RecoveryRuntimeAdmission,c:VersionedOperationSnapshot,r:Records,s:SshSessionHandle,b:SessionBinding):Boolean {
        currentCoroutineContext().ensureActive()
        return runtimeRegistry.isCurrent(a.runtimeLease) && s.isOpen && s.binding==b && b.owner==SessionOwner.Operation(c.snapshot.operationId) &&
            b.serverAccessId==c.snapshot.target.serverAccessId && sessions.find(b.owner,b.serverAccessId)===s &&
            (journal.get(c.snapshot.operationId) as? OperationJournalResult.Success)?.value==c && records(c)==r
    }
    private fun reject(f:RestoreCheckFailure)=RestoreCompatibilityRuntimeResult.Rejected(f)
}
