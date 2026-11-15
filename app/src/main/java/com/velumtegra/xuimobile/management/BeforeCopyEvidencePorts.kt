package com.velumtegra.xuimobile.management
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.*

data class BeforeCopyReview(val token:String,val operationId:String,val revision:Long,val digest:String,
    val serverLabel:String,val sshLabel:String,val reviewedAt:Instant)
sealed interface BeforeCopyResult{
    data class Observed(val evidence:BeforeCopyEvidence):BeforeCopyResult
    data class Unavailable(val message:String):BeforeCopyResult
}
interface BeforeCopyEvidencePort{
    suspend fun review(server:String,installation:String,access:String,operation:String):BeforeCopyReview?
    suspend fun read(review:BeforeCopyReview):BeforeCopyResult
    fun discard(review:BeforeCopyReview)
}
internal data class BeforeCopyAuthority(val local:ManagementRestartReview,val operation:VersionedOperationSnapshot,val parents:WorkingDatabaseRestoreParents)
internal object BeforeCopySourcePolicy{
    fun eligible(c:VersionedOperationSnapshot):Boolean{
        if(c.snapshot.type!=OperationType.WORKING_DATABASE_RESTORE)return false
        val phase=WorkingDatabaseRestoreBinding.parse(c.snapshot.checkpoint.phaseName)?.first?:return false
        val s=c.snapshot
        return (s.status==OperationStatus.SUCCEEDED && s.checkpoint.semantics==CheckpointSemantics.TERMINAL && phase==WorkingDatabaseRestorePhase.VERIFIED) ||
            (s.status in setOf(OperationStatus.RUNNING,OperationStatus.RECONCILIATION_REQUIRED) &&
                s.checkpoint.semantics in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT,CheckpointSemantics.POST_VERIFY_REQUIRED) &&
                phase in setOf(WorkingDatabaseRestorePhase.RESTORING,WorkingDatabaseRestorePhase.FINISHED,WorkingDatabaseRestorePhase.UNCERTAIN))
    }
}
/** Same journal/runtime registry. No journal writes, service commands or restore authority. */
internal class RepositoryBeforeCopyEvidencePort(private val local:ManagementRestartLocalPort,private val journal:OperationJournal,
    private val factory:SshConnectionFactory,
    private val lease:suspend(ServerId,OperationId,suspend()->BeforeCopyResult)->BeforeCopyResult?,
    private val inspect:suspend(ManagementScope,WorkingDatabaseRestoreBinding,SshSessionHandle)->BeforeCopyEvidence?={scope,b,session->BeforeCopyEvidenceSshAdapter().read(scope,b,session)},
    private val now:()->Instant=Instant::now):BeforeCopyEvidencePort{
    private data class Entry(val review:BeforeCopyReview,val authority:BeforeCopyAuthority)
    private val pending=linkedMapOf<String,Entry>();private var active=false
    @Synchronized private fun remember(e:Entry):Boolean{
        pending.entries.removeAll{!recent(it.value.review.reviewedAt)}
        if(pending.size>=8)return false
        pending[e.review.token]=e;return true
    }
    private fun recent(at:Instant)=!now().isBefore(at) && now().isBefore(at.plusSeconds(90))
    @Synchronized override fun discard(review:BeforeCopyReview){pending.remove(review.token)}
    @Synchronized private fun consume(r:BeforeCopyReview):Entry?{
        if(active)return null
        val e=pending.remove(r.token)?:return null
        if(e.review!=r || !recent(r.reviewedAt))return null
        active=true;return e
    }
    @Synchronized private fun finish(){active=false}
    override suspend fun review(server:String,installation:String,access:String,operation:String):BeforeCopyReview?{
        val a=authority(server,installation,access,operation)?:return null
        val b=WorkingDatabaseRestoreBinding.parse(a.operation.snapshot.checkpoint.phaseName)!!.second
        val r=BeforeCopyReview(UUID.randomUUID().toString(),operation,a.operation.revision.value,b.digest,a.local.serverName,a.local.sshLabel,now())
        return r.takeIf{remember(Entry(it,a))}
    }
    override suspend fun read(review:BeforeCopyReview):BeforeCopyResult{
        val e=consume(review)?:return unavailable()
        return try{withContext(Dispatchers.IO){withTimeout(160_000){
            val a=e.authority;val r=a.local
            lease(r.installation.serverId,a.operation.snapshot.operationId){
                if(!same(a))return@lease unavailable()
                val scope=ManagementScope(a.operation.snapshot.operationId,r.installation.serverId,r.access.id,r.installation.id)
                val session=(factory.connect(r.access,SessionOwner.Operation(scope.operationId)) as? SshConnectResult.Connected)?.handle?:return@lease unavailable()
                session.use{
                    val identity=it.binding
                    if(!it.isOpen || identity.owner!=SessionOwner.Operation(scope.operationId) || identity.serverAccessId!=scope.serverAccessId || !same(a))return@lease unavailable()
                    val b=WorkingDatabaseRestoreBinding.parse(a.operation.snapshot.checkpoint.phaseName)!!.second
                    val proof=inspect(scope,b,it)
                    if(!it.isOpen || it.binding!=identity || !same(a) || proof==null || proof.scope!=scope || proof.binding!=b ||
                        proof.observedAt.isBefore(review.reviewedAt) || proof.observedAt.isAfter(now()))unavailable() else BeforeCopyResult.Observed(proof)
                }
            }?:unavailable()
        }}} catch(_:TimeoutCancellationException){unavailable()} catch(c:CancellationException){throw c} catch(_:Exception){unavailable()} finally{finish()}
    }
    private fun unavailable()=BeforeCopyResult.Unavailable("Копия до изменения не подтверждена. Причиной могут быть занятый писатель, изменившаяся цель, недоступный источник или повреждение. Барьер неопределённого исхода сохраняется. Эта проверка не заменяет базу и не запускает службу.")
    private suspend fun same(a:BeforeCopyAuthority)=authority(a.local.serverId,a.local.installationId,a.local.accessId,a.operation.snapshot.operationId.value)==a
    private suspend fun authority(s:String,i:String,a:String,id:String):BeforeCopyAuthority?{
        if(listOf(s,i,a,id).any{it.isBlank()})return null
        val r=(local.readExact(s,i,a) as? ManagementRestartLocalReview.Ready)?.review?.takeIf{it.matches(s,i,a)}?:return null
        val c=(journal.get(OperationId(id)) as? OperationJournalResult.Success)?.value?:return null
        if(c.snapshot.operationId.value!=id || !BeforeCopySourcePolicy.eligible(c))return null
        val b=WorkingDatabaseRestoreBinding.parse(c.snapshot.checkpoint.phaseName)!!.second
        val parents=workingDatabaseRestoreParents(journal,b.comparisonOperationId)?:return null
        if(!WorkingDatabaseRestoreBindingPolicy.matches(c,r.installation,r.access,parents.comparison,parents.check,parents.backup))return null
        val others=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return null
        if(others.any{it.snapshot.target.serverId==r.installation.serverId && it!=c})return null
        if((local.readExact(s,i,a) as? ManagementRestartLocalReview.Ready)?.review!=r ||
            (journal.get(c.snapshot.operationId) as? OperationJournalResult.Success)?.value!=c || workingDatabaseRestoreParents(journal,b.comparisonOperationId)!=parents)return null
        return BeforeCopyAuthority(r,c,parents)
    }
}
