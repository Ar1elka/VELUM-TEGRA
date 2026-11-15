package com.velumtegra.xuimobile.management
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.*

data class RecoveryReadinessReview(val token:String,val scope:ManagementScope,val revision:Long,val binding:RestoreCompatibilityBinding,
    val serverLabel:String,val sshLabel:String,val reviewedAt:Instant)
sealed interface RecoveryReadinessResult{
    data class Observed(val evidence:RecoveryReadinessEvidence):RecoveryReadinessResult
    data class Unavailable(val text:String):RecoveryReadinessResult
}
interface RecoveryReadinessPort{
    suspend fun review(scope:ManagementScope):RecoveryReadinessReview?
    suspend fun read(review:RecoveryReadinessReview):RecoveryReadinessResult
    fun discard(review:RecoveryReadinessReview)
}
internal class RepositoryRecoveryReadinessPort(private val local:ManagementRestartLocalPort,private val journal:OperationJournal,
    private val factory:SshConnectionFactory,private val lease:suspend(ServerId,OperationId,suspend()->RecoveryReadinessResult)->RecoveryReadinessResult?,
    private val inspect:suspend(ManagementScope,RestoreCompatibilityBinding,Long,XuiInstallation,SshSessionHandle)->RecoveryReadinessEvidence?={scope,b,revision,i,session->RecoveryReadinessSshReader().read(scope,b,revision,i,session)},
    private val now:()->Instant=Instant::now):RecoveryReadinessPort{
    private data class Authority(val local:ManagementRestartReview,val current:VersionedOperationSnapshot,val check:VersionedOperationSnapshot,val backup:VersionedOperationSnapshot)
    private data class Entry(val review:RecoveryReadinessReview,val authority:Authority)
    private val pending=linkedMapOf<String,Entry>();private var active=false
    private fun recent(at:Instant)=!now().isBefore(at) && now().isBefore(at.plusSeconds(90))
    @Synchronized private fun remember(e:Entry):Boolean{pending.entries.removeAll{!recent(it.value.review.reviewedAt)};if(pending.size>=8)return false;pending[e.review.token]=e;return true}
    @Synchronized override fun discard(review:RecoveryReadinessReview){pending.remove(review.token)}
    @Synchronized private fun consume(r:RecoveryReadinessReview):Entry?{
        if(active)return null
        val e=pending.remove(r.token)?:return null
        if(e.review!=r || !recent(r.reviewedAt))return null
        active=true;return e
    }
    @Synchronized private fun finish(){active=false}
    override suspend fun review(scope:ManagementScope):RecoveryReadinessReview?{
        val a=authority(scope)?:return null;val b=RestoreCompatibilityBinding.parse(a.current.snapshot.checkpoint.phaseName)!!.second
        val r=RecoveryReadinessReview(UUID.randomUUID().toString(),scope,a.current.revision.value,b,a.local.serverName,a.local.sshLabel,now())
        return r.takeIf{remember(Entry(it,a))}
    }
    override suspend fun read(review:RecoveryReadinessReview):RecoveryReadinessResult{
        val e=consume(review)?:return unavailable()
        return try{withContext(Dispatchers.IO){withTimeout(175_000){
            lease(review.scope.serverId,review.scope.operationId){
                if(!same(review.scope,e.authority) || !recent(review.reviewedAt))return@lease unavailable()
                val session=(factory.connect(e.authority.local.access,SessionOwner.Operation(review.scope.operationId)) as? SshConnectResult.Connected)?.handle?:return@lease unavailable()
                session.use{
                    val identity=it.binding
                    if(!it.isOpen || identity.owner!=SessionOwner.Operation(review.scope.operationId) || identity.serverAccessId!=review.scope.serverAccessId ||
                        !same(review.scope,e.authority) || !recent(review.reviewedAt))return@lease unavailable()
                    val proof=inspect(review.scope,review.binding,review.revision,e.authority.local.installation,it)
                    currentCoroutineContext().ensureActive()
                    if(!it.isOpen || it.binding!=identity || !same(review.scope,e.authority) || proof==null || proof.scope!=review.scope || proof.binding!=review.binding ||
                        proof.comparisonRevision!=review.revision || proof.observedAt.isBefore(review.reviewedAt) || proof.observedAt.isAfter(now()) || !RecoveryReadinessPolicy.fresh(proof,now()))unavailable()
                    else RecoveryReadinessResult.Observed(proof)
                }
            }?:unavailable()
        }}}catch(_:TimeoutCancellationException){unavailable()}catch(c:CancellationException){throw c}catch(_:Exception){unavailable()}finally{finish()}
    }
    private fun unavailable()=RecoveryReadinessResult.Unavailable("Условия восстановления не подтверждены: цель, источник или файлы изменились, есть незавершённая операция либо чтение недоступно. Запись и миграция не разрешены; автоматического повтора нет.")
    private suspend fun get(id:OperationId)=(journal.get(id) as? OperationJournalResult.Success)?.value
    private suspend fun same(s:ManagementScope,a:Authority)=authority(s)==a
    private suspend fun authority(s:ManagementScope):Authority?{
        val r=(local.readExact(s.serverId.value,s.installationId.value,s.serverAccessId.value) as? ManagementRestartLocalReview.Ready)?.review
            ?.takeIf{it.matches(s.serverId.value,s.installationId.value,s.serverAccessId.value)}?:return null
        val c=get(s.operationId)?:return null;if(c.snapshot.operationId!=s.operationId || now().isBefore(c.snapshot.updatedAt))return null
        val b=RestoreCompatibilityBinding.parse(c.snapshot.checkpoint.phaseName)?.second?:return null
        val check=get(b.checkOperationId)?:return null;val backup=get(b.source.sourceOperationId)?:return null
        if(!RecoveryReadinessPolicy.source(c,check,backup,r.installation,r.access))return null
        val others=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return null
        // Do not bypass or reconcile an uncertain compensated row using a read-only planning receipt.
        if(others.any{it.snapshot.target.serverId==s.serverId})return null
        if((local.readExact(s.serverId.value,s.installationId.value,s.serverAccessId.value) as? ManagementRestartLocalReview.Ready)?.review!=r ||
            get(s.operationId)!=c || get(b.checkOperationId)!=check || get(b.source.sourceOperationId)!=backup)return null
        return Authority(r,c,check,backup)
    }
}
