package com.velumtegra.xuimobile.management
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.*

enum class CompensatedPanelStartAction { START_ONCE, READ_RESULT }
data class CompensatedPanelStartReview(val token:String,val operationId:String,val revision:Long,val binding:CompensatedPanelStartBinding,
    val action:CompensatedPanelStartAction,val serverLabel:String,val sshLabel:String,val reviewedAt:Instant)
sealed interface CompensatedPanelStartResult{
    data class Recorded(val operationId:String):CompensatedPanelStartResult
    data class Checked(val receipt:CompensatedPanelStartReceipt):CompensatedPanelStartResult
    data class Unavailable(val message:String):CompensatedPanelStartResult
}
interface CompensatedPanelStartPort{
    suspend fun review(server:String,installation:String,access:String,operation:String):CompensatedPanelStartReview?
    suspend fun perform(review:CompensatedPanelStartReview):CompensatedPanelStartResult
    fun discard(review:CompensatedPanelStartReview)
    suspend fun verifiedSource(server:String,installation:String,access:String,operation:String):VersionedOperationSnapshot?=null
}
internal data class CompensatedStartAuthority(val local:ManagementRestartReview,val current:VersionedOperationSnapshot,val parents:WorkingDatabaseRestoreParents)
/** Same server lease and exact nonterminal source. No new operation/runtime/schema or barrier clearing. */
internal class RepositoryCompensatedPanelStartPort(private val local:ManagementRestartLocalPort,private val journal:OperationJournal,
    private val factory:SshConnectionFactory,
    private val lease:suspend(ServerId,OperationId,suspend()->CompensatedPanelStartResult)->CompensatedPanelStartResult?,
    private val observe:suspend(ManagementScope,BeforeCopyReturnBinding,SshSessionHandle)->BeforeCopyReturnReceipt?={scope,b,s->BeforeCopyReturnSshAdapter().verify(scope,b,s)},
    private val start:suspend(VerifiedCompensatedPanelStartDispatch,VersionedOperationSnapshot,SshSessionHandle)->Boolean={d,c,s->CompensatedPanelStartSshAdapter().start(d,c,s)},
    private val verify:suspend(ManagementScope,CompensatedPanelStartBinding,SshSessionHandle)->CompensatedPanelStartReceipt?={scope,b,s->CompensatedPanelStartSshAdapter().verify(scope,b,s)},
    private val now:()->Instant=Instant::now):CompensatedPanelStartPort{
    private data class Entry(val review:CompensatedPanelStartReview,val authority:CompensatedStartAuthority)
    private data class Observation(val authority:CompensatedStartAuthority,val receipt:CompensatedPanelStartReceipt)
    private val pending=linkedMapOf<String,Entry>();private val observations=linkedMapOf<String,Observation>();private var active=false
    private fun recent(at:Instant)=!now().isBefore(at) && now().isBefore(at.plusSeconds(90))
    @Synchronized private fun remember(e:Entry):Boolean{pending.entries.removeAll{!recent(it.value.review.reviewedAt)}
        if(pending.size>=8)return false;pending[e.review.token]=e;return true}
    @Synchronized override fun discard(review:CompensatedPanelStartReview){pending.remove(review.token)}
    @Synchronized private fun consume(r:CompensatedPanelStartReview):Entry?{
        if(active)return null;val e=pending.remove(r.token)?:return null
        if(e.review!=r || !recent(r.reviewedAt))return null;active=true;observations.remove(r.operationId);return e
    }
    @Synchronized private fun finish(){active=false}
    @Synchronized private fun publish(a:CompensatedStartAuthority,r:CompensatedPanelStartReceipt){
        observations.entries.removeAll{!recent(it.value.receipt.observedAt)}
        if(observations.size<32 || observations.containsKey(r.scope.operationId.value))observations[r.scope.operationId.value]=Observation(a,r)
    }
    @Synchronized private fun observation(id:String)=observations[id]
    override suspend fun verifiedSource(server:String,installation:String,access:String,operation:String):VersionedOperationSnapshot?{
        val o=observation(operation)?:return null
        if(!o.authority.local.matches(server,installation,access) || o.authority.current.snapshot.operationId.value!=operation || !recent(o.receipt.observedAt) || CompensatedPanelStartBinding.parse(o.authority.current.snapshot.checkpoint.phaseName)?.first!=CompensatedPanelStartPhase.ACTIVE_VERIFIED ||
            !same(o.authority))return null
        return o.authority.current
    }
    override suspend fun review(server:String,installation:String,access:String,operation:String):CompensatedPanelStartReview?{
        val a=authority(server,installation,access,operation)?:return null
        val parsed=CompensatedPanelStartBinding.parse(a.current.snapshot.checkpoint.phaseName)
        val b=parsed?.second?:CompensatedPanelStartPolicy.bind(a.current)?:return null
        val action=if(parsed==null)CompensatedPanelStartAction.START_ONCE else CompensatedPanelStartAction.READ_RESULT
        val r=CompensatedPanelStartReview(UUID.randomUUID().toString(),operation,a.current.revision.value,b,action,a.local.serverName,a.local.sshLabel,now())
        return r.takeIf{remember(Entry(it,a))}
    }
    override suspend fun perform(review:CompensatedPanelStartReview):CompensatedPanelStartResult{
        val e=consume(review)?:return unavailable()
        return try{withContext(Dispatchers.IO){withTimeout(330_000){
            val a=e.authority;val r=a.local
            lease(r.installation.serverId,a.current.snapshot.operationId){
                if(!recent(review.reviewedAt) || !same(a))return@lease unavailable()
                val scope=ManagementScope(a.current.snapshot.operationId,r.installation.serverId,r.access.id,r.installation.id)
                val session=(factory.connect(r.access,SessionOwner.Operation(scope.operationId)) as? SshConnectResult.Connected)?.handle?:return@lease unavailable()
                session.use{
                    val identity=it.binding
                    fun connected()=it.isOpen && it.binding==identity && identity.owner==SessionOwner.Operation(scope.operationId) && identity.serverAccessId==scope.serverAccessId
                    if(!connected() || !same(a))return@lease unavailable()
                    if(review.action==CompensatedPanelStartAction.START_ONCE){
                        val receipt=observe(scope,review.binding.returned,it)?:return@lease unavailable()
                        val at=now()
                        if(!recent(review.reviewedAt) || !connected() || !same(a) || receipt.scope!=scope || receipt.binding!=review.binding.returned ||
                            receipt.verifiedAt.isBefore(review.reviewedAt) || receipt.verifiedAt.isAfter(at) || at.epochSecond-receipt.verifiedAt.epochSecond>=30)return@lease unavailable()
                        currentCoroutineContext().ensureActive()
                        val saved=advance(a.current,review.binding,CompensatedPanelStartPhase.STARTING)?:return@lease unavailable()
                        val next=a.copy(current=saved)
                        val dispatch=VerifiedCompensatedPanelStartDispatch.afterCheckpoint(a.current,saved,receipt,review.reviewedAt,now())?:return@lease unavailable()
                        if(!connected() || !same(next))return@lease unavailable()
                        start(dispatch,saved,it)
                        if(connected() && same(next))advance(saved,review.binding,CompensatedPanelStartPhase.AWAITING_READBACK)
                        CompensatedPanelStartResult.Recorded(scope.operationId.value)
                    }else{
                        val receipt=verify(scope,review.binding,it)
                        if(!connected() || !same(a) || receipt==null || receipt.scope!=scope || receipt.binding!=review.binding ||
                            receipt.observedAt.isBefore(review.reviewedAt) || receipt.observedAt.isAfter(now()))return@lease unavailable()
                        val phase=CompensatedPanelStartBinding.parse(a.current.snapshot.checkpoint.phaseName)?.first?:return@lease unavailable()
                        val saved=if(phase==CompensatedPanelStartPhase.ACTIVE_VERIFIED)a.current else advance(a.current,review.binding,CompensatedPanelStartPhase.ACTIVE_VERIFIED)?:return@lease unavailable()
                        val observed=a.copy(current=saved)
                        if(!same(observed))return@lease unavailable()
                        publish(observed,receipt)
                        CompensatedPanelStartResult.Checked(receipt)
                    }
                }
            }?:unavailable()
        }}}catch(_:TimeoutCancellationException){unavailable()}catch(c:CancellationException){throw c}catch(_:Exception){unavailable()}finally{finish()}
    }
    private fun unavailable()=CompensatedPanelStartResult.Unavailable("Исход не подтверждён. Служба может оставаться остановленной. Барьер журнала сохранён; повторного запуска, записи базы и автоматической остановки нет. Нужна отдельная проверка результата.")
    private suspend fun same(a:CompensatedStartAuthority)=authority(a.local.serverId,a.local.installationId,a.local.accessId,a.current.snapshot.operationId.value)==a
    private suspend fun authority(s:String,i:String,a:String,id:String):CompensatedStartAuthority?{
        if(listOf(s,i,a,id).any{it.isBlank()})return null
        val r=(local.readExact(s,i,a) as? ManagementRestartLocalReview.Ready)?.review?.takeIf{it.matches(s,i,a)}?:return null
        val c=(journal.get(OperationId(id)) as? OperationJournalResult.Success)?.value?:return null
        if(c.snapshot.operationId.value!=id || now().isBefore(c.snapshot.updatedAt))return null
        val started=CompensatedPanelStartBinding.parse(c.snapshot.checkpoint.phaseName)?.second
        val returned=started?.returned?:BeforeCopyReturnBinding.parse(c.snapshot.checkpoint.phaseName)?.takeIf{it.first==BeforeCopyReturnPhase.READBACK_VERIFIED}?.second?:return null
        val p=workingDatabaseRestoreParents(journal,returned.original.comparisonOperationId)?:return null
        if(started!=null){if(!CompensatedPanelStartPolicy.matches(c,started,r.installation,r.access,p.comparison,p.check,p.backup))return null}
        else if(CompensatedPanelStartPolicy.bind(c)==null || !BeforeCopyReturnPolicy.matches(c,returned,r.installation,r.access,p.comparison,p.check,p.backup))return null
        val rows=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return null
        if(rows.none{it==c} || rows.any{it.snapshot.target.serverId==r.installation.serverId && it!=c})return null
        if((local.readExact(s,i,a) as? ManagementRestartLocalReview.Ready)?.review!=r ||
            (journal.get(c.snapshot.operationId) as? OperationJournalResult.Success)?.value!=c || workingDatabaseRestoreParents(journal,returned.original.comparisonOperationId)!=p)return null
        return CompensatedStartAuthority(r,c,p)
    }
    private suspend fun advance(c:VersionedOperationSnapshot,b:CompensatedPanelStartBinding,phase:CompensatedPanelStartPhase):VersionedOperationSnapshot?{
        val at=now();if(at.isBefore(c.snapshot.updatedAt))return null
        val next=c.snapshot.copy(checkpoint=OperationCheckpoint(b.phaseName(phase),CheckpointSemantics.POST_VERIFY_REQUIRED,at),updatedAt=at)
        return (journal.advance(c.snapshot.operationId,c.revision,next) as? OperationJournalResult.Success)?.value
    }
}
