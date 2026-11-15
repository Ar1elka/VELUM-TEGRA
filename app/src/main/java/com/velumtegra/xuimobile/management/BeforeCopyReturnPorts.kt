package com.velumtegra.xuimobile.management
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.*

enum class BeforeCopyReturnAction { RETURN_ONCE, READ_RESULT }
data class BeforeCopyReturnReview(val token:String,val operationId:String,val revision:Long,val binding:BeforeCopyReturnBinding,
    val action:BeforeCopyReturnAction,val serverLabel:String,val sshLabel:String,val reviewedAt:Instant)
sealed interface BeforeCopyReturnResult{
    data class Recorded(val operationId:String):BeforeCopyReturnResult
    data class Checked(val receipt:BeforeCopyReturnReceipt):BeforeCopyReturnResult
    data class Unavailable(val message:String):BeforeCopyReturnResult
}
interface BeforeCopyReturnPort{
    suspend fun review(server:String,installation:String,access:String,operation:String,evidence:BeforeCopyEvidence?):BeforeCopyReturnReview?
    suspend fun perform(review:BeforeCopyReturnReview):BeforeCopyReturnResult
    fun discard(review:BeforeCopyReturnReview)
}
internal data class BeforeReturnAuthority(val local:ManagementRestartReview,val current:VersionedOperationSnapshot,val parents:WorkingDatabaseRestoreParents)
/** Uses the existing shared server lease and journal. No new registry, runtime, background host or replay. */
internal class RepositoryBeforeCopyReturnPort(private val local:ManagementRestartLocalPort,private val journal:OperationJournal,
    private val factory:SshConnectionFactory,
    private val lease:suspend(ServerId,OperationId,suspend()->BeforeCopyReturnResult)->BeforeCopyReturnResult?,
    private val observe:suspend(ManagementScope,WorkingDatabaseRestoreBinding,SshSessionHandle)->BeforeCopyEvidence?={scope,b,s->BeforeCopyEvidenceSshAdapter().read(scope,b,s)},
    private val copy:suspend(VerifiedBeforeCopyReturnDispatch,VersionedOperationSnapshot,SshSessionHandle)->Boolean={d,c,s->BeforeCopyReturnSshAdapter().copy(d,c,s)},
    private val verify:suspend(ManagementScope,BeforeCopyReturnBinding,SshSessionHandle)->BeforeCopyReturnReceipt?={scope,b,s->BeforeCopyReturnSshAdapter().verify(scope,b,s)},
    private val now:()->Instant=Instant::now):BeforeCopyReturnPort{
    private data class Entry(val review:BeforeCopyReturnReview,val authority:BeforeReturnAuthority)
    private val pending=linkedMapOf<String,Entry>();private var active=false
    @Synchronized private fun remember(e:Entry):Boolean{
        pending.entries.removeAll{!recent(it.value.review.reviewedAt)}
        if(pending.size>=8)return false;pending[e.review.token]=e;return true
    }
    private fun recent(at:Instant)=!now().isBefore(at) && now().isBefore(at.plusSeconds(90))
    @Synchronized override fun discard(review:BeforeCopyReturnReview){pending.remove(review.token)}
    @Synchronized private fun consume(r:BeforeCopyReturnReview):Entry?{
        if(active)return null
        val e=pending.remove(r.token)?:return null
        if(e.review!=r || !recent(r.reviewedAt))return null
        active=true;return e
    }
    @Synchronized private fun finish(){active=false}
    override suspend fun review(server:String,installation:String,access:String,operation:String,evidence:BeforeCopyEvidence?):BeforeCopyReturnReview?{
        val a=authority(server,installation,access,operation)?:return null
        val parsed=BeforeCopyReturnBinding.parse(a.current.snapshot.checkpoint.phaseName)
        val b=parsed?.second?:evidence?.let{BeforeCopyReturnPolicy.bind(a.current,it,now())}?:return null
        val action=if(parsed==null)BeforeCopyReturnAction.RETURN_ONCE else BeforeCopyReturnAction.READ_RESULT
        val r=BeforeCopyReturnReview(UUID.randomUUID().toString(),operation,a.current.revision.value,b,action,a.local.serverName,a.local.sshLabel,now())
        return r.takeIf{remember(Entry(it,a))}
    }
    override suspend fun perform(review:BeforeCopyReturnReview):BeforeCopyReturnResult{
        val e=consume(review)?:return unavailable()
        return try{withContext(Dispatchers.IO){withTimeout(330_000){
            val a=e.authority;val r=a.local
            lease(r.installation.serverId,a.current.snapshot.operationId){
                if(!same(a))return@lease unavailable()
                val scope=ManagementScope(a.current.snapshot.operationId,r.installation.serverId,r.access.id,r.installation.id)
                val session=(factory.connect(r.access,SessionOwner.Operation(scope.operationId)) as? SshConnectResult.Connected)?.handle?:return@lease unavailable()
                session.use{
                    val identity=it.binding
                    fun connected()=it.isOpen && it.binding==identity && identity.owner==SessionOwner.Operation(scope.operationId) && identity.serverAccessId==scope.serverAccessId
                    if(!connected() || !same(a))return@lease unavailable()
                    if(review.action==BeforeCopyReturnAction.RETURN_ONCE){
                        val evidence=observe(scope,review.binding.original,it)?:return@lease unavailable()
                        if(!recent(review.reviewedAt) || !connected() || !same(a) || evidence.observedAt.isBefore(review.reviewedAt) || BeforeCopyReturnPolicy.bind(a.current,evidence,now())!=review.binding)return@lease unavailable()
                        currentCoroutineContext().ensureActive()
                        // SAME uncertain row keeps POST_VERIFY_REQUIRED; durable barrier is never removed.
                        val saved=advance(a.current,review.binding,BeforeCopyReturnPhase.RETURNING)?:return@lease unavailable()
                        val next=a.copy(current=saved)
                        val dispatch=VerifiedBeforeCopyReturnDispatch.afterCheckpoint(a.current,saved,evidence,now(),review.reviewedAt.plusSeconds(90))?:return@lease unavailable()
                        if(!connected() || !same(next))return@lease unavailable()
                        copy(dispatch,saved,it)
                        if(connected() && same(next))advance(saved,review.binding,BeforeCopyReturnPhase.AWAITING_READBACK)
                        // Even a confirmed remote success requires a separately confirmed readback.
                        BeforeCopyReturnResult.Recorded(scope.operationId.value)
                    }else{
                        val receipt=verify(scope,review.binding,it)
                        if(!connected() || !same(a) || receipt==null || receipt.scope!=scope || receipt.binding!=review.binding ||
                            receipt.verifiedAt.isBefore(review.reviewedAt) || receipt.verifiedAt.isAfter(now()))return@lease unavailable()
                        val phase=BeforeCopyReturnBinding.parse(a.current.snapshot.checkpoint.phaseName)?.first?:return@lease unavailable()
                        if(phase!=BeforeCopyReturnPhase.READBACK_VERIFIED && advance(a.current,review.binding,BeforeCopyReturnPhase.READBACK_VERIFIED)==null)return@lease unavailable()
                        BeforeCopyReturnResult.Checked(receipt)
                    }
                }
            }?:unavailable()
        }}}catch(_:TimeoutCancellationException){unavailable()}catch(c:CancellationException){throw c}catch(_:Exception){unavailable()}finally{finish()}
    }
    private fun unavailable()=BeforeCopyReturnResult.Unavailable("Исход не подтверждён. Журнал сохраняет барьер. Повторной записи и автоматического запуска службы нет; требуется отдельная проверка результата.")
    private suspend fun same(a:BeforeReturnAuthority)=authority(a.local.serverId,a.local.installationId,a.local.accessId,a.current.snapshot.operationId.value)==a
    private suspend fun authority(s:String,i:String,a:String,id:String):BeforeReturnAuthority?{
        if(listOf(s,i,a,id).any{it.isBlank()})return null
        val r=(local.readExact(s,i,a) as? ManagementRestartLocalReview.Ready)?.review?.takeIf{it.matches(s,i,a)}?:return null
        val c=(journal.get(OperationId(id)) as? OperationJournalResult.Success)?.value?:return null
        if(c.snapshot.operationId.value!=id)return null
        val returned=BeforeCopyReturnBinding.parse(c.snapshot.checkpoint.phaseName)?.second
        val b=returned?.original?:WorkingDatabaseRestoreBinding.parse(c.snapshot.checkpoint.phaseName)?.second?:return null
        val p=workingDatabaseRestoreParents(journal,b.comparisonOperationId)?:return null
        if(returned!=null){if(!BeforeCopyReturnPolicy.matches(c,returned,r.installation,r.access,p.comparison,p.check,p.backup))return null}
        else if(!BeforeCopyReturnPolicy.uncertain(c) || !WorkingDatabaseRestoreBindingPolicy.matches(c,r.installation,r.access,p.comparison,p.check,p.backup))return null
        val rows=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return null
        if(rows.none{it==c} || rows.any{it.snapshot.target.serverId==r.installation.serverId && it!=c})return null
        if((local.readExact(s,i,a) as? ManagementRestartLocalReview.Ready)?.review!=r ||
            (journal.get(c.snapshot.operationId) as? OperationJournalResult.Success)?.value!=c || workingDatabaseRestoreParents(journal,b.comparisonOperationId)!=p)return null
        return BeforeReturnAuthority(r,c,p)
    }
    private suspend fun advance(c:VersionedOperationSnapshot,b:BeforeCopyReturnBinding,phase:BeforeCopyReturnPhase):VersionedOperationSnapshot?{
        val at=now();if(at.isBefore(c.snapshot.updatedAt))return null
        val next=c.snapshot.copy(status=OperationStatus.RECONCILIATION_REQUIRED,checkpoint=OperationCheckpoint(b.phaseName(phase),CheckpointSemantics.POST_VERIFY_REQUIRED,at),updatedAt=at)
        return (journal.advance(c.snapshot.operationId,c.revision,next) as? OperationJournalResult.Success)?.value
    }
}
