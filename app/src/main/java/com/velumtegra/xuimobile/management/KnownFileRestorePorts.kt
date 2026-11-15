package com.velumtegra.xuimobile.management
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.*

enum class KnownFileRestoreAction { APPLY, READ, RETURN }
data class KnownFileRestoreReview(val token:String,val scope:ManagementScope,val revision:Long,val binding:KnownFileRestoreBinding,
    val action:KnownFileRestoreAction,val serverLabel:String,val sshLabel:String,val reviewedAt:Instant,val returnManifest:String?=null)
sealed interface KnownFileRestoreResult{
    data class Recorded(val operationId:String):KnownFileRestoreResult
    data class Checked(val evidence:KnownFileRestoreInspection,val terminal:Boolean,val mayReturn:Boolean):KnownFileRestoreResult
    data class Unavailable(val text:String):KnownFileRestoreResult
}
interface KnownFileRestorePort{
    suspend fun review(server:String,installation:String,access:String,comparison:String,operation:String?,evidence:RecoveryReadinessEvidence?,returning:KnownFileRestoreInspection?=null):KnownFileRestoreReview?
    suspend fun perform(review:KnownFileRestoreReview):KnownFileRestoreResult
    fun discard(review:KnownFileRestoreReview)
}
internal class RepositoryKnownFileRestorePort(private val local:ManagementRestartLocalPort,private val journal:OperationJournal,private val factory:SshConnectionFactory,
    private val lease:suspend(ServerId,OperationId,suspend()->KnownFileRestoreResult)->KnownFileRestoreResult?,
    private val prepare:suspend(ManagementScope,KnownFileRestoreBinding,XuiInstallation,SshSessionHandle)->KnownFileRestorePrepared?={scope,b,i,s->KnownFileRestoreSshAdapter().prepare(scope,b,i,s)},
    private val write:suspend(VerifiedKnownFileRestoreDispatch,VersionedOperationSnapshot,XuiInstallation,SshSessionHandle)->Boolean={d,c,i,s->KnownFileRestoreSshAdapter().write(d,c,i,s)},
    private val inspect:suspend(ManagementScope,KnownFileRestoreBinding,XuiInstallation,SshSessionHandle)->KnownFileRestoreInspection?={scope,b,i,s->KnownFileRestoreSshAdapter().inspect(scope,b,i,s)},
    private val now:()->Instant=Instant::now,private val idFactory:()->OperationId={OperationId(UUID.randomUUID().toString())}):KnownFileRestorePort{
    private data class Authority(val local:ManagementRestartReview,val comparison:VersionedOperationSnapshot,val check:VersionedOperationSnapshot,val backup:VersionedOperationSnapshot,val current:VersionedOperationSnapshot?)
    private data class Entry(val review:KnownFileRestoreReview,val authority:Authority)
    private val pending=linkedMapOf<String,Entry>();private var active=false
    private fun recent(at:Instant)=!now().isBefore(at) && now().isBefore(at.plusSeconds(90))
    @Synchronized private fun remember(e:Entry):Boolean{pending.entries.removeAll{!recent(it.value.review.reviewedAt)};if(pending.size>=8)return false;pending[e.review.token]=e;return true}
    @Synchronized override fun discard(review:KnownFileRestoreReview){pending.remove(review.token)}
    @Synchronized private fun consume(r:KnownFileRestoreReview):Entry?{if(active)return null;val e=pending.remove(r.token)?:return null;if(e.review!=r || !recent(r.reviewedAt))return null;active=true;return e}
    @Synchronized private fun finish(){active=false}
    override suspend fun review(server:String,installation:String,access:String,comparison:String,operation:String?,evidence:RecoveryReadinessEvidence?,returning:KnownFileRestoreInspection?):KnownFileRestoreReview?{
        val a=authority(server,installation,access,comparison,operation)?:return null;val current=a.current
        val id=current?.snapshot?.operationId?:idFactory()
        val binding=if(current!=null)KnownFileRestoreBinding.parse(current.snapshot.checkpoint.phaseName)?.second else evidence?.let{
            KnownFileRestorePolicy.bind(id,a.local.installation,a.local.access,a.comparison,a.check,a.backup,it,now())}?:return null
        val b=binding?:return null
        val scope=ManagementScope(id,a.local.installation.serverId,a.local.access.id,a.local.installation.id)
        val action=if(current==null)KnownFileRestoreAction.APPLY else if(returning!=null){
            val phase=KnownFileRestoreBinding.parse(current.snapshot.checkpoint.phaseName)?.first
            if(phase !in setOf(KnownFileRestorePhase.APPLYING,KnownFileRestorePhase.NEEDS_CHECK) || returning.scope!=scope || returning.binding!=b ||
                returning.desiredComplete || !recent(returning.observedAt) || returning.observedAt.isBefore(current.snapshot.updatedAt))return null
            KnownFileRestoreAction.RETURN
        }else KnownFileRestoreAction.READ
        val r=KnownFileRestoreReview(UUID.randomUUID().toString(),scope,current?.revision?.value?:0,b,action,a.local.serverName,a.local.sshLabel,now(),returning?.beforeManifestSha256)
        return r.takeIf{remember(Entry(it,a))}
    }
    override suspend fun perform(review:KnownFileRestoreReview):KnownFileRestoreResult{
        val e=consume(review)?:return unavailable();var persisted:String?=null
        return try{withContext(Dispatchers.IO){withTimeout(410_000){
            val a=e.authority;val r=a.local;val scope=review.scope
            lease(scope.serverId,scope.operationId){
                if(!same(a) || !recent(review.reviewedAt))return@lease unavailable()
                val session=(factory.connect(r.access,SessionOwner.Operation(scope.operationId)) as? SshConnectResult.Connected)?.handle?:return@lease unavailable()
                session.use{
                    val identity=it.binding
                    fun connected()=it.isOpen && it.binding==identity && identity.owner==SessionOwner.Operation(scope.operationId) && identity.serverAccessId==scope.serverAccessId
                    if(!connected() || !same(a) || !recent(review.reviewedAt))return@lease unavailable()
                    when(review.action){
                        KnownFileRestoreAction.APPLY->{
                            if(a.current!=null)return@lease unavailable()
                            val proof=prepare(scope,review.binding,r.installation,it)?:return@lease unavailable()
                            if(!valid(proof.scope,proof.binding,proof.observedAt,review) || !connected() || !same(a) || !recent(review.reviewedAt))return@lease unavailable()
                            currentCoroutineContext().ensureActive();val at=now()
                            val initial=OperationSnapshot(scope.operationId,OperationType.KNOWN_FILE_RESTORE,a.comparison.snapshot.target,OperationStatus.RECONCILIATION_REQUIRED,
                                OperationCheckpoint(review.binding.phaseName(KnownFileRestorePhase.APPLYING),CheckpointSemantics.POST_VERIFY_REQUIRED,at),at,at)
                            val created=(journal.create(initial) as? OperationJournalResult.Success)?.value?:return@lease unavailable();persisted=scope.operationId.value
                            val next=a.copy(current=created)
                            val dispatch=VerifiedKnownFileRestoreDispatch.afterCreate(created,proof,review.reviewedAt,now())?:return@lease KnownFileRestoreResult.Recorded(scope.operationId.value)
                            if(!connected() || !same(next))return@lease KnownFileRestoreResult.Recorded(scope.operationId.value)
                            write(dispatch,created,r.installation,it)
                            if(connected() && same(next))advance(created,review.binding,KnownFileRestorePhase.NEEDS_CHECK)
                            KnownFileRestoreResult.Recorded(scope.operationId.value)
                        }
                        KnownFileRestoreAction.RETURN->{
                            val c=a.current?:return@lease unavailable();val proof=inspect(scope,review.binding,r.installation,it)?:return@lease unavailable()
                            if(!valid(proof.scope,proof.binding,proof.observedAt,review) || proof.desiredComplete || proof.beforeManifestSha256!=review.returnManifest ||
                                !connected() || !same(a) || !recent(review.reviewedAt))return@lease unavailable()
                            currentCoroutineContext().ensureActive()
                            val saved=advance(c,review.binding,KnownFileRestorePhase.RETURNING)?:return@lease unavailable();persisted=scope.operationId.value
                            val next=a.copy(current=saved)
                            val dispatch=VerifiedKnownFileRestoreDispatch.afterReturnCheckpoint(c,saved,proof,review.reviewedAt,now())?:return@lease KnownFileRestoreResult.Recorded(scope.operationId.value)
                            if(!connected() || !same(next))return@lease KnownFileRestoreResult.Recorded(scope.operationId.value)
                            write(dispatch,saved,r.installation,it)
                            if(connected() && same(next))advance(saved,review.binding,KnownFileRestorePhase.RETURN_NEEDS_CHECK)
                            KnownFileRestoreResult.Recorded(scope.operationId.value)
                        }
                        KnownFileRestoreAction.READ->{
                            val c=a.current?:return@lease unavailable();val proof=inspect(scope,review.binding,r.installation,it)?:return@lease unavailable()
                            if(!valid(proof.scope,proof.binding,proof.observedAt,review) || !connected() || !same(a))return@lease unavailable()
                            val phase=KnownFileRestoreBinding.parse(c.snapshot.checkpoint.phaseName)?.first?:return@lease unavailable()
                            val nextPhase=when(phase){
                                KnownFileRestorePhase.APPLYING,KnownFileRestorePhase.NEEDS_CHECK->if(proof.desiredComplete)KnownFileRestorePhase.APPLIED else phase
                                KnownFileRestorePhase.RETURNING,KnownFileRestorePhase.RETURN_NEEDS_CHECK->if(proof.previousComplete)KnownFileRestorePhase.RETURNED else phase
                                KnownFileRestorePhase.APPLIED->if(proof.desiredComplete)phase else return@lease unavailable()
                                KnownFileRestorePhase.RETURNED->if(proof.previousComplete)phase else return@lease unavailable()
                            }
                            val saved=if(phase==nextPhase)c else advance(c,review.binding,nextPhase)?:return@lease unavailable()
                            if(!connected() || !same(a.copy(current=saved)))return@lease unavailable()
                            KnownFileRestoreResult.Checked(proof,nextPhase in setOf(KnownFileRestorePhase.APPLIED,KnownFileRestorePhase.RETURNED),nextPhase in setOf(KnownFileRestorePhase.APPLYING,KnownFileRestorePhase.NEEDS_CHECK) && !proof.desiredComplete)
                        }
                    }
                }
            }?:unavailable()
        }}}catch(_:TimeoutCancellationException){persisted?.let{KnownFileRestoreResult.Recorded(it)}?:unavailable()}catch(c:CancellationException){throw c}catch(_:Exception){persisted?.let{KnownFileRestoreResult.Recorded(it)}?:unavailable()}finally{finish()}
    }
    private fun valid(scope:ManagementScope,b:KnownFileRestoreBinding,at:Instant,r:KnownFileRestoreReview)=scope==r.scope && b==r.binding && !at.isBefore(r.reviewedAt) && !at.isAfter(now()) && recent(at)
    private fun unavailable()=KnownFileRestoreResult.Unavailable("Исход не подтверждён. Автоматической записи, возврата или запуска службы нет. При начатой операции журнал сохраняет барьер; нужна отдельная проверка результата.")
    private suspend fun get(id:OperationId)=(journal.get(id) as? OperationJournalResult.Success)?.value
    private suspend fun same(a:Authority)=authority(a.local.serverId,a.local.installationId,a.local.accessId,a.comparison.snapshot.operationId.value,a.current?.snapshot?.operationId?.value)==a
    private suspend fun authority(s:String,i:String,a:String,parent:String,operation:String?):Authority?{
        if(listOf(s,i,a,parent).any{it.isBlank()} || operation?.isBlank()==true)return null
        val r=(local.readExact(s,i,a) as? ManagementRestartLocalReview.Ready)?.review?.takeIf{it.matches(s,i,a)}?:return null
        val comparison=get(OperationId(parent))?:return null;val b=RestoreCompatibilityBinding.parse(comparison.snapshot.checkpoint.phaseName)?.second?:return null
        val check=get(b.checkOperationId)?:return null;val backup=get(b.source.sourceOperationId)?:return null
        if(!RecoveryReadinessPolicy.source(comparison,check,backup,r.installation,r.access) || now().isBefore(comparison.snapshot.updatedAt))return null
        val rows=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return null
        val own=if(operation!=null)get(OperationId(operation))?:return null else rows.filter{it.snapshot.type==OperationType.KNOWN_FILE_RESTORE &&
            it.snapshot.target==comparison.snapshot.target && KnownFileRestoreBinding.parse(it.snapshot.checkpoint.phaseName)?.second?.comparisonOperationId==comparison.snapshot.operationId}.singleOrNull()
        if(own!=null && (!KnownFileRestorePolicy.matches(own,r.installation,r.access,comparison,check,backup) || now().isBefore(own.snapshot.updatedAt)))return null
        if(rows.any{it.snapshot.target.serverId==r.installation.serverId && it!=own})return null
        if((local.readExact(s,i,a) as? ManagementRestartLocalReview.Ready)?.review!=r || get(comparison.snapshot.operationId)!=comparison || get(check.snapshot.operationId)!=check || get(backup.snapshot.operationId)!=backup ||
            own!=null && get(own.snapshot.operationId)!=own)return null
        return Authority(r,comparison,check,backup,own)
    }
    private suspend fun advance(c:VersionedOperationSnapshot,b:KnownFileRestoreBinding,phase:KnownFileRestorePhase):VersionedOperationSnapshot?{
        val at=now();if(at.isBefore(c.snapshot.updatedAt))return null
        val terminal=phase in setOf(KnownFileRestorePhase.APPLIED,KnownFileRestorePhase.RETURNED)
        val status=if(phase==KnownFileRestorePhase.APPLIED)OperationStatus.SUCCEEDED else if(phase==KnownFileRestorePhase.RETURNED)OperationStatus.FAILED else OperationStatus.RECONCILIATION_REQUIRED
        val next=c.snapshot.copy(status=status,checkpoint=OperationCheckpoint(b.phaseName(phase),if(terminal)CheckpointSemantics.TERMINAL else CheckpointSemantics.POST_VERIFY_REQUIRED,at),updatedAt=at)
        return (journal.advance(c.snapshot.operationId,c.revision,next) as? OperationJournalResult.Success)?.value
    }
}
