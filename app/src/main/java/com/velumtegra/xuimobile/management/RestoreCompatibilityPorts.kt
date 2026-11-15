package com.velumtegra.xuimobile.management

import android.app.Activity
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.*
import com.velumtegra.xuimobile.runtime.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

data class RestoreCompatibilitySourceReview(val operationId:String,val revision:Long,val binding:RestoreCheckBinding,val verifiedAt:Instant)
data class RestoreCompatibilityObservation(val operationId:String,val sourceOperationId:String,val text:String,val terminal:Boolean,
    val mayRetry:Boolean=false,val mayCancel:Boolean=false,val report:RestoreCompatibilityReport?=null,val fresh:Boolean=false)
interface RestoreCompatibilityStatusPort {
    suspend fun source(server:String,installation:String,access:String,source:String):RestoreCompatibilitySourceReview?
    suspend fun read(server:String,installation:String,access:String,operation:String):RestoreCompatibilityObservation?
    suspend fun unfinished(server:String,installation:String,access:String,source:String):List<String>
}
sealed interface RestoreCompatibilityStart {
    data class Recorded(val operationId:String):RestoreCompatibilityStart
    data class Blocked(val text:String):RestoreCompatibilityStart
}
interface RestoreCompatibilityActionPort {
    suspend fun startConfirmed(review:ManagementRestartReview,source:RestoreCompatibilitySourceReview):RestoreCompatibilityStart
    suspend fun retryConfirmed(review:ManagementRestartReview,source:RestoreCompatibilitySourceReview,operation:String):String?
    suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?
}
internal class RestoreCompatibilityResultRegistry {
    private val values=linkedMapOf<OperationId,RestoreCompatibilityRuntimeResult?>()
    @Synchronized fun begin(id:OperationId){values[id]=null;while(values.size>8)values.remove(values.keys.first())}
    @Synchronized fun publish(id:OperationId,value:RestoreCompatibilityRuntimeResult?){if(id in values && values[id] !is RestoreCompatibilityRuntimeResult.Completed)values[id]=value}
    @Synchronized fun latest(id:OperationId)=values[id]
}
internal fun ExactOperationHostTransportSequenceResult.restoreCompatibilityResult():RestoreCompatibilityRuntimeResult?=when(this){
    is ExactOperationHostTransportSequenceResult.RestoreCompatibilityPrepared->restore
    is ExactOperationHostTransportSequenceResult.RestoreCompatibilityEnded->restore
    else->null
}
internal class JournalRestoreCompatibilityStatusPort(private val journal:OperationJournal,private val local:ManagementRestartLocalPort,
    private val registry:RestoreCompatibilityResultRegistry,private val now:()->Instant=Instant::now):RestoreCompatibilityStatusPort {
    override suspend fun source(server:String,installation:String,access:String,source:String):RestoreCompatibilitySourceReview? {
        if(listOf(server,installation,access,source).any{it.isBlank()})return null
        val r=ready(server,installation,access)?:return null
        val check=(journal.get(OperationId(source)) as? OperationJournalResult.Success)?.value?:return null
        if(check.snapshot.operationId.value!=source)return null
        val b=RestoreCheckBinding.parse(check.snapshot.checkpoint.phaseName)?.second?:return null
        val backup=(journal.get(b.sourceOperationId) as? OperationJournalResult.Success)?.value?:return null
        if(!RestoreCompatibilityBindingPolicy.parentMatches(check,backup,r.installation,r.access))return null
        if(ready(server,installation,access)!=r || get(check.snapshot.operationId)!=check || get(backup.snapshot.operationId)!=backup)return null
        return RestoreCompatibilitySourceReview(source,check.revision.value,b,check.snapshot.updatedAt)
    }
    override suspend fun read(server:String,installation:String,access:String,operation:String):RestoreCompatibilityObservation? {
        if(listOf(server,installation,access,operation).any{it.isBlank()})return null
        val r=ready(server,installation,access)?:return null
        val c=get(OperationId(operation))?:return null;if(c.snapshot.operationId.value!=operation)return null
        val parsed=RestoreCompatibilityBinding.parse(c.snapshot.checkpoint.phaseName)?:return null
        val b=parsed.second;val check=get(b.checkOperationId)?:return null;val backup=get(b.source.sourceOperationId)?:return null
        if(!RestoreCompatibilityBindingPolicy.matches(c,r.installation,r.access,check,backup))return null
        val s=c.snapshot;val terminal=s.status in setOf(OperationStatus.SUCCEEDED,OperationStatus.FAILED,OperationStatus.CANCELLED)
        if(terminal!=(s.checkpoint.semantics==CheckpointSemantics.TERMINAL))return null
        if(terminal && when(s.status){OperationStatus.SUCCEEDED->parsed.first!=RestoreCompatibilityPhase.OBSERVED
            OperationStatus.FAILED->parsed.first!=RestoreCompatibilityPhase.FAILED
            else->parsed.first!=RestoreCompatibilityPhase.CANCELLED})return null
        val pending=!terminal && s.status==OperationStatus.RUNNING && s.checkpoint.semantics==CheckpointSemantics.READ_ONLY && parsed.first==RestoreCompatibilityPhase.PENDING
        if(!terminal && !pending)return null
        val done=registry.latest(s.operationId) as? RestoreCompatibilityRuntimeResult.Completed
        val report=done?.takeIf{terminal && s.status==OperationStatus.SUCCEEDED && it.revision==c.revision &&
            it.installation.value==r.installation && it.access==r.access && it.report.binding==b &&
            it.report.scope==ManagementScope(s.operationId,r.installation.serverId,r.access.id,r.installation.id)}?.report
        val fresh=report!=null && !now().isBefore(report.observedAt) && now().epochSecond-report.observedAt.epochSecond<300
        val text=when {
            report!=null->restoreComparisonFeedback(report,fresh)
            terminal && s.status==OperationStatus.SUCCEEDED->"Журнал подтверждает завершённую сверку. Подробные наблюдения не сохранились в памяти; получить их можно только новым явным чтением."
            terminal && s.status==OperationStatus.CANCELLED->"Ожидающий запрос сверки отменён."
            terminal->"Не удалось подтвердить наблюдения. Совпадение и совместимость не установлены."
            else->"Запрос сверки зарегистрирован. Чтение не повторяется автоматически."
        }
        if(ready(server,installation,access)!=r || get(s.operationId)!=c || get(check.snapshot.operationId)!=check || get(backup.snapshot.operationId)!=backup)return null
        return RestoreCompatibilityObservation(operation,b.checkOperationId.value,text,terminal,pending,pending,report,fresh)
    }
    override suspend fun unfinished(server:String,installation:String,access:String,source:String):List<String> {
        val r=ready(server,installation,access)?:return emptyList();val check=get(OperationId(source))?:return emptyList()
        val b=RestoreCheckBinding.parse(check.snapshot.checkpoint.phaseName)?.second?:return emptyList();val backup=get(b.sourceOperationId)?:return emptyList()
        val all=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return emptyList()
        return all.filter{RestoreCompatibilityBindingPolicy.matches(it,r.installation,r.access,check,backup)}.sortedByDescending{it.snapshot.startedAt}.take(20).map{it.snapshot.operationId.value}
    }
    private suspend fun get(id:OperationId)=(journal.get(id) as? OperationJournalResult.Success)?.value
    private suspend fun ready(s:String,i:String,a:String)=(local.readExact(s,i,a) as? ManagementRestartLocalReview.Ready)?.review?.takeIf{it.matches(s,i,a)}
}
internal class ProductionRestoreCompatibilityActionPort(private val local:ManagementRestartLocalPort,private val journal:OperationJournal,
    private val registry:RestoreCompatibilityResultRegistry,private val host:suspend(OperationId)->ExactOperationHostStartResult,
    private val now:()->Instant=Instant::now,private val idFactory:()->OperationId={OperationId(UUID.randomUUID().toString())}):RestoreCompatibilityActionPort {
    constructor(activity:Activity,local:ManagementRestartLocalPort,journal:OperationJournal,registry:RestoreCompatibilityResultRegistry):
        this(local,journal,registry,{id->VisibleExactOperationHostLauncher(activity).start(id)})
    private val statuses=JournalRestoreCompatibilityStatusPort(journal,local,registry,now)
    override suspend fun startConfirmed(review:ManagementRestartReview,source:RestoreCompatibilitySourceReview):RestoreCompatibilityStart {
        if(!fresh(review) || statuses.source(review.serverId,review.installationId,review.accessId,source.operationId)!=source)return blocked("Источник или выбранная цель изменились.")
        val check=get(OperationId(source.operationId))?:return blocked("Исходная запись недоступна.")
        val backup=get(source.binding.sourceOperationId)?:return blocked("Запись резервной копии недоступна.")
        val all=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return blocked("Журнал недоступен.")
        if(DurableServerMutationBarrierPolicy.evaluate(review.installation.serverId,all.map{it.snapshot})!=ServerMutationBarrierDecision.Allowed ||
            all.any{RestoreCompatibilityBindingPolicy.matches(it,review.installation,review.access,check,backup)})return blocked("Есть незавершённая операция. Обновите локальный статус.")
        val id=idFactory();val binding=try {RestoreCompatibilityBindingPolicy.bind(id,review.installation,review.access,check,backup)}catch(_:IllegalArgumentException){return blocked("Не удалось привязать точный источник.")}
        if(!fresh(review) || statuses.source(review.serverId,review.installationId,review.accessId,source.operationId)!=source)return blocked("Источник изменился.")
        val at=now();val initial=OperationSnapshot(id,OperationType.RESTORE_COMPATIBILITY,check.snapshot.target,OperationStatus.RUNNING,
            OperationCheckpoint(binding.phaseName(RestoreCompatibilityPhase.PENDING),CheckpointSemantics.READ_ONLY,at),at,at)
        val created=(journal.create(initial) as? OperationJournalResult.Success)?.value?:return blocked("Журнал не принял запрос.")
        registry.begin(id)
        try {if(!fresh(review) || statuses.source(review.serverId,review.installationId,review.accessId,source.operationId)!=source ||
            host(id)!=ExactOperationHostStartResult.START_REQUEST_ACCEPTED)fail(created,binding)}catch(c:CancellationException){withContext(NonCancellable){fail(created,binding)};throw c}catch(_:Exception){fail(created,binding)}
        return RestoreCompatibilityStart.Recorded(id.value)
    }
    override suspend fun retryConfirmed(review:ManagementRestartReview,source:RestoreCompatibilitySourceReview,operation:String):String? {
        val c=exact(review,operation)?:return "Точная запись недоступна."
        if(statuses.source(review.serverId,review.installationId,review.accessId,source.operationId)!=source ||
            RestoreCompatibilityBinding.parse(c.snapshot.checkpoint.phaseName)?.second?.checkOperationId?.value!=source.operationId ||
            RestoreCompatibilityBinding.parse(c.snapshot.checkpoint.phaseName)?.first!=RestoreCompatibilityPhase.PENDING ||
            c.snapshot.checkpoint.semantics!=CheckpointSemantics.READ_ONLY || c.snapshot.status!=OperationStatus.RUNNING)return "Запрос уже завершился или источник изменился."
        registry.begin(c.snapshot.operationId)
        return if(host(c.snapshot.operationId)==ExactOperationHostStartResult.START_REQUEST_ACCEPTED)null else "Android не принял запрос."
    }
    override suspend fun cancelPending(review:ManagementRestartReview,operation:String):String? {
        val c=exact(review,operation)?:return "Точная запись недоступна.";val b=RestoreCompatibilityBinding.parse(c.snapshot.checkpoint.phaseName)?:return "Запись недоступна."
        if(c.snapshot.checkpoint.semantics!=CheckpointSemantics.READ_ONLY || b.first!=RestoreCompatibilityPhase.PENDING || c.snapshot.status!=OperationStatus.RUNNING)return "Запрос уже завершился."
        val at=now();if(at.isBefore(c.snapshot.updatedAt))return "Время отмены не подтверждено."
        val next=c.snapshot.copy(status=OperationStatus.CANCELLED,checkpoint=OperationCheckpoint(b.second.phaseName(RestoreCompatibilityPhase.CANCELLED),CheckpointSemantics.TERMINAL,at),updatedAt=at)
        return if(journal.advance(c.snapshot.operationId,c.revision,next) is OperationJournalResult.Success)null else "Состояние изменилось. Обновите статус."
    }
    private suspend fun exact(r:ManagementRestartReview,id:String):VersionedOperationSnapshot? {
        if(id.isBlank() || !fresh(r))return null
        val c=get(OperationId(id))?:return null;val b=RestoreCompatibilityBinding.parse(c.snapshot.checkpoint.phaseName)?.second?:return null
        val check=get(b.checkOperationId)?:return null;val backup=get(b.source.sourceOperationId)?:return null
        return c.takeIf{it.snapshot.operationId.value==id && RestoreCompatibilityBindingPolicy.matches(it,r.installation,r.access,check,backup)}
    }
    private suspend fun fail(c:VersionedOperationSnapshot,b:RestoreCompatibilityBinding){val at=now();if(at.isBefore(c.snapshot.updatedAt))return
        journal.advance(c.snapshot.operationId,c.revision,c.snapshot.copy(status=OperationStatus.FAILED,checkpoint=OperationCheckpoint(b.phaseName(RestoreCompatibilityPhase.FAILED),CheckpointSemantics.TERMINAL,at),updatedAt=at))}
    private suspend fun fresh(r:ManagementRestartReview)=(local.readExact(r.serverId,r.installationId,r.accessId) as? ManagementRestartLocalReview.Ready)?.review==r
    private suspend fun get(id:OperationId)=(journal.get(id) as? OperationJournalResult.Success)?.value
    private fun blocked(text:String)=RestoreCompatibilityStart.Blocked(text)
}
