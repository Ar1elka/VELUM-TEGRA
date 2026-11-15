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

data class RestoredPanelStartSourceReview(val operationId:String,val revision:Long,val binding:WorkingDatabaseRestoreBinding,val mayStart:Boolean)
data class RestoredPanelStartObservation(val operationId:String,val sourceOperationId:String,val text:String,val terminal:Boolean,
    val mayCheck:Boolean=false,val mayCancel:Boolean=false,val receipt:RestoredPanelStartReceipt?=null,val mayCheckLogin:Boolean=false)
interface RestoredPanelStartStatusPort{
    suspend fun source(server:String,installation:String,access:String,source:String):RestoredPanelStartSourceReview?
    suspend fun read(server:String,installation:String,access:String,operation:String):RestoredPanelStartObservation?
    suspend fun unfinished(server:String,installation:String,access:String,source:String):List<String>
}
sealed interface RestoredPanelStartRequest{
    data class Recorded(val operationId:String):RestoredPanelStartRequest
    data class Blocked(val text:String):RestoredPanelStartRequest
}
interface RestoredPanelStartActionPort{
    suspend fun startConfirmed(review:ManagementRestartReview,source:RestoredPanelStartSourceReview):RestoredPanelStartRequest
    suspend fun checkConfirmed(review:ManagementRestartReview,source:RestoredPanelStartSourceReview,operation:String):String?
    suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?
}
internal class RestoredPanelStartResultRegistry{
    private val values=linkedMapOf<OperationId,RestoredPanelStartRuntimeResult?>()
    @Synchronized fun begin(id:OperationId){values[id]=null;while(values.size>8)values.remove(values.keys.first())}
    @Synchronized fun publish(id:OperationId,value:RestoredPanelStartRuntimeResult?){if(id in values && values[id] !is RestoredPanelStartRuntimeResult.Completed)values[id]=value}
    @Synchronized fun latest(id:OperationId)=values[id]
}
internal fun ExactOperationHostTransportSequenceResult.restoredPanelStartResult():RestoredPanelStartRuntimeResult?=when(this){
    is ExactOperationHostTransportSequenceResult.RestoredPanelStartPrepared->restore
    is ExactOperationHostTransportSequenceResult.RestoredPanelStartEnded->restore
    else->null
}
internal data class RestoredPanelStartParents(val restore:VersionedOperationSnapshot,val comparison:VersionedOperationSnapshot,val check:VersionedOperationSnapshot,val backup:VersionedOperationSnapshot)
internal suspend fun restoredPanelStartParents(journal:OperationJournal,id:OperationId):RestoredPanelStartParents?{
    val r=(journal.get(id) as? OperationJournalResult.Success)?.value?:return null
    val b=WorkingDatabaseRestoreBinding.parse(r.snapshot.checkpoint.phaseName)?.second?:return null
    val parents=workingDatabaseRestoreParents(journal,b.comparisonOperationId)?:return null
    return RestoredPanelStartParents(r,parents.comparison,parents.check,parents.backup)
}
internal class JournalRestoredPanelStartStatusPort(private val journal:OperationJournal,private val local:ManagementRestartLocalPort,
private val registry:RestoredPanelStartResultRegistry,private val now:()->Instant=Instant::now):RestoredPanelStartStatusPort{
    override suspend fun source(server:String,installation:String,access:String,source:String):RestoredPanelStartSourceReview?{
        if(listOf(server,installation,access,source).any{it.isBlank()})return null
        val r=ready(server,installation,access)?:return null;val p=restoredPanelStartParents(journal,OperationId(source))?:return null
        if(p.restore.snapshot.operationId.value!=source || !RestoredPanelStartBindingPolicy.parentMatches(p.restore,p.comparison,p.check,p.backup,r.installation,r.access))return null
        val b=WorkingDatabaseRestoreBinding.parse(p.restore.snapshot.checkpoint.phaseName)!!.second
        if(ready(server,installation,access)!=r || restoredPanelStartParents(journal,p.restore.snapshot.operationId)!=p)return null
        return RestoredPanelStartSourceReview(source,p.restore.revision.value,b,true)
    }
    override suspend fun read(server:String,installation:String,access:String,operation:String):RestoredPanelStartObservation?{
        if(listOf(server,installation,access,operation).any{it.isBlank()})return null
        val r=ready(server,installation,access)?:return null;val c=get(OperationId(operation))?:return null
        val parsed=RestoredPanelStartBinding.parse(c.snapshot.checkpoint.phaseName)?:return null;val b=parsed.second
        val p=restoredPanelStartParents(journal,b.restoreOperationId)?:return null
        if(c.snapshot.operationId.value!=operation || !RestoredPanelStartBindingPolicy.matches(c,r.installation,r.access,p.restore,p.comparison,p.check,p.backup))return null
        val s=c.snapshot;val terminal=s.status in setOf(OperationStatus.SUCCEEDED,OperationStatus.FAILED,OperationStatus.CANCELLED)
        if(terminal!=(s.checkpoint.semantics==CheckpointSemantics.TERMINAL))return null
        val pending=s.status==OperationStatus.RUNNING && s.checkpoint.semantics==CheckpointSemantics.MUTATION_NOT_STARTED && parsed.first==RestoredPanelStartPhase.PENDING
        val checking=!terminal && s.checkpoint.semantics in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT,CheckpointSemantics.POST_VERIFY_REQUIRED)
        if(!terminal && !pending && !checking)return null
        if(terminal && when(s.status){OperationStatus.SUCCEEDED->parsed.first!=RestoredPanelStartPhase.VERIFIED;OperationStatus.FAILED->parsed.first!=RestoredPanelStartPhase.FAILED;else->parsed.first!=RestoredPanelStartPhase.CANCELLED})return null
        val done=registry.latest(s.operationId) as? RestoredPanelStartRuntimeResult.Completed
        val receipt=done?.takeIf{terminal && s.status==OperationStatus.SUCCEEDED && it.revision==c.revision && it.installation.value==r.installation &&
            it.access==r.access && it.receipt.binding==b && it.receipt.scope==ManagementScope(s.operationId,r.installation.serverId,r.access.id,r.installation.id)}?.receipt
        val text=when{
            receipt!=null->"Проверена активная служба существующей программы: версия, архитектура, структура базы и число подключений соответствуют источнику. Вход в WebPanel, работа VPN и полный откат не подтверждены."
            terminal && s.status==OperationStatus.SUCCEEDED->"Журнал подтверждает завершённую проверку запуска. Подробные наблюдения не сохранились; текущее состояние службы и вход неизвестны."
            terminal && s.status==OperationStatus.CANCELLED->"Ожидающий запрос отменён до отправки изменения."
            terminal->"Команда запуска не отправлялась: предварительная проверка не пройдена. Служба могла измениться вне приложения."
            checking->"Команда запуска могла выполниться. Повторного запуска или остановки не будет. Подтвердите отдельное чтение результата."
            else->"Запрос зарегистрирован, но отправка изменения не подтверждена. Подтверждение не восстанавливается после перезапуска; можно отменить запись."
        }
        if(ready(server,installation,access)!=r || get(s.operationId)!=c || restoredPanelStartParents(journal,b.restoreOperationId)!=p)return null
        return RestoredPanelStartObservation(operation,b.restoreOperationId.value,text,terminal,checking,pending,receipt,terminal && s.status==OperationStatus.SUCCEEDED)
    }
    override suspend fun unfinished(server:String,installation:String,access:String,source:String):List<String>{
        if(source.isBlank())return emptyList();val r=ready(server,installation,access)?:return emptyList();val p=restoredPanelStartParents(journal,OperationId(source))?:return emptyList()
        val all=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return emptyList()
        return all.filter{RestoredPanelStartBindingPolicy.matches(it,r.installation,r.access,p.restore,p.comparison,p.check,p.backup)}.sortedByDescending{it.snapshot.startedAt}.take(20).map{it.snapshot.operationId.value}
    }
    private suspend fun ready(s:String,i:String,a:String)=(local.readExact(s,i,a) as? ManagementRestartLocalReview.Ready)?.review?.takeIf{it.matches(s,i,a)}
    private suspend fun get(id:OperationId)=(journal.get(id) as? OperationJournalResult.Success)?.value
}
internal class ProductionRestoredPanelStartActionPort(private val local:ManagementRestartLocalPort,private val journal:OperationJournal,
    private val statuses:RestoredPanelStartStatusPort,private val runtime:OperationRuntimeCoordinator,private val registry:RestoredPanelStartResultRegistry,
    private val host:suspend(OperationId)->ExactOperationHostStartResult,private val now:()->Instant=Instant::now,private val idFactory:()->OperationId={OperationId(UUID.randomUUID().toString())}):RestoredPanelStartActionPort{
    constructor(activity:Activity,local:ManagementRestartLocalPort,journal:OperationJournal,statuses:RestoredPanelStartStatusPort,runtime:OperationRuntimeCoordinator,registry:RestoredPanelStartResultRegistry):this(local,journal,statuses,runtime,registry,{VisibleExactOperationHostLauncher(activity).start(it)})
    override suspend fun startConfirmed(review:ManagementRestartReview,source:RestoredPanelStartSourceReview):RestoredPanelStartRequest{
        if(!fresh(review) || !source.mayStart || statuses.source(review.serverId,review.installationId,review.accessId,source.operationId)!=source)return blocked("Восстановление базы или точная цель не подтверждены.")
        val p=restoredPanelStartParents(journal,OperationId(source.operationId))?:return blocked("Источник недоступен.")
        val all=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return blocked("Журнал недоступен.")
        if(DurableServerMutationBarrierPolicy.evaluate(review.installation.serverId,all.map{it.snapshot})!=ServerMutationBarrierDecision.Allowed || all.any{it.snapshot.type==OperationType.RESTORED_PANEL_START && it.snapshot.target.serverId==review.installation.serverId})return blocked("Есть незавершённая операция. Завершите её отдельно.")
        val id=idFactory();val b=try{RestoredPanelStartBindingPolicy.bind(id,review.installation,review.access,p.restore,p.comparison,p.check,p.backup)}catch(_:IllegalArgumentException){return blocked("Точный источник не подтверждён.")}
        if(!fresh(review) || statuses.source(review.serverId,review.installationId,review.accessId,source.operationId)!=source)return blocked("Источник изменился.")
        val at=now();val created=(journal.create(OperationSnapshot(id,OperationType.RESTORED_PANEL_START,p.restore.snapshot.target,OperationStatus.RUNNING,
            OperationCheckpoint(b.phaseName(RestoredPanelStartPhase.PENDING),CheckpointSemantics.MUTATION_NOT_STARTED,at),at,at)) as? OperationJournalResult.Success)?.value?:return blocked("Журнал не принял запрос.")
        val confirmation=RestoredPanelStartConfirmationPolicy.confirm(created,review.installation,review.access,p.restore,p.comparison,p.check,p.backup,now())
        if(confirmation==null || !runtime.registerRestoredPanelStartConfirmation(confirmation)){fail(created,b);return RestoredPanelStartRequest.Recorded(id.value)}
        registry.begin(id)
        try{if(!fresh(review) || restoredPanelStartParents(journal,p.restore.snapshot.operationId)!=p || host(id)!=ExactOperationHostStartResult.START_REQUEST_ACCEPTED){runtime.discardRestoredPanelStartConfirmation(id);fail(created,b)}}catch(c:CancellationException){runtime.discardRestoredPanelStartConfirmation(id);withContext(NonCancellable){fail(created,b)};throw c}catch(_:Exception){runtime.discardRestoredPanelStartConfirmation(id);fail(created,b)}
        return RestoredPanelStartRequest.Recorded(id.value)
    }
    override suspend fun checkConfirmed(review:ManagementRestartReview,source:RestoredPanelStartSourceReview,operation:String):String?{
        val c=exact(review,operation)?:return "Точная запись недоступна."
        if(RestoredPanelStartBinding.parse(c.snapshot.checkpoint.phaseName)?.second?.restoreOperationId?.value!=source.operationId ||
            c.snapshot.checkpoint.semantics !in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT,CheckpointSemantics.POST_VERIFY_REQUIRED))return "Начатый запуск не найден."
        registry.begin(c.snapshot.operationId)
        return if(host(c.snapshot.operationId)==ExactOperationHostStartResult.START_REQUEST_ACCEPTED)null else "Android не принял проверку. Повторного запуска не будет."
    }
    override suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?{
        val c=exact(review,operation)?:return "Точная запись недоступна.";val b=RestoredPanelStartBinding.parse(c.snapshot.checkpoint.phaseName)?:return "Запись недоступна."
        if(c.snapshot.checkpoint.semantics!=CheckpointSemantics.MUTATION_NOT_STARTED || b.first!=RestoredPanelStartPhase.PENDING || c.snapshot.status!=OperationStatus.RUNNING)return "Изменение могло начаться. Нужна проверка результата."
        val at=now();if(at.isBefore(c.snapshot.updatedAt))return "Время отмены не подтверждено."
        val next=c.snapshot.copy(status=OperationStatus.CANCELLED,checkpoint=OperationCheckpoint(b.second.phaseName(RestoredPanelStartPhase.CANCELLED),CheckpointSemantics.TERMINAL,at),updatedAt=at)
        val done=journal.advance(c.snapshot.operationId,c.revision,next);runtime.discardRestoredPanelStartConfirmation(c.snapshot.operationId)
        return if(done is OperationJournalResult.Success)null else "Состояние изменилось. Обновите локальный статус."
    }
    private suspend fun exact(r:ManagementRestartReview,id:String):VersionedOperationSnapshot?{
        if(id.isBlank() || !fresh(r))return null;val c=(journal.get(OperationId(id)) as? OperationJournalResult.Success)?.value?:return null
        val b=RestoredPanelStartBinding.parse(c.snapshot.checkpoint.phaseName)?.second?:return null;val p=restoredPanelStartParents(journal,b.restoreOperationId)?:return null
        return c.takeIf{it.snapshot.operationId.value==id && RestoredPanelStartBindingPolicy.matches(it,r.installation,r.access,p.restore,p.comparison,p.check,p.backup)}
    }
    private suspend fun fresh(r:ManagementRestartReview)=(local.readExact(r.serverId,r.installationId,r.accessId) as? ManagementRestartLocalReview.Ready)?.review==r
    private suspend fun fail(c:VersionedOperationSnapshot,b:RestoredPanelStartBinding){val at=now();if(at.isBefore(c.snapshot.updatedAt))return
        journal.advance(c.snapshot.operationId,c.revision,c.snapshot.copy(status=OperationStatus.FAILED,checkpoint=OperationCheckpoint(b.phaseName(RestoredPanelStartPhase.FAILED),CheckpointSemantics.TERMINAL,at),updatedAt=at))}
    private fun blocked(text:String)=RestoredPanelStartRequest.Blocked(text)
}
