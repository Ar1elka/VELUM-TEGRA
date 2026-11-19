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

data class WorkingDatabaseRestoreSourceReview(val operationId:String,val revision:Long,val binding:RestoreCompatibilityBinding,
    val report:RestoreCompatibilityReport?,val mayRestore:Boolean)
data class WorkingDatabaseRestoreObservation(val operationId:String,val sourceOperationId:String,val text:String,val terminal:Boolean,
    val mayCheck:Boolean=false,val mayCancel:Boolean=false,val receipt:WorkingDatabaseRestoreReceipt?=null,val mayStartService:Boolean=false,val mayInspectBeforeCopy:Boolean=false,val mayReturnBeforeCopy:Boolean=false,val mayStartReturnedPanel:Boolean=false)
/** Exactly proven, still unfinished record of this installation and SSH profile. Local journal only. */
data class WorkingDatabaseRestoreRegistered(val operationId:String,val sourceOperationId:String,val text:String)
interface WorkingDatabaseRestoreStatusPort{
    suspend fun source(server:String,installation:String,access:String,source:String):WorkingDatabaseRestoreSourceReview?
    suspend fun read(server:String,installation:String,access:String,operation:String):WorkingDatabaseRestoreObservation?
    suspend fun unfinished(server:String,installation:String,access:String,source:String):List<String>
    /** Null when the journal could not be read or the target is no longer exact; never starts SSH. */
    suspend fun registered(server:String,installation:String,access:String):List<WorkingDatabaseRestoreRegistered>?=null
}
sealed interface WorkingDatabaseRestoreStart{
    data class Recorded(val operationId:String):WorkingDatabaseRestoreStart
    data class Blocked(val text:String):WorkingDatabaseRestoreStart
}
interface WorkingDatabaseRestoreActionPort{
    suspend fun startConfirmed(review:ManagementRestartReview,source:WorkingDatabaseRestoreSourceReview):WorkingDatabaseRestoreStart
    suspend fun checkConfirmed(review:ManagementRestartReview,source:WorkingDatabaseRestoreSourceReview,operation:String):String?
    suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?
}
internal class WorkingDatabaseRestoreResultRegistry{
    private val values=linkedMapOf<OperationId,WorkingDatabaseRestoreRuntimeResult?>()
    @Synchronized fun begin(id:OperationId){values[id]=null;while(values.size>8)values.remove(values.keys.first())}
    @Synchronized fun publish(id:OperationId,value:WorkingDatabaseRestoreRuntimeResult?){if(id in values && values[id] !is WorkingDatabaseRestoreRuntimeResult.Completed)values[id]=value}
    @Synchronized fun latest(id:OperationId)=values[id]
}
internal fun ExactOperationHostTransportSequenceResult.workingDatabaseRestoreResult():WorkingDatabaseRestoreRuntimeResult?=when(this){
    is ExactOperationHostTransportSequenceResult.WorkingDatabaseRestorePrepared->restore
    is ExactOperationHostTransportSequenceResult.WorkingDatabaseRestoreEnded->restore
    else->null
}
internal data class WorkingDatabaseRestoreParents(val comparison:VersionedOperationSnapshot,val check:VersionedOperationSnapshot,val backup:VersionedOperationSnapshot)
internal suspend fun workingDatabaseRestoreParents(journal:OperationJournal,id:OperationId):WorkingDatabaseRestoreParents?{
    val c=(journal.get(id) as? OperationJournalResult.Success)?.value?:return null
    val b=RestoreCompatibilityBinding.parse(c.snapshot.checkpoint.phaseName)?.second?:return null
    val check=(journal.get(b.checkOperationId) as? OperationJournalResult.Success)?.value?:return null
    val backup=(journal.get(b.source.sourceOperationId) as? OperationJournalResult.Success)?.value?:return null
    return WorkingDatabaseRestoreParents(c,check,backup)
}
internal class JournalWorkingDatabaseRestoreStatusPort(private val journal:OperationJournal,private val local:ManagementRestartLocalPort,
    private val comparisons:RestoreCompatibilityStatusPort,private val registry:WorkingDatabaseRestoreResultRegistry,private val now:()->Instant=Instant::now):WorkingDatabaseRestoreStatusPort{
    override suspend fun source(server:String,installation:String,access:String,source:String):WorkingDatabaseRestoreSourceReview?{
        if(listOf(server,installation,access,source).any{it.isBlank()})return null
        val r=ready(server,installation,access)?:return null;val p=workingDatabaseRestoreParents(journal,OperationId(source))?:return null
        if(p.comparison.snapshot.operationId.value!=source || !WorkingDatabaseRestoreBindingPolicy.parentMatches(p.comparison,p.check,p.backup,r.installation,r.access))return null
        val b=RestoreCompatibilityBinding.parse(p.comparison.snapshot.checkpoint.phaseName)!!.second
        val o=comparisons.read(server,installation,access,source)
        val report=o?.report?.takeIf{it.scope==ManagementScope(p.comparison.snapshot.operationId,r.installation.serverId,r.access.id,r.installation.id) && it.binding==b}
        if(ready(server,installation,access)!=r || workingDatabaseRestoreParents(journal,p.comparison.snapshot.operationId)!=p)return null
        return WorkingDatabaseRestoreSourceReview(source,p.comparison.revision.value,b,report,report?.let{WorkingDatabaseRestoreConfirmationPolicy.eligible(it,p.comparison,now())}==true)
    }
    override suspend fun read(server:String,installation:String,access:String,operation:String):WorkingDatabaseRestoreObservation?{
        if(listOf(server,installation,access,operation).any{it.isBlank()})return null
        val r=ready(server,installation,access)?:return null;val c=get(OperationId(operation))?:return null
        val compensated=CompensatedPanelStartBinding.parse(c.snapshot.checkpoint.phaseName)
        if(compensated!=null){
            val parents=workingDatabaseRestoreParents(journal,compensated.second.returned.original.comparisonOperationId)?:return null
            if(c.snapshot.operationId.value!=operation || !CompensatedPanelStartPolicy.matches(c,compensated.second,r.installation,r.access,parents.comparison,parents.check,parents.backup) ||
                ready(server,installation,access)!=r || get(c.snapshot.operationId)!=c)return null
            return WorkingDatabaseRestoreObservation(operation,compensated.second.returned.original.comparisonOperationId.value,
                "После возврата базы запуск службы уже мог выполниться. Повторного запуска и записи базы нет. Откройте отдельную проверку службы и входа; барьер сохраняется.",false,mayStartReturnedPanel=true)
        }
        val returned=BeforeCopyReturnBinding.parse(c.snapshot.checkpoint.phaseName)
        if(returned!=null){
            val parents=workingDatabaseRestoreParents(journal,returned.second.original.comparisonOperationId)?:return null
            if(c.snapshot.operationId.value!=operation || !BeforeCopyReturnPolicy.matches(c,returned.second,r.installation,r.access,parents.comparison,parents.check,parents.backup) ||
                ready(server,installation,access)!=r || get(c.snapshot.operationId)!=c)return null
            return WorkingDatabaseRestoreObservation(operation,returned.second.original.comparisonOperationId.value,
                if(returned.first==BeforeCopyReturnPhase.READBACK_VERIFIED)"Журнал фиксирует проверку возврата прежней базы при остановленной службе. Текущее состояние не восстанавливается из записи; барьер сохраняется." else "Попытка возврата прежней базы могла выполниться. Повторной записи нет. Откройте отдельную проверку результата.",
                false,mayInspectBeforeCopy=true,mayReturnBeforeCopy=true,mayStartReturnedPanel=returned.first==BeforeCopyReturnPhase.READBACK_VERIFIED)
        }
        val parsed=WorkingDatabaseRestoreBinding.parse(c.snapshot.checkpoint.phaseName)?:return null;val b=parsed.second
        val p=workingDatabaseRestoreParents(journal,b.comparisonOperationId)?:return null
        if(c.snapshot.operationId.value!=operation || !WorkingDatabaseRestoreBindingPolicy.matches(c,r.installation,r.access,p.comparison,p.check,p.backup))return null
        val s=c.snapshot;val terminal=s.status in setOf(OperationStatus.SUCCEEDED,OperationStatus.FAILED,OperationStatus.CANCELLED)
        if(terminal!=(s.checkpoint.semantics==CheckpointSemantics.TERMINAL))return null
        val pending=s.status==OperationStatus.RUNNING && s.checkpoint.semantics==CheckpointSemantics.MUTATION_NOT_STARTED && parsed.first==WorkingDatabaseRestorePhase.PENDING
        val checking=!terminal && s.checkpoint.semantics in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT,CheckpointSemantics.POST_VERIFY_REQUIRED)
        if(!terminal && !pending && !checking)return null
        if(terminal && when(s.status){OperationStatus.SUCCEEDED->parsed.first!=WorkingDatabaseRestorePhase.VERIFIED;OperationStatus.FAILED->parsed.first!=WorkingDatabaseRestorePhase.FAILED;else->parsed.first!=WorkingDatabaseRestorePhase.CANCELLED})return null
        val done=registry.latest(s.operationId) as? WorkingDatabaseRestoreRuntimeResult.Completed
        val receipt=done?.takeIf{terminal && s.status==OperationStatus.SUCCEEDED && it.revision==c.revision && it.installation.value==r.installation &&
            it.access==r.access && it.receipt.binding==b && it.receipt.scope==ManagementScope(s.operationId,r.installation.serverId,r.access.id,r.installation.id)}?.receipt
        val text=when{
            receipt!=null->"Рабочая база восстановлена и проверена. Прежняя база сохранена отдельно. На момент проверки служба была остановлена; запуск и работа панели не подтверждены."
            terminal && s.status==OperationStatus.SUCCEEDED->"Журнал подтверждает завершённую проверку восстановления базы. Подробные наблюдения не сохранились; текущее состояние панели неизвестно."
            terminal && s.status==OperationStatus.CANCELLED->"Ожидающий запрос отменён до отправки изменения."
            terminal->"Рабочая база и служба не менялись: запрос не прошёл предварительную проверку. Сверка копии действует 5 минут; если она устарела, выполните новую сверку и повторите."
            checking->"Остановка службы и восстановление могли выполниться. Повторной записи не будет. Подтвердите отдельную проверку результата; панель может оставаться остановленной."
            else->"Запрос зарегистрирован, но отправка изменения не подтверждена. Подтверждение не восстанавливается после перезапуска; можно отменить запись."
        }
        if(ready(server,installation,access)!=r || get(s.operationId)!=c || workingDatabaseRestoreParents(journal,b.comparisonOperationId)!=p)return null
        return WorkingDatabaseRestoreObservation(operation,b.comparisonOperationId.value,text,terminal,checking,pending,receipt,terminal && s.status==OperationStatus.SUCCEEDED && parsed.first==WorkingDatabaseRestorePhase.VERIFIED,checking || (terminal && s.status==OperationStatus.SUCCEEDED),checking)
    }
    override suspend fun unfinished(server:String,installation:String,access:String,source:String):List<String>{
        if(source.isBlank())return emptyList();val r=ready(server,installation,access)?:return emptyList();val p=workingDatabaseRestoreParents(journal,OperationId(source))?:return emptyList()
        val all=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return emptyList()
        return all.filter{row->
            WorkingDatabaseRestoreBindingPolicy.matches(row,r.installation,r.access,p.comparison,p.check,p.backup) ||
                BeforeCopyReturnBinding.parse(row.snapshot.checkpoint.phaseName)?.second?.let{BeforeCopyReturnPolicy.matches(row,it,r.installation,r.access,p.comparison,p.check,p.backup)}==true ||
                CompensatedPanelStartBinding.parse(row.snapshot.checkpoint.phaseName)?.second?.let{CompensatedPanelStartPolicy.matches(row,it,r.installation,r.access,p.comparison,p.check,p.backup)}==true
        }.sortedByDescending{it.snapshot.startedAt}.take(20).map{it.snapshot.operationId.value}
    }
    override suspend fun registered(server:String,installation:String,access:String):List<WorkingDatabaseRestoreRegistered>?{
        val r=ready(server,installation,access)?:return null
        val all=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return null
        val rows=all.filter{row->val t=row.snapshot.target as? OperationTarget.InstallationTarget
            t!=null && t.serverId==r.installation.serverId && t.installationId==r.installation.id && t.serverAccessId==r.access.id &&
                (WorkingDatabaseRestoreBinding.parse(row.snapshot.checkpoint.phaseName)!=null || BeforeCopyReturnBinding.parse(row.snapshot.checkpoint.phaseName)!=null ||
                    CompensatedPanelStartBinding.parse(row.snapshot.checkpoint.phaseName)!=null)
        }.sortedByDescending{it.snapshot.startedAt}.take(20)
        val found=rows.mapNotNull{row->val id=row.snapshot.operationId.value
            read(server,installation,access,id)?.takeIf{!it.terminal && it.operationId==id}?.let{WorkingDatabaseRestoreRegistered(id,it.sourceOperationId,it.text)}}
        // An unfinished restored-panel start is reachable only through its verified parent restore record.
        val starts=all.filter{row->val t=row.snapshot.target as? OperationTarget.InstallationTarget
            t!=null && t.serverId==r.installation.serverId && t.installationId==r.installation.id && t.serverAccessId==r.access.id &&
                row.snapshot.type==OperationType.RESTORED_PANEL_START}.sortedByDescending{it.snapshot.startedAt}.take(20)
        val started=starts.mapNotNull{row->
            val b=RestoredPanelStartBinding.parse(row.snapshot.checkpoint.phaseName)?.second?:return@mapNotNull null
            val p=restoredPanelStartParents(journal,b.restoreOperationId)?:return@mapNotNull null
            if(!RestoredPanelStartBindingPolicy.matches(row,r.installation,r.access,p.restore,p.comparison,p.check,p.backup))return@mapNotNull null
            val id=p.restore.snapshot.operationId.value
            read(server,installation,access,id)?.takeIf{it.mayStartService && it.operationId==id}?.let{
                WorkingDatabaseRestoreRegistered(id,it.sourceOperationId,"Запуск панели после восстановления начат, но его результат не проверен. Откройте запись и перейдите к запуску, чтобы проверить службу.")}
        }.distinctBy{it.operationId}
        return if(ready(server,installation,access)!=r)null else (found+started).take(10)
    }
    private suspend fun ready(s:String,i:String,a:String)=(local.readExact(s,i,a) as? ManagementRestartLocalReview.Ready)?.review?.takeIf{it.matches(s,i,a)}
    private suspend fun get(id:OperationId)=(journal.get(id) as? OperationJournalResult.Success)?.value
}
internal class ProductionWorkingDatabaseRestoreActionPort(private val local:ManagementRestartLocalPort,private val journal:OperationJournal,
    private val statuses:WorkingDatabaseRestoreStatusPort,private val runtime:OperationRuntimeCoordinator,private val registry:WorkingDatabaseRestoreResultRegistry,
    private val host:suspend(OperationId)->ExactOperationHostStartResult,private val now:()->Instant=Instant::now,private val idFactory:()->OperationId={OperationId(UUID.randomUUID().toString())}):WorkingDatabaseRestoreActionPort{
    constructor(activity:Activity,local:ManagementRestartLocalPort,journal:OperationJournal,statuses:WorkingDatabaseRestoreStatusPort,runtime:OperationRuntimeCoordinator,registry:WorkingDatabaseRestoreResultRegistry):this(local,journal,statuses,runtime,registry,{VisibleExactOperationHostLauncher(activity).start(it)})
    override suspend fun startConfirmed(review:ManagementRestartReview,source:WorkingDatabaseRestoreSourceReview):WorkingDatabaseRestoreStart{
        if(!fresh(review) || !source.mayRestore || source.report==null || statuses.source(review.serverId,review.installationId,review.accessId,source.operationId)!=source)return blocked("Сверка устарела или цель изменилась. Выполните новую сверку.")
        val p=workingDatabaseRestoreParents(journal,OperationId(source.operationId))?:return blocked("Источник недоступен.")
        val all=(journal.listNonTerminal() as? OperationJournalResult.Success)?.value?:return blocked("Журнал недоступен.")
        if(DurableServerMutationBarrierPolicy.evaluate(review.installation.serverId,all.map{it.snapshot})!=ServerMutationBarrierDecision.Allowed || all.any{it.snapshot.type==OperationType.WORKING_DATABASE_RESTORE && it.snapshot.target.serverId==review.installation.serverId})return blocked("Есть незавершённая операция. Завершите её отдельно.")
        val id=idFactory();val b=try{WorkingDatabaseRestoreBindingPolicy.bind(id,review.installation,review.access,p.comparison,p.check,p.backup)}catch(_:IllegalArgumentException){return blocked("Точный источник не подтверждён.")}
        if(!fresh(review) || statuses.source(review.serverId,review.installationId,review.accessId,source.operationId)!=source)return blocked("Источник изменился.")
        val at=now();val created=(journal.create(OperationSnapshot(id,OperationType.WORKING_DATABASE_RESTORE,p.comparison.snapshot.target,OperationStatus.RUNNING,
            OperationCheckpoint(b.phaseName(WorkingDatabaseRestorePhase.PENDING),CheckpointSemantics.MUTATION_NOT_STARTED,at),at,at)) as? OperationJournalResult.Success)?.value?:return blocked("Журнал не принял запрос.")
        val confirmation=WorkingDatabaseRestoreConfirmationPolicy.confirm(created,review.installation,review.access,p.comparison,p.check,p.backup,source.report,now())
        if(confirmation==null || !runtime.registerWorkingDatabaseRestoreConfirmation(confirmation)){fail(created,b);return WorkingDatabaseRestoreStart.Recorded(id.value)}
        registry.begin(id)
        try{if(!fresh(review) || workingDatabaseRestoreParents(journal,p.comparison.snapshot.operationId)!=p || host(id)!=ExactOperationHostStartResult.START_REQUEST_ACCEPTED){runtime.discardWorkingDatabaseRestoreConfirmation(id);fail(created,b)}}catch(c:CancellationException){runtime.discardWorkingDatabaseRestoreConfirmation(id);withContext(NonCancellable){fail(created,b)};throw c}catch(_:Exception){runtime.discardWorkingDatabaseRestoreConfirmation(id);fail(created,b)}
        return WorkingDatabaseRestoreStart.Recorded(id.value)
    }
    override suspend fun checkConfirmed(review:ManagementRestartReview,source:WorkingDatabaseRestoreSourceReview,operation:String):String?{
        val c=exact(review,operation)?:return "Точная запись недоступна."
        if(WorkingDatabaseRestoreBinding.parse(c.snapshot.checkpoint.phaseName)?.second?.comparisonOperationId?.value!=source.operationId ||
            c.snapshot.checkpoint.semantics !in setOf(CheckpointSemantics.MUTATION_IN_FLIGHT,CheckpointSemantics.POST_VERIFY_REQUIRED))return "Начатое восстановление не найдено."
        registry.begin(c.snapshot.operationId)
        return if(host(c.snapshot.operationId)==ExactOperationHostStartResult.START_REQUEST_ACCEPTED)null else "Android не принял проверку. Повторной записи не будет."
    }
    override suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?{
        val c=exact(review,operation)?:return "Точная запись недоступна.";val b=WorkingDatabaseRestoreBinding.parse(c.snapshot.checkpoint.phaseName)?:return "Запись недоступна."
        if(c.snapshot.checkpoint.semantics!=CheckpointSemantics.MUTATION_NOT_STARTED || b.first!=WorkingDatabaseRestorePhase.PENDING || c.snapshot.status!=OperationStatus.RUNNING)return "Изменение могло начаться. Нужна проверка результата."
        val at=now();if(at.isBefore(c.snapshot.updatedAt))return "Время отмены не подтверждено."
        val next=c.snapshot.copy(status=OperationStatus.CANCELLED,checkpoint=OperationCheckpoint(b.second.phaseName(WorkingDatabaseRestorePhase.CANCELLED),CheckpointSemantics.TERMINAL,at),updatedAt=at)
        val done=journal.advance(c.snapshot.operationId,c.revision,next);runtime.discardWorkingDatabaseRestoreConfirmation(c.snapshot.operationId)
        return if(done is OperationJournalResult.Success)null else "Состояние изменилось. Обновите локальный статус."
    }
    private suspend fun exact(r:ManagementRestartReview,id:String):VersionedOperationSnapshot?{
        if(id.isBlank() || !fresh(r))return null;val c=(journal.get(OperationId(id)) as? OperationJournalResult.Success)?.value?:return null
        val b=WorkingDatabaseRestoreBinding.parse(c.snapshot.checkpoint.phaseName)?.second?:return null;val p=workingDatabaseRestoreParents(journal,b.comparisonOperationId)?:return null
        return c.takeIf{it.snapshot.operationId.value==id && WorkingDatabaseRestoreBindingPolicy.matches(it,r.installation,r.access,p.comparison,p.check,p.backup)}
    }
    private suspend fun fresh(r:ManagementRestartReview)=(local.readExact(r.serverId,r.installationId,r.accessId) as? ManagementRestartLocalReview.Ready)?.review==r
    private suspend fun fail(c:VersionedOperationSnapshot,b:WorkingDatabaseRestoreBinding){val at=now();if(at.isBefore(c.snapshot.updatedAt))return
        journal.advance(c.snapshot.operationId,c.revision,c.snapshot.copy(status=OperationStatus.FAILED,checkpoint=OperationCheckpoint(b.phaseName(WorkingDatabaseRestorePhase.FAILED),CheckpointSemantics.TERMINAL,at),updatedAt=at))}
    private fun blocked(text:String)=WorkingDatabaseRestoreStart.Blocked(text)
}
