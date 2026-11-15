package com.velumtegra.xuimobile.management
import androidx.lifecycle.*
import androidx.savedstate.SavedStateRegistryOwner
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

data class KnownFileRestoreState(val loading:Boolean=true,val busy:Boolean=false,val review:KnownFileRestoreReview?=null,
    val dialog:Boolean=false,val result:KnownFileRestoreResult?=null,val notice:String?=null)
class ManagementKnownFileRestoreViewModel(private val saved:SavedStateHandle,private val server:String,private val installation:String,
    private val access:String,private val comparison:String,initial:RecoveryReadinessEvidence?,private val port:KnownFileRestorePort,
    private val now:()->Instant=Instant::now):ViewModel(){
    private val mutable=MutableStateFlow(KnownFileRestoreState());val state:StateFlow<KnownFileRestoreState> =mutable
    private var evidence=initial;private var foreground=false;private var generation=0L;private var job:Job?=null
    private fun current(g:Long)=foreground && generation==g
    private fun recent(at:Instant)=!now().isBefore(at) && now().isBefore(at.plusSeconds(90))
    private fun exact(r:KnownFileRestoreReview)=r.scope.serverId.value==server && r.scope.installationId.value==installation && r.scope.serverAccessId.value==access &&
        r.binding.comparisonOperationId.value==comparison && r.revision>=0 && recent(r.reviewedAt) &&
        (saved.get<String>("known_file_operation")?.let{it==r.scope.operationId.value && r.action!=KnownFileRestoreAction.APPLY}?:true)
    fun enterForeground(){if(foreground)return;foreground=true;refresh()}
    fun leaveForeground(){foreground=false;generation++;job?.cancel();mutable.value.review?.let(port::discard);evidence=null;mutable.value=KnownFileRestoreState()}
    fun refresh(){
        if(!foreground || mutable.value.busy)return
        job?.cancel();mutable.value.review?.let(port::discard);val g=++generation;mutable.value=KnownFileRestoreState()
        job=viewModelScope.launch{try{
            val r=port.review(server,installation,access,comparison,saved["known_file_operation"],evidence)
            if(!current(g)){r?.let(port::discard);return@launch}
            val checked=r?.takeIf(::exact);if(checked==null)r?.let(port::discard)
            if(checked?.action==KnownFileRestoreAction.READ)saved["known_file_operation"]=checked.scope.operationId.value
            mutable.value=KnownFileRestoreState(loading=false,review=checked,notice=if(checked==null)"Точный источник недоступен. Вернитесь к отдельной проверке условий; начатую запись нельзя повторять." else if(saved.get<String>("known_file_operation")!=null)"Согласие и наблюдения не восстановлены. Результат требует отдельного чтения." else null)
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=KnownFileRestoreState(loading=false,notice="Локальный источник недоступен.")}}
    }
    fun request(){val s=mutable.value;val r=s.review?:return
        if(foreground && !s.loading && !s.busy){if(!recent(r.reviewedAt)){refresh();return};mutable.value=s.copy(dialog=true,result=null)}}
    fun dismiss(){val s=mutable.value;val r=s.review;if(r?.action==KnownFileRestoreAction.RETURN){port.discard(r);mutable.value=s.copy(dialog=false,review=null)}else mutable.value=s.copy(dialog=false)}
    fun requestReturn(){val s=mutable.value;val p=(s.result as? KnownFileRestoreResult.Checked)?.takeIf{it.mayReturn}?.evidence?:return
        if(!foreground || s.busy || !recent(p.observedAt))return
        val g=++generation;job?.cancel();s.review?.let(port::discard);mutable.value=s.copy(busy=true,review=null)
        job=viewModelScope.launch{try{
            val r=port.review(server,installation,access,comparison,saved["known_file_operation"],null,p)
            if(!current(g)){r?.let(port::discard);return@launch}
            val checked=r?.takeIf{exact(it) && it.action==KnownFileRestoreAction.RETURN && it.scope==p.scope && it.binding==p.binding && it.returnManifest==p.beforeManifestSha256 && recent(p.observedAt)}
            if(checked==null)r?.let(port::discard)
            mutable.value=KnownFileRestoreState(loading=false,review=checked,dialog=checked!=null,notice=if(checked==null)"Нужна новая отдельная проверка результата." else null)
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=KnownFileRestoreState(loading=false,notice="Возврат не подготовлен. Нужна отдельная проверка.")}}
    }
    fun confirm(){val s=mutable.value;val r=s.review?:return
        if(!foreground || s.loading || s.busy || !s.dialog)return
        if(!recent(r.reviewedAt)){refresh();return}
        val g=++generation;mutable.value=s.copy(dialog=false,busy=true,review=null,result=null,notice=null)
        saved["known_file_operation"]=r.scope.operationId.value;evidence=null
        job=viewModelScope.launch{try{
            val raw=port.perform(r);if(!current(g))return@launch
            val result=when(raw){
                is KnownFileRestoreResult.Recorded->if(raw.operationId==r.scope.operationId.value)raw else KnownFileRestoreResult.Unavailable("Указатель операции не совпал.")
                is KnownFileRestoreResult.Checked->if(r.action==KnownFileRestoreAction.READ && raw.evidence.scope==r.scope && raw.evidence.binding==r.binding && !raw.evidence.observedAt.isBefore(r.reviewedAt) && recent(raw.evidence.observedAt))raw else KnownFileRestoreResult.Unavailable("Результат не совпал с источником или временем.")
                is KnownFileRestoreResult.Unavailable->raw
            }
            mutable.value=KnownFileRestoreState(loading=false,result=result)
            val proof=(result as? KnownFileRestoreResult.Checked)?.evidence
            if(proof!=null){delay(java.time.Duration.between(now(),proof.observedAt.plusSeconds(90)).toMillis().coerceIn(0,90_000));if(current(g))mutable.value=KnownFileRestoreState(loading=false,notice="Наблюдение устарело. Нужна отдельная проверка результата.")}
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=KnownFileRestoreState(loading=false,result=KnownFileRestoreResult.Unavailable("Исход не подтверждён. Нужна отдельная проверка; автоматического повтора нет."))}}
    }
    override fun onCleared(){leaveForeground();super.onCleared()}
}
class ManagementKnownFileRestoreViewModelFactory(owner:SavedStateRegistryOwner,private val server:String,private val installation:String,
    private val access:String,private val comparison:String,private val evidence:RecoveryReadinessEvidence?,private val port:KnownFileRestorePort):AbstractSavedStateViewModelFactory(owner,null){
    @Suppress("UNCHECKED_CAST")override fun<T:ViewModel>create(key:String,modelClass:Class<T>,handle:SavedStateHandle):T{
        require(modelClass==ManagementKnownFileRestoreViewModel::class.java)
        return ManagementKnownFileRestoreViewModel(handle,server,installation,access,comparison,evidence,port)as T
    }
}
