package com.velumtegra.xuimobile.management
import androidx.lifecycle.*
import androidx.savedstate.SavedStateRegistryOwner
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
data class CompensatedPanelStartState(val loading:Boolean=true,val busy:Boolean=false,val source:CompensatedPanelStartReview?=null,
    val dialog:Boolean=false,val result:CompensatedPanelStartResult?=null,val notice:String?=null)
class ManagementCompensatedPanelStartViewModel(private val saved:SavedStateHandle,private val server:String,private val installation:String,
    private val access:String,private val operation:String,private val port:CompensatedPanelStartPort):ViewModel(){
    private val mutable=MutableStateFlow(CompensatedPanelStartState());val state:StateFlow<CompensatedPanelStartState> =mutable
    private var foreground=false;private var generation=0L;private var job:Job?=null
    private fun current(g:Long)=foreground && generation==g
    fun enterForeground(){foreground=true;refresh()}
    fun leaveForeground(){foreground=false;generation++;job?.cancel();mutable.value.source?.let(port::discard);mutable.value=CompensatedPanelStartState()}
    fun refresh(){
        if(!foreground || mutable.value.busy)return
        job?.cancel();mutable.value.source?.let(port::discard);val g=++generation;mutable.value=CompensatedPanelStartState()
        job=viewModelScope.launch{try{
            val r=port.review(server,installation,access,operation)
            if(!current(g)){r?.let(port::discard);return@launch}
            val exact=r?.takeIf{it.operationId==operation && it.revision>=0}
            if(exact==null)r?.let(port::discard)
            mutable.value=CompensatedPanelStartState(loading=false,source=exact,notice=if(exact==null)"Запуск недоступен. Сначала отдельно проверьте завершённый возврат прежней базы. Неполный результат возврата и завершённые исходные операции не дают разрешения на запуск." else if(saved.get<Boolean>("compensated_start_attempted")==true)"Предыдущий запуск не повторяется. После контрольной точки доступна отдельная проверка службы. Данные наблюдений после перезапуска не восстанавливаются." else null)
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=CompensatedPanelStartState(loading=false,notice="Локальная запись недоступна.")}}
    }
    fun request(){val s=mutable.value;if(foreground && !s.loading && !s.busy && s.source!=null)mutable.value=s.copy(dialog=true,result=null)}
    fun dismiss(){mutable.value=mutable.value.copy(dialog=false)}
    fun confirm(){val s=mutable.value;val r=s.source?:return
        if(!foreground || s.busy || s.loading || !s.dialog)return
        val g=++generation;mutable.value=s.copy(dialog=false,busy=true,source=null,result=null,notice=null);saved["compensated_start_attempted"]=true
        job=viewModelScope.launch{try{
            val result=port.perform(r);if(!current(g))return@launch
            val checked=if(result is CompensatedPanelStartResult.Checked){val p=result.receipt
                if(r.action==CompensatedPanelStartAction.READ_RESULT && p.binding==r.binding && p.scope==ManagementScope(OperationId(operation),ServerId(server),ServerAccessId(access),XuiInstallationId(installation)) &&
                    !p.observedAt.isBefore(r.reviewedAt) && !p.observedAt.isAfter(Instant.now().plusSeconds(5)))result else CompensatedPanelStartResult.Unavailable("Результат не совпал с точной целью или временем.")
            }else if(result is CompensatedPanelStartResult.Recorded && (r.action!=CompensatedPanelStartAction.START_ONCE || result.operationId!=operation))CompensatedPanelStartResult.Unavailable("Точная попытка не подтверждена.")else result
            mutable.value=mutable.value.copy(busy=false,result=checked)
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=mutable.value.copy(busy=false,result=CompensatedPanelStartResult.Unavailable("Исход неизвестен. Автоматического повтора нет; обновите локальную запись и отдельно проверьте результат."))}}
    }
    override fun onCleared(){leaveForeground();super.onCleared()}
}
class ManagementCompensatedPanelStartViewModelFactory(owner:SavedStateRegistryOwner,private val server:String,private val installation:String,
    private val access:String,private val operation:String,private val port:CompensatedPanelStartPort):AbstractSavedStateViewModelFactory(owner,null){
    @Suppress("UNCHECKED_CAST")override fun<T:ViewModel>create(key:String,modelClass:Class<T>,handle:SavedStateHandle):T{
        require(modelClass==ManagementCompensatedPanelStartViewModel::class.java)
        return ManagementCompensatedPanelStartViewModel(handle,server,installation,access,operation,port)as T
    }
}
