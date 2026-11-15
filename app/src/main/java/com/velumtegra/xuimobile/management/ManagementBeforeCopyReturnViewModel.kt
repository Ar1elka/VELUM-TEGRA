package com.velumtegra.xuimobile.management
import androidx.lifecycle.*
import androidx.savedstate.SavedStateRegistryOwner
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
data class BeforeCopyReturnState(val loading:Boolean=true,val busy:Boolean=false,val source:BeforeCopyReturnReview?=null,
    val dialog:Boolean=false,val result:BeforeCopyReturnResult?=null,val notice:String?=null)
class ManagementBeforeCopyReturnViewModel(private val saved:SavedStateHandle,private val server:String,private val installation:String,
    private val access:String,private val operation:String,private val evidence:BeforeCopyEvidence?,private val port:BeforeCopyReturnPort):ViewModel(){
    private val mutable=MutableStateFlow(BeforeCopyReturnState());val state:StateFlow<BeforeCopyReturnState> =mutable
    private var foreground=false;private var generation=0L;private var job:Job?=null
    private fun current(g:Long)=foreground && generation==g
    fun enterForeground(){foreground=true;refresh()}
    fun leaveForeground(){foreground=false;generation++;job?.cancel();mutable.value.source?.let(port::discard);mutable.value=BeforeCopyReturnState()}
    fun refresh(){
        if(!foreground || mutable.value.busy)return
        job?.cancel();mutable.value.source?.let(port::discard);val g=++generation;mutable.value=BeforeCopyReturnState()
        job=viewModelScope.launch{try{
            val r=port.review(server,installation,access,operation,evidence)
            if(!current(g)){r?.let(port::discard);return@launch}
            val exact=r?.takeIf{it.operationId==operation && it.revision>=0}
            if(exact==null)r?.let(port::discard)
            mutable.value=BeforeCopyReturnState(loading=false,source=exact,notice=if(exact==null)"Возврат недоступен. Нужна свежая проверка прежней копии для точного незавершённого восстановления: остановленная служба, совпадающие файлы/структура и отличающаяся текущая база. Завершённые операции здесь не открываются заново." else if(saved.get<Boolean>("before_return_attempted")==true)"Предыдущая попытка не повторяется. После контрольной точки доступна только отдельная проверка результата." else null)
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=BeforeCopyReturnState(loading=false,notice="Локальная запись недоступна.")}}
    }
    fun request(){val s=mutable.value;if(foreground && !s.loading && !s.busy && s.source!=null)mutable.value=s.copy(dialog=true,result=null)}
    fun dismiss(){mutable.value=mutable.value.copy(dialog=false)}
    fun confirm(){val s=mutable.value;val r=s.source?:return
        if(!foreground || s.busy || s.loading || !s.dialog)return
        val g=++generation;mutable.value=s.copy(dialog=false,busy=true,source=null,result=null,notice=null);saved["before_return_attempted"]=true
        job=viewModelScope.launch{try{
            val result=port.perform(r);if(!current(g))return@launch
            val checked=if(result is BeforeCopyReturnResult.Checked){val p=result.receipt
                if(r.action==BeforeCopyReturnAction.READ_RESULT && p.binding==r.binding && p.scope==ManagementScope(OperationId(operation),ServerId(server),ServerAccessId(access),XuiInstallationId(installation)) &&
                    !p.verifiedAt.isBefore(r.reviewedAt) && !p.verifiedAt.isAfter(Instant.now().plusSeconds(5)))result else BeforeCopyReturnResult.Unavailable("Результат не совпал с точной целью или временем.")
            }else if(result is BeforeCopyReturnResult.Recorded && (r.action!=BeforeCopyReturnAction.RETURN_ONCE || result.operationId!=operation))BeforeCopyReturnResult.Unavailable("Точная попытка не подтверждена.")else result
            mutable.value=mutable.value.copy(busy=false,result=checked)
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=mutable.value.copy(busy=false,result=BeforeCopyReturnResult.Unavailable("Исход неизвестен. Автоматического повтора нет; обновите локальную запись и отдельно проверьте результат."))}}
    }
    override fun onCleared(){leaveForeground();super.onCleared()}
}
class ManagementBeforeCopyReturnViewModelFactory(owner:SavedStateRegistryOwner,private val server:String,private val installation:String,
    private val access:String,private val operation:String,private val evidence:BeforeCopyEvidence?,private val port:BeforeCopyReturnPort):AbstractSavedStateViewModelFactory(owner,null){
    @Suppress("UNCHECKED_CAST")override fun<T:ViewModel>create(key:String,modelClass:Class<T>,handle:SavedStateHandle):T{
        require(modelClass==ManagementBeforeCopyReturnViewModel::class.java)
        return ManagementBeforeCopyReturnViewModel(handle,server,installation,access,operation,evidence,port)as T
    }
}
