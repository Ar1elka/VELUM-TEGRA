package com.velumtegra.xuimobile.management
import androidx.lifecycle.*
import androidx.savedstate.SavedStateRegistryOwner
import java.time.Instant
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

data class BeforeCopyState(val loading:Boolean=true,val busy:Boolean=false,val source:BeforeCopyReview?=null,
    val dialog:Boolean=false,val result:BeforeCopyResult?=null,val notice:String?=null)
class ManagementBeforeCopyEvidenceViewModel(private val saved:SavedStateHandle,private val server:String,private val installation:String,
    private val access:String,private val operation:String,private val port:BeforeCopyEvidencePort):ViewModel(){
    private val mutable=MutableStateFlow(BeforeCopyState());val state:StateFlow<BeforeCopyState> =mutable
    private var foreground=false;private var generation=0L;private var job:Job?=null
    private fun current(g:Long)=foreground && generation==g
    fun enterForeground(){foreground=true;refresh()}
    fun leaveForeground(){foreground=false;generation++;job?.cancel();mutable.value.source?.let(port::discard);mutable.value=BeforeCopyState()}
    fun refresh(){
        if(!foreground || mutable.value.busy)return
        job?.cancel();mutable.value.source?.let(port::discard);val g=++generation;mutable.value=BeforeCopyState()
        job=viewModelScope.launch{try{
            val r=port.review(server,installation,access,operation)
            if(!current(g)){r?.let(port::discard);return@launch}
            val exact=r?.takeIf{it.operationId==operation && it.revision>=0 && Regex("[0-9a-f]{64}").matches(it.digest)}
            if(exact==null)r?.let(port::discard)
            mutable.value=BeforeCopyState(loading=false,source=exact,notice=if(exact==null)"Точный источник T4.9 недоступен или ожидает другое действие." else if(saved.get<Boolean>("before_read_attempted")==true)"Предыдущий результат не восстанавливается. Новое чтение требует отдельного согласия." else null)
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=BeforeCopyState(loading=false,notice="Не удалось прочитать локальный источник.")}}
    }
    fun request(){val s=mutable.value;if(foreground && !s.loading && !s.busy && s.source!=null)mutable.value=s.copy(dialog=true,result=null)}
    fun dismiss(){mutable.value=mutable.value.copy(dialog=false)}
    fun confirm(){val s=mutable.value;val r=s.source?:return
        if(!foreground || s.busy || s.loading || !s.dialog)return
        val g=++generation;mutable.value=s.copy(dialog=false,busy=true,source=null,result=null,notice=null);saved["before_read_attempted"]=true
        job=viewModelScope.launch{try{
            val result=port.read(r)
            if(!current(g))return@launch
            val checked=when(result){is BeforeCopyResult.Unavailable->result;is BeforeCopyResult.Observed->{val p=result.evidence
                if(p.scope.operationId.value==operation && p.scope.serverId.value==server && p.scope.installationId.value==installation && p.scope.serverAccessId.value==access && p.binding.digest==r.digest &&
                    !p.observedAt.isBefore(r.reviewedAt) && !p.observedAt.isAfter(Instant.now().plusSeconds(5)))result else BeforeCopyResult.Unavailable("Результат не совпал с целью или временем.")}}
            mutable.value=mutable.value.copy(busy=false,result=checked)
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=mutable.value.copy(busy=false,result=BeforeCopyResult.Unavailable("Чтение не подтверждено. Автоматического повтора нет."))}}
    }
    override fun onCleared(){leaveForeground();super.onCleared()}
}
class ManagementBeforeCopyEvidenceViewModelFactory(owner:SavedStateRegistryOwner,private val server:String,private val installation:String,
    private val access:String,private val operation:String,private val port:BeforeCopyEvidencePort):AbstractSavedStateViewModelFactory(owner,null){
    @Suppress("UNCHECKED_CAST")override fun<T:ViewModel>create(key:String,modelClass:Class<T>,handle:SavedStateHandle):T{
        require(modelClass==ManagementBeforeCopyEvidenceViewModel::class.java)
        return ManagementBeforeCopyEvidenceViewModel(handle,server,installation,access,operation,port)as T
    }
}
