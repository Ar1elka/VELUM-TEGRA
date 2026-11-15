package com.velumtegra.xuimobile.management
import androidx.lifecycle.*
import androidx.savedstate.SavedStateRegistryOwner
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.domain.RecoveryReadinessPolicy
import java.time.Instant
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

data class RecoveryReadinessState(val loading:Boolean=true,val busy:Boolean=false,val review:RecoveryReadinessReview?=null,
    val dialog:Boolean=false,val result:RecoveryReadinessResult?=null,val notice:String?=null)
class ManagementRecoveryReadinessViewModel(private val saved:SavedStateHandle,private val scope:ManagementScope,
    private val port:RecoveryReadinessPort,private val now:()->Instant=Instant::now):ViewModel(){
    private val mutable=MutableStateFlow(RecoveryReadinessState());val state:StateFlow<RecoveryReadinessState> =mutable
    private var foreground=false;private var generation=0L;private var job:Job?=null
    private fun current(g:Long)=foreground && generation==g
    fun enterForeground(){if(foreground)return;foreground=true;refresh()}
    fun leaveForeground(){foreground=false;generation++;job?.cancel();mutable.value.review?.let(port::discard);mutable.value=RecoveryReadinessState()}
    fun refresh(){
        if(!foreground || mutable.value.busy)return
        job?.cancel();mutable.value.review?.let(port::discard);val g=++generation;mutable.value=RecoveryReadinessState()
        job=viewModelScope.launch{try{
            val r=port.review(scope)
            if(!current(g)){r?.let(port::discard);return@launch}
            val exact=r?.takeIf{it.scope==scope && it.revision>=0 && !now().isBefore(it.reviewedAt) && now().isBefore(it.reviewedAt.plusSeconds(90))}
            if(exact==null)r?.let(port::discard)
            mutable.value=RecoveryReadinessState(loading=false,review=exact,notice=if(exact==null)"Точная завершённая сверка недоступна или есть незавершённая операция." else if(saved.get<Boolean>("recovery_read_attempted")==true)"Предыдущие наблюдения и согласие не восстановлены. Новые данные требуют отдельного чтения." else null)
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=RecoveryReadinessState(loading=false,notice="Локальный источник недоступен.")}}
    }
    fun request(){val s=mutable.value;val r=s.review?:return
        if(foreground && !s.loading && !s.busy){if(now().isBefore(r.reviewedAt) || !now().isBefore(r.reviewedAt.plusSeconds(90))){refresh();return};mutable.value=s.copy(dialog=true,result=null)}}
    fun dismiss(){mutable.value=mutable.value.copy(dialog=false)}
    fun confirm(){val s=mutable.value;val r=s.review?:return
        if(!foreground || s.loading || s.busy || !s.dialog)return
        if(now().isBefore(r.reviewedAt) || !now().isBefore(r.reviewedAt.plusSeconds(90))){refresh();return}
        val g=++generation;mutable.value=s.copy(dialog=false,busy=true,review=null,result=null,notice=null);saved["recovery_read_attempted"]=true
        job=viewModelScope.launch{try{
            val result=port.read(r);if(!current(g))return@launch
            val checked=when(result){is RecoveryReadinessResult.Unavailable->result;is RecoveryReadinessResult.Observed->{val p=result.evidence
                if(p.scope==scope && p.binding==r.binding && p.comparisonRevision==r.revision && !p.observedAt.isBefore(r.reviewedAt) && RecoveryReadinessPolicy.fresh(p,now()))result
                else RecoveryReadinessResult.Unavailable("Результат не совпал с точным источником, ревизией или временем.")}}
            mutable.value=mutable.value.copy(busy=false,result=checked)
            val p=(checked as? RecoveryReadinessResult.Observed)?.evidence
            if(p!=null){val remaining=java.time.Duration.between(now(),p.observedAt.plusSeconds(90)).toMillis().coerceIn(0,90_000)
                delay(remaining);if(current(g))mutable.value=mutable.value.copy(result=null,notice="Наблюдение устарело. Обновите локальный источник и отдельно подтвердите новое чтение.")}
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=mutable.value.copy(busy=false,result=RecoveryReadinessResult.Unavailable("Чтение не подтверждено. Автоматического повтора нет."))}}
    }
    override fun onCleared(){leaveForeground();super.onCleared()}
}
class ManagementRecoveryReadinessViewModelFactory(owner:SavedStateRegistryOwner,private val scope:ManagementScope,private val port:RecoveryReadinessPort):AbstractSavedStateViewModelFactory(owner,null){
    @Suppress("UNCHECKED_CAST")override fun<T:ViewModel>create(key:String,modelClass:Class<T>,handle:SavedStateHandle):T{
        require(modelClass==ManagementRecoveryReadinessViewModel::class.java)
        return ManagementRecoveryReadinessViewModel(handle,scope,port)as T
    }
}
