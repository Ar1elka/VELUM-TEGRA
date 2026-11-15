package com.velumtegra.xuimobile.management

import androidx.lifecycle.AbstractSavedStateViewModelFactory
import androidx.savedstate.SavedStateRegistryOwner
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

data class ManagementWorkingDatabaseRestoreState(val review:ManagementRestartReview?=null,val source:WorkingDatabaseRestoreSourceReview?=null,
    val loading:Boolean=true,val busy:Boolean=false,val dialog:String?=null,val operationId:String?=null,
    val observation:WorkingDatabaseRestoreObservation?=null,val notice:String?=null,val pinned:Boolean=false)
/** Only exact pointers survive process death. All foreground/poll reads are local. */
class ManagementWorkingDatabaseRestoreViewModel(private val saved:SavedStateHandle,private val server:String,private val installation:String,
    private val access:String,private val source:String,private val local:ManagementRestartLocalPort,private val statuses:WorkingDatabaseRestoreStatusPort,
    /** Exact registered record chosen from the backup screen. Never replaced, never allows a new restore. */
    private val pinned:String?=null):ViewModel(){
    private val restored=if(pinned!=null)pinned else saved.get<String>("wdb_operation")?.takeIf{it.isNotBlank() && saved.get<String>("wdb_server")==server &&
        saved.get<String>("wdb_installation")==installation && saved.get<String>("wdb_access")==access && saved.get<String>("wdb_source")==source}
    private val mutable=MutableStateFlow(ManagementWorkingDatabaseRestoreState(operationId=restored,pinned=pinned!=null,
        notice=if(pinned==null && saved.get<Boolean>("wdb_launch_pending")==true)"Передача предыдущего запроса не подтверждена. Автоматического повтора нет." else null))
    val state:StateFlow<ManagementWorkingDatabaseRestoreState> =mutable
    private var foreground=false;private var generation=0L;private var ticket=0L
    private var readJob:Job?=null;private var actionJob:Job?=null
    private var reviewed:Pair<ManagementRestartReview,WorkingDatabaseRestoreSourceReview>?=null
    fun enterForeground(){foreground=true;refresh()}
    fun leaveForeground(){foreground=false;generation++;ticket++;readJob?.cancel();actionJob?.cancel();reviewed=null
        mutable.value=mutable.value.copy(review=null,source=null,observation=null,loading=true,busy=false,dialog=null)}
    fun refresh(){
        if(!foreground || mutable.value.busy)return
        readJob?.cancel();reviewed=null;val g=++generation
        mutable.value=mutable.value.copy(loading=true,review=null,source=null,observation=null,dialog=null)
        readJob=viewModelScope.launch{try{
            val r=readLocal()?:run{invalidate(g);return@launch};val src=readSource()?:run{invalidate(g);return@launch}
            if(!current(g))return@launch
            if(readLocal()!=r){invalidate(g);return@launch};if(!current(g))return@launch
            var id=mutable.value.operationId
            if(pinned==null){val unfinished=statuses.unfinished(server,installation,access,source);if(!current(g))return@launch
                if(id==null && unfinished.isNotEmpty()){id=unfinished.first();save(id)}}
            val o=id?.let{statuses.read(server,installation,access,it)}?.takeIf{exact(it,id,src)}
            if(!current(g))return@launch
            if(readLocal()!=r || readSource()!=src){invalidate(g);return@launch};if(!current(g))return@launch
            mutable.value=mutable.value.copy(review=r,source=src,loading=false,operationId=id,observation=o,
                notice=if(pinned!=null && o==null)"Выбранная запись недоступна или её привязка изменилась. Другая запись не выбирается; вернитесь назад." else mutable.value.notice)
            if(id!=null && o?.terminal!=true)poll(id,r,src,g)
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))invalidate(g)}}
    }
    fun requestRestore(){request("NEW",pinned==null && mutable.value.source?.mayRestore==true && (mutable.value.operationId==null || mutable.value.observation?.terminal==true))}
    fun requestCheck(){request("CHECK",mutable.value.observation?.mayCheck==true)}
    private fun request(mode:String,allowed:Boolean){val s=mutable.value
        if(!foreground || s.loading || s.busy || !allowed || s.review==null || s.source==null)return
        reviewed=s.review to s.source;mutable.value=s.copy(dialog=mode)}
    fun dismiss(){reviewed=null;mutable.value=mutable.value.copy(dialog=null)}
    fun confirm(actions:WorkingDatabaseRestoreActionPort){val s=mutable.value;val mode=s.dialog?:return;val r=reviewed?:return
        if(!foreground || s.busy || s.loading || actionJob?.isActive==true)return
        if(pinned!=null && mode=="NEW")return
        val g=generation;val t=++ticket;reviewed=null;readJob?.cancel();mutable.value=s.copy(dialog=null,busy=true,notice=null);if(pinned==null)saved["wdb_launch_pending"]=true
        actionJob=viewModelScope.launch{try{
            if(readLocal()!=r.first || readSource()!=r.second){invalidate(g);return@launch};if(!current(g) || ticket!=t)return@launch
            var id=mutable.value.operationId
            val notice=if(mode=="NEW")when(val result=actions.startConfirmed(r.first,r.second)){
                is WorkingDatabaseRestoreStart.Recorded->if(result.operationId.isBlank())"Не удалось сохранить точный запрос." else {id=result.operationId;save(result.operationId);null}
                is WorkingDatabaseRestoreStart.Blocked->result.text
            }else if(id==null)"Точная запись недоступна." else actions.checkConfirmed(r.first,r.second,id)
            if(!current(g) || ticket!=t)return@launch;if(pinned==null)saved["wdb_launch_pending"]=false
            mutable.value=mutable.value.copy(busy=false,operationId=id,notice=notice)
            if(id!=null){val op=requireNotNull(id);readJob=viewModelScope.launch{poll(op,r.first,r.second,g)}}
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=mutable.value.copy(busy=false,notice="Передача не подтверждена. Обновите локальный статус; запрос не повторяется.")}}
    }
    fun cancelPending(actions:WorkingDatabaseRestoreActionPort){val s=mutable.value;val r=s.review?:return;val id=s.operationId?:return
        if(!foreground || s.loading || s.busy || s.observation?.mayCancel!=true)return
        val g=generation;readJob?.cancel();mutable.value=s.copy(busy=true)
        actionJob=viewModelScope.launch{try{val notice=if(readLocal()==r)actions.cancelPending(r,id)else"Цель изменилась."
            if(!current(g))return@launch;mutable.value=mutable.value.copy(busy=false,notice=notice);refresh()
        }catch(c:CancellationException){throw c}catch(_:Exception){if(current(g))mutable.value=mutable.value.copy(busy=false,notice="Отмена не подтверждена. Обновите статус.")}}
    }
    private suspend fun poll(id:String,r:ManagementRestartReview,src:WorkingDatabaseRestoreSourceReview,g:Long){repeat(160){
        val o=statuses.read(server,installation,access,id);if(!current(g))return
        if(readLocal()!=r || !sameSource(readSource(),src)){invalidate(g);return};if(!current(g))return
        val checked=o?.takeIf{exact(it,id,src)};mutable.value=mutable.value.copy(observation=checked,
            notice=if(checked==null)"Точная запись или исходная копия недоступна." else mutable.value.notice)
        if(checked==null || checked.terminal)return;delay(1000)
    }}
    private fun exact(o:WorkingDatabaseRestoreObservation,id:String?,src:WorkingDatabaseRestoreSourceReview):Boolean {
        if(o.operationId!=id || o.sourceOperationId!=source)return false
        val receipt=o.receipt?:return true
        return receipt.scope.operationId.value==id && receipt.scope.serverId.value==server && receipt.scope.installationId.value==installation &&
            receipt.scope.serverAccessId.value==access && receipt.binding.comparisonOperationId.value==src.operationId &&
            receipt.binding.comparisonRevision==src.revision && receipt.binding.comparison==src.binding
    }
    private fun sameSource(a:WorkingDatabaseRestoreSourceReview?,b:WorkingDatabaseRestoreSourceReview)=a!=null && a.operationId==b.operationId && a.revision==b.revision && a.binding==b.binding

    private suspend fun readLocal()=(local.readExact(server,installation,access) as? ManagementRestartLocalReview.Ready)?.review?.takeIf{it.matches(server,installation,access)}
    private suspend fun readSource()=statuses.source(server,installation,access,source)?.takeIf{it.operationId==source}
    private fun current(g:Long)=foreground && generation==g
    private fun invalidate(g:Long){if(!current(g))return;reviewed=null;mutable.value=mutable.value.copy(review=null,source=null,observation=null,loading=false,busy=false,dialog=null,notice="Установка, SSH-профиль или источник изменились. Выберите их заново.")}
    private fun save(id:String){if(pinned!=null)return;saved["wdb_operation"]=id;saved["wdb_server"]=server;saved["wdb_installation"]=installation;saved["wdb_access"]=access;saved["wdb_source"]=source}
    override fun onCleared(){foreground=false;generation++;ticket++;readJob?.cancel();actionJob?.cancel();super.onCleared()}
}
class ManagementWorkingDatabaseRestoreViewModelFactory(owner:SavedStateRegistryOwner,private val server:String,private val installation:String,
    private val access:String,private val source:String,private val local:ManagementRestartLocalPort,private val statuses:WorkingDatabaseRestoreStatusPort,
    private val pinned:String?=null):AbstractSavedStateViewModelFactory(owner,null){
    @Suppress("UNCHECKED_CAST") override fun<T:ViewModel>create(key:String,modelClass:Class<T>,handle:SavedStateHandle):T{
        require(modelClass==ManagementWorkingDatabaseRestoreViewModel::class.java)
        return ManagementWorkingDatabaseRestoreViewModel(handle,server,installation,access,source,local,statuses,pinned)as T
    }
}
