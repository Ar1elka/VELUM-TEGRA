package com.velumtegra.xuimobile.management

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.velumtegra.xuimobile.core.model.*

@Composable
fun ManagementRestoreCompatibilityScreen(viewModel:ManagementRestoreCompatibilityViewModel,actions:RestoreCompatibilityActionPort,onBack:()->Unit){
    ManagementRestoreCompatibilityScreen(viewModel,actions,onBack,onRestore={})
}
@Composable
fun ManagementRestoreCompatibilityScreen(viewModel:ManagementRestoreCompatibilityViewModel,actions:RestoreCompatibilityActionPort,onBack:()->Unit,onRestore:(String)->Unit,readiness:(@Composable (RestoreCompatibilityObservation)->Unit)?=null){
    BackHandler(onBack=onBack);val state by viewModel.state.collectAsState();val owner=LocalLifecycleOwner.current
    DisposableEffect(owner,viewModel){val observer=LifecycleEventObserver{_,event->if(event==Lifecycle.Event.ON_START)viewModel.enterForeground();if(event==Lifecycle.Event.ON_STOP)viewModel.leaveForeground()}
        owner.lifecycle.addObserver(observer);onDispose{owner.lifecycle.removeObserver(observer);viewModel.leaveForeground()}}
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(18.dp).testTag("restore_comparison_root"),verticalArrangement=Arrangement.spacedBy(14.dp)){
        OutlinedButton(onClick=onBack,modifier=Modifier.testTag("restore_comparison_back")){Text("‹ Назад")}
        Text("Сверка с панелью",style=MaterialTheme.typography.headlineSmall,fontWeight=FontWeight.Bold)
        StepIntro(
            step="Восстановление · шаг 2 из 4",
            summary=DetailLine("Сравним копию с работающей панелью: версию, базу и файлы. Это только чтение, на сервере ничего не меняется.","restore_comparison_scope"),
            details=listOf(
                DetailLine("Восстановить базу можно, только если версия и структура базы в копии и на сервере совпадают."),
                DetailLine("Результат сверки действует 5 минут. После этого потребуется новая сверка перед восстановлением."),
                DetailLine("В копии могут быть более старые настройки и клиенты. «Подключения» ниже — это inbounds, а не клиенты."),
            ),
        )
        if(state.loading || state.busy)LinearProgressIndicator(Modifier.fillMaxWidth())
        state.review?.let{r->TargetLines(r.serverName,r.sshLabel,"restore_comparison_ssh")
            state.source?.let{src->Text("Версия в копии: "+src.binding.source.version)
                Button(onClick=viewModel::requestRead,enabled=!state.loading && !state.busy && (state.operationId==null || state.observation?.terminal==true),modifier=Modifier.fillMaxWidth().testTag("restore_comparison_read")){Text("Сверить")}
                TechDetails(listOf(DetailLine("SHA-256 копии: "+src.binding.archiveSha256,"restore_comparison_source_hash"),DetailLine("Архитектура: "+src.binding.source.architecture.name)))}}
        state.observation?.let{o->Card(Modifier.fillMaxWidth()){Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){
            Text(o.text,modifier=Modifier.testTag("restore_comparison_status"))
            o.report?.let{r->
                Text(if(r.prerequisitesMatch)"Копия подходит к этой панели" else "Есть различия",style=MaterialTheme.typography.titleMedium,fontWeight=FontWeight.Bold,modifier=Modifier.testTag("restore_comparison_summary"))
                Text("Версия: в копии ${r.binding.source.source.version}, на сервере ${r.currentVersion}",modifier=Modifier.testTag("restore_comparison_version"))
                Text("Структура базы: "+if(r.currentSchemaSha256==null || r.sourceSchemaSha256==null)"не проверена" else if(r.sameSchema)"совпадает" else "различается",modifier=Modifier.testTag("restore_comparison_schema"))
                Text("Файлы: "+when(r.fileSet){RestoreFileSetComparison.MATCH->"состав совпадает";RestoreFileSetComparison.DIFFERENT->"состав различается";RestoreFileSetComparison.UNAVAILABLE->"не проверены"}+(r.changedFiles?.let{", изменено: $it"}?:""),modifier=Modifier.testTag("restore_comparison_files"))
                Text("Подключения: в копии ${r.sourceInbounds?.toString()?:"?"}, на сервере ${r.currentInbounds?.toString()?:"?"}",modifier=Modifier.testTag("restore_comparison_counts"))
                Text("Панель сейчас: "+when(r.serviceState){ManagementServiceState.ACTIVE->"работает";ManagementServiceState.INACTIVE->"остановлена";ManagementServiceState.FAILED->"ошибка службы";else->"состояние неизвестно"})
                Text("Сверено "+humanTime(r.observedAt),style=MaterialTheme.typography.bodySmall,modifier=Modifier.testTag("restore_comparison_time"))
                if(!o.fresh)Text("Сверка устарела. Нажмите «Сверить» ещё раз.",color=MaterialTheme.colorScheme.error,modifier=Modifier.testTag("restore_comparison_stale"))
                if(o.fresh && com.velumtegra.xuimobile.core.domain.WorkingDatabaseRestoreConfirmationPolicy.structuralReady(r))Button(onClick={onRestore(o.operationId)},enabled=!state.loading && !state.busy,modifier=Modifier.fillMaxWidth().testTag("restore_comparison_working_db")){Text("Дальше: восстановить базу")}
                TechDetails(listOf(
                    DetailLine("Архитектура: в копии ${r.binding.source.source.architecture.name}, на сервере ${r.currentArchitecture.name}","restore_comparison_arch"),
                    DetailLine("Сохранённые параметры установки: "+when(r.baselineStatus){ManagementBaselineStatus.Matched->"совпадают";is ManagementBaselineStatus.Drift->"изменились";is ManagementBaselineStatus.Insufficient->"не проверены"}),
                ))
            }
            if(o.report!=null && o.terminal)readiness?.invoke(o)
            if(o.mayRetry)OutlinedButton(onClick=viewModel::requestRetry,enabled=!state.loading && !state.busy,modifier=Modifier.fillMaxWidth().testTag("restore_comparison_retry")){Text("Сверить ещё раз")}
            if(o.mayCancel)OutlinedButton(onClick={viewModel.cancelPending(actions)},enabled=!state.loading && !state.busy,modifier=Modifier.fillMaxWidth().testTag("restore_comparison_cancel")){Text("Отменить запрос")}
        }}}
        state.notice?.let{Text(it,modifier=Modifier.testTag("restore_comparison_notice"))}
        QuietRefresh(viewModel::refresh,!state.busy,"restore_comparison_refresh")
    }
    state.dialog?.let{AlertDialog(onDismissRequest=viewModel::dismiss,title={Text("Сверить копию с панелью?")},text={Column(Modifier.heightIn(max=380.dp).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(10.dp)){
        state.review?.let{Text(it.serverName+" · "+it.sshLabel)}
        Text("Приложение прочитает копию, пробную папку и работающую панель и сравнит версии, базу и файлы. На сервере ничего не изменится.",modifier=Modifier.testTag("restore_comparison_review_scope"))
        state.source?.let{Text("SHA-256: "+it.binding.archiveSha256.take(16)+"…",style=MaterialTheme.typography.bodySmall,modifier=Modifier.testTag("restore_comparison_review_hash"))}
    }},confirmButton={Button(onClick={viewModel.confirm(actions)},modifier=Modifier.testTag("restore_comparison_confirm")){Text("Сверить")}},dismissButton={OutlinedButton(onClick=viewModel::dismiss,modifier=Modifier.testTag("restore_comparison_dismiss")){Text("Отмена")}})}
}
