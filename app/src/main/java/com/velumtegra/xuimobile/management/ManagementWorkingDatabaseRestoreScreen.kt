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

@Composable
fun ManagementWorkingDatabaseRestoreScreen(viewModel:ManagementWorkingDatabaseRestoreViewModel,actions:WorkingDatabaseRestoreActionPort,onBack:()->Unit)=ManagementWorkingDatabaseRestoreScreen(viewModel,actions,onBack,null)
@Composable
fun ManagementWorkingDatabaseRestoreScreen(viewModel:ManagementWorkingDatabaseRestoreViewModel,actions:WorkingDatabaseRestoreActionPort,onBack:()->Unit,onStartService:((String)->Unit)?,onInspectBeforeCopy:((String)->Unit)?=null,onStartReturnedPanel:((String)->Unit)?=null){
    BackHandler(onBack=onBack);val state by viewModel.state.collectAsState();val owner=LocalLifecycleOwner.current
    var acknowledged by remember(state.dialog,state.source?.operationId,state.source?.revision){mutableStateOf(false)}
    DisposableEffect(owner,viewModel){val observer=LifecycleEventObserver{_,event->if(event==Lifecycle.Event.ON_START)viewModel.enterForeground();if(event==Lifecycle.Event.ON_STOP)viewModel.leaveForeground()}
        owner.lifecycle.addObserver(observer);onDispose{owner.lifecycle.removeObserver(observer);viewModel.leaveForeground()}}
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(18.dp).testTag("working_db_root"),verticalArrangement=Arrangement.spacedBy(14.dp)){
        OutlinedButton(onClick=onBack,modifier=Modifier.testTag("working_db_back")){Text("‹ Назад")}
        Text("Восстановление базы панели",style=MaterialTheme.typography.headlineSmall,fontWeight=FontWeight.Bold)
        StepIntro(
            step="Восстановление · шаг 3 из 4",
            summary=DetailLine("Заменим базу панели данными из копии. Панель будет остановлена, VPN может отключиться, а настройки и клиенты, добавленные после копии, пропадут.","working_db_consequence"),
            details=listOf(
                DetailLine("Работает только для той же версии панели: версия, структура базы и файлы должны совпасть с копией.","working_db_scope"),
                DetailLine("Сверка действует 5 минут. Если срок истёк, вернитесь на шаг 2 и выполните новую сверку.","working_db_comparison_expiry"),
                DetailLine("Текущая база перед заменой сохраняется в отдельной закрытой папке. После восстановления панель остаётся остановленной: запуск — следующий шаг.","working_db_stopped"),
                DetailLine("Файлы программы, сертификаты и ключи не меняются. Сохранённых прежних баз не больше 4, сами они не удаляются."),
            ),
        )
        if(state.loading || state.busy)LinearProgressIndicator(Modifier.fillMaxWidth())
        state.review?.let{r->TargetLines(r.serverName,r.sshLabel,"working_db_ssh")
            state.source?.let{src->Text("Версия в копии: "+src.binding.source.source.version)
                if(state.pinned)Text("Это уже начатое восстановление. Здесь можно только проверить его результат.",modifier=Modifier.testTag("working_db_pinned"))
                else if(!src.mayRestore)Text("Сначала вернитесь назад и заново сверьте копию с панелью: сверка устарела или нашла различия.",color=MaterialTheme.colorScheme.error,modifier=Modifier.testTag("working_db_needs_comparison"))
                if(!state.pinned)Button(onClick=viewModel::requestRestore,enabled=src.mayRestore && !state.loading && !state.busy && (state.operationId==null || state.observation?.terminal==true),modifier=Modifier.fillMaxWidth().testTag("working_db_restore")){Text("Восстановить базу")}
                TechDetails(listOf(DetailLine("SHA-256 копии: "+src.binding.source.archiveSha256,"working_db_source_hash"),DetailLine("Архитектура: "+src.binding.source.source.architecture.name)))}}
        state.observation?.let{o->Card(Modifier.fillMaxWidth()){Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){
            Text(o.text,modifier=Modifier.testTag("working_db_status"))
            o.receipt?.let{r->Text("База восстановлена и сверена с копией "+humanTime(r.verifiedAt)+". Панель остановлена.",modifier=Modifier.testTag("working_db_verified"))
                Text("Прежняя база сохранена: "+humanBytes(r.previousBytes),style=MaterialTheme.typography.bodySmall,modifier=Modifier.testTag("working_db_previous_size"))}
            if(o.mayCheck)Button(onClick=viewModel::requestCheck,enabled=!state.loading && !state.busy,modifier=Modifier.fillMaxWidth().testTag("working_db_check")){Text("Проверить результат")}
            if(o.mayStartService && onStartService!=null)Button(onClick={onStartService(o.operationId)},enabled=!state.loading && !state.busy,modifier=Modifier.fillMaxWidth().testTag("working_db_start_service")){Text("Дальше: запустить панель")}
            if(o.mayInspectBeforeCopy && onInspectBeforeCopy!=null)OutlinedButton(onClick={onInspectBeforeCopy(o.operationId)},enabled=!state.loading && !state.busy,modifier=Modifier.fillMaxWidth().testTag("working_db_before_copy")){Text("Откат: проверить прежнюю базу")}
            if(o.mayStartReturnedPanel && onStartReturnedPanel!=null)OutlinedButton(onClick={onStartReturnedPanel(o.operationId)},enabled=!state.loading && !state.busy,modifier=Modifier.fillMaxWidth().testTag("working_db_start_returned_panel")){Text("Откат: запустить панель с прежней базой")}
            if(o.mayCancel)OutlinedButton(onClick={viewModel.cancelPending(actions)},enabled=!state.loading && !state.busy,modifier=Modifier.fillMaxWidth().testTag("working_db_cancel")){Text("Отменить запрос")}
            o.receipt?.let{r->TechDetails(listOf(DetailLine("SHA-256 прежней базы: "+r.previousDatabaseSha256)))}
        }}}
        state.notice?.let{Text(it,modifier=Modifier.testTag("working_db_notice"))}
        QuietRefresh(viewModel::refresh,!state.busy,"working_db_refresh")
    }
    state.dialog?.let{mode->val writing=mode=="NEW"
        AlertDialog(onDismissRequest=viewModel::dismiss,title={Text(if(writing)"Восстановить базу из копии?" else "Проверить результат?")},text={Column(Modifier.heightIn(max=380.dp).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(10.dp)){
            state.review?.let{Text(it.serverName+" · "+it.sshLabel)}
            if(writing){Text("Панель будет остановлена, текущая база сохранена и заменена данными копии. Настройки и клиенты, добавленные после копии, пропадут; VPN может отключиться. Панель останется остановленной до следующего шага.",modifier=Modifier.testTag("working_db_review_consequence"))
                Row(verticalAlignment=androidx.compose.ui.Alignment.CenterVertically){Checkbox(checked=acknowledged,onCheckedChange={acknowledged=it},modifier=Modifier.testTag("working_db_ack"));Text("Понимаю, что панель остановится и данные заменятся")}}
            else Text("Приложение только прочитает результат и сохранённую прежнюю базу. На сервере ничего не изменится.",modifier=Modifier.testTag("working_db_review_readonly"))
            state.source?.let{Text("SHA-256 копии: "+it.binding.source.archiveSha256.take(16)+"…",style=MaterialTheme.typography.bodySmall,modifier=Modifier.testTag("working_db_review_hash"))}
        }},confirmButton={Button(onClick={viewModel.confirm(actions)},enabled=!writing || acknowledged,modifier=Modifier.testTag("working_db_confirm")){Text(if(writing)"Остановить и восстановить" else "Проверить")}},dismissButton={OutlinedButton(onClick=viewModel::dismiss,modifier=Modifier.testTag("working_db_dismiss")){Text("Отмена")}})
    }
}
