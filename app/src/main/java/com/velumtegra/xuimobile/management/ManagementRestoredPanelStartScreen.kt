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
fun ManagementRestoredPanelStartScreen(viewModel:ManagementRestoredPanelStartViewModel,actions:RestoredPanelStartActionPort,onBack:()->Unit,onWebPanels:()->Unit={},onCheckLogin:((String)->Unit)?=null){
    BackHandler(onBack=onBack);val state by viewModel.state.collectAsState();val owner=LocalLifecycleOwner.current
    var acknowledged by remember(state.dialog,state.source?.operationId,state.source?.revision){mutableStateOf(false)}
    DisposableEffect(owner,viewModel){val observer=LifecycleEventObserver{_,event->if(event==Lifecycle.Event.ON_START)viewModel.enterForeground();if(event==Lifecycle.Event.ON_STOP)viewModel.leaveForeground()}
        owner.lifecycle.addObserver(observer);onDispose{owner.lifecycle.removeObserver(observer);viewModel.leaveForeground()}}
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(18.dp).testTag("restored_start_root"),verticalArrangement=Arrangement.spacedBy(14.dp)){
        OutlinedButton(onClick=onBack,modifier=Modifier.testTag("restored_start_back")){Text("‹ Назад")}
        Text("Запуск после восстановления",style=MaterialTheme.typography.headlineSmall,fontWeight=FontWeight.Bold)
        StepIntro(
            step="Восстановление · шаг 4 из 4",
            summary=DetailLine("Запустим панель с восстановленной базой. Она начнёт работать с настройками и клиентами из копии, VPN-подключения возобновятся.","restored_start_consequence"),
            details=listOf(
                DetailLine("Перед запуском приложение ещё раз проверит копию, базу, файлы и то, что панель остановлена.","restored_start_scope"),
                DetailLine("Если связь оборвётся во время запуска, приложение не повторит команду само. Результат нужно будет проверить отдельно.","restored_start_no_replay"),
                DetailLine("Работающая служба ещё не значит, что в панель можно войти. Вход проверяется после запуска.","restored_start_not_login"),
            ),
        )
        if(state.loading || state.busy)LinearProgressIndicator(Modifier.fillMaxWidth())
        state.review?.let{r->TargetLines(r.serverName,r.sshLabel,"restored_start_ssh")
            state.source?.let{src->Text("Версия в копии: "+src.binding.source.source.version)
                Button(onClick=viewModel::requestStart,enabled=src.mayStart && !state.loading && !state.busy && state.operationId==null,modifier=Modifier.fillMaxWidth().testTag("restored_start_start")){Text("Запустить панель")}
                TechDetails(listOf(DetailLine("SHA-256 копии: "+src.binding.source.archiveSha256,"restored_start_source_hash")))}}
        state.observation?.let{o->Card(Modifier.fillMaxWidth()){Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){
            Text(o.text,modifier=Modifier.testTag("restored_start_status"))
            o.receipt?.let{r->Text("Панель работает · версия ${r.version} · проверено "+humanTime(r.observedAt),fontWeight=FontWeight.Bold,modifier=Modifier.testTag("restored_start_verified"))
                Text("Подключений в базе: ${r.inbounds}",modifier=Modifier.testTag("restored_start_inbounds"))}
            if(o.mayCheck)Button(onClick=viewModel::requestCheck,enabled=!state.loading && !state.busy,modifier=Modifier.fillMaxWidth().testTag("restored_start_check")){Text("Проверить результат")}
            if(o.mayCheckLogin && onCheckLogin!=null)Button(onClick={onCheckLogin(o.operationId)},enabled=!state.busy && !state.loading,modifier=Modifier.fillMaxWidth().testTag("restored_start_login_check")){Text("Проверить вход в панель")}
            if(o.receipt!=null)OutlinedButton(onClick=onWebPanels,modifier=Modifier.fillMaxWidth().testTag("restored_start_webpanels")){Text("Открыть веб-панели")}
            if(o.mayCancel)OutlinedButton(onClick={viewModel.cancelPending(actions)},enabled=!state.loading && !state.busy,modifier=Modifier.fillMaxWidth().testTag("restored_start_cancel")){Text("Отменить запрос")}
        }}}
        state.notice?.let{Text(it,modifier=Modifier.testTag("restored_start_notice"))}
        QuietRefresh(viewModel::refresh,!state.busy,"restored_start_refresh")
    }
    state.dialog?.let{mode->val writing=mode=="NEW"
        AlertDialog(onDismissRequest=viewModel::dismiss,title={Text(if(writing)"Запустить восстановленную панель?" else "Проверить службу?")},text={Column(Modifier.heightIn(max=380.dp).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(10.dp)){
            state.review?.let{Text(it.serverName+" · "+it.sshLabel)}
            if(writing){Text("Панель запустится с настройками и клиентами из копии. Её порты снова откроются, VPN-подключения возобновятся.",modifier=Modifier.testTag("restored_start_review_consequence"))
                Row(verticalAlignment=androidx.compose.ui.Alignment.CenterVertically){Checkbox(checked=acknowledged,onCheckedChange={acknowledged=it},modifier=Modifier.testTag("restored_start_ack"));Text("Понимаю, запустить с данными из копии")}}
            else Text("Приложение только прочитает состояние службы, версию и базу. Панель не перезапускается, на сервере ничего не меняется.",modifier=Modifier.testTag("restored_start_review_readonly"))
            state.source?.let{Text("SHA-256 копии: "+it.binding.source.archiveSha256.take(16)+"…",style=MaterialTheme.typography.bodySmall,modifier=Modifier.testTag("restored_start_review_hash"))}
        }},confirmButton={Button(onClick={viewModel.confirm(actions)},enabled=!writing || acknowledged,modifier=Modifier.testTag("restored_start_confirm")){Text(if(writing)"Запустить" else "Проверить")}},dismissButton={OutlinedButton(onClick=viewModel::dismiss,modifier=Modifier.testTag("restored_start_dismiss")){Text("Отмена")}})
    }
}
