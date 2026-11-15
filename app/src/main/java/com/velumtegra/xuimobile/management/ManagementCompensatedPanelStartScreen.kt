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
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
@Composable
fun ManagementCompensatedPanelStartScreen(model:ManagementCompensatedPanelStartViewModel,onBack:()->Unit,onCheckLogin:((String)->Unit)?=null){
    val s by model.state.collectAsState();val owner=LocalLifecycleOwner.current
    var acknowledged by remember(s.dialog,s.source?.token){mutableStateOf(false)}
    BackHandler(onBack=onBack)
    DisposableEffect(owner,model){val o=LifecycleEventObserver{_,event->if(event==Lifecycle.Event.ON_START)model.enterForeground();if(event==Lifecycle.Event.ON_STOP)model.leaveForeground()};owner.lifecycle.addObserver(o);onDispose{owner.lifecycle.removeObserver(o);model.leaveForeground()}}
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(18.dp).testTag("compensated_start_root"),verticalArrangement=Arrangement.spacedBy(12.dp)){
        OutlinedButton(onClick=onBack,modifier=Modifier.testTag("compensated_start_back")){Text("‹ Назад")}
        Text("Запуск с прежней базой",style=MaterialTheme.typography.headlineSmall,fontWeight=androidx.compose.ui.text.font.FontWeight.Bold)
        StepIntro(
            step="Откат восстановления · шаг 3 из 3",
            summary=DetailLine("Запустим панель после возврата прежней базы. Она снова начнёт принимать подключения.","compensated_start_consequence"),
            details=listOf(
                DetailLine("Команда запуска отправляется один раз. Уже начатый запуск можно только проверить.","compensated_start_scope"),
                DetailLine("Если связь оборвётся, приложение не повторит команду и не остановит панель само. Вход в панель проверяется отдельно.","compensated_start_limits"),
            ),
        )
        if(s.loading || s.busy)LinearProgressIndicator(Modifier.fillMaxWidth())
        s.source?.let{r->
            TargetLines(r.serverLabel,r.sshLabel,"compensated_start_ssh")
            Button(onClick=model::request,enabled=!s.loading && !s.busy,modifier=Modifier.fillMaxWidth().testTag("compensated_start_action")){Text(if(r.action==CompensatedPanelStartAction.START_ONCE)"Запустить панель" else "Проверить панель")}
            TechDetails(listOf(DetailLine("SHA-256 прежней базы: "+r.binding.returned.beforeDatabaseSha256,"compensated_start_source_hash"),DetailLine("Запрос: "+r.operationId+" · ревизия "+r.revision)))
        }
        when(val r=s.result){
            is CompensatedPanelStartResult.Recorded->Text("Команда запуска отправлена. Нажмите «Обновить», затем проверьте панель: сама отправка ещё не подтверждает, что она работает.",modifier=Modifier.testTag("compensated_start_recorded"))
            is CompensatedPanelStartResult.Checked->Card(Modifier.fillMaxWidth()){Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
                Text("Панель работает · проверено "+humanTime(r.receipt.observedAt),fontWeight=androidx.compose.ui.text.font.FontWeight.Bold,modifier=Modifier.testTag("compensated_start_checked"))
                Text("Версия, структура базы и файлы совпали с ожидаемыми. Подключений в базе: ${r.receipt.inbounds}.")
                if(onCheckLogin!=null)Button(onClick={onCheckLogin(r.receipt.scope.operationId.value)},modifier=Modifier.fillMaxWidth().testTag("compensated_start_check_login")){Text("Проверить вход в панель")}
            }}
            is CompensatedPanelStartResult.Unavailable->Text(r.message,color=MaterialTheme.colorScheme.error,modifier=Modifier.testTag("compensated_start_unavailable"))
            null->Unit
        }
        s.notice?.let{Text(it,modifier=Modifier.testTag("compensated_start_notice"))}
        QuietRefresh(model::refresh,!s.busy,"compensated_start_refresh")
    }
    if(s.dialog)AlertDialog(onDismissRequest=model::dismiss,title={Text(if(s.source?.action==CompensatedPanelStartAction.START_ONCE)"Запустить панель с прежней базой?" else "Проверить панель?")},text={Column(Modifier.heightIn(max=380.dp).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(10.dp)){
        s.source?.let{Text(it.serverLabel+" · "+it.sshLabel)
            Text(if(it.action==CompensatedPanelStartAction.START_ONCE)"Приложение ещё раз проверит возврат базы и отправит одну команду запуска. При ошибке повтора не будет." else "Приложение только прочитает состояние панели, базу и файлы. Панель не перезапускается.")}
        Row(verticalAlignment=androidx.compose.ui.Alignment.CenterVertically){Checkbox(checked=acknowledged,onCheckedChange={acknowledged=it},modifier=Modifier.testTag("compensated_start_ack"));Text(if(s.source?.action==CompensatedPanelStartAction.START_ONCE)"Понимаю, запустить панель" else "Подключиться и прочитать")}
    }},confirmButton={Button(onClick=model::confirm,enabled=acknowledged,modifier=Modifier.testTag("compensated_start_confirm")){Text(if(s.source?.action==CompensatedPanelStartAction.START_ONCE)"Запустить" else "Проверить")}},dismissButton={OutlinedButton(onClick=model::dismiss,modifier=Modifier.testTag("compensated_start_dismiss")){Text("Отмена")}})
}
