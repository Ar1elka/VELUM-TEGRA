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
fun ManagementBeforeCopyReturnScreen(model:ManagementBeforeCopyReturnViewModel,onBack:()->Unit){
    val s by model.state.collectAsState();val owner=LocalLifecycleOwner.current
    var acknowledged by remember(s.dialog,s.source?.token){mutableStateOf(false)}
    BackHandler(onBack=onBack)
    DisposableEffect(owner,model){val o=LifecycleEventObserver{_,event->if(event==Lifecycle.Event.ON_START)model.enterForeground();if(event==Lifecycle.Event.ON_STOP)model.leaveForeground()};owner.lifecycle.addObserver(o);onDispose{owner.lifecycle.removeObserver(o);model.leaveForeground()}}
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(18.dp).testTag("before_return_root"),verticalArrangement=Arrangement.spacedBy(12.dp)){
        OutlinedButton(onClick=onBack,modifier=Modifier.testTag("before_return_back")){Text("‹ Назад")}
        Text("Вернуть прежнюю базу",style=MaterialTheme.typography.headlineSmall,fontWeight=androidx.compose.ui.text.font.FontWeight.Bold)
        StepIntro(
            step="Откат восстановления · шаг 2 из 3",
            summary=DetailLine("Вернём базу, которая была до восстановления. Нынешняя база сохранится отдельно; всё, что появилось в ней после той копии, перестанет действовать.","before_return_consequence"),
            details=listOf(
                DetailLine("Доступно, только если восстановление не завершилось как надо и панель остановлена.","before_return_scope"),
                DetailLine("Возврат выполняется один раз. Панель остаётся остановленной: запуск — следующий шаг. Файлы программы не меняются.","before_return_limits"),
            ),
        )
        if(s.loading || s.busy)LinearProgressIndicator(Modifier.fillMaxWidth())
        s.source?.let{r->
            TargetLines(r.serverLabel,r.sshLabel,"before_return_ssh")
            Button(onClick=model::request,enabled=!s.loading && !s.busy,modifier=Modifier.fillMaxWidth().testTag("before_return_action")){Text(if(r.action==BeforeCopyReturnAction.RETURN_ONCE)"Вернуть прежнюю базу" else "Проверить результат возврата")}
            TechDetails(listOf(DetailLine("SHA-256 прежней базы: "+r.binding.beforeDatabaseSha256,"before_return_source_hash"),DetailLine("Запрос: "+r.operationId+" · ревизия "+r.revision)))
        }
        when(val r=s.result){
            is BeforeCopyReturnResult.Recorded->Text("Команда отправлена. Нажмите «Обновить», затем проверьте результат: сама отправка ещё не подтверждает возврат.",modifier=Modifier.testTag("before_return_recorded"))
            is BeforeCopyReturnResult.Checked->Card(Modifier.fillMaxWidth()){Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
                Text("Прежняя база возвращена и проверена "+humanTime(r.receipt.verifiedAt)+". Панель остановлена.",fontWeight=androidx.compose.ui.text.font.FontWeight.Bold,modifier=Modifier.testTag("before_return_checked"))
                Text("Заменённая база сохранена: "+humanBytes(r.receipt.displacedBytes),style=MaterialTheme.typography.bodySmall)
                TechDetails(listOf(DetailLine("SHA-256 заменённой базы: "+r.receipt.displacedDatabaseSha256,"before_return_displaced")))
            }}
            is BeforeCopyReturnResult.Unavailable->Text(r.message,color=MaterialTheme.colorScheme.error,modifier=Modifier.testTag("before_return_unavailable"))
            null->Unit
        }
        s.notice?.let{Text(it,modifier=Modifier.testTag("before_return_notice"))}
        QuietRefresh(model::refresh,!s.busy,"before_return_refresh")
    }
    if(s.dialog)AlertDialog(onDismissRequest=model::dismiss,title={Text(if(s.source?.action==BeforeCopyReturnAction.RETURN_ONCE)"Вернуть прежнюю базу?" else "Проверить результат возврата?")},text={Column(Modifier.heightIn(max=380.dp).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(10.dp)){
        s.source?.let{Text(it.serverLabel+" · "+it.sshLabel)
            Text(if(it.action==BeforeCopyReturnAction.RETURN_ONCE)"Нынешняя база будет сохранена отдельно и заменена прежней. Если связь оборвётся, результат нужно будет проверить отдельно. Панель не запускается." else "Приложение только прочитает базу и записи о возврате. На сервере ничего не изменится.")
            Text("SHA-256: "+it.binding.beforeDatabaseSha256.take(16)+"…",style=MaterialTheme.typography.bodySmall)}
        Row(verticalAlignment=androidx.compose.ui.Alignment.CenterVertically){Checkbox(checked=acknowledged,onCheckedChange={acknowledged=it},modifier=Modifier.testTag("before_return_ack"));Text(if(s.source?.action==BeforeCopyReturnAction.RETURN_ONCE)"Понимаю, что база будет заменена" else "Подключиться и прочитать")}
    }},confirmButton={Button(onClick=model::confirm,enabled=acknowledged,modifier=Modifier.testTag("before_return_confirm")){Text(if(s.source?.action==BeforeCopyReturnAction.RETURN_ONCE)"Вернуть" else "Проверить")}},dismissButton={OutlinedButton(onClick=model::dismiss,modifier=Modifier.testTag("before_return_dismiss")){Text("Отмена")}})
}
