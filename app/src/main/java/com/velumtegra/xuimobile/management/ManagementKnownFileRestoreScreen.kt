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

@Composable fun ManagementKnownFileRestoreScreen(model:ManagementKnownFileRestoreViewModel,onBack:()->Unit){
    val s by model.state.collectAsState();val owner=LocalLifecycleOwner.current
    var acknowledged by remember(s.dialog,s.review?.token){mutableStateOf(false)}
    fun back(){model.leaveForeground();onBack()};BackHandler(onBack=::back)
    DisposableEffect(owner,model){val o=LifecycleEventObserver{_,e->if(e==Lifecycle.Event.ON_START)model.enterForeground();if(e==Lifecycle.Event.ON_STOP)model.leaveForeground()};owner.lifecycle.addObserver(o);onDispose{owner.lifecycle.removeObserver(o);model.leaveForeground()}}
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(18.dp).testTag("known_file_root"),verticalArrangement=Arrangement.spacedBy(12.dp)){
        OutlinedButton(onClick=::back,modifier=Modifier.testTag("known_file_back")){Text("‹ Назад")}
        Text("Восстановление файлов",style=MaterialTheme.typography.headlineSmall,fontWeight=androidx.compose.ui.text.font.FontWeight.Bold)
        StepIntro(
            step="Восстановление · дополнительно",
            summary=DetailLine("Вернём из копии изменившиеся настройки, сертификаты и ресурсы Xray. Панель должна быть остановлена и останется остановленной.","known_file_stopped"),
            details=listOf(
                DetailLine("Заменяются только известные файлы, которые отличаются от копии. Программа, служба и база не меняются.","known_file_scope"),
                DetailLine("Файлы заменяются по одному. Если связь оборвётся, часть может остаться старой: приложение не повторит и не отменит замену само. Прежние файлы сохраняются, их можно вернуть.","known_file_limits"),
            ),
        )
        if(s.loading || s.busy)LinearProgressIndicator(Modifier.fillMaxWidth())
        s.review?.let{r->TargetLines(r.serverLabel,r.sshLabel,"known_file_ssh");Text("Файлов к замене: "+r.binding.changedFiles)
            Button(onClick=model::request,enabled=!s.loading && !s.busy,modifier=Modifier.fillMaxWidth().testTag("known_file_request")){Text(when(r.action){KnownFileRestoreAction.APPLY->"Заменить файлы";KnownFileRestoreAction.READ->"Проверить результат";KnownFileRestoreAction.RETURN->"Вернуть прежние файлы"})}}
        when(val result=s.result){
            is KnownFileRestoreResult.Recorded->Text("Команда отправлена. Нажмите «Обновить», затем проверьте результат: сама отправка ещё не подтверждает замену.",modifier=Modifier.testTag("known_file_recorded"))
            is KnownFileRestoreResult.Unavailable->Text(result.text,color=MaterialTheme.colorScheme.error,modifier=Modifier.testTag("known_file_unavailable"))
            is KnownFileRestoreResult.Checked->{val p=result.evidence
                Text(if(result.terminal && p.desiredComplete)"Файлы из копии на месте и проверены" else if(result.terminal && p.previousComplete)"Прежние файлы возвращены и проверены" else "Замена прошла не полностью: часть файлов из копии, часть прежние",fontWeight=androidx.compose.ui.text.font.FontWeight.Bold,modifier=Modifier.testTag("known_file_checked"))
                Text("Из копии: ${p.desiredFiles} · прежних: ${p.previousFiles} · всего: ${p.binding.changedFiles} · проверено "+humanTime(p.observedAt),modifier=Modifier.testTag("known_file_counts"))
                if(result.mayReturn)OutlinedButton(onClick=model::requestReturn,enabled=!s.busy,modifier=Modifier.fillMaxWidth().testTag("known_file_return")){Text("Вернуть прежние файлы")}
                TechDetails(listOf(DetailLine("SHA-256 списка прежних файлов: "+p.beforeManifestSha256,"known_file_manifest")))
            }
            null->Unit
        }
        s.notice?.let{Text(it,modifier=Modifier.testTag("known_file_notice"))}
        QuietRefresh(model::refresh,!s.busy,"known_file_refresh")
    }
    if(s.dialog)AlertDialog(onDismissRequest=model::dismiss,title={Text(when(s.review?.action){KnownFileRestoreAction.APPLY->"Заменить файлы из копии?";KnownFileRestoreAction.RETURN->"Вернуть прежние файлы?";else->"Проверить результат?"})},text={Column(Modifier.heightIn(max=360.dp).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(10.dp)){
        s.review?.let{r->Text(r.serverLabel+" · "+r.sshLabel);Text("Файлов: "+r.binding.changedFiles)
            Text(when(r.action){KnownFileRestoreAction.APPLY->"Прежние файлы будут сохранены и заменены файлами из копии: вернутся её настройки и сертификаты. Если связь оборвётся, часть файлов может остаться старой. База не меняется, панель остаётся остановленной."
                KnownFileRestoreAction.READ->"Приложение только прочитает файлы, базу и состояние панели. На сервере ничего не изменится."
                KnownFileRestoreAction.RETURN->"Сохранённые прежние файлы будут возвращены на место. Возврат тоже может оборваться, повтора не будет. После него результат нужно проверить."})
            Text("SHA-256 копии: "+r.binding.comparison.source.archiveSha256.take(16)+"…",style=MaterialTheme.typography.bodySmall,modifier=Modifier.testTag("known_file_review_hash"))
            r.returnManifest?.let{Text("SHA-256 списка возврата: "+it.take(16)+"…",style=MaterialTheme.typography.bodySmall,modifier=Modifier.testTag("known_file_return_hash"))}}
        Row(verticalAlignment=androidx.compose.ui.Alignment.CenterVertically){Checkbox(checked=acknowledged,onCheckedChange={acknowledged=it},modifier=Modifier.testTag("known_file_ack"));Text(if(s.review?.action==KnownFileRestoreAction.READ)"Подключиться и прочитать" else "Понимаю, что файлы будут заменены")}
    }},confirmButton={Button(onClick=model::confirm,enabled=acknowledged,modifier=Modifier.testTag("known_file_confirm")){Text(when(s.review?.action){KnownFileRestoreAction.APPLY->"Заменить";KnownFileRestoreAction.RETURN->"Вернуть";else->"Проверить"})}},dismissButton={OutlinedButton(onClick=model::dismiss,modifier=Modifier.testTag("known_file_dismiss")){Text("Отмена")}})
}
