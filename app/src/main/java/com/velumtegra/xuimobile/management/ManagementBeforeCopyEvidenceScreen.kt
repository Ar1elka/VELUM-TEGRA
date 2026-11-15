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
import com.velumtegra.xuimobile.core.model.*
import androidx.lifecycle.LifecycleEventObserver

@Composable
fun ManagementBeforeCopyEvidenceScreen(model:ManagementBeforeCopyEvidenceViewModel,onBack:()->Unit,onReturn:((BeforeCopyEvidence?)->Unit)?=null){
    val s by model.state.collectAsState();val owner=LocalLifecycleOwner.current
    var acknowledged by remember(s.dialog,s.source?.token){mutableStateOf(false)}
    BackHandler(onBack=onBack)
    DisposableEffect(owner,model){val o=LifecycleEventObserver{_,event->if(event==Lifecycle.Event.ON_START)model.enterForeground();if(event==Lifecycle.Event.ON_STOP)model.leaveForeground()};owner.lifecycle.addObserver(o);onDispose{owner.lifecycle.removeObserver(o);model.leaveForeground()}}
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(18.dp).testTag("before_copy_root"),verticalArrangement=Arrangement.spacedBy(12.dp)){
        OutlinedButton(onClick=onBack,modifier=Modifier.testTag("before_copy_back")){Text("‹ Назад")}
        Text("Прежняя база",style=MaterialTheme.typography.headlineSmall,fontWeight=androidx.compose.ui.text.font.FontWeight.Bold)
        StepIntro(
            step="Откат восстановления · шаг 1 из 3",
            summary=DetailLine("Проверим базу, которую приложение сохранило перед восстановлением. Это только чтение, на сервере ничего не меняется.","before_copy_scope"),
            details=listOf(
                DetailLine("Приложение подключится по SSH и проверит целостность сохранённой базы.","before_copy_consequence"),
                DetailLine("Если прежняя база цела, а панель остановлена, её можно будет вернуть на следующем шаге.","before_copy_limits"),
            ),
        )
        if(s.loading || s.busy)LinearProgressIndicator(Modifier.fillMaxWidth())
        s.source?.let{TargetLines(it.serverLabel,it.sshLabel,"before_copy_ssh")
            Button(onClick=model::request,enabled=!s.loading && !s.busy,modifier=Modifier.fillMaxWidth().testTag("before_copy_read")){Text("Проверить прежнюю базу")}}
        when(val result=s.result){
            is BeforeCopyResult.Observed->{val p=result.evidence;Card(Modifier.fillMaxWidth()){Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
                Text("Прежняя база цела · "+humanBytes(p.bytes)+" · проверено "+humanTime(p.observedAt),fontWeight=androidx.compose.ui.text.font.FontWeight.Bold,modifier=Modifier.testTag("before_copy_observed"))
                Column(Modifier.testTag("before_copy_findings"),verticalArrangement=Arrangement.spacedBy(4.dp)){
                    Text("Панель: "+(if(p.service==BeforeCopyService.ACTIVE)"работает" else "остановлена"))
                    Text("Текущая база: "+when(p.current){BeforeCopyCurrent.SAME->"совпадает с прежней";BeforeCopyCurrent.DIFFERENT->"отличается от прежней";BeforeCopyCurrent.UNAVAILABLE->"не удалось проверить"})
                    Text("Структура и файлы: "+when(p.structure){BeforeCopyStructure.MATCH->"совпадают";BeforeCopyStructure.DIFFERENT->"есть различия";BeforeCopyStructure.UNAVAILABLE->"не удалось проверить"})
                }
                TechDetails(listOf(DetailLine("SHA-256: "+p.databaseSha256,"before_copy_hash"),DetailLine("Запись о завершении восстановления: "+(if(p.completion==BeforeCopyCompletion.COMPLETE)"есть" else "не найдена"))))
            }}}
            is BeforeCopyResult.Unavailable->Text(result.message,modifier=Modifier.testTag("before_copy_unavailable"))
            null->Unit
        }
        val evidence=(s.result as? BeforeCopyResult.Observed)?.evidence
        if(onReturn!=null && !s.loading && !s.busy && ((evidence!=null && evidence.service==BeforeCopyService.INACTIVE && evidence.structure==BeforeCopyStructure.MATCH && evidence.current==BeforeCopyCurrent.DIFFERENT) || s.source==null))
            OutlinedButton(onClick={onReturn(evidence)},modifier=Modifier.fillMaxWidth().testTag("before_copy_return")){Text(if(evidence==null)"Проверить начатый возврат" else "Дальше: вернуть прежнюю базу")}
        s.notice?.let{Text(it,modifier=Modifier.testTag("before_copy_notice"))}
        QuietRefresh(model::refresh,!s.busy,"before_copy_refresh")
    }
    if(s.dialog)AlertDialog(onDismissRequest=model::dismiss,title={Text("Проверить прежнюю базу?")},text={Column(Modifier.heightIn(max=360.dp).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(10.dp)){
        s.source?.let{Text(it.serverLabel+" · "+it.sshLabel)}
        Text("Приложение подключится по SSH и проверит целостность сохранённой базы. На сервере ничего не изменится.")
        Row(verticalAlignment=androidx.compose.ui.Alignment.CenterVertically){Checkbox(checked=acknowledged,onCheckedChange={acknowledged=it},modifier=Modifier.testTag("before_copy_ack"));Text("Подключиться и прочитать")}
    }},confirmButton={Button(onClick=model::confirm,enabled=acknowledged,modifier=Modifier.testTag("before_copy_confirm")){Text("Проверить")}},dismissButton={OutlinedButton(onClick=model::dismiss,modifier=Modifier.testTag("before_copy_dismiss")){Text("Отмена")}})
}
