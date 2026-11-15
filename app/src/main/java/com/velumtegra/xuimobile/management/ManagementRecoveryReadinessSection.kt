package com.velumtegra.xuimobile.management
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
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.domain.*

private fun groupLabel(g:RecoveryFileGroup)=when(g){RecoveryFileGroup.RUNTIME->"Программа и конфигурация";RecoveryFileGroup.SERVICE->"Служба";RecoveryFileGroup.PANEL_TLS->"TLS панели";RecoveryFileGroup.XRAY_TLS->"TLS Xray";RecoveryFileGroup.XRAY_DATA->"Внешние ресурсы Xray"}
private fun blockerLabel(b:RecoveryReadinessBlocker)=when(b){
    RecoveryReadinessBlocker.VERSION->"Версии различаются: переход между ними не проверен."
    RecoveryReadinessBlocker.ARCHITECTURE->"Архитектуры различаются."
    RecoveryReadinessBlocker.DATABASE_SCHEMA->"Структуры базы различаются."
    RecoveryReadinessBlocker.ENDPOINT->"Адресные настройки панели различаются."
    RecoveryReadinessBlocker.PAGE_SIZE->"Размер страницы SQLite различается."
    RecoveryReadinessBlocker.FILE_MEMBERSHIP->"Изменился состав файлов или их назначение; нужен отдельный разбор зависимостей."
    RecoveryReadinessBlocker.SERVICE_RUNNING->"Служба работает. Перед будущей записью потребуется отдельная подтверждённая остановка."
    RecoveryReadinessBlocker.SERVICE_UNVERIFIED->"Остановка службы и отсутствие её процессов не подтверждены."
    RecoveryReadinessBlocker.MIGRATION_UNVERIFIED->"Миграции приложения и данных не проверены, даже при совпадении версии и структуры."
    RecoveryReadinessBlocker.FILE_WRITE_PROTOCOL_UNVERIFIED->"Полное восстановление файлов установки ещё не проверено."
}
@Composable fun ManagementRecoveryReadinessSection(model:ManagementRecoveryReadinessViewModel,onRestoreFiles:((RecoveryReadinessEvidence)->Unit)?=null){
    val s by model.state.collectAsState();val owner=LocalLifecycleOwner.current
    var acknowledged by remember(s.dialog,s.review?.token){mutableStateOf(false)}
    DisposableEffect(owner,model){val o=LifecycleEventObserver{_,e->if(e==Lifecycle.Event.ON_START)model.enterForeground();if(e==Lifecycle.Event.ON_STOP)model.leaveForeground()};owner.lifecycle.addObserver(o);onDispose{owner.lifecycle.removeObserver(o);model.leaveForeground()}}
    Card(Modifier.fillMaxWidth().testTag("recovery_readiness_root")){Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){
        Text("Файлы панели",style=MaterialTheme.typography.titleMedium,fontWeight=androidx.compose.ui.text.font.FontWeight.Bold)
        StepIntro(
            step=null,
            summary=DetailLine("Если кроме базы изменились настройки или сертификаты, их тоже можно вернуть из копии. Сначала сравним файлы; это только чтение.","recovery_readiness_scope"),
            details=listOf(DetailLine("Сравниваются только известные файлы панели. nginx, выпуск сертификатов и другие службы сервера сюда не входят.","recovery_readiness_limits")),
        )
        if(s.loading || s.busy)LinearProgressIndicator(Modifier.fillMaxWidth())
        s.review?.let{r->Text(r.sshLabel,style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant,modifier=Modifier.testTag("recovery_readiness_ssh"))
            OutlinedButton(onClick=model::request,enabled=!s.loading && !s.busy,modifier=Modifier.fillMaxWidth().testTag("recovery_readiness_read")){Text("Сравнить файлы")}}
        when(val result=s.result){
            is RecoveryReadinessResult.Observed->{val p=result.evidence
                Text("Файлы сравнены "+humanTime(p.observedAt),fontWeight=androidx.compose.ui.text.font.FontWeight.Bold,modifier=Modifier.testTag("recovery_readiness_observed"))
                Text("В копии ${p.sourceFiles}, на сервере ${p.currentFiles}. Изменено: ${p.changedCommon}, новых: ${p.added}, пропало: ${p.missing}.",modifier=Modifier.testTag("recovery_readiness_total"))
                Text("Панель: "+when(p.quiescence){RecoveryQuiescence.STOPPED->"остановлена";RecoveryQuiescence.REQUIRED->"работает";RecoveryQuiescence.UNAVAILABLE->"состояние не подтверждено"},modifier=Modifier.testTag("recovery_readiness_service"))
                val blockers=RecoveryReadinessPolicy.blockers(p)
                if(blockers.isNotEmpty())Text("Что мешает вернуть файлы:",fontWeight=androidx.compose.ui.text.font.FontWeight.Medium)
                blockers.forEach{b->Text("• "+blockerLabel(b),modifier=Modifier.testTag("recovery_readiness_block_"+b.name))}
                if(onRestoreFiles!=null && KnownFileRestorePolicy.candidate(p,java.time.Instant.now()))Button(onClick={onRestoreFiles(p)},modifier=Modifier.fillMaxWidth().testTag("recovery_readiness_restore_files")){Text("Вернуть изменённые файлы")}
                TechDetails(listOf(
                    DetailLine("Версия: в копии ${p.binding.source.source.version} / ${p.binding.source.source.architecture.name}, на сервере ${p.currentVersion} / ${p.currentArchitecture.name}","recovery_readiness_versions"),
                    DetailLine("Объём файлов: "+humanBytes(p.sourceBytes)+" в копии, "+humanBytes(p.currentBytes)+" на сервере"),
                    DetailLine("База: структура "+(if(p.sourceSchema==p.currentSchema)"совпадает" else "различается")+", адрес панели "+(if(p.endpointsMatch)"совпадает" else "различается")+", размер страницы "+(if(p.pageSizesMatch)"совпадает" else "различается"),"recovery_readiness_database"),
                    DetailLine("Режим SQLite: ${p.journalMode.name}; WAL: "+when(p.wal){RecoveryWalPresence.ABSENT->"отсутствует";RecoveryWalPresence.EMPTY->"пустой";RecoveryWalPresence.PRESENT->"есть данные"},"recovery_readiness_wal"),
                )+RecoveryFileGroup.values().map{g->val v=p.groups.getValue(g);DetailLine("${groupLabel(g)}: ${v.sourceFiles} / ${v.currentFiles}; изменено ${v.changedCommon}, новых ${v.added}, пропало ${v.missing}","recovery_readiness_group_"+g.name)})
            }
            is RecoveryReadinessResult.Unavailable->Text(result.text,color=MaterialTheme.colorScheme.error,modifier=Modifier.testTag("recovery_readiness_unavailable"))
            null->Unit
        }
        s.notice?.let{Text(it,modifier=Modifier.testTag("recovery_readiness_notice"))}
        QuietRefresh(model::refresh,!s.busy,"recovery_readiness_refresh")
    }}
    if(s.dialog)AlertDialog(onDismissRequest=model::dismiss,title={Text("Сравнить файлы?")},text={Column(Modifier.heightIn(max=360.dp).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(10.dp)){
        s.review?.let{Text(it.serverLabel+" · "+it.sshLabel)}
        Text("Приложение подключится по SSH и сравнит файлы панели с копией, проверит базу и состояние службы. На сервере ничего не изменится.")
        s.review?.let{Text("SHA-256 копии: "+it.binding.source.archiveSha256.take(16)+"…",style=MaterialTheme.typography.bodySmall,modifier=Modifier.testTag("recovery_readiness_review_hash"))}
        Row(verticalAlignment=androidx.compose.ui.Alignment.CenterVertically){Checkbox(checked=acknowledged,onCheckedChange={acknowledged=it},modifier=Modifier.testTag("recovery_readiness_ack"));Text("Подключиться и прочитать")}
    }},confirmButton={Button(onClick=model::confirm,enabled=acknowledged,modifier=Modifier.testTag("recovery_readiness_confirm")){Text("Сравнить")}},dismissButton={OutlinedButton(onClick=model::dismiss,modifier=Modifier.testTag("recovery_readiness_dismiss")){Text("Отмена")}})
}
