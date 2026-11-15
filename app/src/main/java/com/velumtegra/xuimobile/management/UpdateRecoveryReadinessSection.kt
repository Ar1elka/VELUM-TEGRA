package com.velumtegra.xuimobile.management

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.velumtegra.xuimobile.core.domain.UpdateRecoveryBlocker
import com.velumtegra.xuimobile.core.domain.UpdateRecoveryPlanReview
import com.velumtegra.xuimobile.core.model.*
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
internal fun UpdateRecoveryReadinessSection(viewModel: ManagementUpdatePreparationViewModel,
    state: ManagementUpdatePreparationState, report: UpdatePreflightSnapshot, onDatabaseBackup: ((UpdatePreflightPointer) -> Unit)? = null,
    onInstallationBackup: ((UpdatePreflightPointer) -> Unit)? = null) {
    val assessment = viewModel.recoveryReview(report)
    val source = report.recovery
    Card(Modifier.fillMaxWidth().testTag("recovery_readiness_section")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Шаг 2: создать копию", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            val idle = !state.recoveryReading && !state.launching && !state.reading && !state.reviewing &&
                !state.packageBusy && state.packageReview == null && state.recoveryPlan == null
            when (assessment) {
                is UpdateRecoveryPlanReview.Blocked -> {
                    Text("Сначала нужно исправить:", fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.testTag("recovery_readiness_blocked"))
                    assessment.reasons.forEach { Text("• " + recoveryBlockerText(it), modifier = Modifier.testTag("recovery_blocker_" + it.name)) }
                }
                is UpdateRecoveryPlanReview.Draft -> Text("Установка проверена, копию можно создавать.",
                    modifier = Modifier.testTag("recovery_readiness_checked"))
            }
            if (source == null) {
                Text("Проверка не вернула сведений для копии. Нажмите «Новая проверка установки».",
                    modifier = Modifier.testTag("recovery_source_missing"))
            }
            if (onInstallationBackup != null && state.pointer != null) Button(
                onClick = { state.pointer?.let(onInstallationBackup) }, enabled = idle,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("installation_backup_open")) { Text("Полная копия панели") }
            if (onDatabaseBackup != null && state.pointer != null) OutlinedButton(
                onClick = { state.pointer?.let(onDatabaseBackup) }, enabled = idle,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("database_backup_open")) { Text("Только база") }
            Text("Полная копия включает базу, файлы панели и сертификаты. «Только база» — настройки и клиенты.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag("recovery_readiness_boundary"))
            if (state.recoveryReading) LinearProgressIndicator(Modifier.fillMaxWidth().testTag("recovery_plan_reading"))
            state.recoveryNotice?.let { Text(it, modifier = Modifier.testTag("recovery_plan_notice")) }
            var showChecks by rememberSaveable { mutableStateOf(false) }
            TextButton(onClick = { showChecks = !showChecks }, modifier = Modifier.testTag("recovery_checks_toggle")) {
                Text(if (showChecks) "Скрыть результаты проверки" else "Что проверено")
            }
            if (showChecks) {
                if (source != null) {
                    Text(recoveryDatabaseText(source.database), modifier = Modifier.testTag("recovery_database_access"))
                    source.databaseBytes?.let { Text("Размер базы: " + humanBytes(it), modifier = Modifier.testTag("recovery_database_size")) }
                    Text(when (source.integrity) {
                        DeepDiagnosticDatabaseIntegrityStatus.OK -> "Целостность базы: в порядке"
                        DeepDiagnosticDatabaseIntegrityStatus.FAILED -> "Целостность базы: найдены ошибки"
                        DeepDiagnosticDatabaseIntegrityStatus.UNREADABLE -> "Целостность базы: не удалось проверить"
                    }, modifier = Modifier.testTag("recovery_database_integrity"))
                    Text(when (source.schema) {
                        DeepDiagnosticDatabaseSchemaStatus.SUPPORTED -> "Структура базы: в порядке"
                        DeepDiagnosticDatabaseSchemaStatus.INCOMPLETE -> "Структура базы: не хватает таблиц или полей"
                        DeepDiagnosticDatabaseSchemaStatus.UNREADABLE -> "Структура базы: не удалось проверить"
                    }, modifier = Modifier.testTag("recovery_database_schema"))
                    Text(if (source.runtime == UpdateRecoveryRuntimeState.STANDARD_FILES_PRESENT)
                        "Файлы 3x-ui и Xray: на месте" else "Файлы 3x-ui и Xray: нужна проверка",
                        modifier = Modifier.testTag("recovery_runtime_files"))
                    Text(when (source.panelTls) {
                        UpdateRecoveryPanelTlsState.NOT_CONFIGURED -> "Сертификат панели: не настроен"
                        UpdateRecoveryPanelTlsState.PAIR_PRESENT -> "Сертификат панели: файлы на месте"
                        UpdateRecoveryPanelTlsState.INCOMPLETE -> "Сертификат панели: указан только один из двух файлов"
                        UpdateRecoveryPanelTlsState.UNAVAILABLE -> "Сертификат панели: файлы недоступны"
                        UpdateRecoveryPanelTlsState.UNOBSERVED -> "Сертификат панели: не проверен"
                    }, modifier = Modifier.testTag("recovery_panel_tls"))
                    val missing = source.tools.filterValues { it != UpdateRecoveryToolState.AVAILABLE }.keys
                    Text(if (missing.isEmpty()) "Нужные программы на сервере: есть" else
                        "На сервере не хватает: " + missing.joinToString { it.name.lowercase() }, modifier = Modifier.testTag("recovery_tools"))
                }
                RecoveryFileInventorySection(report, viewModel.recoveryFilesObservedAt())
                OutlinedButton(onClick = viewModel::requestRecoveryPlan, enabled = idle,
                    modifier = Modifier.fillMaxWidth().testTag("recovery_plan_request")) { Text("Подробный состав копии") }
                Text("Эта проверка не говорит, подойдёт ли база к другой версии панели.",
                    style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("recovery_compatibility_pending"))
            }
        }
    }
    state.recoveryPlan?.let { plan ->
        val time = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss").withZone(ZoneId.systemDefault())
        AlertDialog(onDismissRequest = viewModel::dismissRecoveryPlan,
            title = { Text("План резервной копии") },
            text = {
                Column(Modifier.heightIn(max = 440.dp).verticalScroll(rememberScrollState()).testTag("recovery_plan_dialog"),
                    verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text((state.local as? LocalManagementReview.Ready)?.serverName.orEmpty(), modifier = Modifier.testTag("recovery_plan_server"))
                    state.profile?.let { Text("SSH: ${it.username}@${it.host}:${it.port}", modifier = Modifier.testTag("recovery_plan_ssh")) }
                    Text("Текущая версия: ${plan.previousVersion}", modifier = Modifier.testTag("recovery_plan_version"))
                    Text("Архитектура сервера: " + if (plan.architecture == UpdateServerArchitecture.AMD64) "x86_64 / amd64" else "aarch64 / arm64",
                        modifier = Modifier.testTag("recovery_plan_architecture"))
                    Text("Сведения получены: " + time.format(plan.sourceObservedAt))
                    Text("Перепроверить после: " + time.format(plan.validUntil))
                    Text("В копию должны войти", fontWeight = FontWeight.Bold)
                    plan.components.forEach { Text(recoveryComponentText(it), modifier = Modifier.testTag("recovery_component_" + it.name)) }
                    Text("Что ещё нужно подтвердить", fontWeight = FontWeight.Bold)
                    plan.pendingProofs.forEach { Text(recoveryProofText(it), modifier = Modifier.testTag("recovery_pending_" + it.name)) }
                    RecoveryFileInventorySection(report, viewModel.recoveryFilesObservedAt(), detailed = true)
                    Text("Просмотр состава не запускает резервную копию или восстановление.", modifier = Modifier.testTag("recovery_plan_no_execution"))
                }
            },
            confirmButton = { Button(onClick = viewModel::dismissRecoveryPlan, modifier = Modifier.testTag("recovery_plan_close")) { Text("Закрыть") } })
    }
}

internal fun recoveryBlockerText(reason: UpdateRecoveryBlocker): String = when (reason) {
    UpdateRecoveryBlocker.SOURCE_NOT_OBSERVED -> "Нужна новая проверка установки со сведениями для копии."
    UpdateRecoveryBlocker.STALE_OR_FUTURE_REPORT -> "Сведения для плана устарели или имеют неверное время. Выполните новую проверку."
    UpdateRecoveryBlocker.EXACT_TARGET_MISSING -> "Точная установка и выбранный SSH-доступ не подтверждены."
    UpdateRecoveryBlocker.CURRENT_INSTALLATION -> "Сначала устраните замечания к текущей установке."
    UpdateRecoveryBlocker.ARCHITECTURE_UNSUPPORTED -> "Архитектура сервера не поддержана этим планом."
    UpdateRecoveryBlocker.STABLE_VERSION_REQUIRED -> "Для плана требуется подтверждённая стабильная версия 3x-ui."
    UpdateRecoveryBlocker.REQUIRED_TOOLS -> "Для будущей копии не хватает требуемых инструментов. Автоматическая установка не выполняется."
    UpdateRecoveryBlocker.DATABASE_ACCESS -> "Проверьте доступность базы, отсутствие символьных ссылок, приватные права root и предел 128 МиБ."
    UpdateRecoveryBlocker.DATABASE_CHANGED -> "Основной файл базы изменился во время проверки. Нужен новый явный запрос."
    UpdateRecoveryBlocker.DATABASE_INTEGRITY -> "Целостность базы не подтверждена."
    UpdateRecoveryBlocker.DATABASE_SCHEMA -> "Ожидаемая структура базы не подтверждена."
    UpdateRecoveryBlocker.RUNTIME_FILES -> "Стандартные файлы 3x-ui и каталог Xray не подтверждены."
    UpdateRecoveryBlocker.PANEL_TLS -> "Проверьте пару файлов сертификата и ключа панели."
}

private fun recoveryDatabaseText(state: UpdateRecoveryDatabaseState): String = when (state) {
    UpdateRecoveryDatabaseState.PRIVATE_REGULAR -> "База доступна; основной файл принадлежит root и закрыт для других пользователей"
    UpdateRecoveryDatabaseState.UNSAFE_PERMISSIONS -> "Права основного файла базы требуют проверки"
    UpdateRecoveryDatabaseState.UNSAFE_LINK -> "Путь к базе содержит символьную ссылку"
    UpdateRecoveryDatabaseState.UNAVAILABLE -> "Основной файл базы недоступен или пуст"
    UpdateRecoveryDatabaseState.UNOBSERVED -> "Метаданные базы не подтверждены"
    UpdateRecoveryDatabaseState.TOO_LARGE -> "Размер основной базы превышает предел этого плана"
    UpdateRecoveryDatabaseState.CHANGED_DURING_READ -> "Основной файл базы изменился во время проверки"
}
private fun recoveryComponentText(component: UpdateRecoveryComponent): String = when (component) {
    UpdateRecoveryComponent.CONSISTENT_DATABASE -> "Согласованная копия базы, полученная механизмом SQLite"
    UpdateRecoveryComponent.PREVIOUS_BINARY_AND_XRAY_RUNTIME -> "Текущие исполняемые файлы 3x-ui, Xray и данные его окружения"
    UpdateRecoveryComponent.SERVICE_CONFIGURATION_AND_PERMISSIONS -> "Конфигурация службы, владельцы и права файлов"
    UpdateRecoveryComponent.PANEL_SETTINGS_AND_TLS_FILES -> "Настройки панели и используемые сертификат с закрытым ключом"
    UpdateRecoveryComponent.EXTERNAL_XRAY_RESOURCES -> "Внешние ресурсы и сертификаты, указанные в конфигурации Xray"
}
private fun recoveryProofText(proof: UpdateRecoveryRequirement): String = when (proof) {
    UpdateRecoveryRequirement.CONSISTENT_DATABASE_COPY -> "Не подтверждено: согласованная копия базы создана и проверена"
    UpdateRecoveryRequirement.PREVIOUS_BINARY_AND_RUNTIME -> "Не подтверждено: прежние файлы и окружение сохранены"
    UpdateRecoveryRequirement.SERVICE_CONFIGURATION_AND_PERMISSIONS -> "Не подтверждено: служба и права могут быть восстановлены"
    UpdateRecoveryRequirement.PRIVATE_SETTINGS_AND_CERTIFICATES -> "Не подтверждено: полный набор настроек и закрытых файлов сохранён"
    UpdateRecoveryRequirement.VERIFIED_RESTORE_AND_READBACK -> "Не подтверждено: восстановление и итоговая проверка прошли успешно"
}
