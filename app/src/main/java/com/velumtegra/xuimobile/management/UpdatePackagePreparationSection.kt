package com.velumtegra.xuimobile.management

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.util.Locale

@Composable
internal fun UpdatePackagePreparationSection(model: ManagementUpdatePreparationViewModel, state: ManagementUpdatePreparationState,
    report: UpdatePreflightSnapshot) {
    val eligibility = model.packageEligibility(report)
    Card(Modifier.fillMaxWidth().testTag("update_package_section")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Пакет новой версии", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text("Проверенный выпуск: v3.10.2 · MHSanaei/3x-ui на GitHub")
            Text("Архитектура сервера: " + updateArchitectureText(report.architecture), modifier = Modifier.testTag("update_package_architecture"))
            when (eligibility) {
                is UpdatePackageEligibility.Blocked -> Text(updatePackageBlockerText(eligibility.reason),
                    modifier = Modifier.testTag("update_package_blocked"))
                is UpdatePackageEligibility.Available -> {
                    Text(eligibility.release.assetName, style = MaterialTheme.typography.bodySmall)
                    Button(onClick = model::requestPackageReview,
                        enabled = !state.packageBusy && !state.launching && !state.reviewing && state.packageReview == null && !state.recoveryReading && state.recoveryPlan == null,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("update_package_request")) {
                        Text(if (state.packageReceipt == null) "Скачать и проверить пакет" else "Скачать и проверить заново")
                    }
                }
            }
            if (state.packageBusy) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text("Загружаем пакет на устройство и проверяем контрольную сумму…", modifier = Modifier.testTag("update_package_running"))
                OutlinedButton(onClick = model::cancelPackage, modifier = Modifier.testTag("update_package_cancel_download")) { Text("Отменить загрузку") }
            }
            state.packageNotice?.let { Text(it, modifier = Modifier.testTag("update_package_notice")) }
            state.packageReceipt?.let { receipt ->
                Text("Пакет v${receipt.release.version} проверен на устройстве", fontWeight = FontWeight.Bold,
                    modifier = Modifier.testTag("update_package_verified"))
                Text("Размер: " + String.format(Locale.ROOT, "%.1f", receipt.sizeBytes / (1024.0 * 1024.0)) + " МиБ")
                Text("Контрольная сумма SHA-256 совпала с официальным выпуском.")
                Text(receipt.sha256, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    Card(Modifier.fillMaxWidth().testTag("update_package_recovery_requirements")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Перед установкой: восстановление", fontWeight = FontWeight.Bold)
            Text("Резервная копия и восстановление ещё не подтверждены.")
            UpdatePackagePolicy.recoveryRequirements.forEach { requirement -> Text("• " + when (requirement) {
                UpdateRecoveryRequirement.CONSISTENT_DATABASE_COPY -> "Согласованная резервная копия базы данных"
                UpdateRecoveryRequirement.PREVIOUS_BINARY_AND_RUNTIME -> "Предыдущая версия приложения и её окружение"
                UpdateRecoveryRequirement.SERVICE_CONFIGURATION_AND_PERMISSIONS -> "Конфигурация службы и права файлов"
                UpdateRecoveryRequirement.PRIVATE_SETTINGS_AND_CERTIFICATES -> "Настройки и сертификаты установки"
                UpdateRecoveryRequirement.VERIFIED_RESTORE_AND_READBACK -> "Проверка восстановления и результата"
            }) }
            Text("Проверка пакета завершает подготовку файла. Обновление не запускалось.")
        }
    }
    state.packageReview?.let { request ->
        AlertDialog(onDismissRequest = model::dismissPackageReview,
            title = { Text("Загрузить и проверить пакет?") },
            text = { Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text((state.local as? LocalManagementReview.Ready)?.serverName.orEmpty(), modifier = Modifier.testTag("update_package_review_server"))
                Text("3x-ui: " + request.report.currentVersion + " → " + request.release.version)
                Text("Архитектура: " + updateArchitectureText(request.report.architecture))
                Text("Источник: официальный выпуск MHSanaei/3x-ui на GitHub.")
                Text("Файл будет загружен на это устройство и проверен по SHA-256. Для последующей установки потребуется подтверждённое восстановление.")
            } },
            confirmButton = { Button(onClick = model::confirmPackage, modifier = Modifier.testTag("update_package_confirm")) { Text("Скачать и проверить") } },
            dismissButton = { OutlinedButton(onClick = model::dismissPackageReview, modifier = Modifier.testTag("update_package_cancel_review")) { Text("Отмена") } })
    }
}

internal fun updateArchitectureText(value: UpdateServerArchitecture?): String = when (value) {
    UpdateServerArchitecture.AMD64 -> "x86_64 / amd64"
    UpdateServerArchitecture.ARM64 -> "aarch64 / arm64"
    null -> "не подтверждена"
}
internal fun updatePackageBlockerText(value: UpdatePackageBlocker): String = when (value) {
    UpdatePackageBlocker.PRECHECKS -> "Сначала устраните замечания проверки установки."
    UpdatePackageBlocker.STALE_REPORT -> "Отчёт устарел. Выполните новую проверку установки."
    UpdatePackageBlocker.UNKNOWN_ARCHITECTURE -> "Архитектура не подтверждена или пока не поддерживается для этого пакета."
    UpdatePackageBlocker.UNSUPPORTED_VERSION -> "Для этой текущей версии нужен отдельный проверенный путь обновления."
    UpdatePackageBlocker.NO_NEWER_REVIEWED_RELEASE -> "Среди проверенных пакетов нет версии новее установленной."
}
internal fun updatePackageFailureText(value: UpdatePackagePreparationFailure): String = when (value) {
    UpdatePackagePreparationFailure.REPORT_CHANGED -> "Проверка установки изменилась или устарела. Нужен новый запрос."
    UpdatePackagePreparationFailure.BUSY -> "Другая проверка пакета ещё не завершена."
    UpdatePackagePreparationFailure.DOWNLOAD_REJECTED -> "Источник не отдал разрешённый пакет. Загрузка не подтверждена."
    UpdatePackagePreparationFailure.TOO_LARGE -> "Размер пакета превысил разрешённый предел."
    UpdatePackagePreparationFailure.INTEGRITY -> "Контрольная сумма пакета не совпала или файл пуст. Пакет отклонён."
    UpdatePackagePreparationFailure.UNAVAILABLE -> "Получить и проверить пакет не удалось. Повторите действие явно."
}
