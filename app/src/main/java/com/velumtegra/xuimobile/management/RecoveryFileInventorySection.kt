package com.velumtegra.xuimobile.management

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.velumtegra.xuimobile.core.domain.RecoveryFileInventoryPolicy
import com.velumtegra.xuimobile.core.domain.RecoveryFileInventoryReview
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant

@Composable
internal fun RecoveryFileInventorySection(report: UpdatePreflightSnapshot, now: Instant, detailed: Boolean = false) {
    val inventory = report.recoveryFiles
    val review = RecoveryFileInventoryPolicy.review(report, now)
    Column(Modifier.fillMaxWidth().testTag(if (detailed) "recovery_file_details" else "recovery_file_inventory"),
        verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Файлы для восстановления", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        when (review) {
            RecoveryFileInventoryReview.Missing -> Text("Состав файлов ещё не проверен. Выполните новую проверку установки.",
                modifier = Modifier.testTag("recovery_files_missing"))
            RecoveryFileInventoryReview.Stale -> Text("Сведения о файлах устарели. Нужна новая проверка установки.",
                modifier = Modifier.testTag("recovery_files_stale"))
            is RecoveryFileInventoryReview.Findings -> {
                Text("Состав файлов требует проверки", modifier = Modifier.testTag("recovery_files_findings"))
                review.issues.sortedBy { it.ordinal }.forEach { Text(recoveryFileIssueText(it),
                    modifier = Modifier.testTag("recovery_file_issue_" + it.name)) }
            }
            is RecoveryFileInventoryReview.KnownSet -> Text("Файлов панели: ${review.fileCount}, всего " + humanBytes(review.totalBytes) + ".",
                modifier = Modifier.testTag("recovery_files_observed"))
        }
        if (inventory != null && review !is RecoveryFileInventoryReview.Stale) {
            RecoveryFileGroup.values().forEach { group ->
                val observation = inventory.groups.getValue(group)
                if (detailed || observation.files > 0) Text(
                    recoveryFileGroupText(group) + ": " + observation.files + " · " + humanBytes(observation.bytes),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.testTag("recovery_file_group_" + group.name))
            }
        }
        if (detailed) Text("Это список файлов на сервере, а не готовая копия.",
            style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("recovery_files_boundary"))
        if (detailed) {
            Text("Для архива установки ещё требуется", fontWeight = FontWeight.Medium)
            RecoveryFileArtifactProof.values().forEach { Text(recoveryFileProofText(it),
                modifier = Modifier.testTag("recovery_file_pending_" + it.name)) }
        }
    }
}

private fun recoveryFileGroupText(group: RecoveryFileGroup): String = when (group) {
    RecoveryFileGroup.RUNTIME -> "Программа 3x-ui и Xray"
    RecoveryFileGroup.SERVICE -> "Настройки службы"
    RecoveryFileGroup.PANEL_TLS -> "Сертификаты панели"
    RecoveryFileGroup.XRAY_TLS -> "Сертификаты Xray"
    RecoveryFileGroup.XRAY_DATA -> "Базы данных Xray"
}
private fun recoveryFileIssueText(issue: RecoveryFileIssue): String = when (issue) {
    RecoveryFileIssue.READ_UNAVAILABLE -> "Не удалось подтвердить ограниченное чтение файлов. Нужна новая явная проверка."
    RecoveryFileIssue.TARGET_UNVERIFIED -> "Точная установка, доступ или источник файлов не подтверждены."
    RecoveryFileIssue.UNSAFE_PATH -> "Есть неподдержанный путь или ссылка. Автоматический обход не выполняется."
    RecoveryFileIssue.UNSAFE_FILE -> "Тип, владелец, права или ссылки одного из файлов требуют проверки."
    RecoveryFileIssue.FILE_MISSING -> "Один из необходимых или указанных файлов не найден."
    RecoveryFileIssue.LIMIT_EXCEEDED -> "Состав превышает предел этого чтения: 96 файлов, 256 МиБ на файл, 512 МиБ всего."
    RecoveryFileIssue.REFERENCES_UNAVAILABLE -> "Ссылки из настроек и конфигурации Xray не удалось полностью прочитать в пределах этого запроса."
    RecoveryFileIssue.REFERENCES_CHANGED -> "Ссылки на файлы изменились во время чтения. Повторите проверку явно."
    RecoveryFileIssue.FILES_CHANGED -> "Состав или метаданные файлов изменились во время чтения. Нужна новая проверка."
    RecoveryFileIssue.SERVICE_ENVIRONMENT -> "У службы есть нестандартное окружение, внешний файл окружения или другой рабочий каталог. Состав требует отдельной проверки."
    RecoveryFileIssue.UNKNOWN_REFERENCE -> "В конфигурации есть другие абсолютные пути. Их назначение нужно проверить перед полным архивом."
}
private fun recoveryFileProofText(proof: RecoveryFileArtifactProof): String = when (proof) {
    RecoveryFileArtifactProof.REVALIDATED_FILE_SET -> "Перепроверить полный состав и содержимое файлов непосредственно перед созданием архива"
    RecoveryFileArtifactProof.CONSISTENT_DATABASE_PAIRING -> "Связать файлы с согласованной копией базы той же установки и момента"
    RecoveryFileArtifactProof.PRIVATE_ARCHIVE_CREATION -> "Создать ограниченный приватный архив на выбранном сервере"
    RecoveryFileArtifactProof.EXACT_MANIFEST_AND_HASH -> "Проверить точный манифест, размеры и SHA-256 созданного архива"
    RecoveryFileArtifactProof.VERIFIED_RESTORE -> "Выполнить проверенное восстановление и итоговое чтение состояния"
}
