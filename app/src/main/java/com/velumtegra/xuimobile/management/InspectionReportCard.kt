package com.velumtegra.xuimobile.management

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

@Composable
fun InspectionReportCard(status: InspectionStatus, modifier: Modifier = Modifier) {
    Surface(modifier = modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceVariant) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Результат проверки", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            InspectionReportContent(status)
        }
    }
}

/** Operation completion and server health are separate. Only the core's actual facts are rendered. */
@Composable
internal fun InspectionReportContent(status: InspectionStatus) {
    if (!status.terminal) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
    Text(status.text, modifier = Modifier.testTag("inspection_report_summary"))
    status.serviceState?.let {
        Text("Служба: " + serviceStateLabel(it), modifier = Modifier.testTag("inspection_report_service"))
    }
    val detail = status.detail
    if (detail == null) {
        // With a detailed report the same moment is printed once, below, as «Отчёт на момент».
        status.observedAt?.let { Text("Состояние службы проверено: " + inspectionTime(it),
            style = MaterialTheme.typography.bodySmall) }
        status.identity?.let { Text("Установка: " + it) }
        status.configuration?.let { Text("Конфигурация: " + it) }
        status.completedAt?.let { Text("Завершена: " + inspectionTime(it), style = MaterialTheme.typography.bodySmall) }
        if (status.terminal) Text(
            "Подробный отчёт недоступен. Сохранённый итог не подтверждает текущее состояние VPS.",
            modifier = Modifier.testTag("inspection_report_missing"), style = MaterialTheme.typography.bodySmall)
        return
    }
    HorizontalDivider()
    detail.overall?.let { overall ->
        Text(overallLabel(overall), style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold, modifier = Modifier.testTag("inspection_report_overall"),
            color = if (overall == DeepDiagnosticOverallStatus.CRITICAL) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.onSurface)
    }
    Text("Отчёт на момент: " + inspectionTime(detail.observedAt), style = MaterialTheme.typography.bodySmall,
        modifier = Modifier.testTag("inspection_report_observed_at"))
    if (detail.overall != null) {
        if (detail.findings.isEmpty()) Text(
            if (detail.overall == DeepDiagnosticOverallStatus.HEALTHY) "В выполненной диагностике замечаний не выявлено."
            else "Перечень замечаний недоступен.", style = MaterialTheme.typography.bodySmall)
        detail.findings.sortedWith(compareByDescending<DeepDiagnosticFinding> { it.severity.ordinal }
            .thenBy { it.code.ordinal }).forEach { finding ->
            Text(severityLabel(finding.severity) + " · " + findingLabel(finding.code),
                modifier = Modifier.testTag("inspection_report_finding_" + finding.code.name),
                color = if (finding.severity == DeepDiagnosticSeverity.CRITICAL) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.onSurface)
        }
    }
    Text("Установка", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
    when (val identity = detail.identity) {
        ManagementIdentityStatus.Matched -> Text("Сохранённая установка подтверждена.")
        is ManagementIdentityStatus.Drift -> identity.fields.sortedBy { it.ordinal }.forEach {
            Text(identityDriftLabel(it), modifier = Modifier.testTag("inspection_report_identity_" + it.name))
        }
        is ManagementIdentityStatus.Insufficient -> identity.gaps.sortedBy { it.ordinal }.forEach {
            Text(evidenceGapLabel(it), modifier = Modifier.testTag("inspection_report_identity_gap_" + it.name))
        }
    }
    Text("Сохранённые параметры", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
    when (val baseline = detail.baseline) {
        ManagementBaselineStatus.Matched -> Text("Параметры совпадают с сохранёнными.")
        is ManagementBaselineStatus.Drift -> baseline.fields.sortedBy { it.ordinal }.forEach {
            Text(baselineDriftLabel(it), modifier = Modifier.testTag("inspection_report_baseline_" + it.name))
        }
        is ManagementBaselineStatus.Insufficient -> baseline.gaps.sortedBy { it.ordinal }.forEach {
            Text(evidenceGapLabel(it), modifier = Modifier.testTag("inspection_report_baseline_gap_" + it.name))
        }
    }
    Text("Это результат указанной проверки. Состояние VPS могло измениться после неё.",
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

internal fun inspectionTime(time: Instant): String = DateTimeFormatter
    .ofPattern("dd.MM.yyyy · HH:mm:ss", Locale.getDefault()).withZone(ZoneId.systemDefault()).format(time)

private fun overallLabel(status: DeepDiagnosticOverallStatus) = when (status) {
    DeepDiagnosticOverallStatus.HEALTHY -> "По результатам диагностики проблем не выявлено"
    DeepDiagnosticOverallStatus.DEGRADED -> "Есть замечания"
    DeepDiagnosticOverallStatus.CRITICAL -> "Есть критические проблемы"
    DeepDiagnosticOverallStatus.INSUFFICIENT -> "Недостаточно данных для вывода"
}

private fun severityLabel(severity: DeepDiagnosticSeverity) = when (severity) {
    DeepDiagnosticSeverity.CRITICAL -> "Критично"
    DeepDiagnosticSeverity.WARNING -> "Внимание"
    DeepDiagnosticSeverity.INFO -> "Сведения"
}

private fun findingLabel(code: DeepDiagnosticFindingCode) = when (code) {
    DeepDiagnosticFindingCode.IDENTITY_DRIFT -> "Установка отличается от сохранённой"
    DeepDiagnosticFindingCode.SERVICE_NOT_ACTIVE -> "Служба 3x-ui не работает"
    DeepDiagnosticFindingCode.BASELINE_DRIFT -> "Параметры панели изменились"
    DeepDiagnosticFindingCode.SERVICE_DEFINITION_DRIFT -> "Определение службы отличается от сохранённого"
    DeepDiagnosticFindingCode.BINARY_VERSION_UNAVAILABLE -> "Версию программы не удалось подтвердить"
    DeepDiagnosticFindingCode.DATABASE_INTEGRITY_FAILED -> "Проверка целостности базы завершилась ошибкой"
    DeepDiagnosticFindingCode.DATABASE_SCHEMA_INCOMPLETE -> "Структура базы не соответствует ожидаемой"
    DeepDiagnosticFindingCode.CERTIFICATE_MISSING -> "Сертификат панели не найден"
    DeepDiagnosticFindingCode.PRIVATE_KEY_MISSING -> "Файл ключа сертификата не найден"
    DeepDiagnosticFindingCode.CERTIFICATE_EXPIRED -> "Срок действия сертификата истёк"
    DeepDiagnosticFindingCode.CERTIFICATE_NOT_YET_VALID -> "Сертификат ещё не вступил в силу"
    DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE -> "Часть диагностических данных недоступна"
}

private fun identityDriftLabel(field: ManagementIdentityDrift) = when (field) {
    ManagementIdentityDrift.SERVICE_UNIT_ABSENT -> "Служба установки не найдена."
    ManagementIdentityDrift.BINARY_PATH_ABSENT -> "Программа установки не найдена по сохранённому пути."
    ManagementIdentityDrift.ROOT_PATH_ABSENT -> "Каталог установки не найден."
    ManagementIdentityDrift.DATABASE_PATH_ABSENT -> "База данных установки не найдена."
    ManagementIdentityDrift.MANAGED_MARKER_ABSENT -> "Метка управляемой установки не найдена."
    ManagementIdentityDrift.MANAGED_MARKER_MISMATCH -> "Метка управляемой установки отличается от сохранённой."
}

private fun baselineDriftLabel(field: ManagementBaselineDrift) = when (field) {
    ManagementBaselineDrift.PANEL_PORT -> "Порт панели изменился."
    ManagementBaselineDrift.WEB_BASE_PATH -> "Путь панели изменился."
    ManagementBaselineDrift.LISTEN_ADDRESS -> "Адрес прослушивания панели изменился."
    ManagementBaselineDrift.EXPECTED_LISTENER_ABSENT -> "На ожидаемом порту нет слушающей панели."
}

private fun evidenceGapLabel(gap: ManagementEvidenceGap) = when (gap) {
    ManagementEvidenceGap.SERVICE_UNIT_UNOBSERVED -> "Наличие службы не удалось проверить."
    ManagementEvidenceGap.BINARY_PATH_UNOBSERVED -> "Наличие программы не удалось проверить."
    ManagementEvidenceGap.ROOT_PATH_UNOBSERVED -> "Каталог установки не удалось проверить."
    ManagementEvidenceGap.DATABASE_PATH_UNOBSERVED -> "Наличие базы данных не удалось проверить."
    ManagementEvidenceGap.MANAGED_MARKER_UNOBSERVED -> "Метка управляемой установки не проверена."
    ManagementEvidenceGap.SERVICE_STATE_UNOBSERVED -> "Состояние службы не удалось получить."
    ManagementEvidenceGap.PANEL_SETTINGS_UNOBSERVED -> "Настройки панели не удалось прочитать."
    ManagementEvidenceGap.LISTENER_UNOBSERVED -> "Ожидаемый порт панели не удалось проверить."
    ManagementEvidenceGap.CONFLICTING_EVIDENCE -> "Получены противоречивые данные."
}
