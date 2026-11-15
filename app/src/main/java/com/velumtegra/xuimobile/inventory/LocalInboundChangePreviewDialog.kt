package com.velumtegra.xuimobile.inventory

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp

/** Offline-only dry run. No API call, repository access, persistence or configuration changes. */
@Composable
internal fun LocalInboundChangePreviewDialog(accessId: String, onDismiss: () -> Unit) {
    var inboundId by remember(accessId) { mutableStateOf("") }
    var currentPort by remember(accessId) { mutableStateOf("") }
    var proposedPort by remember(accessId) { mutableStateOf("") }
    var currentlyEnabled by remember(accessId) { mutableStateOf(true) }
    var proposedEnabled by remember(accessId) { mutableStateOf(true) }
    var preview by remember(accessId) { mutableStateOf<LocalInboundChangeResult?>(null) }
    var otherInboundPorts by remember(accessId) { mutableStateOf("") }
    var safetyReview by remember(accessId) { mutableStateOf<LocalInboundSafetyResult?>(null) }
    var acknowledgedManualData by remember(accessId) { mutableStateOf(false) }
    var showReversePreview by remember(accessId) { mutableStateOf(false) }
    val clearReview = {
        preview = null
        safetyReview = null
        acknowledgedManualData = false
        showReversePreview = false
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Inbound: офлайн-план изменений") },
        text = {
            Column(
                modifier = Modifier.heightIn(max = 440.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(9.dp),
            ) {
                Text("Только локальный черновик. Введите ТЕКУЩИЕ параметры вручную: " +
                    "приложение не считывает и не проверяет их на VPS. " +
                    "Никаких HTTPS/SSH-запросов, записи на сервер и сохранения черновика нет.")
                OutlinedTextField(
                    value = inboundId,
                    onValueChange = { inboundId = it.take(24); clearReview() },
                    label = { Text("ID inbound (вручную)") },
                    singleLine = true,
                    modifier = Modifier.testTag("offline_inbound_id"),
                )
                OutlinedTextField(
                    value = currentPort,
                    onValueChange = { currentPort = it.take(24); clearReview() },
                    label = { Text("Текущий порт (вручную)") },
                    singleLine = true,
                    modifier = Modifier.testTag("offline_inbound_current_port"),
                )
                OutlinedTextField(
                    value = proposedPort,
                    onValueChange = { proposedPort = it.take(24); clearReview() },
                    label = { Text("Предлагаемый порт") },
                    singleLine = true,
                    modifier = Modifier.testTag("offline_inbound_proposed_port"),
                )
                OutlinedTextField(
                    value = otherInboundPorts,
                    onValueChange = { otherInboundPorts = it.take(256); clearReview() },
                    label = { Text("Порты других inbound (вручную, необязательно)") },
                    placeholder = { Text("например: 80, 8443") },
                    singleLine = true,
                    modifier = Modifier.testTag("offline_other_inbound_ports"),
                )
                Text("Этот список вводится вручную: совпадения — только предупреждения. " +
                    "Занятость портов и адреса прослушивания на VPS НЕ проверяются.")
                Row {
                    Checkbox(
                        checked = currentlyEnabled,
                        onCheckedChange = { currentlyEnabled = it; clearReview() },
                        modifier = Modifier.testTag("offline_inbound_current_enabled"),
                    )
                    Text("Сейчас включён (со слов пользователя)")
                }
                Row {
                    Checkbox(
                        checked = proposedEnabled,
                        onCheckedChange = { proposedEnabled = it; clearReview() },
                        modifier = Modifier.testTag("offline_inbound_proposed_enabled"),
                    )
                    Text("После изменения должен быть включён")
                }
                when (val result = preview) {
                    is LocalInboundChangeResult.Invalid -> {
                        val explanation = when (result.issue) {
                            LocalInboundChangeIssue.INVALID_INBOUND_ID ->
                                "Введите положительный числовой ID inbound."
                            LocalInboundChangeIssue.INVALID_CURRENT_PORT ->
                                "Текущий порт: целое число от 1 до 65535."
                            LocalInboundChangeIssue.INVALID_PROPOSED_PORT ->
                                "Новый порт: целое число от 1 до 65535."
                            LocalInboundChangeIssue.NO_CHANGES ->
                                "Изменений нет: текущие и предложенные значения совпадают."
                        }
                        Text(explanation, modifier = Modifier.testTag("offline_inbound_preview_result"))
                    }
                    is LocalInboundChangeResult.Preview -> {
                        Text("ОФЛАЙН-ПЛАН для inbound #${result.inboundId}",
                            modifier = Modifier.testTag("offline_inbound_preview_result"))
                        if (result.portWillChange) {
                            Text("Порт: ${result.currentPort} → ${result.proposedPort}")
                        } else Text("Порт: ${result.currentPort} (без изменений)")
                        if (result.enabledWillChange) {
                            Text("Состояние: " +
                                (if (result.currentlyEnabled) "включён" else "отключён") + " → " +
                                (if (result.proposedEnabled) "включён" else "отключён"))
                        } else Text("Состояние: без изменений")
                        Text("НЕ ПРИМЕНЕНО. Порт может быть занят; реальное состояние сервера, " +
                            "конфликты и доступность клиентов не проверялись.")
                        when (val safety = safetyReview) {
                            is LocalInboundSafetyResult.Invalid -> {
                                val message = when (safety.issue) {
                                    LocalInboundSafetyIssue.INVALID_OTHER_PORTS ->
                                        "Список других портов: укажите числа 1–65535 через запятую " +
                                            "(без повторов, ведущих нулей и постороннего текста)."
                                    LocalInboundSafetyIssue.TOO_MANY_OTHER_PORTS ->
                                        "Для локальной сверки допустимо не больше 24 других портов."
                                    LocalInboundSafetyIssue.DUPLICATE_OTHER_PORT ->
                                        "Список других портов содержит повторяющиеся значения."
                                }
                                Text(message, modifier = Modifier.testTag("offline_port_review_issue"))
                            }
                            is LocalInboundSafetyResult.Review -> {
                                if (safety.possibleProposedPortCollision) {
                                    Text("ВНИМАНИЕ: новый порт указан среди других inbound. " +
                                        "Возможен конфликт; на VPS это не проверялось.",
                                        modifier = Modifier.testTag("offline_proposed_port_warning"))
                                }
                                if (safety.possibleBaselineMismatch) {
                                    Text("ВНИМАНИЕ: текущий порт также указан среди других inbound. " +
                                        "Проверьте вручную исходные данные и адреса прослушивания.",
                                        modifier = Modifier.testTag("offline_baseline_warning"))
                                }
                                if (!safety.possibleProposedPortCollision &&
                                    !safety.possibleBaselineMismatch) {
                                    Text("В ВАШЕМ списке других портов совпадений не найдено. " +
                                        "Это не проверка реального сервера.")
                                }
                                Row {
                                    Checkbox(
                                        checked = acknowledgedManualData,
                                        onCheckedChange = {
                                            acknowledgedManualData = it
                                            showReversePreview = false
                                        },
                                        modifier = Modifier.testTag("offline_manual_review_ack"),
                                    )
                                    Text("Сверил введённые значения вручную. Это НЕ разрешение менять VPS.")
                                }
                                OutlinedButton(
                                    onClick = { showReversePreview = true },
                                    enabled = acknowledgedManualData,
                                    modifier = Modifier.testTag("offline_show_reverse_plan"),
                                ) { Text("Показать обратный локальный план") }
                                if (showReversePreview && acknowledgedManualData) {
                                    val reverse = safety.reversePreview
                                    Text("ОБРАТНЫЙ ПЛАН (НЕ ПРИМЕНЁН) для inbound #${reverse.inboundId}",
                                        modifier = Modifier.testTag("offline_reverse_plan_result"))
                                    Text("Порт: ${reverse.currentPort} → ${reverse.proposedPort}")
                                    Text("Состояние: " +
                                        (if (reverse.currentlyEnabled) "включён" else "отключён") +
                                        " → " +
                                        (if (reverse.proposedEnabled) "включён" else "отключён"))
                                    Text("Это лишь обратное сравнение. Настоящий откат не создан " +
                                        "и сервер не изменён.")
                                }
                            }
                            null -> Unit
                        }
                    }
                    null -> Unit
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val outcome = LocalInboundChangePlanner.preview(
                        LocalInboundChangeInput(
                            inboundId, currentPort, proposedPort,
                            currentlyEnabled, proposedEnabled,
                        ),
                    )
                    preview = outcome
                    safetyReview = if (outcome is LocalInboundChangeResult.Preview) {
                        LocalInboundSafetyReviewer.review(outcome, otherInboundPorts)
                    } else null
                    acknowledgedManualData = false
                    showReversePreview = false
                },
                modifier = Modifier.testTag("offline_inbound_make_preview"),
            ) { Text("Показать план локально") }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss, modifier = Modifier.testTag("offline_inbound_close")) {
                Text("Закрыть без изменений")
            }
        },
    )
}
