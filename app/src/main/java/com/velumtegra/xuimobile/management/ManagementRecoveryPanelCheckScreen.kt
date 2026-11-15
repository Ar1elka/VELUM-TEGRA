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

@Composable fun ManagementRecoveryPanelCheckScreen(model: ManagementRecoveryPanelCheckViewModel, onBack: () -> Unit, onWebPanels: () -> Unit) {
    BackHandler(onBack = onBack); val state by model.state.collectAsState(); val owner = LocalLifecycleOwner.current
    var acknowledged by remember(state.review?.token) { mutableStateOf(false) }
    DisposableEffect(owner, model) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) model.enterForeground()
            if (event == Lifecycle.Event.ON_STOP) model.leaveForeground()
        }
        owner.lifecycle.addObserver(observer)
        onDispose { owner.lifecycle.removeObserver(observer); model.leaveForeground() }
    }
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(18.dp).testTag("recovery_panel_root"), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        OutlinedButton(onClick = onBack, modifier = Modifier.testTag("recovery_panel_back")) { Text("‹ Назад") }
        Text("Проверка входа в панель", style = MaterialTheme.typography.headlineSmall, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
        StepIntro(
            step = "После восстановления",
            summary = DetailLine("Выберите сохранённый вход. Приложение один раз войдёт в панель, прочитает её состояние и выйдет.", "recovery_panel_scope"),
            details = listOf(
                DetailLine("Если ответ оборвётся, повторной попытки не будет. При включённой двухфакторной защите войдите в панель вручную.", "recovery_panel_consequence"),
                DetailLine("Успех означает, что в панель можно войти. Работу VPN у клиентов эта проверка не подтверждает.", "recovery_panel_limits"),
            ),
        )
        if (state.loading || state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (!state.loading && state.choices.isEmpty()) Text("Для этой панели нет сохранённых входов. Добавьте вход в разделе веб-панелей.")
        state.choices.forEach { choice ->
            OutlinedButton(onClick = { model.select(choice.accessId) }, enabled = !state.loading && !state.busy,
                modifier = Modifier.fillMaxWidth().testTag("recovery_panel_choice_" + choice.accessId)) {
                Text(choice.username + " · " + choice.route)
            }
        }
        when (val result = state.result) {
            is RecoveryPanelCheckResult.Verified -> Text("Вход в панель работает. Проверено " + humanTime(result.observedAt) + ".",
                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold, modifier = Modifier.testTag("recovery_panel_verified"))
            is RecoveryPanelCheckResult.Unverified -> Text(result.message, color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("recovery_panel_unverified"))
            null -> Unit
        }
        state.notice?.let { Text(it, modifier = Modifier.testTag("recovery_panel_notice")) }
        OutlinedButton(onClick = onWebPanels, enabled = !state.busy, modifier = Modifier.fillMaxWidth().testTag("recovery_panel_inventory")) { Text("Открыть веб-панели") }
        QuietRefresh(model::refresh, !state.busy, "recovery_panel_refresh")
    }
    state.review?.let { review -> AlertDialog(onDismissRequest = model::dismiss, title = { Text("Проверить вход?") }, text = {
        Column(Modifier.heightIn(max = 380.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Логин: " + review.username, modifier = Modifier.testTag("recovery_panel_username"))
            Text(review.route + " · " + review.endpoint, modifier = Modifier.testTag("recovery_panel_route"))
            Text("Приложение один раз отправит сохранённые логин и пароль в панель и прочитает её состояние. При ошибке повтора не будет.")
            review.certificate?.let { Text("Сертификат панели: " + it.take(16) + "…", style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("recovery_panel_pin")) }
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) { Checkbox(checked = acknowledged, onCheckedChange = { acknowledged = it }, modifier = Modifier.testTag("recovery_panel_ack")); Text("Отправить логин и пароль один раз") }
        }
    }, confirmButton = { Button(onClick = model::confirm, enabled = acknowledged && !state.busy, modifier = Modifier.testTag("recovery_panel_confirm")) { Text("Проверить вход") } },
        dismissButton = { OutlinedButton(onClick = model::dismiss, modifier = Modifier.testTag("recovery_panel_dismiss")) { Text("Отмена") } }) }
}
