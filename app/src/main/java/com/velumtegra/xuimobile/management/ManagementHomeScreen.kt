package com.velumtegra.xuimobile.management

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.velumtegra.xuimobile.core.model.ExistingInstallationServiceAction
import com.velumtegra.xuimobile.core.ssh.XuiPanelTlsResult
import com.velumtegra.xuimobile.readiness.LiveSshConnectionPolicy
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

@Composable
fun ManagementHomeScreen(
    viewModel: ManagementHomeViewModel,
    launcher: VisibleManagementInspectionsPort,
    onBack: () -> Unit,
    onDetails: () -> Unit,
    onSshProfiles: (String) -> Unit,
    onWebPanels: () -> Unit,
    onRestart: ((String) -> Unit)? = null,
    onHistory: (() -> Unit)? = null,
    onServiceLogs: ((String) -> Unit)? = null,
    onUpdatePreparation: ((String) -> Unit)? = null,
    onBackup: ((String) -> Unit)? = null,
    onStartService: ((String) -> Unit)? = null,
    onStopService: ((String) -> Unit)? = null,
    onExtraServiceAction: ((String, ExistingInstallationServiceAction) -> Unit)? = null,
    readPanelTls: (suspend (String) -> XuiPanelTlsResult)? = null,
    onServerMenu: ((String) -> Unit)? = null,
    readPanelCredentials: (suspend (String) -> com.velumtegra.xuimobile.core.ssh.XuiInstallResultRead)? = null,
    panelAccessDialog: (@Composable (accessId: String, onDismiss: () -> Unit) -> Unit)? = null,
) {
    BackHandler(onBack = onBack)
    val state by viewModel.state.collectAsState()
    var showAdvanced by rememberSaveable { mutableStateOf(false) }
    var tlsAccessId by remember { mutableStateOf<String?>(null) }
    var credentialsAccessId by remember { mutableStateOf<String?>(null) }
    var panelAccessId by remember { mutableStateOf<String?>(null) }
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner, viewModel) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> viewModel.enterForeground()
                Lifecycle.Event.ON_STOP -> viewModel.leaveForeground()
                else -> Unit
            }
        }
        owner.lifecycle.addObserver(observer)
        onDispose {
            owner.lifecycle.removeObserver(observer)
            viewModel.leaveForeground()
        }
    }
    BoxWithConstraints(
        modifier = Modifier.fillMaxSize().safeDrawingPadding().testTag("management_home_root"),
        contentAlignment = Alignment.TopCenter,
    ) {
        val wide = maxWidth >= 720.dp
        Column(
            modifier = Modifier.widthIn(max = 1040.dp).fillMaxSize()
                .verticalScroll(rememberScrollState()).padding(if (wide) 28.dp else 18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedButton(onClick = onBack, modifier = Modifier.testTag("management_home_back")) {
                    Text("‹ Назад")
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text("Управление 3x-ui", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                }
            }
            when (val local = state.local) {
                LocalManagementReview.Loading -> Card(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.padding(20.dp),
                        horizontalArrangement = Arrangement.spacedBy(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        CircularProgressIndicator()
                        Text("Читаем сохранённые сведения…", modifier = Modifier.testTag("management_home_loading"))
                    }
                }
                is LocalManagementReview.Unavailable -> Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                ) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("Установка недоступна", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        Text(local.reason, modifier = Modifier.testTag("management_home_unavailable"))
                        OutlinedButton(onClick = viewModel::refreshLocal) { Text("Обновить сведения") }
                    }
                }
                is LocalManagementReview.Ready -> {
                    val busy = state.launching || state.versionLoading
                    // 1. Where we are and how the panel is doing — the answer most visits come for.
                    Surface(
                        shape = MaterialTheme.shapes.large,
                        color = MaterialTheme.colorScheme.primaryContainer,
                        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    ) {
                        Column(Modifier.fillMaxWidth().padding(20.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(local.serverName, style = MaterialTheme.typography.titleMedium,
                                modifier = Modifier.testTag("management_home_server"))
                            Text(
                                serviceStateLabel(state.result?.serviceState),
                                style = MaterialTheme.typography.headlineSmall,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.testTag("management_home_service"),
                            )
                            Text(
                                (state.result?.observedAt?.let { "Проверено " + checkedTime(it) + " · " } ?: "") +
                                    "порт панели " + local.panelPort,
                                style = MaterialTheme.typography.bodySmall,
                            )
                            Button(
                                onClick = { viewModel.requestAction(ManagementHomeAction.QUICK_INSPECT) },
                                enabled = state.canRequest,
                                modifier = Modifier.fillMaxWidth().testTag("management_home_quick"),
                            ) { Text("Проверить состояние") }
                        }
                    }
                    if (busy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    state.notice?.let { NoticeCard(it, "management_home_notice") }
                    state.versionError?.let { NoticeCard(it, "management_home_version_error") }
                    state.result?.let { result ->
                        Card(
                            modifier = Modifier.fillMaxWidth().testTag("management_home_result"),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                        ) {
                            Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text("Результат проверки", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                                InspectionReportContent(result)
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    OutlinedButton(onClick = viewModel::refreshResult, modifier = Modifier.weight(1f)
                                        .testTag("management_home_refresh_result")) { Text("Обновить") }
                                    if (result.terminal) OutlinedButton(onClick = viewModel::clearResult,
                                        modifier = Modifier.weight(1f)) { Text("Скрыть") }
                                }
                            }
                        }
                    }
                    if (state.unfinished.isNotEmpty()) Card(modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("Незавершённые проверки", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                            state.unfinished.forEach { operation ->
                                OutlinedButton(
                                    onClick = { viewModel.observeExisting(operation.operationId) },
                                    modifier = Modifier.fillMaxWidth().testTag("management_home_observe_" + operation.operationId),
                                ) {
                                    Text(inspectionTitle(operation.kind) + " · " + checkedTime(operation.startedAt))
                                }
                            }
                        }
                    }
                    // A lone saved profile is selected automatically, so the picker is only shown when there is a choice.
                    if (state.accesses.size != 1 || state.selectedAccess == null) Card(modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("Через какой SSH-профиль работать", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                            if (state.accesses.isEmpty()) Text("Нет доступного профиля управления.")
                            state.accesses.forEach { access ->
                                val selected = state.selectedAccessId == access.accessId
                                Surface(
                                    modifier = Modifier.fillMaxWidth().testTag("management_home_access_" + access.accessId)
                                        .selectable(
                                            selected = selected, role = Role.RadioButton,
                                            enabled = !busy && state.pending == null,
                                            onClick = { viewModel.selectAccess(access.accessId) },
                                        ),
                                    shape = MaterialTheme.shapes.medium,
                                    color = if (selected) MaterialTheme.colorScheme.secondaryContainer
                                        else MaterialTheme.colorScheme.surfaceVariant,
                                    border = if (selected) BorderStroke(1.dp, MaterialTheme.colorScheme.primary) else null,
                                ) {
                                    Row(
                                        Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                    ) {
                                        RadioButton(selected = selected, onClick = null)
                                        Column(Modifier.weight(1f)) {
                                            Text(LiveSshConnectionPolicy.exactTarget(access), fontWeight = FontWeight.SemiBold)
                                            Text(if (access.authLabel.startsWith("Пароль")) "Вход по паролю" else "Вход по SSH-ключу",
                                                style = MaterialTheme.typography.bodySmall)
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // 2. The panel itself.
                    SectionTitle("Панель")
                    Button(onClick = onWebPanels, modifier = Modifier.fillMaxWidth()
                        .testTag("management_home_webpanels")) { Text("Открыть веб-панель") }
                    if (panelAccessDialog != null || readPanelCredentials != null) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            if (readPanelCredentials != null) OutlinedButton(
                                onClick = { credentialsAccessId = state.selectedAccessId },
                                enabled = state.canRequest,
                                modifier = Modifier.weight(1f).testTag("management_home_credentials"),
                            ) { Text("Логин и пароль", textAlign = TextAlign.Center) }
                            if (panelAccessDialog != null) OutlinedButton(
                                onClick = { panelAccessId = state.selectedAccessId },
                                enabled = state.canRequest,
                                modifier = Modifier.weight(1f).testTag("management_home_panel_access"),
                            ) { Text("Доступ к панели", textAlign = TextAlign.Center) }
                        }
                    }

                    // 3. Service control: paired so the whole block fits on one screen.
                    SectionTitle("Служба")
                    if (onStartService != null && onStopService != null) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = { state.selectedAccessId?.let(onStartService) },
                                enabled = state.canRequest,
                                modifier = Modifier.weight(1f).testTag("management_home_start"),
                            ) { Text("Запустить") }
                            OutlinedButton(
                                onClick = { state.selectedAccessId?.let(onStopService) },
                                enabled = state.canRequest,
                                modifier = Modifier.weight(1f).testTag("management_home_stop"),
                            ) { Text("Остановить") }
                        }
                    }
                    if (onRestart != null || onExtraServiceAction != null) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            if (onRestart != null) OutlinedButton(
                                onClick = { state.selectedAccessId?.let(onRestart) },
                                enabled = state.canRequest,
                                modifier = Modifier.weight(1f).testTag("management_home_restart"),
                            ) { Text("Перезапустить", textAlign = TextAlign.Center) }
                            if (onExtraServiceAction != null) OutlinedButton(
                                onClick = { state.selectedAccessId?.let { onExtraServiceAction(it, ExistingInstallationServiceAction.XRAY_RESTART) } },
                                enabled = state.canRequest,
                                modifier = Modifier.weight(1f).testTag("management_home_restart_xray"),
                            ) { Text("Перезапустить Xray", textAlign = TextAlign.Center) }
                        }
                    }
                    if (onServiceLogs != null || onBackup != null) {
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            if (onServiceLogs != null) OutlinedButton(
                                onClick = { state.selectedAccessId?.let(onServiceLogs) },
                                enabled = state.canRequest,
                                modifier = Modifier.weight(1f).testTag("management_home_service_logs"),
                            ) { Text("Журнал", textAlign = TextAlign.Center) }
                            if (onBackup != null) OutlinedButton(
                                onClick = { state.selectedAccessId?.let(onBackup) }, enabled = state.canRequest,
                                modifier = Modifier.weight(1f).testTag("management_home_backup"),
                            ) { Text("Резервная копия", textAlign = TextAlign.Center) }
                        }
                    }

                    // 4. Everything rare.
                    TextButton(
                        onClick = { showAdvanced = !showAdvanced },
                        modifier = Modifier.fillMaxWidth().testTag("management_home_advanced"),
                    ) { Text(if (showAdvanced) "Скрыть дополнительное" else "Дополнительно") }
                    if (showAdvanced) {
                        if (onServerMenu != null) OutlinedButton(
                            onClick = { state.selectedAccessId?.let(onServerMenu) },
                            enabled = state.canRequest,
                            modifier = Modifier.fillMaxWidth().testTag("management_home_server_menu"),
                        ) { Text("Все команды x-ui") }
                        if (readPanelTls != null) OutlinedButton(
                            onClick = { tlsAccessId = state.selectedAccessId },
                            enabled = state.canRequest,
                            modifier = Modifier.fillMaxWidth().testTag("management_home_tls"),
                        ) { Text("Сертификат TLS") }
                        if (onExtraServiceAction != null) {
                            Text("Автозапуск при загрузке сервера", style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(
                                    onClick = { state.selectedAccessId?.let { onExtraServiceAction(it, ExistingInstallationServiceAction.ENABLE_AUTOSTART) } },
                                    enabled = state.canRequest,
                                    modifier = Modifier.weight(1f).testTag("management_home_enable_autostart"),
                                ) { Text("Включить") }
                                OutlinedButton(
                                    onClick = { state.selectedAccessId?.let { onExtraServiceAction(it, ExistingInstallationServiceAction.DISABLE_AUTOSTART) } },
                                    enabled = state.canRequest,
                                    modifier = Modifier.weight(1f).testTag("management_home_disable_autostart"),
                                ) { Text("Выключить") }
                            }
                        }
                        VersionFactCard(state, Modifier.fillMaxWidth())
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = { viewModel.requestAction(ManagementHomeAction.READ_VERSION) },
                                enabled = state.canRequest,
                                modifier = Modifier.weight(1f).testTag("management_home_version"),
                            ) { Text("Узнать версию", textAlign = TextAlign.Center) }
                            if (onUpdatePreparation != null) OutlinedButton(
                                onClick = { state.selectedAccessId?.let(onUpdatePreparation) },
                                enabled = state.canRequest,
                                modifier = Modifier.weight(1f).testTag("management_home_update_preparation"),
                            ) { Text("Обновление", textAlign = TextAlign.Center) }
                        }
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = { viewModel.requestAction(ManagementHomeAction.DEEP_DIAGNOSTIC) },
                                enabled = state.canRequest,
                                modifier = Modifier.weight(1f).testTag("management_home_deep"),
                            ) { Text("Диагностика", textAlign = TextAlign.Center) }
                            onHistory?.let { openHistory ->
                                OutlinedButton(onClick = openHistory, modifier = Modifier.weight(1f)
                                    .testTag("management_home_history")) { Text("История проверок", textAlign = TextAlign.Center) }
                            }
                        }
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = onDetails, modifier = Modifier.weight(1f)
                                .testTag("management_home_details")) { Text("Об установке", textAlign = TextAlign.Center) }
                            OutlinedButton(onClick = { onSshProfiles(local.serverName) }, modifier = Modifier.weight(1f)
                                .testTag("management_home_profiles")) { Text("SSH-профили", textAlign = TextAlign.Center) }
                        }
                        TextButton(
                            onClick = viewModel::refreshLocal, enabled = !busy,
                            modifier = Modifier.fillMaxWidth().testTag("management_home_refresh_local"),
                        ) { Text("Перечитать сохранённые сведения") }
                    }
                }
            }
        }
    }
    credentialsAccessId?.let { accessId ->
        val host = state.accesses.singleOrNull { it.accessId == accessId }?.host
            ?: (state.local as? LocalManagementReview.Ready)?.serverName.orEmpty()
        if (readPanelCredentials != null) ManagementPanelCredentialsDialog(
            serverHost = host,
            read = { readPanelCredentials(accessId) },
            onDismiss = { credentialsAccessId = null },
        )
    }
    panelAccessId?.let { accessId ->
        panelAccessDialog?.invoke(accessId) { panelAccessId = null }
    }
    tlsAccessId?.let { accessId ->
        if (readPanelTls != null) ManagementPanelTlsDialog(
            read = { readPanelTls(accessId) },
            onDismiss = { tlsAccessId = null },
        )
    }
    state.pending?.let { review ->
        AlertDialog(
            onDismissRequest = viewModel::dismissReview,
            title = { Text(actionTitle(review.action)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(review.installation.serverName, fontWeight = FontWeight.Bold)
                    Text(LiveSshConnectionPolicy.exactTarget(review.access))
                    Text("Служба: " + review.installation.serviceUnit)
                    Text("Разрешить одну проверку по SSH? Она читает состояние выбранной установки и не меняет настройки VPS.")
                }
            },
            confirmButton = {
                Button(onClick = { viewModel.confirmAction(launcher) },
                    modifier = Modifier.testTag("management_home_confirm")) { Text("Разрешить проверку") }
            },
            dismissButton = {
                OutlinedButton(onClick = viewModel::dismissReview,
                    modifier = Modifier.testTag("management_home_cancel")) { Text("Отмена") }
            },
        )
    }
}

@Composable
private fun VersionFactCard(state: ManagementHomeState, modifier: Modifier) {
    Card(modifier = modifier) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Версия панели", style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(state.version ?: "Ещё не запрошена", style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold, modifier = Modifier.testTag("management_home_version_value"))
            Text(state.versionObservedAt?.let { "Получена с VPS · " + checkedTime(it) }
                ?: "Версия запрашивается отдельной проверкой.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
}

@Composable
private fun NoticeCard(text: String, tag: String) {
    Surface(shape = MaterialTheme.shapes.medium, color = MaterialTheme.colorScheme.errorContainer) {
        Text(text, modifier = Modifier.fillMaxWidth().padding(16.dp).testTag(tag))
    }
}

private fun checkedTime(time: Instant): String = DateTimeFormatter
    .ofPattern("dd.MM · HH:mm:ss", Locale.getDefault()).withZone(ZoneId.systemDefault()).format(time)

private fun inspectionTitle(kind: InspectionKind): String = when (kind) {
    InspectionKind.QUICK_INSPECT -> "Состояние 3x-ui"
    InspectionKind.DEEP_DIAGNOSTIC -> "Диагностика"
}

private fun actionTitle(action: ManagementHomeAction): String = when (action) {
    ManagementHomeAction.QUICK_INSPECT -> "Проверить состояние 3x-ui?"
    ManagementHomeAction.DEEP_DIAGNOSTIC -> "Выполнить диагностику?"
    ManagementHomeAction.READ_VERSION -> "Прочитать версию 3x-ui?"
}
