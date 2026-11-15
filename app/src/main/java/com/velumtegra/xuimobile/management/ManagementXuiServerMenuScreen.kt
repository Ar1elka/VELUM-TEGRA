package com.velumtegra.xuimobile.management

import android.view.Window
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.ui.Alignment
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.velumtegra.xuimobile.core.ssh.XuiServerMenuChannel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val SERVER_OUTPUT_LIMIT = 16_384

@Composable
internal fun ManagementXuiServerMenuScreen(
    serverId: String,
    installationId: String,
    accessId: String,
    menu: ManagementXuiServerMenu,
    window: Window,
    onBack: () -> Unit,
) {
    BackHandler(onBack = onBack)
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    var reviewed by remember(serverId, installationId, accessId) { mutableStateOf<ManagementRestartReview?>(null) }
    var reviewLoaded by remember(serverId, installationId, accessId) { mutableStateOf(false) }
    var requested by remember { mutableStateOf(false) }
    var sessionJob by remember { mutableStateOf<Job?>(null) }
    var sendJob by remember { mutableStateOf<Job?>(null) }
    var channel by remember { mutableStateOf<XuiServerMenuChannel?>(null) }
    var transcript by remember { mutableStateOf("") }
    var turnOutput by remember { mutableStateOf("") }
    var status by remember { mutableStateOf<String?>(null) }
    var response by remember { mutableStateOf("") }
    var reveal by remember { mutableStateOf(false) }
    var showOutput by remember { mutableStateOf(false) }
    var manualInput by remember { mutableStateOf(false) }
    var sending by remember { mutableStateOf(false) }
    var pendingChoice by remember { mutableStateOf<XuiMenuChoice?>(null) }
    val prompt = remember(turnOutput) { xuiMenuPrompt(turnOutput) }
    val choices = prompt?.choices.orEmpty()
    val mainMenu = remember(prompt) { xuiMainMenu(prompt) }
    val sections = remember(prompt) { xuiMenuSections(prompt) }
    val serviceSummary = remember(mainMenu, turnOutput) {
        if (mainMenu) russianXuiStatus(turnOutput) else emptyList()
    }

    fun clearSession() {
        sendJob?.cancel()
        sessionJob?.cancel()
        channel = null
        transcript = ""
        turnOutput = ""
        response = ""
        reveal = false
        showOutput = false
        manualInput = false
        pendingChoice = null
    }

    DisposableEffect(lifecycleOwner, window) {
        val secureFlag = WindowManager.LayoutParams.FLAG_SECURE
        val alreadySecure = window.attributes.flags and secureFlag != 0
        window.addFlags(secureFlag)
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                clearSession()
                status = null
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            sendJob?.cancel()
            sessionJob?.cancel()
            if (!alreadySecure) window.clearFlags(secureFlag)
        }
    }

    LaunchedEffect(serverId, installationId, accessId) {
        reviewed = menu.review(serverId, installationId, accessId)
        reviewLoaded = true
    }

    fun connect() {
        val selected = reviewed ?: return
        if (requested) return
        transcript = ""
        status = "Подключение по SSH…"
        requested = true
        sessionJob = scope.launch {
            try {
                status = menu.open(selected) { opened ->
                    withContext(Dispatchers.Main.immediate) {
                        channel = opened
                        status = null
                        while (true) {
                            val chunk = opened.readAvailable() ?: break
                            if (chunk.isEmpty()) {
                                delay(100)
                            } else {
                                transcript = (transcript + chunk).takeLast(SERVER_OUTPUT_LIMIT)
                                turnOutput = (turnOutput + chunk).takeLast(SERVER_OUTPUT_LIMIT)
                            }
                        }
                    }
                }
            } finally {
                sendJob?.cancel()
                channel = null
                turnOutput = ""
                response = ""
                reveal = false
                manualInput = false
                pendingChoice = null
                requested = false
            }
        }
    }

    fun submit(value: String, interrupt: Boolean = false) {
        val active = channel ?: return
        if (sending || value.length > 1_024 || value.any { it.isISOControl() }) return
        sending = true
        pendingChoice = null
        turnOutput = ""
        response = ""
        reveal = false
        manualInput = false
        showOutput = false
        sendJob = scope.launch {
            try {
                if (interrupt) active.interrupt() else active.sendLine(value)
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                if (channel === active) {
                    sessionJob?.cancel()
                    status = "Связь прервана во время отправки. Проверьте результат на сервере."
                }
            } finally {
                sending = false
            }
        }
    }

    // The x-ui main menu is ~30 commands long: show its groups folded, one open at a time.
    var openSection by remember { mutableStateOf<String?>(null) }
    val exitChoice = if (mainMenu) choices.firstOrNull { it.number == "0" && it.label == "Exit Script" } else null
    val shownSections = if (mainMenu) sections.filter { section -> section.choices.any { it != exitChoice } } else sections

    Column(
        Modifier.fillMaxSize().safeDrawingPadding().imePadding().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(onClick = onBack) { Text("‹ Назад") }
            Text("Команды x-ui", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f))
        }
        reviewed?.let { Text(it.serverName + " · " + it.sshLabel, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant) }
        status?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        if (serviceSummary.isNotEmpty()) {
            Text(serviceSummary.joinToString(" · "), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
        }
        if (channel == null && !requested) {
            if (reviewed != null) {
                Text("Это штатное меню x-ui на сервере. Его команды меняют настройки и службы, поэтому каждая выполняется после подтверждения.")
                Button(onClick = ::connect, modifier = Modifier.fillMaxWidth().testTag("management_xui_menu_connect")) { Text("Открыть меню") }
            } else {
                Text(if (reviewLoaded) "Выбранный SSH-профиль недоступен." else "Загрузка SSH-профиля…")
            }
        }

        // Interrupting only makes sense while a command is running, not while a menu waits for a choice.
        if (channel != null && choices.isEmpty()) {
            TextButton(onClick = { submit("", interrupt = true) }, enabled = !sending) { Text("Прервать команду") }
        }

        if (channel != null && choices.isEmpty()) {
            prompt?.let { Text(russianXuiPrompt(it.text)) }
            if (prompt != null && xuiMenuReturnPrompt(prompt.text)) {
                OutlinedButton(onClick = { submit("") }, enabled = !sending) { Text("Вернуться в меню") }
            } else if (prompt?.yesNo == true) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { submit("y") }, enabled = !sending) { Text("Да") }
                    OutlinedButton(onClick = { submit("n") }, enabled = !sending) { Text("Нет") }
                    TextButton(onClick = { submit("") }, enabled = !sending) {
                        Text(xuiEmptyReplyLabel(prompt.text))
                    }
                }
            } else if (prompt != null || manualInput) {
                val masked = xuiPromptMasksInput(prompt?.text)
                OutlinedTextField(
                    value = response,
                    onValueChange = { response = it.take(1_024).filterNot { ch -> ch.isISOControl() } },
                    label = { Text("Ответ серверу") },
                    singleLine = true,
                    enabled = !sending,
                    modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = if (masked) KeyboardType.Password else KeyboardType.Text),
                    visualTransformation = if (!masked || reveal) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = if (masked) {
                        { TextButton(onClick = { reveal = !reveal }) { Text(if (reveal) "Скрыть" else "Показать") } }
                    } else null,
                )
                OutlinedButton(onClick = { submit(response) }, enabled = !sending) {
                    Text(if (response.isEmpty()) xuiEmptyReplyLabel(prompt?.text) else "Отправить")
                }
            } else if (turnOutput.isNotBlank()) {
                TextButton(onClick = { manualInput = true }) { Text("Ввести ответ") }
            }
        }

        if (choices.isNotEmpty() && transcript.isNotBlank()) {
            TextButton(onClick = { showOutput = !showOutput }) {
                Text(if (showOutput) "Вернуться к командам" else "Ответ сервера")
            }
        }

        LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            if (!showOutput) shownSections.forEach { section ->
                val foldable = mainMenu && shownSections.size > 1
                val open = !foldable || openSection == section.title
                item(key = "section_" + section.title) {
                    if (foldable) {
                        Button(
                            onClick = { openSection = if (open) null else section.title },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant,
                                contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            ),
                            modifier = Modifier.fillMaxWidth().testTag("management_xui_menu_section_" + section.title),
                        ) {
                            Text(section.title, modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
                            Text(if (open) "▴" else section.choices.size.toString() + "  ▾")
                        }
                    } else {
                        Text(
                            section.title,
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.padding(top = 8.dp, bottom = 2.dp),
                        )
                    }
                }
                if (open) items(section.choices.filter { it != exitChoice }, key = { it.number }) { choice ->
                    OutlinedButton(
                        onClick = {
                            if (choice.number == "0" && choice.label in listOf("Exit Script", "Back to Main Menu")) {
                                submit(choice.number)
                            } else {
                                pendingChoice = choice
                            }
                        },
                        enabled = !sending,
                        modifier = Modifier.fillMaxWidth().testTag("management_xui_menu_option_" + choice.number),
                    ) {
                        Text(russianXuiChoice(choice, mainMenu), modifier = Modifier.weight(1f))
                    }
                }
            }
            if (!showOutput && exitChoice != null) item(key = "exit") {
                TextButton(onClick = { submit(exitChoice.number) }, enabled = !sending,
                    modifier = Modifier.fillMaxWidth().testTag("management_xui_menu_option_0")) { Text("Закрыть меню x-ui") }
            }
            if (transcript.isNotBlank() && (choices.isEmpty() || showOutput)) item {
                val output = remember(transcript) { cleanXuiMenuOutput(transcript).trim() }
                Text(output, style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    pendingChoice?.let { choice ->
        AlertDialog(
            onDismissRequest = { pendingChoice = null },
            title = { Text(russianXuiChoice(choice, mainMenu) + "?") },
            text = { reviewed?.let { Text("Команда выполнится на сервере " + it.serverName + ".") } },
            confirmButton = {
                Button(onClick = {
                    if (choice in choices) submit(choice.number) else pendingChoice = null
                }) { Text("Выполнить") }
            },
            dismissButton = {
                TextButton(onClick = { pendingChoice = null }) { Text("Отмена") }
            },
        )
    }
}
