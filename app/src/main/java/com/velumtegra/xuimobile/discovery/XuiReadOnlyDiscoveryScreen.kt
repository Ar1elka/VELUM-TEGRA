package com.velumtegra.xuimobile.discovery

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
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
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.velumtegra.xuimobile.core.ssh.XuiObservedServiceState
import com.velumtegra.xuimobile.readiness.LiveSshConnectionPolicy
import com.velumtegra.xuimobile.readiness.LocalSshAccessList
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.readiness.SshReadinessPort
import java.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** One-shot user-approved read-only discovery. Opening screen never connects to the VPS. */
@Composable
fun XuiReadOnlyDiscoveryScreen(
    serverId: String, serverName: String, readinessPort: SshReadinessPort,
    discoveryPort: XuiReadOnlyDiscoveryPort, onBack: () -> Unit,
    enrollmentPort: XuiVerifiedEnrollmentPort? = null, onSaved: () -> Unit = {},
    now: () -> Instant = Instant::now,
    installPort: XuiFreshInstallActionPort? = null,
    /** After a verified install: close the panel to the internet and save a tunnel sign-in. Returns a message. */
    secureAfterInstall: (suspend (serverId: String, accessId: String) -> String)? = null,
) {
    val owner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    var generation by remember(serverId, readinessPort, discoveryPort) { mutableStateOf(0L) }
    var available by remember(serverId, readinessPort) { mutableStateOf<LocalSshAccessList?>(null) }
    var selected by remember(serverId, readinessPort) { mutableStateOf<LocalSshAccessSummary?>(null) }
    var consent by remember(serverId, readinessPort) { mutableStateOf(false) }
    var busy by remember(serverId, readinessPort) { mutableStateOf(false) }
    var result by remember(serverId, readinessPort) { mutableStateOf<XuiReadOnlyDiscoveryResult?>(null) }
    var job by remember(serverId, readinessPort) { mutableStateOf<Job?>(null) }
    var serviceConsent by remember(serverId, readinessPort) { mutableStateOf(false) }
    var serviceBusy by remember(serverId, readinessPort) { mutableStateOf(false) }
    var serviceResult by remember(serverId, readinessPort) { mutableStateOf<XuiServiceVerificationResult?>(null) }
    var versionConsent by remember(serverId, readinessPort) { mutableStateOf(false) }
    var versionBusy by remember(serverId, readinessPort) { mutableStateOf(false) }
    var versionResult by remember(serverId, readinessPort) { mutableStateOf<XuiVersionVerificationResult?>(null) }
    var enrollConsent by remember(serverId, readinessPort) { mutableStateOf(false) }
    var enrollBusy by remember(serverId, readinessPort) { mutableStateOf(false) }
    var enrollReview by remember(serverId, readinessPort) { mutableStateOf<XuiEnrollmentReview?>(null) }
    var enrollSaveConsent by remember(serverId, readinessPort) { mutableStateOf(false) }
    var enrollSaving by remember(serverId, readinessPort) { mutableStateOf(false) }
    var enrollSave by remember(serverId, readinessPort) { mutableStateOf<XuiEnrollmentSave?>(null) }
    var installDialog by remember(serverId, readinessPort) { mutableStateOf(false) }
    var installAck by remember(serverId, readinessPort) { mutableStateOf(false) }
    var installBusy by remember(serverId, readinessPort) { mutableStateOf(false) }
    var installNotice by remember(serverId, readinessPort) { mutableStateOf<String?>(null) }
    var installRecovery by remember(serverId, readinessPort) { mutableStateOf<XuiFreshInstallRecovery?>(null) }
    var installStarted by remember(serverId, readinessPort) { mutableStateOf<XuiFreshInstallObservation?>(null) }
    var installStatusJob by remember(serverId, readinessPort) { mutableStateOf<Job?>(null) }
    // Per operation: the read-only result check and the post-install panel protection run once each, automatically.
    val autoChecked = remember(serverId) { mutableMapOf<String, Long>() }
    val secured = remember(serverId) { mutableSetOf<String>() }
    var secureNotice by remember(serverId) { mutableStateOf<String?>(null) }
    val anyBusy = busy || serviceBusy || versionBusy || enrollBusy || enrollSaving || installBusy
    fun dropEnrollmentReview() {
        (enrollReview as? XuiEnrollmentReview.Ready)?.let { enrollmentPort?.discard(it.reviewToken) }
        enrollReview = null; enrollSaveConsent = false; enrollSave = null
    }
    fun revoke() {
        (enrollReview as? XuiEnrollmentReview.Ready)?.let { enrollmentPort?.discard(it.reviewToken) }
        enrollConsent = false; enrollBusy = false; enrollReview = null
        enrollSaveConsent = false; enrollSaving = false; enrollSave = null
        ++generation
        job?.cancel()
        job = null
        consent = false
        busy = false
        result = null
        serviceConsent = false
        serviceBusy = false
        serviceResult = null
        versionConsent = false
        versionBusy = false
        versionResult = null
        installStatusJob?.cancel()
        installStatusJob = null
        installDialog = false; installAck = false; installBusy = false
        installNotice = null; installRecovery = null; installStarted = null
    }
    fun reload() {
        revoke()
        selected = null
        available = null
        val request = ++generation
        job = scope.launch {
            val list = try { readinessPort.listForExactServer(serverId) }
                catch (cancel: CancellationException) { throw cancel }
                catch (_: Exception) { LocalSshAccessList.Unavailable("Не удалось прочитать SSH-профили.") }
            if (request == generation && owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                available = if (list is LocalSshAccessList.Available &&
                    (list.items.any { it.accessId.isBlank() || it.credentialRefDigest.isBlank() } ||
                     list.items.map { it.accessId }.distinct().size != list.items.size)) {
                    LocalSshAccessList.Unavailable("Список SSH-профилей неоднозначен. Обновите записи.")
                } else list
            }
        }
    }
    DisposableEffect(owner, serverId, readinessPort, discoveryPort) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> reload()
                Lifecycle.Event.ON_STOP -> { revoke(); selected = null; available = null }
                else -> Unit
            }
        }
        owner.lifecycle.addObserver(observer)
        if (owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) reload()
        onDispose { owner.lifecycle.removeObserver(observer); revoke() }
    }
    fun runInitialCheck(choice: LocalSshAccessSummary, check: suspend () -> XuiReadOnlyDiscoveryResult) {
        if (anyBusy || !consent || selected != choice ||
            !owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return
        val request = ++generation
        dropEnrollmentReview()
        busy = true
        consent = false
        result = null
        serviceConsent = false; serviceResult = null
        versionConsent = false; versionResult = null
        enrollConsent = false
        installDialog = false; installAck = false; installNotice = null
        job = scope.launch {
            val answer = try {
                check()
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                XuiReadOnlyDiscoveryResult.Blocked("Не удалось выполнить проверку.")
            }
            if (request == generation && selected == choice &&
                owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                busy = false
                result = answer
            }
        }
    }
    /** Local journal read only: never opens SSH. Re-run after every install action. */
    fun refreshInstall(choice: LocalSshAccessSummary) {
        val port = installPort ?: return
        installStatusJob?.cancel()
        val request = generation
        val current = installStarted
        installStatusJob = scope.launch {
            val recovery = try { port.recoverExact(serverId, choice) }
                catch (cancel: CancellationException) { throw cancel } catch (_: Exception) { null }
            val started = current?.let { current ->
                try { port.statusExact(current.operationId, serverId, choice) }
                    catch (cancel: CancellationException) { throw cancel } catch (_: Exception) { null }
            }
            if (request == generation && selected == choice &&
                owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                installRecovery = recovery
                if (installStarted == current && started != null) installStarted = started
                val items = listOfNotNull(installStarted) + recovery?.own.orEmpty()
                // The installer runs detached on the VPS; once it may have finished, confirm it read-only by itself.
                val nowMillis = System.currentTimeMillis()
                items.firstOrNull {
                    it.mayCheckReadOnly && nowMillis - (autoChecked[it.operationId] ?: 0L) >= AUTO_CHECK_INTERVAL_MS
                }?.let { item ->
                    autoChecked[item.operationId] = nowMillis
                    val message = try { port.checkResultConfirmed(item.operationId, serverId, choice) }
                        catch (cancel: CancellationException) { throw cancel } catch (_: Exception) { null }
                    if (message == null) installNotice = "Проверяем результат установки…"
                }
                val done = items.firstOrNull { it.succeeded && secured.add(it.operationId) }
                if (done != null && secureAfterInstall != null) {
                    secureNotice = "Закрываем панель от интернета и сохраняем вход через SSH…"
                    // Not tied to installStatusJob: a status refresh must not cancel the protection midway.
                    scope.launch {
                        secureNotice = try { secureAfterInstall.invoke(serverId, choice.accessId) }
                            catch (cancel: CancellationException) { throw cancel }
                            catch (_: Exception) { "Не удалось защитить панель автоматически. Откройте «Доступ к панели» в управлении." }
                    }
                }
            }
        }
    }
    LaunchedEffect(selected, installPort) { selected?.let { refreshInstall(it) } }
    // Keep the local journal view fresh while an install is still in progress (local reads only).
    val pending = (listOfNotNull(installStarted) + installRecovery?.own.orEmpty()).any { !it.terminal }
    LaunchedEffect(selected, pending, installStarted, installRecovery) {
        val choice = selected ?: return@LaunchedEffect
        if (!pending) return@LaunchedEffect
        kotlinx.coroutines.delay(INSTALL_POLL_MS)
        refreshInstall(choice)
    }
    fun close() { revoke(); onBack() }
    BackHandler { close() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp)
        .testTag("xui_discovery_screen"), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Найти 3x-ui на VPS", style = MaterialTheme.typography.titleLarge)
        Text("Сервер: $serverName")
        Text("Доступ только по вашему подтверждению: одна SSH-сессия, строго разрешённые read-only команды. " +
            "Никаких установок, изменений настроек или автоматических привязок в базе.")
        Text("1. Выберите SSH-доступ", style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.testTag("xui_connect_step_access"))
        OutlinedButton(onClick = { reload() }, enabled = !anyBusy,
            modifier = Modifier.testTag("xui_discovery_refresh")) { Text("Обновить SSH-доступы") }
        when (val state = available) {
            null -> Text("Загружаем локальные SSH-профили…")
            is LocalSshAccessList.Unavailable -> Text(state.reason,
                color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("xui_discovery_error"))
            is LocalSshAccessList.Available -> {
                if (state.items.isEmpty()) Text("Добавьте SSH-доступ в карточке сервера.")
                state.items.forEach { item ->
                    OutlinedButton(enabled = !anyBusy, modifier = Modifier.fillMaxWidth()
                        .testTag("xui_discovery_select_${item.accessId}"), onClick = {
                        revoke(); selected = null
                        val request = ++generation
                        job = scope.launch {
                            val checked = try { readinessPort.previewExact(serverId, item.accessId) }
                                catch (cancel: CancellationException) { throw cancel }
                                catch (_: Exception) { LocalSshReadinessResult.Blocked("Нет локальных сведений.") }
                            if (request == generation && owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                if (checked is LocalSshReadinessResult.MetadataPresent &&
                                    checked.summary.copy(authLabel = item.authLabel) == item) selected = checked.summary
                                else result = XuiReadOnlyDiscoveryResult.Blocked("SSH-доступ изменился. Обновите список.")
                            }
                        }
                    }) { Text("${item.username}@${item.host}:${item.port} · ${item.authLabel}") }
                }
            }
        }
        val choice = selected
        if (choice != null) {
            Text("2. Проверьте установленную панель", style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.testTag("xui_connect_step_discovery"))
            Text("Цель: ${LiveSshConnectionPolicy.exactTarget(choice)}")
            Text("Закреплённый SSH-ключ: ${choice.savedFingerprint}")
            Text("Перед проверкой сравните ключ сервера с независимым источником.")
            Row {
                Checkbox(checked = consent, enabled = !anyBusy, onCheckedChange = { consent = it; result = null; dropEnrollmentReview() },
                    modifier = Modifier.testTag("xui_discovery_consent"))
                Text("Разрешаю одну сетевую SSH-проверку с read-only командами. Без изменений VPS.")
            }
            val exactTarget = LiveSshConnectionPolicy.exactTarget(choice)
            Button(modifier = Modifier.testTag("xui_discovery_start"),
                enabled = !anyBusy && consent,
                onClick = {
                    runInitialCheck(choice) {
                        discoveryPort.inspectExact(serverId, choice.accessId, choice, exactTarget, true)
                    }
                }) { Text(if (busy) "Проверяем…" else "Найти X-UI (только чтение)") }
            if (discoveryPort.supportsFreshInstallReadiness) {
                OutlinedButton(
                    modifier = Modifier.testTag("xui_fresh_install_readiness_start"),
                    enabled = !anyBusy && consent,
                    onClick = {
                        runInitialCheck(choice) {
                            discoveryPort.checkFreshInstallReadiness(serverId, choice.accessId, choice, exactTarget, true)
                        }
                    },
                ) { Text("Проверить готовность к новой установке") }
            }
            if (busy) OutlinedButton(onClick = { revoke() },
                modifier = Modifier.testTag("xui_discovery_cancel")) { Text("Отменить") }
            if (installPort != null) {
                val ready = (result as? XuiReadOnlyDiscoveryResult.Observation)?.freshInstallReady == true
                val tracked = listOfNotNull(installStarted) +
                    (installRecovery?.own.orEmpty().filter { it.operationId != installStarted?.operationId })
                if (ready || tracked.isNotEmpty() || (installRecovery?.otherProfileBlockers ?: 0) > 0 || installNotice != null) {
                    Text("3. Новая установка 3x-ui", style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.testTag("xui_fresh_install_section"))
                }
                if (ready) {
                    Text("Проверка готовности пройдена. Установка изменит VPS и запускается только отдельным подтверждением.")
                    Button(modifier = Modifier.testTag("xui_fresh_install_open"), enabled = !anyBusy,
                        onClick = { installAck = false; installNotice = null; installDialog = true }) {
                        Text("Установить 3x-ui на этот VPS…")
                    }
                }
                if ((installRecovery?.otherProfileBlockers ?: 0) > 0) {
                    Text("Для этого VPS есть незавершённая установка, привязанная к другому SSH-профилю. " +
                        "Откройте её через тот же профиль; новая установка заблокирована.",
                        modifier = Modifier.testTag("xui_fresh_install_other_profile"))
                }
                installNotice?.let { Text(it, modifier = Modifier.testTag("xui_fresh_install_notice")) }
                secureNotice?.let { Text(it, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                    modifier = Modifier.testTag("xui_fresh_install_secure")) }
                tracked.forEach { item ->
                    // primary is the brand red in this theme and reads as an error; success stays neutral + bold.
                    Text(if (item.succeeded) "✓ " + item.text else item.text,
                        modifier = Modifier.testTag("xui_fresh_install_status"),
                        color = MaterialTheme.colorScheme.onSurface,
                        fontWeight = if (item.succeeded) androidx.compose.ui.text.font.FontWeight.SemiBold else null)
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(enabled = !anyBusy, modifier = Modifier.testTag("xui_fresh_install_refresh"),
                            onClick = { installStarted = item; refreshInstall(choice) }) { Text("Обновить статус") }
                        if (item.mayCheckReadOnly) Button(enabled = !anyBusy,
                            modifier = Modifier.testTag("xui_fresh_install_check"), onClick = {
                                if (installBusy || selected != choice || !owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return@Button
                                val request = ++generation
                                installStatusJob?.cancel()
                                installBusy = true
                                job = scope.launch {
                                    val message = try { installPort.checkResultConfirmed(item.operationId, serverId, choice) }
                                        catch (cancel: CancellationException) { throw cancel }
                                        catch (_: Exception) { "Не удалось запустить проверку результата." }
                                    if (request != generation || selected != choice || !owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return@launch
                                    installBusy = false
                                    installNotice = message ?: "Проверка результата запущена. Обновите статус позже."
                                    installStarted = item
                                    refreshInstall(choice)
                                }
                            }) { Text("Проверить результат") }
                        if (item.mayCancelBeforeDispatch) OutlinedButton(enabled = !anyBusy,
                            modifier = Modifier.testTag("xui_fresh_install_cancel"), onClick = {
                                if (installBusy || selected != choice || !owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return@OutlinedButton
                                val request = ++generation
                                installStatusJob?.cancel()
                                installBusy = true
                                job = scope.launch {
                                    val message = try { installPort.cancelBeforeDispatch(item.operationId, serverId, choice) }
                                        catch (cancel: CancellationException) { throw cancel }
                                        catch (_: Exception) { "Не удалось отменить запрос." }
                                    if (request != generation || selected != choice || !owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return@launch
                                    installBusy = false
                                    installNotice = message ?: "Ожидающий запрос отменён. Установка не отправлялась."
                                    installStarted = item
                                    refreshInstall(choice)
                                }
                            }) { Text("Отменить ожидающий запрос") }
                    }
                }
                if (installDialog) {
                    AlertDialog(
                        modifier = Modifier.testTag("xui_fresh_install_dialog"),
                        onDismissRequest = { if (!installBusy) { installDialog = false; installAck = false } },
                        title = { Text("Установить 3x-ui?") },
                        text = {
                            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text("Цель: ${LiveSshConnectionPolicy.exactTarget(choice)}")
                                Text("Закреплённый SSH-ключ: ${choice.savedFingerprint}")
                                Text("Это ЗАПИСЬ на VPS от root: приложение скачает закреплённый установщик 3x-ui, " +
                                    "запустит его на сервере, создаст службу и служебную отметку. " +
                                    "Установка идёт на сервере независимо от телефона и не откатывается автоматически.")
                                if (secureAfterInstall != null) Text("После установки панель будет закрыта от интернета " +
                                    "(только 127.0.0.1), а вход в неё через SSH-туннель сохранится на этом телефоне. " +
                                    "Открыть панель в интернет можно позже в «Доступ к панели».")
                                Text("Подтверждение одноразовое. Перед записью приложение заново проверит профиль и сервер. " +
                                    "Повторный запуск не выполняется; при обрыве результат проверяется только чтением.")
                                Row {
                                    Checkbox(checked = installAck, enabled = !installBusy,
                                        onCheckedChange = { installAck = it },
                                        modifier = Modifier.testTag("xui_fresh_install_ack"))
                                    Text("Понимаю, что VPS будет изменён")
                                }
                            }
                        },
                        confirmButton = {
                            Button(modifier = Modifier.testTag("xui_fresh_install_confirm"),
                                enabled = installAck && !installBusy && owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED),
                                onClick = {
                                    if (installBusy || selected != choice || !owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return@Button
                                    val request = ++generation
                                    installStatusJob?.cancel()
                                    installBusy = true
                                    job = scope.launch {
                                        val started = try { installPort.startConfirmed(serverId, choice) }
                                            catch (cancel: CancellationException) { throw cancel }
                                            catch (_: Exception) { XuiFreshInstallStart.Blocked("Не удалось записать запрос. Установка не отправлена.") }
                                        if (request != generation || selected != choice || !owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return@launch
                                        installBusy = false; installDialog = false; installAck = false
                                        // One-shot: the readiness result is spent, a new install needs a new check.
                                        result = null
                                        when (started) {
                                            is XuiFreshInstallStart.Blocked -> installNotice = started.message
                                            is XuiFreshInstallStart.Recorded -> {
                                                installNotice = "Запрос записан, Android запускает фоновую службу. Это ещё не результат установки."
                                                installStarted = XuiFreshInstallObservation(started.operationId, "Запрос записан.", false)
                                            }
                                        }
                                        refreshInstall(choice)
                                    }
                                }) { Text("Установить") }
                        },
                        dismissButton = {
                            OutlinedButton(enabled = !installBusy, onClick = { installDialog = false; installAck = false }) { Text("Отмена") }
                        },
                    )
                }
            }
        }
        when (val answer = result) {
            is XuiReadOnlyDiscoveryResult.Observation -> {
                Text(answer.label, style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.testTag("xui_discovery_observation"))
                Text(answer.detail)
                answer.candidateIdentity?.let { identity ->
                    Text("Структура кандидата 3x-ui подтверждена несколькими признаками",
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.testTag("xui_discovery_candidate_identity"))
                    Text("Служба: ${identity.serviceUnit}")
                    Text("Исполняемый файл: ${identity.binaryPath}")
                    Text("Каталог: ${identity.rootPath}")
                    Text("База данных: ${identity.databasePath}")
                    Text("Это совпадение read-only признаков, не проверка версии, " +
                        "порта, веб-пути, TLS или прав управления.")
                    if (choice != null) {
                        val exactTarget = LiveSshConnectionPolicy.exactTarget(choice)
                        Text("Дополнительно можно отдельно проверить только текущее состояние службы. " +
                            "Это новое SSH-подключение, поэтому требуется отдельное явное подтверждение.")
                        Text("Цель: $exactTarget")
                        Row {
                            Checkbox(checked = serviceConsent, enabled = !anyBusy,
                                onCheckedChange = { serviceConsent = it; serviceResult = null },
                                modifier = Modifier.testTag("xui_service_consent"))
                            Text("Разрешаю отдельное одноразовое SSH-чтение состояния службы. Без изменений VPS.")
                        }
                        Button(
                            modifier = Modifier.testTag("xui_service_verify_start"),
                            enabled = !anyBusy && serviceConsent,
                            onClick = {
                                val request = ++generation
                                val repeated = exactTarget
                                dropEnrollmentReview()
                                serviceBusy = true
                                serviceConsent = false
                                serviceResult = null
                                job = scope.launch {
                                    val check = try {
                                        discoveryPort.verifyServiceExact(
                                            serverId, choice.accessId, choice, repeated, true, identity,
                                        )
                                    } catch (cancel: CancellationException) { throw cancel }
                                      catch (_: Exception) {
                                        XuiServiceVerificationResult.Blocked("Состояние службы неизвестно.")
                                    }
                                    if (request == generation && selected == choice &&
                                        (result as? XuiReadOnlyDiscoveryResult.Observation)?.candidateIdentity == identity &&
                                        owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                        serviceBusy = false
                                        serviceResult = check
                                    }
                                }
                            },
                        ) { Text(if (serviceBusy) "Читаем состояние…" else "Проверить состояние службы (только чтение)") }
                        if (serviceBusy) OutlinedButton(onClick = { revoke() },
                            modifier = Modifier.testTag("xui_service_cancel")) { Text("Отменить проверку") }
                        when (val checked = serviceResult) {
                            is XuiServiceVerificationResult.Observed -> {
                                val label = when (checked.state) {
                                    XuiObservedServiceState.ACTIVE -> "активна"
                                    XuiObservedServiceState.INACTIVE -> "неактивна"
                                    XuiObservedServiceState.FAILED -> "ошибка запуска"
                                    XuiObservedServiceState.ACTIVATING -> "запускается"
                                    XuiObservedServiceState.DEACTIVATING -> "останавливается"
                                    XuiObservedServiceState.RELOADING -> "перезагружается"
                                    XuiObservedServiceState.UNKNOWN -> "неизвестно"
                                }
                                Text("Состояние службы на момент отдельной проверки: $label",
                                    modifier = Modifier.testTag("xui_service_verified_state"))
                                Text("Это не подтверждает веб-панель, TLS или право управления.")
                            }
                            is XuiServiceVerificationResult.Blocked -> Text(checked.message,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.testTag("xui_service_blocked"))
                            null -> Unit
                        }

                        Text("Дополнительно можно отдельно запросить только версию бинарного файла 3x-ui. " +
                            "Проверка не читает настройки панели, пароли или токены и требует нового SSH-согласия.")
                        Text("Цель: $exactTarget")
                        Row {
                            Checkbox(
                                checked = versionConsent, enabled = !anyBusy,
                                onCheckedChange = { versionConsent = it; versionResult = null },
                                modifier = Modifier.testTag("xui_version_consent"),
                            )
                            Text("Разрешаю отдельное одноразовое read-only SSH-чтение версии. Без изменений VPS.")
                        }
                        Button(
                            modifier = Modifier.testTag("xui_version_verify_start"),
                            enabled = !anyBusy && versionConsent,
                            onClick = {
                                val request = ++generation
                                val repeated = exactTarget
                                dropEnrollmentReview()
                                versionBusy = true
                                versionConsent = false
                                versionResult = null
                                job = scope.launch {
                                    val check = try {
                                        discoveryPort.verifyVersionExact(
                                            serverId, choice.accessId, choice, repeated, true, identity,
                                        )
                                    } catch (cancel: CancellationException) { throw cancel }
                                      catch (_: Exception) {
                                        XuiVersionVerificationResult.Blocked("Версия не подтверждена.")
                                    }
                                    if (request == generation && selected == choice &&
                                        (result as? XuiReadOnlyDiscoveryResult.Observation)?.candidateIdentity == identity &&
                                        owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                        versionBusy = false
                                        versionResult = check
                                    }
                                }
                            },
                        ) { Text(if (versionBusy) "Читаем версию…" else "Проверить версию 3x-ui (только чтение)") }
                        if (versionBusy) OutlinedButton(onClick = { revoke() },
                            modifier = Modifier.testTag("xui_version_cancel")) { Text("Отменить проверку версии") }
                        when (val checked = versionResult) {
                            is XuiVersionVerificationResult.Observed -> {
                                Text("Версия бинарного файла 3x-ui: ${checked.version}",
                                    modifier = Modifier.testTag("xui_version_verified_value"))
                                Text("Версия не подтверждает настройки, веб-доступ, TLS или право управления.")
                            }
                            is XuiVersionVerificationResult.Blocked -> Text(checked.message,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.testTag("xui_version_blocked"))
                            null -> Unit
                        }
                        if (enrollmentPort != null) {
                            Text("3. Подключите установку к управлению", style = MaterialTheme.typography.titleMedium,
                                modifier = Modifier.testTag("xui_connect_step_enrollment"))
                            Text("Сначала проверка, затем отдельное сохранение в приложении. После подключения резервная копия создаётся отдельно; сейчас файлы и службы сервера не изменяются.",
                                modifier = Modifier.testTag("xui_enroll_scope"))
                            Text("Приложение заново проверит тот же VPS, сверит идентичность установки и прочитает порт и веб-путь из базы 3x-ui. Для этого требуется ещё одна SSH-сессия. Сначала только просмотр — сохранение отдельной кнопкой.")
                            Text("Цель: $exactTarget")
                            Row {
                                Checkbox(checked = enrollConsent, enabled = !anyBusy,
                                    onCheckedChange = { enrollConsent = it; if (it) {
                                        (enrollReview as? XuiEnrollmentReview.Ready)?.let { ready -> enrollmentPort.discard(ready.reviewToken) }
                                        enrollReview = null; enrollSaveConsent = false
                                    } },
                                    modifier = Modifier.testTag("xui_enroll_read_consent"))
                                Text("Разрешаю одно read-only SSH-подключение и чтение настроек 3x-ui. VPS не изменять.")
                            }
                            Button(enabled = !anyBusy &&
                                    enrollConsent,
                                modifier = Modifier.testTag("xui_enroll_review_start"), onClick = {
                                    if (enrollConsent &&
                                        !enrollBusy && !enrollSaving && !busy && !serviceBusy && !versionBusy) {
                                        val request = ++generation
                                        val enrollmentTarget = exactTarget
                                        dropEnrollmentReview()
                                        enrollBusy = true; enrollConsent = false; enrollReview = null; enrollSaveConsent = false; enrollSave = null
                                        job = scope.launch {
                                            val review = try { enrollmentPort.reviewExact(serverId, choice.accessId, choice,
                                                enrollmentTarget, true, identity) }
                                                catch (cancel: CancellationException) { throw cancel }
                                                catch (_: Exception) { XuiEnrollmentReview.Blocked("Проверка недоступна.") }
                                            if (request == generation && selected == choice &&
                                                (result as? XuiReadOnlyDiscoveryResult.Observation)?.candidateIdentity == identity &&
                                                owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                                enrollBusy = false
                                                enrollReview = if (review is XuiEnrollmentReview.Ready &&
                                                    !XuiEnrollmentUiPolicy.matches(review, LiveSshConnectionPolicy.exactTarget(choice), identity, now())) {
                                                    enrollmentPort.discard(review.reviewToken)
                                                    XuiEnrollmentReview.Blocked("Цель, параметры или срок проверки не совпали. Проверьте установку заново.")
                                                } else review
                                            } else if (review is XuiEnrollmentReview.Ready) enrollmentPort.discard(review.reviewToken)
                                        }
                                    }
                                }) { Text(if (enrollBusy) "Проверяем установку…" else "Проверить для подключения") }
                            if (enrollBusy) {
                                CircularProgressIndicator(modifier = Modifier.testTag("xui_enroll_progress"))
                                OutlinedButton(onClick = { revoke() }, modifier = Modifier.testTag("xui_enroll_cancel")) {
                                    Text("Отменить проверку подключения")
                                }
                            }
                            when (val review = enrollReview) {
                                is XuiEnrollmentReview.Ready -> {
                                    Text("Подтверждённая установка:", style = MaterialTheme.typography.titleSmall,
                                        modifier = Modifier.testTag("xui_enroll_verified"))
                                    Text("Сохранить для: ${review.exactTarget}", modifier = Modifier.testTag("xui_enroll_confirm_target"))
                                    Text("Служба: ${review.serviceUnit}; бинарный файл: ${review.binaryPath}")
                                    Text("База данных: ${review.databasePath}")
                                    Text("Порт: ${review.panelPort}; веб-путь: ${review.webBasePath}")
                                    Text("Это локальная привязка SSH-управления, а не вход с паролем в Web Panel. " +
                                        "Никаких команд установки и изменения VPS не будет.")
                                    Row {
                                        Checkbox(checked = enrollSaveConsent, enabled = !anyBusy,
                                            onCheckedChange = { enrollSaveConsent = it },
                                            modifier = Modifier.testTag("xui_enroll_save_consent"))
                                        Text("Сохранить именно эту установку и SSH-доступ в базе приложения.")
                                    }
                                    Button(enabled = enrollSaveConsent && !anyBusy,
                                        modifier = Modifier.testTag("xui_enroll_save"), onClick = {
                                            if (enrollSaveConsent && !enrollSaving && !enrollBusy && !busy && !serviceBusy && !versionBusy) {
                                                val request = ++generation
                                                enrollSaveConsent = false
                                                if (!XuiEnrollmentUiPolicy.matches(review, LiveSshConnectionPolicy.exactTarget(choice), identity, now())) {
                                                    enrollmentPort.discard(review.reviewToken)
                                                    enrollReview = XuiEnrollmentReview.Blocked("Подтверждение устарело. Проверьте установку заново.")
                                                } else {
                                                    enrollSaving = true
                                                    job = scope.launch {
                                                        val saved = try { enrollmentPort.saveReviewed(review.reviewToken, serverId, choice.accessId) }
                                                            catch (cancel: CancellationException) { throw cancel }
                                                            catch (_: Exception) { XuiEnrollmentSave.Blocked("Не удалось подтвердить итог локальной записи.") }
                                                        if (request == generation && owner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                                            enrollSaving = false; enrollReview = null; enrollSave = saved
                                                            if (saved is XuiEnrollmentSave.Saved) onSaved()
                                                        }
                                                    }
                                                }
                                            }
                                        }) { Text(if (enrollSaving) "Сохраняем…" else "Сохранить установку в X-UI") }
                                }
                                is XuiEnrollmentReview.Blocked -> Text(review.message, color = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.testTag("xui_enroll_review_blocked"))
                                null -> Unit
                            }
                            when (val saved = enrollSave) {
                                is XuiEnrollmentSave.Saved -> Text(
                                    if (saved.alreadyKnown) "Установка уже подключена к управлению. Откройте её карточку для проверки и резервного копирования."
                                    else "Установка подключена к управлению. Следующий шаг — проверка и резервное копирование в её карточке.",
                                    modifier = Modifier.testTag("xui_enroll_saved"))
                                is XuiEnrollmentSave.Blocked -> Text(saved.message, color = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.testTag("xui_enroll_save_blocked"))
                                null -> Unit
                            }
                        }
                    }
                }
                if (enrollSave !is XuiEnrollmentSave.Saved) {
                    Text("До отдельного сохранения эти сведения не создают запись установки.", modifier = Modifier.testTag("xui_enroll_not_saved"))
                }
            }
            is XuiReadOnlyDiscoveryResult.Blocked -> Text(answer.message,
                color = MaterialTheme.colorScheme.error, modifier = Modifier.testTag("xui_discovery_blocked"))
            null -> Unit
        }
        OutlinedButton(onClick = { close() }, modifier = Modifier.testTag("xui_discovery_back")) {
            Text("Назад к серверам")
        }
    }
}

private const val AUTO_CHECK_INTERVAL_MS = 20_000L
private const val INSTALL_POLL_MS = 5_000L
