package com.velumtegra.xuimobile.readiness

import androidx.activity.compose.BackHandler
import android.os.SystemClock
import java.util.UUID
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import kotlinx.coroutines.CancellationException

/** Offline-only surface. No SSH/Socket/SecretStore capability is reachable from this screen. */
@Composable
fun SshReadinessScreen(
    serverId: String,
    serverName: String,
    port: SshReadinessPort,
    onBack: () -> Unit,
) {
    BackHandler { onBack() }
    val lifecycleOwner = LocalLifecycleOwner.current
    var items by remember(serverId, port) { mutableStateOf<LocalSshAccessList?>(null) }
    var listGeneration by remember(serverId, port) { mutableStateOf(0L) }
    var selectedAccessId by remember(serverId, port) { mutableStateOf<String?>(null) }
    var acknowledged by remember(serverId, port) { mutableStateOf(false) }
    var preview by remember(serverId, port) { mutableStateOf<LocalSshReadinessResult?>(null) }
    var busy by remember(serverId, port) { mutableStateOf(false) }
    var requestGeneration by remember(serverId, port) { mutableStateOf(0L) }
    var draftAcknowledged by remember(serverId, port) { mutableStateOf(false) }
    var draftBusy by remember(serverId, port) { mutableStateOf(false) }
    var draftResult by remember(serverId, port) { mutableStateOf<OfflineSshConnectionDraftResult?>(null) }
    val consentGate = remember(serverId, port) { OfflineSshConsentRehearsal() }
    var consentAcknowledged by remember(serverId, port) { mutableStateOf(false) }
    var consentResult by remember(serverId, port) { mutableStateOf<OfflineSshConsentResult?>(null) }
    var consentBusy by remember(serverId, port) { mutableStateOf(false) }
    var handoffResult by remember(serverId, port) { mutableStateOf<OfflineSshHandoffResult?>(null) }
    fun invalidateConsent() {
        consentGate.revoke()
        consentAcknowledged = false
        consentResult = null
        consentBusy = false
        handoffResult = null
    }
    fun invalidatePending() {
        requestGeneration++
        preview = null
        busy = false
        draftAcknowledged = false
        draftBusy = false
        draftResult = null
        invalidateConsent()
    }
    val scope = rememberCoroutineScope()

    // A new foreground session must re-read the exact server's local access list. The generation
    // guard prevents an old suspended list call (even a cancellation-ignoring port) from rendering
    // stale access metadata after STOP, a second START or a port replacement.
    fun refreshForegroundAccesses() {
        val generation = ++listGeneration
        items = null
        selectedAccessId = null
        acknowledged = false
        invalidatePending()
        scope.launch {
            val refreshed = try {
                port.listForExactServer(serverId)
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                LocalSshAccessList.Unavailable("Не удалось обновить локальный список SSH-доступов.")
            }
            if (generation == listGeneration &&
                lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                items = refreshed
            }
        }
    }

    DisposableEffect(lifecycleOwner, serverId, port) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> refreshForegroundAccesses()
                Lifecycle.Event.ON_STOP -> {
                    listGeneration++
                    items = null
                    selectedAccessId = null
                    acknowledged = false
                    invalidatePending()
                }
                else -> Unit
            }
        }
        // LifecycleRegistry catches a newly added observer up to the current lifecycle state,
        // including ON_START for an already foreground Activity. Avoid a duplicate manual read.
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            listGeneration++
            requestGeneration++
            consentGate.revoke()
        }
    }
    Column(
        modifier = Modifier.fillMaxSize().testTag("ssh_readiness_root")
            .verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("SSH · локальная проверка", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text("Выбранный сервер: $serverName", modifier = Modifier.testTag("ssh_readiness_exact_server"))
        Text("Server ID: $serverId", style = MaterialTheme.typography.bodySmall)
        Text(
            "Только сохранённые локальные метаданные. Без сетевого SSH-соединения, команд VPS или чтения секретов.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        when (val current = items) {
            null -> Text("Читаем локальные SSH-доступы…")
            is LocalSshAccessList.Unavailable -> Text(current.reason, modifier = Modifier.testTag("ssh_readiness_load_error"))
            is LocalSshAccessList.Available -> {
                if (current.items.isEmpty()) Text("У сервера пока нет SSH-доступов. Сначала сохраните доступ.")
                current.items.forEach { access ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                            Text("${access.username}@${access.host}:${access.port}", fontWeight = FontWeight.SemiBold)
                            Text("Аутентификация: ${access.authLabel}")
                            Text("Сохранённый pin: ${access.savedFingerprint}", style = MaterialTheme.typography.bodySmall)
                            OutlinedButton(
                                onClick = {
                                    selectedAccessId = access.accessId
                                    acknowledged = false
                                    invalidatePending()
                                },
                                modifier = Modifier.testTag("ssh_readiness_choose_${access.accessId}"),
                            ) { Text(if (selectedAccessId == access.accessId) "Выбран" else "Выбрать этот SSH-доступ") }
                        }
                    }
                }
            }
        }
        if (selectedAccessId != null) {
            Text("SSH Access ID: $selectedAccessId", modifier = Modifier.testTag("ssh_readiness_exact_access"))
            androidx.compose.foundation.layout.Row {
                Checkbox(checked = acknowledged, onCheckedChange = {
                    acknowledged = it
                    invalidatePending()
                }, modifier = Modifier.testTag("ssh_readiness_acknowledge"))
                Text("Понимаю: только локальный просмотр; host key по сети и успешность входа не проверяются.")
            }
        }
        Button(
            onClick = {
                val exact = selectedAccessId ?: return@Button
                val generation = ++requestGeneration
                busy = true
                preview = null
                draftResult = null
                invalidateConsent()
                scope.launch {
                    val result = try {
                        port.previewExact(serverId, exact)
                    } catch (cancel: CancellationException) {
                        throw cancel
                    } catch (_: Exception) {
                        LocalSshReadinessResult.Blocked("Не удалось повторно прочитать локальные SSH-метаданные.")
                    }
                    if (generation == requestGeneration && selectedAccessId == exact && acknowledged) {
                        preview = result
                        busy = false
                    }
                }
            },
            enabled = selectedAccessId != null && acknowledged && !busy,
            modifier = Modifier.testTag("ssh_readiness_preview"),
        ) { Text("Проверить локальные метаданные") }
        when (val checked = preview) {
            null -> Unit
            is LocalSshReadinessResult.Blocked -> Text(
                checked.reason, modifier = Modifier.testTag("ssh_readiness_blocked"),
                color = MaterialTheme.colorScheme.error,
            )
            is LocalSshReadinessResult.MetadataPresent -> {
                Text("Локальные метаданные найдены для выбранного SSH-доступа.",
                    modifier = Modifier.testTag("ssh_readiness_metadata_present"), fontWeight = FontWeight.SemiBold)
                Text("${checked.summary.username}@${checked.summary.host}:${checked.summary.port} · ${checked.summary.authLabel}")
                Text("Pin сохранён: ${checked.summary.savedFingerprint}")
                Text("НЕ проверено: расшифровка секрета, парольная фраза, подлинность удалённого host key, сеть и SSH-аутентификация.")
                Text("Если ссылка на сохранённые учётные данные изменится, офлайн-черновик и согласие будут отклонены.")
                Text(
                    "Шаг 2 · локальный черновик будущего подключения. Не является разрешением на SSH.",
                    style = MaterialTheme.typography.titleSmall,
                )
                Text("Цель локальной проверки: ${OfflineSshConnectionDraftPolicy.expectedConfirmation(checked.summary)}")
                androidx.compose.foundation.layout.Row {
                    Checkbox(
                        checked = draftAcknowledged,
                        onCheckedChange = {
                            requestGeneration++
                            draftAcknowledged = it
                            draftResult = null
                            draftBusy = false
                            invalidateConsent()
                        },
                        modifier = Modifier.testTag("ssh_draft_acknowledge"),
                    )
                    Text("Подтверждаю создание только офлайн-черновика, без разрешения сетевого SSH.")
                }
                Button(
                    onClick = {
                        val exact = selectedAccessId ?: return@Button
                        val prior = preview
                        val input = OfflineSshConnectionDraftPolicy.expectedConfirmation(checked.summary)
                        val consent = draftAcknowledged
                        val generation = ++requestGeneration
                        draftBusy = true
                        draftResult = null
                        invalidateConsent()
                        scope.launch {
                            val fresh = try {
                                port.previewExact(serverId, exact)
                            } catch (cancel: CancellationException) {
                                throw cancel
                            } catch (_: Exception) {
                                LocalSshReadinessResult.Blocked("Повторная проверка метаданных не удалась.")
                            }
                            if (generation == requestGeneration && selectedAccessId == exact &&
                                acknowledged && draftAcknowledged && preview == prior) {
                                draftResult = OfflineSshConnectionDraftPolicy.prepare(
                                    serverId, exact, prior, fresh, input, consent,
                                )
                                draftBusy = false
                            }
                        }
                    },
                    enabled = acknowledged && draftAcknowledged && !draftBusy && !busy,
                    modifier = Modifier.testTag("ssh_draft_prepare"),
                ) { Text("Подготовить офлайн-черновик") }
                when (val draft = draftResult) {
                    is OfflineSshConnectionDraftResult.Blocked -> Text(
                        draft.reason,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.testTag("ssh_draft_blocked"),
                    )
                    is OfflineSshConnectionDraftResult.Prepared -> {
                        Text("Офлайн-черновик подготовлен для Server ID: ${draft.draft.serverId}",
                            modifier = Modifier.testTag("ssh_draft_prepared"), fontWeight = FontWeight.SemiBold)
                        Text("SSH Access ID: ${draft.draft.accessId} · ${draft.draft.username}@${draft.draft.host}:${draft.draft.port}")
                        Text("Сохранённый pin: ${draft.draft.savedFingerprint}")
                        Text("СЕТЬ ЗАПРЕЩЕНА: нет SSH-сессии, разрешения на вход, проверки сервера или действий VPS.")
                        Text("Шаг 3 · офлайн-репетиция одноразового согласия (60 секунд). Не является разрешением на подключение.",
                            style = MaterialTheme.typography.titleSmall)
                        val draftTarget = "${draft.draft.username}@${draft.draft.host}:${draft.draft.port}"
                        androidx.compose.foundation.layout.Row {
                            Checkbox(
                                checked = consentAcknowledged,
                                onCheckedChange = {
                                    requestGeneration++
                                    consentGate.revoke()
                                    consentAcknowledged = it
                                    handoffResult = null
                                    consentResult = null
                                    consentBusy = false
                                },
                                modifier = Modifier.testTag("ssh_consent_acknowledge"),
                            )
                            Text("Понимаю: только офлайн-репетиция, не право на SSH, чтение секретов или команды VPS.")
                        }
                        Button(
                            onClick = {
                                val exact = selectedAccessId ?: return@Button
                                val originalDraft = (draftResult as? OfflineSshConnectionDraftResult.Prepared)?.draft
                                    ?: return@Button
                                val input = draftTarget
                                val acknowledgedNow = consentAcknowledged
                                val generation = ++requestGeneration
                                consentGate.revoke()
                                consentBusy = true
                                handoffResult = null
                                consentResult = null
                                scope.launch {
                                    val fresh = try {
                                        port.previewExact(serverId, exact)
                                    } catch (cancel: CancellationException) { throw cancel }
                                      catch (_: Exception) { LocalSshReadinessResult.Blocked("Не удалось обновить метаданные.") }
                                    if (generation == requestGeneration && selectedAccessId == exact &&
                                        consentAcknowledged && acknowledged && draftAcknowledged &&
                                        (draftResult as? OfflineSshConnectionDraftResult.Prepared)?.draft == originalDraft) {
                                        consentResult = consentGate.arm(originalDraft, fresh, input,
                                            acknowledgedNow, SystemClock.elapsedRealtime(), UUID.randomUUID().toString())
                                        consentBusy = false
                                    }
                                }
                            },
                            enabled = acknowledged && draftAcknowledged && consentAcknowledged &&
                                !consentBusy && !draftBusy,
                            modifier = Modifier.testTag("ssh_consent_arm"),
                        ) { Text("Подготовить одноразовую офлайн-репетицию") }
                        when (val step = consentResult) {
                            is OfflineSshConsentResult.Armed -> {
                                Text("Офлайн-репетиция подготовлена: 60 секунд, одно использование; сеть запрещена.",
                                    modifier = Modifier.testTag("ssh_consent_armed"))
                                Text("Шаг 4 · проверка офлайн-передачи согласия: не выдаёт права на SSH.",
                                    style = MaterialTheme.typography.titleSmall)
                                Button(
                                    onClick = {
                                        val exact = selectedAccessId ?: return@Button
                                        val original = step
                                        val input = draftTarget
                                        val approved = consentAcknowledged
                                        val generation = ++requestGeneration
                                        consentBusy = true
                                        handoffResult = null
                                        scope.launch {
                                            val inspected = OfflineSshAuthorizationHandoff(consentGate).inspectWithFreshLocalRead(
                                                original.receipt, serverId, exact, port, input, approved,
                                                SystemClock::elapsedRealtime,
                                            )
                                            if (generation == requestGeneration && selectedAccessId == exact &&
                                                consentResult == original && consentAcknowledged && acknowledged &&
                                                draftAcknowledged) {
                                                handoffResult = inspected
                                                consentResult = null
                                                consentBusy = false
                                            }
                                        }
                                    },
                                    enabled = !consentBusy,
                                    modifier = Modifier.testTag("ssh_handoff_inspect"),
                                ) { Text("Проверить передачу согласия без сети") }
                                OutlinedButton(
                                    onClick = {
                                        requestGeneration++
                                        invalidateConsent()
                                    },
                                    modifier = Modifier.testTag("ssh_handoff_cancel"),
                                ) { Text("Отменить согласие") }
                                Button(
                                    onClick = {
                                        val exact = selectedAccessId ?: return@Button
                                        val generation = ++requestGeneration
                                        consentBusy = true
                                        scope.launch {
                                            val fresh = try {
                                                port.previewExact(serverId, exact)
                                            } catch (cancel: CancellationException) { throw cancel }
                                              catch (_: Exception) { LocalSshReadinessResult.Blocked("Не удалось обновить метаданные.") }
                                            if (generation == requestGeneration && selectedAccessId == exact &&
                                                consentResult == step && consentAcknowledged && acknowledged && draftAcknowledged) {
                                                consentResult = consentGate.simulateOneTimeUse(step.receipt, fresh,
                                                    draftTarget, consentAcknowledged, SystemClock.elapsedRealtime())
                                                consentBusy = false
                                            }
                                        }
                                    },
                                    enabled = !consentBusy,
                                    modifier = Modifier.testTag("ssh_consent_simulate"),
                                ) { Text("Отметить однократное использование (без сети)") }
                            }
                            is OfflineSshConsentResult.SimulatedOnce -> Text(
                                "Однократная офлайн-репетиция завершена. SSH не запускался; повторное использование запрещено.",
                                modifier = Modifier.testTag("ssh_consent_simulated"),
                            )
                            is OfflineSshConsentResult.Blocked -> Text(
                                step.reason, color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.testTag("ssh_consent_blocked"),
                            )
                            null -> Unit
                        }
                        when (val handed = handoffResult) {
                            is OfflineSshHandoffResult.Inspected -> {
                                Text("Офлайн-передача проверена и согласие погашено; SSH не запускался.",
                                    modifier = Modifier.testTag("ssh_handoff_inspected"))
                                Text("Server ID: ${handed.serverId} · SSH Access ID: ${handed.accessId}")
                                Text("${handed.exactTarget} · pin: ${handed.pinnedFingerprint}")
                                Text("НЕТ разрешения: сеть, секреты, SSH-сессия, команды VPS.")
                            }
                            is OfflineSshHandoffResult.Blocked -> Text(
                                handed.reason, modifier = Modifier.testTag("ssh_handoff_blocked"),
                                color = MaterialTheme.colorScheme.error,
                            )
                            null -> Unit
                        }
                    }
                    null -> Unit
                }
            }
        }
        Text(
            "Это НЕ разрешение на подключение. Функции проверки сети/SSH на этом экране нет.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodySmall,
        )
        OutlinedButton(onClick = onBack, modifier = Modifier.testTag("ssh_readiness_back")) { Text("К серверам") }
    }
}
