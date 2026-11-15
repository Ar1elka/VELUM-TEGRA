package com.velumtegra.xuimobile.management

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Local metadata only: no SecretStore, SSH session, discovery or management execution. */
sealed interface LocalManagementReview {
    data object Loading : LocalManagementReview
    data class Ready(
        val serverName: String,
        val serverId: String,
        val installationId: String,
        val ownership: String,
        val serviceUnit: String,
        val panelPort: Int,
        val webBasePath: String,
        val managementBindings: Int,
        /** Exact locally authorized SSH access IDs; identifiers only, never credentials. */
        val accessIds: List<String> = emptyList(),
    ) : LocalManagementReview
    data class Unavailable(val reason: String) : LocalManagementReview
}

fun interface ManagementLocalReviewPort {
    suspend fun readExact(serverId: String, installationId: String): LocalManagementReview
}

/** Only unambiguous local absolute panel paths may be displayed as trusted metadata.
 * Reject URL authority, traversal, escapes and query/fragment separators. No URL is opened. */
internal fun isSafeLocalPanelPath(path: String): Boolean {
    if (!path.startsWith('/') || path.startsWith("//")) return false
    if (path.any { it == '\\' || it == '?' || it == '#' || it == '%' || it.isWhitespace() || (it.code < 32 || it.code == 127) }) return false
    return path.split('/').none { it == "." || it == ".." }
}

/** Read-only exact-target join. Stale/missing/mismatched records fail closed. */
class RepositoryManagementLocalReviewPort(
    private val servers: ServerRepository,
    private val installations: XuiInstallationRepository,
    private val management: ManagementAccessRepository,
    private val accesses: ServerAccessRepository,
) : ManagementLocalReviewPort {
    override suspend fun readExact(serverId: String, installationId: String): LocalManagementReview =
        withContext(Dispatchers.IO) {
            if (serverId.isBlank() || installationId.isBlank()) {
                return@withContext LocalManagementReview.Unavailable("Не выбран конкретный сервер и установка X-UI.")
            }
            val server = when (val read = servers.get(ServerId(serverId))) {
                is RepositoryResult.Success -> read.value.value
                else -> return@withContext LocalManagementReview.Unavailable("Сервер больше не найден в локальной базе.")
            }
            // A repository lookup must prove the returned key, not just trust the
            // requested key. Reject a foreign server before reading its installations.
            if (server.id.value != serverId) {
                return@withContext LocalManagementReview.Unavailable("Сервер не соответствует выбранному идентификатору.")
            }
            val installation = when (val read = installations.get(XuiInstallationId(installationId))) {
                is RepositoryResult.Success -> read.value.value
                else -> return@withContext LocalManagementReview.Unavailable("Установка X-UI не найдена в локальной базе.")
            }
            if (installation.id.value != installationId) {
                return@withContext LocalManagementReview.Unavailable("Установка не соответствует выбранному идентификатору.")
            }
            if (installation.serverId.value != serverId) {
                return@withContext LocalManagementReview.Unavailable("Установка не принадлежит выбранному серверу.")
            }
            if (!isSafeLocalPanelPath(installation.baseline.webBasePath)) {
                return@withContext LocalManagementReview.Unavailable("Локальный путь панели повреждён или неоднозначен.")
            }
            val bindings = when (val read = management.listForInstallation(installation.id)) {
                is RepositoryResult.Success -> read.value
                else -> return@withContext LocalManagementReview.Unavailable("Привязки управления сейчас недоступны.")
            }
            if (bindings.isEmpty()) {
                return@withContext LocalManagementReview.Unavailable("Для установки больше нет привязок SSH-управления.")
            }
            // Validate the entire binding inventory before looking up any SSH
            // access. A malformed later row must not trigger earlier access reads.
            if (bindings.any { it.installationId != installation.id }) {
                return@withContext LocalManagementReview.Unavailable("Привязка управления не соответствует установке.")
            }
            val accessIds = bindings.map { it.serverAccessId.value }
            if (accessIds.any { it.isBlank() } || accessIds.distinct().size != accessIds.size) {
                return@withContext LocalManagementReview.Unavailable("Локальные привязки управления повреждены или повторяются.")
            }
            for (binding in bindings) {
                val access = when (val read = accesses.get(binding.serverAccessId)) {
                    is RepositoryResult.Success -> read.value
                    else -> return@withContext LocalManagementReview.Unavailable("SSH-доступ из привязки больше не найден.")
                }
                // An access returned for the correct lookup argument can still have
                // a different record ID. Do not advertise an unverified binding ID.
                if (access.id != binding.serverAccessId) {
                    return@withContext LocalManagementReview.Unavailable("SSH-доступ не соответствует идентификатору привязки.")
                }
                if (access.serverId.value != serverId) {
                    return@withContext LocalManagementReview.Unavailable("SSH-доступ относится к другому серверу.")
                }
            }
            LocalManagementReview.Ready(
                serverName = server.displayName,
                serverId = server.id.value,
                installationId = installation.id.value,
                ownership = installation.ownership.name,
                serviceUnit = installation.identity.serviceUnit,
                panelPort = installation.baseline.panelPort,
                webBasePath = installation.baseline.webBasePath,
                managementBindings = bindings.size,
                accessIds = accessIds.sorted(),
            )
        }
}

/** Every UI read must independently prove target identity and trustworthy local fields.
 * Untrusted Ready values must not expose foreign or malformed installation metadata. */
internal fun LocalManagementReview.requireExactInstallation(
    serverId: String,
    installationId: String,
): LocalManagementReview {
    val ready = this as? LocalManagementReview.Ready ?: return this
    // An alternate local port can echo a blank requested ID back as a matching
    // Ready. Matching two empty IDs is not proof of a concrete target.
    if (serverId.isBlank() || installationId.isBlank() ||
        ready.serverId.isBlank() || ready.installationId.isBlank() ||
        ready.serverId != serverId || ready.installationId != installationId
    ) {
        return LocalManagementReview.Unavailable("Локальные сведения не соответствуют выбранной установке.")
    }
    // A port can supply a malformed Ready even when the requested target IDs match.
    // Reject untrusted access IDs before the UI offers them as exact choices.
    if (ready.accessIds.any { it.isBlank() } ||
        ready.accessIds.distinct().size != ready.accessIds.size ||
        (ready.accessIds.isNotEmpty() && ready.managementBindings != ready.accessIds.size)
    ) {
        return LocalManagementReview.Unavailable("Локальный список SSH-доступов повреждён или не соответствует привязкам.")
    }
    // Production XuiInstallation models validate these scalar fields. An alternate
    // local port can bypass the model and hand the UI an inconsistent Ready. Do not
    // display those values as trusted saved installation facts or offer an offline plan.
    if (ready.panelPort !in 1..65535 ||
        ready.serviceUnit.isBlank() ||
        !isSafeLocalPanelPath(ready.webBasePath) ||
        (ready.ownership != "MANAGED" && ready.ownership != "ADOPTED") ||
        ready.managementBindings < 0
    ) {
        return LocalManagementReview.Unavailable("Локальные параметры установки повреждены или не подтверждены.")
    }
    // Older metadata-only ports have no access IDs. Retain valid read-only details,
    // but never invent a selectable SSH access for such records.
    return ready
}

/** Exact local target review; a future explicit QUICK_INSPECT screen may reuse this identity. */
@Composable
fun ManagementLocalReviewScreen(
    serverId: String,
    installationId: String,
    port: ManagementLocalReviewPort,
    onBack: () -> Unit,
    inspections: VisibleManagementInspectionsPort? = null,
    showOfflineDraft: Boolean = true,
) {
    BackHandler { onBack() }
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    var result by remember(serverId, installationId, port) { mutableStateOf<LocalManagementReview>(LocalManagementReview.Loading) }
    var generation by remember(serverId, installationId, port) { mutableStateOf(0L) }
    var selectedAccessId by remember(serverId, installationId, port) { mutableStateOf<String?>(null) }
    var previewAccessId by remember(serverId, installationId, port) { mutableStateOf<String?>(null) }
    var previewBusy by remember(serverId, installationId, port) { mutableStateOf(false) }
    var previewError by remember(serverId, installationId, port) { mutableStateOf<String?>(null) }
    var previewRequest by remember(serverId, installationId, port) { mutableStateOf(0L) }
    // A foreground refresh and an explicit user refresh share one fail-closed read fence.
    fun refreshLocalReview() {
        if (!lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return
        val current = ++generation
        previewRequest++
        selectedAccessId = null
        previewAccessId = null
        previewBusy = false
        previewError = null
        result = LocalManagementReview.Loading
        scope.launch {
            val fresh = try {
                port.readExact(serverId, installationId)
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                LocalManagementReview.Unavailable("Не удалось прочитать локальные сведения об установке.")
            }
            if (current == generation && lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                result = fresh.requireExactInstallation(serverId, installationId)
            }
        }
    }
    DisposableEffect(lifecycleOwner, serverId, installationId, port) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> refreshLocalReview()
                Lifecycle.Event.ON_STOP -> {
                    generation++
                    previewRequest++
                    result = LocalManagementReview.Loading
                    selectedAccessId = null
                    previewAccessId = null
                    previewBusy = false
                    previewError = null
                }
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer); generation++ }
    }
    Column(
        modifier = Modifier.fillMaxSize().safeDrawingPadding().testTag("management_review_root")
            .verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedButton(onClick = onBack, modifier = Modifier.testTag("management_review_back")) {
            Text("‹ Назад")
        }
        Text("Об установке", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text("Что приложение запомнило об этой панели. Сам сервер здесь не проверяется.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.testTag("management_review_offline"))
        when (val current = result) {
            LocalManagementReview.Loading -> Text("Читаем сохранённые сведения…", modifier = Modifier.testTag("management_review_loading"))
            is LocalManagementReview.Unavailable -> Text(current.reason, modifier = Modifier.testTag("management_review_unavailable"))
            is LocalManagementReview.Ready -> Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(current.serverName, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(if (current.ownership == "MANAGED") "Панель установлена этим приложением"
                        else "Панель была на сервере до подключения")
                    Text("Порт панели: ${current.panelPort}", modifier = Modifier.testTag("management_review_panel_port"))
                    Text("Путь панели: ${current.webBasePath}")
                    Text("Служба: ${current.serviceUnit}")
                    Text("SSH-профилей для управления: ${current.managementBindings}",
                        modifier = Modifier.testTag("management_review_bindings"))
                    Text("Код сервера: ${current.serverId}", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag("management_review_exact_server"))
                    Text("Код установки: ${current.installationId}", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag("management_review_exact_installation"))
                }
            }
        }
        OutlinedButton(
            onClick = { refreshLocalReview() },
            modifier = Modifier.testTag("management_review_refresh"),
        ) { Text("Перечитать") }
        // The offline QUICK_INSPECT plan is an engineering aid; the product screen leaves it out.
        if (showOfflineDraft && result is LocalManagementReview.Ready) {
            val ready = result as LocalManagementReview.Ready
            Card(modifier = Modifier.fillMaxWidth().testTag("management_quick_draft_card")) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("QUICK_INSPECT · подготовка (офлайн)", fontWeight = FontWeight.SemiBold)
                    Text("Выберите точный SSH-доступ. Просмотр плана не запускает SSH и не читает секреты.")
                    ready.accessIds.forEach { id ->
                        OutlinedButton(
                            onClick = {
                                previewRequest++
                                selectedAccessId = id
                                previewAccessId = null
                                previewBusy = false
                                previewError = null
                            },
                            modifier = Modifier.testTag("management_quick_access_$id"),
                        ) { Text(if (selectedAccessId == id) "Выбран: $id" else "Выбрать доступ: $id") }
                    }
                    // Explicit revocation does not change saved metadata or call the repository.
                    // Bump the request fence so an already-running preview cannot restore the plan.
                    if (selectedAccessId != null || previewAccessId != null || previewBusy) {
                        OutlinedButton(
                            onClick = {
                                previewRequest++
                                selectedAccessId = null
                                previewAccessId = null
                                previewBusy = false
                                previewError = null
                            },
                            modifier = Modifier.testTag("management_quick_clear_selection"),
                        ) { Text("Снять выбор доступа и закрыть план") }
                    }
                    OutlinedButton(
                        enabled = selectedAccessId != null && !previewBusy,
                        modifier = Modifier.testTag("management_quick_preview_button"),
                        onClick = {
                            val access = selectedAccessId
                            if (access != null) {
                                val expected = ready
                                val currentGeneration = generation
                                val currentRequest = ++previewRequest
                                previewBusy = true
                                previewError = null
                                previewAccessId = null
                                scope.launch {
                                    val fresh = try {
                                        port.readExact(serverId, installationId)
                                    } catch (cancel: CancellationException) {
                                        throw cancel
                                    } catch (_: Exception) {
                                        LocalManagementReview.Unavailable("Не удалось перепроверить локальные привязки.")
                                    }
                                    if (currentGeneration == generation &&
                                        currentRequest == previewRequest &&
                                        lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
                                    ) {
                                        val exact = fresh.requireExactInstallation(serverId, installationId)
                                        previewBusy = false
                                        if (exact is LocalManagementReview.Ready &&
                                            access in exact.accessIds &&
                                            exact == expected
                                        ) {
                                            result = exact
                                            previewAccessId = access
                                        } else {
                                            result = exact
                                            selectedAccessId = null
                                            previewAccessId = null
                                            previewError = "Локальные данные изменились или доступ недоступен. Выберите доступ заново."
                                        }
                                    }
                                }
                            }
                        },
                    ) { Text(if (previewBusy) "Перепроверяем…" else "Просмотреть план QUICK_INSPECT (офлайн)") }
                    previewError?.let { Text(it, modifier = Modifier.testTag("management_quick_preview_blocked")) }
                    previewAccessId?.let { access ->
                        Text("План (без выполнения):", fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.testTag("management_quick_preview_ready"))
                        Text("Сервер: ${ready.serverId}")
                        Text("Установка: ${ready.installationId}")
                        Text("SSH-доступ: $access", modifier = Modifier.testTag("management_quick_preview_access"))
                        Text("QUICK_INSPECT: только чтение; служба, идентичность, базовые параметры и порт панели.")
                        Text("Состояние VPS: не проверялось. Команды и сетевое подключение НЕ запускаются.")
                        if (inspections != null) {
                            ManagementLiveInspectionControls(
                                serverId = ready.serverId,
                                installationId = ready.installationId,
                                accessId = access,
                                port = inspections,
                            )
                        }
                    }
                }
            }
        }
    }
}
