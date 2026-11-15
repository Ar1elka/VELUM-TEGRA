package com.velumtegra.xuimobile.inventory

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.TextButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelRouteTarget
import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionRequest
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionResult
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext

enum class InventorySection(val heading: String, val explanation: String) {
    SERVERS(
        "Мои серверы",
        "Ваши VPS и SSH-доступы к ним.",
    ),
    MANAGEMENT(
        "Управление X-UI",
        "Серверы, на которых найдена панель 3x-ui.",
    ),
    WEB_PANEL(
        "Веб-панели",
        "Сохранённые входы в веб-панель 3x-ui.",
    ),
}

private data class InventoryItem(
    val title: String,
    val detail: String,
    val support: String,
    val serverId: String? = null,
    val installationId: String? = null,
    val sshCount: Int = 0,
    val installationCount: Int = 0,
    val webPanelAccessId: String? = null,
    val webPanelDirectLinked: Boolean = false,
    val webPanelSshLinked: Boolean = false,
    val webPanelStandalone: Boolean = false,
)

private sealed interface InventoryLoad {
    data object Loading : InventoryLoad
    data class Ready(val items: List<InventoryItem>) : InventoryLoad
    data class Error(val message: String) : InventoryLoad
}

@Composable
internal fun InventoryScreen(
    section: InventorySection,
    serverRepository: ServerRepository,
    serverAccessRepository: ServerAccessRepository,
    installationRepository: XuiInstallationRepository,
    managementAccessRepository: ManagementAccessRepository,
    webPanelAccessRepository: WebPanelAccessRepository,
    onAddServer: () -> Unit = {},
    onAddSshAccess: (String, String) -> Unit = { _, _ -> },
    onReviewSshReadiness: (String, String) -> Unit = { _, _ -> },
    onConnectSsh: (String, String) -> Unit = { _, _ -> },
    onManageSshProfiles: (String, String) -> Unit = { _, _ -> },
    onDiscoverXui: (String, String) -> Unit = { _, _ -> },
    onReviewManagement: (String, String) -> Unit = { _, _ -> },
    onOpenWebPanelInApp: (String) -> Unit = {},
    onOpenSavedWebPanel: (SavedDirectWebPanel) -> Unit = { onOpenWebPanelInApp(it.url) },
    onOpenPrivateWebPanel: (PrivateWebPanelOpenRequest) -> Unit = {},
    linkedCredentialPort: LinkedWebPanelCredentialPort? = null,
    linkedLoginCheckPort: LinkedWebPanelLoginCheckPort? = null,
    linkedInboundReadPort: LinkedWebPanelInboundReadPort? = null,
    linkedServerStatusReadPort: LinkedWebPanelServerStatusReadPort? = null,
    linkedClientCountReadPort: LinkedWebPanelClientCountReadPort? = null,
    linkedClientTrafficReadPort: LinkedWebPanelClientTrafficReadPort? = null,
    linkedClientQuotaExpiryReadPort: LinkedWebPanelClientQuotaExpiryReadPort? = null,
    linkedInboundDetailsReadPort: LinkedWebPanelInboundDetailsReadPort? = null,
    /** Non-null only for the local, per-installation mode of the WEB_PANEL section. */
    webPanelScope: WebPanelInstallationScope? = null,
    onBackToManagement: () -> Unit = {},
    /** Removes the server with all its local records; null keeps the old empty-card-only deletion. */
    purgeServer: (suspend (com.velumtegra.xuimobile.core.model.ServerId,
        com.velumtegra.xuimobile.core.domain.RecordRevision) -> com.velumtegra.xuimobile.core.domain.RepositoryResult<List<String>>)? = null,
) {
    if (webPanelScope != null) BackHandler(onBack = onBackToManagement)
    var searchText by rememberSaveable(section) { mutableStateOf("") }
    var refresh by rememberSaveable(section) { mutableIntStateOf(0) }
    var load by remember(section) { mutableStateOf<InventoryLoad>(InventoryLoad.Loading) }
    val actionScope = rememberCoroutineScope()
    // Reuse the canonical exact-id resolver; no shadow store, credential read or SSH probing.
    val savedPanelResolver = remember(serverRepository, serverAccessRepository,
        installationRepository, webPanelAccessRepository) {
        ExactWebPanelTargetResolver(
            webPanelAccessRepository, installationRepository, serverRepository, serverAccessRepository,
        )
    }
    var openingWebPanelId by remember(section) { mutableStateOf<String?>(null) }
    var webPanelOpenNotice by remember(section) { mutableStateOf<String?>(null) }
    val cardActions = remember(serverRepository, serverAccessRepository, installationRepository) {
        LocalServerCardActions(serverRepository, serverAccessRepository, installationRepository)
    }
    var renameTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var renameText by remember(section) { mutableStateOf("") }
    var deleteTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var actionBusy by remember(section) { mutableStateOf(false) }
    var actionNotice by remember(section) { mutableStateOf<String?>(null) }
    var linkedPanelTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var privatePanelTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var linkedCredentialTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var standaloneCredentialDialog by remember(section) { mutableStateOf(false) }
    var scopedCredentialDialog by remember(section) { mutableStateOf(false) }
    var loginCheckTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var inboundReadTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var serverStatusReadTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var clientCountReadTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var clientTrafficReadTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var clientQuotaExpiryReadTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var inboundDetailsReadTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }
    var offlineInboundPreviewTarget by remember(section) { mutableStateOf<InventoryItem?>(null) }

    fun performAction(block: suspend () -> ServerCardActionResult, onSuccess: String) {
        if (actionBusy) return
        actionBusy = true
        actionNotice = null
        actionScope.launch {
            try {
                val result = withContext(Dispatchers.IO) { block() }
                when (result) {
                    ServerCardActionResult.Done -> { renameTarget = null; deleteTarget = null; actionNotice = onSuccess; refresh++ }
                    is ServerCardActionResult.Blocked -> actionNotice = result.explanation
                }
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (_: Exception) {
                actionNotice = "Не удалось изменить локальную запись. Данные VPS не затронуты."
            } finally { actionBusy = false }
        }
    }

    LaunchedEffect(section, refresh, webPanelScope) {
        load = InventoryLoad.Loading
        load = withContext(Dispatchers.IO) {
            try {
                loadInventory(
                    section = section,
                    serverRepository = serverRepository,
                    serverAccessRepository = serverAccessRepository,
                    installationRepository = installationRepository,
                    managementAccessRepository = managementAccessRepository,
                    webPanelAccessRepository = webPanelAccessRepository,
                    webPanelScope = webPanelScope,
                    panelResolver = savedPanelResolver,
                )
            } catch (_: Exception) {
                InventoryLoad.Error("Локальные данные не удалось прочитать. Попробуйте обновить список.")
            }
        }
    }

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
    Column(
        modifier = Modifier.widthIn(max = 960.dp).fillMaxSize().safeDrawingPadding()
            .testTag("inventory_${section.name.lowercase()}")
            .verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (webPanelScope != null) {
            OutlinedButton(onClick = onBackToManagement,
                modifier = Modifier.fillMaxWidth().testTag("inventory_scoped_back")) {
                Text("← Назад в управление")
            }
        }
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(if (webPanelScope != null) "Веб-панели этой установки" else section.heading,
                style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f))
            // The list reloads by itself after every action; this stays for a manual re-read.
            TextButton(onClick = { refresh++ }, modifier = Modifier.testTag("inventory_refresh")) {
                Text("Обновить")
            }
        }
        Text(
            if (webPanelScope != null) "Сохранённые входы в панель этой установки."
            else section.explanation,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        // The saved-panel card is the primary flow. Exact manual URL remains below the list.
        if (section == InventorySection.SERVERS) {
            Button(onClick = onAddServer, modifier = Modifier.fillMaxWidth().testTag("inventory_add_server")) {
                Text("+ Добавить сервер")
            }
        }
        if (actionNotice != null && section == InventorySection.SERVERS) {
            Text(actionNotice.orEmpty(), modifier = Modifier.testTag("inventory_server_action_notice"))
        }
        if (section == InventorySection.WEB_PANEL && webPanelScope != null && linkedCredentialPort != null) {
            OutlinedButton(onClick = { scopedCredentialDialog = true },
                modifier = Modifier.fillMaxWidth().testTag("inventory_scoped_save_credential")) {
                Text("Сохранить доступ Web Panel")
            }
        }
        if (section == InventorySection.WEB_PANEL && webPanelScope == null && linkedCredentialPort != null) {
            Button(onClick = { standaloneCredentialDialog = true },
                modifier = Modifier.fillMaxWidth().testTag("inventory_add_manual_ssh_panel")) {
                Text("+ Закрытая панель вручную (через SSH)")
            }
        }
        if (section == InventorySection.WEB_PANEL && webPanelOpenNotice != null) {
            Text(webPanelOpenNotice.orEmpty(),
                modifier = Modifier.testTag("inventory_saved_panel_open_notice"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error)
        }
        // Search only earns its place once the list no longer fits on one screen.
        val searchable = ((load as? InventoryLoad.Ready)?.items?.size ?: 0) > SEARCH_THRESHOLD
        if (searchable) OutlinedTextField(
            value = searchText, onValueChange = { searchText = it },
            label = { Text("Поиск по названию") }, singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("inventory_search"),
        )
        when (val current = load) {
            InventoryLoad.Loading -> Text("Загружаем сохранённые записи…")
            is InventoryLoad.Error -> Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            ) {
                Text(current.message, modifier = Modifier.padding(18.dp))
            }
            is InventoryLoad.Ready -> {
                if (current.items.isEmpty()) {
                    Card {
                        Column(
                            modifier = Modifier.padding(20.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Text("Здесь пока пусто", fontWeight = FontWeight.SemiBold)
                            Text(
                                when (section) {
                                    InventorySection.SERVERS -> "Нажмите «Добавить сервер», чтобы начать."
                                    InventorySection.MANAGEMENT -> "Откройте «Мои серверы» и нажмите «Найти 3x-ui» у нужного сервера."
                                    InventorySection.WEB_PANEL -> if (webPanelScope != null)
                                        "Для этой установки нет сохранённых панелей."
                                    else "Добавьте панель через сохранённый SSH-профиль."
                                },
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                } else {
                    val query = if (searchable) searchText.trim() else ""
                    val visibleItems = current.items.filter { it.title.contains(query, ignoreCase = true) }
                    if (visibleItems.isEmpty()) Text("По этому названию ничего не найдено.",
                        modifier = Modifier.testTag("inventory_search_empty"))
                    visibleItems.forEach { item ->
                        Card(modifier = Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large,
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text(item.title, style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold)
                                Text(item.detail, color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    style = MaterialTheme.typography.bodyMedium)
                                if (item.support.isNotBlank()) Text(item.support, style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                                // One tap opens the existing 3x-ui site, never a recreated native panel.
                                // Re-read exact access + installation before navigation: no guesses, secrets,
                                // cached port assumptions, browser Intent, or background connection.
                                if (section == InventorySection.WEB_PANEL && item.webPanelAccessId != null) {
                                    val accessId = item.webPanelAccessId
                                    if (item.webPanelDirectLinked) {
                                        Button(
                                            onClick = {
                                                if (openingWebPanelId != null) return@Button
                                                openingWebPanelId = accessId
                                                webPanelOpenNotice = null
                                                actionScope.launch {
                                                    try {
                                                        val saved = withContext(Dispatchers.IO) {
                                                            when (val resolved = savedPanelResolver.resolve(
                                                                WebPanelTargetResolutionRequest(
                                                                    webPanelAccessId = WebPanelAccessId(accessId),
                                                                    scheme = WebPanelScheme.HTTPS,
                                                                ),
                                                            )) {
                                                                is WebPanelTargetResolutionResult.Resolved -> {
                                                                    if (resolved.target.webPanelAccessId.value != accessId ||
                                                                        !webPanelTargetMatchesScope(webPanelScope,
                                                                            resolved.target.installation,
                                                                            resolved.target.routeTarget)) null
                                                                    else savedLinkedWebPanelHttpsUrl(
                                                                        resolved.target.installation,
                                                                        resolved.target.routeTarget,
                                                                    )?.let { SavedDirectWebPanel(it, resolved.target) }
                                                                }
                                                                else -> null
                                                            }
                                                        }
                                                        if (saved != null) onOpenSavedWebPanel(saved)
                                                        else webPanelOpenNotice = if (webPanelScope != null) {
                                                            "Сохранённый профиль или адрес этой установки изменился. Обновите список и выберите профиль заново."
                                                        } else {
                                                            "Сохранённый адрес не подтверждён локальными данными. " +
                                                                "Обновите установку или укажите точный HTTPS-адрес вручную."
                                                        }
                                                    } catch (cancel: CancellationException) {
                                                        throw cancel
                                                    } catch (_: Exception) {
                                                        webPanelOpenNotice =
                                                            "Не удалось прочитать сохранённую панель. VPS не затронут."
                                                    } finally {
                                                        openingWebPanelId = null
                                                    }
                                                }
                                            },
                                            enabled = openingWebPanelId == null,
                                            modifier = Modifier.fillMaxWidth()
                                                .testTag("inventory_webpanel_open_saved_$accessId"),
                                        ) {
                                            Text(if (openingWebPanelId == accessId) "Проверяем сохранённый адрес…"
                                                else "Открыть панель 3x-ui")
                                        }
                                    } else if (item.webPanelSshLinked) {
                                        Button(
                                            onClick = { privatePanelTarget = item },
                                            enabled = openingWebPanelId == null,
                                            modifier = Modifier.fillMaxWidth().testTag("inventory_webpanel_open_ssh_$accessId"),
                                        ) { Text("Открыть панель через SSH") }
                                    } else {
                                        Text("Этот доступ не привязан к подтверждённой установке 3x-ui.",
                                            style = MaterialTheme.typography.bodySmall)
                                    }
                                }
                                if (section == InventorySection.WEB_PANEL && item.webPanelDirectLinked) {
                                    var checksExpanded by remember(item.webPanelAccessId) { mutableStateOf(false) }
                                    TextButton(onClick = { checksExpanded = !checksExpanded }, modifier = Modifier.fillMaxWidth()) {
                                        Text(if (checksExpanded) "Скрыть дополнительные проверки" else "Дополнительные проверки")
                                    }
                                    if (checksExpanded) {
                                if (section == InventorySection.WEB_PANEL && item.webPanelDirectLinked &&
                                    item.webPanelAccessId != null && linkedLoginCheckPort != null) {
                                    OutlinedButton(onClick = { loginCheckTarget = item },
                                        modifier = Modifier.fillMaxWidth()
                                            .testTag("inventory_webpanel_login_check_${item.webPanelAccessId}")) {
                                        Text("Проверить вход по HTTPS")
                                    }
                                }
                                if (section == InventorySection.WEB_PANEL && item.webPanelDirectLinked &&
                                    item.webPanelAccessId != null && linkedInboundReadPort != null) {
                                    OutlinedButton(onClick = { inboundReadTarget = item },
                                        modifier = Modifier.fillMaxWidth()
                                            .testTag("inventory_inbounds_read_${item.webPanelAccessId}")) {
                                        Text("Подключения: прочитать по HTTPS")
                                    }
                                }
                                if (section == InventorySection.WEB_PANEL && item.webPanelDirectLinked &&
                                    item.webPanelAccessId != null && linkedServerStatusReadPort != null) {
                                    OutlinedButton(onClick = { serverStatusReadTarget = item },
                                        modifier = Modifier.fillMaxWidth()
                                            .testTag("inventory_server_status_read_${item.webPanelAccessId}")) {
                                        Text("Состояние сервера: прочитать по HTTPS")
                                    }
                                }
                                if (section == InventorySection.WEB_PANEL && item.webPanelDirectLinked &&
                                    item.webPanelAccessId != null && linkedClientCountReadPort != null) {
                                    OutlinedButton(onClick = { clientCountReadTarget = item },
                                        modifier = Modifier.fillMaxWidth()
                                            .testTag("inventory_client_counts_read_${item.webPanelAccessId}")) {
                                        Text("Клиенты: сводка по HTTPS")
                                    }
                                }
                                if (section == InventorySection.WEB_PANEL && item.webPanelDirectLinked &&
                                    item.webPanelAccessId != null && linkedClientTrafficReadPort != null) {
                                    OutlinedButton(onClick = { clientTrafficReadTarget = item },
                                        modifier = Modifier.fillMaxWidth()
                                            .testTag("inventory_client_traffic_read_${item.webPanelAccessId}")) {
                                        Text("Трафик клиентов: сводка HTTPS")
                                    }
                                }
                                if (section == InventorySection.WEB_PANEL && item.webPanelDirectLinked &&
                                    item.webPanelAccessId != null && linkedClientQuotaExpiryReadPort != null) {
                                    OutlinedButton(onClick = { clientQuotaExpiryReadTarget = item },
                                        modifier = Modifier.fillMaxWidth()
                                            .testTag("inventory_client_quota_expiry_read_${item.webPanelAccessId}")) {
                                        Text("Лимиты и сроки клиентов: HTTPS")
                                    }
                                }
                                if (section == InventorySection.WEB_PANEL && item.webPanelDirectLinked &&
                                    item.webPanelAccessId != null && linkedInboundDetailsReadPort != null) {
                                    OutlinedButton(onClick = { inboundDetailsReadTarget = item },
                                        modifier = Modifier.fillMaxWidth()
                                            .testTag("inventory_inbound_details_read_${item.webPanelAccessId}")) {
                                        Text("Параметры inbound: HTTPS")
                                    }
                                }
                                if (section == InventorySection.WEB_PANEL && item.webPanelDirectLinked &&
                                    item.webPanelAccessId != null) {
                                    OutlinedButton(onClick = { offlineInboundPreviewTarget = item },
                                        modifier = Modifier.fillMaxWidth()
                                            .testTag("inventory_offline_inbound_preview_${item.webPanelAccessId}")) {
                                        Text("Inbound: офлайн-план изменений")
                                    }
                                }
                                    }
                                }
                                if (section == InventorySection.MANAGEMENT && item.serverId != null && item.installationId != null) {
                                    Button(
                                        onClick = { onReviewManagement(item.serverId, item.installationId) },
                                        modifier = Modifier.fillMaxWidth().testTag("inventory_management_review_${item.installationId}"),
                                    ) { Text("Управлять 3x-ui") }
                                    OutlinedButton(
                                        onClick = { linkedPanelTarget = item },
                                        modifier = Modifier.fillMaxWidth().testTag("inventory_open_linked_panel_${item.installationId}"),
                                    ) { Text("Открыть Web Panel установки") }
                                    if (linkedCredentialPort != null) {
                                        OutlinedButton(
                                            onClick = { linkedCredentialTarget = item },
                                            modifier = Modifier.fillMaxWidth()
                                                .testTag("inventory_save_panel_credential_${item.installationId}"),
                                        ) { Text("Сохранить доступ Web Panel") }
                                    }
                                }
                                if (section == InventorySection.SERVERS && item.serverId != null) {
                                    // Without a saved SSH access, connecting/discovery cannot succeed yet:
                                    // promote "Добавить SSH" to the primary action and move them below.
                                    // The card shows only the next sensible step; everything rare lives under «Ещё».
                                    val needsSsh = item.sshCount == 0
                                    if (needsSsh) {
                                        Button(onClick = { onAddSshAccess(item.serverId, item.title) },
                                            modifier = Modifier.fillMaxWidth().testTag("inventory_add_ssh_${item.serverId}")) {
                                            Text("Добавить SSH-доступ")
                                        }
                                    } else {
                                        Row(modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            val connect = Modifier.weight(1f).testTag("inventory_live_ssh_${item.serverId}")
                                            val discover = Modifier.weight(1f).testTag("inventory_discover_xui_${item.serverId}")
                                            if (item.installationCount == 0) {
                                                Button(onClick = { onDiscoverXui(item.serverId, item.title) }, modifier = discover) {
                                                    Text("Найти 3x-ui", textAlign = TextAlign.Center, maxLines = 2)
                                                }
                                                OutlinedButton(onClick = { onConnectSsh(item.serverId, item.title) }, modifier = connect) {
                                                    Text("Проверить SSH", textAlign = TextAlign.Center, maxLines = 2)
                                                }
                                            } else {
                                                Button(onClick = { onConnectSsh(item.serverId, item.title) }, modifier = connect) {
                                                    Text("Проверить SSH", textAlign = TextAlign.Center, maxLines = 2)
                                                }
                                                OutlinedButton(onClick = { onDiscoverXui(item.serverId, item.title) }, modifier = discover) {
                                                    Text("Найти 3x-ui заново", textAlign = TextAlign.Center, maxLines = 2)
                                                }
                                            }
                                        }
                                    }
                                    var moreExpanded by rememberSaveable(item.serverId) { mutableStateOf(false) }
                                    TextButton(onClick = { moreExpanded = !moreExpanded },
                                        modifier = Modifier.fillMaxWidth().testTag("inventory_more_${item.serverId}")) {
                                        Text(if (moreExpanded) "Скрыть" else "Ещё")
                                    }
                                    if (moreExpanded) {
                                        if (!needsSsh) {
                                            Row(modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                                OutlinedButton(onClick = { onManageSshProfiles(item.serverId, item.title) },
                                                    modifier = Modifier.weight(1f).testTag("inventory_manage_ssh_${item.serverId}")) {
                                                    Text("SSH-профили", textAlign = TextAlign.Center, maxLines = 2)
                                                }
                                                OutlinedButton(onClick = { onAddSshAccess(item.serverId, item.title) },
                                                    modifier = Modifier.weight(1f).testTag("inventory_add_ssh_${item.serverId}")) {
                                                    Text("Ещё один SSH", textAlign = TextAlign.Center, maxLines = 2)
                                                }
                                            }
                                        }
                                        Row(modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            OutlinedButton(onClick = {
                                                renameTarget = item; renameText = item.title; actionNotice = null
                                            }, enabled = !actionBusy,
                                                modifier = Modifier.weight(1f).testTag("inventory_rename_server_${item.serverId}")) {
                                                Text("Переименовать", textAlign = TextAlign.Center, maxLines = 2)
                                            }
                                            if (!needsSsh) {
                                                OutlinedButton(onClick = { onReviewSshReadiness(item.serverId, item.title) },
                                                    modifier = Modifier.weight(1f).testTag("inventory_ssh_readiness_${item.serverId}")) {
                                                    Text("Данные SSH", textAlign = TextAlign.Center, maxLines = 2)
                                                }
                                            }
                                        }
                                        TextButton(onClick = { deleteTarget = item; actionNotice = null },
                                            enabled = !actionBusy,
                                            modifier = Modifier.fillMaxWidth().testTag("inventory_delete_server_${item.serverId}")) {
                                            Text("Удалить с телефона", color = MaterialTheme.colorScheme.error)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (section == InventorySection.WEB_PANEL && privatePanelTarget?.webPanelAccessId != null) {
            PrivatePanelSshLaunchDialog(
                accessId = requireNotNull(privatePanelTarget?.webPanelAccessId),
                standalone = requireNotNull(privatePanelTarget).webPanelStandalone,
                onDismiss = { privatePanelTarget = null },
                onConnect = { request ->
                    privatePanelTarget = null
                    onOpenPrivateWebPanel(if (webPanelScope != null) request.copy(scope = webPanelScope) else request)
                },
            )
        }
        if (section == InventorySection.WEB_PANEL && standaloneCredentialDialog && linkedCredentialPort != null) {
            StandalonePrivatePanelCredentialDialog(
                servers = serverRepository,
                sshAccesses = serverAccessRepository,
                port = linkedCredentialPort,
                onDismiss = { standaloneCredentialDialog = false },
                onSaved = { standaloneCredentialDialog = false; refresh++ },
            )
        }
        if (section == InventorySection.WEB_PANEL && webPanelScope == null) {
            var manualExpanded by rememberSaveable { mutableStateOf(false) }
            TextButton(onClick = { manualExpanded = !manualExpanded },
                modifier = Modifier.fillMaxWidth().testTag("inventory_manual_https_toggle")) {
                Text(if (manualExpanded) "Скрыть ввод адреса" else "Открыть панель по HTTPS-адресу вручную")
            }
            if (manualExpanded) ExactHttpsWebPanelEntry(onOpenInApp = onOpenWebPanelInApp)
        }
        if (section == InventorySection.WEB_PANEL && loginCheckTarget?.webPanelAccessId != null &&
            linkedLoginCheckPort != null) {
            LinkedWebPanelLoginCheckDialog(
                accessId = requireNotNull(loginCheckTarget?.webPanelAccessId),
                port = linkedLoginCheckPort,
                onDismiss = { loginCheckTarget = null },
            )
        }
        if (section == InventorySection.WEB_PANEL && inboundReadTarget?.webPanelAccessId != null &&
            linkedInboundReadPort != null) {
            LinkedWebPanelInboundReadDialog(
                accessId = requireNotNull(inboundReadTarget?.webPanelAccessId),
                port = linkedInboundReadPort,
                onDismiss = { inboundReadTarget = null },
            )
        }
        if (section == InventorySection.WEB_PANEL && serverStatusReadTarget?.webPanelAccessId != null &&
            linkedServerStatusReadPort != null) {
            LinkedWebPanelServerStatusDialog(
                accessId = requireNotNull(serverStatusReadTarget?.webPanelAccessId),
                port = linkedServerStatusReadPort,
                onDismiss = { serverStatusReadTarget = null },
            )
        }
        if (section == InventorySection.WEB_PANEL && clientCountReadTarget?.webPanelAccessId != null &&
            linkedClientCountReadPort != null) {
            LinkedWebPanelClientCountReadDialog(
                accessId = requireNotNull(clientCountReadTarget?.webPanelAccessId),
                port = linkedClientCountReadPort,
                onDismiss = { clientCountReadTarget = null },
            )
        }
        if (section == InventorySection.WEB_PANEL && clientTrafficReadTarget?.webPanelAccessId != null &&
            linkedClientTrafficReadPort != null) {
            LinkedWebPanelClientTrafficReadDialog(
                accessId = requireNotNull(clientTrafficReadTarget?.webPanelAccessId),
                port = linkedClientTrafficReadPort,
                onDismiss = { clientTrafficReadTarget = null },
            )
        }
        if (section == InventorySection.WEB_PANEL && clientQuotaExpiryReadTarget?.webPanelAccessId != null &&
            linkedClientQuotaExpiryReadPort != null) {
            LinkedWebPanelClientQuotaExpiryReadDialog(
                accessId = requireNotNull(clientQuotaExpiryReadTarget?.webPanelAccessId),
                port = linkedClientQuotaExpiryReadPort,
                onDismiss = { clientQuotaExpiryReadTarget = null },
            )
        }
        if (section == InventorySection.WEB_PANEL && inboundDetailsReadTarget?.webPanelAccessId != null &&
            linkedInboundDetailsReadPort != null) {
            LinkedWebPanelInboundDetailsReadDialog(
                accessId = requireNotNull(inboundDetailsReadTarget?.webPanelAccessId),
                port = linkedInboundDetailsReadPort,
                onDismiss = { inboundDetailsReadTarget = null },
            )
        }
        if (section == InventorySection.WEB_PANEL && offlineInboundPreviewTarget?.webPanelAccessId != null) {
            LocalInboundChangePreviewDialog(
                accessId = requireNotNull(offlineInboundPreviewTarget?.webPanelAccessId),
                onDismiss = { offlineInboundPreviewTarget = null },
            )
        }
        if (section == InventorySection.WEB_PANEL && webPanelScope != null && scopedCredentialDialog &&
            linkedCredentialPort != null) {
            LinkedWebPanelCredentialDialog(
                serverId = webPanelScope.serverId,
                installationId = webPanelScope.installationId,
                port = linkedCredentialPort,
                sshAccesses = serverAccessRepository,
                onDismiss = { scopedCredentialDialog = false },
                onSaved = { scopedCredentialDialog = false; refresh++ },
            )
        }
        if (section == InventorySection.MANAGEMENT && linkedCredentialTarget != null && linkedCredentialPort != null) {
            val item = requireNotNull(linkedCredentialTarget)
            val server = item.serverId
            val installation = item.installationId
            if (server != null && installation != null) {
                LinkedWebPanelCredentialDialog(
                    serverId = server,
                    installationId = installation,
                    port = linkedCredentialPort,
                    sshAccesses = serverAccessRepository,
                    onDismiss = { linkedCredentialTarget = null },
                    onSaved = {
                        linkedCredentialTarget = null
                        refresh++
                    },
                )
            }
        }
        if (section == InventorySection.MANAGEMENT && linkedPanelTarget != null) {
            val item = requireNotNull(linkedPanelTarget)
            val server = item.serverId
            val installation = item.installationId
            if (server != null && installation != null) {
                LinkedInstallationHttpsLaunchDialog(
                    serverId = server,
                    installationId = installation,
                    installationRepository = installationRepository,
                    onDismiss = { linkedPanelTarget = null },
                    onOpenInApp = onOpenWebPanelInApp,
                )
            }
        }
        if (section == InventorySection.SERVERS && renameTarget != null) {
            val item = requireNotNull(renameTarget)
            AlertDialog(
                onDismissRequest = { if (!actionBusy) renameTarget = null },
                title = { Text("Переименовать сервер") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("Изменится только название локальной карточки. VPS и SSH-настройки останутся прежними.")
                        OutlinedTextField(
                            value = renameText,
                            onValueChange = { renameText = it },
                            label = { Text("Новое название") },
                            enabled = !actionBusy,
                            singleLine = true,
                            modifier = Modifier.testTag("inventory_rename_input"),
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = { performAction({ cardActions.rename(requireNotNull(item.serverId), item.title, renameText) }, "Название сервера изменено.") },
                        enabled = !actionBusy,
                        modifier = Modifier.testTag("inventory_rename_confirm"),
                    ) { Text("Сохранить") }
                },
                dismissButton = { OutlinedButton(onClick = { renameTarget = null }, enabled = !actionBusy, modifier = Modifier.testTag("inventory_rename_cancel")) { Text("Отмена") } },
            )
        }
        if (section == InventorySection.SERVERS && deleteTarget != null) {
            val item = requireNotNull(deleteTarget)
            val linked = item.sshCount > 0 || item.installationCount > 0
            val purge = purgeServer
            var typedName by remember(item.serverId) { mutableStateOf("") }
            val fullDelete = linked && purge != null
            AlertDialog(
                onDismissRequest = { if (!actionBusy) deleteTarget = null },
                title = { Text(if (fullDelete) "Удалить сервер с телефона?" else "Удалить локальную карточку?") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(when {
                            fullDelete -> "С телефона будут удалены «${item.title}» и всё, что с ним связано: " +
                                "SSH-профили (${item.sshCount}), записи установок X-UI (${item.installationCount}), " +
                                "сохранённые входы в панель, отпечатки сертификатов и история операций. " +
                                "Пароли будут стёрты из защищённого хранилища. На VPS ничего не изменится — " +
                                "сервер можно снова добавить и найти 3x-ui. Отменить удаление нельзя."
                            linked -> "У «${item.title}» есть SSH-доступы или установки X-UI. Удаление заблокировано до отдельного безопасного удаления связей. VPS не затронут."
                            else -> "Удалить «${item.title}» только из этого приложения? На VPS ничего не удалится. Отменить удаление после подтверждения нельзя."
                        })
                        if (fullDelete) OutlinedTextField(
                            typedName, { typedName = it }, singleLine = true,
                            label = { Text("Введите название сервера: ${item.title}") },
                            modifier = Modifier.fillMaxWidth().testTag("inventory_delete_typed_name"),
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            if (fullDelete) performAction({
                                cardActions.deleteWithLocalRecords(requireNotNull(item.serverId), item.title, requireNotNull(purge))
                            }, "Сервер и все его записи удалены с телефона. VPS не затронут.")
                            else performAction({ cardActions.deleteEmpty(requireNotNull(item.serverId), item.title) }, "Пустая карточка сервера удалена с телефона.")
                        },
                        enabled = !actionBusy && (!linked || (fullDelete && typedName.trim() == item.title)),
                        modifier = Modifier.testTag("inventory_delete_confirm"),
                    ) { Text("Удалить") }
                },
                dismissButton = { OutlinedButton(onClick = { deleteTarget = null }, enabled = !actionBusy, modifier = Modifier.testTag("inventory_delete_cancel")) { Text("Отмена") } },
            )
        }
    }
    }
}

private const val SEARCH_THRESHOLD = 4

/** One human line for a server card: where it is and what the next step is. */
internal fun serverCardDetail(hosts: List<String>, sshCount: Int, installationCount: Int): String = when {
    sshCount == 0 -> "SSH-доступ ещё не добавлен"
    else -> listOfNotNull(
        hosts.singleOrNull() ?: hosts.firstOrNull()?.let { "$it и ещё ${hosts.size - 1}" },
        if (sshCount > 1) "SSH-профилей: $sshCount" else null,
        if (installationCount > 0) "3x-ui найдена" else "3x-ui ещё не найдена",
    ).joinToString(" · ")
}

private suspend fun loadInventory(
    section: InventorySection,
    serverRepository: ServerRepository,
    serverAccessRepository: ServerAccessRepository,
    installationRepository: XuiInstallationRepository,
    managementAccessRepository: ManagementAccessRepository,
    webPanelAccessRepository: WebPanelAccessRepository,
    webPanelScope: WebPanelInstallationScope? = null,
    panelResolver: ExactWebPanelTargetResolver? = null,
): InventoryLoad {
    if (section == InventorySection.WEB_PANEL) {
        if (webPanelScope != null) {
            // Confirm the installation really belongs to the server before listing anything.
            val owned = when (val read = installationRepository.listForServer(ServerId(webPanelScope.serverId))) {
                is RepositoryResult.Success -> read.value.any {
                    it.value.id.value == webPanelScope.installationId && it.value.serverId.value == webPanelScope.serverId
                }
                else -> return InventoryLoad.Error("Не удалось подтвердить установку сервера в локальной базе.")
            }
            if (!owned) return InventoryLoad.Ready(emptyList())
        }
        val records = when (val read = webPanelAccessRepository.list()) {
            is RepositoryResult.Success -> read.value
            else -> return InventoryLoad.Error("Не удалось прочитать Web Panel доступы из локальной базы.")
        }
        val exactLink = webPanelScope?.let { WebPanelInstallationLink.Linked(XuiInstallationId(it.installationId)) }
        return InventoryLoad.Ready(records.filter { exactLink == null || it.value.installationLink == exactLink }.map { record ->
            val access = record.value
            val relation = when (access.installationLink) {
                WebPanelInstallationLink.Standalone -> "Самостоятельный Web Panel доступ"
                is WebPanelInstallationLink.Linked -> "Связь с установкой подтверждена"
            }
            var route = when (val path = access.route) {
                is WebPanelRoute.Direct -> "Прямое подключение: ${path.originHost}"
                is WebPanelRoute.SshTunnel -> "Через сохранённый SSH-туннель"
            }
            if (webPanelScope != null && panelResolver != null) {
                // Exact link text from the same resolver; read-only, no network.
                val resolved = panelResolver.resolve(WebPanelTargetResolutionRequest(access.id, WebPanelScheme.HTTPS))
                val target = (resolved as? WebPanelTargetResolutionResult.Resolved)?.target
                if (target != null && webPanelTargetMatchesScope(webPanelScope, target.installation, target.routeTarget)) {
                    when (val rt = target.routeTarget) {
                        is ResolvedWebPanelRouteTarget.Direct ->
                            savedLinkedWebPanelHttpsUrl(target.installation, rt)?.let { route = "HTTPS: $it" }
                        is ResolvedWebPanelRouteTarget.SshTunnel -> {
                            val host = rt.remoteEndpoint.host.value
                            val address = if (':' in host) "[$host]" else host
                            route = "SSH: $address:${rt.remoteEndpoint.port}${rt.webBasePath.value}"
                        }
                    }
                }
            }
            InventoryItem(
                title = "Web Panel · ${access.username}",
                detail = route,
                support = relation,
                webPanelAccessId = access.id.value,
                serverId = webPanelScope?.serverId,
                installationId = webPanelScope?.installationId,
                webPanelDirectLinked = access.installationLink is WebPanelInstallationLink.Linked &&
                    access.route is WebPanelRoute.Direct,
                webPanelSshLinked = access.route is WebPanelRoute.SshTunnel,
                webPanelStandalone = access.installationLink == WebPanelInstallationLink.Standalone,
            )
        })
    }

    val servers = when (val read = serverRepository.list()) {
        is RepositoryResult.Success -> read.value.map { it.value }
        else -> return InventoryLoad.Error("Не удалось прочитать список серверов из локальной базы.")
    }
    if (section == InventorySection.SERVERS) {
        val items = mutableListOf<InventoryItem>()
        for (server in servers) {
            val accesses = when (val read = serverAccessRepository.listForServer(server.id)) {
                is RepositoryResult.Success -> read.value
                else -> return InventoryLoad.Error("Не удалось прочитать сохранённые SSH-доступы.")
            }
            val installations = when (val read = installationRepository.listForServer(server.id)) {
                is RepositoryResult.Success -> read.value
                else -> return InventoryLoad.Error("Не удалось прочитать установки X-UI.")
            }
            items.add(
                InventoryItem(
                    title = server.displayName,
                    detail = serverCardDetail(
                        accesses.map { it.endpoint.host }.distinct(), accesses.size, installations.size,
                    ),
                    support = "",
                    serverId = server.id.value,
                    sshCount = accesses.size,
                    installationCount = installations.size,
                ),
            )
        }
        return InventoryLoad.Ready(items)
    }

    val items = mutableListOf<InventoryItem>()
    for (server: Server in servers) {
        val installations = when (val read = installationRepository.listForServer(server.id)) {
            is RepositoryResult.Success -> read.value
            else -> return InventoryLoad.Error("Не удалось прочитать локальные установки X-UI.")
        }
        for (record in installations) {
            val installation = record.value
            val management = when (val read = managementAccessRepository.listForInstallation(installation.id)) {
                is RepositoryResult.Success -> read.value
                else -> return InventoryLoad.Error("Не удалось проверить привязку SSH-управления.")
            }
            if (management.isNotEmpty()) {
                items.add(
                    InventoryItem(
                        title = server.displayName,
                        detail = "3x-ui · порт панели ${installation.baseline.panelPort}",
                        support = "",
                        serverId = server.id.value,
                        installationId = installation.id.value,
                    ),
                )
            }
        }
    }
    return InventoryLoad.Ready(items)
}
