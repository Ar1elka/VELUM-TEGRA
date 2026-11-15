package com.velumtegra.xuimobile.feature.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/** Operational home: real entry points, never inferred online/VPS statuses. */
@Composable
fun HomeScreen(
    darkTheme: Boolean = true,
    onDarkThemeChange: (Boolean) -> Unit = {},
    scannerRunning: Boolean = false,
    scannerPaused: Boolean = false,
    scannerNetworkLost: Boolean = false,
    scannerCompleted: Int = 0,
    scannerFeasible: Int = 0,
    onOpenScanner: () -> Unit = {},
    onStopScanner: () -> Unit = {},
    onOpenSiteDeployer: () -> Unit = {},
    onOpenServers: () -> Unit = {},
    onOpenManagement: () -> Unit = {},
    onOpenWebPanel: () -> Unit = {},
    onOpenSshPort: (() -> Unit)? = null,
    onOpenBlocklist: (() -> Unit)? = null,
) {
    BoxWithConstraints(
        modifier = Modifier.fillMaxSize().safeDrawingPadding(),
        contentAlignment = Alignment.TopCenter,
    ) {
    val wide = maxWidth >= 680.dp
    Column(
        modifier = Modifier.widthIn(max = 1040.dp).fillMaxSize().testTag("home_root")
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 18.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text("VELUM//TEGRA", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.ExtraBold)
                Text("Центр управления", style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Surface(shape = MaterialTheme.shapes.small,
                color = MaterialTheme.colorScheme.primaryContainer,
                contentColor = MaterialTheme.colorScheme.onPrimaryContainer) {
                Text("V//T", modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                    style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
            }
        }

        Text("Серверы", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        if (wide) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            DashboardAction(label = "Серверы", description = "VPS и SSH", symbol = "▤",
                onClick = onOpenServers, modifier = Modifier.weight(1f).testTag("home_servers"))
            DashboardAction(label = "X-UI", description = "Установки", symbol = "⌘",
                onClick = onOpenManagement, modifier = Modifier.weight(1f).testTag("home_management"))
            DashboardAction(label = "Веб-панель", description = "Профили", symbol = "◫",
                onClick = onOpenWebPanel, modifier = Modifier.weight(1f).testTag("home_web_panel"))
        }
        } else {
            DashboardAction(label = "Мои серверы", description = "Добавить VPS и SSH-доступ", symbol = "▤",
                onClick = onOpenServers, modifier = Modifier.fillMaxWidth().testTag("home_servers"))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                DashboardAction(label = "Управление 3x-ui", description = "Установка и состояние", symbol = "⌘",
                    onClick = onOpenManagement, modifier = Modifier.weight(1f).testTag("home_management"))
                DashboardAction(label = "Веб-панель", description = "Открыть 3x-ui",  symbol = "◫",
                    onClick = onOpenWebPanel, modifier = Modifier.weight(1f).testTag("home_web_panel"))
            }
        }

        if (onOpenSshPort != null || onOpenBlocklist != null) {
            Text("Защита сервера", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                onOpenSshPort?.let { open ->
                    DashboardAction(label = "SSH-порт", description = "Сменить порт входа", symbol = "↔",
                        onClick = open, modifier = Modifier.weight(1f).testTag("home_ssh_port"))
                }
                onOpenBlocklist?.let { open ->
                    DashboardAction(label = "От сканеров", description = "Блок-лист сетей", symbol = "⛨",
                        onClick = open, modifier = Modifier.weight(1f).testTag("home_as_blocklist"))
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth().testTag("home_scanner_card"),
            shape = MaterialTheme.shapes.large,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Reality Scanner", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    Surface(shape = MaterialTheme.shapes.small,
                        color = if (scannerRunning) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface,
                        contentColor = if (scannerRunning) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface) {
                        Text(if (scannerRunning) "АКТИВЕН" else "ГОТОВ",
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 5.dp),
                            style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                    }
                }
                Text(if (scannerRunning) {
                    "${scannerStatusLabel(scannerPaused, scannerNetworkLost)} · Проверено $scannerCompleted · Найдено $scannerFeasible"
                } else {
                    "Поиск подходящих IP и проверка маршрута прямо с телефона."
                }, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onOpenScanner,
                        modifier = Modifier.weight(1f).testTag("home_reality_scanner")) {
                        Text("Открыть сканер")
                    }
                    if (scannerRunning) {
                        OutlinedButton(onClick = onStopScanner, modifier = Modifier.weight(1f)) {
                            Text("Остановить")
                        }
                    }
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.large,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Конструктор сайта", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text("Создайте вариант, проверьте его и опубликуйте на выбранном VPS.",
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedButton(onClick = onOpenSiteDeployer,
                    modifier = Modifier.fillMaxWidth().testTag("home_site_deployer_review")) {
                    Text("Открыть конструктор")
                }
            }
        }

        Surface(
            modifier = Modifier.fillMaxWidth().testTag("home_theme_card"),
            color = MaterialTheme.colorScheme.surfaceVariant,
            shape = MaterialTheme.shapes.medium,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Тема приложения", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Text(
                        if (darkTheme) "Тёмная · чёрный и красный" else "Светлая · красный и белый",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = darkTheme,
                    onCheckedChange = onDarkThemeChange,
                    modifier = Modifier.testTag("home_dark_theme_switch"),
                )
            }
        }
    }
    }
}

@Composable
private fun DashboardAction(label: String, description: String, symbol: String,
                            onClick: () -> Unit, modifier: Modifier = Modifier) {
    OutlinedButton(
        onClick = onClick, modifier = modifier.heightIn(min = 80.dp),
        shape = MaterialTheme.shapes.medium,
        contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 5.dp, vertical = 10.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(symbol, style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold,
                maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text(description, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

private fun scannerStatusLabel(paused: Boolean, networkLost: Boolean): String = when {
    networkLost -> "НЕТ СВЯЗИ"
    paused -> "НА ПАУЗЕ"
    else -> "СКАНИРОВАНИЕ"
}
