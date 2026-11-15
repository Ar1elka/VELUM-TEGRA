package com.velumtegra.xuimobile.scanner

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Environment
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.FileProvider
import com.velumtegra.xuimobile.core.scanner.RealityScanProgress
import com.velumtegra.xuimobile.core.scanner.RealityScanResult
import com.velumtegra.xuimobile.core.scanner.RealityScanResultGrouping
import com.velumtegra.xuimobile.core.scanner.RealityScanResultRanking
import com.velumtegra.xuimobile.core.scanner.RealitySniRatingProjection
import com.velumtegra.xuimobile.core.scanner.RealitySniVerdict
import com.velumtegra.xuimobile.core.scanner.android.CheburcheckSniAnalyzer
import com.velumtegra.xuimobile.core.scanner.android.GeoIpResolver
import com.velumtegra.xuimobile.core.scanner.android.RealityScanSession
import com.velumtegra.xuimobile.core.scanner.android.RealityScanSessionStore
import com.velumtegra.xuimobile.core.scanner.RealitySniAnalysis
import com.velumtegra.xuimobile.core.scanner.android.RealityScannerEngine
import com.velumtegra.xuimobile.core.scanner.android.RealityScannerForegroundService
import androidx.compose.material3.LinearProgressIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** One run of "check every SNI" asks a public service at most this many times. */
private const val SNI_BATCH_LIMIT = 100

private fun RealitySniVerdict.displayLabel(): String =
    when (this) {
        RealitySniVerdict.CLEAN -> "Чистый SNI"
        RealitySniVerdict.WHITELIST_CONFIRMED -> "Белый список — подтверждено"
        RealitySniVerdict.WHITELIST_CANDIDATE -> "Белый список — кандидат"
        RealitySniVerdict.BLOCKED -> "Есть блокировка"
        RealitySniVerdict.UNKNOWN -> "Не определено"
    }

private fun RealityScanResult.asCopyText(): String =
    buildString {
        appendLine("Reality Scanner")
        appendLine("$ip:$port")
        if (origin.isNotBlank() && origin != ip) appendLine("Источник: $origin")
        appendLine("Соответствует критериям: ${if (feasible) "да" else "нет"}")
        appendLine("TLS: ${tls.ifBlank { "—" }}")
        appendLine("ALPN: ${alpn.ifBlank { "—" }}")
        appendLine("Домен: ${certificateDomain.ifBlank { "—" }}")
        appendLine("Issuer: ${certificateIssuer.ifBlank { "—" }}")
        appendLine("Cipher: ${cipherSuite.ifBlank { "—" }}")
        appendLine("Curve: ${curve ?: "N/A (Android TLS)"}")
        appendLine("Geo: ${geo.ifBlank { "N/A" }}")
        appendLine("Ping: ${latencyMs?.let { "$it ms" } ?: "—"}")
        appendLine("SNI: ${selectedSni ?: "—"}")
        if (sniCandidates.isNotEmpty()) appendLine("SNI-кандидаты: ${sniCandidates.joinToString(", ")}")
        sniAnalysis?.let { analysis ->
            appendLine("SNI-анализ: ${analysis.verdict.displayLabel()}")
            if (analysis.reasons.isNotEmpty()) appendLine("SNI-причины: ${analysis.reasons.joinToString(", ")}")
            if (analysis.source.isNotBlank()) appendLine("SNI-источник: ${analysis.source}")
        }
        error?.let { appendLine("Ошибка: $it") }
    }.trimEnd()

private fun formatScanTime(timestamp: Long): String =
    SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(timestamp))

private fun buildCsv(results: List<RealityScanResult>): String =
    buildString {
        appendLine("IP,PORT,ORIGIN,FEASIBLE,TLS,ALPN,CURVE,CERT_DOMAIN,CERT_ISSUER,CIPHER,GEO,PING_MS,SELECTED_SNI,SNI_CANDIDATES,SNI_VERDICT,SNI_ANALYSIS_REASONS,SNI_ANALYSIS_SOURCE,SNI_ANALYZED_AT,ERROR")
        results.forEach { r ->
            listOf(
                r.ip,
                r.port.toString(),
                r.origin,
                r.feasible.toString(),
                r.tls,
                r.alpn,
                r.curve ?: "",
                r.certificateDomain,
                r.certificateIssuer,
                r.cipherSuite,
                r.geo,
                r.latencyMs?.toString() ?: "",
                r.selectedSni ?: "",
                r.sniCandidates.joinToString(";"),
                r.sniAnalysis?.verdict?.name ?: "",
                r.sniAnalysis?.reasons?.joinToString(";") ?: "",
                r.sniAnalysis?.source ?: "",
                r.sniAnalysis?.checkedAt?.toString() ?: "",
                r.error ?: "",
            ).joinToString(",") { value -> "\"${value.replace("\"", "\"\"")}\"" }.let(::appendLine)
        }
    }.trimEnd()

private fun buildJson(results: List<RealityScanResult>): String =
    JSONObject()
        .put("generatedAt", System.currentTimeMillis())
        .put(
            "results",
            JSONArray().apply {
                results.forEach { result ->
                    put(
                        JSONObject()
                            .put("id", result.id)
                            .put("origin", result.origin)
                            .put("ip", result.ip)
                            .put("port", result.port)
                            .put("feasible", result.feasible)
                            .put("tls", result.tls)
                            .put("alpn", result.alpn)
                            .put("certificateDomain", result.certificateDomain)
                            .put("certificateIssuer", result.certificateIssuer)
                            .put("cipherSuite", result.cipherSuite)
                            .put("curve", result.curve ?: "")
                            .put("geo", result.geo)
                            .put("latencyMs", result.latencyMs ?: JSONObject.NULL)
                            .put("selectedSni", result.selectedSni ?: "")
                            .put("sniCandidates", JSONArray(result.sniCandidates))
                            .put(
                                "sniAnalysis",
                                result.sniAnalysis?.let { analysis ->
                                    JSONObject()
                                        .put("sni", analysis.sni)
                                        .put("verdict", analysis.verdict.name)
                                        .put("reasons", JSONArray(analysis.reasons))
                                        .put("source", analysis.source)
                                        .put("checkedAt", analysis.checkedAt)
                                } ?: JSONObject.NULL,
                            )
                            .put("error", result.error ?: "")
                            .put("timestamp", result.timestamp),
                    )
                }
            },
        ).toString(2)

private fun createExportFile(context: Context, extension: String, content: String): Uri? =
    runCatching {
        val dir = context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS) ?: return null
        if (!dir.exists()) dir.mkdirs()
        val file =
            File(
                dir,
                "reality_scan_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())}.$extension",
            )
        file.writeText(content, Charsets.UTF_8)
        FileProvider.getUriForFile(context, context.packageName + ".fileprovider", file)
    }.getOrNull()

private fun shareFile(context: Context, uri: Uri, mimeType: String) {
    runCatching {
        val send =
            Intent(Intent.ACTION_SEND).apply {
                type = mimeType
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                clipData = ClipData.newRawUri("Reality Scanner", uri)
            }
        context.startActivity(Intent.createChooser(send, "Экспорт Reality Scanner"))
    }
}

private fun copyText(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText("Reality Scanner", text))
}

@Composable
fun RealityScannerScreen(
    modifier: Modifier = Modifier,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val geoDatabase = remember { File(context.filesDir, "Country.mmdb") }
    val geoUpdater = remember { GeoIpAutoUpdater(context.applicationContext) }
    val sniAnalyzer = remember { CheburcheckSniAnalyzer(context.applicationContext) }

    var geoReady by remember { mutableStateOf(geoDatabase.exists()) }
    var geoStatus by remember { mutableStateOf(if (geoReady) "База найдена" else "База не установлена") }
    var geoUpdating by remember { mutableStateOf(false) }

    val geoPicker =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) {
                runCatching {
                    context.contentResolver.openInputStream(uri).use { input ->
                        requireNotNull(input) { "Не удалось открыть Country.mmdb." }
                        geoDatabase.outputStream().use { output -> input.copyTo(output) }
                    }
                    geoReady = geoDatabase.exists() && geoDatabase.length() > 0
                    geoStatus = if (geoReady) GeoIpResolver.validate(geoDatabase) else "Файл не скопирован"
                }.onFailure { error ->
                    geoReady = false
                    geoStatus = "Ошибка: ${error.message ?: "не удалось импортировать"}"
                }
            }
        }

    LaunchedEffect(Unit) {
        RealityScannerForegroundService.ensureRunning(context)
        geoUpdating = true
        val update = geoUpdater.updateIfNeeded(force = false)
        geoReady = update.available && update.databaseFile.exists()
        geoStatus = update.status
        geoUpdating = false
    }

    val engine = remember { RealityScannerEngine() }
    var input by rememberSaveable { mutableStateOf("") }
    // Reality lives on 443 and eight threads suit a phone; an empty field only cost an extra error.
    var port by rememberSaveable { mutableStateOf("443") }
    var threads by rememberSaveable { mutableStateOf("8") }
    var ipv6 by rememberSaveable { mutableStateOf(false) }
    var tls12 by rememberSaveable { mutableStateOf(false) }
    var scanning by remember { mutableStateOf(false) }
    var paused by remember { mutableStateOf(false) }
    var networkLost by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(RealityScanProgress(0, 0, 0)) }
    var results by remember { mutableStateOf(RealityScanSessionStore.loadCurrent(context)) }
    var history by remember { mutableStateOf(RealityScanSessionStore.loadHistory(context)) }
    var favorites by remember { mutableStateOf(RealityScanSessionStore.loadFavorites(context)) }
    var error by remember { mutableStateOf<String?>(null) }

    var showAdditional by rememberSaveable { mutableStateOf(false) }
    var showResults by rememberSaveable { mutableStateOf(false) }
    var showHistory by rememberSaveable { mutableStateOf(false) }
    var showFavorites by rememberSaveable { mutableStateOf(false) }
    var showClearHistoryConfirm by rememberSaveable { mutableStateOf(false) }
    var selectedResult by remember { mutableStateOf<RealityScanResult?>(null) }
    var showSniPicker by rememberSaveable { mutableStateOf(false) }
    var analyzingSniId by remember { mutableStateOf<String?>(null) }
    var serviceError by remember { mutableStateOf("") }
    var sniBatchJob by remember { mutableStateOf<Job?>(null) }
    var sniBatchStatus by remember { mutableStateOf<String?>(null) }
    val liveResultGroups = remember(results) { RealityScanResultGrouping.split(results) }
    val inputSummary = remember(input, ipv6) { engine.summarizeInput(input, ipv6) }

    LaunchedEffect(Unit) {
        var seenRevision = -1L
        while (true) {
            val state = RealityScannerForegroundService.state(context)
            scanning = state.running
            paused = state.paused
            networkLost = state.networkLost
            serviceError = state.error
            if (state.running && state.input.isNotBlank()) {
                input = state.input
                port = state.port.toString()
                threads = state.threads.toString()
                ipv6 = state.ipv6
                tls12 = state.tls12
            }
            progress = RealityScanProgress(state.total, state.completed, state.feasible)
            // Re-parsing the current list, up to 50 history sessions and favorites twice a second kept the
            // phone busy for nothing; the store says when something was actually written.
            val revision = RealityScanSessionStore.revision()
            if (revision != seenRevision) {
                val (current, savedHistory, savedFavorites) = withContext(Dispatchers.IO) {
                    Triple(
                        RealityScanSessionStore.loadCurrent(context),
                        RealityScanSessionStore.loadHistory(context),
                        RealityScanSessionStore.loadFavorites(context),
                    )
                }
                results = current
                history = savedHistory
                favorites = savedFavorites
                seenRevision = revision
            }
            delay(500)
        }
    }

    BackHandler { onBack() }

    fun startScan() {
        if (scanning) return
        // The service used to reject an unreadable target silently and the screen just returned to "ready".
        val validation =
            ScannerUiProjection.validateStart(input, port, threads) ?: engine.inputProblem(input, ipv6)
        if (validation != null) {
            error = validation
            return
        }
        error = null
        serviceError = ""
        results = emptyList()
        RealityScanSessionStore.clearCurrent(context)
        RealityScannerForegroundService.start(
            context = context,
            input = input,
            port = port.toInt(),
            threadCount = threads.toInt(),
            enableIpv6 = ipv6,
            enableTls12 = tls12,
            geoDatabase = geoDatabase.takeIf { geoReady },
        )
    }

    fun toggleFavorite(result: RealityScanResult) {
        val next =
            if (favorites.any { it.id == result.id }) {
                favorites.filterNot { it.id == result.id }
            } else {
                favorites + result
            }
        favorites = next.distinctBy { it.id }
        RealityScanSessionStore.saveFavorites(context, favorites)
    }

    fun applyUpdatedResult(updated: RealityScanResult) {
        RealityScanSessionStore.updateResultEverywhere(context, updated)
        results = results.map { if (it.id == updated.id) updated else it }
        favorites = favorites.map { if (it.id == updated.id) updated else it }
        history =
            history.map { session ->
                session.copy(results = session.results.map { if (it.id == updated.id) updated else it })
            }
        if (selectedResult?.id == updated.id) selectedResult = updated
    }

    fun selectSni(result: RealityScanResult, sni: String) {
        if (sni !in result.sniCandidates || result.selectedSni == sni) return
        applyUpdatedResult(result.copy(selectedSni = sni, sniAnalysis = null))
        showSniPicker = false
    }

    fun analyzeSelectedSni(result: RealityScanResult) {
        val sni = result.selectedSni ?: return
        if (analyzingSniId != null) return
        analyzingSniId = result.id
        scope.launch {
            val analysis = sniAnalyzer.analyze(sni)
            val latest = results.firstOrNull { it.id == result.id } ?: selectedResult ?: result
            applyUpdatedResult(latest.copy(sniAnalysis = analysis))
            analyzingSniId = null
        }
    }

    /**
     * The rating columns stay empty until every result is opened and checked by hand, so one tap checks the
     * whole list. Requests go one by one, each distinct SNI once; a second tap stops the run.
     */
    fun analyzeAllSni(source: List<RealityScanResult>) {
        sniBatchJob?.takeIf { it.isActive }?.let { running ->
            running.cancel()
            return
        }
        val pending =
            source.filter { item ->
                val sni = item.selectedSni
                sni != null && item.sniAnalysis?.sni?.equals(sni, ignoreCase = true) != true
            }
        if (pending.isEmpty()) {
            sniBatchStatus = "Все SNI в этом списке уже проверены."
            return
        }
        val batch = pending.take(SNI_BATCH_LIMIT)
        sniBatchJob =
            scope.launch {
                var finalStatus = "Проверка SNI остановлена."
                try {
                    val known = HashMap<String, RealitySniAnalysis>()
                    var unavailable = 0
                    var checked = 0
                    for ((index, item) in batch.withIndex()) {
                        sniBatchStatus = "Проверяю SNI: ${index + 1} из ${batch.size}…"
                        val sni = item.selectedSni ?: continue
                        val analysis =
                            known[sni] ?: sniAnalyzer.analyze(sni).also { fresh ->
                                if (fresh.source == "unavailable") unavailable++ else known[sni] = fresh
                                delay(250) // a public service: no bursts
                            }
                        if (analysis.source == "unavailable") {
                            if (unavailable >= 3) {
                                finalStatus = "Сервис проверки SNI не отвечает. Проверено: $checked. Попробуй позже."
                                return@launch
                            }
                            continue // leave it unchecked so the next run retries it
                        }
                        unavailable = 0
                        val latest = (results + favorites).firstOrNull { it.id == item.id } ?: item
                        if (latest.selectedSni == sni) applyUpdatedResult(latest.copy(sniAnalysis = analysis))
                        checked++
                    }
                    val left = pending.size - batch.size
                    finalStatus =
                        "Проверено SNI: $checked." +
                            if (left > 0) " Осталось $left — нажми ещё раз." else ""
                } finally {
                    sniBatchStatus = finalStatus
                    sniBatchJob = null
                }
            }
    }

    ResponsiveScannerColumn(
        modifier = modifier.testTag("reality_scanner_root"),
        scroll = true,
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.testTag("reality_scanner_back"),
            ) { Text("‹ Назад") }
            Column {
                Text("Reality Scanner", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.primary)
                Text("Поиск ближайших подходящих узлов", style = MaterialTheme.typography.bodySmall)
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                val checked =
                    "Проверено ${progress.completed}" +
                        if (progress.total > 0) " из ${progress.total} (${progress.percent}%)" else ""
                val finishedRun = !scanning && progress.completed > 0
                val statusTitle =
                    when {
                        scanning && networkLost -> "Связь потеряна"
                        scanning && paused -> "Сканирование на паузе"
                        scanning -> "Сканирование выполняется"
                        finishedRun -> "Сканирование завершено"
                        results.isNotEmpty() -> "Последний запуск завершён"
                        else -> "Готов к сканированию"
                    }
                val statusDetails =
                    when {
                        scanning && networkLost -> "Foreground Service сохранил сеанс и ждёт восстановления сети."
                        scanning && paused -> "Сеанс сохранён. $checked • найдено ${progress.feasible}"
                        scanning -> "$checked • найдено ${progress.feasible}"
                        finishedRun && progress.feasible == 0 ->
                            "$checked • подходящих узлов нет. Попробуй другой адрес или порт."
                        finishedRun -> "$checked • подходящих ${progress.feasible}"
                        results.isNotEmpty() -> "Результатов ${results.size} • TLS 1.3 ${liveResultGroups.tls13.size} • TLS 1.2 ${liveResultGroups.tls12.size}"
                        else -> "Укажи цель. Проверка выполняется локально с телефона."
                    }
                Text(statusTitle, style = MaterialTheme.typography.titleMedium)
                Text(statusDetails, style = MaterialTheme.typography.bodySmall)
                if (scanning && progress.total > 0) {
                    LinearProgressIndicator(
                        progress = { progress.percent / 100f },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Параметры сканирования", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Сканер ищет соседние IP и выполняет только целевые проверки Reality/TLS.",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    label = { Text("IP / домен / CIDR") },
                    placeholder = { Text("например 1.1.1.1 или example.com") },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp, max = 82.dp),
                    minLines = 2,
                    enabled = !scanning,
                )
                if (input.isNotBlank()) {
                    Text(
                        when {
                            inputSummary == null -> "Цель пока не распознана."
                            inputSummary.infinite ->
                                "Один IP: сканер идёт по соседним адресам без ограничения, пока не нажмёшь «Стоп»."
                            inputSummary.total == 1 ->
                                "Одна цель: будет проверен только этот адрес. Для поиска соседей укажи IP."
                            else -> "Список: будет проверено целей — ${inputSummary.total}."
                        },
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = port,
                        onValueChange = { port = it },
                        label = { Text("Порт") },
                        placeholder = { Text("1–65535") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(1f),
                        enabled = !scanning,
                    )
                    OutlinedTextField(
                        value = threads,
                        onValueChange = { threads = it },
                        label = { Text("Потоки") },
                        placeholder = { Text("1–32") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.weight(1f),
                        enabled = !scanning,
                    )
                }

                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("GeoIP", style = MaterialTheme.typography.labelLarge)
                            if (geoUpdating) Text("Обновление…", style = MaterialTheme.typography.bodySmall)
                        }
                        Text(
                            if (geoReady) "✓ GeoLite2-Country доступна • автообновление включено" else "База ещё не установлена",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("IPv6", style = MaterialTheme.typography.labelLarge)
                        Text("Добавлять IPv6-цели в план поиска", style = MaterialTheme.typography.bodySmall)
                    }
                    Switch(checked = ipv6, onCheckedChange = { ipv6 = it }, enabled = !scanning)
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("TLS 1.2 — совместимость", style = MaterialTheme.typography.labelLarge)
                        Text("TLS 1.3 остаётся основным режимом", style = MaterialTheme.typography.bodySmall)
                    }
                    Switch(checked = tls12, onCheckedChange = { tls12 = it }, enabled = !scanning)
                }

                if (scanning) {
                    if (networkLost) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                        ) {
                            Text(
                                "Связь с интернетом потеряна. Сканер безопасно поставлен на паузу.",
                                modifier = Modifier.padding(10.dp),
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                        }
                    }
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = {
                                if (!networkLost) {
                                    if (paused) RealityScannerForegroundService.resume(context)
                                    else RealityScannerForegroundService.pause(context)
                                }
                            },
                            modifier = Modifier.weight(1f),
                            enabled = !networkLost,
                        ) { Text(if (paused) "Продолжить" else "Пауза") }
                        OutlinedButton(
                            onClick = { RealityScannerForegroundService.stop(context) },
                            modifier = Modifier.weight(1f),
                        ) { Text("Стоп") }
                    }
                } else {
                    Button(onClick = ::startScan, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        Text("Начать сканирование")
                    }
                }
            }
        }

        (error ?: serviceError.takeIf { it.isNotBlank() && !scanning })?.let { message ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            ) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        if (error != null) "Проверь параметры" else "Сканирование остановлено",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                    Text(message, color = MaterialTheme.colorScheme.onErrorContainer)
                }
            }
        }

        if (results.isNotEmpty() || scanning) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Результаты", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "TLS 1.3 ${liveResultGroups.tls13.size} • TLS 1.2 ${liveResultGroups.tls12.size}" +
                            if (liveResultGroups.other.isNotEmpty()) " • другие ${liveResultGroups.other.size}" else "",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedButton(onClick = { showResults = true }, modifier = Modifier.fillMaxWidth()) {
                        Text(if (scanning) "Открыть результаты • поиск продолжается" else "Открыть результаты")
                    }
                    if (results.isNotEmpty() && !scanning) {
                        OutlinedButton(
                            onClick = {
                                RealityScanSessionStore.clearCurrent(context)
                                results = emptyList()
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Очистить текущие результаты") }
                    }
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Сохранённые данные", style = MaterialTheme.typography.titleMedium)
                Text("История ${history.size} • Избранное ${favorites.size}", style = MaterialTheme.typography.bodySmall)
                OutlinedButton(onClick = { showAdditional = true }, modifier = Modifier.fillMaxWidth()) {
                    Text("История, избранное и GeoIP")
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))
    }

    if (showAdditional) {
        AlertDialog(
            onDismissRequest = { showAdditional = false },
            title = { Text("Дополнительно") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(geoStatus)
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                geoUpdating = true
                                val update = geoUpdater.updateIfNeeded(force = true)
                                geoReady = update.available && update.databaseFile.exists()
                                geoStatus = update.status
                                geoUpdating = false
                            }
                        },
                        enabled = !scanning && !geoUpdating,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Проверить обновление GeoIP") }
                    OutlinedButton(
                        onClick = { geoPicker.launch(arrayOf("application/octet-stream", "*/*")) },
                        enabled = !scanning && !geoUpdating,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Импорт GeoIP вручную") }
                    OutlinedButton(
                        onClick = { showHistory = true; showAdditional = false },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("История сканирований (${history.size})") }
                    OutlinedButton(
                        onClick = { showFavorites = true; showAdditional = false },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Избранное (${favorites.size})") }
                }
            },
            confirmButton = { OutlinedButton(onClick = { showAdditional = false }) { Text("Закрыть") } },
        )
    }

    if (showResults) {
        ResultsDialog(
            title = if (scanning) "Результаты • поиск продолжается" else "Результаты",
            results = results,
            favorites = favorites,
            onClose = { showResults = false },
            onSelect = { selectedResult = it },
            onToggleFavorite = ::toggleFavorite,
            onExportCsv = { createExportFile(context, "csv", buildCsv(results))?.let { shareFile(context, it, "text/csv") } },
            onExportJson = { createExportFile(context, "json", buildJson(results))?.let { shareFile(context, it, "application/json") } },
            splitByTls = true,
            sniBatchRunning = sniBatchJob != null,
            sniBatchStatus = sniBatchStatus,
            onAnalyzeAllSni = { analyzeAllSni(results) },
        )
    }

    if (showHistory) {
        HistoryDialog(
            history = history,
            onClose = { showHistory = false },
            onOpen = { session ->
                results = session.results
                RealityScanSessionStore.saveCurrent(context, results)
                showHistory = false
                showResults = true
            },
            onExportCsv = { session -> createExportFile(context, "csv", buildCsv(session.results))?.let { shareFile(context, it, "text/csv") } },
            onExportJson = { session -> createExportFile(context, "json", buildJson(session.results))?.let { shareFile(context, it, "application/json") } },
            onClearAll = { showClearHistoryConfirm = true },
        )
    }

    if (showFavorites) {
        ResultsDialog(
            title = "Избранное (${favorites.size})",
            results = favorites,
            favorites = favorites,
            onClose = { showFavorites = false },
            onSelect = { selectedResult = it },
            onToggleFavorite = ::toggleFavorite,
            onExportCsv = { createExportFile(context, "csv", buildCsv(favorites))?.let { shareFile(context, it, "text/csv") } },
            onExportJson = { createExportFile(context, "json", buildJson(favorites))?.let { shareFile(context, it, "application/json") } },
            sniBatchRunning = sniBatchJob != null,
            sniBatchStatus = sniBatchStatus,
            onAnalyzeAllSni = { analyzeAllSni(favorites) },
        )
    }

    if (showClearHistoryConfirm) {
        AlertDialog(
            onDismissRequest = { showClearHistoryConfirm = false },
            title = { Text("Удалить всю историю?") },
            text = { Text("Будут удалены все сохранённые сеансы сканирования.") },
            confirmButton = {
                Button(onClick = {
                    history = emptyList()
                    RealityScanSessionStore.saveHistory(context, emptyList())
                    showClearHistoryConfirm = false
                    showHistory = false
                }) { Text("Удалить всё") }
            },
            dismissButton = { OutlinedButton(onClick = { showClearHistoryConfirm = false }) { Text("Отмена") } },
        )
    }

    selectedResult?.let { result ->
        AlertDialog(
            onDismissRequest = { selectedResult = null },
            title = { Text("${result.ip}:${result.port}") },
            text = {
                SelectionContainer {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Домен: ${result.certificateDomain.ifBlank { "—" }}")
                        Text("TLS: ${result.tls.ifBlank { "—" }}")
                        Text("ALPN: ${result.alpn.ifBlank { "—" }}")
                        Text("Cipher: ${result.cipherSuite.ifBlank { "—" }}")
                        Text("Curve: ${result.curve ?: "N/A (Android TLS)"}")
                        Text("Geo: ${result.geo.ifBlank { "N/A" }}")
                        Text("Ping: ${result.latencyMs?.let { "$it ms" } ?: "—"}")
                        Text("SNI: ${result.selectedSni ?: "—"}")
                        if (result.sniCandidates.isNotEmpty()) {
                            Text("SNI-кандидатов: ${result.sniCandidates.size}", style = MaterialTheme.typography.bodySmall)
                        }
                        result.sniAnalysis?.let { analysis ->
                            Text("SNI-анализ: ${analysis.verdict.displayLabel()}")
                            if (analysis.reasons.isNotEmpty()) {
                                Text("Причины: ${analysis.reasons.joinToString(", ")}", style = MaterialTheme.typography.bodySmall)
                            }
                            if (analysis.source.isNotBlank()) {
                                Text("Источник: ${analysis.source}", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                        result.error?.let { Text("Ошибка: $it") }
                    }
                }
            },
            confirmButton = { Button(onClick = { copyText(context, result.asCopyText()) }) { Text("Копировать всё") } },
            dismissButton = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (result.sniCandidates.isNotEmpty()) {
                        OutlinedButton(onClick = { showSniPicker = true }) { Text("Выбрать SNI") }
                    }
                    if (result.selectedSni != null) {
                        OutlinedButton(
                            onClick = { analyzeSelectedSni(result) },
                            enabled = analyzingSniId == null,
                        ) {
                            Text(if (analyzingSniId == result.id) "Проверяю…" else "Проверить SNI")
                        }
                    }
                    OutlinedButton(onClick = { selectedResult = null }) { Text("Закрыть") }
                }
            },
        )
    }

    if (showSniPicker) {
        selectedResult?.let { result ->
            AlertDialog(
                onDismissRequest = { showSniPicker = false },
                title = { Text("SNI для VLESS-Reality") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Кандидаты получены из DNS SAN/CN сертификата. Выбор не запускает повторный scan.")
                        LazyColumn(
                            modifier = Modifier.heightIn(max = 420.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            items(result.sniCandidates) { candidate ->
                                OutlinedButton(
                                    onClick = { selectSni(result, candidate) },
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Text(if (candidate == result.selectedSni) "✓ $candidate" else candidate)
                                }
                            }
                        }
                    }
                },
                confirmButton = { OutlinedButton(onClick = { showSniPicker = false }) { Text("Закрыть") } },
            )
        }
    }
}

@Composable
private fun ResultsDialog(
    title: String,
    results: List<RealityScanResult>,
    favorites: List<RealityScanResult>,
    onClose: () -> Unit,
    onSelect: (RealityScanResult) -> Unit,
    onToggleFavorite: (RealityScanResult) -> Unit,
    onExportCsv: () -> Unit,
    onExportJson: () -> Unit,
    splitByTls: Boolean = false,
    sniBatchRunning: Boolean = false,
    sniBatchStatus: String? = null,
    onAnalyzeAllSni: () -> Unit = {},
) {
    val rankedResults = remember(results) { RealityScanResultRanking.byBestLatency(results) }
    val groups = remember(rankedResults) { RealityScanResultGrouping.split(rankedResults) }

    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false)) {
        Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(
                modifier = Modifier.fillMaxSize().safeDrawingPadding().navigationBarsPadding().padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Column {
                        Text(title, style = MaterialTheme.typography.titleLarge)
                        Text("${results.size} результат(а) • ранжирование по лучшему ping", style = MaterialTheme.typography.bodySmall)
                    }
                    OutlinedButton(onClick = onClose) { Text("Закрыть") }
                }
                Card(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedButton(onClick = onExportCsv, modifier = Modifier.weight(1f), enabled = results.isNotEmpty()) { Text("Экспорт CSV") }
                        OutlinedButton(onClick = onExportJson, modifier = Modifier.weight(1f), enabled = results.isNotEmpty()) { Text("Экспорт JSON") }
                    }
                }
                if (results.any { it.selectedSni != null }) {
                    OutlinedButton(onClick = onAnalyzeAllSni, modifier = Modifier.fillMaxWidth()) {
                        Text(if (sniBatchRunning) "Остановить проверку SNI" else "Проверить SNI у всех")
                    }
                    sniBatchStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
                if (results.isEmpty()) {
                    Text("Подходящих результатов пока нет.")
                } else if (splitByTls && groups.other.isEmpty()) {
                    TlsSplitResultLists(
                        tls13 = groups.tls13,
                        tls12 = groups.tls12,
                        favorites = favorites,
                        onSelect = onSelect,
                        onToggleFavorite = onToggleFavorite,
                        modifier = Modifier.weight(1f),
                    )
                } else {
                    if (splitByTls && groups.other.isNotEmpty()) {
                        Text(
                            "Есть ${groups.other.size} результат(а) с другим/неизвестным TLS; показан совместимый общий список.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    ResultList(
                        results = rankedResults,
                        favorites = favorites,
                        onSelect = onSelect,
                        onToggleFavorite = onToggleFavorite,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }
}

@Composable
private fun TlsSplitResultLists(
    tls13: List<RealityScanResult>,
    tls12: List<RealityScanResult>,
    favorites: List<RealityScanResult>,
    onSelect: (RealityScanResult) -> Unit,
    onToggleFavorite: (RealityScanResult) -> Unit,
    modifier: Modifier = Modifier,
) {
    // With TLS 1.2 switched off its pane is always empty, yet it took half of a phone screen.
    val panes = listOf("TLS 1.3" to tls13, "TLS 1.2" to tls12).filter { it.second.isNotEmpty() }
    BoxWithConstraints(modifier = modifier.fillMaxWidth()) {
        if (maxWidth >= 700.dp) {
            Row(
                modifier = Modifier.fillMaxSize(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                panes.forEach { (title, group) ->
                    ResultGroupPane(
                        title = title,
                        results = group,
                        favorites = favorites,
                        onSelect = onSelect,
                        onToggleFavorite = onToggleFavorite,
                        modifier = Modifier.weight(1f).fillMaxHeight(),
                    )
                }
            }
        } else {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                panes.forEach { (title, group) ->
                    ResultGroupPane(
                        title = title,
                        results = group,
                        favorites = favorites,
                        onSelect = onSelect,
                        onToggleFavorite = onToggleFavorite,
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                    )
                }
            }
        }
    }
}

@Composable
private fun ResultGroupPane(
    title: String,
    results: List<RealityScanResult>,
    favorites: List<RealityScanResult>,
    onSelect: (RealityScanResult) -> Unit,
    onToggleFavorite: (RealityScanResult) -> Unit,
    modifier: Modifier = Modifier,
) {
    val rating = remember(results) { RealitySniRatingProjection.project(results) }

    Card(modifier = modifier) {
        Column(
            modifier = Modifier.fillMaxSize().padding(8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text("$title (${results.size})", style = MaterialTheme.typography.titleSmall)
            SniRatingColumns(
                clean = rating.clean,
                whitelist = rating.whitelist,
                onSelect = onSelect,
                modifier = Modifier.fillMaxWidth(),
            )
            if (rating.remainder.isNotEmpty()) {
                Text(
                    "Вне TOP: ${rating.remainder.size} • кандидат / блокировка / неизвестно / ещё не проверено",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (results.isEmpty()) {
                Text("Подходящих результатов пока нет.", style = MaterialTheme.typography.bodySmall)
            } else {
                Text("Все результаты $title", style = MaterialTheme.typography.bodySmall)
                ResultList(
                    results = results,
                    favorites = favorites,
                    onSelect = onSelect,
                    onToggleFavorite = onToggleFavorite,
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

@Composable
private fun SniRatingColumns(
    clean: List<RealityScanResult>,
    whitelist: List<RealityScanResult>,
    onSelect: (RealityScanResult) -> Unit,
    modifier: Modifier = Modifier,
) {
    BoxWithConstraints(modifier = modifier) {
        if (maxWidth >= 360.dp) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                SniRatingColumn(
                    title = "Чистый SNI",
                    results = clean,
                    onSelect = onSelect,
                    modifier = Modifier.weight(1f),
                )
                SniRatingColumn(
                    title = "SNI белого списка",
                    results = whitelist,
                    onSelect = onSelect,
                    modifier = Modifier.weight(1f),
                )
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                SniRatingColumn(
                    title = "Чистый SNI",
                    results = clean,
                    onSelect = onSelect,
                    modifier = Modifier.fillMaxWidth(),
                )
                SniRatingColumn(
                    title = "SNI белого списка",
                    results = whitelist,
                    onSelect = onSelect,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

@Composable
private fun SniRatingColumn(
    title: String,
    results: List<RealityScanResult>,
    onSelect: (RealityScanResult) -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier) {
        Column(
            modifier = Modifier.padding(6.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text("$title (${results.size})", style = MaterialTheme.typography.labelLarge)
            if (results.isEmpty()) {
                Text("Пока нет подтверждённых результатов", style = MaterialTheme.typography.bodySmall)
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxWidth().heightIn(max = 190.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    items(results, key = { "rating-${it.id}" }) { result ->
                        SniRatingCompactCard(result = result, onSelect = onSelect)
                    }
                }
            }
        }
    }
}

@Composable
private fun SniRatingCompactCard(
    result: RealityScanResult,
    onSelect: (RealityScanResult) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().clickable { onSelect(result) }) {
        Column(modifier = Modifier.padding(6.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(result.selectedSni ?: "—", style = MaterialTheme.typography.bodyMedium)
            Text(
                "${result.ip}:${result.port} • ${result.latencyMs?.let { "$it ms" } ?: "Ping —"}",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun ResultList(
    results: List<RealityScanResult>,
    favorites: List<RealityScanResult>,
    onSelect: (RealityScanResult) -> Unit,
    onToggleFavorite: (RealityScanResult) -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = modifier) {
        items(results, key = { it.id }) { result ->
            ResultCard(
                result = result,
                isFavorite = favorites.any { it.id == result.id },
                onSelect = onSelect,
                onToggleFavorite = onToggleFavorite,
            )
        }
    }
}

@Composable
private fun ResultCard(
    result: RealityScanResult,
    isFavorite: Boolean,
    onSelect: (RealityScanResult) -> Unit,
    onToggleFavorite: (RealityScanResult) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().clickable { onSelect(result) }) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("${result.ip}:${result.port}", style = MaterialTheme.typography.titleSmall)
                    Text(result.certificateDomain.ifBlank { "Домен не определён" }, style = MaterialTheme.typography.bodySmall)
                }
                Text(result.latencyMs?.let { "$it ms" } ?: "Ping —", style = MaterialTheme.typography.labelLarge)
            }
            Text(
                "${result.tls.ifBlank { "TLS —" }} • ALPN ${result.alpn.ifBlank { "—" }} • ${result.geo.ifBlank { "N/A" }}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text("SNI: ${result.selectedSni ?: "—"}", style = MaterialTheme.typography.bodySmall)
            result.sniAnalysis?.let { analysis ->
                Text("${analysis.verdict.displayLabel()}", style = MaterialTheme.typography.labelMedium)
            }
            OutlinedButton(onClick = { onToggleFavorite(result) }) {
                Text(if (isFavorite) "★ В избранном" else "☆ Добавить в избранное")
            }
        }
    }
}

@Composable
private fun HistoryDialog(
    history: List<RealityScanSession>,
    onClose: () -> Unit,
    onOpen: (RealityScanSession) -> Unit,
    onExportCsv: (RealityScanSession) -> Unit,
    onExportJson: (RealityScanSession) -> Unit,
    onClearAll: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("История сканирований") },
        text = {
            if (history.isEmpty()) {
                Text("История пока пуста.")
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.heightIn(max = 520.dp)) {
                    items(history, key = { it.id }) { session ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(formatScanTime(session.createdAt), style = MaterialTheme.typography.titleSmall)
                                Text("${session.results.size} подходящих")
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    OutlinedButton(onClick = { onOpen(session) }, modifier = Modifier.weight(1f)) { Text("Открыть") }
                                    OutlinedButton(onClick = { onExportCsv(session) }, modifier = Modifier.weight(1f)) { Text("CSV") }
                                    OutlinedButton(onClick = { onExportJson(session) }, modifier = Modifier.weight(1f)) { Text("JSON") }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { OutlinedButton(onClick = onClose) { Text("Закрыть") } },
        dismissButton = { OutlinedButton(onClick = onClearAll, enabled = history.isNotEmpty()) { Text("Удалить всё") } },
    )
}
