package com.velumtegra.xuimobile.inventory

import android.annotation.SuppressLint
import android.net.http.SslError
import android.webkit.SslErrorHandler
import android.webkit.ValueCallback
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import androidx.compose.ui.platform.LocalContext
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import androidx.compose.material3.Button
import android.os.Build
import android.util.Log
import android.widget.Toast
import java.io.ByteArrayInputStream
import android.view.ViewGroup
import android.webkit.RenderProcessGoneDetail
import android.webkit.CookieManager
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebChromeClient
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView

/** The user's real 3x-ui page, not a native replacement for its controls.
 * Login and all panel actions belong to the remote page. SSH management remains separate.
 * The toolbar never connects via SSH or submits an API mutation itself.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun EmbeddedHttpsWebPanelScreen(
    initialUrl: String,
    onClose: () -> Unit,
    allowHttpWithinSsh: Boolean = false,
    onlyLocalSshOrigin: Boolean = false,
    certificateTrustScope: String? = null,
    savedLoginScript: (suspend (String) -> String?)? = null,
) {
    val context = LocalContext.current
    val pinStore = remember(context.applicationContext) { PrivatePanelCertificatePins(context) }
    var certificatePrompt by remember(initialUrl, certificateTrustScope) {
        mutableStateOf<PendingPanelCertificate?>(null)
    }
    var tlsRejected by remember(initialUrl) { mutableStateOf(false) }
    var webView by remember(initialUrl) { mutableStateOf<WebView?>(null) }
    var isLoading by remember(initialUrl) { mutableStateOf(true) }
    var errorMessage by remember(initialUrl) { mutableStateOf<String?>(null) }
    var loadAttempt by remember(initialUrl) { mutableStateOf(0) }
    var finishedAttempt by remember(initialUrl) { mutableStateOf(0) }
    var hasVisiblePage by remember(initialUrl) { mutableStateOf(false) }
    var rendererGone by remember(initialUrl) { mutableStateOf(false) }
    var canGoBack by remember(initialUrl) { mutableStateOf(false) }
    var canGoForward by remember(initialUrl) { mutableStateOf(false) }
    var loginPage by remember(initialUrl) { mutableStateOf(false) }
    var fillingLogin by remember(initialUrl) { mutableStateOf(false) }
    var loginNotice by remember(initialUrl) { mutableStateOf<String?>(null) }
    val loginScope = rememberCoroutineScope()

    // Panel downloads (backup, exported links/configs) and uploads (backup import) need explicit host support.
    var pendingSave by remember(initialUrl) { mutableStateOf<PendingPanelFile?>(null) }
    var fileCallback by remember(initialUrl) { mutableStateOf<ValueCallback<Array<Uri>>?>(null) }
    val saveLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { target ->
        PanelTunnelHoldService.stop(context.applicationContext)
        val file = pendingSave
        pendingSave = null
        if (target == null || file == null) return@rememberLauncherForActivityResult
        val resolver = context.applicationContext.contentResolver
        loginScope.launch {
            val saved = withContext(Dispatchers.IO) {
                try { resolver.openOutputStream(target, "w")?.use { it.write(file.bytes) } != null }
                catch (_: Exception) { false }
            }
            Toast.makeText(context.applicationContext,
                if (saved) "Файл «${file.name}» сохранён." else "Не удалось сохранить файл.",
                Toast.LENGTH_SHORT).show()
        }
    }
    val fileBridge = remember(initialUrl) {
        WebPanelFileBridge(
            onFile = { file ->
                pendingSave = file
                if (onlyLocalSshOrigin) PanelTunnelHoldService.start(context.applicationContext)
                try { saveLauncher.launch(file.name) } catch (_: Exception) {
                    PanelTunnelHoldService.stop(context.applicationContext)
                    pendingSave = null
                    Toast.makeText(context.applicationContext, "Нет приложения для сохранения файлов.", Toast.LENGTH_SHORT).show()
                }
            },
            onFailure = { Toast.makeText(context.applicationContext, it, Toast.LENGTH_LONG).show() },
        )
    }
    val openLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { picked ->
        // Keep the hold a little longer: the page uploads the chosen file right after this callback.
        val app = context.applicationContext
        loginScope.launch { delay(20_000L); PanelTunnelHoldService.stop(app) }
        fileCallback?.onReceiveValue(picked?.let { arrayOf(it) })
        fileCallback = null
    }

    fun canFillLogin(view: WebView, url: String): Boolean {
        if (webView !== view || view.url != url || isLoading ||
            tlsRejected || errorMessage != null || !isSavedPanelLoginPage(initialUrl, url)) return false
        val observed = observedPanelCertificate(view.certificate) ?: return false
        // Direct HTTPS uses Android's certificate validation. Loopback additionally requires the exact saved pin.
        if (!onlyLocalSshOrigin) return true
        val scope = certificateTrustScope ?: return false
        return certificatePinDecision(pinStore.read(scope), observed.fingerprint) == CertificatePinDecision.MATCH
    }
    // Validate independently even when launched by a linked installation.
    val authorized = remember(initialUrl, allowHttpWithinSsh, onlyLocalSshOrigin, certificateTrustScope) {
        if (onlyLocalSshOrigin) isExactDirectSshLoopbackUrl(initialUrl) &&
            (initialUrl.startsWith("http://") || !certificateTrustScope.isNullOrBlank())
        else exactPrivateSshPanelUrl(initialUrl, allowHttpWithinSsh) != null
    }
    fun allowedOrigin(candidateUrl: String): Boolean = when {
        onlyLocalSshOrigin -> isSameDirectSshLoopbackOrigin(initialUrl, candidateUrl)
        allowHttpWithinSsh -> isSamePrivateSshOrigin(initialUrl, candidateUrl, true)
        else -> isSameAuthorizedHttpsPanelOrigin(initialUrl, candidateUrl)
    }

    fun updateHistory(view: WebView) {
        canGoBack = view.canGoBack()
        canGoForward = view.canGoForward()
    }

    // A stalled WebView must never leave an indefinitely blank panel or spinner.
    LaunchedEffect(initialUrl, loadAttempt) {
        delay(25_000L)
        if (isLoading && !hasVisiblePage && errorMessage == null) {
            isLoading = false
            errorMessage = "Панель не ответила за 25 секунд. Проверь: HTTP или HTTPS, " +
                "порт 3x-ui на VPS, адрес 127.0.0.1 и секретный веб-путь. " +
                "Нажми ↻ для повтора либо ×, чтобы закрыть туннель."
        }
    }

    // A page can finish successfully yet be visually empty (wrong base path or failed SPA scripts).
    // Inspect only a boolean for visible controls/text; never extract page content or credentials.
    LaunchedEffect(initialUrl, finishedAttempt) {
        if (finishedAttempt > 0) {
            delay(7_000L)
            if (!isLoading && errorMessage == null) {
                webView?.evaluateJavascript(
                    "(function(){var b=document.body;return !!(b && " +
                        "(b.innerText.trim().length>0 || b.querySelector('input,button,form,img,canvas,svg')));})()"
                ) { visible ->
                    if (visible == "false" && errorMessage == null) {
                        errorMessage = "WebView загрузил страницу, но интерфейс 3x-ui не появился. " +
                            "Проверь протокол, порт и секретный веб-путь. " +
                            "Если параметры верны — пришли скриншот этого экрана."
                    }
                }
            }
        }
    }

    BackHandler {
        val page = webView
        if (page != null && page.canGoBack()) page.goBack() else onClose()
    }
    DisposableEffect(initialUrl, certificateTrustScope) {
        onDispose {
            certificatePrompt = null // Pending handlers are canceled before showing the prompt.
            fileCallback?.onReceiveValue(null)
            fileCallback = null
            fileBridge.cancel()
            PanelTunnelHoldService.stop(context.applicationContext)
            webView?.apply {
                removeJavascriptInterface(WebPanelFileBridge.JS_NAME)
                stopLoading()
                removeAllViews()
                destroy()
            }
            webView = null
        }
    }
    Column(modifier = Modifier.fillMaxSize().testTag("webpanel_embedded_screen")) {
        WebPanelToolbar(
            viaSsh = onlyLocalSshOrigin,
            onClose = onClose,
            onBack = if (authorized && canGoBack) {
                { webView?.takeIf { it.canGoBack() }?.goBack() }
            } else null,
            onForward = if (authorized && canGoForward) {
                { webView?.takeIf { it.canGoForward() }?.goForward() }
            } else null,
            onReload = if (authorized && webView != null) {
                {
                    errorMessage = null
                    isLoading = true
                    hasVisiblePage = false
                    loadAttempt++
                    webView?.reload()
                }
            } else null,
        )
        if (!authorized) {
            Text(
                "Некорректный адрес панели. Открытие заблокировано.",
                modifier = Modifier.padding(12.dp).testTag("webpanel_embedded_blocked"),
            )
        } else {
            if (savedLoginScript != null && loginPage && !isLoading && errorMessage == null) {
                TextButton(
                    onClick = {
                        val view = webView ?: return@TextButton
                        val url = view.url ?: return@TextButton
                        if (!canFillLogin(view, url)) {
                            loginNotice = "Не удалось подтвердить защищённую страницу входа."
                            return@TextButton
                        }
                        val attempt = loadAttempt
                        fillingLogin = true
                        loginNotice = null
                        loginScope.launch {
                            try {
                                val script = savedLoginScript(url)
                                if (attempt == loadAttempt && canFillLogin(view, url)) {
                                    if (script == null) loginNotice = "Сохранённые данные входа недоступны."
                                    else view.evaluateJavascript(script) { result ->
                                        if (attempt == loadAttempt && webView === view) {
                                            loginNotice = if (result == "true") "Логин и пароль подставлены. Нажмите кнопку входа в панели."
                                                else "Не удалось распознать форму входа."
                                        }
                                    }
                                }
                            } catch (cancel: CancellationException) {
                                throw cancel
                            } catch (_: Exception) {
                                if (attempt == loadAttempt) loginNotice = "Не удалось подставить данные входа."
                            } finally {
                                fillingLogin = false
                            }
                        }
                    },
                    enabled = !fillingLogin,
                    modifier = Modifier.padding(horizontal = 8.dp).testTag("webpanel_fill_saved_login"),
                ) { Text("Подставить логин и пароль") }
                loginNotice?.let { Text(it, modifier = Modifier.padding(horizontal = 12.dp)) }
            }
            if (isLoading) {
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth().testTag("webpanel_embedded_progress"),
                )
                if (!hasVisiblePage) Text(
                    "Загружаем страницу 3x-ui через выбранный маршрут…",
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                        .testTag("webpanel_embedded_loading_status"),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            // A successful load has no permanent status banner taking up WebView space.
            if (errorMessage != null) {
                Text(
                    errorMessage.orEmpty(),
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                        .testTag("webpanel_embedded_status"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            if (rendererGone) {
                Text(
                    "Встроенный браузер Android завершился. SSH-панель не открыта. " +
                        "Нажми «Закрыть» и открой её снова. Сервер не изменён.",
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.fillMaxWidth().padding(12.dp)
                        .testTag("webpanel_renderer_gone"),
                )
            } else AndroidView(
                modifier = Modifier.fillMaxWidth().weight(1f).testTag("webpanel_embedded_webview"),
                factory = { context ->
                    WebView(context).apply {
                        // Without explicit MATCH_PARENT, WebView treats AndroidView's default WRAP_CONTENT as a
                        // zero layout height: CSS 100vh becomes 0 and every 3x-ui dropdown menu collapses to 8px.
                        layoutParams = ViewGroup.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT,
                        )
                        settings.apply {
                            javaScriptEnabled = true // Required by the official 3x-ui frontend.
                            domStorageEnabled = true
                            allowFileAccess = false
                            allowContentAccess = false
                            javaScriptCanOpenWindowsAutomatically = false
                            setSupportMultipleWindows(false)
                            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) safeBrowsingEnabled = true
                        }
                        CookieManager.getInstance().setAcceptThirdPartyCookies(this, false)
                        addJavascriptInterface(fileBridge, WebPanelFileBridge.JS_NAME)
                        setDownloadListener { url, _, contentDisposition, mimeType, _ ->
                            val pageUrl = this.url
                            if (pageUrl == null || !allowedOrigin(pageUrl) ||
                                !allowedOrigin(WebPanelFileBridge.originCheckUrl(url))) {
                                Toast.makeText(context, "Скачивание вне панели заблокировано.", Toast.LENGTH_SHORT).show()
                                return@setDownloadListener
                            }
                            evaluateJavascript(fileBridge.begin(url, contentDisposition, mimeType), null)
                        }
                        webChromeClient = object : WebChromeClient() {
                            override fun onShowFileChooser(
                                view: WebView, callback: ValueCallback<Array<Uri>>, params: FileChooserParams,
                            ): Boolean {
                                val pageUrl = view.url
                                if (pageUrl == null || !allowedOrigin(pageUrl)) return false
                                fileCallback?.onReceiveValue(null)
                                fileCallback = callback
                                if (onlyLocalSshOrigin) PanelTunnelHoldService.start(context.applicationContext)
                                return try {
                                    openLauncher.launch(arrayOf("*/*"))
                                    true
                                } catch (_: Exception) {
                                    PanelTunnelHoldService.stop(context.applicationContext)
                                    fileCallback = null
                                    callback.onReceiveValue(null)
                                    true
                                }
                            }
                        }
                        webViewClient = object : WebViewClient() {
                            fun openOutside(view: WebView, url: String): Boolean {
                                val link = WebPanelFileBridge.externalLink(url) ?: return false
                                return try {
                                    view.context.startActivity(Intent(Intent.ACTION_VIEW, link)
                                        .addCategory(Intent.CATEGORY_BROWSABLE)
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                                    Toast.makeText(view.context, "Ссылка открыта во внешнем браузере.", Toast.LENGTH_SHORT).show()
                                    true
                                } catch (_: ActivityNotFoundException) { false }
                            }
                            // Direct SSH WebView is not a general browser: block off-origin
                            // HTTP(S) subresources. Main-frame navigation is checked below.
                            // WebView does not offer a full network firewall for WebSockets;
                            // the private mode must not be described as an OS-level egress deny.
                            override fun shouldInterceptRequest(
                                view: WebView, request: WebResourceRequest,
                            ): WebResourceResponse? {
                                if (!onlyLocalSshOrigin) return null
                                val scheme = request.url.scheme?.lowercase(java.util.Locale.ROOT)
                                if (scheme != "http" && scheme != "https") return null
                                if (allowedOrigin(request.url.toString())) return null
                                Log.w("VELUM_PANEL", "BLOCKED_NONLOCAL_WEB_RESOURCE")
                                return WebResourceResponse("text/plain", "utf-8", 403,
                                    "Blocked", emptyMap(), ByteArrayInputStream(ByteArray(0)))
                            }
                            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                                if (!request.isForMainFrame) return false
                                return if (allowedOrigin(request.url.toString())) {
                                    false
                                } else if (request.hasGesture() && openOutside(view, request.url.toString())) {
                                    true
                                } else {
                                    isLoading = false
                                    errorMessage = "Переход за пределы выбранной веб-панели заблокирован."
                                    true
                                }
                            }

                            @Suppress("DEPRECATION")
                            override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
                                return if (allowedOrigin(url)) {
                                    false
                                } else {
                                    isLoading = false
                                    errorMessage = "Переход за пределы выбранной веб-панели заблокирован."
                                    true
                                }
                            }

                            override fun onPageStarted(view: WebView, url: String, favicon: android.graphics.Bitmap?) {
                                loginPage = false
                                loginNotice = null
                                if (!allowedOrigin(url)) {
                                    view.stopLoading()
                                    isLoading = false
                                    errorMessage = "Переход за пределы выбранной веб-панели заблокирован."
                                } else {
                                    errorMessage = null // A permitted navigation may start a new TLS handshake.
                                    tlsRejected = false
                                    isLoading = true
                                    hasVisiblePage = false
                                    loadAttempt++
                                    updateHistory(view)
                                }
                            }

                            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
                                // The legacy template used unconditional proceed() for localhost.
                                // This replacement permits ONLY a previously user-confirmed,
                                // exact DER SHA-256 leaf behind this owned SSH-forward and target.
                                val scope = certificateTrustScope
                                val promptAllowed = onlyLocalSshOrigin && !scope.isNullOrBlank() &&
                                    initialUrl.startsWith("https://") &&
                                    allowedOrigin(error.url.orEmpty()) &&
                                    !error.hasError(SslError.SSL_EXPIRED) &&
                                    !error.hasError(SslError.SSL_NOTYETVALID) &&
                                    !error.hasError(SslError.SSL_DATE_INVALID) &&
                                    !error.hasError(SslError.SSL_INVALID) &&
                                    (error.primaryError == SslError.SSL_UNTRUSTED ||
                                        error.primaryError == SslError.SSL_IDMISMATCH)
                                val observed = if (promptAllowed) observedPanelCertificate(error.certificate) else null
                                val decision = if (scope != null) certificatePinDecision(
                                    pinStore.read(scope), observed?.fingerprint) else CertificatePinDecision.INVALID
                                if (promptAllowed && decision == CertificatePinDecision.MATCH) {
                                    handler.proceed() // Pin verified against WebView's EXACT presented certificate.
                                    return
                                }
                                handler.cancel() // Never leave a handler open across dialog/teardown.
                                tlsRejected = true
                                isLoading = false
                                if (promptAllowed && observed != null &&
                                    (decision == CertificatePinDecision.FIRST_USE ||
                                     decision == CertificatePinDecision.CHANGED)) {
                                    if (certificatePrompt == null) {
                                        certificatePrompt = PendingPanelCertificate(observed,
                                            pinStore.read(requireNotNull(scope)))
                                    }
                                    errorMessage = "TLS-сертификат панели требует личного подтверждения. " +
                                        "Ни пароль, ни страница авторизации ещё не загружались."
                                } else if (promptAllowed && observed == null) {
                                    errorMessage = "WebView не предоставил проверяемый X.509 сертификат панели. " +
                                        "HTTPS заблокирован; принимать сертификат вслепую нельзя."
                                } else {
                                    errorMessage = privatePanelTlsErrorMessage(error.primaryError)
                                }
                                Log.w("VELUM_PANEL", "TLS_PIN_CHECK ${decision.name} code=${error.primaryError}")
                            }

                            override fun onReceivedError(view: WebView, request: WebResourceRequest, error: WebResourceError) {
                                if (request.isForMainFrame && !tlsRejected) {
                                    isLoading = false
                                    errorMessage = "Ошибка сети WebView (код ${error.errorCode}). " +
                                        "Проверь SSH-маршрут, протокол HTTP/HTTPS и порт панели на VPS."
                                }
                            }

                            override fun onReceivedHttpError(view: WebView, request: WebResourceRequest,
                                errorResponse: WebResourceResponse) {
                                if (request.isForMainFrame && errorResponse.statusCode >= 400) {
                                    isLoading = false
                                    errorMessage = "Веб-панель ответила HTTP ${errorResponse.statusCode}. " +
                                        "Проверь секретный URL-путь и порт 3x-ui."
                                }
                            }

                            override fun onPageCommitVisible(view: WebView, url: String) {
                                if (allowedOrigin(url)) hasVisiblePage = true
                            }

                            override fun doUpdateVisitedHistory(view: WebView, url: String, isReload: Boolean) {
                                loginPage = isSavedPanelLoginPage(initialUrl, url)
                                loginNotice = null
                            }

                            override fun onPageFinished(view: WebView, url: String) {
                                if (allowedOrigin(url)) view.evaluateJavascript(WebPanelFileBridge.PAGE_HOOK, null)
                                loginPage = isSavedPanelLoginPage(initialUrl, url)
                                isLoading = false
                                finishedAttempt++
                                updateHistory(view)
                                // Do not erase an error (especially TLS) during a failed load.
                            }

                            @android.annotation.TargetApi(Build.VERSION_CODES.O)
                            override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
                                // The renderer is no longer usable; never silently show an empty screen.
                                Log.e("VELUM_PANEL", "RENDER_PROCESS_GONE crash=${detail.didCrash()}")
                                (view.parent as? ViewGroup)?.removeView(view)
                                view.destroy()
                                if (webView === view) webView = null
                                rendererGone = true
                                isLoading = false
                                errorMessage = "Процесс WebView завершился. Панель закрыта для безопасности."
                                return true
                            }
                        }
                        webView = this
                        loadUrl(initialUrl)
                    }
                },
            )
        }
    }
    val prompt = certificatePrompt
    if (prompt != null) {
        AlertDialog(
            onDismissRequest = { certificatePrompt = null },
            title = { Text(if (prompt.previousFingerprint == null)
                "Первое доверие сертификату 3x-ui" else "Сертификат 3x-ui изменился") },
            text = { Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Это сертификат, предъявленный панелью внутри выбранного SSH-туннеля. " +
                    "Разрешение относится только к этой панели и маршруту. " +
                    "Сверь SHA-256 отпечаток с сертификатом своего VPS перед подтверждением.")
                Text("SHA-256: " + prompt.observed.fingerprint.chunked(2).joinToString(":"))
                Text("Subject: " + prompt.observed.subject)
                Text("Действителен до: " + prompt.observed.notAfter)
                if (prompt.previousFingerprint != null) {
                    Text("Ранее доверенный SHA-256: " +
                        prompt.previousFingerprint.chunked(2).joinToString(":"))
                    Text("Смена сертификата требует отдельного подтверждения.")
                }
                Text("Это не подтверждение подлинности сертификата сторонней CA. " +
                    "Без твоего согласия HTTPS останется заблокирован.")
            } },
            confirmButton = { Button(onClick = {
                val scope = certificateTrustScope
                certificatePrompt = null
                if (scope != null && pinStore.save(scope, prompt.observed.fingerprint)) {
                    errorMessage = null
                    tlsRejected = false
                    isLoading = true
                    webView?.reload() // Original canceled request stays canceled.
                } else {
                    errorMessage = "Не удалось сохранить доверенный сертификат. HTTPS заблокирован."
                }
            }, modifier = Modifier.testTag("webpanel_certificate_confirm")) { Text("Подтвердить отпечаток") } },
            dismissButton = { TextButton(onClick = { certificatePrompt = null },
                modifier = Modifier.testTag("webpanel_certificate_cancel")) { Text("Отмена") } },
        )
    }
}

internal data class PendingPanelCertificate(
    val observed: ObservedPanelCertificate,
    val previousFingerprint: String?,
)

/** Diagnostic-only TLS classification: the certificate is NEVER accepted here. */
/** Native sibling of the WebView, also available before the SSH tunnel is ready. */
@Composable
internal fun WebPanelToolbar(
    viaSsh: Boolean,
    onClose: () -> Unit,
    onBack: (() -> Unit)? = null,
    onForward: (() -> Unit)? = null,
    onReload: (() -> Unit)? = null,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 2.dp)
            .testTag("webpanel_toolbar"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            if (viaSsh) "3x-ui · SSH" else "3x-ui",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.weight(1f).padding(start = 8.dp),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        IconButton(
            onClick = { onBack?.invoke() },
            enabled = onBack != null,
            modifier = Modifier.testTag("webpanel_embedded_back")
                .semantics { contentDescription = "Назад по веб-панели" },
        ) { Text("‹", style = MaterialTheme.typography.headlineSmall) }
        IconButton(
            onClick = { onForward?.invoke() },
            enabled = onForward != null,
            modifier = Modifier.testTag("webpanel_embedded_forward")
                .semantics { contentDescription = "Вперёд по веб-панели" },
        ) { Text("›", style = MaterialTheme.typography.headlineSmall) }
        IconButton(
            onClick = { onReload?.invoke() },
            enabled = onReload != null,
            modifier = Modifier.testTag("webpanel_embedded_reload")
                .semantics { contentDescription = "Обновить веб-панель" },
        ) { Text("↻", style = MaterialTheme.typography.headlineSmall) }
        if (viaSsh) {
            TextButton(onClick = onClose, modifier = Modifier.testTag("private_panel_root_close")) {
                Text("Закрыть")
            }
        } else {
            IconButton(
                onClick = onClose,
                modifier = Modifier.testTag("webpanel_embedded_close")
                    .semantics { contentDescription = "Закрыть веб-панель" },
            ) { Text("×", style = MaterialTheme.typography.headlineSmall) }
        }
    }
}

internal fun privatePanelTlsErrorMessage(primaryError: Int): String = when (primaryError) {
    SslError.SSL_UNTRUSTED -> "Недоверенный TLS-сертификат (возможно, самоподписанный). " +
        "HTTPS заблокирован. Для доверия потребуется проверенный публичный сертификат, без приватного ключа."
    SslError.SSL_IDMISMATCH -> "Имя TLS-сертификата не совпадает с адресом панели. " +
        "HTTPS заблокирован. Проверь имя хоста и SAN сертификата."
    SslError.SSL_EXPIRED, SslError.SSL_NOTYETVALID, SslError.SSL_DATE_INVALID ->
        "TLS-сертификат пока недействителен или просрочен. HTTPS заблокирован."
    else -> "Ошибка проверки TLS-сертификата. HTTPS заблокирован. " +
        "Не отключай проверку сертификата; проверь имя и цепочку доверия."
}
