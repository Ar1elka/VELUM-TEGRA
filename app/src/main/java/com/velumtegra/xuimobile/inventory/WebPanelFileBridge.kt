package com.velumtegra.xuimobile.inventory

import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.webkit.JavascriptInterface
import android.webkit.URLUtil
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Locale

/** A file the panel page asked to download, held in memory only until the user picks where to save it. */
internal class PendingPanelFile(val name: String, val bytes: ByteArray) {
    override fun toString(): String = "PendingPanelFile($name, ${bytes.size} bytes)"
}

/**
 * Android WebView has no built-in download handling. The panel downloads either by navigating to an
 * attachment URL (database backup) or by clicking an `<a download>` with a blob: URL that it revokes
 * immediately (exported links, configs). The page re-fetches the same-origin resource itself (its cookies,
 * the pinned tunnel TLS) and hands the bytes to this bridge; a random one-shot token ties every delivery
 * to a download WebView announced, so the page cannot push unsolicited files.
 */
internal class WebPanelFileBridge(
    private val onFile: (PendingPanelFile) -> Unit,
    private val onFailure: (String) -> Unit,
) {
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var expected: Pair<String, String>? = null // token to fallback file name

    /** Returns the script to evaluate in the page, or null when [url] is not a downloadable panel resource. */
    fun begin(url: String, contentDisposition: String?, mimeType: String?): String {
        val token = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        expected = token to URLUtil.guessFileName(url, contentDisposition, mimeType)
        return "(function(u,t,lim){var n=(window.__velumDlHref===u&&window.__velumDlName)||'';" +
            "var kept=window.__velumBlobs&&window.__velumBlobs.get(u);" +
            "(kept?Promise.resolve([kept,'']):fetch(u,{credentials:'include'}).then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);" +
            "var cd=r.headers.get('content-disposition')||'';return r.blob().then(function(b){return [b,cd];});}))" +
            ".then(function(x){var b=x[0];if(b.size>lim)throw new Error('too-large');var fr=new FileReader();" +
            "fr.onload=function(){var s=String(fr.result);" +
            "VelumPanelFiles.deliver(t,n,x[1],b.type||'',s.substring(s.indexOf(',')+1));};" +
            "fr.onerror=function(){VelumPanelFiles.fail(t,'read');};fr.readAsDataURL(b);})" +
            ".catch(function(e){VelumPanelFiles.fail(t,String(e&&e.message||e));});})(" +
            JSONObject.quote(url) + "," + JSONObject.quote(token) + "," + MAX_BYTES + ")"
    }

    fun cancel() { expected = null }

    @JavascriptInterface
    fun deliver(token: String?, anchorName: String?, contentDisposition: String?, mimeType: String?, base64: String?) {
        val (want, fallback) = expected ?: return
        if (token != want) return
        expected = null
        val bytes = try { Base64.decode(base64.orEmpty(), Base64.DEFAULT) } catch (_: IllegalArgumentException) { null }
        if (bytes == null) { main.post { onFailure("Файл пришёл повреждённым.") }; return }
        val fromHeader = contentDisposition?.takeIf { it.isNotBlank() }
            ?.let { URLUtil.guessFileName("https://x/download", it, mimeType) }
        val name = safeFileName(anchorName?.takeIf { it.isNotBlank() } ?: fromHeader ?: fallback)
        main.post { onFile(PendingPanelFile(name, bytes)) }
    }

    @JavascriptInterface
    fun fail(token: String?, reason: String?) {
        val (want, _) = expected ?: return
        if (token != want) return
        expected = null
        val text = if (reason == "too-large") "Файл больше ${MAX_BYTES / (1024 * 1024)} МБ, сохранить его здесь нельзя."
            else "Не удалось скачать файл из панели."
        main.post { onFailure(text) }
    }

    companion object {
        const val JS_NAME = "VelumPanelFiles"
        const val MAX_BYTES = 32 * 1024 * 1024

        /**
         * Installed after each page load: remembers the name of the last `<a download>` click and delays
         * blob: URL revocation so the bytes can still be read after WebView reports the download.
         */
        const val PAGE_HOOK = "(function(){if(window.__velumDl)return;window.__velumDl=1;" +
            // The panel CSP forbids fetch(blob:), so keep the Blob itself for a short while.
            "var m=window.__velumBlobs=new Map();var mk=URL.createObjectURL.bind(URL);" +
            "URL.createObjectURL=function(o){var u=mk(o);if(o instanceof Blob)m.set(u,o);return u;};" +
            "var rev=URL.revokeObjectURL.bind(URL);URL.revokeObjectURL=function(u){setTimeout(function(){m.delete(u);rev(u);},120000);};" +
            "function note(a){if(a&&a.hasAttribute&&a.hasAttribute('download')){window.__velumDlName=a.getAttribute('download')||'';window.__velumDlHref=a.href;}}" +
            "var c=HTMLAnchorElement.prototype.click;HTMLAnchorElement.prototype.click=function(){note(this);return c.apply(this,arguments);};" +
            "document.addEventListener('click',function(e){var t=e.target;note(t&&t.closest?t.closest('a[download]'):null);},true);})();"

        internal fun safeFileName(raw: String): String {
            val cleaned = raw.substringAfterLast('/').substringAfterLast('\\')
                .replace(Regex("[^\\p{L}\\p{N}._ -]"), "_").trim().trim('.')
            return cleaned.take(120).ifBlank { "3x-ui-download" }
        }

        /** blob:https://127.0.0.1:1234/uuid → https://127.0.0.1:1234/uuid for the origin check. */
        internal fun originCheckUrl(url: String): String =
            if (url.lowercase(Locale.ROOT).startsWith("blob:")) url.substring(5) else url

        /** Only public https links leave the app; loopback/private targets are useless outside the tunnel. */
        internal fun externalLink(url: String): Uri? {
            val uri = try { Uri.parse(url) } catch (_: Exception) { return null }
            if (uri.scheme?.lowercase(Locale.ROOT) != "https") return null
            val host = uri.host?.lowercase(Locale.ROOT)?.trim('[', ']') ?: return null
            if (host.isEmpty() || host == "localhost" || host.endsWith(".localhost") || host == "::1" ||
                host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.") ||
                Regex("^172\\.(1[6-9]|2\\d|3[01])\\.").containsMatchIn(host)) return null
            return uri
        }
    }
}
