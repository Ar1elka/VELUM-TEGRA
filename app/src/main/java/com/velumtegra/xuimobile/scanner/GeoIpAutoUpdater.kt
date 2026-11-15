package com.velumtegra.xuimobile.scanner

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

internal data class GeoIpUpdateResult(
    val updated: Boolean,
    val available: Boolean,
    val status: String,
    val databaseFile: File,
)

/** Keeps the approved optional Country.mmdb auto-update behavior independent from scan ownership. */
internal class GeoIpAutoUpdater(private val context: Context) {
    companion object {
        private const val PREFS = "velum_geoip_updater"
        private const val KEY_LAST_CHECK = "last_check"
        private const val KEY_ETAG = "etag"
        private const val CHECK_INTERVAL_MS = 24L * 60L * 60L * 1000L
        private const val DOWNLOAD_URL =
            "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
        private const val MAX_DATABASE_BYTES = 50L * 1024L * 1024L
    }

    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val databaseFile = File(context.filesDir, "Country.mmdb")
    private val tempFile = File(context.filesDir, "Country.mmdb.download")

    suspend fun updateIfNeeded(force: Boolean = false): GeoIpUpdateResult =
        withContext(Dispatchers.IO) {
            val now = System.currentTimeMillis()
            val age = now - prefs.getLong(KEY_LAST_CHECK, 0L)
            if (!force && databaseFile.exists() && age in 0 until CHECK_INTERVAL_MS) {
                return@withContext result(false, "GeoLite2-Country актуальна")
            }

            try {
                val head = (URL(DOWNLOAD_URL).openConnection() as HttpURLConnection).apply {
                    requestMethod = "HEAD"
                    connectTimeout = 15_000
                    readTimeout = 30_000
                    prefs.getString(KEY_ETAG, null)?.let { setRequestProperty("If-None-Match", it) }
                }
                val code = head.responseCode
                val etag = head.getHeaderField("ETag")
                val length = head.contentLengthLong
                head.disconnect()

                if (code == HttpURLConnection.HTTP_NOT_MODIFIED && databaseFile.exists()) {
                    prefs.edit().putLong(KEY_LAST_CHECK, now).apply()
                    return@withContext result(false, "GeoLite2-Country актуальна")
                }
                if (code !in 200..399) return@withContext result(false, "Источник GeoIP: HTTP $code")
                if (length > MAX_DATABASE_BYTES) return@withContext result(false, "GeoIP: файл слишком большой")
                if (databaseFile.exists() && etag != null && etag == prefs.getString(KEY_ETAG, null)) {
                    prefs.edit().putLong(KEY_LAST_CHECK, now).apply()
                    return@withContext result(false, "GeoLite2-Country актуальна")
                }

                val get = (URL(DOWNLOAD_URL).openConnection() as HttpURLConnection).apply {
                    connectTimeout = 15_000
                    readTimeout = 60_000
                }
                if (get.responseCode !in 200..299) {
                    val failed = get.responseCode
                    get.disconnect()
                    return@withContext result(false, "GeoIP download: HTTP $failed")
                }
                tempFile.outputStream().use { output ->
                    get.inputStream.use { input ->
                        val buffer = ByteArray(16 * 1024)
                        var total = 0L
                        while (true) {
                            val read = input.read(buffer)
                            if (read <= 0) break
                            total += read
                            require(total <= MAX_DATABASE_BYTES) { "GeoIP: файл слишком большой" }
                            output.write(buffer, 0, read)
                        }
                    }
                }
                get.disconnect()
                require(tempFile.length() > 1024) { "GeoIP: загруженный файл слишком мал" }
                if (databaseFile.exists()) databaseFile.delete()
                require(tempFile.renameTo(databaseFile)) { "GeoIP: не удалось установить базу" }
                prefs.edit().putLong(KEY_LAST_CHECK, now).putString(KEY_ETAG, etag).apply()
                result(true, "GeoLite2-Country обновлена")
            } catch (error: Exception) {
                tempFile.delete()
                result(false, "GeoIP: ${error.message ?: error.javaClass.simpleName}")
            }
        }

    private fun result(updated: Boolean, status: String) =
        GeoIpUpdateResult(updated, databaseFile.exists(), status, databaseFile)
}
