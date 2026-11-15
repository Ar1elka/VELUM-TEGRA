package com.velumtegra.xuimobile.core.scanner.android

import android.util.Log
import com.maxmind.db.CHMCache
import com.maxmind.db.Reader
import java.io.Closeable
import java.io.File
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Android-safe reader for the optional local Country.mmdb used by Scanner result rows.
 *
 * The high-level geoip2 `DatabaseReader` builds its response models through Java records. Android desugars
 * records into plain classes, so every lookup failed with ConstructorNotFoundException and each row silently
 * showed "N/A". Reading the raw record as a map needs no model classes at all.
 */
class GeoIpResolver(database: File) : Closeable {
    private val reader = Reader(database, Reader.FileMode.MEMORY, CHMCache())
    private val failureLogged = AtomicBoolean(false)

    val databaseType: String
        get() = reader.metadata.databaseType

    val databaseDescription: String
        get() = reader.metadata.description.values.firstOrNull() ?: ""

    fun lookup(ip: String): String =
        runCatching { countryCode(reader, InetAddress.getByName(ip)) ?: "N/A" }
            .getOrElse { error ->
                // A broken reader must not hide behind "N/A" again; say why once per scan.
                if (failureLogged.compareAndSet(false, true)) {
                    Log.w(TAG, "lookup failed: ${error.javaClass.simpleName}: ${error.message}")
                }
                "N/A"
            }

    override fun close() {
        reader.close()
    }

    companion object {
        private const val TAG = "VelumGeoIp"

        /** Where the address is located; falls back to where its network is registered. */
        private fun countryCode(reader: Reader, address: InetAddress): String? {
            val record = reader.get(address, Map::class.java) ?: return null
            return isoCode(record["country"]) ?: isoCode(record["registered_country"])
        }

        private fun isoCode(node: Any?): String? =
            ((node as? Map<*, *>)?.get("iso_code") as? String)?.takeIf { it.isNotBlank() }

        fun validate(database: File): String =
            runCatching {
                require(database.exists()) { "Файл Country.mmdb не найден" }
                require(database.length() > 1024) { "Файл Country.mmdb слишком мал" }

                Reader(database, Reader.FileMode.MEMORY, CHMCache()).use { reader ->
                    val checks =
                        listOf("1.1.1.1", "8.8.8.8").map { ip ->
                            val country = runCatching { countryCode(reader, InetAddress.getByName(ip)) }.getOrNull()
                            if (country.isNullOrBlank()) "$ip → N/A" else "$ip → $country"
                        }
                    "OK: ${reader.metadata.databaseType} • ${checks.joinToString(" • ")}"
                }
            }.getOrElse { error ->
                "Ошибка GeoIP: ${error.message ?: error.javaClass.simpleName}"
            }
    }
}
