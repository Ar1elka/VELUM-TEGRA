package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.UpdatePackageIntegrity
import com.velumtegra.xuimobile.core.domain.UpdatePackageIntegrityResult
import com.velumtegra.xuimobile.core.domain.UpdatePackagePolicy
import com.velumtegra.xuimobile.core.model.*
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.URI
import java.time.Instant
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext

enum class UpdatePackagePreparationFailure { REPORT_CHANGED, BUSY, DOWNLOAD_REJECTED, TOO_LARGE, INTEGRITY, UNAVAILABLE }
sealed interface UpdatePackagePreparationResult {
    data class Verified(val receipt: UpdatePackageReceipt) : UpdatePackagePreparationResult
    data class Failed(val reason: UpdatePackagePreparationFailure) : UpdatePackagePreparationResult
}
interface UpdatePackagePreparationPort {
    suspend fun prepare(request: UpdatePackageRequest): UpdatePackagePreparationResult
    fun discard(receipt: UpdatePackageReceipt)
}

internal fun interface UpdatePackageHttpTransport {
    fun open(uri: URI): UpdatePackageHttpResponse
}
internal class UpdatePackageHttpResponse(val status: Int, val location: String?, val contentLength: Long?,
    val body: InputStream, private val disconnect: () -> Unit = {}) : Closeable {
    override fun close() { try { body.close() } finally { disconnect() } }
}

/** HTTPS system trust is independent of per-panel certificate pins and SSH credentials. */
internal object SystemUpdatePackageHttpTransport : UpdatePackageHttpTransport {
    override fun open(uri: URI): UpdatePackageHttpResponse {
        val connection = uri.toURL().openConnection() as HttpsURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000; connection.readTimeout = 15_000
            connection.useCaches = false
            connection.setRequestProperty("User-Agent", "VELUM-TEGRA-UpdatePackage/1")
            connection.setRequestProperty("Accept", "application/octet-stream")
            connection.setRequestProperty("Accept-Encoding", "identity")
            val status = connection.responseCode
            val body = if (status == 200) connection.inputStream else ByteArrayInputStream(ByteArray(0))
            return UpdatePackageHttpResponse(status, connection.getHeaderField("Location"),
                connection.getHeaderFieldLong("Content-Length", -1).takeIf { it >= 0 }, body) { connection.disconnect() }
        } catch (error: Exception) { connection.disconnect(); throw error }
    }
}

internal object UpdatePackageDownloadUrlPolicy {
    fun allowed(release: ReviewedXuiUpdatePackage, uri: URI): Boolean {
        if (uri.scheme != "https" || uri.rawUserInfo != null || uri.rawFragment != null ||
            uri.port !in setOf(-1, 443) || uri.normalize() != uri || (uri.rawQuery?.length ?: 0) > 8192) return false
        if (uri == URI(release.downloadUrl)) return true
        if (!Regex("/[A-Za-z0-9._/-]{1,1023}").matches(uri.rawPath ?: "")) return false
        return when (uri.host) {
            "release-assets.githubusercontent.com" -> uri.rawPath.startsWith("/github-production-release-asset/")
            "objects.githubusercontent.com" -> uri.rawPath.startsWith("/github-production-release-asset-2e65be/")
            else -> false
        }
    }
}

/** One bounded private cache, one existing journal for target truth, no remote mutation runtime. */
internal class OfficialUpdatePackagePreparationPort(
    private val directory: File,
    private val statuses: UpdatePreflightStatusPort,
    private val transport: UpdatePackageHttpTransport = SystemUpdatePackageHttpTransport,
    private val now: () -> Instant = Instant::now,
) : UpdatePackagePreparationPort {
    private val mutex = Mutex()
    private val cacheLock = Any()
    private var cached: Pair<UpdatePackageReceipt, File>? = null

    override suspend fun prepare(request: UpdatePackageRequest): UpdatePackagePreparationResult {
        if (!mutex.tryLock()) return failed(UpdatePackagePreparationFailure.BUSY)
        var temporary: File? = null
        var completeFile: File? = null
        var published: UpdatePackageReceipt? = null
        try {
            if (!UpdatePackagePolicy.matches(request, now()) || !stillCurrent(request.report))
                return failed(UpdatePackagePreparationFailure.REPORT_CHANGED)
            currentCoroutineContext().ensureActive()
            if (synchronized(cacheLock) { cached != null }) return failed(UpdatePackagePreparationFailure.BUSY)
            val token = UUID.randomUUID().toString().replace("-", "")
            val file = withContext(Dispatchers.IO) {
                if (!directory.isDirectory && !directory.mkdirs()) throw IOException("Package cache unavailable")
                directory.listFiles()?.filter { Regex("pkg-[0-9a-f]{32}\\.(?:part|tar\\.gz)").matches(it.name) }
                    ?.forEach { if (!it.delete()) throw IOException("Old package cache unavailable") }
                File(directory, "pkg-$token.part").also {
                    if (!it.createNewFile()) throw IOException("Package cache collision")
                    temporary = it
                }
            }
            temporary = file
            val integrity = download(request.release, file)
            val matched = integrity as? UpdatePackageIntegrityResult.Matched ?: return failed(when (integrity) {
                UpdatePackageIntegrityResult.TooLarge -> UpdatePackagePreparationFailure.TOO_LARGE
                else -> UpdatePackagePreparationFailure.INTEGRITY
            })
            if (!UpdatePackagePolicy.matches(request, now()) || !stillCurrent(request.report))
                return failed(UpdatePackagePreparationFailure.REPORT_CHANGED)
            currentCoroutineContext().ensureActive()
            val receipt = UpdatePackageReceipt(request.report.scope, request.report.observedAt, request.release,
                matched.sha256, matched.sizeBytes, now(), token)
            val finalFile = withContext(Dispatchers.IO) {
                File(directory, "pkg-$token.tar.gz").also {
                    if (!file.renameTo(it)) throw IOException("Package cache commit unavailable")
                    completeFile = it
                }
            }
            completeFile = finalFile
            currentCoroutineContext().ensureActive()
            synchronized(cacheLock) { cached = receipt to finalFile }
            published = receipt
            return UpdatePackagePreparationResult.Verified(receipt)
        } catch (cancel: CancellationException) {
            published?.let(::discard)
            throw cancel
        } catch (_: RejectedDownload) {
            return failed(UpdatePackagePreparationFailure.DOWNLOAD_REJECTED)
        } catch (_: Exception) {
            return failed(UpdatePackagePreparationFailure.UNAVAILABLE)
        } finally {
            deleteOwned(temporary)
            if (published == null) deleteOwned(completeFile)
            mutex.unlock()
        }
    }

    override fun discard(receipt: UpdatePackageReceipt) = synchronized(cacheLock) {
        val entry = cached
        if (entry != null && entry.first == receipt) { deleteOwned(entry.second); cached = null }
        Unit
    }

    private suspend fun stillCurrent(report: UpdatePreflightSnapshot): Boolean {
        val scope = report.scope
        val status = statuses.read(scope.serverId.value, scope.installationId.value,
            UpdatePreflightPointer(scope.operationId.value, scope.serverAccessId.value))
        return status.terminal && status.snapshot == report
    }

    private suspend fun download(release: ReviewedXuiUpdatePackage, file: File): UpdatePackageIntegrityResult = withContext(Dispatchers.IO) {
        val context = currentCoroutineContext()
        val deadline = System.nanoTime() + 300_000_000_000L
        fun checkActive() { context.ensureActive(); if (System.nanoTime() - deadline >= 0) throw RejectedDownload() }
        var uri = URI(release.downloadUrl)
        repeat(5) {
            checkActive()
            if (!UpdatePackageDownloadUrlPolicy.allowed(release, uri)) throw RejectedDownload()
            transport.open(uri).use { response ->
                checkActive()
                if (response.status in setOf(301, 302, 303, 307, 308)) {
                    val location = response.location ?: throw RejectedDownload()
                    if (location.length > 10_000) throw RejectedDownload()
                    uri = uri.resolve(location)
                } else {
                    if (response.status != 200) throw RejectedDownload()
                    if ((response.contentLength ?: 0) > UpdatePackageReceipt.MAX_BYTES)
                        return@withContext UpdatePackageIntegrityResult.TooLarge
                    return@withContext FileOutputStream(file).use { output ->
                        val result = UpdatePackageIntegrity.copyAndVerify(response.body, output, release.sha256, checkActive = ::checkActive)
                        if (result is UpdatePackageIntegrityResult.Matched) output.fd.sync()
                        result
                    }
                }
            }
        }
        throw RejectedDownload()
    }

    private fun failed(reason: UpdatePackagePreparationFailure) = UpdatePackagePreparationResult.Failed(reason)
    private fun deleteOwned(file: File?) { try { file?.delete() } catch (_: SecurityException) { } }
    private class RejectedDownload : IOException()
}
