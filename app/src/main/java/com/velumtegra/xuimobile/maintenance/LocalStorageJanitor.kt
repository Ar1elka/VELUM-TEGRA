package com.velumtegra.xuimobile.maintenance

import android.util.Log
import com.velumtegra.xuimobile.core.domain.ReferenceProvenSecretGarbageCollector
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretGarbageCollectionResult
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.inventory.PrivatePanelCertificatePins
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

internal data class JanitorReport(
    val secretsDeleted: Int,
    val pinsDropped: Int,
    val cacheDirsDeleted: Int,
    val fenceMarkersDeleted: Int,
)

/**
 * Removes local leftovers that nothing references any more. Never touches a VPS.
 *  - encrypted secrets: only via the reference-proven GC (same coordinator as every credential writer);
 *  - panel certificate pins of deleted panel sign-ins;
 *  - Site Deployer per-attempt preparation folders older than [CACHE_MAX_AGE_MS];
 *  - replay-fence markers older than [FENCE_MAX_AGE_MS]: every fenced authorization expires within
 *    minutes (publish permit ≤ 60 s), so a month-old marker can no longer guard anything.
 */
internal class LocalStorageJanitor(
    private val secrets: () -> ReferenceProvenSecretGarbageCollector,
    private val panels: () -> WebPanelAccessRepository,
    private val pins: PrivatePanelCertificatePins,
    private val siteCacheRoot: File,
    private val fenceRoot: () -> File,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val lock = Mutex()

    suspend fun sweep(): JanitorReport = lock.withLock {
        withContext(Dispatchers.IO) {
            val report = JanitorReport(
                secretsDeleted = step("secrets") { collectSecrets() },
                pinsDropped = step("pins") { dropPins() },
                cacheDirsDeleted = step("cache") { pruneChildren(siteCacheRoot, CACHE_MAX_AGE_MS, directories = true) },
                fenceMarkersDeleted = step("fences") { pruneFences() },
            )
            Log.i(TAG, "sweep: $report")
            report
        }
    }

    private suspend fun collectSecrets(): Int = when (val r = secrets().collect()) {
        is SecretGarbageCollectionResult.Completed -> r.deleted.size
        else -> 0
    }

    /** Fail-closed: without a complete list of panel sign-ins no pin is dropped. */
    private suspend fun dropPins(): Int {
        val list = panels().list() as? RepositoryResult.Success ?: return 0
        return pins.retainOnly(list.value.map { it.value.id.value }.toSet())
    }

    private fun pruneFences(): Int {
        val root = fenceRoot()
        if (!root.isDirectory) return 0
        return root.listFiles().orEmpty().filter { it.isDirectory && !isSymlink(it) }
            .sumOf { pruneChildren(it, FENCE_MAX_AGE_MS, directories = false) }
    }

    /** Deletes direct children older than [maxAgeMs]; never follows symlinks out of [parent]. */
    private fun pruneChildren(parent: File, maxAgeMs: Long, directories: Boolean): Int {
        if (!parent.isDirectory || isSymlink(parent)) return 0
        val cutoff = now() - maxAgeMs
        var deleted = 0
        for (child in parent.listFiles().orEmpty()) {
            if (isSymlink(child) || child.lastModified() > cutoff) continue
            val ok = if (directories && child.isDirectory) deleteTree(child) else child.isFile && child.delete()
            if (ok) deleted++
        }
        return deleted
    }

    private fun deleteTree(dir: File): Boolean {
        for (child in dir.listFiles().orEmpty()) {
            if (isSymlink(child)) { child.delete(); continue }
            if (child.isDirectory) deleteTree(child) else child.delete()
        }
        return dir.delete()
    }

    private fun isSymlink(file: File): Boolean = try {
        java.nio.file.Files.isSymbolicLink(file.toPath())
    } catch (_: Exception) { true }

    private suspend fun step(name: String, block: suspend () -> Int): Int = try {
        block()
    } catch (cancel: CancellationException) {
        throw cancel
    } catch (error: Exception) {
        Log.w(TAG, "sweep $name failed: ${error.javaClass.simpleName}")
        0
    }

    companion object {
        private const val TAG = "VelumJanitor"
        val CACHE_MAX_AGE_MS: Long = TimeUnit.HOURS.toMillis(1)
        val FENCE_MAX_AGE_MS: Long = TimeUnit.DAYS.toMillis(30)
    }
}
