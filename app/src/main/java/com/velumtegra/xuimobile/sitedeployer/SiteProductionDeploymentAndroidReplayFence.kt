package com.velumtegra.xuimobile.sitedeployer

import android.content.Context
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentDurableReplayFence
import java.io.File
import java.io.IOException

/**
 * Android production binding for the Site Deployer durable replay fence.
 *
 * The root is an exact direct child of [Context.getNoBackupFilesDir]. Callers cannot choose a path,
 * and an existing symlink/escape is rejected after canonicalization. Merely creating the Android
 * process does not touch this directory; [open] is used lazily by the application composition root.
 */
internal object SiteProductionDeploymentAndroidReplayFence {
    const val ROOT_DIRECTORY_NAME: String = "site-production-deployment-replay-fence-v1"

    fun canonicalRoot(context: Context): File {
        val appContext = context.applicationContext
        val noBackupRoot = canonicalDirectory(appContext.noBackupFilesDir, "Android no-backup root")
        val candidate = try {
            File(noBackupRoot, ROOT_DIRECTORY_NAME).canonicalFile
        } catch (error: IOException) {
            throw IllegalArgumentException("Site Deployer replay root cannot be canonicalized", error)
        }
        require(candidate.parentFile == noBackupRoot) {
            "Site Deployer replay root escaped the exact Android no-backup root"
        }
        return candidate
    }

    fun open(context: Context): SiteProductionDeploymentDurableReplayFence {
        val expectedRoot = canonicalRoot(context)
        return SiteProductionDeploymentDurableReplayFence.open(expectedRoot).also { fence ->
            require(fence.snapshot().canonicalRootPath == expectedRoot.path) {
                "Durable replay fence opened a root different from the Android production binding"
            }
        }
    }

    private fun canonicalDirectory(directory: File, label: String): File {
        require(directory.path.isNotBlank()) { "$label path must not be blank" }
        if (directory.exists()) {
            require(directory.isDirectory) { "$label must be a directory" }
        } else {
            require(directory.mkdirs() || directory.isDirectory) { "$label cannot be created" }
        }
        val canonical = try {
            directory.canonicalFile
        } catch (error: IOException) {
            throw IllegalArgumentException("$label cannot be canonicalized", error)
        }
        require(canonical.isDirectory) { "$label canonical path must be a directory" }
        return canonical
    }
}
