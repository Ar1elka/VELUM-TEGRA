package com.velumtegra.xuimobile.core.site

import java.io.BufferedInputStream
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.Comparator
import java.util.stream.Collectors
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

object SiteLocalExportAdapter {
    fun export(plan: SiteExportPlan, outputRoot: Path): SiteLocalExportReceipt =
        exportInternal(plan, outputRoot, null)

    internal fun exportInternal(
        plan: SiteExportPlan,
        outputRoot: Path,
        stageHook: ((SiteLocalExportStage, Path) -> Unit)?,
    ): SiteLocalExportReceipt {
        SiteLocalExportPolicy.validatePlan(plan)
        val root = SiteLocalExportPolicy.resolveRoot(outputRoot)
        val target = SiteLocalExportPolicy.resolveTarget(root, plan)
        val temp = createTemp(root, plan)
        var published = false
        try {
            when (plan.manifest.format) {
                SiteExportFormat.DIRECTORY -> writeDirectory(plan, temp)
                SiteExportFormat.ZIP -> writeZip(plan, temp)
            }
            stageHook?.invoke(SiteLocalExportStage.TEMP_WRITTEN, temp)
            val artifactSha = verifyTemp(plan, temp)
            stageHook?.invoke(SiteLocalExportStage.TEMP_VERIFIED, temp)
            require(!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) { "Export target appeared during export" }
            atomicMove(temp, target)
            published = true
            verifyPublished(plan, target)
            return SiteLocalExportReceipt(
                format = plan.manifest.format,
                outputName = plan.manifest.outputName,
                outputPath = target,
                fileCount = plan.manifest.fileCount,
                totalBytes = plan.manifest.totalBytes,
                sourceTreeSha256 = plan.manifest.sourceTreeSha256,
                planSha256 = plan.manifest.planSha256,
                artifactSha256 = artifactSha,
                verified = true,
            )
        } catch (error: Throwable) {
            if (published) cleanup(target) else cleanup(temp)
            throw error
        }
    }

    private fun createTemp(root: Path, plan: SiteExportPlan): Path =
        when (plan.manifest.format) {
            SiteExportFormat.DIRECTORY -> Files.createTempDirectory(root, ".${plan.manifest.outputBaseName}.tmp-")
            SiteExportFormat.ZIP -> Files.createTempFile(root, ".${plan.manifest.outputBaseName}.tmp-", ".zip.part")
        }

    private fun writeDirectory(plan: SiteExportPlan, tempRoot: Path) {
        plan.entries.forEach { entry ->
            val target = SiteLocalExportPolicy.resolveEntry(tempRoot, entry.path)
            target.parent?.let(Files::createDirectories)
            require(!Files.exists(target, LinkOption.NOFOLLOW_LINKS)) { "Duplicate physical export path: ${entry.path}" }
            Files.write(
                target,
                entry.content.toByteArray(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE,
            )
        }
    }

    private fun writeZip(plan: SiteExportPlan, tempFile: Path) {
        ZipOutputStream(Files.newOutputStream(tempFile, StandardOpenOption.TRUNCATE_EXISTING)).use { zip ->
            plan.entries.forEach { entry ->
                val bytes = entry.content.toByteArray(StandardCharsets.UTF_8)
                val crc = CRC32().apply { update(bytes) }
                val zipEntry = ZipEntry(entry.path).apply {
                    method = ZipEntry.STORED
                    size = bytes.size.toLong()
                    compressedSize = bytes.size.toLong()
                    this.crc = crc.value
                    time = 0L
                }
                zip.putNextEntry(zipEntry)
                zip.write(bytes)
                zip.closeEntry()
            }
        }
    }

    private fun verifyTemp(plan: SiteExportPlan, temp: Path): String? =
        when (plan.manifest.format) {
            SiteExportFormat.DIRECTORY -> {
                verifyDirectory(plan, temp)
                null
            }
            SiteExportFormat.ZIP -> {
                verifyZip(plan, temp)
                sha256File(temp)
            }
        }

    private fun verifyPublished(plan: SiteExportPlan, target: Path) {
        when (plan.manifest.format) {
            SiteExportFormat.DIRECTORY -> verifyDirectory(plan, target)
            SiteExportFormat.ZIP -> verifyZip(plan, target)
        }
    }

    private fun verifyDirectory(plan: SiteExportPlan, root: Path) {
        require(Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) { "Export directory is missing" }
        require(!Files.isSymbolicLink(root)) { "Export directory must not be a symbolic link" }
        val actualFiles = Files.walk(root).use { stream ->
            stream.filter { path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) }
                .map { path -> root.relativize(path).toString().replace('\\', '/') }
                .sorted()
                .collect(Collectors.toList())
        }
        require(actualFiles == plan.entries.map(SiteExportEntry::path)) { "Export directory file set mismatch" }
        plan.entries.forEach { entry ->
            val path = SiteLocalExportPolicy.resolveEntry(root, entry.path)
            require(!Files.isSymbolicLink(path)) { "Symbolic links are forbidden in export output" }
            val size = Files.size(path)
            require(size == entry.byteSize.toLong()) { "Post-write size mismatch: ${entry.path}" }
            require(sha256File(path) == entry.sha256) { "Post-write SHA-256 mismatch: ${entry.path}" }
        }
    }

    private fun verifyZip(plan: SiteExportPlan, zipPath: Path) {
        require(Files.isRegularFile(zipPath, LinkOption.NOFOLLOW_LINKS)) { "Export ZIP is missing" }
        require(!Files.isSymbolicLink(zipPath)) { "Export ZIP must not be a symbolic link" }
        ZipFile(zipPath.toFile(), StandardCharsets.UTF_8).use { zip ->
            val entries = zip.entries().toList()
            require(entries.none(ZipEntry::isDirectory)) { "ZIP must not contain directory entries" }
            require(entries.map(ZipEntry::getName) == plan.entries.map(SiteExportEntry::path)) {
                "ZIP entry set/order mismatch"
            }
            require(entries.map(ZipEntry::getName).distinct().size == entries.size) { "ZIP contains duplicate entries" }
            entries.zip(plan.entries).forEach { (zipEntry, expected) ->
                SiteBuildPolicy.validatePath(zipEntry.name)
                require(zipEntry.size == expected.byteSize.toLong()) { "ZIP entry size mismatch: ${expected.path}" }
                val bytes = zip.getInputStream(zipEntry).use { input ->
                    val bounded = input.readBoundedBytes(SiteBuildPolicy.MAX_DOCUMENT_BYTES + 1)
                    require(bounded.size <= SiteBuildPolicy.MAX_DOCUMENT_BYTES) {
                        "ZIP entry exceeds post-write limit: ${expected.path}"
                    }
                    bounded
                }
                require(bytes.size == expected.byteSize) { "ZIP entry byte count mismatch: ${expected.path}" }
                require(SiteBundleDigest.sha256(bytes) == expected.sha256) {
                    "ZIP entry SHA-256 mismatch: ${expected.path}"
                }
            }
        }
    }

    private fun atomicMove(source: Path, target: Path) {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE)
        } catch (error: AtomicMoveNotSupportedException) {
            throw IllegalStateException("Selected export filesystem does not support atomic publish", error)
        }
    }

    private fun sha256File(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        BufferedInputStream(Files.newInputStream(path)).use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count > 0) digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }

    private fun cleanup(path: Path) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return
        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)) {
            Files.walk(path).use { stream ->
                stream.sorted(Comparator.reverseOrder()).forEach { child -> Files.deleteIfExists(child) }
            }
        } else {
            Files.deleteIfExists(path)
        }
    }
}

private fun java.io.InputStream.readBoundedBytes(limit: Int): ByteArray {
    val output = java.io.ByteArrayOutputStream(minOf(DEFAULT_BUFFER_SIZE, limit))
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    var total = 0
    while (true) {
        val count = read(buffer)
        if (count < 0) break
        if (count == 0) continue
        total += count
        if (total > limit) {
            output.write(buffer, 0, count - (total - limit))
            break
        }
        output.write(buffer, 0, count)
    }
    return output.toByteArray()
}
