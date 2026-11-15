package com.velumtegra.xuimobile.core.site

/**
 * What the operator asked to do when the selected server already has a site at the requested
 * folder/port.
 *
 * - [DETECT_ONLY]: publish only into a free folder/port; any existing site is reported back to the
 *   UI so the operator can choose explicitly.
 * - [REPLACE_EXISTING]: replace the files of the existing site in the same folder. The previous
 *   files are moved to a backup folder (rename only) and restored automatically if the commit fails.
 */
enum class SiteExistingSiteMode {
    DETECT_ONLY,
    REPLACE_EXISTING,
}

/** Read-only evidence about the requested nginx endpoint. */
data class SiteEndpointObservation(
    /** The deterministic VELUM nginx config for this host/folder/domain/port already exists. */
    val configPresent: Boolean,
    /** Something is already listening on the requested TCP port. */
    val portInUse: Boolean,
    /** Every TCP port that was observed in LISTEN state. */
    val listeningPorts: Set<Int>,
)

data class SiteExistingTargetFile(
    val relativePath: String,
    val byteSize: Long,
    val sha256: String,
)

/** Read-only evidence about the requested target folder. */
data class SiteExistingTargetObservation(
    val present: Boolean,
    val isDirectory: Boolean,
    val totalFileCount: Int,
    val hasSymlinksOrSpecialEntries: Boolean,
    val hasEmptyDirectories: Boolean,
    /** Exact files (only collected while [totalFileCount] is within [SiteExistingSitePolicy.MAX_REPLACEABLE_FILES]). */
    val files: List<SiteExistingTargetFile>,
) {
    companion object {
        val ABSENT = SiteExistingTargetObservation(
            present = false,
            isDirectory = false,
            totalFileCount = 0,
            hasSymlinksOrSpecialEntries = false,
            hasEmptyDirectories = false,
            files = emptyList(),
        )
    }
}

enum class SiteReplaceBlocker {
    TARGET_ABSENT,
    TARGET_NOT_DIRECTORY,
    TARGET_EMPTY,
    TOO_MANY_FILES,
    UNSUPPORTED_ENTRIES,
    UNSUPPORTED_FILE,
    TOO_LARGE,
    PORT_USED_BY_OTHER_SERVICE,
}

/** Result shown to the operator when the selected server already has something at the endpoint. */
data class SiteExistingSiteReport(
    val targetRoot: String,
    val port: Int,
    val targetFolderPresent: Boolean,
    val targetFileCount: Int,
    val configPresent: Boolean,
    val portInUse: Boolean,
    /** Port is busy but not by the VELUM config for this exact folder/domain/port. */
    val portUsedByOtherService: Boolean,
    val replaceBlocker: SiteReplaceBlocker?,
    val suggestedPort: Int?,
    val suggestedTargetRoot: String,
) {
    val conflict: Boolean
        get() = targetFolderPresent || configPresent || portInUse

    val replaceAvailable: Boolean
        get() = replaceBlocker == null

    /** A replacement only swaps files when nginx is already serving this exact folder. */
    val replaceKeepsExistingWebServerConfig: Boolean
        get() = replaceAvailable && configPresent
}

object SiteExistingSitePolicy {
    const val MAX_REPLACEABLE_FILES: Int = SiteBuildPolicy.MAX_DOCUMENTS

    /** Ports commonly free on a VPS running 3x-ui and suitable for an additional web site. */
    val ALTERNATE_PORT_CANDIDATES: List<Int> = listOf(8443, 2053, 2083, 2087, 2096, 8080, 8880, 9443, 10443, 8843)

    fun report(
        targetRoot: String,
        port: Int,
        target: SiteExistingTargetObservation,
        endpoint: SiteEndpointObservation,
    ): SiteExistingSiteReport {
        val canonicalRoot = SiteRemoteDeployPolicy.prepareTargetRoot(targetRoot)
        require(port in 1..65535) { "Port is outside 1..65535" }
        val portUsedByOther = endpoint.portInUse && !endpoint.configPresent
        val suggestedPort = suggestPort(port, endpoint.listeningPorts + if (endpoint.portInUse) setOf(port) else emptySet())
        return SiteExistingSiteReport(
            targetRoot = canonicalRoot,
            port = port,
            targetFolderPresent = target.present,
            targetFileCount = target.totalFileCount,
            configPresent = endpoint.configPresent,
            portInUse = endpoint.portInUse,
            portUsedByOtherService = portUsedByOther,
            replaceBlocker = replaceBlocker(target, portUsedByOther),
            suggestedPort = suggestedPort,
            suggestedTargetRoot = if (target.present && suggestedPort != null) {
                alternateTargetRoot(canonicalRoot, suggestedPort)
            } else {
                canonicalRoot
            },
        )
    }

    fun suggestPort(requested: Int, busy: Set<Int>): Int? {
        val taken = busy + requested
        ALTERNATE_PORT_CANDIDATES.firstOrNull { it !in taken }?.let { return it }
        return (requested + 1..65535).firstOrNull { it !in taken && it >= 1024 }
    }

    fun alternateTargetRoot(targetRoot: String, port: Int): String {
        val canonical = SiteRemoteDeployPolicy.prepareTargetRoot(targetRoot)
        val base = canonical.removeSuffix("-$port")
        return SiteRemoteDeployPolicy.prepareTargetRoot("$base-$port")
    }

    /**
     * Converts the exact observed folder into the previous-tree expectation required by the
     * rename-only replacement transaction. [observedTreeSha256] must be the digest reconstructed
     * from the exact remote bytes (see SiteRemoteReadOnlyDigest) using [treeEntries] of this
     * observation. Returns null when the folder cannot be replaced safely.
     */
    fun previousTreeExpectation(
        target: SiteExistingTargetObservation,
        observedTreeSha256: String,
    ): SiteDeployerRemoteTreeExpectation? {
        if (replaceBlocker(target, portUsedByOtherService = false) != null) return null
        val files = target.files.sortedBy { it.relativePath }.map { file ->
            SiteDeployerRemoteTreeFileExpectation(
                relativePath = file.relativePath,
                mediaType = mediaTypeFor(file.relativePath),
                byteSize = file.byteSize.toInt(),
                sha256 = file.sha256,
            )
        }
        val expectation = SiteDeployerRemoteTreeExpectation(
            treeSha256 = observedTreeSha256,
            fileCount = files.size,
            totalBytes = files.sumOf { it.byteSize.toLong() },
            files = files,
        )
        return runCatching { SiteDeployerCommitTransactionBoundary.validateExpectation(expectation); expectation }.getOrNull()
    }

    /** Sorted digest entries for the observed files; media types are derived from extensions. */
    fun treeEntries(target: SiteExistingTargetObservation): List<SiteRemoteTransportTreeEntrySpec> =
        target.files.sortedBy { it.relativePath }.map { SiteRemoteTransportTreeEntrySpec(it.relativePath, mediaTypeFor(it.relativePath)) }

    fun replaceBlocker(target: SiteExistingTargetObservation, portUsedByOtherService: Boolean): SiteReplaceBlocker? = when {
        !target.present -> SiteReplaceBlocker.TARGET_ABSENT
        !target.isDirectory -> SiteReplaceBlocker.TARGET_NOT_DIRECTORY
        target.hasSymlinksOrSpecialEntries || target.hasEmptyDirectories -> SiteReplaceBlocker.UNSUPPORTED_ENTRIES
        target.totalFileCount == 0 -> SiteReplaceBlocker.TARGET_EMPTY
        target.totalFileCount > MAX_REPLACEABLE_FILES || target.files.size != target.totalFileCount ->
            SiteReplaceBlocker.TOO_MANY_FILES
        target.files.any { !supportedPath(it.relativePath) || !sha256.matches(it.sha256) } ->
            SiteReplaceBlocker.UNSUPPORTED_FILE
        target.files.any { it.byteSize !in 0..SiteBuildPolicy.MAX_DOCUMENT_BYTES.toLong() } ||
            target.files.sumOf { it.byteSize } > SiteBuildPolicy.MAX_TOTAL_BYTES -> SiteReplaceBlocker.TOO_LARGE
        portUsedByOtherService -> SiteReplaceBlocker.PORT_USED_BY_OTHER_SERVICE
        else -> null
    }

    fun mediaTypeFor(path: String): String = when (path.substringAfterLast('.', "").lowercase()) {
        "html" -> "text/html; charset=utf-8"
        "css" -> "text/css; charset=utf-8"
        "js" -> "text/javascript; charset=utf-8"
        "svg" -> "image/svg+xml"
        else -> "text/plain; charset=utf-8"
    }

    private fun supportedPath(path: String): Boolean = runCatching { SiteBuildPolicy.validatePath(path) }.isSuccess

    private val sha256 = Regex("^[0-9a-f]{64}$")
}
