package com.velumtegra.xuimobile.core.site

/**
 * Non-network derivation of the exact staging-only write contract for one verified Phase 11.51
 * preparation. The result contains no commit/rename/delete/chmod/chown operation and therefore
 * cannot publish the site by itself.
 */
object SiteDeployerStagingWriteBoundary {
    const val CONTRACT_VERSION: Int = 1
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun prepare(preparation: SiteDeployerLocalPreparationResult): SiteDeployerStagingWritePlan {
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        val remote = preparation.remoteDeployPlan
        val staging = SiteRemoteDeployPolicy.prepareTargetRoot(remote.publish.stagingRoot)
        val target = SiteRemoteDeployPolicy.prepareTargetRoot(remote.publish.targetRoot)
        require(staging != target)

        val relativeDirectories = remote.entries
            .mapNotNull { it.path.substringBeforeLast('/', missingDelimiterValue = "").ifBlank { null } }
            .flatMap { parent ->
                val segments = parent.split('/')
                segments.indices.map { index -> segments.take(index + 1).joinToString("/") }
            }
            .distinct()
            .sortedWith(compareBy<String> { it.count { ch -> ch == '/' } }.thenBy { it })

        val directories = buildList {
            add(SiteDeployerStagingDirectory(relativePath = "", remotePath = staging))
            relativeDirectories.forEach { relative ->
                SiteBuildPolicy.validatePath("$relative/index.html")
                add(SiteDeployerStagingDirectory(relativePath = relative, remotePath = "$staging/$relative"))
            }
        }
        val files = remote.entries.map { entry ->
            SiteDeployerStagingFile(
                relativePath = entry.path,
                remotePath = "$staging/${entry.path}",
                mediaType = entry.mediaType,
                byteSize = entry.byteSize,
                sha256 = entry.sha256,
            )
        }

        val base = SiteDeployerStagingWritePlan(
            contractVersion = CONTRACT_VERSION,
            preparationSha256 = preparation.preparationSha256,
            deploymentPlanSha256 = remote.deploymentPlanSha256,
            remoteHostIdentity = remote.remoteHostIdentity,
            targetRoot = target,
            stagingRoot = staging,
            sourceTreeSha256 = remote.sourceTreeSha256,
            fileCount = remote.fileCount,
            totalBytes = remote.totalBytes,
            directories = directories,
            files = files,
            stagingWritePlanSha256 = "",
        )
        return base.copy(stagingWritePlanSha256 = digest(base)).also { validate(it, preparation.bundle) }
    }

    fun validate(plan: SiteDeployerStagingWritePlan, bundle: SiteBundle) {
        SiteBuildPolicy.validate(bundle)
        require(plan.contractVersion == CONTRACT_VERSION)
        require(sha256.matches(plan.preparationSha256))
        require(sha256.matches(plan.deploymentPlanSha256))
        require(sha256.matches(plan.sourceTreeSha256))
        require(sha256.matches(plan.stagingWritePlanSha256))
        require(plan.remoteHostIdentity.isNotBlank())
        SiteRemoteDeployPolicy.prepareTargetRoot(plan.targetRoot)
        SiteRemoteDeployPolicy.prepareTargetRoot(plan.stagingRoot)
        require(plan.targetRoot != plan.stagingRoot)
        require(plan.fileCount == plan.files.size)
        require(plan.fileCount == bundle.manifest.fileCount)
        require(plan.totalBytes == plan.files.sumOf { it.byteSize.toLong() })
        require(plan.totalBytes == bundle.manifest.totalBytes)
        require(plan.sourceTreeSha256 == bundle.manifest.treeSha256)
        require(plan.files.map { it.relativePath } == plan.files.map { it.relativePath }.sorted())
        require(plan.files.map { it.relativePath }.distinct().size == plan.files.size)
        require(plan.directories.isNotEmpty() && plan.directories.first().relativePath.isEmpty())
        require(plan.directories.first().remotePath == plan.stagingRoot)
        require(plan.directories.map { it.remotePath }.distinct().size == plan.directories.size)
        require(plan.directories.drop(1).all { it.remotePath.startsWith(plan.stagingRoot + "/") })

        val bundleByPath = bundle.documents.associateBy { it.path }
        plan.files.forEach { file ->
            SiteBuildPolicy.validatePath(file.relativePath)
            require(file.remotePath == "${plan.stagingRoot}/${file.relativePath}")
            require(file.remotePath.startsWith(plan.stagingRoot + "/"))
            val document = requireNotNull(bundleByPath[file.relativePath])
            require(document.mediaType == file.mediaType)
            require(document.byteSize == file.byteSize)
            require(document.sha256 == file.sha256)
        }
        require(digest(plan.copy(stagingWritePlanSha256 = "")) == plan.stagingWritePlanSha256)
    }

    private fun digest(plan: SiteDeployerStagingWritePlan): String {
        val canonical = buildString {
            append("contractVersion=").append(plan.contractVersion).append('\n')
            append("preparation=").append(plan.preparationSha256).append('\n')
            append("deploymentPlan=").append(plan.deploymentPlanSha256).append('\n')
            append("host=").append(plan.remoteHostIdentity).append('\n')
            append("target=").append(plan.targetRoot).append('\n')
            append("staging=").append(plan.stagingRoot).append('\n')
            append("tree=").append(plan.sourceTreeSha256).append('\n')
            append("fileCount=").append(plan.fileCount).append('\n')
            append("totalBytes=").append(plan.totalBytes).append('\n')
            plan.directories.forEach { append("dir=").append(it.relativePath).append('|').append(it.remotePath).append('\n') }
            plan.files.forEach {
                append("file=").append(it.relativePath).append('|').append(it.remotePath).append('|')
                    .append(it.mediaType).append('|').append(it.byteSize).append('|').append(it.sha256).append('\n')
            }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }
}
