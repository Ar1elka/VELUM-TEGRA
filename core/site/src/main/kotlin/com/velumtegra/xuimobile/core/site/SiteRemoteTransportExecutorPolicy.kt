package com.velumtegra.xuimobile.core.site

internal data class SiteRemoteTransportExecutionLayout(
    val stagingRoot: String,
    val targetRoot: String,
    val backupRoot: String?,
)

internal object SiteRemoteTransportExecutorPolicy {
    fun validateBinding(
        authorization: SiteRemoteTransportAuthorization,
        capabilities: SiteRemoteTransportCapabilities,
    ) {
        SiteRemoteTransportPolicy.validateCapabilities(capabilities)
        SiteRemoteTransportPolicy.validateAuthorization(authorization)
        require(authorization.implementationId == capabilities.implementationId) {
            "Transport authorization implementation id does not match primitive port"
        }
        require(authorization.capabilityProfileSha256 == SiteRemoteTransportPolicy.capabilityProfileSha256(capabilities)) {
            "Transport authorization capability profile does not match primitive port"
        }
        require(capabilities.capabilities.containsAll(authorization.requiredCapabilities)) {
            "Primitive port is missing an authorized capability"
        }
        require(authorization.fileCount <= capabilities.maxFiles) { "Primitive port maxFiles is below authorization" }
        require(authorization.totalBytes <= capabilities.maxTotalBytes) { "Primitive port maxTotalBytes is below authorization" }
    }

    fun layout(authorization: SiteRemoteTransportAuthorization): SiteRemoteTransportExecutionLayout {
        SiteRemoteTransportPolicy.validateAuthorization(authorization)
        val publishRenames = authorization.forwardOperations
            .filterIsInstance<SiteRemoteTransportOperation.AtomicRename>()
        val publish = publishRenames.singleOrNull { it.purpose == SiteRemoteTransportRenamePurpose.STAGING_TO_TARGET }
            ?: error("Transport authorization must contain exactly one staging-to-target publish rename")
        val backup = publishRenames.filter { it.purpose == SiteRemoteTransportRenamePurpose.TARGET_TO_BACKUP }
        require(backup.size <= 1) { "Transport authorization contains multiple target-to-backup renames" }
        backup.singleOrNull()?.let {
            require(it.fromPath == publish.toPath) { "Backup rename source must be the publish target" }
        }
        val stagingCreate = authorization.forwardOperations
            .filterIsInstance<SiteRemoteTransportOperation.CreateDirectory>()
            .firstOrNull()
            ?: error("Transport authorization must create a staging root")
        require(stagingCreate.path == publish.fromPath) { "First created directory must be the staging root" }

        val assertPrefix = authorization.forwardOperations.takeWhile { it is SiteRemoteTransportOperation.AssertPathState }
        require(assertPrefix.size >= 2) { "Transport authorization must begin with target/staging re-stat guards" }
        val expectedTarget = assertPrefix.filterIsInstance<SiteRemoteTransportOperation.AssertPathState>()
            .singleOrNull { it.path == publish.toPath }
            ?: error("Transport authorization is missing target re-stat guard")
        require(expectedTarget.expectedType != SiteRemoteObservedPathType.SYMLINK)
        require(
            assertPrefix.filterIsInstance<SiteRemoteTransportOperation.AssertPathState>()
                .any { it.path == publish.fromPath && it.expectedType == SiteRemoteObservedPathType.ABSENT },
        ) { "Transport authorization is missing staging-absent re-stat guard" }

        val backupRoot = backup.singleOrNull()?.toPath
        if (backupRoot != null) {
            require(
                assertPrefix.filterIsInstance<SiteRemoteTransportOperation.AssertPathState>()
                    .any { it.path == backupRoot && it.expectedType == SiteRemoteObservedPathType.ABSENT },
            ) { "Transport authorization is missing backup-absent re-stat guard" }
        }
        return SiteRemoteTransportExecutionLayout(
            stagingRoot = publish.fromPath,
            targetRoot = publish.toPath,
            backupRoot = backupRoot,
        )
    }

    fun preparePayloads(
        authorization: SiteRemoteTransportAuthorization,
        source: SiteRemoteTransportSource,
    ): Map<String, ByteArray> {
        val uploads = authorization.forwardOperations.filterIsInstance<SiteRemoteTransportOperation.UploadFile>()
        require(uploads.size == authorization.fileCount) { "Authorization upload count does not match fileCount" }
        require(uploads.map { it.relativePath }.distinct().size == uploads.size) { "Authorization contains duplicate upload paths" }

        var totalBytes = 0L
        val payloads = LinkedHashMap<String, ByteArray>(uploads.size)
        uploads.forEach { upload ->
            val payload = source.read(upload.relativePath)
            require(payload.size == upload.byteSize) { "Source byte size mismatch: ${upload.relativePath}" }
            require(payload.size <= authorization.totalBytes) { "Source payload exceeds authorization bounds" }
            require(SiteBundleDigest.sha256(payload) == upload.sha256) { "Source SHA-256 mismatch: ${upload.relativePath}" }
            totalBytes += payload.size
            payloads[upload.relativePath] = payload.copyOf()
        }
        require(totalBytes == authorization.totalBytes) { "Source total byte count does not match authorization" }
        return payloads
    }


    fun treeEntrySpecs(authorization: SiteRemoteTransportAuthorization): List<SiteRemoteTransportTreeEntrySpec> =
        authorization.forwardOperations
            .filterIsInstance<SiteRemoteTransportOperation.UploadFile>()
            .map { SiteRemoteTransportTreeEntrySpec(it.relativePath, it.mediaType) }

    fun validateTree(
        operation: SiteRemoteTransportOperation.VerifyTree,
        observation: SiteRemoteTransportTreeObservation,
    ) {
        require(observation.rootPath == operation.rootPath) { "Remote tree observation path mismatch" }
        require(observation.treeSha256 == operation.expectedTreeSha256) { "Remote tree SHA-256 mismatch" }
        require(observation.fileCount == operation.fileCount) { "Remote tree file count mismatch" }
        require(observation.totalBytes == operation.totalBytes) { "Remote tree byte count mismatch" }
    }
}
