package com.velumtegra.xuimobile.core.site

object SiteRemoteTransportBoundary {
    fun authorize(
        plan: SiteRemoteDeployPlan,
        preflight: SiteRemotePreflightReport,
        capabilities: SiteRemoteTransportCapabilities,
    ): SiteRemoteTransportAuthorization {
        SiteRemoteDeployPolicy.validatePlan(plan)
        SiteRemoteTransportPolicy.validatePreflightEvidence(plan, preflight)
        SiteRemoteTransportPolicy.validateCapabilities(capabilities)

        val required = SiteRemoteTransportPolicy.requiredCapabilities(plan)
        require(capabilities.capabilities.containsAll(required)) { "Remote transport is missing required capabilities" }
        require(plan.fileCount <= capabilities.maxFiles) { "Remote transport file-count capability is too small" }
        require(plan.totalBytes <= capabilities.maxTotalBytes) { "Remote transport total-byte capability is too small" }
        require(plan.entries.all { it.byteSize <= capabilities.maxSingleFileBytes }) { "Remote transport single-file capability is too small" }

        val forward = buildForwardOperations(plan)
        val rollback = buildRollbackOperations(plan)
        (forward + rollback).forEach { operation ->
            operation.remotePaths().forEach { path ->
                require(path.length <= capabilities.maxRemotePathLength) { "Remote transport path capability is too small" }
            }
        }

        val base = SiteRemoteTransportAuthorization(
            contractVersion = SiteRemoteTransportPolicy.CONTRACT_VERSION,
            implementationId = capabilities.implementationId,
            capabilityProfileSha256 = SiteRemoteTransportPolicy.capabilityProfileSha256(capabilities),
            deploymentPlanSha256 = plan.deploymentPlanSha256,
            preflightSha256 = preflight.preflightSha256,
            remoteHostIdentity = plan.remoteHostIdentity,
            sourceTreeSha256 = plan.sourceTreeSha256,
            fileCount = plan.fileCount,
            totalBytes = plan.totalBytes,
            requiredCapabilities = required,
            forwardOperations = forward,
            rollbackOperations = rollback,
            authorizationSha256 = "",
        )
        return base.copy(
            authorizationSha256 = SiteRemoteTransportDigest.authorizationSha256(base),
        ).also(SiteRemoteTransportPolicy::validateAuthorization)
    }

    private fun buildForwardOperations(plan: SiteRemoteDeployPlan): List<SiteRemoteTransportOperation> = buildList {
        add(
            SiteRemoteTransportOperation.AssertPathState(
                plan.publish.targetRoot,
                when (plan.publish.existingTargetPolicy) {
                    SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> SiteRemoteObservedPathType.ABSENT
                    SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> SiteRemoteObservedPathType.DIRECTORY
                },
            ),
        )
        add(SiteRemoteTransportOperation.AssertPathState(plan.publish.stagingRoot, SiteRemoteObservedPathType.ABSENT))
        plan.publish.backupRoot?.let { backup ->
            add(SiteRemoteTransportOperation.AssertPathState(backup, SiteRemoteObservedPathType.ABSENT))
        }
        val directories = remoteDirectories(plan)
        directories.forEach { directory ->
            add(
                SiteRemoteTransportOperation.CreateDirectory(
                    path = directory,
                    owner = plan.publish.owner,
                    group = plan.publish.group,
                    mode = plan.publish.directoryMode,
                ),
            )
        }
        plan.entries.forEach { entry ->
            val remotePath = remoteFilePath(plan.publish.stagingRoot, entry.path)
            add(
                SiteRemoteTransportOperation.UploadFile(
                    relativePath = entry.path,
                    remotePath = remotePath,
                    mediaType = entry.mediaType,
                    byteSize = entry.byteSize,
                    sha256 = entry.sha256,
                ),
            )
            add(SiteRemoteTransportOperation.VerifyFileSha256(remotePath, entry.sha256))
            add(
                SiteRemoteTransportOperation.ApplyFileMetadata(
                    remotePath = remotePath,
                    owner = plan.publish.owner,
                    group = plan.publish.group,
                    mode = plan.publish.fileMode,
                ),
            )
        }
        directories.asReversed().forEach { directory ->
            add(
                SiteRemoteTransportOperation.ApplyDirectoryMetadata(
                    remotePath = directory,
                    owner = plan.publish.owner,
                    group = plan.publish.group,
                    mode = plan.publish.directoryMode,
                ),
            )
        }
        add(
            SiteRemoteTransportOperation.VerifyTree(
                rootPath = plan.publish.stagingRoot,
                expectedTreeSha256 = plan.sourceTreeSha256,
                fileCount = plan.fileCount,
                totalBytes = plan.totalBytes,
            ),
        )
        plan.publish.backupRoot?.let { backup ->
            add(
                SiteRemoteTransportOperation.AtomicRename(
                    fromPath = plan.publish.targetRoot,
                    toPath = backup,
                    purpose = SiteRemoteTransportRenamePurpose.TARGET_TO_BACKUP,
                ),
            )
        }
        add(
            SiteRemoteTransportOperation.AtomicRename(
                fromPath = plan.publish.stagingRoot,
                toPath = plan.publish.targetRoot,
                purpose = SiteRemoteTransportRenamePurpose.STAGING_TO_TARGET,
            ),
        )
        add(
            SiteRemoteTransportOperation.VerifyTree(
                rootPath = plan.publish.targetRoot,
                expectedTreeSha256 = plan.sourceTreeSha256,
                fileCount = plan.fileCount,
                totalBytes = plan.totalBytes,
            ),
        )
    }

    private fun buildRollbackOperations(plan: SiteRemoteDeployPlan): List<SiteRemoteTransportOperation> = buildList {
        add(SiteRemoteTransportOperation.RemoveTransactionTree(plan.publish.stagingRoot))
        add(SiteRemoteTransportOperation.RemoveTransactionTree(plan.publish.targetRoot))
        plan.publish.backupRoot?.let { backup ->
            add(
                SiteRemoteTransportOperation.AtomicRename(
                    fromPath = backup,
                    toPath = plan.publish.targetRoot,
                    purpose = SiteRemoteTransportRenamePurpose.BACKUP_TO_TARGET_ROLLBACK,
                ),
            )
        }
    }

    private fun remoteDirectories(plan: SiteRemoteDeployPlan): List<String> {
        val relativeParents = plan.entries
            .mapNotNull { entry -> entry.path.substringBeforeLast('/', missingDelimiterValue = "").ifBlank { null } }
            .flatMap { parent ->
                val segments = parent.split('/')
                segments.indices.map { index -> segments.take(index + 1).joinToString("/") }
            }
            .distinct()
            .sortedWith(compareBy<String> { it.count { ch -> ch == '/' } }.thenBy { it })
        return listOf(plan.publish.stagingRoot) + relativeParents.map { remoteFilePath(plan.publish.stagingRoot, it) }
    }

    private fun remoteFilePath(root: String, relativePath: String): String = "$root/$relativePath".also {
        SiteRemoteTransportPolicy.validateRemoteOperationPath(it)
    }

    private fun SiteRemoteTransportOperation.remotePaths(): List<String> = when (this) {
        is SiteRemoteTransportOperation.AssertPathState -> listOf(path)
        is SiteRemoteTransportOperation.CreateDirectory -> listOf(path)
        is SiteRemoteTransportOperation.UploadFile -> listOf(remotePath)
        is SiteRemoteTransportOperation.VerifyFileSha256 -> listOf(remotePath)
        is SiteRemoteTransportOperation.ApplyFileMetadata -> listOf(remotePath)
        is SiteRemoteTransportOperation.ApplyDirectoryMetadata -> listOf(remotePath)
        is SiteRemoteTransportOperation.VerifyTree -> listOf(rootPath)
        is SiteRemoteTransportOperation.AtomicRename -> listOf(fromPath, toPath)
        is SiteRemoteTransportOperation.RemoveTransactionTree -> listOf(path)
    }
}
