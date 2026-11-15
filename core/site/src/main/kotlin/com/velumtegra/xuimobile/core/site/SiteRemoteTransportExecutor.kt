package com.velumtegra.xuimobile.core.site

class SiteRemoteTransportExecutor(
    private val primitive: SiteRemoteTransportPrimitivePort,
) : SiteRemoteTransportPort {
    override val capabilities: SiteRemoteTransportCapabilities
        get() = primitive.capabilities

    override fun execute(
        authorization: SiteRemoteTransportAuthorization,
        source: SiteRemoteTransportSource,
    ): SiteRemoteTransportResult {
        SiteRemoteTransportExecutorPolicy.validateBinding(authorization, capabilities)
        val layout = SiteRemoteTransportExecutorPolicy.layout(authorization)
        val payloads = SiteRemoteTransportExecutorPolicy.preparePayloads(authorization, source)
        val treeEntrySpecs = SiteRemoteTransportExecutorPolicy.treeEntrySpecs(authorization)

        val state = TransactionState()
        var uploadedFiles = 0
        var uploadedBytes = 0L

        try {
            authorization.forwardOperations.forEach { operation ->
                when (operation) {
                    is SiteRemoteTransportOperation.AssertPathState -> {
                        require(primitive.statPath(operation.path) == operation.expectedType) {
                            "Remote re-stat guard failed: ${operation.path}"
                        }
                    }
                    is SiteRemoteTransportOperation.CreateDirectory -> {
                        primitive.createDirectory(operation.path, operation.owner, operation.group, operation.mode)
                        if (operation.path == layout.stagingRoot) state.stagingOwned = true
                    }
                    is SiteRemoteTransportOperation.UploadFile -> {
                        val payload = requireNotNull(payloads[operation.relativePath]) {
                            "Authorized upload payload is missing: ${operation.relativePath}"
                        }
                        primitive.uploadFile(operation.remotePath, payload.copyOf())
                        uploadedFiles += 1
                        uploadedBytes += payload.size
                    }
                    is SiteRemoteTransportOperation.VerifyFileSha256 -> {
                        require(primitive.fileSha256(operation.remotePath) == operation.expectedSha256) {
                            "Remote file SHA-256 mismatch: ${operation.remotePath}"
                        }
                    }
                    is SiteRemoteTransportOperation.ApplyFileMetadata -> {
                        primitive.applyMetadata(operation.remotePath, operation.owner, operation.group, operation.mode)
                    }
                    is SiteRemoteTransportOperation.ApplyDirectoryMetadata -> {
                        primitive.applyMetadata(operation.remotePath, operation.owner, operation.group, operation.mode)
                    }
                    is SiteRemoteTransportOperation.VerifyTree -> {
                        SiteRemoteTransportExecutorPolicy.validateTree(
                            operation,
                            primitive.inspectTree(operation.rootPath, treeEntrySpecs),
                        )
                    }
                    is SiteRemoteTransportOperation.AtomicRename -> executeRename(operation, layout, state)
                    is SiteRemoteTransportOperation.RemoveTransactionTree -> error("Forward authorization must not contain cleanup operations")
                }
            }
        } catch (failure: Throwable) {
            if (!state.transactionTouched()) throw failure
            return rollbackOrThrow(
                authorization = authorization,
                layout = layout,
                state = state,
                uploadedFiles = uploadedFiles,
                uploadedBytes = uploadedBytes,
                failure = failure,
            )
        }

        return SiteRemoteTransportResult(
            authorizationSha256 = authorization.authorizationSha256,
            outcome = SiteRemoteTransportOutcome.COMMITTED,
            uploadedFileCount = uploadedFiles,
            uploadedBytes = uploadedBytes,
            publishedTreeSha256 = authorization.sourceTreeSha256,
            rollbackPerformed = false,
        ).also { SiteRemoteTransportPolicy.validateResult(authorization, it) }
    }

    private fun executeRename(
        operation: SiteRemoteTransportOperation.AtomicRename,
        layout: SiteRemoteTransportExecutionLayout,
        state: TransactionState,
    ) {
        try {
            primitive.atomicRename(operation.fromPath, operation.toPath)
            applySuccessfulRename(operation, state)
        } catch (failure: Throwable) {
            reconcileRenameAfterFailure(operation, layout, state)
            throw failure
        }
    }

    private fun applySuccessfulRename(
        operation: SiteRemoteTransportOperation.AtomicRename,
        state: TransactionState,
    ) {
        when (operation.purpose) {
            SiteRemoteTransportRenamePurpose.TARGET_TO_BACKUP -> state.backupOwnsOriginal = true
            SiteRemoteTransportRenamePurpose.STAGING_TO_TARGET -> {
                state.stagingOwned = false
                state.publishedTargetOwned = true
            }
            SiteRemoteTransportRenamePurpose.BACKUP_TO_TARGET_ROLLBACK -> state.backupOwnsOriginal = false
        }
    }

    private fun reconcileRenameAfterFailure(
        operation: SiteRemoteTransportOperation.AtomicRename,
        layout: SiteRemoteTransportExecutionLayout,
        state: TransactionState,
    ) {
        val from = runCatching { primitive.statPath(operation.fromPath) }.getOrNull()
        val to = runCatching { primitive.statPath(operation.toPath) }.getOrNull()
        when (operation.purpose) {
            SiteRemoteTransportRenamePurpose.TARGET_TO_BACKUP -> when {
                from == SiteRemoteObservedPathType.ABSENT && to == SiteRemoteObservedPathType.DIRECTORY -> {
                    state.backupOwnsOriginal = true
                }
                from == SiteRemoteObservedPathType.DIRECTORY && to == SiteRemoteObservedPathType.ABSENT -> Unit
                else -> state.renameStateAmbiguous = true
            }
            SiteRemoteTransportRenamePurpose.STAGING_TO_TARGET -> when {
                from == SiteRemoteObservedPathType.ABSENT && to == SiteRemoteObservedPathType.DIRECTORY -> {
                    state.stagingOwned = false
                    state.publishedTargetOwned = true
                }
                from == SiteRemoteObservedPathType.DIRECTORY && to == SiteRemoteObservedPathType.ABSENT -> Unit
                else -> state.renameStateAmbiguous = true
            }
            SiteRemoteTransportRenamePurpose.BACKUP_TO_TARGET_ROLLBACK -> {
                if (operation.fromPath != layout.backupRoot || operation.toPath != layout.targetRoot) {
                    state.renameStateAmbiguous = true
                }
            }
        }
    }

    private fun rollbackOrThrow(
        authorization: SiteRemoteTransportAuthorization,
        layout: SiteRemoteTransportExecutionLayout,
        state: TransactionState,
        uploadedFiles: Int,
        uploadedBytes: Long,
        failure: Throwable,
    ): SiteRemoteTransportResult {
        val rollbackErrors = mutableListOf<String>()
        var targetRemoved = !state.publishedTargetOwned

        if (state.stagingOwned) {
            runCatching { primitive.removeTransactionTree(layout.stagingRoot) }
                .onSuccess { state.stagingOwned = false }
                .onFailure { rollbackErrors += "staging-cleanup:${it.message ?: it::class.simpleName}" }
        }

        if (state.publishedTargetOwned) {
            runCatching { primitive.removeTransactionTree(layout.targetRoot) }
                .onSuccess {
                    state.publishedTargetOwned = false
                    targetRemoved = true
                }
                .onFailure {
                    targetRemoved = false
                    rollbackErrors += "published-target-cleanup:${it.message ?: it::class.simpleName}"
                }
        }

        if (state.backupOwnsOriginal && targetRemoved && !state.renameStateAmbiguous) {
            val backup = layout.backupRoot
            if (backup == null) {
                rollbackErrors += "backup-state-without-backup-root"
            } else {
                runCatching { primitive.atomicRename(backup, layout.targetRoot) }
                    .onSuccess { state.backupOwnsOriginal = false }
                    .onFailure { rollbackErrors += "backup-restore:${it.message ?: it::class.simpleName}" }
            }
        }

        if (state.renameStateAmbiguous) rollbackErrors += "ambiguous-rename-state"
        if (rollbackErrors.isNotEmpty() || state.stagingOwned || state.publishedTargetOwned || state.backupOwnsOriginal) {
            throw SiteRemoteTransportRollbackException(
                message = "Remote transport failed and rollback could not be proven complete",
                cause = failure,
                rollbackErrors = rollbackErrors.distinct(),
            )
        }

        return SiteRemoteTransportResult(
            authorizationSha256 = authorization.authorizationSha256,
            outcome = SiteRemoteTransportOutcome.ROLLED_BACK,
            uploadedFileCount = uploadedFiles,
            uploadedBytes = uploadedBytes,
            publishedTreeSha256 = null,
            rollbackPerformed = true,
        ).also { SiteRemoteTransportPolicy.validateResult(authorization, it) }
    }

    private data class TransactionState(
        var stagingOwned: Boolean = false,
        var backupOwnsOriginal: Boolean = false,
        var publishedTargetOwned: Boolean = false,
        var renameStateAmbiguous: Boolean = false,
    ) {
        fun transactionTouched(): Boolean = stagingOwned || backupOwnsOriginal || publishedTargetOwned || renameStateAmbiguous
    }
}
