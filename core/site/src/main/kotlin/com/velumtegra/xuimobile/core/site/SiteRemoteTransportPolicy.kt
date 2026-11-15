package com.velumtegra.xuimobile.core.site

object SiteRemoteTransportPolicy {
    const val CONTRACT_VERSION: Int = 2
    const val MAX_IMPLEMENTATION_ID_LENGTH: Int = 64
    const val MIN_REMOTE_PATH_LIMIT: Int = 256
    const val MAX_REMOTE_PATH_LIMIT: Int = 4096

    private val implementationId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun validateCapabilities(profile: SiteRemoteTransportCapabilities) {
        require(profile.implementationId.length <= MAX_IMPLEMENTATION_ID_LENGTH && implementationId.matches(profile.implementationId)) {
            "Remote transport implementation id is not canonical/safe"
        }
        require(profile.capabilities.isNotEmpty()) { "Remote transport must expose at least one capability" }
        require(profile.capabilities == profile.capabilities.distinct().sortedBy { it.name }) {
            "Remote transport capabilities must be unique and sorted"
        }
        require(profile.maxFiles in 1..SiteBuildPolicy.MAX_DOCUMENTS) { "Remote transport maxFiles is outside supported bounds" }
        require(profile.maxTotalBytes in 1L..SiteBuildPolicy.MAX_TOTAL_BYTES) { "Remote transport maxTotalBytes is outside supported bounds" }
        require(profile.maxSingleFileBytes in 1..SiteBuildPolicy.MAX_DOCUMENT_BYTES) {
            "Remote transport maxSingleFileBytes is outside supported bounds"
        }
        require(profile.maxRemotePathLength in MIN_REMOTE_PATH_LIMIT..MAX_REMOTE_PATH_LIMIT) {
            "Remote transport remote-path limit is outside supported bounds"
        }
    }

    fun validatePreflightEvidence(plan: SiteRemoteDeployPlan, report: SiteRemotePreflightReport) {
        SiteRemoteDeployPolicy.validatePlan(plan)
        SiteRemotePreflightPolicy.validateReport(report)
        require(report.status == SiteRemotePreflightStatus.READY) { "Remote transport requires READY preflight evidence" }
        require(report.deploymentPlanSha256 == plan.deploymentPlanSha256) { "Preflight evidence is bound to a different deployment plan" }
        require(report.requiredAvailableBytes == SiteRemotePreflightPolicy.requiredAvailableBytes(plan)) {
            "Preflight required capacity does not match deployment plan"
        }
        val expectedCodes = buildList {
            add(SiteRemotePreflightCheckCode.SERVER_HOST_IDENTITY)
            add(SiteRemotePreflightCheckCode.SERVER_KEY_FINGERPRINT)
            add(SiteRemotePreflightCheckCode.TARGET_STATE)
            add(SiteRemotePreflightCheckCode.STAGING_STATE)
            add(SiteRemotePreflightCheckCode.BACKUP_STATE)
            add(SiteRemotePreflightCheckCode.AVAILABLE_CAPACITY)
            add(SiteRemotePreflightCheckCode.OWNER_ACCOUNT)
            add(SiteRemotePreflightCheckCode.GROUP_ACCOUNT)
            add(SiteRemotePreflightCheckCode.OWNERSHIP_APPLICABLE)
            add(SiteRemotePreflightCheckCode.MODE_APPLICABLE)
            if (plan.certificate.mode == SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN) {
                add(SiteRemotePreflightCheckCode.CERTIFICATE_PRESENT)
                add(SiteRemotePreflightCheckCode.CERTIFICATE_SERVER_IDENTITY)
                add(SiteRemotePreflightCheckCode.CERTIFICATE_DOMAIN)
                add(SiteRemotePreflightCheckCode.CERTIFICATE_USABLE_NOW)
                add(SiteRemotePreflightCheckCode.CERTIFICATE_PRIVATE_KEY_SERVER_RESIDENT)
            }
        }
        require(report.checks.map { it.code } == expectedCodes) { "Preflight evidence is incomplete or has unexpected checks" }
        require(report.checks.all { it.passed }) { "READY preflight evidence contains a failed check" }
    }

    fun validateAuthorization(authorization: SiteRemoteTransportAuthorization) {
        require(authorization.contractVersion == CONTRACT_VERSION) { "Unsupported remote transport contract version" }
        require(implementationId.matches(authorization.implementationId)) { "Remote transport implementation id is invalid" }
        require(sha256.matches(authorization.capabilityProfileSha256)) { "Capability profile SHA-256 is invalid" }
        require(sha256.matches(authorization.deploymentPlanSha256)) { "Deployment plan SHA-256 is invalid" }
        require(sha256.matches(authorization.preflightSha256)) { "Preflight SHA-256 is invalid" }
        require(sha256.matches(authorization.sourceTreeSha256)) { "Source tree SHA-256 is invalid" }
        require(authorization.fileCount in 1..SiteBuildPolicy.MAX_DOCUMENTS) { "Transport authorization file count is invalid" }
        require(authorization.totalBytes in 1L..SiteBuildPolicy.MAX_TOTAL_BYTES) { "Transport authorization total bytes are invalid" }
        require(authorization.requiredCapabilities == authorization.requiredCapabilities.distinct().sortedBy { it.name }) {
            "Required remote transport capabilities must be unique and sorted"
        }
        require(authorization.forwardOperations.isNotEmpty()) { "Transport authorization must contain forward operations" }
        authorization.forwardOperations.forEach(::validateOperation)
        authorization.rollbackOperations.forEach(::validateOperation)
        require(authorization.authorizationSha256 == SiteRemoteTransportDigest.authorizationSha256(authorization.copy(authorizationSha256 = ""))) {
            "Remote transport authorization SHA-256 mismatch"
        }
    }

    fun validateResult(authorization: SiteRemoteTransportAuthorization, result: SiteRemoteTransportResult) {
        validateAuthorization(authorization)
        require(result.authorizationSha256 == authorization.authorizationSha256) { "Transport result is bound to a different authorization" }
        require(result.uploadedFileCount in 0..authorization.fileCount) { "Transport result uploaded file count is invalid" }
        require(result.uploadedBytes in 0L..authorization.totalBytes) { "Transport result uploaded byte count is invalid" }
        when (result.outcome) {
            SiteRemoteTransportOutcome.COMMITTED -> {
                require(result.uploadedFileCount == authorization.fileCount) { "Committed transport must upload every file" }
                require(result.uploadedBytes == authorization.totalBytes) { "Committed transport byte count mismatch" }
                require(result.publishedTreeSha256 == authorization.sourceTreeSha256) { "Committed transport tree SHA-256 mismatch" }
                require(!result.rollbackPerformed) { "Committed transport must not report rollback" }
            }
            SiteRemoteTransportOutcome.ROLLED_BACK -> {
                require(result.publishedTreeSha256 == null) { "Rolled-back transport must not report a published tree" }
                require(result.rollbackPerformed) { "Rolled-back transport must report rollback" }
            }
        }
    }

    internal fun requiredCapabilities(plan: SiteRemoteDeployPlan): List<SiteRemoteTransportCapability> = buildSet {
        add(SiteRemoteTransportCapability.CREATE_DIRECTORY)
        add(SiteRemoteTransportCapability.UPLOAD_FILE)
        add(SiteRemoteTransportCapability.STAT_PATH)
        add(SiteRemoteTransportCapability.VERIFY_SHA256)
        add(SiteRemoteTransportCapability.APPLY_OWNER_GROUP)
        add(SiteRemoteTransportCapability.APPLY_MODE)
        add(SiteRemoteTransportCapability.ATOMIC_RENAME)
        add(SiteRemoteTransportCapability.REMOVE_TRANSACTION_TREE)
        if (plan.publish.rollbackOnFailure) add(SiteRemoteTransportCapability.ROLLBACK_RENAME)
    }.sortedBy { it.name }

    fun capabilityProfileSha256(profile: SiteRemoteTransportCapabilities): String {
        validateCapabilities(profile)
        val canonical = buildString {
            append("implementationId=").append(profile.implementationId).append('\n')
            append("maxFiles=").append(profile.maxFiles).append('\n')
            append("maxTotalBytes=").append(profile.maxTotalBytes).append('\n')
            append("maxSingleFileBytes=").append(profile.maxSingleFileBytes).append('\n')
            append("maxRemotePathLength=").append(profile.maxRemotePathLength).append('\n')
            profile.capabilities.forEach { append("capability=").append(it.name).append('\n') }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    internal fun validateRemoteOperationPath(path: String) {
        SiteRemoteDeployPolicy.prepareTargetRoot(path)
        require(path.length <= MAX_REMOTE_PATH_LIMIT) { "Remote operation path exceeds hard safety limit" }
    }

    private fun validateOperation(operation: SiteRemoteTransportOperation) {
        when (operation) {
            is SiteRemoteTransportOperation.AssertPathState -> {
                validateRemoteOperationPath(operation.path)
                require(operation.expectedType != SiteRemoteObservedPathType.SYMLINK) { "Transport path guard must never accept a symlink" }
            }
            is SiteRemoteTransportOperation.CreateDirectory -> {
                validateRemoteOperationPath(operation.path)
                require(operation.owner.isNotBlank() && operation.group.isNotBlank() && operation.mode.isNotBlank()) {
                    "Create-directory metadata must not be blank"
                }
            }
            is SiteRemoteTransportOperation.UploadFile -> {
                SiteBuildPolicy.validatePath(operation.relativePath)
                validateRemoteOperationPath(operation.remotePath)
                require(operation.mediaType.isNotBlank() && operation.mediaType.length <= 128) { "Upload media type is invalid" }
                require(operation.mediaType.none { it == '\u0000' || it == '\r' || it == '\n' }) { "Upload media type contains forbidden control characters" }
                require(operation.byteSize in 0..SiteBuildPolicy.MAX_DOCUMENT_BYTES) { "Upload file exceeds size limit" }
                require(sha256.matches(operation.sha256)) { "Upload file SHA-256 is invalid" }
            }
            is SiteRemoteTransportOperation.VerifyFileSha256 -> {
                validateRemoteOperationPath(operation.remotePath)
                require(sha256.matches(operation.expectedSha256)) { "Verify-file SHA-256 is invalid" }
            }
            is SiteRemoteTransportOperation.ApplyFileMetadata -> {
                validateRemoteOperationPath(operation.remotePath)
                require(operation.owner.isNotBlank() && operation.group.isNotBlank() && operation.mode.isNotBlank()) {
                    "File metadata must not be blank"
                }
            }
            is SiteRemoteTransportOperation.ApplyDirectoryMetadata -> {
                validateRemoteOperationPath(operation.remotePath)
                require(operation.owner.isNotBlank() && operation.group.isNotBlank() && operation.mode.isNotBlank()) {
                    "Directory metadata must not be blank"
                }
            }
            is SiteRemoteTransportOperation.VerifyTree -> {
                validateRemoteOperationPath(operation.rootPath)
                require(sha256.matches(operation.expectedTreeSha256)) { "Verify-tree SHA-256 is invalid" }
                require(operation.fileCount in 1..SiteBuildPolicy.MAX_DOCUMENTS) { "Verify-tree file count is invalid" }
                require(operation.totalBytes in 1L..SiteBuildPolicy.MAX_TOTAL_BYTES) { "Verify-tree byte count is invalid" }
            }
            is SiteRemoteTransportOperation.AtomicRename -> {
                validateRemoteOperationPath(operation.fromPath)
                validateRemoteOperationPath(operation.toPath)
                require(operation.fromPath != operation.toPath) { "Remote rename endpoints must differ" }
            }
            is SiteRemoteTransportOperation.RemoveTransactionTree -> {
                validateRemoteOperationPath(operation.path)
                require(operation.transactionOwnedOnly) { "Remote cleanup must be transaction-owned only" }
            }
        }
    }
}

internal object SiteRemoteTransportDigest {
    fun authorizationSha256(authorizationWithoutSha: SiteRemoteTransportAuthorization): String {
        val canonical = buildString {
            append("contractVersion=").append(authorizationWithoutSha.contractVersion).append('\n')
            append("implementationId=").append(authorizationWithoutSha.implementationId).append('\n')
            append("capabilityProfileSha256=").append(authorizationWithoutSha.capabilityProfileSha256).append('\n')
            append("deploymentPlanSha256=").append(authorizationWithoutSha.deploymentPlanSha256).append('\n')
            append("preflightSha256=").append(authorizationWithoutSha.preflightSha256).append('\n')
            append("remoteHostIdentity=").append(authorizationWithoutSha.remoteHostIdentity).append('\n')
            append("sourceTreeSha256=").append(authorizationWithoutSha.sourceTreeSha256).append('\n')
            append("fileCount=").append(authorizationWithoutSha.fileCount).append('\n')
            append("totalBytes=").append(authorizationWithoutSha.totalBytes).append('\n')
            authorizationWithoutSha.requiredCapabilities.forEach { append("required=").append(it.name).append('\n') }
            authorizationWithoutSha.forwardOperations.forEach { appendOperation("forward", it) }
            authorizationWithoutSha.rollbackOperations.forEach { appendOperation("rollback", it) }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun StringBuilder.appendOperation(scope: String, operation: SiteRemoteTransportOperation) {
        append(scope).append('=')
        when (operation) {
            is SiteRemoteTransportOperation.AssertPathState -> append("ASSERT_STATE\u0000${operation.path}\u0000${operation.expectedType.name}")
            is SiteRemoteTransportOperation.CreateDirectory -> append("CREATE_DIR\u0000${operation.path}\u0000${operation.owner}\u0000${operation.group}\u0000${operation.mode}")
            is SiteRemoteTransportOperation.UploadFile -> append("UPLOAD\u0000${operation.relativePath}\u0000${operation.remotePath}\u0000${operation.mediaType}\u0000${operation.byteSize}\u0000${operation.sha256}")
            is SiteRemoteTransportOperation.VerifyFileSha256 -> append("VERIFY_FILE\u0000${operation.remotePath}\u0000${operation.expectedSha256}")
            is SiteRemoteTransportOperation.ApplyFileMetadata -> append("FILE_META\u0000${operation.remotePath}\u0000${operation.owner}\u0000${operation.group}\u0000${operation.mode}")
            is SiteRemoteTransportOperation.ApplyDirectoryMetadata -> append("DIR_META\u0000${operation.remotePath}\u0000${operation.owner}\u0000${operation.group}\u0000${operation.mode}")
            is SiteRemoteTransportOperation.VerifyTree -> append("VERIFY_TREE\u0000${operation.rootPath}\u0000${operation.expectedTreeSha256}\u0000${operation.fileCount}\u0000${operation.totalBytes}")
            is SiteRemoteTransportOperation.AtomicRename -> append("RENAME\u0000${operation.fromPath}\u0000${operation.toPath}\u0000${operation.purpose.name}")
            is SiteRemoteTransportOperation.RemoveTransactionTree -> append("REMOVE_TX_TREE\u0000${operation.path}\u0000${operation.transactionOwnedOnly}")
        }
        append('\n')
    }
}
