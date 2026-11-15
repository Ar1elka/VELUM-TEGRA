package com.velumtegra.xuimobile.core.site

enum class SiteRemoteTransportCapability {
    CREATE_DIRECTORY,
    UPLOAD_FILE,
    STAT_PATH,
    VERIFY_SHA256,
    APPLY_OWNER_GROUP,
    APPLY_MODE,
    ATOMIC_RENAME,
    ROLLBACK_RENAME,
    REMOVE_TRANSACTION_TREE,
}

data class SiteRemoteTransportCapabilities(
    val implementationId: String,
    val capabilities: List<SiteRemoteTransportCapability>,
    val maxFiles: Int,
    val maxTotalBytes: Long,
    val maxSingleFileBytes: Int,
    val maxRemotePathLength: Int,
)

sealed interface SiteRemoteTransportOperation {
    data class AssertPathState(
        val path: String,
        val expectedType: SiteRemoteObservedPathType,
    ) : SiteRemoteTransportOperation

    data class CreateDirectory(
        val path: String,
        val owner: String,
        val group: String,
        val mode: String,
    ) : SiteRemoteTransportOperation

    data class UploadFile(
        val relativePath: String,
        val remotePath: String,
        val mediaType: String,
        val byteSize: Int,
        val sha256: String,
    ) : SiteRemoteTransportOperation

    data class VerifyFileSha256(
        val remotePath: String,
        val expectedSha256: String,
    ) : SiteRemoteTransportOperation

    data class ApplyFileMetadata(
        val remotePath: String,
        val owner: String,
        val group: String,
        val mode: String,
    ) : SiteRemoteTransportOperation

    data class ApplyDirectoryMetadata(
        val remotePath: String,
        val owner: String,
        val group: String,
        val mode: String,
    ) : SiteRemoteTransportOperation

    data class VerifyTree(
        val rootPath: String,
        val expectedTreeSha256: String,
        val fileCount: Int,
        val totalBytes: Long,
    ) : SiteRemoteTransportOperation

    data class AtomicRename(
        val fromPath: String,
        val toPath: String,
        val purpose: SiteRemoteTransportRenamePurpose,
    ) : SiteRemoteTransportOperation

    data class RemoveTransactionTree(
        val path: String,
        val transactionOwnedOnly: Boolean = true,
    ) : SiteRemoteTransportOperation
}

enum class SiteRemoteTransportRenamePurpose {
    TARGET_TO_BACKUP,
    STAGING_TO_TARGET,
    BACKUP_TO_TARGET_ROLLBACK,
}

data class SiteRemoteTransportAuthorization(
    val contractVersion: Int,
    val implementationId: String,
    val capabilityProfileSha256: String,
    val deploymentPlanSha256: String,
    val preflightSha256: String,
    val remoteHostIdentity: String,
    val sourceTreeSha256: String,
    val fileCount: Int,
    val totalBytes: Long,
    val requiredCapabilities: List<SiteRemoteTransportCapability>,
    val forwardOperations: List<SiteRemoteTransportOperation>,
    val rollbackOperations: List<SiteRemoteTransportOperation>,
    val authorizationSha256: String,
)

fun interface SiteRemoteTransportSource {
    fun read(relativePath: String): ByteArray
}

enum class SiteRemoteTransportOutcome {
    COMMITTED,
    ROLLED_BACK,
}

data class SiteRemoteTransportResult(
    val authorizationSha256: String,
    val outcome: SiteRemoteTransportOutcome,
    val uploadedFileCount: Int,
    val uploadedBytes: Long,
    val publishedTreeSha256: String?,
    val rollbackPerformed: Boolean,
)

interface SiteRemoteTransportPort {
    val capabilities: SiteRemoteTransportCapabilities

    fun execute(
        authorization: SiteRemoteTransportAuthorization,
        source: SiteRemoteTransportSource,
    ): SiteRemoteTransportResult
}
