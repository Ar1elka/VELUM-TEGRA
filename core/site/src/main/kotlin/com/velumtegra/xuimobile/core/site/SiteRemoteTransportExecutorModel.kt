package com.velumtegra.xuimobile.core.site

data class SiteRemoteTransportTreeEntrySpec(
    val relativePath: String,
    val mediaType: String,
)

data class SiteRemoteTransportTreeObservation(
    val rootPath: String,
    val treeSha256: String,
    val fileCount: Int,
    val totalBytes: Long,
)

interface SiteRemoteTransportPrimitivePort {
    val capabilities: SiteRemoteTransportCapabilities

    fun statPath(path: String): SiteRemoteObservedPathType

    fun createDirectory(
        path: String,
        owner: String,
        group: String,
        mode: String,
    )

    fun uploadFile(remotePath: String, payload: ByteArray)

    fun fileSha256(remotePath: String): String

    fun applyMetadata(
        path: String,
        owner: String,
        group: String,
        mode: String,
    )

    fun inspectTree(
        rootPath: String,
        entries: List<SiteRemoteTransportTreeEntrySpec>,
    ): SiteRemoteTransportTreeObservation

    fun atomicRename(fromPath: String, toPath: String)

    /** Must only remove transaction-owned staging/published trees and be idempotent for ABSENT paths. */
    fun removeTransactionTree(path: String)
}

class SiteRemoteTransportRollbackException(
    message: String,
    cause: Throwable,
    val rollbackErrors: List<String>,
) : IllegalStateException(message, cause)
