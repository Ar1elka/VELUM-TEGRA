package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId

@JvmInline
value class RecordRevision(val value: Long) {
    init {
        require(value >= 0) { "Record revision must be non-negative" }
    }
}

data class VersionedRecord<T>(
    val value: T,
    val revision: RecordRevision,
)

sealed interface RepositoryResult<out T> {
    data class Success<T>(val value: T) : RepositoryResult<T>
    data object NotFound : RepositoryResult<Nothing>
    data class ConstraintConflict(val reason: String) : RepositoryResult<Nothing>
    data class StaleRevision(
        val expected: RecordRevision,
        val actual: RecordRevision,
    ) : RepositoryResult<Nothing>
    data class Corruption(val reason: String) : RepositoryResult<Nothing>
    data class StorageFailure(val reason: String) : RepositoryResult<Nothing>
}

interface ServerRepository {
    suspend fun get(serverId: ServerId): RepositoryResult<VersionedRecord<Server>>
    suspend fun list(): RepositoryResult<List<VersionedRecord<Server>>>
    suspend fun create(server: Server): RepositoryResult<RecordRevision>
    suspend fun update(server: Server, expectedRevision: RecordRevision): RepositoryResult<RecordRevision>
    suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision): RepositoryResult<Unit>
}

/**
 * Read/delete capability for exact ServerAccess records.
 *
 * Creation is intentionally NOT exposed here because a ServerAccess contains a SecretId reference.
 * Cross-store creation must go through CredentialReferenceWriter under CredentialMutationCoordinator.
 * Target-defining fields remain immutable under one ServerAccessId.
 */
interface ServerAccessRepository {
    suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess>
    suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>>
    suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit>
}

interface XuiInstallationRepository {
    suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>>
    suspend fun listForServer(serverId: ServerId): RepositoryResult<List<VersionedRecord<XuiInstallation>>>
    suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision>
    suspend fun update(
        installation: XuiInstallation,
        expectedRevision: RecordRevision,
    ): RepositoryResult<RecordRevision>
    suspend fun delete(
        installationId: XuiInstallationId,
        expectedRevision: RecordRevision,
    ): RepositoryResult<Unit>
}

interface ManagementAccessRepository {
    suspend fun get(
        installationId: XuiInstallationId,
        serverAccessId: ServerAccessId,
    ): RepositoryResult<ManagementAccess>

    suspend fun listForInstallation(
        installationId: XuiInstallationId,
    ): RepositoryResult<List<ManagementAccess>>

    suspend fun listForServerAccess(
        serverAccessId: ServerAccessId,
    ): RepositoryResult<List<ManagementAccess>>

    suspend fun create(access: ManagementAccess): RepositoryResult<Unit>

    suspend fun delete(
        installationId: XuiInstallationId,
        serverAccessId: ServerAccessId,
    ): RepositoryResult<Unit>
}

/**
 * Normal WebPanel metadata capability.
 *
 * create() is intentionally absent and updateMetadata() must preserve passwordSecretId.
 * Secret reference creation/replacement belongs to CredentialReferenceWriter only.
 */
interface WebPanelAccessRepository {
    suspend fun get(webPanelAccessId: WebPanelAccessId): RepositoryResult<VersionedRecord<WebPanelAccess>>
    suspend fun list(): RepositoryResult<List<VersionedRecord<WebPanelAccess>>>
    suspend fun updateMetadata(
        access: WebPanelAccess,
        expectedRevision: RecordRevision,
    ): RepositoryResult<RecordRevision>
    suspend fun delete(
        webPanelAccessId: WebPanelAccessId,
        expectedRevision: RecordRevision,
    ): RepositoryResult<Unit>
}

/**
 * Narrow persistence capability for writes that introduce/change durable SecretId references.
 * This port is intended to be owned by CredentialTransactionService and not exposed to feature/UI code.
 */
interface CredentialReferenceWriter {
    suspend fun createServerAccess(serverAccess: ServerAccess): RepositoryResult<Unit>
    suspend fun createWebPanelAccess(access: WebPanelAccess): RepositoryResult<RecordRevision>

    suspend fun swapWebPanelCredential(
        webPanelAccessId: WebPanelAccessId,
        expectedSecretId: SecretId,
        newSecretId: SecretId,
        newUsername: String,
        expectedRevision: RecordRevision,
    ): RepositoryResult<RecordRevision>
}
