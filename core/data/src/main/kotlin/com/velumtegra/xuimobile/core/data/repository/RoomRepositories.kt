package com.velumtegra.xuimobile.core.data.repository

import androidx.room3.withWriteTransaction
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.mapping.PersistenceMappingResult
import com.velumtegra.xuimobile.core.data.mapping.toDomain
import com.velumtegra.xuimobile.core.data.mapping.toEntity
import com.velumtegra.xuimobile.core.domain.CredentialReferenceWriter
import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId

class RoomServerRepository(
    private val database: VelumDatabase,
) : ServerRepository {
    private val dao get() = database.serverDao()

    override suspend fun get(serverId: ServerId): RepositoryResult<VersionedRecord<Server>> = repositoryDbCall {
        val entity = dao.get(serverId.value) ?: return@repositoryDbCall RepositoryResult.NotFound
        entity.toDomain().asRepositoryResult()
    }

    override suspend fun list(): RepositoryResult<List<VersionedRecord<Server>>> = repositoryDbCall {
        mapList(dao.list()) { it.toDomain() }
    }

    override suspend fun create(server: Server): RepositoryResult<RecordRevision> = repositoryDbCall {
        val revision = RecordRevision(0)
        val inserted = dao.insert(server.toEntity(revision))
        if (inserted == -1L) RepositoryResult.ConstraintConflict("ServerId already exists")
        else RepositoryResult.Success(revision)
    }

    override suspend fun update(
        server: Server,
        expectedRevision: RecordRevision,
    ): RepositoryResult<RecordRevision> = repositoryDbCall {
        database.withWriteTransaction {
            val current = dao.get(server.id.value) ?: return@withWriteTransaction RepositoryResult.NotFound
            if (current.revision != expectedRevision.value) {
                return@withWriteTransaction RepositoryResult.StaleRevision(
                    expectedRevision,
                    RecordRevision(current.revision),
                )
            }
            if (current.createdAtEpochSecond != server.createdAt.epochSecond || current.createdAtNano != server.createdAt.nano) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict(
                    "Server.createdAt is immutable under one ServerId",
                )
            }
            val next = when (val result = expectedRevision.nextRevision()) {
                is RevisionAdvance.Success -> result.value
                RevisionAdvance.Exhausted -> return@withWriteTransaction RepositoryResult.StorageFailure(
                    "Server revision exhausted",
                )
            }
            val changed = dao.updateCas(
                serverId = server.id.value,
                displayName = server.displayName,
                expectedRevision = expectedRevision.value,
                nextRevision = next.value,
            )
            if (changed != 1) RepositoryResult.StorageFailure("Server CAS update lost its locked row")
            else RepositoryResult.Success(next)
        }
    }

    override suspend fun delete(
        serverId: ServerId,
        expectedRevision: RecordRevision,
    ): RepositoryResult<Unit> = repositoryDbCall {
        database.withWriteTransaction {
            val current = dao.get(serverId.value) ?: return@withWriteTransaction RepositoryResult.NotFound
            if (current.revision != expectedRevision.value) {
                return@withWriteTransaction RepositoryResult.StaleRevision(
                    expectedRevision,
                    RecordRevision(current.revision),
                )
            }
            val changed = dao.deleteCas(serverId.value, expectedRevision.value)
            if (changed != 1) RepositoryResult.StorageFailure("Server delete lost its locked row")
            else RepositoryResult.Success(Unit)
        }
    }

    /**
     * Removes the server and ALL its local records (SSH profiles, X-UI installations, management links,
     * panel sign-ins bound to it, operation history) in one transaction. Refused while any operation of the
     * server is unfinished. Secrets are not touched here: the reference-proven GC removes the orphans.
     * Returns the removed panel sign-in ids so callers can drop their per-profile caches.
     */
    suspend fun deleteWithAllLocalRecords(
        serverId: ServerId,
        expectedRevision: RecordRevision,
    ): RepositoryResult<List<String>> = repositoryDbCall {
        database.withWriteTransaction<RepositoryResult<List<String>>> {
            val current = dao.get(serverId.value) ?: return@withWriteTransaction RepositoryResult.NotFound
            if (current.revision != expectedRevision.value) {
                return@withWriteTransaction RepositoryResult.StaleRevision(expectedRevision, RecordRevision(current.revision))
            }
            if (database.serverAccessDao().unfinishedServerOperations(serverId.value) != 0L) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict("Server has unfinished operations")
            }
            val purge = database.serverPurgeDao()
            val panels = purge.webPanelIds(serverId.value)
            purge.deleteWebPanels(serverId.value)
            purge.deleteManagementAccesses(serverId.value)
            purge.deleteJournal(serverId.value)
            purge.deleteOperations(serverId.value)
            purge.deleteInstallations(serverId.value)
            purge.deleteServerAccesses(serverId.value)
            if (dao.deleteCas(serverId.value, expectedRevision.value) != 1) {
                throw IllegalStateException("Server delete lost its locked row")
            }
            RepositoryResult.Success(panels)
        }
    }
}

class RoomServerAccessRepository(
    private val database: VelumDatabase,
) : ServerAccessRepository {
    private val dao get() = database.serverAccessDao()

    override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> = repositoryDbCall {
        val entity = dao.get(serverAccessId.value) ?: return@repositoryDbCall RepositoryResult.NotFound
        entity.toDomain().asRepositoryResult()
    }

    override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> = repositoryDbCall {
        mapList(dao.listForServer(serverId.value)) { it.toDomain() }
    }


    /** The original endpoint and its operation history keep their immutable identity. */
    suspend fun publishVerifiedSshPort(source: ServerAccess, candidate: ServerAccess): RepositoryResult<ServerAccess> =
        repositoryDbCall<ServerAccess> {
            if (source.id == candidate.id || source.endpoint.port != 22 || candidate.endpoint.port == 22 ||
                candidate.copy(id = source.id, endpoint = source.endpoint) != source
            ) return@repositoryDbCall RepositoryResult.ConstraintConflict("Invalid SSH migration target")
            database.withWriteTransaction<RepositoryResult<ServerAccess>> {
                val old = source.toEntity()
                if (dao.get(old.serverAccessId) != old) {
                    return@withWriteTransaction RepositoryResult.ConstraintConflict("Source SSH profile changed")
                }
                if (dao.unfinishedServerOperations(old.serverId) != 0L) {
                    return@withWriteTransaction RepositoryResult.ConstraintConflict("Server has unfinished operations")
                }
                val proposed = candidate.toEntity()
                val sameEndpoint = dao.listForServer(old.serverId).filter {
                    it.copy(serverAccessId = proposed.serverAccessId) == proposed
                }
                if (sameEndpoint.size > 1) {
                    return@withWriteTransaction RepositoryResult.ConstraintConflict("Ambiguous replacement SSH profile")
                }
                val replacement = sameEndpoint.singleOrNull() ?: proposed.also {
                    check(dao.insert(it) != -1L) { "Replacement SSH profile ID already exists" }
                }
                val links = database.managementAccessDao()
                for (link in links.listForServerAccess(old.serverAccessId)) {
                    links.insert(link.copy(serverAccessId = replacement.serverAccessId))
                    check(links.delete(link.installationId, old.serverAccessId) == 1)
                }
                val panels = dao.webPanelReferenceCount(old.serverAccessId)
                check(database.webPanelAccessDao().moveSshRoute(
                    old.serverAccessId, replacement.serverAccessId, old.serverId,
                ).toLong() == panels) { "A saved panel could not be migrated atomically" }
                RepositoryResult.Success(candidate.copy(id = ServerAccessId(replacement.serverAccessId)))
            }
        }

    suspend fun hasSshPortLinks(serverId: ServerId, port: Int): RepositoryResult<Boolean> = repositoryDbCall {
        database.withWriteTransaction {
            val old = dao.listForServer(serverId.value).filter { it.port == port }
            RepositoryResult.Success(old.any {
                dao.managementReferenceCount(it.serverAccessId) > 0 ||
                    dao.webPanelReferenceCount(it.serverAccessId) > 0
            })
        }
    }

    override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> = repositoryDbCall {
        database.withWriteTransaction {
            val target = dao.get(serverAccessId.value) ?: return@withWriteTransaction RepositoryResult.NotFound
            // A profile superseded by an SSH port migration keeps pinning finished operations forever (FK RESTRICT),
            // so it could never be removed. Hand that finished history to its successor: the same server, user,
            // credential and host key, differing only by port. Unfinished operations still block deletion.
            if (dao.operationReferenceCount(target.serverAccessId) > 0 &&
                dao.unfinishedOperationReferenceCount(target.serverAccessId) == 0L
            ) {
                val successors = dao.listForServer(target.serverId).filter {
                    it.serverAccessId != target.serverAccessId && it.port != target.port &&
                        it.copy(serverAccessId = target.serverAccessId, port = target.port) == target
                }
                successors.singleOrNull()?.let { successor ->
                    dao.moveFinishedOperations(target.serverAccessId, successor.serverAccessId, target.serverId)
                }
            }
            val blockers = buildList {
                if (dao.managementReferenceCount(serverAccessId.value) > 0) add("ManagementAccess")
                if (dao.webPanelReferenceCount(serverAccessId.value) > 0) add("WebPanelAccess")
                if (dao.operationReferenceCount(serverAccessId.value) > 0) add("OperationSnapshot")
            }
            if (blockers.isNotEmpty()) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict(
                    "ServerAccess is still referenced by ${blockers.joinToString()}",
                )
            }
            val changed = dao.delete(serverAccessId.value)
            if (changed != 1) RepositoryResult.StorageFailure("ServerAccess delete lost its locked row")
            else RepositoryResult.Success(Unit)
        }
    }
}

class RoomCredentialReferenceWriter(
    private val database: VelumDatabase,
) : CredentialReferenceWriter {
    override suspend fun createServerAccess(serverAccess: ServerAccess): RepositoryResult<Unit> = repositoryDbCall {
        database.withWriteTransaction {
            if (database.serverDao().get(serverAccess.serverId.value) == null) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict("Owning Server does not exist")
            }
            val inserted = database.serverAccessDao().insert(serverAccess.toEntity())
            if (inserted == -1L) RepositoryResult.ConstraintConflict("ServerAccessId already exists")
            else RepositoryResult.Success(Unit)
        }
    }

    override suspend fun createWebPanelAccess(access: WebPanelAccess): RepositoryResult<RecordRevision> = repositoryDbCall {
        database.withWriteTransaction {
            val boundServerId = when (val bound = database.resolveBoundServerFor(access)) {
                is BoundServerResolution.Success -> bound.serverId
                is BoundServerResolution.MissingReference -> return@withWriteTransaction RepositoryResult.ConstraintConflict(bound.reason)
                is BoundServerResolution.CrossServer -> return@withWriteTransaction RepositoryResult.ConstraintConflict(
                    "Linked WebPanel installation (${bound.installationServerId.value}) and SSH route " +
                        "(${bound.routeServerId.value}) belong to different Servers",
                )
            }
            val revision = RecordRevision(0)
            val entity = when (val mapped = access.toEntity(revision, boundServerId)) {
                is PersistenceMappingResult.Success -> mapped.value
                is PersistenceMappingResult.Corruption -> return@withWriteTransaction RepositoryResult.ConstraintConflict(mapped.reason)
            }
            val inserted = database.webPanelAccessDao().insert(entity)
            if (inserted == -1L) RepositoryResult.ConstraintConflict("WebPanelAccessId already exists")
            else RepositoryResult.Success(revision)
        }
    }

    override suspend fun swapWebPanelCredential(
        webPanelAccessId: WebPanelAccessId,
        expectedSecretId: SecretId,
        newSecretId: SecretId,
        newUsername: String,
        expectedRevision: RecordRevision,
    ): RepositoryResult<RecordRevision> = repositoryDbCall {
        database.withWriteTransaction {
            val dao = database.webPanelAccessDao()
            val current = dao.get(webPanelAccessId.value) ?: return@withWriteTransaction RepositoryResult.NotFound
            if (current.revision != expectedRevision.value) {
                return@withWriteTransaction RepositoryResult.StaleRevision(
                    expectedRevision,
                    RecordRevision(current.revision),
                )
            }
            if (current.passwordSecretId != expectedSecretId.value) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict(
                    "WebPanel password SecretId changed before credential swap",
                )
            }
            if (newSecretId == expectedSecretId) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict(
                    "WebPanel credential replacement requires a new SecretId",
                )
            }
            if (newUsername.isBlank()) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict(
                    "WebPanel username must not be blank",
                )
            }
            val next = when (val result = expectedRevision.nextRevision()) {
                is RevisionAdvance.Success -> result.value
                RevisionAdvance.Exhausted -> return@withWriteTransaction RepositoryResult.StorageFailure(
                    "WebPanelAccess revision exhausted",
                )
            }
            val changed = dao.swapCredentialCas(
                webPanelAccessId = webPanelAccessId.value,
                expectedSecretId = expectedSecretId.value,
                newSecretId = newSecretId.value,
                newUsername = newUsername,
                expectedRevision = expectedRevision.value,
                nextRevision = next.value,
            )
            if (changed != 1) RepositoryResult.StorageFailure("WebPanel credential CAS swap lost its locked row")
            else RepositoryResult.Success(next)
        }
    }
}

class RoomXuiInstallationRepository(
    private val database: VelumDatabase,
) : XuiInstallationRepository {
    private val dao get() = database.installationDao()

    override suspend fun get(
        installationId: XuiInstallationId,
    ): RepositoryResult<VersionedRecord<XuiInstallation>> = repositoryDbCall {
        val entity = dao.get(installationId.value) ?: return@repositoryDbCall RepositoryResult.NotFound
        entity.toDomain().asRepositoryResult()
    }

    override suspend fun listForServer(
        serverId: ServerId,
    ): RepositoryResult<List<VersionedRecord<XuiInstallation>>> = repositoryDbCall {
        mapList(dao.listForServer(serverId.value)) { it.toDomain() }
    }

    override suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision> = repositoryDbCall {
        database.withWriteTransaction {
            if (database.serverDao().get(installation.serverId.value) == null) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict("Owning Server does not exist")
            }
            val revision = RecordRevision(0)
            val inserted = dao.insert(installation.toEntity(revision))
            if (inserted == -1L) RepositoryResult.ConstraintConflict("Installation identity conflicts with durable state")
            else RepositoryResult.Success(revision)
        }
    }

    override suspend fun update(
        installation: XuiInstallation,
        expectedRevision: RecordRevision,
    ): RepositoryResult<RecordRevision> = repositoryDbCall {
        database.withWriteTransaction {
            val current = dao.get(installation.id.value) ?: return@withWriteTransaction RepositoryResult.NotFound
            if (current.revision != expectedRevision.value) {
                return@withWriteTransaction RepositoryResult.StaleRevision(
                    expectedRevision,
                    RecordRevision(current.revision),
                )
            }
            if (current.serverId != installation.serverId.value) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict(
                    "XuiInstallation.serverId is immutable under one installationId",
                )
            }
            val next = when (val result = expectedRevision.nextRevision()) {
                is RevisionAdvance.Success -> result.value
                RevisionAdvance.Exhausted -> return@withWriteTransaction RepositoryResult.StorageFailure(
                    "Installation revision exhausted",
                )
            }
            val nextEntity = installation.toEntity(next)
            val changed = dao.updateCas(
                installationId = nextEntity.installationId,
                ownership = nextEntity.ownership,
                identityServiceUnit = nextEntity.identityServiceUnit,
                identityBinaryPath = nextEntity.identityBinaryPath,
                identityRootPath = nextEntity.identityRootPath,
                identityDatabasePath = nextEntity.identityDatabasePath,
                managedInstallId = nextEntity.managedInstallId,
                baselineServiceUnit = nextEntity.baselineServiceUnit,
                baselineBinaryPath = nextEntity.baselineBinaryPath,
                baselineRootPath = nextEntity.baselineRootPath,
                baselineDatabasePath = nextEntity.baselineDatabasePath,
                panelPort = nextEntity.panelPort,
                webBasePath = nextEntity.webBasePath,
                listenAddress = nextEntity.listenAddress,
                capturedAtEpochSecond = nextEntity.capturedAtEpochSecond,
                capturedAtNano = nextEntity.capturedAtNano,
                expectedRevision = expectedRevision.value,
                nextRevision = next.value,
            )
            if (changed != 1) RepositoryResult.StorageFailure("Installation CAS update lost its locked row")
            else RepositoryResult.Success(next)
        }
    }

    override suspend fun delete(
        installationId: XuiInstallationId,
        expectedRevision: RecordRevision,
    ): RepositoryResult<Unit> = repositoryDbCall {
        database.withWriteTransaction {
            val current = dao.get(installationId.value) ?: return@withWriteTransaction RepositoryResult.NotFound
            if (current.revision != expectedRevision.value) {
                return@withWriteTransaction RepositoryResult.StaleRevision(
                    expectedRevision,
                    RecordRevision(current.revision),
                )
            }
            val blockers = buildList {
                if (dao.managementReferenceCount(installationId.value) > 0) add("ManagementAccess")
                if (dao.webPanelReferenceCount(installationId.value) > 0) add("WebPanelAccess")
                if (dao.operationReferenceCount(installationId.value) > 0) add("OperationSnapshot")
            }
            if (blockers.isNotEmpty()) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict(
                    "Installation is still referenced by ${blockers.joinToString()}",
                )
            }
            val changed = dao.deleteCas(installationId.value, expectedRevision.value)
            if (changed != 1) RepositoryResult.StorageFailure("Installation delete lost its locked row")
            else RepositoryResult.Success(Unit)
        }
    }
}

class RoomManagementAccessRepository(
    private val database: VelumDatabase,
) : ManagementAccessRepository {
    private val dao get() = database.managementAccessDao()

    override suspend fun get(
        installationId: XuiInstallationId,
        serverAccessId: ServerAccessId,
    ): RepositoryResult<ManagementAccess> = repositoryDbCall {
        val entity = dao.get(installationId.value, serverAccessId.value)
            ?: return@repositoryDbCall RepositoryResult.NotFound
        entity.toDomain().asRepositoryResult()
    }

    override suspend fun listForInstallation(
        installationId: XuiInstallationId,
    ): RepositoryResult<List<ManagementAccess>> = repositoryDbCall {
        mapList(dao.listForInstallation(installationId.value)) { it.toDomain() }
    }

    override suspend fun listForServerAccess(
        serverAccessId: ServerAccessId,
    ): RepositoryResult<List<ManagementAccess>> = repositoryDbCall {
        mapList(dao.listForServerAccess(serverAccessId.value)) { it.toDomain() }
    }

    override suspend fun create(access: ManagementAccess): RepositoryResult<Unit> = repositoryDbCall {
        database.withWriteTransaction {
            val installationServer = database.installationDao().serverIdFor(access.installationId.value)
                ?: return@withWriteTransaction RepositoryResult.ConstraintConflict("Installation does not exist")
            val accessServer = database.serverAccessDao().serverIdFor(access.serverAccessId.value)
                ?: return@withWriteTransaction RepositoryResult.ConstraintConflict("ServerAccess does not exist")
            if (installationServer != accessServer) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict(
                    "ManagementAccess cannot link installation and access from different Servers",
                )
            }
            val inserted = dao.insert(access.toEntity(ServerId(installationServer)))
            if (inserted == -1L) RepositoryResult.ConstraintConflict("ManagementAccess already exists")
            else RepositoryResult.Success(Unit)
        }
    }

    override suspend fun delete(
        installationId: XuiInstallationId,
        serverAccessId: ServerAccessId,
    ): RepositoryResult<Unit> = repositoryDbCall {
        database.withWriteTransaction {
            if (dao.get(installationId.value, serverAccessId.value) == null) {
                return@withWriteTransaction RepositoryResult.NotFound
            }
            val changed = dao.delete(installationId.value, serverAccessId.value)
            if (changed != 1) RepositoryResult.StorageFailure("ManagementAccess delete lost its locked row")
            else RepositoryResult.Success(Unit)
        }
    }
}

class RoomWebPanelAccessRepository(
    private val database: VelumDatabase,
) : WebPanelAccessRepository {
    private val dao get() = database.webPanelAccessDao()

    override suspend fun get(
        webPanelAccessId: WebPanelAccessId,
    ): RepositoryResult<VersionedRecord<WebPanelAccess>> = repositoryDbCall {
        val entity = dao.get(webPanelAccessId.value) ?: return@repositoryDbCall RepositoryResult.NotFound
        entity.toDomain().asRepositoryResult()
    }

    override suspend fun list(): RepositoryResult<List<VersionedRecord<WebPanelAccess>>> = repositoryDbCall {
        mapList(dao.list()) { it.toDomain() }
    }


    override suspend fun updateMetadata(
        access: WebPanelAccess,
        expectedRevision: RecordRevision,
    ): RepositoryResult<RecordRevision> = repositoryDbCall {
        database.withWriteTransaction {
            val current = dao.get(access.id.value) ?: return@withWriteTransaction RepositoryResult.NotFound
            if (current.revision != expectedRevision.value) {
                return@withWriteTransaction RepositoryResult.StaleRevision(
                    expectedRevision,
                    RecordRevision(current.revision),
                )
            }
            if (current.passwordSecretId != access.passwordSecretId.value) {
                return@withWriteTransaction RepositoryResult.ConstraintConflict(
                    "WebPanel password SecretId can only change through CredentialReferenceWriter",
                )
            }
            val boundServerId = when (val bound = database.resolveBoundServerFor(access)) {
                is BoundServerResolution.Success -> bound.serverId
                is BoundServerResolution.MissingReference -> return@withWriteTransaction RepositoryResult.ConstraintConflict(bound.reason)
                is BoundServerResolution.CrossServer -> return@withWriteTransaction RepositoryResult.ConstraintConflict(
                    "Linked WebPanel installation (${bound.installationServerId.value}) and SSH route " +
                        "(${bound.routeServerId.value}) belong to different Servers",
                )
            }
            val next = when (val result = expectedRevision.nextRevision()) {
                is RevisionAdvance.Success -> result.value
                RevisionAdvance.Exhausted -> return@withWriteTransaction RepositoryResult.StorageFailure(
                    "WebPanelAccess revision exhausted",
                )
            }
            val entity = when (val mapped = access.toEntity(next, boundServerId)) {
                is PersistenceMappingResult.Success -> mapped.value
                is PersistenceMappingResult.Corruption -> return@withWriteTransaction RepositoryResult.ConstraintConflict(mapped.reason)
            }
            val changed = dao.updateCas(
                webPanelAccessId = entity.webPanelAccessId,
                installationLinkKind = entity.installationLinkKind,
                installationId = entity.installationId,
                boundServerId = entity.boundServerId,
                username = entity.username,
                passwordSecretId = entity.passwordSecretId,
                routeKind = entity.routeKind,
                routeOriginHost = entity.routeOriginHost,
                routeServerAccessId = entity.routeServerAccessId,
                expectedRevision = expectedRevision.value,
                nextRevision = next.value,
            )
            if (changed != 1) RepositoryResult.StorageFailure("WebPanelAccess CAS update lost its locked row")
            else RepositoryResult.Success(next)
        }
    }

    override suspend fun delete(
        webPanelAccessId: WebPanelAccessId,
        expectedRevision: RecordRevision,
    ): RepositoryResult<Unit> = repositoryDbCall {
        database.withWriteTransaction {
            val current = dao.get(webPanelAccessId.value) ?: return@withWriteTransaction RepositoryResult.NotFound
            if (current.revision != expectedRevision.value) {
                return@withWriteTransaction RepositoryResult.StaleRevision(
                    expectedRevision,
                    RecordRevision(current.revision),
                )
            }
            val changed = dao.deleteCas(webPanelAccessId.value, expectedRevision.value)
            if (changed != 1) RepositoryResult.StorageFailure("WebPanelAccess delete lost its locked row")
            else RepositoryResult.Success(Unit)
        }
    }

}

private suspend fun VelumDatabase.resolveBoundServerFor(access: WebPanelAccess): BoundServerResolution {
    val linkedId = (access.installationLink as? WebPanelInstallationLink.Linked)?.installationId
    val routeAccessId = (access.route as? WebPanelRoute.SshTunnel)?.serverAccessId
    val installationServer = linkedId?.let { installationDao().serverIdFor(it.value)?.let(::ServerId) }
    val routeServer = routeAccessId?.let { serverAccessDao().serverIdFor(it.value)?.let(::ServerId) }
    return resolveBoundServer(
        installationRequired = linkedId != null,
        installationServerId = installationServer,
        routeAccessRequired = routeAccessId != null,
        routeServerId = routeServer,
    )
}

private inline fun <E, T> mapList(
    entities: List<E>,
    mapper: (E) -> PersistenceMappingResult<T>,
): RepositoryResult<List<T>> {
    val values = ArrayList<T>(entities.size)
    for (entity in entities) {
        when (val mapped = mapper(entity)) {
            is PersistenceMappingResult.Success -> values += mapped.value
            is PersistenceMappingResult.Corruption -> return RepositoryResult.Corruption(mapped.reason)
        }
    }
    return RepositoryResult.Success(values)
}

