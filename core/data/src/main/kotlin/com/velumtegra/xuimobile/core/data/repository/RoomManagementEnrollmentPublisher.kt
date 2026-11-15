package com.velumtegra.xuimobile.core.data.repository

import android.database.SQLException
import android.database.sqlite.SQLiteDatabaseCorruptException
import androidx.room3.withWriteTransaction
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.mapping.PersistenceMappingResult
import com.velumtegra.xuimobile.core.data.mapping.toDomain
import com.velumtegra.xuimobile.core.data.mapping.toEntity
import com.velumtegra.xuimobile.core.domain.ExistingInstallationReinstallPublicationRejection
import com.velumtegra.xuimobile.core.domain.ExistingInstallationReinstallPublicationRequest
import com.velumtegra.xuimobile.core.domain.ExistingInstallationReinstallPublicationResult
import com.velumtegra.xuimobile.core.domain.InstallerManagementPublicationRequest
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublicationResult
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublisher
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentRejection
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentRequest
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallation

/**
 * Room v1 atomic publication boundary for Phase 6 Management enrollment.
 *
 * The installation and ManagementAccess relation are created/reused under one write transaction. No
 * WebPanel/SecretStore table is touched here and no remote work is reachable from this component.
 */
class RoomManagementEnrollmentPublisher(
    private val database: VelumDatabase,
) : ManagementEnrollmentPublisher {
    override suspend fun publish(
        request: ManagementEnrollmentRequest,
    ): ManagementEnrollmentPublicationResult = publishExact(
        serverId = request.proof.scope.serverId,
        serverAccessId = request.proof.scope.serverAccessId,
        expected = request.newInstallation(),
    )

    override suspend fun publishInstaller(
        request: InstallerManagementPublicationRequest,
    ): ManagementEnrollmentPublicationResult = publishExact(
        serverId = request.scope.serverId,
        serverAccessId = request.scope.serverAccessId,
        expected = request.newInstallation(),
    )

    override suspend fun republishReinstall(
        request: ExistingInstallationReinstallPublicationRequest,
    ): ExistingInstallationReinstallPublicationResult = reinstallPublicationDbCall {
        database.withWriteTransaction {
            val serverDao = database.serverDao()
            val accessDao = database.serverAccessDao()
            val installationDao = database.installationDao()
            val managementDao = database.managementAccessDao()

            if (serverDao.get(request.serverId.value) == null) {
                return@withWriteTransaction reinstallRejected(
                    ExistingInstallationReinstallPublicationRejection.SERVER_NOT_FOUND,
                )
            }
            val access = accessDao.get(request.serverAccessId.value)
                ?: return@withWriteTransaction reinstallRejected(
                    ExistingInstallationReinstallPublicationRejection.SERVER_ACCESS_NOT_FOUND,
                )
            if (access.serverId != request.serverId.value) {
                return@withWriteTransaction reinstallRejected(
                    ExistingInstallationReinstallPublicationRejection.SERVER_ACCESS_SCOPE_MISMATCH,
                )
            }

            val entity = installationDao.get(request.installationId.value)
                ?: return@withWriteTransaction reinstallRejected(
                    ExistingInstallationReinstallPublicationRejection.INSTALLATION_NOT_FOUND,
                )
            val current = when (val mapped = entity.toDomain()) {
                is PersistenceMappingResult.Success -> mapped.value
                is PersistenceMappingResult.Corruption ->
                    return@withWriteTransaction ExistingInstallationReinstallPublicationResult.Corruption
            }
            if (current.revision != request.expectedRevision) {
                return@withWriteTransaction reinstallRejected(
                    ExistingInstallationReinstallPublicationRejection.INSTALLATION_REVISION_STALE,
                )
            }
            if (current.value.serverId != request.serverId || current.value.id != request.installationId) {
                return@withWriteTransaction reinstallRejected(
                    ExistingInstallationReinstallPublicationRejection.INSTALLATION_SCOPE_MISMATCH,
                )
            }
            if (current.value.ownership != InstallationOwnership.MANAGED) {
                return@withWriteTransaction reinstallRejected(
                    ExistingInstallationReinstallPublicationRejection.INSTALLATION_NOT_MANAGED,
                )
            }
            if (current.value.identity != request.expectedIdentity ||
                current.value.identity.managedInstallId == null
            ) {
                return@withWriteTransaction reinstallRejected(
                    ExistingInstallationReinstallPublicationRejection.MANAGED_IDENTITY_MISMATCH,
                )
            }
            if (managementDao.get(request.installationId.value, request.serverAccessId.value) == null) {
                return@withWriteTransaction reinstallRejected(
                    ExistingInstallationReinstallPublicationRejection.MANAGEMENT_ACCESS_MISSING,
                )
            }

            val updated = try {
                request.updatedInstallation(current.value)
            } catch (_: IllegalArgumentException) {
                return@withWriteTransaction ExistingInstallationReinstallPublicationResult.Corruption
            }
            val nextRevision = when (val next = current.revision.nextRevision()) {
                is RevisionAdvance.Success -> next.value
                RevisionAdvance.Exhausted -> return@withWriteTransaction ExistingInstallationReinstallPublicationResult.StorageFailure
            }
            val baselineUpdated = current.value.baseline != updated.baseline
            val changed = installationDao.updateCas(
                installationId = updated.id.value,
                ownership = updated.ownership.name,
                identityServiceUnit = updated.identity.serviceUnit,
                identityBinaryPath = updated.identity.binaryPath,
                identityRootPath = updated.identity.rootPath,
                identityDatabasePath = updated.identity.databasePath,
                managedInstallId = updated.identity.managedInstallId?.value,
                baselineServiceUnit = updated.baseline.serviceUnit,
                baselineBinaryPath = updated.baseline.binaryPath,
                baselineRootPath = updated.baseline.rootPath,
                baselineDatabasePath = updated.baseline.databasePath,
                panelPort = updated.baseline.panelPort,
                webBasePath = updated.baseline.webBasePath,
                listenAddress = updated.baseline.listenAddress,
                capturedAtEpochSecond = updated.baseline.capturedAt.epochSecond,
                capturedAtNano = updated.baseline.capturedAt.nano,
                expectedRevision = current.revision.value,
                nextRevision = nextRevision.value,
            )
            if (changed != 1) {
                return@withWriteTransaction ExistingInstallationReinstallPublicationResult.StorageFailure
            }

            ExistingInstallationReinstallPublicationResult.Published(
                installation = VersionedRecord(updated, nextRevision),
                managementAccess = ManagementAccess(request.installationId, request.serverAccessId),
                baselineUpdated = baselineUpdated,
            )
        }
    }

    private suspend fun publishExact(
        serverId: ServerId,
        serverAccessId: ServerAccessId,
        expected: XuiInstallation,
    ): ManagementEnrollmentPublicationResult = managementEnrollmentDbCall {
        database.withWriteTransaction {
            val serverDao = database.serverDao()
            val accessDao = database.serverAccessDao()
            val installationDao = database.installationDao()
            val managementDao = database.managementAccessDao()

            if (expected.serverId != serverId) {
                return@withWriteTransaction rejected(ManagementEnrollmentRejection.SERVER_ACCESS_SCOPE_MISMATCH)
            }
            if (serverDao.get(serverId.value) == null) {
                return@withWriteTransaction rejected(ManagementEnrollmentRejection.SERVER_NOT_FOUND)
            }
            val access = accessDao.get(serverAccessId.value)
                ?: return@withWriteTransaction rejected(ManagementEnrollmentRejection.SERVER_ACCESS_NOT_FOUND)
            if (access.serverId != serverId.value) {
                return@withWriteTransaction rejected(ManagementEnrollmentRejection.SERVER_ACCESS_SCOPE_MISMATCH)
            }

            val sameServer = when (val mapped = mapInstallations(installationDao.listForServer(serverId.value))) {
                is InstallationListMapping.Success -> mapped.value
                InstallationListMapping.Corruption -> return@withWriteTransaction ManagementEnrollmentPublicationResult.Corruption
            }
            val physicalMatches = sameServer.filter { it.value.identity.samePhysicalIdentity(expected.identity) }

            var installationCreated = false
            val managedInstallId = expected.identity.managedInstallId
            val chosen = if (managedInstallId != null) {
                val markerEntity = installationDao.getByManagedInstallId(managedInstallId.value)
                if (markerEntity != null) {
                    val existing = when (val mapped = markerEntity.toDomain()) {
                        is PersistenceMappingResult.Success -> mapped.value
                        is PersistenceMappingResult.Corruption -> return@withWriteTransaction ManagementEnrollmentPublicationResult.Corruption
                    }
                    if (
                        existing.value.serverId != serverId ||
                        existing.value.ownership != InstallationOwnership.MANAGED ||
                        existing.value.identity != expected.identity
                    ) {
                        return@withWriteTransaction rejected(ManagementEnrollmentRejection.MANAGED_MARKER_CONFLICT)
                    }
                    if (!existing.value.baseline.sameOperationalBaseline(expected.baseline)) {
                        return@withWriteTransaction rejected(ManagementEnrollmentRejection.INSTALLATION_BASELINE_CONFLICT)
                    }
                    if (physicalMatches.any { it.value.id != existing.value.id }) {
                        return@withWriteTransaction rejected(ManagementEnrollmentRejection.DURABLE_INSTALLATION_AMBIGUOUS)
                    }
                    existing
                } else {
                    if (physicalMatches.isNotEmpty()) {
                        return@withWriteTransaction rejected(ManagementEnrollmentRejection.INSTALLATION_IDENTITY_CONFLICT)
                    }
                    if (installationDao.get(expected.id.value) != null) {
                        return@withWriteTransaction rejected(ManagementEnrollmentRejection.INSTALLATION_ID_CONFLICT)
                    }
                    insertNewInstallation(expected)
                        .also { installationCreated = true }
                }
            } else {
                when {
                    physicalMatches.size > 1 -> {
                        return@withWriteTransaction rejected(ManagementEnrollmentRejection.DURABLE_INSTALLATION_AMBIGUOUS)
                    }
                    physicalMatches.size == 1 -> {
                        val existing = physicalMatches.single()
                        if (
                            existing.value.ownership != InstallationOwnership.ADOPTED ||
                            existing.value.identity.managedInstallId != null
                        ) {
                            return@withWriteTransaction rejected(ManagementEnrollmentRejection.INSTALLATION_IDENTITY_CONFLICT)
                        }
                        existing
                    }
                    else -> {
                        if (installationDao.get(expected.id.value) != null) {
                            return@withWriteTransaction rejected(ManagementEnrollmentRejection.INSTALLATION_ID_CONFLICT)
                        }
                        insertNewInstallation(expected)
                            .also { installationCreated = true }
                    }
                }
            }

            val managementAccess = ManagementAccess(
                installationId = chosen.value.id,
                serverAccessId = serverAccessId,
            )
            val existingAccess = managementDao.get(chosen.value.id.value, serverAccessId.value)
            val managementAccessCreated = existingAccess == null
            if (managementAccessCreated) {
                val inserted = managementDao.insert(managementAccess.toEntity(ServerId(access.serverId)))
                check(inserted != -1L) {
                    "Atomic ManagementAccess insert unexpectedly conflicted after exact preflight"
                }
            }

            ManagementEnrollmentPublicationResult.Published(
                installation = chosen,
                managementAccess = managementAccess,
                installationCreated = installationCreated,
                managementAccessCreated = managementAccessCreated,
            )
        }
    }

    private suspend fun insertNewInstallation(
        installation: XuiInstallation,
    ): VersionedRecord<XuiInstallation> {
        val revision = RecordRevision(0)
        val inserted = database.installationDao().insert(installation.toEntity(revision))
        check(inserted != -1L) {
            "Atomic XuiInstallation insert unexpectedly conflicted after exact preflight"
        }
        return VersionedRecord(installation, revision)
    }
}

private sealed interface InstallationListMapping {
    data class Success(val value: List<VersionedRecord<XuiInstallation>>) : InstallationListMapping
    data object Corruption : InstallationListMapping
}

private fun mapInstallations(
    entities: List<com.velumtegra.xuimobile.core.data.db.XuiInstallationEntity>,
): InstallationListMapping {
    val result = ArrayList<VersionedRecord<XuiInstallation>>(entities.size)
    for (entity in entities) {
        when (val mapped = entity.toDomain()) {
            is PersistenceMappingResult.Success -> result += mapped.value
            is PersistenceMappingResult.Corruption -> return InstallationListMapping.Corruption
        }
    }
    return InstallationListMapping.Success(result)
}

private fun InstallationIdentity.samePhysicalIdentity(other: InstallationIdentity): Boolean =
    serviceUnit == other.serviceUnit &&
        binaryPath == other.binaryPath &&
        rootPath == other.rootPath &&
        databasePath == other.databasePath

private fun com.velumtegra.xuimobile.core.model.InstallationBaseline.sameOperationalBaseline(
    other: com.velumtegra.xuimobile.core.model.InstallationBaseline,
): Boolean =
    serviceUnit == other.serviceUnit &&
        binaryPath == other.binaryPath &&
        rootPath == other.rootPath &&
        databasePath == other.databasePath &&
        panelPort == other.panelPort &&
        webBasePath == other.webBasePath &&
        listenAddress == other.listenAddress

private fun rejected(reason: ManagementEnrollmentRejection) =
    ManagementEnrollmentPublicationResult.Rejected(reason)

private suspend fun managementEnrollmentDbCall(
    block: suspend () -> ManagementEnrollmentPublicationResult,
): ManagementEnrollmentPublicationResult = try {
    block()
} catch (_: SQLiteDatabaseCorruptException) {
    ManagementEnrollmentPublicationResult.Corruption
} catch (_: SQLException) {
    ManagementEnrollmentPublicationResult.StorageFailure
} catch (_: IllegalArgumentException) {
    ManagementEnrollmentPublicationResult.Corruption
} catch (_: IllegalStateException) {
    ManagementEnrollmentPublicationResult.StorageFailure
}

private fun reinstallRejected(reason: ExistingInstallationReinstallPublicationRejection) =
    ExistingInstallationReinstallPublicationResult.Rejected(reason)

private suspend fun reinstallPublicationDbCall(
    block: suspend () -> ExistingInstallationReinstallPublicationResult,
): ExistingInstallationReinstallPublicationResult = try {
    block()
} catch (_: SQLiteDatabaseCorruptException) {
    ExistingInstallationReinstallPublicationResult.Corruption
} catch (_: SQLException) {
    ExistingInstallationReinstallPublicationResult.StorageFailure
} catch (_: IllegalArgumentException) {
    ExistingInstallationReinstallPublicationResult.Corruption
} catch (_: IllegalStateException) {
    ExistingInstallationReinstallPublicationResult.StorageFailure
}
