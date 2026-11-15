package com.velumtegra.xuimobile.core.data.mapping

import com.velumtegra.xuimobile.core.data.db.ManagementAccessEntity
import com.velumtegra.xuimobile.core.data.db.OperationJournalEntity
import com.velumtegra.xuimobile.core.data.db.OperationSnapshotEntity
import com.velumtegra.xuimobile.core.data.db.ServerAccessEntity
import com.velumtegra.xuimobile.core.data.db.ServerEntity
import com.velumtegra.xuimobile.core.data.db.WebPanelAccessEntity
import com.velumtegra.xuimobile.core.data.db.XuiInstallationEntity
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.DateTimeException
import java.time.Instant

sealed interface PersistenceMappingResult<out T> {
    data class Success<T>(val value: T) : PersistenceMappingResult<T>
    data class Corruption(val reason: String) : PersistenceMappingResult<Nothing>
}

/** Stable persisted codes. Never replace these with enum ordinals. */
object PersistenceCodes {
    const val SSH_AUTH_PASSWORD = "PASSWORD"
    const val SSH_AUTH_PRIVATE_KEY = "PRIVATE_KEY"

    const val INSTALLATION_MANAGED = "MANAGED"
    const val INSTALLATION_ADOPTED = "ADOPTED"

    const val PANEL_LINK_STANDALONE = "STANDALONE"
    const val PANEL_LINK_LINKED = "LINKED"
    const val PANEL_ROUTE_DIRECT = "DIRECT"
    const val PANEL_ROUTE_SSH_TUNNEL = "SSH_TUNNEL"

    const val TARGET_SERVER = "SERVER"
    const val TARGET_INSTALLATION = "INSTALLATION"

    const val OP_DISCOVERY = "DISCOVERY"
    const val OP_QUICK_INSPECT = "QUICK_INSPECT"
    const val OP_DEEP_DIAGNOSTIC = "DEEP_DIAGNOSTIC"
    const val OP_SERVICE_LOG_READ = "SERVICE_LOG_READ"
    const val OP_UPDATE_PREFLIGHT = "UPDATE_PREFLIGHT"
    const val OP_DATABASE_BACKUP = "DATABASE_BACKUP"
    const val OP_INSTALLATION_BACKUP = "INSTALLATION_BACKUP"
    const val OP_INSTALLATION_RESTORE_CHECK = "INSTALLATION_RESTORE_CHECK"
    const val OP_WORKING_DATABASE_RESTORE = "WORKING_DATABASE_RESTORE"
    const val OP_RESTORED_PANEL_START = "RESTORED_PANEL_START"
    const val OP_KNOWN_FILE_RESTORE = "KNOWN_FILE_RESTORE"
    const val OP_RESTORE_COMPATIBILITY = "RESTORE_COMPATIBILITY"
    const val OP_INSTALL = "INSTALL"
    const val OP_RESTART = "RESTART"
    const val OP_RECOVERY = "RECOVERY"
    const val OP_UNINSTALL = "UNINSTALL"
    const val OP_REINSTALL = "REINSTALL"

    const val STATUS_PENDING = "PENDING"
    const val STATUS_RUNNING = "RUNNING"
    const val STATUS_WAITING = "WAITING"
    const val STATUS_RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    const val STATUS_SUCCEEDED = "SUCCEEDED"
    const val STATUS_FAILED = "FAILED"
    const val STATUS_CANCELLED = "CANCELLED"

    const val CHECKPOINT_READ_ONLY = "READ_ONLY"
    const val CHECKPOINT_MUTATION_NOT_STARTED = "MUTATION_NOT_STARTED"
    const val CHECKPOINT_MUTATION_IN_FLIGHT = "MUTATION_IN_FLIGHT"
    const val CHECKPOINT_MUTATION_VERIFIED = "MUTATION_VERIFIED"
    const val CHECKPOINT_RESTART_IN_FLIGHT = "RESTART_IN_FLIGHT"
    const val CHECKPOINT_POST_VERIFY_REQUIRED = "POST_VERIFY_REQUIRED"
    const val CHECKPOINT_COMMIT_VERIFIED = "COMMIT_VERIFIED"
    const val CHECKPOINT_TERMINAL = "TERMINAL"
}

private fun instant(epochSecond: Long, nano: Int): PersistenceMappingResult<Instant> {
    if (nano !in 0..999_999_999) {
        return PersistenceMappingResult.Corruption("Invalid nanosecond value: $nano")
    }
    return try {
        PersistenceMappingResult.Success(Instant.ofEpochSecond(epochSecond, nano.toLong()))
    } catch (error: DateTimeException) {
        PersistenceMappingResult.Corruption("Invalid persisted instant: ${error.message}")
    }
}

private inline fun <T> mapping(block: () -> T): PersistenceMappingResult<T> = try {
    PersistenceMappingResult.Success(block())
} catch (error: IllegalArgumentException) {
    PersistenceMappingResult.Corruption(error.message ?: "Domain invariant rejected persisted data")
} catch (error: IllegalStateException) {
    PersistenceMappingResult.Corruption(error.message ?: "Persisted data is internally inconsistent")
}

private fun <T> PersistenceMappingResult<T>.orThrow(): T = when (this) {
    is PersistenceMappingResult.Success -> value
    is PersistenceMappingResult.Corruption -> error(reason)
}

fun Server.toEntity(revision: RecordRevision): ServerEntity = ServerEntity(
    serverId = id.value,
    displayName = displayName,
    createdAtEpochSecond = createdAt.epochSecond,
    createdAtNano = createdAt.nano,
    revision = revision.value,
)

fun ServerEntity.toDomain(): PersistenceMappingResult<VersionedRecord<Server>> {
    if (revision < 0) return PersistenceMappingResult.Corruption("Server revision is negative")
    val createdAt = instant(createdAtEpochSecond, createdAtNano)
    if (createdAt is PersistenceMappingResult.Corruption) return createdAt
    return mapping {
        VersionedRecord(
            value = Server(
                id = ServerId(serverId),
                displayName = displayName,
                createdAt = createdAt.orThrow(),
            ),
            revision = RecordRevision(revision),
        )
    }
}

fun ServerAccess.toEntity(): ServerAccessEntity = ServerAccessEntity(
    serverAccessId = id.value,
    serverId = serverId.value,
    host = endpoint.host,
    port = endpoint.port,
    username = username,
    authKind = when (auth) {
        is SshAuthRef.Password -> PersistenceCodes.SSH_AUTH_PASSWORD
        is SshAuthRef.PrivateKey -> PersistenceCodes.SSH_AUTH_PRIVATE_KEY
    },
    secretId = auth.secretId.value,
    pinnedHostKey = pinnedHostKey.value,
)

fun ServerAccessEntity.toDomain(): PersistenceMappingResult<ServerAccess> = mapping {
    val auth = when (authKind) {
        PersistenceCodes.SSH_AUTH_PASSWORD -> SshAuthRef.Password(SecretId(secretId))
        PersistenceCodes.SSH_AUTH_PRIVATE_KEY -> SshAuthRef.PrivateKey(SecretId(secretId))
        else -> error("Unknown SSH auth kind: $authKind")
    }
    ServerAccess(
        id = ServerAccessId(serverAccessId),
        serverId = ServerId(serverId),
        endpoint = SshEndpoint(host = host, port = port),
        username = username,
        auth = auth,
        pinnedHostKey = HostKeyFingerprint(pinnedHostKey),
    )
}

fun XuiInstallation.toEntity(revision: RecordRevision): XuiInstallationEntity = XuiInstallationEntity(
    installationId = id.value,
    serverId = serverId.value,
    ownership = when (ownership) {
        InstallationOwnership.MANAGED -> PersistenceCodes.INSTALLATION_MANAGED
        InstallationOwnership.ADOPTED -> PersistenceCodes.INSTALLATION_ADOPTED
    },
    identityServiceUnit = identity.serviceUnit,
    identityBinaryPath = identity.binaryPath,
    identityRootPath = identity.rootPath,
    identityDatabasePath = identity.databasePath,
    managedInstallId = identity.managedInstallId?.value,
    baselineServiceUnit = baseline.serviceUnit,
    baselineBinaryPath = baseline.binaryPath,
    baselineRootPath = baseline.rootPath,
    baselineDatabasePath = baseline.databasePath,
    panelPort = baseline.panelPort,
    webBasePath = baseline.webBasePath,
    listenAddress = baseline.listenAddress,
    capturedAtEpochSecond = baseline.capturedAt.epochSecond,
    capturedAtNano = baseline.capturedAt.nano,
    revision = revision.value,
)

fun XuiInstallationEntity.toDomain(): PersistenceMappingResult<VersionedRecord<XuiInstallation>> {
    if (revision < 0) return PersistenceMappingResult.Corruption("Installation revision is negative")
    val capturedAt = instant(capturedAtEpochSecond, capturedAtNano)
    if (capturedAt is PersistenceMappingResult.Corruption) return capturedAt
    return mapping {
        val ownershipValue = when (ownership) {
            PersistenceCodes.INSTALLATION_MANAGED -> InstallationOwnership.MANAGED
            PersistenceCodes.INSTALLATION_ADOPTED -> InstallationOwnership.ADOPTED
            else -> error("Unknown installation ownership: $ownership")
        }
        VersionedRecord(
            value = XuiInstallation(
                id = XuiInstallationId(installationId),
                serverId = ServerId(serverId),
                ownership = ownershipValue,
                identity = InstallationIdentity(
                    serviceUnit = identityServiceUnit,
                    binaryPath = identityBinaryPath,
                    rootPath = identityRootPath,
                    databasePath = identityDatabasePath,
                    managedInstallId = managedInstallId?.let(::ManagedInstallId),
                ),
                baseline = InstallationBaseline(
                    serviceUnit = baselineServiceUnit,
                    binaryPath = baselineBinaryPath,
                    rootPath = baselineRootPath,
                    databasePath = baselineDatabasePath,
                    panelPort = panelPort,
                    webBasePath = webBasePath,
                    listenAddress = listenAddress,
                    capturedAt = capturedAt.orThrow(),
                ),
            ),
            revision = RecordRevision(revision),
        )
    }
}

fun ManagementAccess.toEntity(serverId: ServerId): ManagementAccessEntity = ManagementAccessEntity(
    installationId = installationId.value,
    serverAccessId = serverAccessId.value,
    serverId = serverId.value,
)

fun ManagementAccessEntity.toDomain(): PersistenceMappingResult<ManagementAccess> = mapping {
    ManagementAccess(
        installationId = XuiInstallationId(installationId),
        serverAccessId = ServerAccessId(serverAccessId),
    )
}

/**
 * boundServerId is resolved from exact parents by the future repository transaction.
 * It is deliberately not guessed by this mapper.
 */
fun WebPanelAccess.toEntity(
    revision: RecordRevision,
    boundServerId: ServerId?,
): PersistenceMappingResult<WebPanelAccessEntity> = mapping {
    val installationIdValue = when (val link = installationLink) {
        WebPanelInstallationLink.Standalone -> {
            if (route is WebPanelRoute.Direct && boundServerId != null) {
                error("Standalone direct WebPanel access must not invent a bound Server")
            }
            null
        }
        is WebPanelInstallationLink.Linked -> {
            requireNotNull(boundServerId) { "Linked WebPanel access requires an exact bound Server" }
            link.installationId.value
        }
    }

    val routeKind: String
    val routeOriginHost: String?
    val routeServerAccessId: String?
    when (val routeValue = route) {
        is WebPanelRoute.Direct -> {
            routeKind = PersistenceCodes.PANEL_ROUTE_DIRECT
            routeOriginHost = routeValue.originHost
            routeServerAccessId = null
        }
        is WebPanelRoute.SshTunnel -> {
            requireNotNull(boundServerId) { "SSH-tunnel WebPanel access requires an exact bound Server" }
            routeKind = PersistenceCodes.PANEL_ROUTE_SSH_TUNNEL
            routeOriginHost = null
            routeServerAccessId = routeValue.serverAccessId.value
        }
    }

    WebPanelAccessEntity(
        webPanelAccessId = id.value,
        installationLinkKind = when (installationLink) {
            WebPanelInstallationLink.Standalone -> PersistenceCodes.PANEL_LINK_STANDALONE
            is WebPanelInstallationLink.Linked -> PersistenceCodes.PANEL_LINK_LINKED
        },
        installationId = installationIdValue,
        boundServerId = boundServerId?.value,
        username = username,
        passwordSecretId = passwordSecretId.value,
        routeKind = routeKind,
        routeOriginHost = routeOriginHost,
        routeServerAccessId = routeServerAccessId,
        revision = revision.value,
    )
}

fun WebPanelAccessEntity.toDomain(): PersistenceMappingResult<VersionedRecord<WebPanelAccess>> {
    if (revision < 0) return PersistenceMappingResult.Corruption("WebPanel revision is negative")
    return mapping {
        val link = when (installationLinkKind) {
            PersistenceCodes.PANEL_LINK_STANDALONE -> {
                check(installationId == null) { "Standalone WebPanel row must not contain installationId" }
                WebPanelInstallationLink.Standalone
            }
            PersistenceCodes.PANEL_LINK_LINKED -> {
                check(boundServerId != null) { "Linked WebPanel row requires boundServerId" }
                WebPanelInstallationLink.Linked(
                    XuiInstallationId(requireNotNull(installationId) { "Linked WebPanel row requires installationId" }),
                )
            }
            else -> error("Unknown WebPanel link kind: $installationLinkKind")
        }

        val route = when (routeKind) {
            PersistenceCodes.PANEL_ROUTE_DIRECT -> {
                check(routeServerAccessId == null) { "Direct WebPanel row must not contain route ServerAccess" }
                if (link is WebPanelInstallationLink.Standalone) {
                    check(boundServerId == null) { "Standalone direct WebPanel row must not bind a Server" }
                }
                WebPanelRoute.Direct(requireNotNull(routeOriginHost) { "Direct WebPanel row requires origin host" })
            }
            PersistenceCodes.PANEL_ROUTE_SSH_TUNNEL -> {
                check(routeOriginHost == null) { "SSH-tunnel WebPanel row must not contain direct origin" }
                check(boundServerId != null) { "SSH-tunnel WebPanel row requires boundServerId" }
                WebPanelRoute.SshTunnel(
                    ServerAccessId(requireNotNull(routeServerAccessId) { "SSH-tunnel row requires ServerAccess" }),
                )
            }
            else -> error("Unknown WebPanel route kind: $routeKind")
        }

        VersionedRecord(
            value = WebPanelAccess(
                id = WebPanelAccessId(webPanelAccessId),
                installationLink = link,
                username = username,
                passwordSecretId = SecretId(passwordSecretId),
                route = route,
            ),
            revision = RecordRevision(revision),
        )
    }
}

fun OperationSnapshot.toEntity(revision: OperationRevision): OperationSnapshotEntity {
    val targetKind: String
    val installationId: String?
    when (val targetValue = target) {
        is OperationTarget.ServerTarget -> {
            targetKind = PersistenceCodes.TARGET_SERVER
            installationId = null
        }
        is OperationTarget.InstallationTarget -> {
            targetKind = PersistenceCodes.TARGET_INSTALLATION
            installationId = targetValue.installationId.value
        }
    }
    return OperationSnapshotEntity(
        operationId = operationId.value,
        operationType = type.toStorageCode(),
        targetKind = targetKind,
        serverId = target.serverId.value,
        serverAccessId = target.serverAccessId.value,
        installationId = installationId,
        status = status.toStorageCode(),
        checkpointPhaseName = checkpoint.phaseName,
        checkpointSemantics = checkpoint.semantics.toStorageCode(),
        checkpointEpochSecond = checkpoint.recordedAt.epochSecond,
        checkpointNano = checkpoint.recordedAt.nano,
        startedAtEpochSecond = startedAt.epochSecond,
        startedAtNano = startedAt.nano,
        updatedAtEpochSecond = updatedAt.epochSecond,
        updatedAtNano = updatedAt.nano,
        revision = revision.value,
    )
}

fun OperationSnapshotEntity.toDomain(): PersistenceMappingResult<VersionedOperationSnapshot> {
    if (revision < 0) return PersistenceMappingResult.Corruption("Operation revision is negative")
    val checkpointAt = instant(checkpointEpochSecond, checkpointNano)
    if (checkpointAt is PersistenceMappingResult.Corruption) return checkpointAt
    val startedAt = instant(startedAtEpochSecond, startedAtNano)
    if (startedAt is PersistenceMappingResult.Corruption) return startedAt
    val updatedAt = instant(updatedAtEpochSecond, updatedAtNano)
    if (updatedAt is PersistenceMappingResult.Corruption) return updatedAt

    return mapping {
        val typeValue = operationTypeFromStorageCode(operationType)
            ?: error("Unknown operation type: $operationType")
        val statusValue = operationStatusFromStorageCode(status)
            ?: error("Unknown operation status: $status")
        val semanticsValue = checkpointSemanticsFromStorageCode(checkpointSemantics)
            ?: error("Unknown checkpoint semantics: $checkpointSemantics")
        val targetValue = when (targetKind) {
            PersistenceCodes.TARGET_SERVER -> {
                check(installationId == null) { "Server operation target must not contain installationId" }
                OperationTarget.ServerTarget(
                    serverId = ServerId(serverId),
                    serverAccessId = ServerAccessId(serverAccessId),
                )
            }
            PersistenceCodes.TARGET_INSTALLATION -> OperationTarget.InstallationTarget(
                serverId = ServerId(serverId),
                serverAccessId = ServerAccessId(serverAccessId),
                installationId = XuiInstallationId(
                    requireNotNull(installationId) { "Installation operation target requires installationId" },
                ),
            )
            else -> error("Unknown operation target kind: $targetKind")
        }
        VersionedOperationSnapshot(
            snapshot = OperationSnapshot(
                operationId = OperationId(operationId),
                type = typeValue,
                target = targetValue,
                status = statusValue,
                checkpoint = OperationCheckpoint(
                    phaseName = checkpointPhaseName,
                    semantics = semanticsValue,
                    recordedAt = checkpointAt.orThrow(),
                ),
                startedAt = startedAt.orThrow(),
                updatedAt = updatedAt.orThrow(),
            ),
            revision = OperationRevision(revision),
        )
    }
}

fun OperationJournalEntry.toEntity(): OperationJournalEntity = OperationJournalEntity(
    operationId = operationId.value,
    revision = revision.value,
    status = status.toStorageCode(),
    checkpointPhaseName = checkpoint.phaseName,
    checkpointSemantics = checkpoint.semantics.toStorageCode(),
    checkpointEpochSecond = checkpoint.recordedAt.epochSecond,
    checkpointNano = checkpoint.recordedAt.nano,
    recordedAtEpochSecond = recordedAt.epochSecond,
    recordedAtNano = recordedAt.nano,
)

fun OperationJournalEntity.toDomain(): PersistenceMappingResult<OperationJournalEntry> {
    if (revision < 0) return PersistenceMappingResult.Corruption("Journal revision is negative")
    val checkpointAt = instant(checkpointEpochSecond, checkpointNano)
    if (checkpointAt is PersistenceMappingResult.Corruption) return checkpointAt
    val recordedAt = instant(recordedAtEpochSecond, recordedAtNano)
    if (recordedAt is PersistenceMappingResult.Corruption) return recordedAt
    return mapping {
        OperationJournalEntry(
            operationId = OperationId(operationId),
            revision = OperationRevision(revision),
            status = operationStatusFromStorageCode(status)
                ?: error("Unknown operation status: $status"),
            checkpoint = OperationCheckpoint(
                phaseName = checkpointPhaseName,
                semantics = checkpointSemanticsFromStorageCode(checkpointSemantics)
                    ?: error("Unknown checkpoint semantics: $checkpointSemantics"),
                recordedAt = checkpointAt.orThrow(),
            ),
            recordedAt = recordedAt.orThrow(),
        )
    }
}

private fun OperationType.toStorageCode(): String = when (this) {
    OperationType.DISCOVERY -> PersistenceCodes.OP_DISCOVERY
    OperationType.QUICK_INSPECT -> PersistenceCodes.OP_QUICK_INSPECT
    OperationType.DEEP_DIAGNOSTIC -> PersistenceCodes.OP_DEEP_DIAGNOSTIC
    OperationType.SERVICE_LOG_READ -> PersistenceCodes.OP_SERVICE_LOG_READ
    OperationType.UPDATE_PREFLIGHT -> PersistenceCodes.OP_UPDATE_PREFLIGHT
    OperationType.DATABASE_BACKUP -> PersistenceCodes.OP_DATABASE_BACKUP
    OperationType.INSTALLATION_BACKUP -> PersistenceCodes.OP_INSTALLATION_BACKUP
    OperationType.INSTALLATION_RESTORE_CHECK -> PersistenceCodes.OP_INSTALLATION_RESTORE_CHECK
    OperationType.WORKING_DATABASE_RESTORE -> PersistenceCodes.OP_WORKING_DATABASE_RESTORE
    OperationType.RESTORED_PANEL_START -> PersistenceCodes.OP_RESTORED_PANEL_START
    OperationType.KNOWN_FILE_RESTORE -> PersistenceCodes.OP_KNOWN_FILE_RESTORE
    OperationType.RESTORE_COMPATIBILITY -> PersistenceCodes.OP_RESTORE_COMPATIBILITY
    OperationType.INSTALL -> PersistenceCodes.OP_INSTALL
    OperationType.RESTART -> PersistenceCodes.OP_RESTART
    OperationType.RECOVERY -> PersistenceCodes.OP_RECOVERY
    OperationType.UNINSTALL -> PersistenceCodes.OP_UNINSTALL
    OperationType.REINSTALL -> PersistenceCodes.OP_REINSTALL
}

private fun operationTypeFromStorageCode(code: String): OperationType? = when (code) {
    PersistenceCodes.OP_DISCOVERY -> OperationType.DISCOVERY
    PersistenceCodes.OP_QUICK_INSPECT -> OperationType.QUICK_INSPECT
    PersistenceCodes.OP_DEEP_DIAGNOSTIC -> OperationType.DEEP_DIAGNOSTIC
    PersistenceCodes.OP_SERVICE_LOG_READ -> OperationType.SERVICE_LOG_READ
    PersistenceCodes.OP_UPDATE_PREFLIGHT -> OperationType.UPDATE_PREFLIGHT
    PersistenceCodes.OP_DATABASE_BACKUP -> OperationType.DATABASE_BACKUP
    PersistenceCodes.OP_INSTALLATION_BACKUP -> OperationType.INSTALLATION_BACKUP
    PersistenceCodes.OP_INSTALLATION_RESTORE_CHECK -> OperationType.INSTALLATION_RESTORE_CHECK
    PersistenceCodes.OP_WORKING_DATABASE_RESTORE -> OperationType.WORKING_DATABASE_RESTORE
    PersistenceCodes.OP_RESTORED_PANEL_START -> OperationType.RESTORED_PANEL_START
    PersistenceCodes.OP_KNOWN_FILE_RESTORE -> OperationType.KNOWN_FILE_RESTORE
    PersistenceCodes.OP_RESTORE_COMPATIBILITY -> OperationType.RESTORE_COMPATIBILITY
    PersistenceCodes.OP_INSTALL -> OperationType.INSTALL
    PersistenceCodes.OP_RESTART -> OperationType.RESTART
    PersistenceCodes.OP_RECOVERY -> OperationType.RECOVERY
    PersistenceCodes.OP_UNINSTALL -> OperationType.UNINSTALL
    PersistenceCodes.OP_REINSTALL -> OperationType.REINSTALL
    else -> null
}

private fun OperationStatus.toStorageCode(): String = when (this) {
    OperationStatus.PENDING -> PersistenceCodes.STATUS_PENDING
    OperationStatus.RUNNING -> PersistenceCodes.STATUS_RUNNING
    OperationStatus.WAITING -> PersistenceCodes.STATUS_WAITING
    OperationStatus.RECONCILIATION_REQUIRED -> PersistenceCodes.STATUS_RECONCILIATION_REQUIRED
    OperationStatus.SUCCEEDED -> PersistenceCodes.STATUS_SUCCEEDED
    OperationStatus.FAILED -> PersistenceCodes.STATUS_FAILED
    OperationStatus.CANCELLED -> PersistenceCodes.STATUS_CANCELLED
}

private fun operationStatusFromStorageCode(code: String): OperationStatus? = when (code) {
    PersistenceCodes.STATUS_PENDING -> OperationStatus.PENDING
    PersistenceCodes.STATUS_RUNNING -> OperationStatus.RUNNING
    PersistenceCodes.STATUS_WAITING -> OperationStatus.WAITING
    PersistenceCodes.STATUS_RECONCILIATION_REQUIRED -> OperationStatus.RECONCILIATION_REQUIRED
    PersistenceCodes.STATUS_SUCCEEDED -> OperationStatus.SUCCEEDED
    PersistenceCodes.STATUS_FAILED -> OperationStatus.FAILED
    PersistenceCodes.STATUS_CANCELLED -> OperationStatus.CANCELLED
    else -> null
}

private fun CheckpointSemantics.toStorageCode(): String = when (this) {
    CheckpointSemantics.READ_ONLY -> PersistenceCodes.CHECKPOINT_READ_ONLY
    CheckpointSemantics.MUTATION_NOT_STARTED -> PersistenceCodes.CHECKPOINT_MUTATION_NOT_STARTED
    CheckpointSemantics.MUTATION_IN_FLIGHT -> PersistenceCodes.CHECKPOINT_MUTATION_IN_FLIGHT
    CheckpointSemantics.MUTATION_VERIFIED -> PersistenceCodes.CHECKPOINT_MUTATION_VERIFIED
    CheckpointSemantics.RESTART_IN_FLIGHT -> PersistenceCodes.CHECKPOINT_RESTART_IN_FLIGHT
    CheckpointSemantics.POST_VERIFY_REQUIRED -> PersistenceCodes.CHECKPOINT_POST_VERIFY_REQUIRED
    CheckpointSemantics.COMMIT_VERIFIED -> PersistenceCodes.CHECKPOINT_COMMIT_VERIFIED
    CheckpointSemantics.TERMINAL -> PersistenceCodes.CHECKPOINT_TERMINAL
}

private fun checkpointSemanticsFromStorageCode(code: String): CheckpointSemantics? = when (code) {
    PersistenceCodes.CHECKPOINT_READ_ONLY -> CheckpointSemantics.READ_ONLY
    PersistenceCodes.CHECKPOINT_MUTATION_NOT_STARTED -> CheckpointSemantics.MUTATION_NOT_STARTED
    PersistenceCodes.CHECKPOINT_MUTATION_IN_FLIGHT -> CheckpointSemantics.MUTATION_IN_FLIGHT
    PersistenceCodes.CHECKPOINT_MUTATION_VERIFIED -> CheckpointSemantics.MUTATION_VERIFIED
    PersistenceCodes.CHECKPOINT_RESTART_IN_FLIGHT -> CheckpointSemantics.RESTART_IN_FLIGHT
    PersistenceCodes.CHECKPOINT_POST_VERIFY_REQUIRED -> CheckpointSemantics.POST_VERIFY_REQUIRED
    PersistenceCodes.CHECKPOINT_COMMIT_VERIFIED -> CheckpointSemantics.COMMIT_VERIFIED
    PersistenceCodes.CHECKPOINT_TERMINAL -> CheckpointSemantics.TERMINAL
    else -> null
}
