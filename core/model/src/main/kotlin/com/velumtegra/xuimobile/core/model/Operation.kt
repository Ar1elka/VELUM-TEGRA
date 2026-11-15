package com.velumtegra.xuimobile.core.model

import java.time.Instant

enum class OperationType {
    DISCOVERY,
    QUICK_INSPECT,
    DEEP_DIAGNOSTIC,
    SERVICE_LOG_READ,
    UPDATE_PREFLIGHT,
    DATABASE_BACKUP,
    INSTALLATION_BACKUP,
    INSTALLATION_RESTORE_CHECK,
    RESTORE_COMPATIBILITY,
    WORKING_DATABASE_RESTORE,
    RESTORED_PANEL_START,
    KNOWN_FILE_RESTORE,
    INSTALL,
    RESTART,
    RECOVERY,
    UNINSTALL,
    REINSTALL,
}

sealed interface OperationTarget {
    val serverId: ServerId
    val serverAccessId: ServerAccessId

    data class ServerTarget(
        override val serverId: ServerId,
        override val serverAccessId: ServerAccessId,
    ) : OperationTarget

    data class InstallationTarget(
        override val serverId: ServerId,
        override val serverAccessId: ServerAccessId,
        val installationId: XuiInstallationId,
    ) : OperationTarget
}

enum class OperationStatus {
    PENDING,
    RUNNING,
    WAITING,
    RECONCILIATION_REQUIRED,
    SUCCEEDED,
    FAILED,
    CANCELLED,
}

/**
 * Semantics of the last durable checkpoint, independent of feature-specific phase names.
 * This is what lifecycle recovery uses to decide whether replay is safe.
 */
enum class CheckpointSemantics {
    READ_ONLY,
    MUTATION_NOT_STARTED,
    MUTATION_IN_FLIGHT,
    MUTATION_VERIFIED,
    RESTART_IN_FLIGHT,
    POST_VERIFY_REQUIRED,
    COMMIT_VERIFIED,
    TERMINAL,
}

data class OperationCheckpoint(
    val phaseName: String,
    val semantics: CheckpointSemantics,
    val recordedAt: Instant,
) {
    init {
        require(phaseName.isNotBlank())
    }
}

data class OperationSnapshot(
    val operationId: OperationId,
    val type: OperationType,
    val target: OperationTarget,
    val status: OperationStatus,
    val checkpoint: OperationCheckpoint,
    val startedAt: Instant,
    val updatedAt: Instant,
)
