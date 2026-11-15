package com.velumtegra.xuimobile.core.model

import java.time.Instant

/** Exact immutable identity of one short-lived Management QUICK_INSPECT operation. */
data class ManagementScope(
    val operationId: OperationId,
    val serverId: ServerId,
    val serverAccessId: ServerAccessId,
    val installationId: XuiInstallationId,
)

enum class ManagementPresence {
    PRESENT,
    ABSENT,
}

enum class ManagementPathKind {
    BINARY,
    ROOT,
    DATABASE,
}

enum class ManagementServiceState {
    ACTIVE,
    INACTIVE,
    FAILED,
    ACTIVATING,
    DEACTIVATING,
    RELOADING,
    UNKNOWN,
}

data class ManagementPanelSettings(
    val panelPort: Int,
    val webBasePath: String,
    val listenAddress: String?,
) {
    init {
        require(panelPort in 1..65535) { "panelPort must be in 1..65535" }
        requireManagementPath(webBasePath, "webBasePath")
        listenAddress?.let { requireManagementText(it, "listenAddress", 128) }
    }
}

/** Safe normalized Management fact. Raw stdout/stderr is intentionally not representable. */
sealed interface ManagementObservation {
    val observedAt: Instant

    data class ServiceUnitPresence(
        val serviceUnit: String,
        val presence: ManagementPresence,
        override val observedAt: Instant,
    ) : ManagementObservation {
        init {
            requireManagementText(serviceUnit, "serviceUnit", 255)
        }
    }

    data class PathPresence(
        val pathKind: ManagementPathKind,
        val path: String,
        val presence: ManagementPresence,
        override val observedAt: Instant,
    ) : ManagementObservation {
        init {
            requireManagementPath(path, "path")
        }
    }

    data class ManagedInstallMarker(
        val managedInstallId: ManagedInstallId?,
        val presence: ManagementPresence,
        override val observedAt: Instant,
    ) : ManagementObservation {
        init {
            when (presence) {
                ManagementPresence.PRESENT -> requireNotNull(managedInstallId) {
                    "Present managed-install marker requires its exact id"
                }
                ManagementPresence.ABSENT -> require(managedInstallId == null) {
                    "Absent managed-install marker cannot carry an id"
                }
            }
        }
    }

    data class ServiceState(
        val serviceUnit: String,
        val state: ManagementServiceState,
        override val observedAt: Instant,
    ) : ManagementObservation {
        init {
            requireManagementText(serviceUnit, "serviceUnit", 255)
        }
    }

    data class PanelSettings(
        val settings: ManagementPanelSettings,
        override val observedAt: Instant,
    ) : ManagementObservation

    data class ListenerPresence(
        val port: Int,
        val listenAddress: String?,
        val presence: ManagementPresence,
        override val observedAt: Instant,
    ) : ManagementObservation {
        init {
            require(port in 1..65535) { "Listener port must be in 1..65535" }
            listenAddress?.let { requireManagementText(it, "listenAddress", 128) }
        }
    }
}

data class ManagementEvidence(
    val scope: ManagementScope,
    val observations: List<ManagementObservation>,
) {
    init {
        require(observations.isNotEmpty()) { "Management evidence must contain normalized observations" }
    }
}

enum class ManagementIdentityDrift {
    SERVICE_UNIT_ABSENT,
    BINARY_PATH_ABSENT,
    ROOT_PATH_ABSENT,
    DATABASE_PATH_ABSENT,
    MANAGED_MARKER_ABSENT,
    MANAGED_MARKER_MISMATCH,
}

enum class ManagementBaselineDrift {
    PANEL_PORT,
    WEB_BASE_PATH,
    LISTEN_ADDRESS,
    EXPECTED_LISTENER_ABSENT,
}

enum class ManagementEvidenceGap {
    SERVICE_UNIT_UNOBSERVED,
    BINARY_PATH_UNOBSERVED,
    ROOT_PATH_UNOBSERVED,
    DATABASE_PATH_UNOBSERVED,
    MANAGED_MARKER_UNOBSERVED,
    SERVICE_STATE_UNOBSERVED,
    PANEL_SETTINGS_UNOBSERVED,
    LISTENER_UNOBSERVED,
    CONFLICTING_EVIDENCE,
}

sealed interface ManagementIdentityStatus {
    data object Matched : ManagementIdentityStatus
    data class Drift(val fields: Set<ManagementIdentityDrift>) : ManagementIdentityStatus {
        init { require(fields.isNotEmpty()) }
    }
    data class Insufficient(val gaps: Set<ManagementEvidenceGap>) : ManagementIdentityStatus {
        init { require(gaps.isNotEmpty()) }
    }
}

sealed interface ManagementBaselineStatus {
    data object Matched : ManagementBaselineStatus
    data class Drift(val fields: Set<ManagementBaselineDrift>) : ManagementBaselineStatus {
        init { require(fields.isNotEmpty()) }
    }
    data class Insufficient(val gaps: Set<ManagementEvidenceGap>) : ManagementBaselineStatus {
        init { require(gaps.isNotEmpty()) }
    }
}

/** Process-local live result. It is not a durable baseline update. */
data class ManagementLiveSnapshot(
    val scope: ManagementScope,
    val identityStatus: ManagementIdentityStatus,
    val serviceState: ManagementServiceState,
    val baselineStatus: ManagementBaselineStatus,
    val freshProof: InstallationProof?,
    val observedAt: Instant,
) {
    init {
        freshProof?.let { proof ->
            require(proof.installationId == scope.installationId)
            require(proof.serverId == scope.serverId)
            require(proof.serverAccessId == scope.serverAccessId)
            require(!proof.observedAt.isAfter(observedAt))
        }
    }
}

sealed interface ManagementBaselineReadbackResult {
    data class Complete(val baseline: InstallationBaseline) : ManagementBaselineReadbackResult
    data class IdentityDrift(val fields: Set<ManagementIdentityDrift>) : ManagementBaselineReadbackResult {
        init { require(fields.isNotEmpty()) }
    }
    data class Insufficient(val gaps: Set<ManagementEvidenceGap>) : ManagementBaselineReadbackResult {
        init { require(gaps.isNotEmpty()) }
    }
}

enum class ManagementFailureKind {
    EXACT_ACCESS_UNAVAILABLE,
    SECRET_UNAVAILABLE,
    HOST_IDENTITY_MISMATCH,
    AUTHENTICATION_REJECTED,
    TRANSPORT_UNAVAILABLE,
    TRANSPORT_TIMEOUT,
    MALFORMED_READBACK,
    INTERNAL_INVARIANT_FAILURE,
}

private fun requireManagementText(value: String, field: String, maxLength: Int) {
    require(value.isNotBlank()) { "$field must not be blank" }
    require(value.length <= maxLength) { "$field is too long" }
    require(value.none { it == '\u0000' || it == '\n' || it == '\r' }) { "$field contains control characters" }
}

private fun requireManagementPath(value: String, field: String) {
    requireManagementText(value, field, 1024)
    require(value.startsWith('/')) { "$field must be absolute" }
    require(!value.contains("//")) { "$field must be normalized" }
    require(value.split('/').none { it == "." || it == ".." }) { "$field must not contain dot segments" }
}
