package com.velumtegra.xuimobile.core.model

import java.time.Instant

/** Exact immutable identity of one Discovery run. No fallback identity is represented here. */
data class DiscoveryScope(
    val operationId: OperationId,
    val serverId: ServerId,
    val serverAccessId: ServerAccessId,
)

enum class DiscoveryStage {
    DISCOVER,
    CLASSIFY,
    PROVE,
    RESULT,
}

enum class DiscoveryPresence {
    PRESENT,
    ABSENT,
}

data class DiscoveryPlatform(
    val distributionId: String,
    val versionId: String?,
) {
    init {
        requireNormalizedText(distributionId, "distributionId", maxLength = 64)
        versionId?.let { requireNormalizedText(it, "versionId", maxLength = 64) }
    }
}

enum class DiscoveryPathKind {
    BINARY,
    ROOT,
    DATABASE,
}

enum class DiscoveryPanelFamily {
    SUPPORTED_3X_UI,
    FOREIGN_PANEL,
}

enum class DiscoveryObservationKind {
    PLATFORM,
    SERVICE_UNIT,
    INSTALLATION_PATH,
    MANAGED_INSTALL_MARKER,
    LISTENER,
    WEB_BASE_PATH,
    PANEL_FAMILY,
}

/**
 * Safe normalized read-only fact. Raw stdout/stderr is intentionally not representable by this model.
 */
sealed interface DiscoveryObservation {
    val kind: DiscoveryObservationKind
    val observedAt: Instant

    data class Platform(
        val platform: DiscoveryPlatform,
        override val observedAt: Instant,
    ) : DiscoveryObservation {
        override val kind: DiscoveryObservationKind = DiscoveryObservationKind.PLATFORM
    }

    data class ServiceUnit(
        val serviceUnit: String,
        val presence: DiscoveryPresence,
        override val observedAt: Instant,
    ) : DiscoveryObservation {
        override val kind: DiscoveryObservationKind = DiscoveryObservationKind.SERVICE_UNIT

        init {
            requireNormalizedText(serviceUnit, "serviceUnit", maxLength = 255)
        }
    }

    data class InstallationPath(
        val pathKind: DiscoveryPathKind,
        val path: String,
        val presence: DiscoveryPresence,
        override val observedAt: Instant,
    ) : DiscoveryObservation {
        override val kind: DiscoveryObservationKind = DiscoveryObservationKind.INSTALLATION_PATH

        init {
            requireAbsoluteNormalizedPath(path, "path")
        }
    }

    data class ManagedInstallMarker(
        val managedInstallId: ManagedInstallId?,
        val presence: DiscoveryPresence,
        override val observedAt: Instant,
    ) : DiscoveryObservation {
        override val kind: DiscoveryObservationKind = DiscoveryObservationKind.MANAGED_INSTALL_MARKER

        init {
            when (presence) {
                DiscoveryPresence.PRESENT -> requireNotNull(managedInstallId) {
                    "Present managed-install marker requires its exact typed id"
                }
                DiscoveryPresence.ABSENT -> require(managedInstallId == null) {
                    "Absent managed-install marker cannot carry an id"
                }
            }
        }
    }

    data class Listener(
        val port: Int,
        val listenAddress: String?,
        override val observedAt: Instant,
    ) : DiscoveryObservation {
        override val kind: DiscoveryObservationKind = DiscoveryObservationKind.LISTENER

        init {
            require(port in 1..65535) { "Listener port must be in 1..65535" }
            listenAddress?.let { requireNormalizedText(it, "listenAddress", maxLength = 128) }
        }
    }

    data class WebBasePath(
        val webBasePath: String,
        override val observedAt: Instant,
    ) : DiscoveryObservation {
        override val kind: DiscoveryObservationKind = DiscoveryObservationKind.WEB_BASE_PATH

        init {
            requireAbsoluteNormalizedPath(webBasePath, "webBasePath")
        }
    }

    data class PanelFamily(
        val family: DiscoveryPanelFamily,
        override val observedAt: Instant,
    ) : DiscoveryObservation {
        override val kind: DiscoveryObservationKind = DiscoveryObservationKind.PANEL_FAMILY
    }
}

data class DiscoveryEvidence(
    val scope: DiscoveryScope,
    val observations: List<DiscoveryObservation>,
) {
    init {
        require(observations.isNotEmpty()) { "Discovery evidence must contain at least one normalized observation" }
    }

    val kinds: Set<DiscoveryObservationKind>
        get() = observations.mapTo(linkedSetOf()) { it.kind }
}

enum class DiscoveryProofSignal {
    SERVICE_UNIT,
    BINARY_PATH,
    ROOT_PATH,
    DATABASE_PATH,
    MANAGED_INSTALL_MARKER,
    PANEL_LISTENER,
    PANEL_SETTINGS,
}

/**
 * Proof of a newly observed candidate only. It deliberately has no XuiInstallationId and is not
 * accepted by TargetProofPolicy, whose mutation boundary consumes InstallationProof instead.
 */
data class DiscoveryProof(
    val id: DiscoveryProofId,
    val scope: DiscoveryScope,
    val observedIdentity: InstallationIdentity,
    val candidateBaseline: InstallationBaseline?,
    val supportingSignals: Set<DiscoveryProofSignal>,
    val observedAt: Instant,
) {
    init {
        require(supportingSignals.size >= 2) {
            "Discovery proof requires at least two independent installation signals"
        }
        if (observedIdentity.managedInstallId != null) {
            require(DiscoveryProofSignal.MANAGED_INSTALL_MARKER in supportingSignals) {
                "A managedInstallId requires managed-marker proof"
            }
        }
        candidateBaseline?.let { baseline ->
            require(baseline.serviceUnit == observedIdentity.serviceUnit)
            require(baseline.binaryPath == observedIdentity.binaryPath)
            require(baseline.rootPath == observedIdentity.rootPath)
            require(baseline.databasePath == observedIdentity.databasePath)
            require(!baseline.capturedAt.isAfter(observedAt)) {
                "Candidate baseline cannot be captured after the proof observation"
            }
        }
    }
}

enum class DiscoveryConflict {
    CONFLICTING_PLATFORM_EVIDENCE,
    MULTIPLE_SUPPORTED_CANDIDATES,
    CONFLICTING_SERVICE_UNITS,
    CONFLICTING_INSTALLATION_PATHS,
    SUPPORTED_AND_FOREIGN_PANEL_EVIDENCE,
}

enum class DiscoveryEvidenceGap {
    PLATFORM_UNREADABLE,
    PERMISSION_DENIED,
    INSTALLATION_IDENTITY_INCOMPLETE,
    BASELINE_INCOMPLETE,
}

/** Deterministic interpretation of normalized evidence before terminal RESULT. */
sealed interface DiscoveryClassification {
    data class SupportedCandidate(val platform: DiscoveryPlatform) : DiscoveryClassification
    data object NoSupportedInstallation : DiscoveryClassification
    data class UnsupportedPlatform(val platform: DiscoveryPlatform) : DiscoveryClassification
    data object ForeignPanel : DiscoveryClassification
    data class Ambiguous(val conflicts: Set<DiscoveryConflict>) : DiscoveryClassification {
        init {
            require(conflicts.isNotEmpty())
        }
    }
    data class InsufficientEvidence(val gaps: Set<DiscoveryEvidenceGap>) : DiscoveryClassification {
        init {
            require(gaps.isNotEmpty())
        }
    }
}

enum class DiscoveryFailureKind {
    EXACT_ACCESS_UNAVAILABLE,
    SECRET_UNAVAILABLE,
    HOST_IDENTITY_MISMATCH,
    AUTHENTICATION_REJECTED,
    TRANSPORT_UNAVAILABLE,
    TRANSPORT_TIMEOUT,
    MALFORMED_PROBE_EVIDENCE,
    INTERNAL_INVARIANT_FAILURE,
}

/** Terminal typed result. No variant carries raw command/output or mutation authorization. */
sealed interface DiscoveryResult {
    val scope: DiscoveryScope
    val completedAt: Instant

    data class ProvenSupportedInstallation(
        val proof: DiscoveryProof,
        override val completedAt: Instant,
    ) : DiscoveryResult {
        override val scope: DiscoveryScope = proof.scope

        init {
            require(!completedAt.isBefore(proof.observedAt))
        }
    }

    data class NoSupportedInstallation(
        override val scope: DiscoveryScope,
        override val completedAt: Instant,
    ) : DiscoveryResult

    data class UnsupportedPlatform(
        override val scope: DiscoveryScope,
        val platform: DiscoveryPlatform,
        override val completedAt: Instant,
    ) : DiscoveryResult

    data class ForeignPanelDetected(
        override val scope: DiscoveryScope,
        override val completedAt: Instant,
    ) : DiscoveryResult

    data class AmbiguousEvidence(
        override val scope: DiscoveryScope,
        val conflicts: Set<DiscoveryConflict>,
        override val completedAt: Instant,
    ) : DiscoveryResult {
        init {
            require(conflicts.isNotEmpty())
        }
    }

    data class InsufficientEvidence(
        override val scope: DiscoveryScope,
        val gaps: Set<DiscoveryEvidenceGap>,
        override val completedAt: Instant,
    ) : DiscoveryResult {
        init {
            require(gaps.isNotEmpty())
        }
    }

    data class Failed(
        override val scope: DiscoveryScope,
        val failure: DiscoveryFailureKind,
        override val completedAt: Instant,
    ) : DiscoveryResult

    data class Cancelled(
        override val scope: DiscoveryScope,
        override val completedAt: Instant,
    ) : DiscoveryResult
}

/**
 * Durable-safe terminal category encoded in the generic Operation checkpoint.
 *
 * This is deliberately coarser than [DiscoveryResult]: after process death the Room v1 journal can
 * reconstruct only this category plus exact scope/time. It must never be used to invent a lost
 * [DiscoveryProof] or any other detailed evidence.
 */
enum class DiscoveryTerminalKind(
    val phaseName: String,
    val operationStatus: OperationStatus,
) {
    PROVEN_SUPPORTED("DISCOVERY_RESULT_PROVEN_SUPPORTED", OperationStatus.SUCCEEDED),
    NO_SUPPORTED_INSTALLATION("DISCOVERY_RESULT_NONE", OperationStatus.SUCCEEDED),
    UNSUPPORTED_PLATFORM("DISCOVERY_RESULT_UNSUPPORTED_PLATFORM", OperationStatus.SUCCEEDED),
    FOREIGN_PANEL("DISCOVERY_RESULT_FOREIGN_PANEL", OperationStatus.SUCCEEDED),
    AMBIGUOUS("DISCOVERY_RESULT_AMBIGUOUS", OperationStatus.SUCCEEDED),
    INSUFFICIENT("DISCOVERY_RESULT_INSUFFICIENT", OperationStatus.SUCCEEDED),
    FAILED("DISCOVERY_RESULT_FAILED", OperationStatus.FAILED),
    CANCELLED("DISCOVERY_RESULT_CANCELLED", OperationStatus.CANCELLED),
    ;

    companion object {
        fun fromPhaseName(phaseName: String): DiscoveryTerminalKind? =
            entries.singleOrNull { it.phaseName == phaseName }
    }
}

fun DiscoveryResult.terminalKind(): DiscoveryTerminalKind = when (this) {
    is DiscoveryResult.ProvenSupportedInstallation -> DiscoveryTerminalKind.PROVEN_SUPPORTED
    is DiscoveryResult.NoSupportedInstallation -> DiscoveryTerminalKind.NO_SUPPORTED_INSTALLATION
    is DiscoveryResult.UnsupportedPlatform -> DiscoveryTerminalKind.UNSUPPORTED_PLATFORM
    is DiscoveryResult.ForeignPanelDetected -> DiscoveryTerminalKind.FOREIGN_PANEL
    is DiscoveryResult.AmbiguousEvidence -> DiscoveryTerminalKind.AMBIGUOUS
    is DiscoveryResult.InsufficientEvidence -> DiscoveryTerminalKind.INSUFFICIENT
    is DiscoveryResult.Failed -> DiscoveryTerminalKind.FAILED
    is DiscoveryResult.Cancelled -> DiscoveryTerminalKind.CANCELLED
}

private fun requireNormalizedText(value: String, field: String, maxLength: Int) {
    require(value.isNotBlank()) { "$field must not be blank" }
    require(value == value.trim()) { "$field must already be normalized" }
    require(value.length <= maxLength) { "$field exceeds normalized length limit" }
    require('\n' !in value && '\r' !in value && '\u0000' !in value) {
        "$field must not contain control delimiters"
    }
}

private fun requireAbsoluteNormalizedPath(value: String, field: String) {
    requireNormalizedText(value, field, maxLength = 512)
    require(value.startsWith('/')) { "$field must be an absolute path" }
}
