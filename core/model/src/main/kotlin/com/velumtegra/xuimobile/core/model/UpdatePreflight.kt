package com.velumtegra.xuimobile.core.model

import java.time.Instant

enum class UpdateRootStatus { DIRECT_ROOT, NOT_ROOT, UNOBSERVED }
enum class UpdateLayoutStatus { STANDARD_3X_UI_SYSTEMD, UNSUPPORTED }
enum class UpdatePreflightFailure { TARGET_NOT_VERIFIED, READBACK_UNAVAILABLE, TRANSPORT_UNCERTAIN, INTERNAL_CONTRACT }

/** A read-only preparation report. This type cannot authorize or dispatch an update. */
data class UpdatePreflightSnapshot(
    val scope: ManagementScope,
    val root: UpdateRootStatus,
    val layout: UpdateLayoutStatus,
    val serviceDefinition: DeepDiagnosticServiceDefinitionStatus,
    val currentVersion: String?,
    val serviceState: ManagementServiceState,
    val baselineStatus: ManagementBaselineStatus,
    val observedAt: Instant,
    val architecture: UpdateServerArchitecture? = null,
    val recovery: UpdateRecoverySourceSnapshot? = null,
    val recoveryFiles: RecoveryFileInventory? = null,
) {
    init {
        recoveryFiles?.let {
            require(it.scope == scope)
            require(!it.observedAt.isAfter(observedAt))
        }
        recovery?.let {
            require(it.scope == scope)
            require(!it.observedAt.isAfter(observedAt))
        }
        currentVersion?.let {
            require(Regex("v?[0-9]{1,3}(?:\\.[0-9]{1,3}){1,3}(?:-(?:rc|beta|alpha|dev)(?:[.-][A-Za-z0-9]{1,12}){0,2})?").matches(it))
            require(layout == UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD)
            require(serviceDefinition == DeepDiagnosticServiceDefinitionStatus.CONSISTENT)
        }
    }
}
