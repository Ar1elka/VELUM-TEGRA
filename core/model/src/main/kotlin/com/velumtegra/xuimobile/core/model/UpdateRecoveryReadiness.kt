package com.velumtegra.xuimobile.core.model

import java.time.Instant

enum class UpdateRecoveryTool { SQLITE3, TAR, SHA256SUM, STAT }
enum class UpdateRecoveryToolState { AVAILABLE, MISSING }
enum class UpdateRecoveryDatabaseState {
    PRIVATE_REGULAR, UNSAFE_PERMISSIONS, UNSAFE_LINK, UNAVAILABLE, UNOBSERVED,
    TOO_LARGE, CHANGED_DURING_READ,
}
enum class UpdateRecoveryRuntimeState { STANDARD_FILES_PRESENT, UNSAFE_LINK, UNAVAILABLE }
enum class UpdateRecoveryPanelTlsState { NOT_CONFIGURED, PAIR_PRESENT, INCOMPLETE, UNAVAILABLE, UNOBSERVED }

/** Finite source observations only. No database/key contents, paths, shell or backup receipt. */
data class UpdateRecoverySourceSnapshot(
    val scope: ManagementScope,
    val tools: Map<UpdateRecoveryTool, UpdateRecoveryToolState>,
    val database: UpdateRecoveryDatabaseState,
    val databaseBytes: Long?,
    val runtime: UpdateRecoveryRuntimeState,
    val integrity: DeepDiagnosticDatabaseIntegrityStatus,
    val schema: DeepDiagnosticDatabaseSchemaStatus,
    val panelTls: UpdateRecoveryPanelTlsState,
    val observedAt: Instant,
) {
    init {
        require(tools.keys == UpdateRecoveryTool.values().toSet())
        databaseBytes?.let { require(it >= 0) }
    }
    companion object {
        const val MAX_DATABASE_BYTES: Long = 128L * 1024 * 1024
    }
}

enum class UpdateRecoveryComponent {
    CONSISTENT_DATABASE,
    PREVIOUS_BINARY_AND_XRAY_RUNTIME,
    SERVICE_CONFIGURATION_AND_PERMISSIONS,
    PANEL_SETTINGS_AND_TLS_FILES,
    EXTERNAL_XRAY_RESOURCES,
}

/** A time-limited native review draft, NEVER backup, update, restore or replay authority. */
data class UpdateRecoveryDraftPlan(
    val scope: ManagementScope,
    val previousVersion: String,
    val architecture: UpdateServerArchitecture,
    val sourceObservedAt: Instant,
    val validUntil: Instant,
) {
    init {
        require(Regex("v?[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}").matches(previousVersion))
        require(validUntil.isAfter(sourceObservedAt))
    }
    val components: List<UpdateRecoveryComponent> get() = UpdateRecoveryComponent.values().toList()
    val pendingProofs: List<UpdateRecoveryRequirement> get() = UpdateRecoveryRequirement.values().toList()
}
