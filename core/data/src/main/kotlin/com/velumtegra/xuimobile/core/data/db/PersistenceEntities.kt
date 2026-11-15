package com.velumtegra.xuimobile.core.data.db

import androidx.room3.ColumnInfo
import androidx.room3.Entity
import androidx.room3.ForeignKey
import androidx.room3.Index

@Entity(tableName = "servers")
data class ServerEntity(
    @androidx.room3.PrimaryKey
    @ColumnInfo(name = "server_id")
    val serverId: String,
    @ColumnInfo(name = "display_name")
    val displayName: String,
    @ColumnInfo(name = "created_at_epoch_second")
    val createdAtEpochSecond: Long,
    @ColumnInfo(name = "created_at_nano")
    val createdAtNano: Int,
    @ColumnInfo(name = "revision")
    val revision: Long,
)

@Entity(
    tableName = "server_accesses",
    primaryKeys = ["server_access_id"],
    foreignKeys = [
        ForeignKey(
            entity = ServerEntity::class,
            parentColumns = ["server_id"],
            childColumns = ["server_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.RESTRICT,
        ),
    ],
    indices = [
        Index(value = ["server_id"]),
        Index(value = ["server_access_id", "server_id"], unique = true),
        Index(value = ["secret_id"]),
    ],
)
data class ServerAccessEntity(
    @ColumnInfo(name = "server_access_id")
    val serverAccessId: String,
    @ColumnInfo(name = "server_id")
    val serverId: String,
    @ColumnInfo(name = "host")
    val host: String,
    @ColumnInfo(name = "port")
    val port: Int,
    @ColumnInfo(name = "username")
    val username: String,
    @ColumnInfo(name = "auth_kind")
    val authKind: String,
    @ColumnInfo(name = "secret_id")
    val secretId: String,
    @ColumnInfo(name = "pinned_host_key")
    val pinnedHostKey: String,
)

@Entity(
    tableName = "xui_installations",
    primaryKeys = ["installation_id"],
    foreignKeys = [
        ForeignKey(
            entity = ServerEntity::class,
            parentColumns = ["server_id"],
            childColumns = ["server_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.RESTRICT,
        ),
    ],
    indices = [
        Index(value = ["server_id"]),
        Index(value = ["installation_id", "server_id"], unique = true),
        Index(value = ["managed_install_id"], unique = true),
    ],
)
data class XuiInstallationEntity(
    @ColumnInfo(name = "installation_id")
    val installationId: String,
    @ColumnInfo(name = "server_id")
    val serverId: String,
    @ColumnInfo(name = "ownership")
    val ownership: String,
    @ColumnInfo(name = "identity_service_unit")
    val identityServiceUnit: String,
    @ColumnInfo(name = "identity_binary_path")
    val identityBinaryPath: String,
    @ColumnInfo(name = "identity_root_path")
    val identityRootPath: String,
    @ColumnInfo(name = "identity_database_path")
    val identityDatabasePath: String,
    @ColumnInfo(name = "managed_install_id")
    val managedInstallId: String?,
    @ColumnInfo(name = "baseline_service_unit")
    val baselineServiceUnit: String,
    @ColumnInfo(name = "baseline_binary_path")
    val baselineBinaryPath: String,
    @ColumnInfo(name = "baseline_root_path")
    val baselineRootPath: String,
    @ColumnInfo(name = "baseline_database_path")
    val baselineDatabasePath: String,
    @ColumnInfo(name = "panel_port")
    val panelPort: Int,
    @ColumnInfo(name = "web_base_path")
    val webBasePath: String,
    @ColumnInfo(name = "listen_address")
    val listenAddress: String?,
    @ColumnInfo(name = "captured_at_epoch_second")
    val capturedAtEpochSecond: Long,
    @ColumnInfo(name = "captured_at_nano")
    val capturedAtNano: Int,
    @ColumnInfo(name = "revision")
    val revision: Long,
)

@Entity(
    tableName = "management_accesses",
    primaryKeys = ["installation_id", "server_access_id"],
    foreignKeys = [
        ForeignKey(
            entity = XuiInstallationEntity::class,
            parentColumns = ["installation_id", "server_id"],
            childColumns = ["installation_id", "server_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.RESTRICT,
        ),
        ForeignKey(
            entity = ServerAccessEntity::class,
            parentColumns = ["server_access_id", "server_id"],
            childColumns = ["server_access_id", "server_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.RESTRICT,
        ),
    ],
    indices = [
        Index(value = ["installation_id", "server_id"]),
        Index(value = ["server_access_id", "server_id"]),
        Index(value = ["server_id"]),
    ],
)
data class ManagementAccessEntity(
    @ColumnInfo(name = "installation_id")
    val installationId: String,
    @ColumnInfo(name = "server_access_id")
    val serverAccessId: String,
    /** Redundant by design: binds both composite FKs to one exact Server. */
    @ColumnInfo(name = "server_id")
    val serverId: String,
)

@Entity(
    tableName = "web_panel_accesses",
    primaryKeys = ["web_panel_access_id"],
    foreignKeys = [
        ForeignKey(
            entity = XuiInstallationEntity::class,
            parentColumns = ["installation_id", "server_id"],
            childColumns = ["installation_id", "bound_server_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.RESTRICT,
        ),
        ForeignKey(
            entity = ServerAccessEntity::class,
            parentColumns = ["server_access_id", "server_id"],
            childColumns = ["route_server_access_id", "bound_server_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.RESTRICT,
        ),
    ],
    indices = [
        Index(value = ["installation_id", "bound_server_id"]),
        Index(value = ["route_server_access_id", "bound_server_id"]),
        Index(value = ["password_secret_id"]),
    ],
)
data class WebPanelAccessEntity(
    @ColumnInfo(name = "web_panel_access_id")
    val webPanelAccessId: String,
    @ColumnInfo(name = "installation_link_kind")
    val installationLinkKind: String,
    @ColumnInfo(name = "installation_id")
    val installationId: String?,
    /**
     * Shared server discriminator. For LINKED + SSH_TUNNEL both composite FKs must resolve
     * through this same value, structurally forbidding accidental cross-server tunnels.
     */
    @ColumnInfo(name = "bound_server_id")
    val boundServerId: String?,
    @ColumnInfo(name = "username")
    val username: String,
    @ColumnInfo(name = "password_secret_id")
    val passwordSecretId: String,
    @ColumnInfo(name = "route_kind")
    val routeKind: String,
    @ColumnInfo(name = "route_origin_host")
    val routeOriginHost: String?,
    @ColumnInfo(name = "route_server_access_id")
    val routeServerAccessId: String?,
    @ColumnInfo(name = "revision")
    val revision: Long,
)

@Entity(
    tableName = "operation_snapshots",
    primaryKeys = ["operation_id"],
    foreignKeys = [
        ForeignKey(
            entity = ServerAccessEntity::class,
            parentColumns = ["server_access_id", "server_id"],
            childColumns = ["server_access_id", "server_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.RESTRICT,
        ),
        ForeignKey(
            entity = XuiInstallationEntity::class,
            parentColumns = ["installation_id", "server_id"],
            childColumns = ["installation_id", "server_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.RESTRICT,
        ),
    ],
    indices = [
        Index(value = ["server_access_id", "server_id"]),
        Index(value = ["installation_id", "server_id"]),
        Index(value = ["status"]),
    ],
)
data class OperationSnapshotEntity(
    @ColumnInfo(name = "operation_id")
    val operationId: String,
    @ColumnInfo(name = "operation_type")
    val operationType: String,
    @ColumnInfo(name = "target_kind")
    val targetKind: String,
    @ColumnInfo(name = "server_id")
    val serverId: String,
    @ColumnInfo(name = "server_access_id")
    val serverAccessId: String,
    @ColumnInfo(name = "installation_id")
    val installationId: String?,
    @ColumnInfo(name = "status")
    val status: String,
    @ColumnInfo(name = "checkpoint_phase_name")
    val checkpointPhaseName: String,
    @ColumnInfo(name = "checkpoint_semantics")
    val checkpointSemantics: String,
    @ColumnInfo(name = "checkpoint_epoch_second")
    val checkpointEpochSecond: Long,
    @ColumnInfo(name = "checkpoint_nano")
    val checkpointNano: Int,
    @ColumnInfo(name = "started_at_epoch_second")
    val startedAtEpochSecond: Long,
    @ColumnInfo(name = "started_at_nano")
    val startedAtNano: Int,
    @ColumnInfo(name = "updated_at_epoch_second")
    val updatedAtEpochSecond: Long,
    @ColumnInfo(name = "updated_at_nano")
    val updatedAtNano: Int,
    @ColumnInfo(name = "revision")
    val revision: Long,
)

@Entity(
    tableName = "operation_journal",
    primaryKeys = ["operation_id", "revision"],
    foreignKeys = [
        ForeignKey(
            entity = OperationSnapshotEntity::class,
            parentColumns = ["operation_id"],
            childColumns = ["operation_id"],
            onDelete = ForeignKey.RESTRICT,
            onUpdate = ForeignKey.RESTRICT,
        ),
    ],
    indices = [Index(value = ["operation_id"])],
)
data class OperationJournalEntity(
    @ColumnInfo(name = "operation_id")
    val operationId: String,
    @ColumnInfo(name = "revision")
    val revision: Long,
    @ColumnInfo(name = "status")
    val status: String,
    @ColumnInfo(name = "checkpoint_phase_name")
    val checkpointPhaseName: String,
    @ColumnInfo(name = "checkpoint_semantics")
    val checkpointSemantics: String,
    @ColumnInfo(name = "checkpoint_epoch_second")
    val checkpointEpochSecond: Long,
    @ColumnInfo(name = "checkpoint_nano")
    val checkpointNano: Int,
    @ColumnInfo(name = "recorded_at_epoch_second")
    val recordedAtEpochSecond: Long,
    @ColumnInfo(name = "recorded_at_nano")
    val recordedAtNano: Int,
)
