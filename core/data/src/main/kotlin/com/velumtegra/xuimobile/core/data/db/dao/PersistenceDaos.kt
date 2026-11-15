package com.velumtegra.xuimobile.core.data.db.dao

import androidx.room3.Dao
import androidx.room3.Insert
import androidx.room3.OnConflictStrategy
import androidx.room3.Query
import com.velumtegra.xuimobile.core.data.db.ManagementAccessEntity
import com.velumtegra.xuimobile.core.data.db.ServerAccessEntity
import com.velumtegra.xuimobile.core.data.db.ServerEntity
import com.velumtegra.xuimobile.core.data.db.WebPanelAccessEntity
import com.velumtegra.xuimobile.core.data.db.XuiInstallationEntity

@Dao
interface ServerDao {
    @Query("SELECT * FROM servers WHERE server_id = :serverId LIMIT 1")
    suspend fun get(serverId: String): ServerEntity?

    @Query("SELECT * FROM servers ORDER BY created_at_epoch_second, created_at_nano, server_id")
    suspend fun list(): List<ServerEntity>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(entity: ServerEntity): Long

    @Query(
        """
        UPDATE servers
        SET display_name = :displayName, revision = :nextRevision
        WHERE server_id = :serverId AND revision = :expectedRevision
        """,
    )
    suspend fun updateCas(
        serverId: String,
        displayName: String,
        expectedRevision: Long,
        nextRevision: Long,
    ): Int

    @Query("DELETE FROM servers WHERE server_id = :serverId AND revision = :expectedRevision")
    suspend fun deleteCas(serverId: String, expectedRevision: Long): Int
}

@Dao
interface ServerAccessDao {
    @Query("SELECT * FROM server_accesses WHERE server_access_id = :serverAccessId LIMIT 1")
    suspend fun get(serverAccessId: String): ServerAccessEntity?

    @Query("SELECT * FROM server_accesses WHERE server_id = :serverId ORDER BY server_access_id")
    suspend fun listForServer(serverId: String): List<ServerAccessEntity>

    @Query("SELECT server_id FROM server_accesses WHERE server_access_id = :serverAccessId LIMIT 1")
    suspend fun serverIdFor(serverAccessId: String): String?

    @Query("SELECT secret_id FROM server_accesses ORDER BY server_access_id")
    suspend fun listSecretIds(): List<String>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(entity: ServerAccessEntity): Long

    @Query("DELETE FROM server_accesses WHERE server_access_id = :serverAccessId")
    suspend fun delete(serverAccessId: String): Int

    @Query("SELECT COUNT(*) FROM management_accesses WHERE server_access_id = :serverAccessId")
    suspend fun managementReferenceCount(serverAccessId: String): Long

    @Query("SELECT COUNT(*) FROM web_panel_accesses WHERE route_server_access_id = :serverAccessId")
    suspend fun webPanelReferenceCount(serverAccessId: String): Long

    @Query(
        "SELECT COUNT(*) FROM operation_snapshots WHERE server_id = :serverId " +
            "AND status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED')",
    )
    suspend fun unfinishedServerOperations(serverId: String): Long

    @Query("SELECT COUNT(*) FROM operation_snapshots WHERE server_access_id = :serverAccessId")
    suspend fun operationReferenceCount(serverAccessId: String): Long

    @Query(
        "SELECT COUNT(*) FROM operation_snapshots WHERE server_access_id = :serverAccessId " +
            "AND status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED')",
    )
    suspend fun unfinishedOperationReferenceCount(serverAccessId: String): Long

    /** Moves finished history only; the caller proved [newId] is the same login on a migrated SSH port. */
    @Query(
        "UPDATE operation_snapshots SET server_access_id = :newId " +
            "WHERE server_access_id = :oldId AND server_id = :serverId " +
            "AND status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')",
    )
    suspend fun moveFinishedOperations(oldId: String, newId: String, serverId: String): Int
}

/**
 * Removes every local record of one server, children first (all FKs are RESTRICT). Called only inside one
 * write transaction after proving the server has no unfinished operation. Never touches another server.
 */
@Dao
interface ServerPurgeDao {
    @Query("SELECT web_panel_access_id FROM web_panel_accesses WHERE bound_server_id = :serverId")
    suspend fun webPanelIds(serverId: String): List<String>

    @Query("DELETE FROM web_panel_accesses WHERE bound_server_id = :serverId")
    suspend fun deleteWebPanels(serverId: String): Int

    @Query("DELETE FROM management_accesses WHERE server_id = :serverId")
    suspend fun deleteManagementAccesses(serverId: String): Int

    @Query(
        "DELETE FROM operation_journal WHERE operation_id IN " +
            "(SELECT operation_id FROM operation_snapshots WHERE server_id = :serverId)",
    )
    suspend fun deleteJournal(serverId: String): Int

    @Query("DELETE FROM operation_snapshots WHERE server_id = :serverId")
    suspend fun deleteOperations(serverId: String): Int

    @Query("DELETE FROM xui_installations WHERE server_id = :serverId")
    suspend fun deleteInstallations(serverId: String): Int

    @Query("DELETE FROM server_accesses WHERE server_id = :serverId")
    suspend fun deleteServerAccesses(serverId: String): Int
}

@Dao
interface XuiInstallationDao {
    @Query("SELECT * FROM xui_installations WHERE installation_id = :installationId LIMIT 1")
    suspend fun get(installationId: String): XuiInstallationEntity?

    @Query("SELECT * FROM xui_installations WHERE server_id = :serverId ORDER BY installation_id")
    suspend fun listForServer(serverId: String): List<XuiInstallationEntity>

    @Query("SELECT server_id FROM xui_installations WHERE installation_id = :installationId LIMIT 1")
    suspend fun serverIdFor(installationId: String): String?

    @Query("SELECT * FROM xui_installations WHERE managed_install_id = :managedInstallId LIMIT 1")
    suspend fun getByManagedInstallId(managedInstallId: String): XuiInstallationEntity?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(entity: XuiInstallationEntity): Long

    @Query(
        """
        UPDATE xui_installations
        SET ownership = :ownership,
            identity_service_unit = :identityServiceUnit,
            identity_binary_path = :identityBinaryPath,
            identity_root_path = :identityRootPath,
            identity_database_path = :identityDatabasePath,
            managed_install_id = :managedInstallId,
            baseline_service_unit = :baselineServiceUnit,
            baseline_binary_path = :baselineBinaryPath,
            baseline_root_path = :baselineRootPath,
            baseline_database_path = :baselineDatabasePath,
            panel_port = :panelPort,
            web_base_path = :webBasePath,
            listen_address = :listenAddress,
            captured_at_epoch_second = :capturedAtEpochSecond,
            captured_at_nano = :capturedAtNano,
            revision = :nextRevision
        WHERE installation_id = :installationId AND revision = :expectedRevision
        """,
    )
    suspend fun updateCas(
        installationId: String,
        ownership: String,
        identityServiceUnit: String,
        identityBinaryPath: String,
        identityRootPath: String,
        identityDatabasePath: String,
        managedInstallId: String?,
        baselineServiceUnit: String,
        baselineBinaryPath: String,
        baselineRootPath: String,
        baselineDatabasePath: String,
        panelPort: Int,
        webBasePath: String,
        listenAddress: String?,
        capturedAtEpochSecond: Long,
        capturedAtNano: Int,
        expectedRevision: Long,
        nextRevision: Long,
    ): Int

    @Query("DELETE FROM xui_installations WHERE installation_id = :installationId AND revision = :expectedRevision")
    suspend fun deleteCas(installationId: String, expectedRevision: Long): Int

    @Query("SELECT COUNT(*) FROM management_accesses WHERE installation_id = :installationId")
    suspend fun managementReferenceCount(installationId: String): Long

    @Query("SELECT COUNT(*) FROM web_panel_accesses WHERE installation_id = :installationId")
    suspend fun webPanelReferenceCount(installationId: String): Long

    @Query("SELECT COUNT(*) FROM operation_snapshots WHERE installation_id = :installationId")
    suspend fun operationReferenceCount(installationId: String): Long
}

@Dao
interface ManagementAccessDao {
    @Query(
        """
        SELECT * FROM management_accesses
        WHERE installation_id = :installationId AND server_access_id = :serverAccessId
        LIMIT 1
        """,
    )
    suspend fun get(installationId: String, serverAccessId: String): ManagementAccessEntity?

    @Query("SELECT * FROM management_accesses WHERE installation_id = :installationId ORDER BY server_access_id")
    suspend fun listForInstallation(installationId: String): List<ManagementAccessEntity>

    @Query("SELECT * FROM management_accesses WHERE server_access_id = :serverAccessId ORDER BY installation_id")
    suspend fun listForServerAccess(serverAccessId: String): List<ManagementAccessEntity>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(entity: ManagementAccessEntity): Long

    @Query(
        """
        DELETE FROM management_accesses
        WHERE installation_id = :installationId AND server_access_id = :serverAccessId
        """,
    )
    suspend fun delete(installationId: String, serverAccessId: String): Int
}

@Dao
interface WebPanelAccessDao {
    @Query("SELECT * FROM web_panel_accesses WHERE web_panel_access_id = :webPanelAccessId LIMIT 1")
    suspend fun get(webPanelAccessId: String): WebPanelAccessEntity?

    @Query("SELECT * FROM web_panel_accesses ORDER BY web_panel_access_id")
    suspend fun list(): List<WebPanelAccessEntity>

    @Query("SELECT password_secret_id FROM web_panel_accesses ORDER BY web_panel_access_id")
    suspend fun listPasswordSecretIds(): List<String>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(entity: WebPanelAccessEntity): Long

    @Query(
        """
        UPDATE web_panel_accesses
        SET installation_link_kind = :installationLinkKind,
            installation_id = :installationId,
            bound_server_id = :boundServerId,
            username = :username,
            password_secret_id = :passwordSecretId,
            route_kind = :routeKind,
            route_origin_host = :routeOriginHost,
            route_server_access_id = :routeServerAccessId,
            revision = :nextRevision
        WHERE web_panel_access_id = :webPanelAccessId AND revision = :expectedRevision
        """,
    )
    suspend fun updateCas(
        webPanelAccessId: String,
        installationLinkKind: String,
        installationId: String?,
        boundServerId: String?,
        username: String,
        passwordSecretId: String,
        routeKind: String,
        routeOriginHost: String?,
        routeServerAccessId: String?,
        expectedRevision: Long,
        nextRevision: Long,
    ): Int

    @Query(
        """
        UPDATE web_panel_accesses
        SET username = :newUsername, password_secret_id = :newSecretId, revision = :nextRevision
        WHERE web_panel_access_id = :webPanelAccessId
          AND password_secret_id = :expectedSecretId
          AND revision = :expectedRevision
        """,
    )
    suspend fun swapCredentialCas(
        webPanelAccessId: String,
        expectedSecretId: String,
        newSecretId: String,
        newUsername: String,
        expectedRevision: Long,
        nextRevision: Long,
    ): Int

    @Query(
        """
        UPDATE web_panel_accesses
        SET route_server_access_id = :newId, revision = revision + 1
        WHERE route_server_access_id = :oldId AND bound_server_id = :serverId
          AND revision < 9223372036854775807
        """,
    )
    suspend fun moveSshRoute(oldId: String, newId: String, serverId: String): Int

    @Query("DELETE FROM web_panel_accesses WHERE web_panel_access_id = :webPanelAccessId AND revision = :expectedRevision")
    suspend fun deleteCas(webPanelAccessId: String, expectedRevision: Long): Int
}
