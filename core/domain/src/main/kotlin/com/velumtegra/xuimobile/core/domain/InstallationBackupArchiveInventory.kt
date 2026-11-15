package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallationId

/**
 * Read-only capability of the SAME durable operation journal, not a second history store.
 * At most 10 newest INSTALLATION_BACKUP snapshots of exactly this server, installation and SSH access
 * that are SUCCEEDED with a TERMINAL VERIFIED checkpoint, ordered by start time descending then
 * OperationId ascending. Database backups are never included. No replay or mutation API; callers
 * must still re-check every row with [InstallationBackupBindingPolicy].
 */
fun interface InstallationBackupArchiveInventory {
    suspend fun recentVerifiedArchives(
        serverId: ServerId,
        installationId: XuiInstallationId,
        accessId: ServerAccessId,
    ): OperationJournalResult<List<VersionedOperationSnapshot>>
}
