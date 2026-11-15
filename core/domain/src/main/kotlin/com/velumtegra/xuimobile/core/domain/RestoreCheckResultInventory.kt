package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallationId

/**
 * Read-only capability of the SAME durable operation journal. At most 5 newest INSTALLATION_RESTORE_CHECK
 * snapshots of exactly this server, installation and SSH access that are SUCCEEDED with a TERMINAL checkpoint
 * whose phase name starts with the exact [phasePrefix] (verified phase + parent binding + parent revision),
 * ordered by update time descending then OperationId ascending. Callers must still re-check every row with
 * [RestoreCheckBindingPolicy.matches]. No replay or mutation API.
 */
fun interface RestoreCheckResultInventory {
    suspend fun recentVerifiedRestoreChecks(
        serverId: ServerId,
        installationId: XuiInstallationId,
        accessId: ServerAccessId,
        phasePrefix: String,
    ): OperationJournalResult<List<VersionedOperationSnapshot>>
}
