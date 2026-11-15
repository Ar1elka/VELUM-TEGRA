package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallationId

/**
 * Read-only capability of the SAME durable operation journal, not a second history store.
 * At most 51 newest QUICK_INSPECT / DEEP_DIAGNOSTIC snapshots (including terminals),
 * ordered by start time descending then OperationId ascending. Every returned snapshot
 * must pass the journal's existing durable-evidence validation. No replay or mutation API.
 */
fun interface InstallationInspectionInventory {
    suspend fun recentInspections(
        serverId: ServerId,
        installationId: XuiInstallationId,
    ): OperationJournalResult<List<VersionedOperationSnapshot>>
}
