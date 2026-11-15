package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId

/**
 * Exact local publication request after one managed Phase 9 REINSTALL has been remotely verified.
 * The same logical installation row is updated by CAS; no duplicate installation/WebPanel state is
 * created here and no remote work is reachable from this request.
 */
data class ExistingInstallationReinstallPublicationRequest(
    val operationId: OperationId,
    val serverId: ServerId,
    val serverAccessId: ServerAccessId,
    val installationId: XuiInstallationId,
    val expectedRevision: RecordRevision,
    val expectedIdentity: InstallationIdentity,
    val verifiedBaseline: InstallationBaseline,
) {
    init {
        require(operationId.value.isNotBlank()) { "operationId must not be blank" }
        require(expectedIdentity.managedInstallId != null) { "Managed reinstall requires managedInstallId" }
        require(verifiedBaseline.serviceUnit == expectedIdentity.serviceUnit)
        require(verifiedBaseline.binaryPath == expectedIdentity.binaryPath)
        require(verifiedBaseline.rootPath == expectedIdentity.rootPath)
        require(verifiedBaseline.databasePath == expectedIdentity.databasePath)
    }

    fun updatedInstallation(existing: XuiInstallation): XuiInstallation {
        require(existing.id == installationId) { "Reinstall publication installation id changed" }
        require(existing.serverId == serverId) { "Reinstall publication server id changed" }
        require(existing.ownership == InstallationOwnership.MANAGED) { "Reinstall publication requires MANAGED ownership" }
        require(existing.identity == expectedIdentity) { "Reinstall publication identity changed" }
        return existing.copy(baseline = verifiedBaseline)
    }
}

enum class ExistingInstallationReinstallPublicationRejection {
    PUBLISHER_UNSUPPORTED,
    SERVER_NOT_FOUND,
    SERVER_ACCESS_NOT_FOUND,
    SERVER_ACCESS_SCOPE_MISMATCH,
    INSTALLATION_NOT_FOUND,
    INSTALLATION_REVISION_STALE,
    INSTALLATION_SCOPE_MISMATCH,
    INSTALLATION_NOT_MANAGED,
    MANAGED_IDENTITY_MISMATCH,
    MANAGEMENT_ACCESS_MISSING,
}

sealed interface ExistingInstallationReinstallPublicationResult {
    data class Published(
        val installation: VersionedRecord<XuiInstallation>,
        val managementAccess: ManagementAccess,
        val baselineUpdated: Boolean,
    ) : ExistingInstallationReinstallPublicationResult

    data class Rejected(
        val reason: ExistingInstallationReinstallPublicationRejection,
    ) : ExistingInstallationReinstallPublicationResult

    data object Corruption : ExistingInstallationReinstallPublicationResult
    data object StorageFailure : ExistingInstallationReinstallPublicationResult
}
