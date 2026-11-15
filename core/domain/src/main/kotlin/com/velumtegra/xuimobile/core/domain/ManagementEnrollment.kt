package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.DiscoveryProof
import com.velumtegra.xuimobile.core.model.DiscoveryProofSignal
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId

/**
 * Explicit process-local Discovery proof handoff into durable Management enrollment.
 *
 * There is intentionally no constructor from a durable/coarse Discovery terminal summary. The full
 * [DiscoveryProof] must still exist in the current process and the accepted baseline must describe
 * exactly the same installation identity.
 */
data class ManagementEnrollmentRequest(
    val proof: DiscoveryProof,
    val baseline: InstallationBaseline,
    val proposedInstallationId: XuiInstallationId,
) {
    init {
        require(proposedInstallationId.value.isNotBlank()) { "proposedInstallationId must not be blank" }
        require(REQUIRED_IDENTITY_SIGNALS.all { it in proof.supportingSignals }) {
            "Management enrollment requires a complete proven installation identity"
        }
        require(baseline.matches(proof.observedIdentity)) {
            "Management baseline must match the exact Discovery installation identity"
        }
    }

    val expectedOwnership: InstallationOwnership
        get() = if (proof.observedIdentity.managedInstallId != null) {
            InstallationOwnership.MANAGED
        } else {
            InstallationOwnership.ADOPTED
        }

    fun newInstallation(): XuiInstallation = XuiInstallation(
        id = proposedInstallationId,
        serverId = proof.scope.serverId,
        ownership = expectedOwnership,
        identity = proof.observedIdentity,
        baseline = baseline,
    )

    companion object {
        private val REQUIRED_IDENTITY_SIGNALS = setOf(
            DiscoveryProofSignal.SERVICE_UNIT,
            DiscoveryProofSignal.BINARY_PATH,
            DiscoveryProofSignal.ROOT_PATH,
            DiscoveryProofSignal.DATABASE_PATH,
        )
    }
}

private fun InstallationBaseline.matches(identity: InstallationIdentity): Boolean =
    serviceUnit == identity.serviceUnit &&
        binaryPath == identity.binaryPath &&
        rootPath == identity.rootPath &&
        databasePath == identity.databasePath

enum class ManagementEnrollmentRejection {
    SERVER_NOT_FOUND,
    SERVER_ACCESS_NOT_FOUND,
    SERVER_ACCESS_SCOPE_MISMATCH,
    INSTALLATION_ID_CONFLICT,
    INSTALLATION_IDENTITY_CONFLICT,
    MANAGED_MARKER_CONFLICT,
    INSTALLATION_BASELINE_CONFLICT,
    DURABLE_INSTALLATION_AMBIGUOUS,
}

/** Safe publication result: no raw SQLite/SSH/secret text crosses this feature boundary. */
sealed interface ManagementEnrollmentPublicationResult {
    data class Published(
        val installation: VersionedRecord<XuiInstallation>,
        val managementAccess: ManagementAccess,
        val installationCreated: Boolean,
        val managementAccessCreated: Boolean,
    ) : ManagementEnrollmentPublicationResult

    data class Rejected(
        val reason: ManagementEnrollmentRejection,
    ) : ManagementEnrollmentPublicationResult

    data object Corruption : ManagementEnrollmentPublicationResult
    data object StorageFailure : ManagementEnrollmentPublicationResult
}

/**
 * One atomic local publication boundary for `XuiInstallation + ManagementAccess`.
 * Feature code must not emulate enrollment with two unrelated repository calls.
 */
interface ManagementEnrollmentPublisher {
    suspend fun publish(request: ManagementEnrollmentRequest): ManagementEnrollmentPublicationResult

    /** Phase 8 fresh-install publication after exact remote post-install verification. */
    suspend fun publishInstaller(
        request: InstallerManagementPublicationRequest,
    ): ManagementEnrollmentPublicationResult

    /** Phase 9 managed reinstall publication: CAS-update the same logical installation row. */
    suspend fun republishReinstall(
        request: ExistingInstallationReinstallPublicationRequest,
    ): ExistingInstallationReinstallPublicationResult =
        ExistingInstallationReinstallPublicationResult.Rejected(
            ExistingInstallationReinstallPublicationRejection.PUBLISHER_UNSUPPORTED,
        )
}
