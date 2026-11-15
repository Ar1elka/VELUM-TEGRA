package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.Instant

/**
 * Normalized, non-secret read-back from the fixed Phase 8.5 post-install SSH verifier.
 * Raw shell output, credentials and installer logs are intentionally not representable here.
 */
data class InstallerPostInstallFacts(
    val markerReadback: ManagedInstallMarkerReadbackState,
    val serviceUnitPresent: Boolean,
    val binaryPresent: Boolean,
    val rootPresent: Boolean,
    val databasePresent: Boolean,
    val serviceState: ManagementServiceState,
    val panelPort: Int,
    val webBasePath: String,
    val listenAddress: String?,
    val listenerPresent: Boolean,
    val observedAt: Instant,
) {
    init {
        require(panelPort in 1..65535) { "panelPort must be in 1..65535" }
        require(webBasePath.startsWith('/')) { "webBasePath must be absolute" }
        require(webBasePath == "/" || webBasePath.endsWith('/')) {
            "webBasePath must use canonical trailing-slash form"
        }
        require(webBasePath == webBasePath.trim()) { "webBasePath must already be normalized" }
        require('\n' !in webBasePath && '\r' !in webBasePath && '\u0000' !in webBasePath) {
            "webBasePath must not contain control delimiters"
        }
        listenAddress?.let {
            require(it == it.trim() && it.isNotBlank()) { "listenAddress must already be normalized" }
            require('\n' !in it && '\r' !in it && '\u0000' !in it) {
                "listenAddress must not contain control delimiters"
            }
        }
    }
}

enum class InstallerPostInstallRejection {
    MANAGED_MARKER_NOT_MATCHED,
    SERVICE_UNIT_NOT_PRESENT,
    BINARY_NOT_PRESENT,
    ROOT_NOT_PRESENT,
    DATABASE_NOT_PRESENT,
    SERVICE_NOT_ACTIVE,
    LISTENER_NOT_PRESENT,
}

sealed interface InstallerPostInstallVerificationDecision {
    data class Verified(val request: InstallerManagementPublicationRequest) : InstallerPostInstallVerificationDecision
    data class Rejected(val reason: InstallerPostInstallRejection) : InstallerPostInstallVerificationDecision
}

/** Fixed installation identity produced by the pinned OFFICIAL_3X_UI_LINUX_V1 installer. */
object InstallerPostInstallPolicy {
    const val SERVICE_UNIT: String = "x-ui.service"
    const val BINARY_PATH: String = "/usr/local/x-ui/x-ui"
    const val ROOT_PATH: String = "/usr/local/x-ui"
    const val DATABASE_PATH: String = "/etc/x-ui/x-ui.db"

    fun verify(
        scope: InstallerWorkerScope,
        facts: InstallerPostInstallFacts,
    ): InstallerPostInstallVerificationDecision {
        if (facts.markerReadback != ManagedInstallMarkerReadbackState.MATCH) {
            return InstallerPostInstallVerificationDecision.Rejected(
                InstallerPostInstallRejection.MANAGED_MARKER_NOT_MATCHED,
            )
        }
        if (!facts.serviceUnitPresent) {
            return InstallerPostInstallVerificationDecision.Rejected(
                InstallerPostInstallRejection.SERVICE_UNIT_NOT_PRESENT,
            )
        }
        if (!facts.binaryPresent) {
            return InstallerPostInstallVerificationDecision.Rejected(
                InstallerPostInstallRejection.BINARY_NOT_PRESENT,
            )
        }
        if (!facts.rootPresent) {
            return InstallerPostInstallVerificationDecision.Rejected(
                InstallerPostInstallRejection.ROOT_NOT_PRESENT,
            )
        }
        if (!facts.databasePresent) {
            return InstallerPostInstallVerificationDecision.Rejected(
                InstallerPostInstallRejection.DATABASE_NOT_PRESENT,
            )
        }
        if (facts.serviceState != ManagementServiceState.ACTIVE) {
            return InstallerPostInstallVerificationDecision.Rejected(
                InstallerPostInstallRejection.SERVICE_NOT_ACTIVE,
            )
        }
        if (!facts.listenerPresent) {
            return InstallerPostInstallVerificationDecision.Rejected(
                InstallerPostInstallRejection.LISTENER_NOT_PRESENT,
            )
        }

        val baseline = InstallationBaseline(
            serviceUnit = SERVICE_UNIT,
            binaryPath = BINARY_PATH,
            rootPath = ROOT_PATH,
            databasePath = DATABASE_PATH,
            panelPort = facts.panelPort,
            webBasePath = facts.webBasePath,
            listenAddress = facts.listenAddress,
            capturedAt = facts.observedAt,
        )
        return InstallerPostInstallVerificationDecision.Verified(
            InstallerManagementPublicationRequest(
                scope = scope,
                baseline = baseline,
                proposedInstallationId = installationIdFor(scope),
            ),
        )
    }

    fun installationIdFor(scope: InstallerWorkerScope): XuiInstallationId =
        XuiInstallationId("xui-${scope.managedInstallId.value}")
}

/** Exact already-verified local publication request for fresh Installer success. */
data class InstallerManagementPublicationRequest(
    val scope: InstallerWorkerScope,
    val baseline: InstallationBaseline,
    val proposedInstallationId: XuiInstallationId,
) {
    init {
        require(proposedInstallationId == InstallerPostInstallPolicy.installationIdFor(scope)) {
            "Installer publication id must be deterministic from ManagedInstallId"
        }
        require(baseline.serviceUnit == InstallerPostInstallPolicy.SERVICE_UNIT)
        require(baseline.binaryPath == InstallerPostInstallPolicy.BINARY_PATH)
        require(baseline.rootPath == InstallerPostInstallPolicy.ROOT_PATH)
        require(baseline.databasePath == InstallerPostInstallPolicy.DATABASE_PATH)
    }

    fun newInstallation(): XuiInstallation = XuiInstallation(
        id = proposedInstallationId,
        serverId = scope.serverId,
        ownership = InstallationOwnership.MANAGED,
        identity = InstallationIdentity(
            serviceUnit = InstallerPostInstallPolicy.SERVICE_UNIT,
            binaryPath = InstallerPostInstallPolicy.BINARY_PATH,
            rootPath = InstallerPostInstallPolicy.ROOT_PATH,
            databasePath = InstallerPostInstallPolicy.DATABASE_PATH,
            managedInstallId = scope.managedInstallId,
        ),
        baseline = baseline,
    )
}
