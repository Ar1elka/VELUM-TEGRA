package com.velumtegra.xuimobile.core.model

import java.time.Instant

enum class InstallationOwnership {
    MANAGED,
    ADOPTED,
}

data class InstallationIdentity(
    val serviceUnit: String,
    val binaryPath: String,
    val rootPath: String,
    val databasePath: String,
    val managedInstallId: ManagedInstallId?,
) {
    init {
        require(serviceUnit.isNotBlank())
        require(binaryPath.startsWith('/'))
        require(rootPath.startsWith('/'))
        require(databasePath.startsWith('/'))
    }
}

data class InstallationBaseline(
    val serviceUnit: String,
    val binaryPath: String,
    val rootPath: String,
    val databasePath: String,
    val panelPort: Int,
    val webBasePath: String,
    val listenAddress: String?,
    val capturedAt: Instant,
) {
    init {
        require(panelPort in 1..65535)
        require(webBasePath.startsWith('/'))
    }
}

/** A concrete 3X-UI installation on one Server. */
data class XuiInstallation(
    val id: XuiInstallationId,
    val serverId: ServerId,
    val ownership: InstallationOwnership,
    val identity: InstallationIdentity,
    val baseline: InstallationBaseline,
) {
    init {
        when (ownership) {
            InstallationOwnership.MANAGED -> requireNotNull(identity.managedInstallId) {
                "Managed installation requires a managedInstallId"
            }
            InstallationOwnership.ADOPTED -> require(identity.managedInstallId == null) {
                "Adopted installation must not have a managedInstallId"
            }
        }
    }
}
