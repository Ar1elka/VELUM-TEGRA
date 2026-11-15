package com.velumtegra.xuimobile.core.model

/** Management is a capability: exact installation + exact SSH access. */
data class ManagementAccess(
    val installationId: XuiInstallationId,
    val serverAccessId: ServerAccessId,
)
