package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelInstallation
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelRouteTarget

/**
 * Exact (server, installation) pair for the scoped Web Panel list opened from Management.
 * It only narrows what is shown/opened; it never grants access and carries no secrets.
 */
internal data class WebPanelInstallationScope(val serverId: String, val installationId: String)

/**
 * Re-checked on the CURRENT resolver result right before an HTTPS launch or SSH connection.
 * A profile re-linked to another installation/server after the list was read fails here.
 * A null scope (global section, manual standalone paths) keeps the previous behaviour.
 */
internal fun webPanelTargetMatchesScope(
    scope: WebPanelInstallationScope?,
    installation: ResolvedWebPanelInstallation,
    route: ResolvedWebPanelRouteTarget,
): Boolean {
    if (scope == null) return true
    val linked = installation as? ResolvedWebPanelInstallation.Linked ?: return false
    if (linked.installationId.value != scope.installationId || linked.serverId.value != scope.serverId) return false
    return when (route) {
        is ResolvedWebPanelRouteTarget.Direct -> true
        is ResolvedWebPanelRouteTarget.SshTunnel -> route.serverId.value == scope.serverId
    }
}
