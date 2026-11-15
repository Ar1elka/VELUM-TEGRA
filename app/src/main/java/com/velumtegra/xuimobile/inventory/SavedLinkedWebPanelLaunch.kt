package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelInstallation
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelRouteTarget
import com.velumtegra.xuimobile.core.domain.WebPanelScheme

/**
 * Only a linked DIRECT HTTPS target resolved against the CURRENT local records can open.
 * The standard 3x-ui UI handles credentials itself; this function never accesses SecretStore.
 * Standalone/SSH-tunnel routes, stale/broken records and non-HTTPS targets have no fallback.
 * Does not perform a network connection or write server settings.
 */
internal fun savedLinkedWebPanelHttpsUrl(
    installation: ResolvedWebPanelInstallation,
    route: ResolvedWebPanelRouteTarget,
): String? {
    if (installation !is ResolvedWebPanelInstallation.Linked) return null
    if (route !is ResolvedWebPanelRouteTarget.Direct) return null
    val origin = route.origin
    if (origin.scheme != WebPanelScheme.HTTPS) return null
    return linkedInstallationHttpsUrl(origin.host.value, origin.port, origin.webBasePath.value)
}
