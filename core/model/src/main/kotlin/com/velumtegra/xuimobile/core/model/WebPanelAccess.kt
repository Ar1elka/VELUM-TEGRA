package com.velumtegra.xuimobile.core.model

sealed interface WebPanelRoute {
    data class SshTunnel(val serverAccessId: ServerAccessId) : WebPanelRoute

    /** Direct origin host; panel port/base path are installation state, not credential identity. */
    data class Direct(val originHost: String) : WebPanelRoute {
        init {
            require(originHost.isNotBlank())
        }
    }
}

/**
 * WebPanel credentials may exist before an installation relationship is proven.
 * Linking is explicit so standalone local access cannot be mistaken for a proven installation.
 */
sealed interface WebPanelInstallationLink {
    data object Standalone : WebPanelInstallationLink
    data class Linked(val installationId: XuiInstallationId) : WebPanelInstallationLink
}

/** Local knowledge needed to authenticate to a web panel. Deleting it is local-only. */
data class WebPanelAccess(
    val id: WebPanelAccessId,
    val installationLink: WebPanelInstallationLink,
    val username: String,
    val passwordSecretId: SecretId,
    val route: WebPanelRoute,
) {
    init {
        require(username.isNotBlank())
    }
}
