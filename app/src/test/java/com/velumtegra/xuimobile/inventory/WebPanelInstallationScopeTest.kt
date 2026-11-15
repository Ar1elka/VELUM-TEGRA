package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.DirectWebPanelOrigin
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelInstallation
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelRouteTarget
import com.velumtegra.xuimobile.core.domain.WebPanelBasePath
import com.velumtegra.xuimobile.core.domain.WebPanelHost
import com.velumtegra.xuimobile.core.domain.WebPanelRemoteEndpoint
import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WebPanelInstallationScopeTest {
    private val scope = WebPanelInstallationScope("s-1", "i-1")
    private fun linked(server: String = "s-1", installation: String = "i-1") =
        ResolvedWebPanelInstallation.Linked(XuiInstallationId(installation), RecordRevision(1), ServerId(server))
    private val direct = ResolvedWebPanelRouteTarget.Direct(DirectWebPanelOrigin(
        WebPanelScheme.HTTPS, WebPanelHost("panel.example.com"), 2053, WebPanelBasePath("/p/")))
    private fun ssh(server: String = "s-1") = ResolvedWebPanelRouteTarget.SshTunnel(
        ServerAccessId("a-1"), ServerId(server), WebPanelRemoteEndpoint(WebPanelHost("127.0.0.1"), 2053),
        WebPanelScheme.HTTPS, WebPanelBasePath("/p/"))

    @Test fun `exact server and installation pass for direct and ssh`() {
        assertTrue(webPanelTargetMatchesScope(scope, linked(), direct))
        assertTrue(webPanelTargetMatchesScope(scope, linked(), ssh()))
    }

    @Test fun `profile re-linked to another installation or server is refused`() {
        assertFalse(webPanelTargetMatchesScope(scope, linked(installation = "i-2"), direct))
        assertFalse(webPanelTargetMatchesScope(scope, linked(server = "s-2"), direct))
        assertFalse(webPanelTargetMatchesScope(scope, linked(), ssh(server = "s-2")))
    }

    @Test fun `standalone never matches a scope`() {
        assertFalse(webPanelTargetMatchesScope(scope, ResolvedWebPanelInstallation.Standalone, direct))
    }

    @Test fun `global section without scope is unchanged`() {
        assertTrue(webPanelTargetMatchesScope(null, ResolvedWebPanelInstallation.Standalone, direct))
        assertTrue(webPanelTargetMatchesScope(null, linked(installation = "other"), ssh("x")))
    }
}
