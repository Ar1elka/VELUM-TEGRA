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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SavedLinkedWebPanelLaunchTest {
    private val linked = ResolvedWebPanelInstallation.Linked(
        installationId = XuiInstallationId("i-1"),
        installationRevision = RecordRevision(4),
        serverId = ServerId("s-1"),
    )
    private fun direct(scheme: WebPanelScheme = WebPanelScheme.HTTPS, path: String = "/secret/") =
        ResolvedWebPanelRouteTarget.Direct(DirectWebPanelOrigin(
            scheme, WebPanelHost("panel.example.com"), 2053, WebPanelBasePath(path),
        ))

    @Test fun `linked direct target uses saved host port and path`() {
        assertEquals("https://panel.example.com:2053/secret/", savedLinkedWebPanelHttpsUrl(linked, direct()))
    }

    @Test fun `no silent HTTPS upgrade or standalone guessing`() {
        assertNull(savedLinkedWebPanelHttpsUrl(linked, direct(WebPanelScheme.HTTP)))
        assertNull(savedLinkedWebPanelHttpsUrl(ResolvedWebPanelInstallation.Standalone, direct()))
    }

    @Test fun `SSH tunnel cannot be mistaken for direct host`() {
        val sshRoute = ResolvedWebPanelRouteTarget.SshTunnel(
            serverAccessId = ServerAccessId("ssh-1"),
            serverId = ServerId("s-1"),
            remoteEndpoint = WebPanelRemoteEndpoint(WebPanelHost("127.0.0.1"), 2053),
            scheme = WebPanelScheme.HTTPS,
            webBasePath = WebPanelBasePath("/secret/"),
        )
        assertNull(savedLinkedWebPanelHttpsUrl(linked, sshRoute))
    }

    @Test fun `saved path must pass strict exact HTTPS validator`() {
        assertEquals("https://panel.example.com:2053/", savedLinkedWebPanelHttpsUrl(linked, direct(path="/")))
    }
}
