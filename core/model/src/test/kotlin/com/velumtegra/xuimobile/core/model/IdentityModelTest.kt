package com.velumtegra.xuimobile.core.model

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityModelTest {
    @Test
    fun `server identity is independent from ssh endpoint`() {
        val serverId = ServerId("server-a")
        val accessA = ServerAccess(
            id = ServerAccessId("access-a"),
            serverId = serverId,
            endpoint = SshEndpoint("203.0.113.10", 22),
            username = "root",
            auth = SshAuthRef.Password(SecretId("secret-a")),
            pinnedHostKey = HostKeyFingerprint("SHA256:a"),
        )
        val accessB = accessA.copy(
            id = ServerAccessId("access-b"),
            endpoint = SshEndpoint("example.test", 2222),
        )

        assertEquals(accessA.serverId, accessB.serverId)
        assertNotEquals(accessA.id, accessB.id)
    }

    @Test
    fun `installer is operation type not persistent owner`() {
        assertEquals(OperationType.INSTALL, OperationType.valueOf("INSTALL"))
        val owner: SessionOwner = SessionOwner.Operation(OperationId("install-op"))
        assertEquals(OperationId("install-op"), (owner as SessionOwner.Operation).operationId)
    }

    @Test
    fun `web panel access may be standalone`() {
        val access = WebPanelAccess(
            id = WebPanelAccessId("web-standalone"),
            installationLink = WebPanelInstallationLink.Standalone,
            username = "panel-user",
            passwordSecretId = SecretId("panel-secret"),
            route = WebPanelRoute.Direct("panel.example.test"),
        )

        assertEquals(WebPanelInstallationLink.Standalone, access.installationLink)
    }

    @Test
    fun `web panel access can explicitly link to installation`() {
        val installationId = XuiInstallationId("xui-a")
        val access = WebPanelAccess(
            id = WebPanelAccessId("web-a"),
            installationLink = WebPanelInstallationLink.Linked(installationId),
            username = "panel-user",
            passwordSecretId = SecretId("panel-secret"),
            route = WebPanelRoute.SshTunnel(ServerAccessId("access-a")),
        )

        val link = access.installationLink
        assertTrue(link is WebPanelInstallationLink.Linked)
        assertEquals(installationId, (link as WebPanelInstallationLink.Linked).installationId)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `managed installation cannot exist without managed install id`() {
        val now = Instant.parse("2026-08-30T09:00:00Z")
        val identity = InstallationIdentity(
            "x-ui.service",
            "/usr/local/x-ui/x-ui",
            "/usr/local/x-ui",
            "/etc/x-ui/x-ui.db",
            null,
        )
        XuiInstallation(
            id = XuiInstallationId("xui-a"),
            serverId = ServerId("server-a"),
            ownership = InstallationOwnership.MANAGED,
            identity = identity,
            baseline = InstallationBaseline(
                identity.serviceUnit,
                identity.binaryPath,
                identity.rootPath,
                identity.databasePath,
                2053,
                "/hidden/",
                "127.0.0.1",
                now,
            ),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `adopted installation cannot carry managed install id`() {
        val now = Instant.parse("2026-08-30T09:00:00Z")
        val identity = InstallationIdentity(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            managedInstallId = ManagedInstallId("managed-a"),
        )

        XuiInstallation(
            id = XuiInstallationId("xui-a"),
            serverId = ServerId("server-a"),
            ownership = InstallationOwnership.ADOPTED,
            identity = identity,
            baseline = InstallationBaseline(
                serviceUnit = identity.serviceUnit,
                binaryPath = identity.binaryPath,
                rootPath = identity.rootPath,
                databasePath = identity.databasePath,
                panelPort = 2053,
                webBasePath = "/hidden/",
                listenAddress = "127.0.0.1",
                capturedAt = now,
            ),
        )
    }
}
