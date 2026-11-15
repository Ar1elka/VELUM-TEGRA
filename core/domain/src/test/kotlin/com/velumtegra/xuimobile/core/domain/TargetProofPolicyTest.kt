package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TargetProofPolicyTest {
    private val now = Instant.parse("2026-08-30T09:00:00Z")
    private val serverId = ServerId("server-a")
    private val accessId = ServerAccessId("access-a")
    private val installationId = XuiInstallationId("xui-a")
    private val identity = InstallationIdentity(
        serviceUnit = "x-ui.service",
        binaryPath = "/usr/local/x-ui/x-ui",
        rootPath = "/usr/local/x-ui",
        databasePath = "/etc/x-ui/x-ui.db",
        managedInstallId = null,
    )
    private val baseline = InstallationBaseline(
        serviceUnit = identity.serviceUnit,
        binaryPath = identity.binaryPath,
        rootPath = identity.rootPath,
        databasePath = identity.databasePath,
        panelPort = 2053,
        webBasePath = "/hidden/",
        listenAddress = "127.0.0.1",
        capturedAt = now,
    )
    private val installation = XuiInstallation(
        id = installationId,
        serverId = serverId,
        ownership = InstallationOwnership.ADOPTED,
        identity = identity,
        baseline = baseline,
    )
    private val access = ServerAccess(
        id = accessId,
        serverId = serverId,
        endpoint = SshEndpoint("203.0.113.10", 22),
        username = "root",
        auth = SshAuthRef.Password(SecretId("ssh-secret")),
        pinnedHostKey = HostKeyFingerprint("SHA256:test"),
    )

    private fun proof(
        proofAccessId: ServerAccessId = accessId,
        proofInstallationId: XuiInstallationId = installationId,
        observedIdentity: InstallationIdentity = identity,
        validUntil: Instant = now.plusSeconds(60),
    ) = InstallationProof(
        id = TargetProofId("proof"),
        installationId = proofInstallationId,
        serverId = serverId,
        serverAccessId = proofAccessId,
        observedIdentity = observedIdentity,
        observedAt = now,
        validUntil = validUntil,
    )

    @Test
    fun `exact fresh proof authorizes mutation type`() {
        val result = TargetProofPolicy.verifyKnownInstallation(installation, access, proof(), now)
        assertTrue(result is TargetVerificationResult.Verified)
        val verified = (result as TargetVerificationResult.Verified).target
        assertTrue(MutationAuthorizationPolicy.mayEnterMutation(verified))
    }

    @Test
    fun `proof through another access path is rejected`() {
        val result = TargetProofPolicy.verifyKnownInstallation(
            installation,
            access,
            proof(proofAccessId = ServerAccessId("other-access")),
            now,
        )
        assertTrue(result is TargetVerificationResult.Rejected)
    }

    @Test
    fun `proof for another installation is rejected`() {
        val result = TargetProofPolicy.verifyKnownInstallation(
            installation,
            access,
            proof(proofInstallationId = XuiInstallationId("other-xui")),
            now,
        )
        assertTrue(result is TargetVerificationResult.Rejected)
    }

    @Test
    fun `stale proof is rejected`() {
        val result = TargetProofPolicy.verifyKnownInstallation(
            installation,
            access,
            proof().copy(
                observedAt = now.minusSeconds(120),
                validUntil = now.minusSeconds(1),
            ),
            now,
        )
        assertTrue(result is TargetVerificationResult.Rejected)
    }

    @Test
    fun `changed installation identity is rejected`() {
        val changed = identity.copy(binaryPath = "/opt/x-ui/x-ui")
        val result = TargetProofPolicy.verifyKnownInstallation(
            installation,
            access,
            proof(observedIdentity = changed),
            now,
        )
        assertFalse(result is TargetVerificationResult.Verified)
    }
}
