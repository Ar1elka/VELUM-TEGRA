package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Test

class ExistingInstallationRestartConfirmationPolicyTest {
    private val now = Instant.parse("2026-10-14T10:00:00Z")
    private val server = ServerId("fixture-server")
    private val access = ServerAccess(ServerAccessId("fixture-access"), server,
        SshEndpoint("fixture.invalid", 22), "operator", SshAuthRef.Password(SecretId("fixture-reference")),
        HostKeyFingerprint("SHA256:fixture"))
    private val installation = XuiInstallation(XuiInstallationId("fixture-installation"), server,
        InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db",
            2053, "/panel/", "127.0.0.1", now.minusSeconds(60)))
    private val current = VersionedOperationSnapshot(OperationSnapshot(OperationId("fixture-operation"),
        OperationType.RESTART, OperationTarget.InstallationTarget(server, access.id, installation.id),
        OperationStatus.RUNNING, OperationCheckpoint("RESTART_USER_CONFIRMED", CheckpointSemantics.MUTATION_NOT_STARTED, now),
        now, now), OperationRevision(7))

    @Test fun `confirmation binds exact revision target and reviewed metadata for ninety seconds`() {
        val c = (ExistingInstallationRestartConfirmationPolicy.confirm(current, installation, access, now)
            as ExistingInstallationRestartConfirmationResult.Confirmed).confirmation
        assertEquals(current.snapshot.operationId, c.operationId)
        assertEquals(current.revision, c.operationRevision)
        assertEquals(current.snapshot.target, c.target)
        assertEquals(installation, c.expectedInstallation)
        assertEquals(access, c.expectedAccess)
        assertEquals(now.plusSeconds(90), c.validUntil)
    }

    @Test fun `foreign target or access never receives confirmation`() {
        val target = current.snapshot.target as OperationTarget.InstallationTarget
        val foreignTargets = listOf(target.copy(serverId = ServerId("other-server")),
            target.copy(serverAccessId = ServerAccessId("other-access")),
            target.copy(installationId = XuiInstallationId("other-installation")))
        for (foreign in foreignTargets) assertEquals(ExistingInstallationRestartConfirmationResult.Rejected,
            ExistingInstallationRestartConfirmationPolicy.confirm(current.copy(snapshot = current.snapshot.copy(target = foreign)), installation, access, now))
        assertEquals(ExistingInstallationRestartConfirmationResult.Rejected,
            ExistingInstallationRestartConfirmationPolicy.confirm(current, installation, access.copy(serverId = ServerId("other-server")), now))
    }

    @Test fun `unsafe durable checkpoints cannot recreate mutation consent`() {
        for (semantics in listOf(CheckpointSemantics.RESTART_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED,
            CheckpointSemantics.COMMIT_VERIFIED, CheckpointSemantics.TERMINAL)) {
            val unsafe = current.copy(snapshot = current.snapshot.copy(checkpoint = OperationCheckpoint("RECOVERED", semantics, now)))
            assertEquals(ExistingInstallationRestartConfirmationResult.Rejected,
                ExistingInstallationRestartConfirmationPolicy.confirm(unsafe, installation, access, now))
        }
    }

    @Test fun `baseline identity drift and non restart requests are rejected`() {
        assertEquals(ExistingInstallationRestartConfirmationResult.Rejected,
            ExistingInstallationRestartConfirmationPolicy.confirm(current,
                installation.copy(baseline = installation.baseline.copy(binaryPath = "/other/x-ui")), access, now))
        assertEquals(ExistingInstallationRestartConfirmationResult.Rejected,
            ExistingInstallationRestartConfirmationPolicy.confirm(current.copy(snapshot = current.snapshot.copy(type = OperationType.UNINSTALL)), installation, access, now))
        assertEquals(ExistingInstallationRestartConfirmationResult.Rejected,
            ExistingInstallationRestartConfirmationPolicy.confirm(current.copy(snapshot = current.snapshot.copy(status = OperationStatus.CANCELLED)), installation, access, now))
    }

    @Test fun `regressed confirmation time is rejected`() {
        assertEquals(ExistingInstallationRestartConfirmationResult.Rejected,
            ExistingInstallationRestartConfirmationPolicy.confirm(current, installation, access, now.minusSeconds(1)))
    }
}
