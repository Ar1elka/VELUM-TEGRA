package com.velumtegra.xuimobile.core.site

import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentDurableReplayFenceTest {
    @Test
    fun `durable fence survives reconstruction and preserves one-shot semantics for reviewed production boundaries`() {
        val root = Files.createTempDirectory("phase11-21-durable-fence-").toFile()
        val permitSha = "a".repeat(64)
        val invocationSha = "b".repeat(64)
        val acquisitionHandoffSha = "c".repeat(64)
        val credentialResolutionHandoffSha = "f".repeat(64)
        val credentialResolutionExecutionReceiptSha = "9".repeat(64)
        val sshSessionAcquisitionHandoffSha = "8".repeat(64)
        val sftpChannelOpenHandoffSha = "7".repeat(64)
        val sftpReadOnlyPreflightHandoffSha = "6".repeat(64)
        val realVpsReadOnlyPreflightHandoffSha = "5".repeat(64)
        val realVpsCredentialResolutionHandoffSha = "4".repeat(64)
        val realVpsCredentialResolutionExecutionReceiptSha = "3".repeat(64)
        val realVpsSshSessionAcquisitionHandoffSha = "2".repeat(64)
        val realVpsSshSessionAcquisitionExecutionReceiptSha = "1".repeat(64)
        val realVpsSftpChannelOpenHandoffSha = "0".repeat(64)
        val realVpsSftpChannelOpenExecutionReceiptSha = "b".repeat(64)
        val realVpsSftpReadOnlyPreflightHandoffSha = "c".repeat(64)
        val realVpsSftpReadOnlyPreflightExecutionReceiptSha = "a".repeat(64)

        val firstProcess = SiteProductionDeploymentDurableReplayFence.open(root)
        assertTrue(firstProcess.runtimeMutationConsumptionPort().consumeOnce(permitSha))
        assertTrue(firstProcess.coordinatorInvocationUsePort().consumeOnce(invocationSha))
        assertTrue(firstProcess.transportAcquisitionHandoffConsumptionPort().consumeOnce(acquisitionHandoffSha))
        assertTrue(firstProcess.credentialResolutionHandoffConsumptionPort().consumeOnce(credentialResolutionHandoffSha))
        assertTrue(firstProcess.credentialResolutionExecutionUsePort().consumeOnce(credentialResolutionExecutionReceiptSha))
        assertTrue(firstProcess.sshSessionAcquisitionHandoffConsumptionPort().consumeOnce(sshSessionAcquisitionHandoffSha))
        assertTrue(firstProcess.sftpChannelOpenHandoffConsumptionPort().consumeOnce(sftpChannelOpenHandoffSha))
        assertTrue(firstProcess.sftpReadOnlyPreflightHandoffConsumptionPort().consumeOnce(sftpReadOnlyPreflightHandoffSha))
        assertTrue(firstProcess.realVpsReadOnlyPreflightHandoffConsumptionPort().consumeOnce(realVpsReadOnlyPreflightHandoffSha))
        assertTrue(firstProcess.realVpsCredentialResolutionHandoffConsumptionPort().consumeOnce(realVpsCredentialResolutionHandoffSha))
        assertTrue(firstProcess.realVpsCredentialResolutionExecutionUsePort().consumeOnce(realVpsCredentialResolutionExecutionReceiptSha))
        assertTrue(firstProcess.realVpsSshSessionAcquisitionHandoffConsumptionPort().consumeOnce(realVpsSshSessionAcquisitionHandoffSha))
        assertTrue(firstProcess.realVpsSshSessionAcquisitionExecutionUsePort().consumeOnce(realVpsSshSessionAcquisitionExecutionReceiptSha))
        assertTrue(firstProcess.realVpsSftpChannelOpenHandoffConsumptionPort().consumeOnce(realVpsSftpChannelOpenHandoffSha))
        assertTrue(firstProcess.realVpsSftpChannelOpenExecutionUsePort().consumeOnce(realVpsSftpChannelOpenExecutionReceiptSha))
        assertTrue(firstProcess.realVpsSftpReadOnlyPreflightHandoffConsumptionPort().consumeOnce(realVpsSftpReadOnlyPreflightHandoffSha))
        assertTrue(firstProcess.realVpsSftpReadOnlyPreflightExecutionUsePort().consumeOnce(realVpsSftpReadOnlyPreflightExecutionReceiptSha))

        val restartedProcess = SiteProductionDeploymentDurableReplayFence.open(root)
        assertFalse(restartedProcess.runtimeMutationConsumptionPort().consumeOnce(permitSha))
        assertFalse(restartedProcess.coordinatorInvocationUsePort().consumeOnce(invocationSha))
        assertFalse(restartedProcess.transportAcquisitionHandoffConsumptionPort().consumeOnce(acquisitionHandoffSha))
        assertFalse(restartedProcess.credentialResolutionHandoffConsumptionPort().consumeOnce(credentialResolutionHandoffSha))
        assertFalse(restartedProcess.credentialResolutionExecutionUsePort().consumeOnce(credentialResolutionExecutionReceiptSha))
        assertFalse(restartedProcess.sshSessionAcquisitionHandoffConsumptionPort().consumeOnce(sshSessionAcquisitionHandoffSha))
        assertFalse(restartedProcess.sftpChannelOpenHandoffConsumptionPort().consumeOnce(sftpChannelOpenHandoffSha))
        assertFalse(restartedProcess.sftpReadOnlyPreflightHandoffConsumptionPort().consumeOnce(sftpReadOnlyPreflightHandoffSha))
        assertFalse(restartedProcess.realVpsReadOnlyPreflightHandoffConsumptionPort().consumeOnce(realVpsReadOnlyPreflightHandoffSha))
        assertFalse(restartedProcess.realVpsCredentialResolutionHandoffConsumptionPort().consumeOnce(realVpsCredentialResolutionHandoffSha))
        assertFalse(restartedProcess.realVpsCredentialResolutionExecutionUsePort().consumeOnce(realVpsCredentialResolutionExecutionReceiptSha))
        assertFalse(restartedProcess.realVpsSshSessionAcquisitionHandoffConsumptionPort().consumeOnce(realVpsSshSessionAcquisitionHandoffSha))
        assertFalse(restartedProcess.realVpsSshSessionAcquisitionExecutionUsePort().consumeOnce(realVpsSshSessionAcquisitionExecutionReceiptSha))
        assertFalse(restartedProcess.realVpsSftpChannelOpenHandoffConsumptionPort().consumeOnce(realVpsSftpChannelOpenHandoffSha))
        assertFalse(restartedProcess.realVpsSftpChannelOpenExecutionUsePort().consumeOnce(realVpsSftpChannelOpenExecutionReceiptSha))
        assertFalse(restartedProcess.realVpsSftpReadOnlyPreflightHandoffConsumptionPort().consumeOnce(realVpsSftpReadOnlyPreflightHandoffSha))
        assertFalse(restartedProcess.realVpsSftpReadOnlyPreflightExecutionUsePort().consumeOnce(realVpsSftpReadOnlyPreflightExecutionReceiptSha))
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.RUNTIME_MUTATION_PERMIT,
                permitSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.COORDINATOR_INVOCATION_AUTHORIZATION,
                invocationSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.TRANSPORT_ACQUISITION_HANDOFF_AUTHORIZATION,
                acquisitionHandoffSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION,
                credentialResolutionHandoffSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT,
                credentialResolutionExecutionReceiptSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION,
                sshSessionAcquisitionHandoffSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION,
                sftpChannelOpenHandoffSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
                sftpReadOnlyPreflightHandoffSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
                realVpsReadOnlyPreflightHandoffSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION,
                realVpsCredentialResolutionHandoffSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT,
                realVpsCredentialResolutionExecutionReceiptSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION,
                realVpsSshSessionAcquisitionHandoffSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_SSH_SESSION_ACQUISITION_EXECUTION_RECEIPT,
                realVpsSshSessionAcquisitionExecutionReceiptSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION,
                realVpsSftpChannelOpenHandoffSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_CHANNEL_OPEN_EXECUTION_RECEIPT,
                realVpsSftpChannelOpenExecutionReceiptSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
                realVpsSftpReadOnlyPreflightHandoffSha,
            ),
        )
        assertTrue(
            restartedProcess.hasConsumed(
                SiteProductionDeploymentReplayScope.REAL_VPS_SFTP_READ_ONLY_PREFLIGHT_EXECUTION_RECEIPT,
                realVpsSftpReadOnlyPreflightExecutionReceiptSha,
            ),
        )
        val snapshot = restartedProcess.snapshot()
        assertEquals(1, snapshot.runtimeMutationPermitMarkerCount)
        assertEquals(1, snapshot.coordinatorInvocationAuthorizationMarkerCount)
        assertEquals(1, snapshot.transportAcquisitionHandoffAuthorizationMarkerCount)
        assertEquals(1, snapshot.credentialResolutionHandoffAuthorizationMarkerCount)
        assertEquals(1, snapshot.credentialResolutionExecutionReceiptMarkerCount)
        assertEquals(1, snapshot.sshSessionAcquisitionHandoffAuthorizationMarkerCount)
        assertEquals(1, snapshot.sftpChannelOpenHandoffAuthorizationMarkerCount)
        assertEquals(1, snapshot.sftpReadOnlyPreflightHandoffAuthorizationMarkerCount)
        assertEquals(1, snapshot.realVpsReadOnlyPreflightHandoffAuthorizationMarkerCount)
        assertEquals(1, snapshot.realVpsCredentialResolutionHandoffAuthorizationMarkerCount)
        assertEquals(1, snapshot.realVpsCredentialResolutionExecutionReceiptMarkerCount)
        assertEquals(1, snapshot.realVpsSshSessionAcquisitionHandoffAuthorizationMarkerCount)
        assertEquals(1, snapshot.realVpsSshSessionAcquisitionExecutionReceiptMarkerCount)
        assertEquals(1, snapshot.realVpsSftpChannelOpenHandoffAuthorizationMarkerCount)
        assertEquals(1, snapshot.realVpsSftpChannelOpenExecutionReceiptMarkerCount)
        assertEquals(1, snapshot.realVpsSftpReadOnlyPreflightHandoffAuthorizationMarkerCount)
        assertEquals(1, snapshot.realVpsSftpReadOnlyPreflightExecutionReceiptMarkerCount)

        // Recovery is deliberately fail-closed: a marker that exists without valid metadata still
        // means the authorization may already have been consumed before a process stopped.
        val uncertainSha = "e".repeat(64)
        val namespace = File(root, "runtime-mutation-permit")
        assertTrue(namespace.isDirectory)
        val uncertainMarker = File(namespace, "$uncertainSha.consumed")
        assertTrue(uncertainMarker.createNewFile())
        assertFalse(
            SiteProductionDeploymentDurableReplayFence.open(root)
                .runtimeMutationConsumptionPort()
                .consumeOnce(uncertainSha),
        )

        // Cross-instance racing must have exactly one winner because marker creation is atomic.
        val raceSha = "d".repeat(64)
        val threads = 12
        val ready = CountDownLatch(threads)
        val start = CountDownLatch(1)
        val winners = AtomicInteger(0)
        val pool = Executors.newFixedThreadPool(threads)
        repeat(threads) {
            pool.submit {
                ready.countDown()
                start.await(5, TimeUnit.SECONDS)
                val fence = SiteProductionDeploymentDurableReplayFence.open(root)
                if (fence.coordinatorInvocationUsePort().consumeOnce(raceSha)) {
                    winners.incrementAndGet()
                }
            }
        }
        assertTrue(ready.await(5, TimeUnit.SECONDS))
        start.countDown()
        pool.shutdown()
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS))
        assertEquals(1, winners.get())
    }

    @Test
    fun `durable fence rejects invalid digests and invalid roots fail before authorization`() {
        val root = Files.createTempDirectory("phase11-21-invalid-").toFile()
        val fence = SiteProductionDeploymentDurableReplayFence.open(root)
        assertThrows(IllegalArgumentException::class.java) {
            fence.runtimeMutationConsumptionPort().consumeOnce("../not-a-digest")
        }

        val fileRoot = File(root, "not-a-directory")
        assertTrue(fileRoot.createNewFile())
        assertThrows(IllegalArgumentException::class.java) {
            SiteProductionDeploymentDurableReplayFence.open(fileRoot)
        }
    }
}
