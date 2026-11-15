package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.DiscoveryProof
import com.velumtegra.xuimobile.core.model.DiscoveryProofId
import com.velumtegra.xuimobile.core.model.DiscoveryProofSignal
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class ManagementEnrollmentPolicyTest {
    private val observedAt = Instant.parse("2026-09-06T10:00:00Z")
    private val scope = DiscoveryScope(
        operationId = OperationId("discovery-op"),
        serverId = ServerId("server-a"),
        serverAccessId = ServerAccessId("access-a"),
    )

    @Test
    fun adoptedRequestBuildsExactInstallationFromProofAndBaseline() {
        val proof = proof(managedInstallId = null)
        val request = ManagementEnrollmentRequest(
            proof = proof,
            baseline = baseline(proof.observedIdentity),
            proposedInstallationId = XuiInstallationId("installation-a"),
        )

        val installation = request.newInstallation()
        assertEquals(scope.serverId, installation.serverId)
        assertEquals(InstallationOwnership.ADOPTED, installation.ownership)
        assertEquals(proof.observedIdentity, installation.identity)
        assertEquals(request.baseline, installation.baseline)
        assertNull(installation.identity.managedInstallId)
    }

    @Test
    fun managedOwnershipComesOnlyFromProvenManagedMarker() {
        val managedId = ManagedInstallId("managed-a")
        val proof = proof(managedInstallId = managedId)
        val request = ManagementEnrollmentRequest(
            proof = proof,
            baseline = baseline(proof.observedIdentity),
            proposedInstallationId = XuiInstallationId("installation-managed"),
        )

        assertEquals(InstallationOwnership.MANAGED, request.expectedOwnership)
        assertEquals(managedId, request.newInstallation().identity.managedInstallId)
    }

    @Test
    fun mismatchedBaselineIsRejectedBeforePersistence() {
        val proof = proof(managedInstallId = null)
        val mismatched = baseline(proof.observedIdentity).copy(panelPort = 2053, rootPath = "/other/root")

        assertThrows(IllegalArgumentException::class.java) {
            ManagementEnrollmentRequest(
                proof = proof,
                baseline = mismatched,
                proposedInstallationId = XuiInstallationId("installation-a"),
            )
        }
    }

    @Test
    fun handcraftedPartialProofCannotEnterEnrollment() {
        val identity = identity(null)
        val partial = DiscoveryProof(
            id = DiscoveryProofId("partial-proof"),
            scope = scope,
            observedIdentity = identity,
            candidateBaseline = null,
            supportingSignals = setOf(
                DiscoveryProofSignal.SERVICE_UNIT,
                DiscoveryProofSignal.BINARY_PATH,
            ),
            observedAt = observedAt,
        )

        assertThrows(IllegalArgumentException::class.java) {
            ManagementEnrollmentRequest(
                proof = partial,
                baseline = baseline(identity),
                proposedInstallationId = XuiInstallationId("installation-a"),
            )
        }
    }

    private fun proof(managedInstallId: ManagedInstallId?): DiscoveryProof {
        val identity = identity(managedInstallId)
        val signals = linkedSetOf(
            DiscoveryProofSignal.SERVICE_UNIT,
            DiscoveryProofSignal.BINARY_PATH,
            DiscoveryProofSignal.ROOT_PATH,
            DiscoveryProofSignal.DATABASE_PATH,
        )
        if (managedInstallId != null) signals += DiscoveryProofSignal.MANAGED_INSTALL_MARKER
        return DiscoveryProof(
            id = DiscoveryProofId("proof-${managedInstallId?.value ?: "adopted"}"),
            scope = scope,
            observedIdentity = identity,
            candidateBaseline = null,
            supportingSignals = signals,
            observedAt = observedAt,
        )
    }

    private fun identity(managedInstallId: ManagedInstallId?) = InstallationIdentity(
        serviceUnit = "x-ui.service",
        binaryPath = "/usr/local/x-ui/x-ui",
        rootPath = "/usr/local/x-ui",
        databasePath = "/etc/x-ui/x-ui.db",
        managedInstallId = managedInstallId,
    )

    private fun baseline(identity: InstallationIdentity) = InstallationBaseline(
        serviceUnit = identity.serviceUnit,
        binaryPath = identity.binaryPath,
        rootPath = identity.rootPath,
        databasePath = identity.databasePath,
        panelPort = 54321,
        webBasePath = "/panel/",
        listenAddress = "127.0.0.1",
        capturedAt = observedAt.plusSeconds(1),
    )
}
