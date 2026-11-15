package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallerPostInstallPolicyTest {
    private val scope = InstallerWorkerScope(
        operationId = OperationId("install-post-verify"),
        serverId = ServerId("server-a"),
        serverAccessId = ServerAccessId("access-a"),
        managedInstallId = ManagedInstallId("v1-0123456789abcdef0123456789abcdef"),
    )
    private val observedAt = Instant.parse("2026-09-12T07:00:00Z")

    @Test
    fun completeExactFactsProduceManagedAtomicPublicationRequest() {
        val result = InstallerPostInstallPolicy.verify(scope, goodFacts())
        assertTrue(result is InstallerPostInstallVerificationDecision.Verified)
        val request = (result as InstallerPostInstallVerificationDecision.Verified).request
        val installation = request.newInstallation()

        assertEquals(scope.serverId, installation.serverId)
        assertEquals(scope.managedInstallId, installation.identity.managedInstallId)
        assertEquals("xui-${scope.managedInstallId.value}", installation.id.value)
        assertEquals(23456, installation.baseline.panelPort)
        assertEquals("/panel/", installation.baseline.webBasePath)
    }

    @Test
    fun markerMismatchCannotProducePublicationRequest() {
        val result = InstallerPostInstallPolicy.verify(
            scope,
            goodFacts().copy(markerReadback = ManagedInstallMarkerReadbackState.MISMATCH),
        )
        assertEquals(
            InstallerPostInstallVerificationDecision.Rejected(
                InstallerPostInstallRejection.MANAGED_MARKER_NOT_MATCHED,
            ),
            result,
        )
    }

    @Test
    fun inactiveServiceCannotProducePublicationRequest() {
        val result = InstallerPostInstallPolicy.verify(
            scope,
            goodFacts().copy(serviceState = ManagementServiceState.INACTIVE),
        )
        assertEquals(
            InstallerPostInstallVerificationDecision.Rejected(
                InstallerPostInstallRejection.SERVICE_NOT_ACTIVE,
            ),
            result,
        )
    }

    @Test
    fun nonCanonicalWebBasePathCannotBecomeDurableBaseline() {
        val result = runCatching { goodFacts().copy(webBasePath = "/panel") }
        assertTrue(result.isFailure)
    }

    @Test
    fun deterministicInstallationIdDependsOnlyOnManagedInstallIdentity() {
        val first = InstallerPostInstallPolicy.installationIdFor(scope)
        val second = InstallerPostInstallPolicy.installationIdFor(
            scope.copy(operationId = OperationId("different-operation")),
        )
        assertEquals(first, second)
    }

    private fun goodFacts() = InstallerPostInstallFacts(
        markerReadback = ManagedInstallMarkerReadbackState.MATCH,
        serviceUnitPresent = true,
        binaryPresent = true,
        rootPresent = true,
        databasePresent = true,
        serviceState = ManagementServiceState.ACTIVE,
        panelPort = 23456,
        webBasePath = "/panel/",
        listenAddress = null,
        listenerPresent = true,
        observedAt = observedAt,
    )
}
