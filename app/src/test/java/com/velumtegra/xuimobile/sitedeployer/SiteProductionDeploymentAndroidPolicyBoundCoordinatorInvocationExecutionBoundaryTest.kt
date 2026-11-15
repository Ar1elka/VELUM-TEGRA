package com.velumtegra.xuimobile.sitedeployer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundaryTest {
    @Test
    fun `admission digest binds exact coordinator authority and keeps mutation surface narrow`() {
        val base = SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmission(
            contractVersion = 1,
            status = SiteProductionDeploymentPolicyBoundCoordinatorInvocationAdmissionStatus
                .READY_FOR_ONE_EXISTING_COORDINATOR_INVOCATION,
            invocationAuthorizationSha256 = "1".repeat(64),
            executionAuthorizationSha256 = "2".repeat(64),
            coordinatorRequestSha256 = "3".repeat(64),
            runtimeIdentitySha256 = "4".repeat(64),
            permitSha256 = "5".repeat(64),
            candidateTransportAuthorizationSha256 = "6".repeat(64),
            capabilityProfileSha256 = "7".repeat(64),
            localPreparationSha256 = "8".repeat(64),
            deploymentPlanSha256 = "9".repeat(64),
            sourceTreeSha256 = "a".repeat(64),
            remoteHostIdentity = "192.0.2.169",
            targetRoot = "/tmp/velum-phase11-80",
            coordinatorInvocationId = "phase11_80_invocation_0001",
            evaluatedAtEpochMillis = 1000L,
            permitExpiresAtEpochMillis = 60000L,
            requiresDurableCoordinatorInvocationFence = true,
            delegatesToExistingCoordinator = true,
            delegatesTransportToAcceptedPhase1155Transaction = true,
            addsNewRemoteMutationPrimitive = false,
            automaticRetryAuthorized = false,
            arbitraryCommandAuthorized = false,
            exposesDeployUiAction = false,
            admissionSha256 = "",
        )
        val admission = base.copy(
            admissionSha256 = SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
                .admissionSha256ForTest(base),
        )
        SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
            .validateAdmission(admission)

        assertTrue(admission.requiresDurableCoordinatorInvocationFence)
        assertTrue(admission.delegatesToExistingCoordinator)
        assertTrue(admission.delegatesTransportToAcceptedPhase1155Transaction)
        assertFalse(admission.addsNewRemoteMutationPrimitive)
        assertFalse(admission.automaticRetryAuthorized)
        assertFalse(admission.arbitraryCommandAuthorized)
        assertFalse(admission.exposesDeployUiAction)

        val changed = admission.copy(targetRoot = "/tmp/velum-phase11-80-changed")
        var rejected = false
        try {
            SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary
                .validateAdmission(changed)
        } catch (_: IllegalArgumentException) {
            rejected = true
        }
        assertTrue(rejected)
        assertEquals(64, admission.admissionSha256.length)
    }
}
