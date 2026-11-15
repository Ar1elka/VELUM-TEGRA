package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteProductionServiceBindingReadinessMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentAndroidReleaseBootstrapBoundaryTest {
    @Test
    fun `release flow selector binds first publication only to post coordinator activation`() {
        assertEquals(
            SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED,
            SiteProductionDeploymentAndroidReleaseBootstrapBoundary.readinessModeFor(
                SiteProductionDeploymentReleaseFlow.PRECONFIGURED_ENDPOINT,
            ),
        )
        assertEquals(
            SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION,
            SiteProductionDeploymentAndroidReleaseBootstrapBoundary.readinessModeFor(
                SiteProductionDeploymentReleaseFlow.FIRST_PUBLICATION_POST_COORDINATOR,
            ),
        )
    }

    @Test
    fun `reviewed first publication admits complete http context without adding authority`() {
        val admission = SiteProductionDeploymentAndroidReleaseBootstrapBoundary
            .admitReviewedFirstPublication(fixture())

        assertEquals(
            SiteProductionDeploymentReleaseBootstrapStatus
                .READY_TO_PUBLISH_REVIEWED_FIRST_PUBLICATION_CONTEXT,
            admission.status,
        )
        assertEquals(
            SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION,
            admission.selectedReadinessMode,
        )
        assertTrue(admission.completePostCoordinatorServingCapabilityRequired)
        assertEquals(SiteCertificateReuseMode.NONE, admission.certificateReuseMode)
        assertFalse(admission.requiresFinalHttpsTlsVerification)
        assertFalse(admission.productionNetworkTouched)
        assertFalse(admission.credentialMaterialRead)
        assertFalse(admission.realServerMutationEnabled)
        assertFalse(admission.authorizesTransport)
        assertFalse(admission.authorizesCoordinatorInvocation)
        assertFalse(admission.automaticRetryAuthorized)
        assertFalse(admission.arbitraryCommandAuthorized)
        assertFalse(admission.silentProtocolDowngradePerformed)
        assertEquals(64, admission.bootstrapAdmissionSha256.length)
    }

    @Test
    fun `preconfigured flow cannot masquerade as reviewed first publication`() {
        assertRejected(
            fixture().copy(
                releaseFlow = SiteProductionDeploymentReleaseFlow.PRECONFIGURED_ENDPOINT,
                serviceBindingReadinessMode =
                    SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED,
                readyRecordServiceBindingReadinessMode =
                    SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED,
                serviceBindingObservedConfigured = true,
            ),
        )
    }

    @Test
    fun `first publication fails closed when endpoint is already configured`() {
        assertRejected(fixture().copy(serviceBindingObservedConfigured = true))
    }

    @Test
    fun `first publication fails closed without phase1194 complete serving capability`() {
        assertRejected(fixture().copy(postCoordinatorCredentialProviderPresent = false))
    }

    @Test
    fun `certificate reuse is admitted only as explicit final https tls verified release path`() {
        val admission = SiteProductionDeploymentAndroidReleaseBootstrapBoundary
            .admitReviewedFirstPublication(
                fixture().copy(
                    certificateReuseMode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                ),
            )

        assertEquals(SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN, admission.certificateReuseMode)
        assertTrue(admission.requiresFinalHttpsTlsVerification)
        assertFalse(admission.silentProtocolDowngradePerformed)
    }

    @Test
    fun `host key and exact host mismatches fail closed`() {
        assertRejected(fixture().copy(serviceObservationHostIdentity = "203.0.113.10"))
        assertRejected(fixture().copy(serviceObservationServerKeySha256 = "f".repeat(64)))
        assertRejected(fixture().copy(serverAccessPinnedHostKeySha256 = "e".repeat(64)))
    }

    @Test
    fun `bootstrap admission digest changes when exact publication identity changes`() {
        val first = SiteProductionDeploymentAndroidReleaseBootstrapBoundary
            .admitReviewedFirstPublication(fixture())
        val changed = SiteProductionDeploymentAndroidReleaseBootstrapBoundary
            .admitReviewedFirstPublication(fixture().copy(servicePort = 8443))

        assertNotEquals(first.bootstrapAdmissionSha256, changed.bootstrapAdmissionSha256)
    }

    @Test
    fun `tampered admission digest is rejected`() {
        val admission = SiteProductionDeploymentAndroidReleaseBootstrapBoundary
            .admitReviewedFirstPublication(fixture())
        assertRejectedAdmission(admission.copy(targetRoot = "/var/www/changed"))
    }

    @Test
    fun `replacement of an already served site admits file swap only`() {
        val admission = SiteProductionDeploymentAndroidReleaseBootstrapBoundary.admitReviewedReplacement(
            evidence = replacementFixture(),
            replacementPolicyBound = true,
            previousTargetTreeBound = true,
        )
        assertEquals(
            SiteProductionDeploymentReleaseBootstrapStatus.READY_TO_PUBLISH_REVIEWED_REPLACEMENT_CONTEXT,
            admission.status,
        )
        assertEquals(SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED, admission.selectedReadinessMode)
        assertFalse(admission.completePostCoordinatorServingCapabilityRequired)
        assertFalse(admission.requiresFinalHttpsTlsVerification)
        assertFalse(admission.realServerMutationEnabled)
        assertFalse(admission.automaticRetryAuthorized)
        SiteProductionDeploymentAndroidReleaseBootstrapBoundary.validateAdmission(admission)
        assertRejectedAdmission(admission.copy(releaseFlow = SiteProductionDeploymentReleaseFlow.FIRST_PUBLICATION_POST_COORDINATOR))
    }

    @Test
    fun `replacement fails closed without exact evidence`() {
        fun rejected(
            evidence: SiteProductionDeploymentReleaseBootstrapEvidence,
            policy: Boolean = true,
            tree: Boolean = true,
        ): Boolean = try {
            SiteProductionDeploymentAndroidReleaseBootstrapBoundary.admitReviewedReplacement(evidence, policy, tree)
            false
        } catch (_: IllegalArgumentException) {
            true
        }
        assertTrue(rejected(replacementFixture(), policy = false))
        assertTrue(rejected(replacementFixture(), tree = false))
        assertTrue(rejected(replacementFixture().copy(serviceBindingObservedConfigured = false)))
        assertTrue(rejected(replacementFixture().copy(postCoordinatorCredentialProviderPresent = true)))
        assertTrue(rejected(replacementFixture().copy(certificateReuseMode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN)))
        assertTrue(rejected(fixture()))
        assertTrue(rejected(replacementFixture().copy(expectedServerKeySha256 = "9".repeat(64))))
    }

    private fun replacementFixture(): SiteProductionDeploymentReleaseBootstrapEvidence = fixture().copy(
        releaseFlow = SiteProductionDeploymentReleaseFlow.PRECONFIGURED_ENDPOINT,
        serviceBindingReadinessMode = SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED,
        readyRecordServiceBindingReadinessMode = SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED,
        serviceBindingObservedConfigured = true,
        postCoordinatorCredentialProviderPresent = false,
    )

    private fun fixture(): SiteProductionDeploymentReleaseBootstrapEvidence =
        SiteProductionDeploymentReleaseBootstrapEvidence(
            releaseFlow = SiteProductionDeploymentReleaseFlow.FIRST_PUBLICATION_POST_COORDINATOR,
            serverAccessId = "server_access_phase11_96",
            serverId = "server_phase11_96",
            remoteHostIdentity = "198.51.100.10",
            sshPort = 22,
            sshUsername = "root",
            serverAccessPinnedHostKeySha256 = "1".repeat(64),
            expectedServerKeySha256 = "1".repeat(64),
            remoteObservationHostIdentity = "198.51.100.10",
            remoteObservationServerKeySha256 = "1".repeat(64),
            serviceObservationHostIdentity = "198.51.100.10",
            serviceObservationServerKeySha256 = "1".repeat(64),
            serviceDomain = "site.example.test",
            servicePort = 8080,
            serviceBindingReadinessMode =
                SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION,
            serviceBindingObservedConfigured = false,
            readyRecordServiceBindingReadinessMode =
                SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION,
            readyRecordOperatorApproved = true,
            readyRecordApprovalSha256 = "2".repeat(64),
            preparationSha256 = "3".repeat(64),
            deploymentPlanSha256 = "4".repeat(64),
            sourceTreeSha256 = "5".repeat(64),
            coordinatorAdmissionSha256 = "6".repeat(64),
            targetRoot = "/var/www/velum-site",
            certificateReuseMode = SiteCertificateReuseMode.NONE,
            postCoordinatorCredentialProviderPresent = true,
            uiPreparedAtEpochMillis = 2_000L,
            permitExpiresAtEpochMillis = 60_000L,
        )

    private fun assertRejected(evidence: SiteProductionDeploymentReleaseBootstrapEvidence) {
        var rejected = false
        try {
            SiteProductionDeploymentAndroidReleaseBootstrapBoundary
                .admitReviewedFirstPublication(evidence)
        } catch (_: IllegalArgumentException) {
            rejected = true
        }
        assertTrue(rejected)
    }

    private fun assertRejectedAdmission(admission: SiteProductionDeploymentReleaseBootstrapAdmission) {
        var rejected = false
        try {
            SiteProductionDeploymentAndroidReleaseBootstrapBoundary.validateAdmission(admission)
        } catch (_: IllegalArgumentException) {
            rejected = true
        }
        assertTrue(rejected)
    }
}
