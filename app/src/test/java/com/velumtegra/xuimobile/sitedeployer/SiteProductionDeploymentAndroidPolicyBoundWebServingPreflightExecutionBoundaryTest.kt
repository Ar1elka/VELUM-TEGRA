package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityObservation
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityTrust
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundaryTest {
    @Test
    fun `explicit no-reuse HTTP selection produces exact local-only preflight admission`() {
        val (root, preparation) = prepare(reuse = false)
        try {
            val selection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation = preparation,
                staticPublicationEvidence = evidence(preparation),
            )
            val admission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary.admit(selection)

            assertEquals(
                SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_READ_ONLY_PREFLIGHT_EXECUTION,
                admission.status,
            )
            assertEquals(SiteWebServingProtocol.HTTP, admission.selectedProtocol)
            assertEquals(selection.publicationPlan?.publicationPlanSha256, admission.publicationPlanSha256)
            assertTrue(admission.readOnlyPreflightExecutionEligible)
            assertTrue(admission.freshCredentialResolutionRequired)
            assertTrue(admission.liveHostKeyVerificationRequired)
            assertFalse(admission.productionNetworkTouchedByAdmission)
            assertFalse(admission.configMutationAuthorized)
            SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary
                .validateAdmission(admission)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `blocked explicit reuse selection is rejected before any network eligibility exists`() {
        val (root, preparation) = prepare(reuse = true)
        try {
            val composition =
                SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.composeValidated(
                    preparation = preparation,
                    staticPublicationEvidence = evidence(preparation),
                    eligibilityReport = eligibilityReport(emptyList(), configured = false),
                    observedRemoteHostIdentity = REMOTE_HOST,
                    realVpsExecutionProofSha256 = "c".repeat(64),
                )
            val selection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation = preparation,
                staticPublicationEvidence = evidence(preparation),
                certificateComposition = composition,
            )
            val admission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary.admit(selection)

            assertEquals(
                SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                    .BLOCKED_BY_EXPLICIT_SERVING_POLICY,
                admission.status,
            )
            assertFalse(admission.readOnlyPreflightExecutionEligible)
            assertFalse(admission.freshCredentialResolutionRequired)
            assertFalse(admission.liveHostKeyVerificationRequired)
            assertNull(admission.selectedProtocol)
            assertNull(admission.publicationPlanSha256)
            assertNull(admission.remoteHostIdentity)
            assertFalse(admission.productionNetworkTouchedByAdmission)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `eligible exact-domain reuse selection binds HTTPS plan before preflight`() {
        val (root, preparation) = prepare(reuse = true)
        try {
            val composition =
                SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.composeValidated(
                    preparation = preparation,
                    staticPublicationEvidence = evidence(preparation),
                    eligibilityReport = eligibilityReport(listOf("site.example.com"), configured = true),
                    observedRemoteHostIdentity = REMOTE_HOST,
                    realVpsExecutionProofSha256 = "d".repeat(64),
                )
            val selection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation = preparation,
                staticPublicationEvidence = evidence(preparation),
                certificateComposition = composition,
            )
            val admission =
                SiteProductionDeploymentAndroidPolicyBoundWebServingPreflightExecutionBoundary.admit(selection)

            assertEquals(
                SiteProductionDeploymentPolicyBoundWebServingPreflightAdmissionStatus
                    .READY_FOR_SEPARATE_REAL_VPS_READ_ONLY_PREFLIGHT_EXECUTION,
                admission.status,
            )
            assertEquals(SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE, admission.selectedProtocol)
            assertEquals(selection.publicationPlan?.publicationPlanSha256, admission.publicationPlanSha256)
            assertFalse(admission.productionNetworkTouchedByAdmission)
        } finally {
            deleteTree(root)
        }
    }

    private fun eligibilityReport(
        dnsNames: List<String>,
        configured: Boolean,
    ) = SiteExisting3xUiCertificateReuseEligibilityBoundary.evaluate(
        plan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare(REMOTE_HOST),
        trust = SiteExisting3xUiCertificateReuseEligibilityTrust(HOST_KEY),
        observation = SiteExisting3xUiCertificateReuseEligibilityObservation(
            remoteHostIdentity = REMOTE_HOST,
            verifiedHostKeySha256 = HOST_KEY,
            databasePath = SiteExisting3xUiCertificateReuseEligibilityBoundary.DATABASE_PATH,
            databasePathType = SiteWebServingObservedPathType.FILE,
            sqliteReadOnlyAvailable = true,
            certificatePath = if (configured) "/etc/ssl/x-ui/fullchain.pem" else null,
            privateKeyPath = if (configured) "/etc/ssl/x-ui/privkey.pem" else null,
            certificatePathType = if (configured) SiteWebServingObservedPathType.FILE else null,
            privateKeyPathType = if (configured) SiteWebServingObservedPathType.FILE else null,
            certificateSha256 = if (configured) "a".repeat(64) else null,
            certificateDnsNames = dnsNames,
            certificateNotBeforeEpochMillis =
                if (configured) Instant.parse("2026-09-01T00:00:00Z").toEpochMilli() else null,
            certificateNotAfterEpochMillis =
                if (configured) Instant.parse("2026-12-01T00:00:00Z").toEpochMilli() else null,
            remoteCommandCount = if (configured) 3 else 1,
            mutationOperationPerformed = false,
            arbitraryCommandAccepted = false,
            privateKeyContentReadPerformed = false,
        ),
        observedAtEpochMillis = Instant.parse("2026-10-04T00:00:00Z").toEpochMilli(),
    )

    private fun evidence(preparation: SiteDeployerLocalPreparationResult) =
        SiteStaticPublicationEvidence(
            preparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            committedClean = true,
            remoteResidualStateClean = true,
        )

    private fun prepare(reuse: Boolean): Pair<Path, SiteDeployerLocalPreparationResult> {
        val root = Files.createTempDirectory("phase11_69-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(if (reuse) 11691L else 11690L),
                domain = "Site.Example.COM",
                servicePort = 58479,
                remoteHostIdentity = REMOTE_HOST,
                targetRoot = "/srv/www/site",
                owner = "www_data",
                group = "www_data",
                reuseExisting3xUiCertificate = reuse,
            ),
            root,
        )
        return root to preparation
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private companion object {
        const val REMOTE_HOST = "203.0.113.10"
        val HOST_KEY = "7".repeat(64)
    }
}
