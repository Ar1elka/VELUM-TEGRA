package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
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

class SiteProductionDeploymentAndroidServingPolicySelectionBoundaryTest {
    @Test
    fun `explicit no-reuse intent selects HTTP plan`() {
        val (root, preparation) = prepare(reuse = false)
        try {
            val result = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation = preparation,
                staticPublicationEvidence = evidence(preparation),
            )

            assertEquals(
                SiteProductionDeploymentServingPolicySelectionStatus
                    .HTTP_PUBLICATION_PLAN_READY_EXPLICIT_NO_CERTIFICATE_REUSE,
                result.status,
            )
            assertEquals(SiteCertificateReuseMode.NONE, result.requestedCertificateReuseMode)
            assertEquals(SiteWebServingProtocol.HTTP, result.selectedProtocol)
            assertEquals(SiteWebServingProtocol.HTTP, requireNotNull(result.publicationPlan).protocol)
            assertTrue(result.publicationPlanSelected)
            assertTrue(result.explicitUserIntentPreserved)
            assertFalse(result.silentProtocolDowngradePerformed)
            assertFalse(result.productionNetworkTouchedBySelection)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `explicit reuse intent with eligible exact-domain certificate selects HTTPS`() {
        val (root, preparation) = prepare(reuse = true)
        try {
            val composition =
                SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.composeValidated(
                    preparation = preparation,
                    staticPublicationEvidence = evidence(preparation),
                    eligibilityReport = eligibilityReport(listOf("site.example.com"), configured = true),
                    observedRemoteHostIdentity = REMOTE_HOST,
                    realVpsExecutionProofSha256 = "b".repeat(64),
                )
            val result = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation = preparation,
                staticPublicationEvidence = evidence(preparation),
                certificateComposition = composition,
            )

            assertEquals(
                SiteProductionDeploymentServingPolicySelectionStatus
                    .HTTPS_PUBLICATION_PLAN_READY_EXPLICIT_EXISTING_CERTIFICATE_REUSE,
                result.status,
            )
            assertEquals(SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE, result.selectedProtocol)
            assertEquals(
                SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE,
                requireNotNull(result.publicationPlan).protocol,
            )
            assertTrue(result.publicationPlanSelected)
            assertFalse(result.silentProtocolDowngradePerformed)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `explicit reuse intent with no configured certificate stays blocked and never downgrades to HTTP`() {
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
            val result = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation = preparation,
                staticPublicationEvidence = evidence(preparation),
                certificateComposition = composition,
            )

            assertEquals(
                SiteProductionDeploymentServingPolicySelectionStatus
                    .BLOCKED_REUSE_REQUESTED_NO_CONFIGURED_CERTIFICATE,
                result.status,
            )
            assertNull(result.selectedProtocol)
            assertNull(result.publicationPlan)
            assertFalse(result.publicationPlanSelected)
            assertTrue(result.explicitUserIntentPreserved)
            assertFalse(result.silentProtocolDowngradePerformed)
            assertFalse(result.automaticRetryAuthorized)
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
        val root = Files.createTempDirectory("phase11_68-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(if (reuse) 11681L else 11680L),
                domain = "Site.Example.COM",
                servicePort = 8443,
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
