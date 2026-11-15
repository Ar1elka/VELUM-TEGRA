package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityObservation
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityTrust
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingStrategy
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentAndroidCertificatePublicationCompositionGateTest {
    @Test
    fun `validated eligible report selects exact existing-certificate https plan`() =
        withPreparation { preparation ->
            val result = SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.composeValidated(
                preparation = preparation,
                staticPublicationEvidence = evidence(preparation),
                eligibilityReport = eligibilityReport(listOf("site.example.com"), configured = true),
                observedRemoteHostIdentity = REMOTE_HOST,
                realVpsExecutionProofSha256 = "b".repeat(64),
                strategy = SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1,
            )

            assertEquals(
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .HTTPS_PUBLICATION_PLAN_READY_FROM_VALIDATED_EXISTING_3X_UI_CERTIFICATE,
                result.status,
            )
            assertTrue(result.realVpsExecutionProofValidated)
            assertTrue(result.publicationPlanSelected)
            val plan = requireNotNull(result.publicationPlan)
            assertEquals(SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE, plan.protocol)
            assertEquals("site.example.com", plan.domain)
            assertEquals("/etc/ssl/x-ui/fullchain.pem", plan.certificatePath)
            assertEquals("/etc/ssl/x-ui/privkey.pem", plan.privateKeyPath)
            assertFalse(result.tlsConfigurationAuthorized)
            assertFalse(result.nginxMutationAuthorized)
            assertFalse(result.productionNetworkTouchedByComposition)
            SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.validate(result)
        }

    @Test
    fun `exact no-configured-panel-certificate state blocks publication-plan selection`() =
        withPreparation { preparation ->
            val result = SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.composeValidated(
                preparation = preparation,
                staticPublicationEvidence = evidence(preparation),
                eligibilityReport = eligibilityReport(emptyList(), configured = false),
                observedRemoteHostIdentity = REMOTE_HOST,
                realVpsExecutionProofSha256 = "c".repeat(64),
            )

            assertEquals(
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE,
                result.status,
            )
            assertNull(result.publicationPlan)
            assertFalse(result.publicationPlanSelected)
            assertFalse(result.certificateMutationAuthorized)
            assertFalse(result.automaticRetryAuthorized)
        }

    @Test
    fun `eligible certificate for another exact domain remains blocked`() =
        withPreparation { preparation ->
            val result = SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.composeValidated(
                preparation = preparation,
                staticPublicationEvidence = evidence(preparation),
                eligibilityReport = eligibilityReport(listOf("other.example.com"), configured = true),
                observedRemoteHostIdentity = REMOTE_HOST,
                realVpsExecutionProofSha256 = "d".repeat(64),
            )

            assertEquals(
                SiteProductionDeploymentCertificatePublicationCompositionStatus
                    .BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN,
                result.status,
            )
            assertNull(result.publicationPlan)
            assertFalse(result.publicationPlanSelected)
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

    private fun evidence(preparation: com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult) =
        SiteStaticPublicationEvidence(
            preparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
            committedClean = true,
            remoteResidualStateClean = true,
        )

    private fun withPreparation(
        block: (com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult) -> Unit,
    ) {
        val root = Files.createTempDirectory("phase11_67-")
        try {
            block(
                SiteDeployerLocalPreparationBoundary.prepare(
                    SiteDeployerLocalPreparationRequest(
                        rootSeed = DesignSeed(1167L),
                        domain = "Site.Example.COM",
                        servicePort = 8443,
                        remoteHostIdentity = REMOTE_HOST,
                        targetRoot = "/srv/www/site",
                        owner = "www_data",
                        group = "www_data",
                        reuseExisting3xUiCertificate = true,
                    ),
                    root,
                ),
            )
        } finally {
            deleteTree(root)
        }
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
