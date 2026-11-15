package com.velumtegra.xuimobile.integration

import android.os.StrictMode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
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
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidCertificatePublicationCompositionGate
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidServingPolicySelectionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentServingPolicySelectionStatus
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_68RealDeviceExplicitCertificateIntentServingPolicyAcceptanceInstrumentedTest {
    @Test
    fun explicitReuseIntentIsPreservedAndNoCertificateStateNeverSilentlyDowngradesToHttp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val httpRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_68-http-")
        val reuseRoot = Files.createTempDirectory(context.cacheDir.toPath(), "phase11_68-reuse-")
        val priorPolicy = StrictMode.getThreadPolicy()
        try {
            StrictMode.setThreadPolicy(
                StrictMode.ThreadPolicy.Builder(priorPolicy)
                    .detectNetwork()
                    .penaltyDeath()
                    .build(),
            )

            val httpPreparation = prepare(httpRoot, reuse = false, seed = 11680L)
            val httpSelection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation = httpPreparation,
                staticPublicationEvidence = evidence(httpPreparation),
            )
            assertEquals(
                SiteProductionDeploymentServingPolicySelectionStatus
                    .HTTP_PUBLICATION_PLAN_READY_EXPLICIT_NO_CERTIFICATE_REUSE,
                httpSelection.status,
            )
            assertEquals(SiteWebServingProtocol.HTTP, httpSelection.selectedProtocol)
            assertTrue(httpSelection.publicationPlanSelected)
            assertFalse(httpSelection.silentProtocolDowngradePerformed)

            val reusePreparation = prepare(reuseRoot, reuse = true, seed = 11681L)
            val blockedComposition =
                SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.composeValidated(
                    preparation = reusePreparation,
                    staticPublicationEvidence = evidence(reusePreparation),
                    eligibilityReport = eligibilityReport(emptyList(), configured = false),
                    observedRemoteHostIdentity = REMOTE_HOST,
                    realVpsExecutionProofSha256 = "c".repeat(64),
                )
            val blockedSelection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation = reusePreparation,
                staticPublicationEvidence = evidence(reusePreparation),
                certificateComposition = blockedComposition,
            )
            assertEquals(
                SiteProductionDeploymentServingPolicySelectionStatus
                    .BLOCKED_REUSE_REQUESTED_NO_CONFIGURED_CERTIFICATE,
                blockedSelection.status,
            )
            assertNull(blockedSelection.selectedProtocol)
            assertNull(blockedSelection.publicationPlan)
            assertFalse(blockedSelection.publicationPlanSelected)
            assertTrue(blockedSelection.explicitUserIntentPreserved)
            assertFalse(blockedSelection.silentProtocolDowngradePerformed)

            val eligibleComposition =
                SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.composeValidated(
                    preparation = reusePreparation,
                    staticPublicationEvidence = evidence(reusePreparation),
                    eligibilityReport = eligibilityReport(listOf("site.example.com"), configured = true),
                    observedRemoteHostIdentity = REMOTE_HOST,
                    realVpsExecutionProofSha256 = "d".repeat(64),
                )
            val httpsSelection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
                preparation = reusePreparation,
                staticPublicationEvidence = evidence(reusePreparation),
                certificateComposition = eligibleComposition,
            )
            assertEquals(
                SiteProductionDeploymentServingPolicySelectionStatus
                    .HTTPS_PUBLICATION_PLAN_READY_EXPLICIT_EXISTING_CERTIFICATE_REUSE,
                httpsSelection.status,
            )
            assertEquals(SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE, httpsSelection.selectedProtocol)
            assertTrue(httpsSelection.publicationPlanSelected)
            assertFalse(httpsSelection.silentProtocolDowngradePerformed)

            for (selection in listOf(httpSelection, blockedSelection, httpsSelection)) {
                SiteProductionDeploymentAndroidServingPolicySelectionBoundary.validate(selection)
                assertFalse(selection.productionNetworkTouchedBySelection)
                assertFalse(selection.remoteMutationPerformed)
                assertFalse(selection.certificateMutationAuthorized)
                assertFalse(selection.tlsConfigurationAuthorized)
                assertFalse(selection.nginxMutationAuthorized)
                assertFalse(selection.dnsMutationAuthorized)
                assertFalse(selection.firewallMutationAuthorized)
                assertFalse(selection.packageInstallAuthorized)
                assertFalse(selection.privateKeyContentReadAuthorized)
                assertFalse(selection.automaticRetryAuthorized)
                assertFalse(selection.coordinatorInvoked)
                assertFalse(selection.exposesDeployUiAction)
            }
        } finally {
            StrictMode.setThreadPolicy(priorPolicy)
            deleteTree(httpRoot)
            deleteTree(reuseRoot)
        }
    }

    private fun prepare(root: Path, reuse: Boolean, seed: Long) =
        SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(seed),
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
