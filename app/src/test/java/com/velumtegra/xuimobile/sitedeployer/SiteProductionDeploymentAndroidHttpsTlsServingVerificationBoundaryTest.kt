package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityObservation
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityTrust
import com.velumtegra.xuimobile.core.site.SiteServerCertificateFileReference
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundaryTest {
    @Test
    fun `exact validated certificate path produces one bounded TLS result without mutation authority`() {
        val fixture = fixture()
        try {
            val plan = verificationPlan(fixture)
            val result = SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.executeWithAdapters(
                plan = plan,
                executionAttemptId = "phase11_97_test_attempt",
                executedAtEpochMillis = Instant.parse("2026-10-05T20:00:00Z").toEpochMilli(),
                resolver = SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.DnsResolver {
                    listOf("2001:db8::10", REMOTE_HOST)
                },
                probe = SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.HttpsTlsProbe {
                        observedPlan,
                        selectedAddress,
                        _ ->
                    SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.HttpsTlsObservation(
                        selectedResolvedAddress = selectedAddress,
                        tlsProtocol = "TLSv1.3",
                        platformTrustValidated = true,
                        exactHostnameVerified = true,
                        sniDomain = observedPlan.domain,
                        peerLeafCertificateDerSha256 = "d".repeat(64),
                        peerCertificateDnsNames = observedPlan.expectedCertificateDnsNames,
                        httpStatusCode = 200,
                        contentLength = observedPlan.expectedBodyBytes,
                        observedBodySha256 = observedPlan.expectedBodySha256,
                    )
                },
            )

            assertEquals(
                SiteProductionDeploymentHttpsTlsServingVerificationStatus
                    .HTTPS_TLS_IDENTITY_AND_EXACT_INDEX_VERIFIED,
                result.status,
            )
            assertEquals(1, result.dnsResolutionInvocationCount)
            assertTrue(result.resolvedSetContainsExactIpv4)
            assertEquals(REMOTE_HOST, result.selectedResolvedAddress)
            assertTrue(result.tlsHandshakePerformed)
            assertTrue(result.platformTrustValidated)
            assertTrue(result.exactHostnameVerified)
            assertTrue(result.exactPeerDnsNamesVerified)
            assertTrue(result.exactBodySha256Verified)
            assertFalse(result.remoteMutationPerformed)
            assertFalse(result.certificateMutationPerformed)
            assertFalse(result.privateKeyContentReadPerformed)
            assertFalse(result.dnsMutationPerformed)
            assertFalse(result.firewallMutationPerformed)
            assertFalse(result.packageInstallPerformed)
            assertFalse(result.automaticRetryPerformed)
            assertFalse(result.coordinatorReinvoked)
            assertFalse(result.staticPublicationReplayPerformed)
        } finally {
            deleteTree(fixture.root)
        }
    }

    @Test
    fun `fresh certificate reference drift fails closed before TLS execution`() {
        val fixture = fixture()
        try {
            val original = requireNotNull(fixture.composition.bindingReport.certificateReference)
            val drifted = original.copy(certificateSha256 = "e".repeat(64))
            val error = runCatching {
                SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.prepareAfterValidatedReload(
                    preparation = fixture.preparation,
                    certificateComposition = fixture.composition,
                    selection = fixture.selection,
                    postCoordinatorNginxReloadExecutionResultSha256 = "b".repeat(64),
                    freshCertificateEligibilityExecutionProofSha256 = "c".repeat(64),
                    freshCertificateReference = drifted,
                )
            }.exceptionOrNull()

            assertTrue(error is IllegalArgumentException)
        } finally {
            deleteTree(fixture.root)
        }
    }

    @Test
    fun `DNS set missing exact accepted VPS address blocks before TLS probe`() {
        val fixture = fixture()
        try {
            val plan = verificationPlan(fixture)
            var probeCalled = false
            val error = runCatching {
                SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.executeWithAdapters(
                    plan = plan,
                    executionAttemptId = "phase11_97_dns_block",
                    executedAtEpochMillis = Instant.parse("2026-10-05T20:00:00Z").toEpochMilli(),
                    resolver = SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.DnsResolver {
                        listOf("203.0.113.99")
                    },
                    probe = SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.HttpsTlsProbe {
                            _,
                            _,
                            _ ->
                        probeCalled = true
                        error("probe must not run")
                    },
                )
            }.exceptionOrNull()

            assertTrue(error is IllegalArgumentException)
            assertFalse(probeCalled)
        } finally {
            deleteTree(fixture.root)
        }
    }

    private data class Fixture(
        val root: Path,
        val preparation: SiteDeployerLocalPreparationResult,
        val composition: SiteProductionDeploymentCertificatePublicationCompositionResult,
        val selection: SiteProductionDeploymentServingPolicySelectionResult,
    )

    private fun fixture(): Fixture {
        val root = Files.createTempDirectory("phase11_97-")
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(11970L),
                domain = "Site.Example.COM",
                servicePort = 8443,
                remoteHostIdentity = REMOTE_HOST,
                targetRoot = "/srv/www/site",
                owner = "www_data",
                group = "www_data",
                reuseExisting3xUiCertificate = true,
            ),
            root,
        )
        val composition = SiteProductionDeploymentAndroidCertificatePublicationCompositionGate.composeValidated(
            preparation = preparation,
            staticPublicationEvidence = evidence(preparation),
            eligibilityReport = eligibilityReport(),
            observedRemoteHostIdentity = REMOTE_HOST,
            realVpsExecutionProofSha256 = "9".repeat(64),
        )
        val selection = SiteProductionDeploymentAndroidServingPolicySelectionBoundary.select(
            preparation = preparation,
            staticPublicationEvidence = evidence(preparation),
            certificateComposition = composition,
        )
        return Fixture(root, preparation, composition, selection)
    }

    private fun verificationPlan(fixture: Fixture) =
        SiteProductionDeploymentAndroidHttpsTlsServingVerificationBoundary.prepareAfterValidatedReload(
            preparation = fixture.preparation,
            certificateComposition = fixture.composition,
            selection = fixture.selection,
            postCoordinatorNginxReloadExecutionResultSha256 = "b".repeat(64),
            freshCertificateEligibilityExecutionProofSha256 = "c".repeat(64),
            freshCertificateReference = requireNotNull(fixture.composition.bindingReport.certificateReference),
        )

    private fun eligibilityReport() = SiteExisting3xUiCertificateReuseEligibilityBoundary.evaluate(
        plan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare(REMOTE_HOST),
        trust = SiteExisting3xUiCertificateReuseEligibilityTrust(HOST_KEY),
        observation = SiteExisting3xUiCertificateReuseEligibilityObservation(
            remoteHostIdentity = REMOTE_HOST,
            verifiedHostKeySha256 = HOST_KEY,
            databasePath = SiteExisting3xUiCertificateReuseEligibilityBoundary.DATABASE_PATH,
            databasePathType = SiteWebServingObservedPathType.FILE,
            sqliteReadOnlyAvailable = true,
            certificatePath = "/etc/ssl/x-ui/fullchain.pem",
            privateKeyPath = "/etc/ssl/x-ui/privkey.pem",
            certificatePathType = SiteWebServingObservedPathType.FILE,
            privateKeyPathType = SiteWebServingObservedPathType.FILE,
            certificateSha256 = "a".repeat(64),
            certificateDnsNames = listOf("site.example.com"),
            certificateNotBeforeEpochMillis = Instant.parse("2026-09-01T00:00:00Z").toEpochMilli(),
            certificateNotAfterEpochMillis = Instant.parse("2026-12-01T00:00:00Z").toEpochMilli(),
            remoteCommandCount = 3,
            mutationOperationPerformed = false,
            arbitraryCommandAccepted = false,
            privateKeyContentReadPerformed = false,
        ),
        observedAtEpochMillis = Instant.parse("2026-10-05T00:00:00Z").toEpochMilli(),
    )

    private fun evidence(preparation: SiteDeployerLocalPreparationResult) = SiteStaticPublicationEvidence(
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
