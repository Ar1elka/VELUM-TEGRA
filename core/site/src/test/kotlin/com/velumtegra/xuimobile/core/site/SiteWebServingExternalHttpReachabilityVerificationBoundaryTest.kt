package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteWebServingExternalHttpReachabilityVerificationBoundaryTest {
    @Test
    fun acceptedLoopbackProofPlanProducesOneLiteralIpv4ExternalHttpProbe() {
        val root = Files.createTempDirectory("phase11_63-")
        try {
            val fixture = fixture(root, "203.0.113.7")
            val plan = SiteWebServingExternalHttpReachabilityVerificationBoundary.prepare(
                fixture.preparation,
                fixture.publication,
                fixture.reload,
                fixture.loopback,
            )
            SiteWebServingExternalHttpReachabilityVerificationBoundary.validateAgainst(
                plan,
                fixture.preparation,
                fixture.publication,
                fixture.reload,
                fixture.loopback,
            )
            assertEquals("203.0.113.7", plan.targetIpv4Literal)
            assertEquals(fixture.loopback.expectedBodySha256, plan.expectedBodySha256)
            assertTrue(plan.externalTcpConnectOnceAuthorized)
            assertTrue(plan.externalHttpGetOnceAuthorized)
            assertTrue(plan.externalNetworkPathReachabilityClaimAuthorized)
            assertFalse(plan.dnsResolutionAuthorized)
            assertFalse(plan.dnsMutationAuthorized)
            assertFalse(plan.firewallMutationAuthorized)
            assertFalse(plan.httpsAuthorized)
            assertFalse(plan.automaticRetryAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun hostnameRemoteTargetFailsClosedBecauseDnsIsSeparateAuthority() {
        val root = Files.createTempDirectory("phase11_63-dns-block-")
        try {
            val fixture = fixture(root, "server.example.com")
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingExternalHttpReachabilityVerificationBoundary.prepare(
                    fixture.preparation,
                    fixture.publication,
                    fixture.reload,
                    fixture.loopback,
                )
            }
        } finally {
            deleteTree(root)
        }
    }

    private data class Fixture(
        val preparation: SiteDeployerLocalPreparationResult,
        val publication: SiteWebServingPublicationPlan,
        val reload: SiteWebServingNginxReloadExecutionPlan,
        val loopback: SiteWebServingLiveHttpVerificationPlan,
    )

    private fun fixture(root: Path, host: String): Fixture {
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1163L),
                domain = "site.example.com",
                servicePort = 54325,
                remoteHostIdentity = host,
                targetRoot = "/srv/www/site",
                owner = "www_data",
                group = "www_data",
                reuseExisting3xUiCertificate = false,
            ),
            root,
        )
        val publication = SiteWebServingPublicationPlanBoundary.prepare(
            SiteWebServingPublicationPlanRequest(
                preparation = preparation,
                staticPublicationEvidence = SiteStaticPublicationEvidence(
                    preparationSha256 = preparation.preparationSha256,
                    remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
                    targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
                    finalTargetTreeSha256 = preparation.remoteDeployPlan.sourceTreeSha256,
                    committedClean = true,
                    remoteResidualStateClean = true,
                ),
                strategy = SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1,
                certificateReference = null,
            ),
        )
        val preflight = SiteWebServingReadOnlyPreflightBoundary.evaluate(
            publication,
            SiteWebServingReadOnlyPreflightTrust("b".repeat(64)),
            SiteWebServingReadOnlyPreflightObservation(
                remoteHostIdentity = publication.remoteHostIdentity,
                verifiedHostKeySha256 = "b".repeat(64),
                nginxExecutablePath = "/usr/sbin/nginx",
                confDPathType = SiteWebServingObservedPathType.DIRECTORY,
                configPath = publication.configPath,
                configPathType = SiteWebServingObservedPathType.ABSENT,
                existingConfigSha256 = null,
                listenerState = SiteWebServingListenerState.FREE,
                certificatePathType = null,
                observedCertificateSha256 = null,
                privateKeyPathType = null,
                remoteCommandCount = 4,
                mutationOperationPerformed = false,
                arbitraryCommandAccepted = false,
                privateKeyContentReadPerformed = false,
            ),
        )
        val mutation = SiteWebServingConfigMutationPreparationBoundary.prepare(
            SiteWebServingConfigMutationPreparationRequest(publication, preflight, "web-config-tx-1163"),
        )
        val staging = SiteWebServingConfigStagingSyntaxExecutionBoundary.prepare(mutation, publication, preflight)
        val activation = SiteWebServingConfigActivationExecutionBoundary.prepare(mutation, staging, publication, preflight)
        val reload = SiteWebServingNginxReloadExecutionBoundary.prepare(activation, publication)
        val loopback = SiteWebServingLiveHttpVerificationBoundary.prepare(preparation, publication, reload)
        return Fixture(preparation, publication, reload, loopback)
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}
