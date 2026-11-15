package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteWebServingLiveHttpVerificationBoundaryTest {
    @Test
    fun successfulReloadProducesReadOnlyExactIndexVerificationPlan() {
        val root = Files.createTempDirectory("phase11_62-")
        try {
            val fixture = fixture(root)
            val plan = SiteWebServingLiveHttpVerificationBoundary.prepare(
                fixture.preparation,
                fixture.publication,
                fixture.reload,
            )
            SiteWebServingLiveHttpVerificationBoundary.validateAgainst(
                plan,
                fixture.preparation,
                fixture.publication,
                fixture.reload,
            )
            val index = fixture.preparation.bundle.documents.single { it.path == "index.html" }
            assertEquals(index.sha256, plan.expectedBodySha256)
            assertEquals(index.byteSize, plan.expectedBodyBytes)
            assertEquals("/index.html", plan.requestPath)
            assertTrue(plan.requiresSuccessfulReloadProof)
            assertTrue(plan.requiresExpectedListenerLiveBeforeProbe)
            assertTrue(plan.loopbackHttpGetOnceAuthorized)
            assertTrue(plan.requiresHttpStatus200)
            assertTrue(plan.requiresExactBodySha256)
            assertFalse(plan.externalReachabilityClaimAuthorized)
            assertFalse(plan.configMutationAuthorized)
            assertFalse(plan.dnsMutationAuthorized)
            assertFalse(plan.firewallMutationAuthorized)
            assertFalse(plan.packageInstallAuthorized)
            assertFalse(plan.automaticRetryAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun httpsPublicationFailsClosedBecauseTlsVerificationIsSeparateAuthority() {
        val root = Files.createTempDirectory("phase11_62-https-block-")
        try {
            val fixture = fixture(root)
            val https = fixture.publication.copy(
                protocol = SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE,
                certificateSha256 = "a".repeat(64),
                certificatePath = "/etc/ssl/certs/site.pem",
                privateKeyPath = "/etc/ssl/private/site.key",
            )
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingLiveHttpVerificationBoundary.prepare(
                    fixture.preparation,
                    https,
                    fixture.reload.copy(publicationPlanSha256 = https.publicationPlanSha256),
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
    )

    private fun fixture(root: Path): Fixture {
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1162L),
                domain = "site.example.com",
                servicePort = 54324,
                remoteHostIdentity = "server-1.example",
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
            SiteWebServingConfigMutationPreparationRequest(publication, preflight, "web-config-tx-1162"),
        )
        val staging = SiteWebServingConfigStagingSyntaxExecutionBoundary.prepare(mutation, publication, preflight)
        val activation = SiteWebServingConfigActivationExecutionBoundary.prepare(mutation, staging, publication, preflight)
        val reload = SiteWebServingNginxReloadExecutionBoundary.prepare(activation, publication)
        return Fixture(preparation, publication, reload)
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}
