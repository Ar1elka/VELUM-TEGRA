package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteWebServingNginxReloadExecutionBoundaryTest {
    @Test
    fun activatedPlanProducesDeterministicReloadAuthorityWithoutOtherMutation() {
        val root = Files.createTempDirectory("phase11_61-")
        try {
            val fixture = fixture(root)
            val reload = SiteWebServingNginxReloadExecutionBoundary.prepare(fixture.activation, fixture.plan)
            SiteWebServingNginxReloadExecutionBoundary.validateAgainst(reload, fixture.activation, fixture.plan)
            assertEquals(fixture.activation.activationPlanSha256, reload.activationPlanSha256)
            assertEquals(fixture.plan.desiredConfigSha256, reload.desiredConfigSha256)
            assertEquals(fixture.plan.port, reload.expectedListenerPort)
            assertTrue(reload.requiresSuccessfulActivationProof)
            assertTrue(reload.requiresExactConfigShaBeforeReload)
            assertTrue(reload.requiresSuccessfulNginxSyntaxBeforeReload)
            assertTrue(reload.requiresListenerFreeBeforeReload)
            assertTrue(reload.requiresDurablePreReloadCheckpoint)
            assertTrue(reload.reloadNginxOnceAuthorized)
            assertTrue(reload.requiresExactConfigShaAfterReload)
            assertTrue(reload.requiresExpectedListenerLiveAfterReload)
            assertFalse(reload.configMutationAuthorized)
            assertFalse(reload.dnsMutationAuthorized)
            assertFalse(reload.firewallMutationAuthorized)
            assertFalse(reload.packageInstallAuthorized)
            assertFalse(reload.automaticRetryAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun tamperedActivationIdentityFailsClosed() {
        val root = Files.createTempDirectory("phase11_61-block-")
        try {
            val fixture = fixture(root)
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingNginxReloadExecutionBoundary.prepare(
                    fixture.activation.copy(publicationPlanSha256 = "0".repeat(64)),
                    fixture.plan,
                )
            }
        } finally {
            deleteTree(root)
        }
    }

    private data class Fixture(
        val plan: SiteWebServingPublicationPlan,
        val activation: SiteWebServingConfigActivationExecutionPlan,
    )

    private fun fixture(root: Path): Fixture {
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1161L),
                domain = "site.example.com",
                servicePort = 54323,
                remoteHostIdentity = "server-1.example",
                targetRoot = "/srv/www/site",
                owner = "www_data",
                group = "www_data",
                reuseExisting3xUiCertificate = false,
            ),
            root,
        )
        val plan = SiteWebServingPublicationPlanBoundary.prepare(
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
            plan,
            SiteWebServingReadOnlyPreflightTrust("b".repeat(64)),
            SiteWebServingReadOnlyPreflightObservation(
                remoteHostIdentity = plan.remoteHostIdentity,
                verifiedHostKeySha256 = "b".repeat(64),
                nginxExecutablePath = "/usr/sbin/nginx",
                confDPathType = SiteWebServingObservedPathType.DIRECTORY,
                configPath = plan.configPath,
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
            SiteWebServingConfigMutationPreparationRequest(plan, preflight, "web-config-tx-1161"),
        )
        val staging = SiteWebServingConfigStagingSyntaxExecutionBoundary.prepare(mutation, plan, preflight)
        val activation = SiteWebServingConfigActivationExecutionBoundary.prepare(mutation, staging, plan, preflight)
        return Fixture(plan, activation)
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}
