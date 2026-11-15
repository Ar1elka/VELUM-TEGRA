package com.velumtegra.xuimobile.integration

import android.os.StrictMode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteStaticPublicationEvidence
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationCounteraction
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparedStep
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigRollbackBaseline
import com.velumtegra.xuimobile.core.site.SiteWebServingListenerState
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanRequest
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightObservation
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightTrust
import com.velumtegra.xuimobile.core.site.SiteWebServingStrategy
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_58RealDeviceWebServingConfigMutationPreparationAcceptanceInstrumentedTest {
    @Test
    fun exactReadyPreflightProducesFiniteRollbackAwareMutationPreparationWithoutNetworkOrAuthority() {
        val priorPolicy = StrictMode.getThreadPolicy()
        StrictMode.setThreadPolicy(
            StrictMode.ThreadPolicy.Builder(priorPolicy)
                .detectNetwork()
                .penaltyDeath()
                .build(),
        )
        val cacheRoot = InstrumentationRegistry.getInstrumentation().targetContext.cacheDir.toPath()
        val rootA = Files.createTempDirectory(cacheRoot, "phase11_58-a-")
        val rootB = Files.createTempDirectory(cacheRoot, "phase11_58-b-")
        try {
            val planA = plan(rootA)
            val planB = plan(rootB)
            val first = SiteWebServingConfigMutationPreparationBoundary.prepare(
                SiteWebServingConfigMutationPreparationRequest(planA, readyPreflight(planA), "web-config-tx-1158"),
            )
            val second = SiteWebServingConfigMutationPreparationBoundary.prepare(
                SiteWebServingConfigMutationPreparationRequest(planB, readyPreflight(planB), "web-config-tx-1158"),
            )

            assertEquals(first.mutationPreparationSha256, second.mutationPreparationSha256)
            assertEquals(first.stagingConfigPath, second.stagingConfigPath)
            assertEquals(SiteWebServingConfigRollbackBaseline.EXACT_CONFIG_PATH_PROVEN_ABSENT, first.rollbackBaseline)
            assertEquals(SiteWebServingConfigMutationPreparedStep.DURABLE_BASELINE_CHECKPOINT, first.steps.first())
            assertEquals(SiteWebServingConfigMutationPreparedStep.POST_SERVE_VERIFY, first.steps.last())
            assertTrue(SiteWebServingConfigMutationPreparedStep.VALIDATE_NGINX_SYNTAX in first.steps)
            assertTrue(SiteWebServingConfigMutationPreparedStep.DURABLE_PRE_RELOAD_CHECKPOINT in first.steps)
            assertTrue(SiteWebServingConfigMutationCounteraction.READ_ONLY_RECONCILIATION_AFTER_UNCERTAIN_RELOAD in first.counteractions)
            assertTrue(SiteWebServingConfigMutationCounteraction.DELETE_EXACT_CONFIG_ONLY_IF_DESIRED_SHA_MATCHES in first.counteractions)
            assertTrue(first.stagingConfigPath.endsWith(".stage"))
            assertFalse(first.stagingConfigPath.endsWith(".conf"))
            assertTrue(first.requiresDurableBaselineCheckpointBeforeFirstWrite)
            assertTrue(first.requiresExactStagingShaVerification)
            assertTrue(first.requiresNginxSyntaxValidationBeforeReload)
            assertTrue(first.requiresDurablePreReloadCheckpoint)
            assertTrue(first.requiresPostServeVerification)
            assertFalse(first.configMutationAuthorized)
            assertFalse(first.webServerReloadAuthorized)
            assertFalse(first.dnsMutationAuthorized)
            assertFalse(first.firewallMutationAuthorized)
            assertFalse(first.packageInstallAuthorized)
            assertFalse(first.automaticRetryAuthorized)
        } finally {
            deleteTree(rootA)
            deleteTree(rootB)
            StrictMode.setThreadPolicy(priorPolicy)
        }
    }

    private fun plan(root: Path): SiteWebServingPublicationPlan {
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1158L),
                domain = "site.example.com",
                servicePort = 54321,
                remoteHostIdentity = "server-1.example",
                targetRoot = "/srv/www/site",
                owner = "www_data",
                group = "www_data",
                reuseExisting3xUiCertificate = false,
            ),
            root,
        )
        return SiteWebServingPublicationPlanBoundary.prepare(
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
    }

    private fun readyPreflight(plan: SiteWebServingPublicationPlan) = SiteWebServingReadOnlyPreflightBoundary.evaluate(
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

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}
