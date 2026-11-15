package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteWebServingConfigMutationPreparationBoundaryTest {
    @Test
    fun exactReadyPreflightProducesDeterministicFiniteMutationPreparationWithoutAuthority() {
        val rootA = Files.createTempDirectory("phase11_58-a-")
        val rootB = Files.createTempDirectory("phase11_58-b-")
        try {
            val planA = plan(rootA)
            val planB = plan(rootB)
            val preflightA = readyPreflight(planA)
            val preflightB = readyPreflight(planB)

            val first = SiteWebServingConfigMutationPreparationBoundary.prepare(
                SiteWebServingConfigMutationPreparationRequest(planA, preflightA, "web-config-tx-1158"),
            )
            val second = SiteWebServingConfigMutationPreparationBoundary.prepare(
                SiteWebServingConfigMutationPreparationRequest(planB, preflightB, "web-config-tx-1158"),
            )

            assertEquals(first.mutationPreparationSha256, second.mutationPreparationSha256)
            assertEquals(first.stagingConfigPath, second.stagingConfigPath)
            assertEquals(SiteWebServingConfigRollbackBaseline.EXACT_CONFIG_PATH_PROVEN_ABSENT, first.rollbackBaseline)
            assertEquals(
                listOf(
                    SiteWebServingConfigMutationPreparedStep.DURABLE_BASELINE_CHECKPOINT,
                    SiteWebServingConfigMutationPreparedStep.WRITE_OPERATION_OWNED_STAGING_CONFIG,
                    SiteWebServingConfigMutationPreparedStep.VERIFY_STAGING_CONFIG_SHA256,
                    SiteWebServingConfigMutationPreparedStep.ATOMIC_ACTIVATE_EXACT_CONFIG_PATH,
                    SiteWebServingConfigMutationPreparedStep.VALIDATE_NGINX_SYNTAX,
                    SiteWebServingConfigMutationPreparedStep.DURABLE_PRE_RELOAD_CHECKPOINT,
                    SiteWebServingConfigMutationPreparedStep.RELOAD_NGINX_ONCE,
                    SiteWebServingConfigMutationPreparedStep.POST_SERVE_VERIFY,
                ),
                first.steps,
            )
            assertTrue(first.stagingConfigPath.startsWith("/etc/nginx/conf.d/.velum-tegra-"))
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
        }
    }

    @Test
    fun blockedOrMismatchedPreflightFailsClosed() {
        val root = Files.createTempDirectory("phase11_58-block-")
        try {
            val plan = plan(root)
            val ready = readyPreflight(plan)
            val blocked = ready.copy(
                status = SiteWebServingReadOnlyPreflightStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
                checks = ready.checks.map {
                    if (it.code == SiteWebServingReadOnlyPreflightCheckCode.LIVE_PORT_FREE) it.copy(passed = false) else it
                },
            )
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingConfigMutationPreparationBoundary.prepare(
                    SiteWebServingConfigMutationPreparationRequest(plan, blocked, "web-config-tx-1158"),
                )
            }
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingConfigMutationPreparationBoundary.prepare(
                    SiteWebServingConfigMutationPreparationRequest(
                        plan,
                        ready.copy(publicationPlanSha256 = "0".repeat(64)),
                        "web-config-tx-1158",
                    ),
                )
            }
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun transactionIdentityChangesOperationOwnedStagingAndPreparationIdentity() {
        val root = Files.createTempDirectory("phase11_58-id-")
        try {
            val plan = plan(root)
            val preflight = readyPreflight(plan)
            val first = SiteWebServingConfigMutationPreparationBoundary.prepare(
                SiteWebServingConfigMutationPreparationRequest(plan, preflight, "web-config-tx-1158-a"),
            )
            val second = SiteWebServingConfigMutationPreparationBoundary.prepare(
                SiteWebServingConfigMutationPreparationRequest(plan, preflight, "web-config-tx-1158-b"),
            )
            assertNotEquals(first.stagingConfigPath, second.stagingConfigPath)
            assertNotEquals(first.mutationPreparationSha256, second.mutationPreparationSha256)
        } finally {
            deleteTree(root)
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

    private fun readyPreflight(plan: SiteWebServingPublicationPlan): SiteWebServingReadOnlyPreflightReport =
        SiteWebServingReadOnlyPreflightBoundary.evaluate(
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
