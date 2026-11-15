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

class SiteWebServingConfigStagingSyntaxExecutionBoundaryTest {
    @Test
    fun exactPreparationProducesDeterministicStagingOnlySyntaxAuthority() {
        val rootA = Files.createTempDirectory("phase11_59-a-")
        val rootB = Files.createTempDirectory("phase11_59-b-")
        try {
            val first = fixture(rootA, "web-config-tx-1159")
            val second = fixture(rootB, "web-config-tx-1159")

            assertEquals(first.execution.executionPlanSha256, second.execution.executionPlanSha256)
            assertEquals(first.execution.validationConfigPath, second.execution.validationConfigPath)
            assertTrue(first.execution.stagingConfigWriteAuthorized)
            assertTrue(first.execution.validationConfigWriteAuthorized)
            assertTrue(first.execution.isolatedNginxSyntaxValidationAuthorized)
            assertFalse(first.execution.exactConfigActivationAuthorized)
            assertFalse(first.execution.webServerReloadAuthorized)
            assertFalse(first.execution.dnsMutationAuthorized)
            assertFalse(first.execution.firewallMutationAuthorized)
            assertFalse(first.execution.packageInstallAuthorized)
            assertFalse(first.execution.automaticRetryAuthorized)
            assertTrue(first.execution.stagingConfigPath.endsWith(".stage"))
            assertTrue(first.execution.validationConfigPath.endsWith(".validate"))
            assertFalse(first.execution.stagingConfigPath.endsWith(".conf"))
            assertFalse(first.execution.validationConfigPath.endsWith(".conf"))
            assertTrue(first.execution.validationConfigUtf8.contains("http {"))
            assertTrue(first.execution.validationConfigUtf8.contains("include ${first.execution.stagingConfigPath};"))
            assertEquals(
                listOf(
                    SiteWebServingConfigStagingSyntaxAuthorizedStep.REVALIDATE_EXACT_BASELINE,
                    SiteWebServingConfigStagingSyntaxAuthorizedStep.DURABLE_BASELINE_CHECKPOINT,
                    SiteWebServingConfigStagingSyntaxAuthorizedStep.WRITE_OPERATION_OWNED_STAGING_CONFIG,
                    SiteWebServingConfigStagingSyntaxAuthorizedStep.VERIFY_STAGING_CONFIG_SHA256,
                    SiteWebServingConfigStagingSyntaxAuthorizedStep.WRITE_OPERATION_OWNED_VALIDATION_CONFIG,
                    SiteWebServingConfigStagingSyntaxAuthorizedStep.VERIFY_VALIDATION_CONFIG_SHA256,
                    SiteWebServingConfigStagingSyntaxAuthorizedStep.VALIDATE_NGINX_SYNTAX_AGAINST_STAGING,
                    SiteWebServingConfigStagingSyntaxAuthorizedStep.DELETE_OPERATION_OWNED_VALIDATION_CONFIG,
                    SiteWebServingConfigStagingSyntaxAuthorizedStep.DELETE_OPERATION_OWNED_STAGING_CONFIG,
                    SiteWebServingConfigStagingSyntaxAuthorizedStep.VERIFY_EXACT_CONFIG_STILL_ABSENT,
                    SiteWebServingConfigStagingSyntaxAuthorizedStep.VERIFY_LISTENER_STILL_FREE,
                ),
                first.execution.steps,
            )
        } finally {
            deleteTree(rootA)
            deleteTree(rootB)
        }
    }

    @Test
    fun transactionIdentityChangesExecutionIdentityAndOperationOwnedPaths() {
        val rootA = Files.createTempDirectory("phase11_59-id-a-")
        val rootB = Files.createTempDirectory("phase11_59-id-b-")
        try {
            val first = fixture(rootA, "web-config-tx-1159-a")
            val second = fixture(rootB, "web-config-tx-1159-b")
            assertNotEquals(first.preparation.stagingConfigPath, second.preparation.stagingConfigPath)
            assertNotEquals(first.execution.validationConfigPath, second.execution.validationConfigPath)
            assertNotEquals(first.execution.executionPlanSha256, second.execution.executionPlanSha256)
        } finally {
            deleteTree(rootA)
            deleteTree(rootB)
        }
    }

    @Test
    fun mismatchedPreparationOrPreflightFailsClosed() {
        val root = Files.createTempDirectory("phase11_59-block-")
        try {
            val fixture = fixture(root, "web-config-tx-1159")
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingConfigStagingSyntaxExecutionBoundary.prepare(
                    fixture.preparation.copy(publicationPlanSha256 = "0".repeat(64)),
                    fixture.plan,
                    fixture.preflight,
                )
            }
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingConfigStagingSyntaxExecutionBoundary.prepare(
                    fixture.preparation,
                    fixture.plan,
                    fixture.preflight.copy(status = SiteWebServingReadOnlyPreflightStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION),
                )
            }
        } finally {
            deleteTree(root)
        }
    }

    private data class Fixture(
        val plan: SiteWebServingPublicationPlan,
        val preflight: SiteWebServingReadOnlyPreflightReport,
        val preparation: SiteWebServingConfigMutationPreparation,
        val execution: SiteWebServingConfigStagingSyntaxExecutionPlan,
    )

    private fun fixture(root: Path, transactionId: String): Fixture {
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1159L),
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
            SiteWebServingConfigMutationPreparationRequest(plan, preflight, transactionId),
        )
        val execution = SiteWebServingConfigStagingSyntaxExecutionBoundary.prepare(mutation, plan, preflight)
        return Fixture(plan, preflight, mutation, execution)
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}
