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

class SiteWebServingConfigActivationExecutionBoundaryTest {
    @Test
    fun successfulStagingSyntaxPlanProducesDeterministicActivationWithoutReloadAuthority() {
        val rootA = Files.createTempDirectory("phase11_60-a-")
        val rootB = Files.createTempDirectory("phase11_60-b-")
        try {
            val first = fixture(rootA, "web-config-tx-1160")
            val second = fixture(rootB, "web-config-tx-1160")
            assertEquals(first.activation.activationPlanSha256, second.activation.activationPlanSha256)
            assertEquals(first.mutation.stagingConfigPath, first.activation.stagingConfigPath)
            assertTrue(first.activation.requiresSuccessfulStagingSyntaxProof)
            assertTrue(first.activation.requiresDurablePreactivationCheckpoint)
            assertTrue(first.activation.stagingConfigWriteAuthorized)
            assertTrue(first.activation.exactConfigActivationAuthorized)
            assertTrue(first.activation.nginxSyntaxValidationAuthorized)
            assertFalse(first.activation.webServerReloadAuthorized)
            assertFalse(first.activation.dnsMutationAuthorized)
            assertFalse(first.activation.firewallMutationAuthorized)
            assertFalse(first.activation.packageInstallAuthorized)
            assertFalse(first.activation.automaticRetryAuthorized)
            assertEquals(
                listOf(
                    SiteWebServingConfigActivationAuthorizedStep.REVALIDATE_EXACT_BASELINE,
                    SiteWebServingConfigActivationAuthorizedStep.DURABLE_PREACTIVATION_CHECKPOINT,
                    SiteWebServingConfigActivationAuthorizedStep.WRITE_OPERATION_OWNED_STAGING_CONFIG,
                    SiteWebServingConfigActivationAuthorizedStep.VERIFY_STAGING_CONFIG_SHA256,
                    SiteWebServingConfigActivationAuthorizedStep.ATOMIC_ACTIVATE_EXACT_CONFIG_PATH,
                    SiteWebServingConfigActivationAuthorizedStep.VERIFY_EXACT_CONFIG_SHA256,
                    SiteWebServingConfigActivationAuthorizedStep.VALIDATE_NGINX_SYNTAX_WITH_EXACT_CONFIG,
                    SiteWebServingConfigActivationAuthorizedStep.VERIFY_STAGING_PATH_ABSENT,
                    SiteWebServingConfigActivationAuthorizedStep.VERIFY_LISTENER_STILL_FREE,
                ),
                first.activation.steps,
            )
        } finally {
            deleteTree(rootA)
            deleteTree(rootB)
        }
    }

    @Test
    fun differentTransactionChangesActivationIdentity() {
        val rootA = Files.createTempDirectory("phase11_60-id-a-")
        val rootB = Files.createTempDirectory("phase11_60-id-b-")
        try {
            val first = fixture(rootA, "web-config-tx-1160-a")
            val second = fixture(rootB, "web-config-tx-1160-b")
            assertNotEquals(first.activation.stagingConfigPath, second.activation.stagingConfigPath)
            assertNotEquals(first.activation.activationPlanSha256, second.activation.activationPlanSha256)
        } finally {
            deleteTree(rootA)
            deleteTree(rootB)
        }
    }

    @Test
    fun tamperedStagingSyntaxPlanFailsClosed() {
        val root = Files.createTempDirectory("phase11_60-block-")
        try {
            val fixture = fixture(root, "web-config-tx-1160")
            assertThrows(IllegalArgumentException::class.java) {
                SiteWebServingConfigActivationExecutionBoundary.prepare(
                    fixture.mutation,
                    fixture.stagingSyntax.copy(desiredConfigSha256 = "0".repeat(64)),
                    fixture.plan,
                    fixture.preflight,
                )
            }
        } finally {
            deleteTree(root)
        }
    }

    private data class Fixture(
        val plan: SiteWebServingPublicationPlan,
        val preflight: SiteWebServingReadOnlyPreflightReport,
        val mutation: SiteWebServingConfigMutationPreparation,
        val stagingSyntax: SiteWebServingConfigStagingSyntaxExecutionPlan,
        val activation: SiteWebServingConfigActivationExecutionPlan,
    )

    private fun fixture(root: Path, transactionId: String): Fixture {
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1160L),
                domain = "site.example.com",
                servicePort = 54322,
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
        val stagingSyntax = SiteWebServingConfigStagingSyntaxExecutionBoundary.prepare(mutation, plan, preflight)
        val activation = SiteWebServingConfigActivationExecutionBoundary.prepare(mutation, stagingSyntax, plan, preflight)
        return Fixture(plan, preflight, mutation, stagingSyntax, activation)
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}
