package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteWebServingRuntimeProvisioningBoundaryTest {
    @Test
    fun supportedMissingNginxPrerequisiteProducesExactSingleAttemptAptPlan() {
        val root = Files.createTempDirectory("phase11_59b-plan-")
        try {
            val publicationPlan = publicationPlan(root)
            val preflight = missingNginxPreflight(publicationPlan)
            val prerequisite = SiteWebServingRuntimePrerequisiteBoundary.evaluate(
                publicationPlan,
                preflight,
                SiteWebServingRuntimePrerequisiteObservation(
                    remoteHostIdentity = publicationPlan.remoteHostIdentity,
                    verifiedHostKeySha256 = "b".repeat(64),
                    distributionId = "ubuntu",
                    distributionVersionId = "24.04",
                    aptGetExecutablePath = "/usr/bin/apt-get",
                    dpkgQueryExecutablePath = "/usr/bin/dpkg-query",
                    nginxExecutablePath = null,
                    nginxRootPathType = SiteWebServingObservedPathType.ABSENT,
                    confDPathType = SiteWebServingObservedPathType.ABSENT,
                    remoteCommandCount = 6,
                    mutationOperationPerformed = false,
                    arbitraryCommandAccepted = false,
                ),
            )
            val plan = SiteWebServingRuntimeProvisioningBoundary.prepare(publicationPlan, prerequisite)
            SiteWebServingRuntimeProvisioningBoundary.validateAgainst(plan, publicationPlan, prerequisite)
            assertEquals("nginx", plan.packageName)
            assertEquals("/usr/bin/apt-get", plan.aptGetExecutablePath)
            assertEquals("/usr/bin/dpkg-query", plan.dpkgQueryExecutablePath)
            assertTrue(plan.requiresDurablePredispatchCheckpoint)
            assertTrue(plan.aptMetadataRefreshAuthorized)
            assertTrue(plan.packageInstallAuthorized)
            assertTrue(plan.packageManagedConfigCreationAuthorized)
            assertTrue(plan.packageManagedServiceLifecycleAuthorized)
            assertFalse(plan.siteConfigMutationAuthorized)
            assertFalse(plan.explicitServiceCommandAuthorized)
            assertFalse(plan.webServerReloadAuthorized)
            assertFalse(plan.dnsMutationAuthorized)
            assertFalse(plan.firewallMutationAuthorized)
            assertFalse(plan.automaticRetryAuthorized)
            assertEquals(9, plan.steps.size)
        } finally {
            deleteTree(root)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun blockedPrerequisiteCannotProducePackageMutationPlan() {
        val root = Files.createTempDirectory("phase11_59b-blocked-")
        try {
            val publicationPlan = publicationPlan(root)
            val preflight = missingNginxPreflight(publicationPlan)
            val blocked = SiteWebServingRuntimePrerequisiteBoundary.evaluate(
                publicationPlan,
                preflight,
                SiteWebServingRuntimePrerequisiteObservation(
                    remoteHostIdentity = publicationPlan.remoteHostIdentity,
                    verifiedHostKeySha256 = "b".repeat(64),
                    distributionId = "ubuntu",
                    distributionVersionId = "24.04",
                    aptGetExecutablePath = "/usr/bin/apt-get",
                    dpkgQueryExecutablePath = "/usr/bin/dpkg-query",
                    nginxExecutablePath = null,
                    nginxRootPathType = SiteWebServingObservedPathType.DIRECTORY,
                    confDPathType = SiteWebServingObservedPathType.ABSENT,
                    remoteCommandCount = 6,
                    mutationOperationPerformed = false,
                    arbitraryCommandAccepted = false,
                ),
            )
            SiteWebServingRuntimeProvisioningBoundary.prepare(publicationPlan, blocked)
        } finally {
            deleteTree(root)
        }
    }

    private fun missingNginxPreflight(plan: SiteWebServingPublicationPlan): SiteWebServingReadOnlyPreflightReport =
        SiteWebServingReadOnlyPreflightBoundary.evaluate(
            plan,
            SiteWebServingReadOnlyPreflightTrust("b".repeat(64)),
            SiteWebServingReadOnlyPreflightObservation(
                remoteHostIdentity = plan.remoteHostIdentity,
                verifiedHostKeySha256 = "b".repeat(64),
                nginxExecutablePath = null,
                confDPathType = SiteWebServingObservedPathType.ABSENT,
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

    private fun publicationPlan(root: Path): SiteWebServingPublicationPlan {
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(11592L),
                domain = "phase1159b.example.com",
                servicePort = 58475,
                remoteHostIdentity = "server-1.example",
                targetRoot = "/tmp/velum-p1159b",
                owner = "root",
                group = "root",
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

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}
