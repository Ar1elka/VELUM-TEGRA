package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteWebServingRuntimePrerequisiteBoundaryTest {
    @Test
    fun cleanUbuntuAptHostWithOnlyMissingNginxGapRequiresSeparateProvisioningBoundary() {
        val root = Files.createTempDirectory("phase11_59a-ubuntu-")
        try {
            val plan = plan(root)
            val preflight = missingNginxPreflight(plan)
            val observation = SiteWebServingRuntimePrerequisiteObservation(
                remoteHostIdentity = plan.remoteHostIdentity,
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
            )
            val report = SiteWebServingRuntimePrerequisiteBoundary.evaluate(plan, preflight, observation)
            assertEquals(
                SiteWebServingRuntimePrerequisiteStatus.SUPPORTED_DEBIAN_APT_PROVISIONING_REQUIRED,
                report.status,
            )
            assertTrue(report.provisioningPreparationEligible)
            assertFalse(report.packageInstallAuthorized)
            assertFalse(report.configMutationAuthorized)
            assertFalse(report.webServerReloadAuthorized)
            assertFalse(report.automaticRetryAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun partialOrAmbiguousNginxStateRemainsBlocked() {
        val root = Files.createTempDirectory("phase11_59a-partial-")
        try {
            val plan = plan(root)
            val preflight = missingNginxPreflight(plan)
            val observation = SiteWebServingRuntimePrerequisiteObservation(
                remoteHostIdentity = plan.remoteHostIdentity,
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
            )
            val report = SiteWebServingRuntimePrerequisiteBoundary.evaluate(plan, preflight, observation)
            assertEquals(
                SiteWebServingRuntimePrerequisiteStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
                report.status,
            )
            assertFalse(report.provisioningPreparationEligible)
            assertFalse(report.packageInstallAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun alreadyReadyNginxRequiresFreshMainPreflightInsteadOfProvisioning() {
        val root = Files.createTempDirectory("phase11_59a-ready-")
        try {
            val plan = plan(root)
            val preflight = missingNginxPreflight(plan)
            val observation = SiteWebServingRuntimePrerequisiteObservation(
                remoteHostIdentity = plan.remoteHostIdentity,
                verifiedHostKeySha256 = "b".repeat(64),
                distributionId = "debian",
                distributionVersionId = "12",
                aptGetExecutablePath = "/usr/bin/apt-get",
                dpkgQueryExecutablePath = "/usr/bin/dpkg-query",
                nginxExecutablePath = "/usr/sbin/nginx",
                nginxRootPathType = SiteWebServingObservedPathType.DIRECTORY,
                confDPathType = SiteWebServingObservedPathType.DIRECTORY,
                remoteCommandCount = 6,
                mutationOperationPerformed = false,
                arbitraryCommandAccepted = false,
            )
            val report = SiteWebServingRuntimePrerequisiteBoundary.evaluate(plan, preflight, observation)
            assertEquals(
                SiteWebServingRuntimePrerequisiteStatus.EXISTING_NGINX_PREREQUISITES_READY_REQUIRES_FRESH_PREFLIGHT,
                report.status,
            )
            assertFalse(report.provisioningPreparationEligible)
            assertFalse(report.packageInstallAuthorized)
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
        ).also { report ->
            assertEquals(
                SiteWebServingReadOnlyPreflightStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
                report.status,
            )
            val failed = report.checks.filterNot { it.passed }.map { it.code }.toSet()
            assertEquals(
                setOf(
                    SiteWebServingReadOnlyPreflightCheckCode.NGINX_EXECUTABLE,
                    SiteWebServingReadOnlyPreflightCheckCode.NGINX_CONF_D_DIRECTORY,
                ),
                failed,
            )
        }

    private fun plan(root: Path): SiteWebServingPublicationPlan {
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(11591L),
                domain = "phase1159a.example.com",
                servicePort = 58474,
                remoteHostIdentity = "server-1.example",
                targetRoot = "/tmp/velum-p1159a",
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
