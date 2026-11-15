package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteWebServingReadOnlyPreflightBoundaryTest {
    @Test
    fun exactReadyHttpObservationProducesReadyReportWithoutMutationAuthority() {
        val root = Files.createTempDirectory("phase11_57-ready-")
        try {
            val plan = plan(root, reuseCertificate = false)
            val observation = SiteWebServingReadOnlyPreflightObservation(
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
            )
            val report = SiteWebServingReadOnlyPreflightBoundary.evaluate(
                plan,
                SiteWebServingReadOnlyPreflightTrust("b".repeat(64)),
                observation,
            )
            assertEquals(
                SiteWebServingReadOnlyPreflightStatus.READY_FOR_SEPARATE_CONFIG_MUTATION_BOUNDARY,
                report.status,
            )
            assertTrue(report.checks.all { it.passed })
            assertFalse(report.configMutationAuthorized)
            assertFalse(report.webServerReloadAuthorized)
            assertFalse(report.dnsMutationAuthorized)
            assertFalse(report.firewallMutationAuthorized)
            assertFalse(report.packageInstallAuthorized)
            assertFalse(report.automaticRetryAuthorized)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun existingConfigOrOccupiedPortBlocksAndRequiresSeparateReconciliation() {
        val root = Files.createTempDirectory("phase11_57-block-")
        try {
            val plan = plan(root, reuseCertificate = false)
            val observation = SiteWebServingReadOnlyPreflightObservation(
                remoteHostIdentity = plan.remoteHostIdentity,
                verifiedHostKeySha256 = "b".repeat(64),
                nginxExecutablePath = "/usr/sbin/nginx",
                confDPathType = SiteWebServingObservedPathType.DIRECTORY,
                configPath = plan.configPath,
                configPathType = SiteWebServingObservedPathType.FILE,
                existingConfigSha256 = plan.desiredConfigSha256,
                listenerState = SiteWebServingListenerState.OCCUPIED,
                certificatePathType = null,
                observedCertificateSha256 = null,
                privateKeyPathType = null,
                remoteCommandCount = 5,
                mutationOperationPerformed = false,
                arbitraryCommandAccepted = false,
                privateKeyContentReadPerformed = false,
            )
            val report = SiteWebServingReadOnlyPreflightBoundary.evaluate(
                plan,
                SiteWebServingReadOnlyPreflightTrust("b".repeat(64)),
                observation,
            )
            assertEquals(
                SiteWebServingReadOnlyPreflightStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
                report.status,
            )
            assertFalse(report.checks.first { it.code == SiteWebServingReadOnlyPreflightCheckCode.EXACT_CONFIG_PATH_ABSENT }.passed)
            assertFalse(report.checks.first { it.code == SiteWebServingReadOnlyPreflightCheckCode.LIVE_PORT_FREE }.passed)
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun httpsRequiresExactCertificateHashAndOnlyServerSidePrivateKeyPresence() {
        val root = Files.createTempDirectory("phase11_57-https-")
        try {
            val plan = plan(root, reuseCertificate = true)
            val observation = SiteWebServingReadOnlyPreflightObservation(
                remoteHostIdentity = plan.remoteHostIdentity,
                verifiedHostKeySha256 = "c".repeat(64),
                nginxExecutablePath = "/usr/sbin/nginx",
                confDPathType = SiteWebServingObservedPathType.DIRECTORY,
                configPath = plan.configPath,
                configPathType = SiteWebServingObservedPathType.ABSENT,
                existingConfigSha256 = null,
                listenerState = SiteWebServingListenerState.FREE,
                certificatePathType = SiteWebServingObservedPathType.FILE,
                observedCertificateSha256 = "0".repeat(64),
                privateKeyPathType = SiteWebServingObservedPathType.FILE,
                remoteCommandCount = 7,
                mutationOperationPerformed = false,
                arbitraryCommandAccepted = false,
                privateKeyContentReadPerformed = false,
            )
            val report = SiteWebServingReadOnlyPreflightBoundary.evaluate(
                plan,
                SiteWebServingReadOnlyPreflightTrust("c".repeat(64)),
                observation,
            )
            assertEquals(
                SiteWebServingReadOnlyPreflightStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
                report.status,
            )
            assertFalse(report.checks.first { it.code == SiteWebServingReadOnlyPreflightCheckCode.CERTIFICATE_SHA256_MATCHES }.passed)
            assertTrue(report.checks.first { it.code == SiteWebServingReadOnlyPreflightCheckCode.PRIVATE_KEY_FILE_PRESENT_SERVER_SIDE }.passed)
            assertFalse(observation.privateKeyContentReadPerformed)
        } finally {
            deleteTree(root)
        }
    }

    private fun plan(root: Path, reuseCertificate: Boolean): SiteWebServingPublicationPlan {
        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(1157L),
                domain = "site.example.com",
                servicePort = 54321,
                remoteHostIdentity = "server-1.example",
                targetRoot = "/srv/www/site",
                owner = "www_data",
                group = "www_data",
                reuseExisting3xUiCertificate = reuseCertificate,
            ),
            root,
        )
        val certificate = if (reuseCertificate) SiteServerCertificateFileReference(
            remoteHostIdentity = preparation.remoteDeployPlan.remoteHostIdentity,
            certificateSha256 = "a".repeat(64),
            dnsNames = listOf("site.example.com"),
            certificatePath = "/etc/x-ui/cert/fullchain.pem",
            privateKeyPath = "/etc/x-ui/cert/private.key",
            usableNow = true,
            privateKeyPresentOnServer = true,
        ) else null
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
                certificateReference = certificate,
            ),
        )
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }
}
