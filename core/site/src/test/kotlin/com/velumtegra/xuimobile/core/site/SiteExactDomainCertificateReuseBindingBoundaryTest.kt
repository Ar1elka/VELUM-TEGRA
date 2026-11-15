package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteExactDomainCertificateReuseBindingBoundaryTest {
    @Test
    fun `eligible same-server certificate covering exact domain becomes bound without https authority`() =
        withPreparation { preparation ->
            val report = eligibleReport(listOf("site.example.com", "www.example.com"))
            val binding = SiteExactDomainCertificateReuseBindingBoundary.evaluate(
                preparation,
                report,
                REMOTE_HOST,
            )

            assertEquals(
                SiteExactDomainCertificateReuseBindingStatus.BOUND_FOR_EXACT_DOMAIN_HTTPS_PLANNING,
                binding.status,
            )
            assertSame(report.certificateReference, binding.certificateReference)
            assertEquals("site.example.com", binding.requiredDomain)
            assertTrue(binding.checks.all { it.passed })
            assertFalse(binding.httpsPlanningAuthorized)
            assertFalse(binding.tlsConfigurationAuthorized)
            assertFalse(binding.privateKeyContentReadAuthorized)
            assertFalse(binding.productionNetworkTouched)
            SiteExactDomainCertificateReuseBindingBoundary.validate(binding)
        }

    @Test
    fun `exact live no-configured-panel-certificate shape remains fail closed`() =
        withPreparation { preparation ->
            val report = noConfiguredCertificateReport()
            val binding = SiteExactDomainCertificateReuseBindingBoundary.evaluate(
                preparation,
                report,
                REMOTE_HOST,
            )

            assertEquals(
                SiteExactDomainCertificateReuseBindingStatus.BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE,
                binding.status,
            )
            assertNull(binding.certificateReference)
            assertEquals(
                NO_CONFIGURED_CHECKS,
                binding.eligibilityFailedCheckCodes.toSet(),
            )
            assertFalse(binding.httpsPlanningAuthorized)
            assertFalse(binding.certificateMutationAuthorized)
            assertFalse(binding.automaticRetryAuthorized)
        }

    @Test
    fun `eligible certificate without exact domain blocks instead of using wildcard inference`() =
        withPreparation { preparation ->
            val report = eligibleReport(listOf("other.example.com"))
            val binding = SiteExactDomainCertificateReuseBindingBoundary.evaluate(
                preparation,
                report,
                REMOTE_HOST,
            )

            assertEquals(
                SiteExactDomainCertificateReuseBindingStatus.BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN,
                binding.status,
            )
            assertNull(binding.certificateReference)
            assertFalse(binding.checks.single {
                it.code == SiteExactDomainCertificateReuseBindingCheckCode.EXACT_REQUIRED_DOMAIN_COVERED
            }.passed)
        }

    @Test
    fun `host provenance mismatch requires reconciliation even for an eligible certificate`() =
        withPreparation { preparation ->
            val binding = SiteExactDomainCertificateReuseBindingBoundary.evaluate(
                preparation,
                eligibleReport(listOf("site.example.com")),
                "198.51.100.42",
            )

            assertEquals(
                SiteExactDomainCertificateReuseBindingStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
                binding.status,
            )
            assertNull(binding.certificateReference)
            assertFalse(binding.checks.single {
                it.code == SiteExactDomainCertificateReuseBindingCheckCode.OBSERVED_REMOTE_HOST_MATCHES_PREPARATION
            }.passed)
        }

    private fun eligibleReport(dnsNames: List<String>): SiteExisting3xUiCertificateReuseEligibilityReport {
        val plan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare(REMOTE_HOST)
        return SiteExisting3xUiCertificateReuseEligibilityBoundary.evaluate(
            plan = plan,
            trust = SiteExisting3xUiCertificateReuseEligibilityTrust(HOST_KEY),
            observation = baseObservation().copy(certificateDnsNames = dnsNames),
            observedAtEpochMillis = NOW,
        )
    }

    private fun noConfiguredCertificateReport(): SiteExisting3xUiCertificateReuseEligibilityReport {
        val plan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare(REMOTE_HOST)
        return SiteExisting3xUiCertificateReuseEligibilityBoundary.evaluate(
            plan = plan,
            trust = SiteExisting3xUiCertificateReuseEligibilityTrust(HOST_KEY),
            observation = baseObservation().copy(
                certificatePath = null,
                privateKeyPath = null,
                certificatePathType = null,
                privateKeyPathType = null,
                certificateSha256 = null,
                certificateDnsNames = emptyList(),
                certificateNotBeforeEpochMillis = null,
                certificateNotAfterEpochMillis = null,
                remoteCommandCount = 1,
            ),
            observedAtEpochMillis = NOW,
        )
    }

    private fun baseObservation() = SiteExisting3xUiCertificateReuseEligibilityObservation(
        remoteHostIdentity = REMOTE_HOST,
        verifiedHostKeySha256 = HOST_KEY,
        databasePath = SiteExisting3xUiCertificateReuseEligibilityBoundary.DATABASE_PATH,
        databasePathType = SiteWebServingObservedPathType.FILE,
        sqliteReadOnlyAvailable = true,
        certificatePath = "/etc/ssl/x-ui/fullchain.pem",
        privateKeyPath = "/etc/ssl/x-ui/privkey.pem",
        certificatePathType = SiteWebServingObservedPathType.FILE,
        privateKeyPathType = SiteWebServingObservedPathType.FILE,
        certificateSha256 = "a".repeat(64),
        certificateDnsNames = listOf("site.example.com"),
        certificateNotBeforeEpochMillis = Instant.parse("2026-09-01T00:00:00Z").toEpochMilli(),
        certificateNotAfterEpochMillis = Instant.parse("2026-12-01T00:00:00Z").toEpochMilli(),
        remoteCommandCount = 3,
        mutationOperationPerformed = false,
        arbitraryCommandAccepted = false,
        privateKeyContentReadPerformed = false,
    )

    private fun withPreparation(block: (SiteDeployerLocalPreparationResult) -> Unit) {
        val root = Files.createTempDirectory("phase11_66-")
        try {
            block(
                SiteDeployerLocalPreparationBoundary.prepare(
                    SiteDeployerLocalPreparationRequest(
                        rootSeed = DesignSeed(1166L),
                        domain = "Site.Example.COM",
                        servicePort = 8443,
                        remoteHostIdentity = REMOTE_HOST,
                        targetRoot = "/srv/www/site",
                        owner = "www_data",
                        group = "www_data",
                        reuseExisting3xUiCertificate = true,
                    ),
                    root,
                ),
            )
        } finally {
            deleteTree(root)
        }
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private companion object {
        const val REMOTE_HOST = "203.0.113.10"
        val HOST_KEY = "7".repeat(64)
        val NOW = Instant.parse("2026-10-04T00:00:00Z").toEpochMilli()
        val NO_CONFIGURED_CHECKS = setOf(
            SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_REFERENCE_CANONICAL,
            SiteExisting3xUiCertificateReuseEligibilityCheckCode.PRIVATE_KEY_REFERENCE_CANONICAL,
            SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_REGULAR_FILE,
            SiteExisting3xUiCertificateReuseEligibilityCheckCode.PRIVATE_KEY_REGULAR_FILE_SERVER_SIDE,
            SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_SHA256_OBSERVED,
            SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_DNS_NAMES_NORMALIZABLE,
            SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_CURRENTLY_VALID,
        )
    }
}
