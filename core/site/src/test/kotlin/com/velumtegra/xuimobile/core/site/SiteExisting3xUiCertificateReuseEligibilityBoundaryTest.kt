package com.velumtegra.xuimobile.core.site

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteExisting3xUiCertificateReuseEligibilityBoundaryTest {
    @Test
    fun `same server valid exact dns certificate becomes reusable reference without tls authority`() {
        val plan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare("203.0.113.10")
        val now = Instant.parse("2026-10-03T12:00:00Z").toEpochMilli()
        val report = SiteExisting3xUiCertificateReuseEligibilityBoundary.evaluate(
            plan = plan,
            trust = SiteExisting3xUiCertificateReuseEligibilityTrust(HOST_KEY),
            observation = observation(),
            observedAtEpochMillis = now,
        )

        assertEquals(
            SiteExisting3xUiCertificateReuseEligibilityStatus.ELIGIBLE_FOR_EXACT_DOMAIN_BINDING,
            report.status,
        )
        val reference = requireNotNull(report.certificateReference)
        assertEquals("203.0.113.10", reference.remoteHostIdentity)
        assertEquals(listOf("panel.example.com", "www.example.com"), reference.dnsNames)
        assertEquals("/etc/ssl/x-ui/fullchain.pem", reference.certificatePath)
        assertEquals("/etc/ssl/x-ui/privkey.pem", reference.privateKeyPath)
        assertTrue(reference.usableNow)
        assertTrue(reference.privateKeyPresentOnServer)
        assertFalse(report.certificateMutationAuthorized)
        assertFalse(report.tlsConfigurationAuthorized)
        assertFalse(report.privateKeyContentReadAuthorized)
        assertFalse(report.automaticRetryAuthorized)
        SiteExisting3xUiCertificateReuseEligibilityBoundary.validateReport(report)
    }

    @Test
    fun `wildcard or expired certificate blocks reuse and produces no reference`() {
        val plan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare("203.0.113.10")
        val now = Instant.parse("2026-10-03T12:00:00Z").toEpochMilli()
        val blocked = SiteExisting3xUiCertificateReuseEligibilityBoundary.evaluate(
            plan,
            SiteExisting3xUiCertificateReuseEligibilityTrust(HOST_KEY),
            observation().copy(
                certificateDnsNames = listOf("*.example.com"),
                certificateNotAfterEpochMillis = Instant.parse("2026-10-02T12:00:00Z").toEpochMilli(),
            ),
            now,
        )

        assertEquals(
            SiteExisting3xUiCertificateReuseEligibilityStatus.BLOCKED_REQUIRES_REVIEW_OR_RECONCILIATION,
            blocked.status,
        )
        assertNull(blocked.certificateReference)
        assertFalse(blocked.checks.single {
            it.code == SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_DNS_NAMES_NORMALIZABLE
        }.passed)
        assertFalse(blocked.checks.single {
            it.code == SiteExisting3xUiCertificateReuseEligibilityCheckCode.CERTIFICATE_CURRENTLY_VALID
        }.passed)
    }

    @Test
    fun `private key absence blocks reuse without authorizing key content access`() {
        val plan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare("203.0.113.10")
        val report = SiteExisting3xUiCertificateReuseEligibilityBoundary.evaluate(
            plan,
            SiteExisting3xUiCertificateReuseEligibilityTrust(HOST_KEY),
            observation().copy(privateKeyPathType = SiteWebServingObservedPathType.ABSENT),
            Instant.parse("2026-10-03T12:00:00Z").toEpochMilli(),
        )

        assertNull(report.certificateReference)
        assertFalse(report.privateKeyContentReadAuthorized)
        assertFalse(report.checks.single {
            it.code == SiteExisting3xUiCertificateReuseEligibilityCheckCode.PRIVATE_KEY_REGULAR_FILE_SERVER_SIDE
        }.passed)
    }

    private fun observation() = SiteExisting3xUiCertificateReuseEligibilityObservation(
        remoteHostIdentity = "203.0.113.10",
        verifiedHostKeySha256 = HOST_KEY,
        databasePath = SiteExisting3xUiCertificateReuseEligibilityBoundary.DATABASE_PATH,
        databasePathType = SiteWebServingObservedPathType.FILE,
        sqliteReadOnlyAvailable = true,
        certificatePath = "/etc/ssl/x-ui/fullchain.pem",
        privateKeyPath = "/etc/ssl/x-ui/privkey.pem",
        certificatePathType = SiteWebServingObservedPathType.FILE,
        privateKeyPathType = SiteWebServingObservedPathType.FILE,
        certificateSha256 = "a".repeat(64),
        certificateDnsNames = listOf("www.example.com", "panel.example.com"),
        certificateNotBeforeEpochMillis = Instant.parse("2026-09-01T12:00:00Z").toEpochMilli(),
        certificateNotAfterEpochMillis = Instant.parse("2026-12-01T12:00:00Z").toEpochMilli(),
        remoteCommandCount = 3,
        mutationOperationPerformed = false,
        arbitraryCommandAccepted = false,
        privateKeyContentReadPerformed = false,
    )

    private companion object {
        val HOST_KEY = "7".repeat(64)
    }
}
