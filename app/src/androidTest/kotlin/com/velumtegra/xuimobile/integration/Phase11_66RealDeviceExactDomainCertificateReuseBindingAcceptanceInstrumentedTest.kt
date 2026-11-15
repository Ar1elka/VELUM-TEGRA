package com.velumtegra.xuimobile.integration

import android.os.StrictMode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteExactDomainCertificateReuseBindingBoundary
import com.velumtegra.xuimobile.core.site.SiteExactDomainCertificateReuseBindingCheckCode
import com.velumtegra.xuimobile.core.site.SiteExactDomainCertificateReuseBindingStatus
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityObservation
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityTrust
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_66RealDeviceExactDomainCertificateReuseBindingAcceptanceInstrumentedTest {
    @Test
    fun exactDomainBindingIsDeterministicAndLiveNoConfiguredShapeRemainsFailClosedWithoutNetwork() {
        val priorPolicy = StrictMode.getThreadPolicy()
        StrictMode.setThreadPolicy(
            StrictMode.ThreadPolicy.Builder(priorPolicy)
                .detectNetwork()
                .penaltyDeath()
                .build(),
        )
        val cacheRoot = InstrumentationRegistry.getInstrumentation().targetContext.cacheDir.toPath()
        val firstRoot = Files.createTempDirectory(cacheRoot, "phase11_66-a-")
        val secondRoot = Files.createTempDirectory(cacheRoot, "phase11_66-b-")
        try {
            val firstPreparation = preparation(firstRoot)
            val secondPreparation = preparation(secondRoot)
            val eligible = eligibilityReport(listOf("site.example.com", "www.example.com"), configured = true)
            val first = SiteExactDomainCertificateReuseBindingBoundary.evaluate(firstPreparation, eligible, REMOTE_HOST)
            val second = SiteExactDomainCertificateReuseBindingBoundary.evaluate(secondPreparation, eligible, REMOTE_HOST)

            assertEquals(
                SiteExactDomainCertificateReuseBindingStatus.BOUND_FOR_EXACT_DOMAIN_HTTPS_PLANNING,
                first.status,
            )
            assertEquals(first.bindingReportSha256, second.bindingReportSha256)
            assertEquals(first.certificateReference, second.certificateReference)
            assertEquals("site.example.com", first.requiredDomain)
            assertTrue(first.checks.all { it.passed })
            assertFalse(first.httpsPlanningAuthorized)
            assertFalse(first.tlsConfigurationAuthorized)
            assertFalse(first.certificateMutationAuthorized)
            assertFalse(first.privateKeyContentReadAuthorized)
            assertFalse(first.productionNetworkTouched)

            val noConfigured = SiteExactDomainCertificateReuseBindingBoundary.evaluate(
                firstPreparation,
                eligibilityReport(emptyList(), configured = false),
                REMOTE_HOST,
            )
            assertEquals(
                SiteExactDomainCertificateReuseBindingStatus.BLOCKED_NO_CONFIGURED_3X_UI_PANEL_CERTIFICATE_REFERENCE,
                noConfigured.status,
            )
            assertNull(noConfigured.certificateReference)
            assertFalse(noConfigured.httpsPlanningAuthorized)
            assertFalse(noConfigured.automaticRetryAuthorized)

            val wrongDomain = SiteExactDomainCertificateReuseBindingBoundary.evaluate(
                firstPreparation,
                eligibilityReport(listOf("other.example.com"), configured = true),
                REMOTE_HOST,
            )
            assertEquals(
                SiteExactDomainCertificateReuseBindingStatus.BLOCKED_CERTIFICATE_DOES_NOT_COVER_EXACT_DOMAIN,
                wrongDomain.status,
            )
            assertFalse(wrongDomain.checks.single {
                it.code == SiteExactDomainCertificateReuseBindingCheckCode.EXACT_REQUIRED_DOMAIN_COVERED
            }.passed)
            assertNull(wrongDomain.certificateReference)
        } finally {
            deleteTree(firstRoot)
            deleteTree(secondRoot)
            StrictMode.setThreadPolicy(priorPolicy)
        }
    }

    private fun preparation(root: Path) = SiteDeployerLocalPreparationBoundary.prepare(
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
    )

    private fun eligibilityReport(
        dnsNames: List<String>,
        configured: Boolean,
    ) = SiteExisting3xUiCertificateReuseEligibilityBoundary.evaluate(
        plan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare(REMOTE_HOST),
        trust = SiteExisting3xUiCertificateReuseEligibilityTrust(HOST_KEY),
        observation = SiteExisting3xUiCertificateReuseEligibilityObservation(
            remoteHostIdentity = REMOTE_HOST,
            verifiedHostKeySha256 = HOST_KEY,
            databasePath = SiteExisting3xUiCertificateReuseEligibilityBoundary.DATABASE_PATH,
            databasePathType = SiteWebServingObservedPathType.FILE,
            sqliteReadOnlyAvailable = true,
            certificatePath = if (configured) "/etc/ssl/x-ui/fullchain.pem" else null,
            privateKeyPath = if (configured) "/etc/ssl/x-ui/privkey.pem" else null,
            certificatePathType = if (configured) SiteWebServingObservedPathType.FILE else null,
            privateKeyPathType = if (configured) SiteWebServingObservedPathType.FILE else null,
            certificateSha256 = if (configured) "a".repeat(64) else null,
            certificateDnsNames = dnsNames,
            certificateNotBeforeEpochMillis =
                if (configured) Instant.parse("2026-09-01T00:00:00Z").toEpochMilli() else null,
            certificateNotAfterEpochMillis =
                if (configured) Instant.parse("2026-12-01T00:00:00Z").toEpochMilli() else null,
            remoteCommandCount = if (configured) 3 else 1,
            mutationOperationPerformed = false,
            arbitraryCommandAccepted = false,
            privateKeyContentReadPerformed = false,
        ),
        observedAtEpochMillis = Instant.parse("2026-10-04T00:00:00Z").toEpochMilli(),
    )

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private companion object {
        const val REMOTE_HOST = "203.0.113.10"
        val HOST_KEY = "7".repeat(64)
    }
}
