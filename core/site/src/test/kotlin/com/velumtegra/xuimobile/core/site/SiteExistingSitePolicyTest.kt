package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteExistingSitePolicyTest {
    private val sha = "a".repeat(64)
    private val ownSite = SiteExistingTargetObservation(
        present = true,
        isDirectory = true,
        totalFileCount = 2,
        hasSymlinksOrSpecialEntries = false,
        hasEmptyDirectories = false,
        files = listOf(
            SiteExistingTargetFile("index.html", 120, sha),
            SiteExistingTargetFile("css/site.css", 80, sha),
        ),
    )

    @Test
    fun `free endpoint is not a conflict`() {
        val report = SiteExistingSitePolicy.report(
            "/var/www/velum-site",
            443,
            SiteExistingTargetObservation.ABSENT,
            SiteEndpointObservation(configPresent = false, portInUse = false, listeningPorts = setOf(22)),
        )
        assertFalse(report.conflict)
    }

    @Test
    fun `own previous site on same endpoint can be replaced keeping nginx config`() {
        val report = SiteExistingSitePolicy.report(
            "/var/www/velum-site",
            443,
            ownSite,
            SiteEndpointObservation(configPresent = true, portInUse = true, listeningPorts = setOf(22, 443)),
        )
        assertTrue(report.conflict)
        assertTrue(report.replaceAvailable)
        assertTrue(report.replaceKeepsExistingWebServerConfig)
        assertFalse(report.portUsedByOtherService)
        assertEquals(8443, report.suggestedPort)
        assertEquals("/var/www/velum-site-8443", report.suggestedTargetRoot)
    }

    @Test
    fun `port taken by another program blocks replacement but offers another port`() {
        val report = SiteExistingSitePolicy.report(
            "/var/www/velum-site",
            443,
            ownSite,
            SiteEndpointObservation(configPresent = false, portInUse = true, listeningPorts = setOf(443, 8443)),
        )
        assertEquals(SiteReplaceBlocker.PORT_USED_BY_OTHER_SERVICE, report.replaceBlocker)
        assertEquals(2053, report.suggestedPort)
    }

    @Test
    fun `busy port without folder keeps folder and moves only the port`() {
        val report = SiteExistingSitePolicy.report(
            "/var/www/velum-site",
            443,
            SiteExistingTargetObservation.ABSENT,
            SiteEndpointObservation(configPresent = false, portInUse = true, listeningPorts = setOf(443)),
        )
        assertTrue(report.conflict)
        assertEquals(SiteReplaceBlocker.TARGET_ABSENT, report.replaceBlocker)
        assertEquals("/var/www/velum-site", report.suggestedTargetRoot)
    }

    @Test
    fun `large or unsupported folders are not replaceable`() {
        assertEquals(
            SiteReplaceBlocker.TOO_MANY_FILES,
            SiteExistingSitePolicy.replaceBlocker(ownSite.copy(totalFileCount = 500, files = emptyList()), false),
        )
        assertEquals(
            SiteReplaceBlocker.UNSUPPORTED_FILE,
            SiteExistingSitePolicy.replaceBlocker(
                ownSite.copy(totalFileCount = 1, files = listOf(SiteExistingTargetFile("photo.jpg", 10, sha))),
                false,
            ),
        )
        assertNull(SiteExistingSitePolicy.previousTreeExpectation(ownSite.copy(hasEmptyDirectories = true), sha))
    }

    @Test
    fun `alternate root is stable`() {
        assertEquals("/srv/site-2053", SiteExistingSitePolicy.alternateTargetRoot("/srv/site", 2053))
        assertEquals("/srv/site-2053", SiteExistingSitePolicy.alternateTargetRoot("/srv/site-2053", 2053))
    }
}
