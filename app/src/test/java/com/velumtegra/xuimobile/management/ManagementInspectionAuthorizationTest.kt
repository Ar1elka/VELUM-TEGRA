package com.velumtegra.xuimobile.management

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ManagementInspectionAuthorizationTest {
    private val review = LocalManagementReview.Ready(
        serverName = "Example",
        serverId = "server-11",
        installationId = "install-22",
        ownership = "ADOPTED",
        serviceUnit = "x-ui.service",
        panelPort = 2053,
        webBasePath = "/panel/",
        managementBindings = 2,
        accessIds = listOf("ssh-1", "ssh-2"),
    )

    @Test fun exactTupleIsRequired() {
        assertTrue(inspectionReviewMatches(review, "server-11", "install-22", "ssh-2"))
        assertFalse(inspectionReviewMatches(review, "server-OTHER", "install-22", "ssh-2"))
        assertFalse(inspectionReviewMatches(review, "server-11", "install-OTHER", "ssh-2"))
        assertFalse(inspectionReviewMatches(review, "server-11", "install-22", "ssh-OTHER"))
        assertFalse(inspectionReviewMatches(review, "", "install-22", "ssh-2"))
        assertFalse(inspectionReviewMatches(review, "server-11", "", "ssh-2"))
    }

    @Test fun staleOrUntrustedReviewIsBlocked() {
        assertFalse(inspectionReviewMatches(LocalManagementReview.Loading, "server-11", "install-22", "ssh-2"))
        assertFalse(inspectionReviewMatches(LocalManagementReview.Unavailable("missing"), "server-11", "install-22", "ssh-2"))
        assertFalse(inspectionReviewMatches(review.copy(managementBindings = 1), "server-11", "install-22", "ssh-2"))
        assertFalse(inspectionReviewMatches(review.copy(accessIds = listOf("ssh-1", "ssh-1")), "server-11", "install-22", "ssh-1"))
        assertFalse(inspectionReviewMatches(review.copy(panelPort = 0), "server-11", "install-22", "ssh-2"))
        assertFalse(inspectionReviewMatches(review.copy(webBasePath = "//foreign/panel"), "server-11", "install-22", "ssh-2"))
    }
}
