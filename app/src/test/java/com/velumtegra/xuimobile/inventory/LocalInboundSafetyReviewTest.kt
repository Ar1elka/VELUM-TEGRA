package com.velumtegra.xuimobile.inventory

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalInboundSafetyReviewTest {
    private fun change(old: String = "443", target: String = "8443",
        oldEnabled: Boolean = true, newEnabled: Boolean = false,
    ): LocalInboundChangeResult.Preview =
        LocalInboundChangePlanner.preview(
            LocalInboundChangeInput("17", old, target, oldEnabled, newEnabled),
        ) as LocalInboundChangeResult.Preview

    @Test fun `empty manual list creates reversible offline preview`() {
        val original = change()
        val reviewed = LocalInboundSafetyReviewer.review(original, "")
            as LocalInboundSafetyResult.Review
        assertFalse(reviewed.possibleProposedPortCollision)
        assertFalse(reviewed.possibleBaselineMismatch)
        assertEquals(8443, reviewed.reversePreview.currentPort)
        assertEquals(443, reviewed.reversePreview.proposedPort)
        assertFalse(reviewed.reversePreview.currentlyEnabled)
        assertTrue(reviewed.reversePreview.proposedEnabled)
        assertEquals(original,
            (LocalInboundSafetyReviewer.review(reviewed.reversePreview, "")
                as LocalInboundSafetyResult.Review).reversePreview)
    }

    @Test fun `manually listed proposed port is a potential collision only`() {
        val review = LocalInboundSafetyReviewer.review(change(), "80, 8443, 20222")
            as LocalInboundSafetyResult.Review
        assertTrue(review.possibleProposedPortCollision)
        assertFalse(review.possibleBaselineMismatch)
    }

    @Test fun `manually listed current port warns baseline mismatch`() {
        val review = LocalInboundSafetyReviewer.review(change(), "443, 80")
            as LocalInboundSafetyResult.Review
        assertFalse(review.possibleProposedPortCollision)
        assertTrue(review.possibleBaselineMismatch)
    }

    @Test fun `enable only changes do not report a proposed port collision`() {
        val review = LocalInboundSafetyReviewer.review(change(target = "443"), "443")
            as LocalInboundSafetyResult.Review
        assertFalse(review.possibleProposedPortCollision)
        assertTrue(review.possibleBaselineMismatch)
    }

    @Test fun `duplicate manually entered ports are rejected`() {
        assertEquals(LocalInboundSafetyIssue.DUPLICATE_OTHER_PORT,
            (LocalInboundSafetyReviewer.review(change(), "80, 443,80")
                as LocalInboundSafetyResult.Invalid).issue)
    }

    @Test fun `unsafe formats are refused and never reflected in result`() {
        listOf("0", "65536", "00080", "443;password=SECRET", "22\n23", "1,", ",1", "-5",
            "+80", "80\t,443", "99999999999999", "  ", "443, ０８０")
            .forEach { bad ->
                val result = LocalInboundSafetyReviewer.review(change(), bad)
                assertEquals(LocalInboundSafetyIssue.INVALID_OTHER_PORTS,
                    (result as LocalInboundSafetyResult.Invalid).issue)
                assertFalse(result.toString().contains(bad))
                assertFalse(result.toString().contains("SECRET"))
            }
    }

    @Test fun `more than 24 manually listed ports is rejected`() {
        val text = (1..25).joinToString(",")
        assertEquals(LocalInboundSafetyIssue.TOO_MANY_OTHER_PORTS,
            (LocalInboundSafetyReviewer.review(change(), text)
                as LocalInboundSafetyResult.Invalid).issue)
    }

    @Test fun `valid boundary ports never include raw user content`() {
        val review = LocalInboundSafetyReviewer.review(change(), "1, 65535")
            as LocalInboundSafetyResult.Review
        assertFalse(review.possibleProposedPortCollision)
        assertFalse(review.toString().contains("password="))
    }
}
