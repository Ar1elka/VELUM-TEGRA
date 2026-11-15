package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.management.isSafeLocalPanelPath
import java.time.Duration
import java.time.Instant

/** Presentation fence only; the production port still owns consent, freshness and publication. */
object XuiEnrollmentUiPolicy {
    fun matches(review: XuiEnrollmentReview.Ready, exactTarget: String,
        candidate: XuiCandidateIdentityEvidence, now: Instant): Boolean =
        review.reviewToken.isNotBlank() && review.reviewToken.length <= 128 &&
            review.exactTarget == exactTarget &&
            XuiServiceVerificationPolicy.approvedCandidate(candidate) &&
            review.serviceUnit == candidate.serviceUnit && review.binaryPath == candidate.binaryPath &&
            review.databasePath == candidate.databasePath && review.panelPort in 1..65535 &&
            isSafeLocalPanelPath(review.webBasePath) &&
            now.isBefore(review.expiresAt) &&
            Duration.between(now, review.expiresAt) <= Duration.ofSeconds(90)
}
