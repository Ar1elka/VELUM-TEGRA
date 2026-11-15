package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.site.SiteDeployerPreflightState
import com.velumtegra.xuimobile.core.site.SiteDeployerReadiness
import com.velumtegra.xuimobile.core.site.SiteRemoteCertificateObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPath
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import com.velumtegra.xuimobile.core.site.SiteRemoteOwnershipObservation
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightCheckCode
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteServerObservation
import com.velumtegra.xuimobile.core.site.ThemeFamily
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteDeployerReviewViewModelTest {
    @Test
    fun `default screen state is deterministic dry run with no write action`() {
        val viewModel = SiteDeployerReviewViewModel()
        val state = viewModel.uiState.value
        val review = requireNotNull(state.review)

        assertFalse(state.writeActionsEnabled)
        assertFalse(state.realServerMutationEnabled)
        assertFalse(review.realServerMutationEnabled)
        assertTrue(review.fixtureDeploymentOnly)
        assertFalse(review.preflight.authorizesTransport)
        assertEquals(SiteDeployerPreflightState.NOT_OBSERVED, review.preflight.state)
        assertEquals(SiteDeployerReadiness.UNKNOWN, review.remoteTarget.readiness)
        assertTrue(state.releaseTargets.isEmpty())
        assertNull(state.selectedReleaseServerId)
        assertNull(state.selectedReleaseServerAccessId)
        assertNull(state.releaseBootstrapAdmissionSha256)
        assertFalse(state.releaseBootstrapInProgress)
    }

    @Test
    fun `production target binding replaces fixture target inputs without granting mutation authority`() {
        val boundKey = "c".repeat(64)
        val port = object : SiteDeployerProductionExecutionPort {
            override fun currentTargetBinding() = SiteProductionDeploymentUiTargetBinding(
                remoteHostIdentity = "203.0.113.93",
                targetRoot = "/srv/www/phase1193",
                owner = "www-data",
                group = "www-data",
                existingTargetPolicy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                certificateReuseRequested = false,
                trustedServerKeySha256 = boundKey,
            )

            override fun currentAdmission(
                review: com.velumtegra.xuimobile.core.site.SiteDeployerReviewState,
            ): SiteProductionDeploymentUiAdmission? = null

            override suspend fun executeOnce(
                authorization: SiteProductionDeploymentUiExecutionAuthorization,
            ): SiteProductionDeploymentUiExecutionReceipt = error("not authorized in target-binding test")
        }

        val viewModel = SiteDeployerReviewViewModel(port)
        val state = viewModel.uiState.value
        val review = requireNotNull(state.review)

        assertEquals("203.0.113.93", review.remoteTarget.remoteHostIdentity)
        assertEquals("/srv/www/phase1193", review.remoteTarget.targetRoot)
        assertEquals(SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE, review.remoteTarget.existingTargetPolicy)
        assertNotNull(review.remoteTarget.backupRoot)
        assertNull(state.productionAdmission)
        assertFalse(state.productionDeployEnabled)
        assertFalse(state.writeActionsEnabled)
        assertFalse(state.realServerMutationEnabled)
    }

    @Test
    fun `editing identity domain port and seed rebuilds exact review projection`() {
        val viewModel = SiteDeployerReviewViewModel()
        val before = requireNotNull(viewModel.uiState.value.review)

        viewModel.onSiteNameChanged("Velum Nova")
        viewModel.onTaglineChanged("Review only")
        viewModel.onDomainChanged("Example.COM")
        viewModel.onPortChanged("8443")
        viewModel.generateNextVariant()

        val state = viewModel.uiState.value
        val review = requireNotNull(state.review)
        assertNull(state.validationMessage)
        assertEquals("Velum Nova", review.design.siteName)
        assertEquals("Review only", review.design.tagline)
        assertEquals("example.com", review.serviceBinding.domain)
        assertEquals(8443, review.serviceBinding.port)
        assertNotEquals(before.reviewSha256, review.reviewSha256)
        assertFalse(review.serviceBinding.appliedByCurrentDeployContract)
        assertFalse(review.preflight.authorizesTransport)
    }

    @Test
    fun `theme override cycles from automatic and keeps mutation disabled`() {
        val viewModel = SiteDeployerReviewViewModel()
        assertNull(viewModel.uiState.value.form.themeFamily)

        viewModel.cycleThemeOverride()

        val state = viewModel.uiState.value
        val review = requireNotNull(state.review)
        assertEquals(ThemeFamily.values().first(), state.form.themeFamily)
        assertEquals(ThemeFamily.values().first(), review.design.themeFamily)
        assertFalse(state.writeActionsEnabled)
        assertFalse(review.realServerMutationEnabled)
    }

    @Test
    fun `invalid user input fails closed without stale review`() {
        val viewModel = SiteDeployerReviewViewModel()

        viewModel.onDomainChanged("localhost")
        assertNull(viewModel.uiState.value.review)
        assertNotNull(viewModel.uiState.value.validationMessage)
        assertFalse(viewModel.uiState.value.writeActionsEnabled)

        viewModel.onDomainChanged("site.example.com")
        viewModel.onPortChanged("70000")
        assertNull(viewModel.uiState.value.review)
        assertNotNull(viewModel.uiState.value.validationMessage)
        assertFalse(viewModel.uiState.value.realServerMutationEnabled)
    }

    @Test
    fun `editing form invalidates previously observed remote evidence`() {
        val viewModel = SiteDeployerReviewViewModel()
        viewModel.onCertificateReuseChanged(true)
        val draft = requireNotNull(viewModel.uiState.value.review)
        viewModel.replaceReadOnlyObservation(readyObservation(draft))
        assertEquals(SiteDeployerPreflightState.READY, requireNotNull(viewModel.uiState.value.review).preflight.state)

        viewModel.onSiteNameChanged("Changed after observation")

        val changed = requireNotNull(viewModel.uiState.value.review)
        assertEquals(SiteDeployerPreflightState.NOT_OBSERVED, changed.preflight.state)
        assertEquals(SiteDeployerReadiness.UNKNOWN, changed.remoteTarget.readiness)
        assertEquals(SiteDeployerReadiness.UNKNOWN, changed.certificate.readiness)
        assertFalse(changed.preflight.authorizesTransport)
    }

    @Test
    fun `read only observation seam projects ready and blocked evidence but never transport authorization`() {
        val viewModel = SiteDeployerReviewViewModel()
        viewModel.onCertificateReuseChanged(true)
        val draft = requireNotNull(viewModel.uiState.value.review)

        viewModel.replaceReadOnlyObservation(readyObservation(draft))
        val ready = requireNotNull(viewModel.uiState.value.review)
        assertEquals(SiteDeployerPreflightState.READY, ready.preflight.state)
        assertEquals(SiteDeployerReadiness.READY, ready.remoteTarget.readiness)
        assertEquals(SiteDeployerReadiness.READY, ready.certificate.readiness)
        assertFalse(ready.preflight.authorizesTransport)

        val blockedObservation = readyObservation(ready).copy(
            target = SiteRemoteObservedPath(
                path = ready.remoteTarget.targetRoot,
                type = SiteRemoteObservedPathType.FILE,
                byteSize = 1,
            ),
            availableBytes = 0,
            certificate = SiteRemoteCertificateObservation(
                serverKeySha256 = SiteDeployerReviewViewModel.FIXTURE_SERVER_KEY_SHA256,
                dnsNames = listOf("other.example.com"),
                certificateSha256 = "b".repeat(64),
                usableNow = false,
                privateKeyPresentOnServer = true,
            ),
        )
        viewModel.replaceReadOnlyObservation(blockedObservation)

        val blocked = requireNotNull(viewModel.uiState.value.review)
        val blockerCodes = blocked.preflightBlockers.map { it.code }.toSet()
        assertEquals(SiteDeployerPreflightState.BLOCKED, blocked.preflight.state)
        assertTrue(SiteRemotePreflightCheckCode.TARGET_STATE in blockerCodes)
        assertTrue(SiteRemotePreflightCheckCode.AVAILABLE_CAPACITY in blockerCodes)
        assertTrue(SiteRemotePreflightCheckCode.CERTIFICATE_DOMAIN in blockerCodes)
        assertTrue(SiteRemotePreflightCheckCode.CERTIFICATE_USABLE_NOW in blockerCodes)
        assertFalse(blocked.preflight.authorizesTransport)
        assertFalse(viewModel.uiState.value.writeActionsEnabled)
    }

    private fun readyObservation(review: com.velumtegra.xuimobile.core.site.SiteDeployerReviewState) =
        SiteRemotePreflightObservation(
            server = SiteRemoteServerObservation(
                remoteHostIdentity = review.remoteTarget.remoteHostIdentity,
                serverKeySha256 = SiteDeployerReviewViewModel.FIXTURE_SERVER_KEY_SHA256,
            ),
            target = SiteRemoteObservedPath(
                path = review.remoteTarget.targetRoot,
                type = SiteRemoteObservedPathType.ABSENT,
            ),
            staging = SiteRemoteObservedPath(
                path = review.remoteTarget.stagingRoot,
                type = SiteRemoteObservedPathType.ABSENT,
            ),
            backup = review.remoteTarget.backupRoot?.let {
                SiteRemoteObservedPath(path = it, type = SiteRemoteObservedPathType.ABSENT)
            },
            availableBytes = review.preflight.requiredAvailableBytes + 4096,
            ownership = SiteRemoteOwnershipObservation(
                ownerExists = true,
                groupExists = true,
                ownershipChangeApplicable = true,
                modeChangeApplicable = true,
            ),
            certificate = SiteRemoteCertificateObservation(
                serverKeySha256 = SiteDeployerReviewViewModel.FIXTURE_SERVER_KEY_SHA256,
                dnsNames = listOf(review.serviceBinding.domain),
                certificateSha256 = "b".repeat(64),
                usableNow = true,
                privateKeyPresentOnServer = true,
            ),
        )
}
