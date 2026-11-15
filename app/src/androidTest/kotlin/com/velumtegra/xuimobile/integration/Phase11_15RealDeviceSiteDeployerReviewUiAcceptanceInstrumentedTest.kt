package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.lifecycle.ViewModelProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.MainActivity
import com.velumtegra.xuimobile.core.site.SiteDeployerExecutionMode
import com.velumtegra.xuimobile.core.site.SiteDeployerPreflightState
import com.velumtegra.xuimobile.core.site.SiteDeployerReadiness
import com.velumtegra.xuimobile.core.site.ThemeFamily
import com.velumtegra.xuimobile.sitedeployer.SiteDeployerReviewViewModel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_15RealDeviceSiteDeployerReviewUiAcceptanceInstrumentedTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun russianReviewUiEditsRemainDryRunOnlyAndFailClosed() {
        compose.onNodeWithTag("home_site_deployer_review").performClick()
        compose.onNodeWithTag("site_deployer_review_root").fetchSemanticsNode()
        compose.onNodeWithText("Конструктор сайта").fetchSemanticsNode()
        compose.onNodeWithText("Предпросмотр без изменений").fetchSemanticsNode()
        compose.onNodeWithText("ТОЛЬКО ПРЕДПРОСМОТР").fetchSemanticsNode()
        compose.onNodeWithText("Изменение реального VPS: выключено").fetchSemanticsNode()
        compose.onNodeWithTag("site_deployer_target_root").performScrollTo().fetchSemanticsNode()
        compose.onNodeWithTag("site_deployer_prepare_production_context").performScrollTo().assertIsNotEnabled()

        val siteName = compose.onNodeWithTag("site_deployer_site_name")
        siteName.performScrollTo()
        siteName.performTextReplacement("Русский стенд")

        val tagline = compose.onNodeWithTag("site_deployer_tagline")
        tagline.performScrollTo()
        tagline.performTextReplacement("Проверка предпросмотра")

        val seed = compose.onNodeWithTag("site_deployer_seed")
        seed.performScrollTo()
        seed.performTextReplacement("115")

        compose.onNodeWithTag("site_deployer_theme").performScrollTo().performClick()

        val domain = compose.onNodeWithTag("site_deployer_domain")
        domain.performScrollTo()
        domain.performTextReplacement("ui-acceptance.example.com")

        val port = compose.onNodeWithTag("site_deployer_port")
        port.performScrollTo()
        port.performTextReplacement("70000")
        compose.onNodeWithText("Порт должен быть числом от 1 до 65535.").fetchSemanticsNode()

        val viewModel = ViewModelProvider(compose.activity)[SiteDeployerReviewViewModel::class.java]
        compose.waitForIdle()
        assertNull(viewModel.uiState.value.review)
        assertFalse(viewModel.uiState.value.writeActionsEnabled)
        assertFalse(viewModel.uiState.value.realServerMutationEnabled)

        port.performTextReplacement("8443")
        compose.onNodeWithTag("site_deployer_certificate_reuse").performScrollTo().performClick()
        compose.waitForIdle()

        val state = viewModel.uiState.value
        val review = state.review ?: throw AssertionError("valid review must exist")
        assertEquals("Русский стенд", state.form.siteName)
        assertEquals("Проверка предпросмотра", state.form.tagline)
        assertEquals("115", state.form.seed)
        assertEquals(ThemeFamily.DARK_TECH, state.form.themeFamily)
        assertEquals("ui-acceptance.example.com", state.form.domain)
        assertEquals("8443", state.form.port)
        assertTrue(state.form.reuseExisting3xUiCertificate)
        assertFalse(state.writeActionsEnabled)
        assertFalse(state.realServerMutationEnabled)
        assertNull(state.selectedReleaseServerId)
        assertNull(state.selectedReleaseServerAccessId)
        assertNull(state.releaseBootstrapAdmissionSha256)

        assertEquals(SiteDeployerExecutionMode.DRY_RUN_ONLY, review.executionMode)
        assertFalse(review.realServerMutationEnabled)
        assertTrue(review.fixtureDeploymentOnly)
        assertEquals("Русский стенд", review.design.siteName)
        assertEquals("ui-acceptance.example.com", review.serviceBinding.domain)
        assertEquals(8443, review.serviceBinding.port)
        assertFalse(review.serviceBinding.appliedByCurrentDeployContract)
        assertEquals(SiteDeployerReadiness.UNKNOWN, review.remoteTarget.readiness)
        assertTrue(review.certificate.requested)
        assertEquals(SiteDeployerReadiness.UNKNOWN, review.certificate.readiness)
        assertEquals(SiteDeployerPreflightState.NOT_OBSERVED, review.preflight.state)
        assertFalse(review.preflight.authorizesTransport)
        assertTrue(review.preflight.checks.isEmpty())
        assertTrue(review.preflightBlockers.isEmpty())

        compose.onNodeWithText("Адрес сервиса: ui-acceptance.example.com:8443").performScrollTo().fetchSemanticsNode()
        compose.onNodeWithText("Состояние: Сервер ещё не проверен").performScrollTo().fetchSemanticsNode()
        compose.onNodeWithText("Причины блокировки: станут известны после проверки сервера").performScrollTo().fetchSemanticsNode()
        compose.onNodeWithTag("site_deployer_no_write_notice").performScrollTo().fetchSemanticsNode()
    }
}
