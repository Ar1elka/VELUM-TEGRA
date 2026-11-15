package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.assertIsDisplayed
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.MainActivity
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase12_4RealDeviceWholeAppNavigationUiAcceptanceInstrumentedTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun homeScannerAndSiteDeployerRemainReachableAndBackSafe() {
        compose.onNodeWithTag("home_root").fetchSemanticsNode()
        compose.onNodeWithText("Центр управления").fetchSemanticsNode()

        compose.onNodeWithTag("home_reality_scanner").performScrollTo().assertIsDisplayed().performClick()
        compose.onNodeWithTag("reality_scanner_root").fetchSemanticsNode()
        compose.onNodeWithText("Reality Scanner").fetchSemanticsNode()
        compose.runOnIdle {
            compose.activity.onBackPressedDispatcher.onBackPressed()
        }
        compose.onNodeWithTag("home_root").fetchSemanticsNode()

        compose.onNodeWithTag("home_site_deployer_review").performScrollTo().assertIsDisplayed().performClick()
        compose.onNodeWithTag("site_deployer_review_root").fetchSemanticsNode()
        compose.onNodeWithText("Site Deployer").fetchSemanticsNode()
        compose.runOnIdle {
            compose.activity.onBackPressedDispatcher.onBackPressed()
        }
        compose.onNodeWithTag("home_root").fetchSemanticsNode()
        compose.onNodeWithText("Центр управления").fetchSemanticsNode()
    }
}
