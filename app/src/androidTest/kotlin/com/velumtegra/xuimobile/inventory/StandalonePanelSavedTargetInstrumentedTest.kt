package com.velumtegra.xuimobile.inventory

import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.domain.StandaloneWebPanelTargetDetails
import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class StandalonePanelSavedTargetInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun reopensWithSavedTargetOnlyForTheSameAccess() {
        val first = UUID.randomUUID().toString()
        val second = UUID.randomUUID().toString()
        val shown = mutableStateOf<String?>(first)
        val requests = mutableListOf<PrivateWebPanelOpenRequest>()
        val prefs = compose.activity.getSharedPreferences("standalone_panel_targets", 0)
        try {
            compose.setContent {
                shown.value?.let { accessId ->
                    PrivatePanelSshLaunchDialog(accessId, standalone = true,
                        onDismiss = { shown.value = null },
                        onConnect = { requests += it; shown.value = null })
                }
            }
            compose.onNodeWithTag("private_panel_connect").assertIsNotEnabled()
            compose.onNodeWithTag("manual_panel_port").performScrollTo().performTextReplacement("2053")
            compose.onNodeWithTag("manual_panel_web_path").performScrollTo().performTextReplacement("/fixture/")
            compose.onNodeWithTag("private_panel_http").performScrollTo().performClick()
            compose.onNodeWithTag("private_panel_connect").performClick()
            compose.runOnIdle {
                assertEquals(WebPanelScheme.HTTP, requests.single().scheme)
                assertEquals(StandaloneWebPanelTargetDetails.SshTunnel("127.0.0.1", 2053, "/fixture/"),
                    requests.single().standaloneTarget)
                shown.value = first
            }
            compose.onNodeWithTag("manual_panel_port").assertTextContains("2053")
            compose.onNodeWithTag("manual_panel_web_path").assertTextContains("/fixture/")
            compose.onNodeWithTag("private_panel_connect").performClick()
            compose.runOnIdle {
                assertEquals(WebPanelScheme.HTTPS, requests.last().scheme)
                assertEquals(requests.first().standaloneTarget, requests.last().standaloneTarget)
                shown.value = second
            }
            compose.onNodeWithTag("private_panel_connect").assertIsNotEnabled()
            compose.runOnIdle { assertEquals(2, requests.size) }
        } finally {
            prefs.edit().remove("$first.host").remove("$first.port").remove("$first.path").apply()
        }
    }
}
