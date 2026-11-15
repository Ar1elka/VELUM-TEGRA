package com.velumtegra.xuimobile.inventory

import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PrivateWebPanelToolbarInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun singleCloseButtonCancelsPendingConnection() {
        val started = CompletableDeferred<Unit>()
        val cancelled = CompletableDeferred<Unit>()
        val port = object : PrivateWebPanelSshPort {
            override suspend fun open(request: PrivateWebPanelOpenRequest): PrivateWebPanelOpenResult {
                started.complete(Unit)
                try {
                    awaitCancellation()
                } finally {
                    cancelled.complete(Unit)
                }
            }
        }
        compose.setContent {
            var open by remember { mutableStateOf(true) }
            if (open) PrivateSshWebPanelScreen(
                request = PrivateWebPanelOpenRequest("fixture", WebPanelScheme.HTTPS, "127.0.0.1"),
                port = port,
                onClose = { open = false },
            )
        }

        compose.waitUntil(5_000) { started.isCompleted }
        assertSingleSshToolbar()
        compose.onNodeWithTag("webpanel_embedded_back").assertIsNotEnabled()
        compose.onNodeWithTag("private_panel_root_close").performClick()
        compose.waitUntil(5_000) { cancelled.isCompleted }
        compose.onAllNodesWithTag("webpanel_toolbar").assertCountEquals(0)
    }

    @Test fun singleCloseButtonRemainsAvailableWhenWebContentIsBlocked() {
        compose.setContent {
            var open by remember { mutableStateOf(true) }
            if (open) EmbeddedHttpsWebPanelScreen(
                initialUrl = "about:blank",
                onlyLocalSshOrigin = true,
                onClose = { open = false },
            )
        }

        compose.onNodeWithTag("webpanel_embedded_blocked").assertExists()
        assertSingleSshToolbar()
        compose.onNodeWithTag("private_panel_root_close").performClick()
        compose.onAllNodesWithTag("webpanel_toolbar").assertCountEquals(0)
    }

    private fun assertSingleSshToolbar() {
        compose.onAllNodesWithTag("webpanel_toolbar").assertCountEquals(1)
        compose.onAllNodesWithText("3x-ui · SSH").assertCountEquals(1)
        compose.onAllNodesWithText("Закрыть").assertCountEquals(1)
        compose.onAllNodesWithTag("webpanel_embedded_close").assertCountEquals(0)
    }
}
