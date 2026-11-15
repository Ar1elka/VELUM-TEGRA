package com.velumtegra.xuimobile.discovery

import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.readiness.LocalSshAccessList
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.readiness.SshReadinessPort
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * In-process Compose regression for the explicit fresh-install confirmation. All ports are fakes:
 * no SSH, no VPS, no real address, no secret, no network and no database.
 */
@RunWith(AndroidJUnit4::class)
class XuiFreshInstallConfirmationInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val access = LocalSshAccessSummary(
        accessId = "fixture-access", host = "fixture.invalid", port = 22, username = "fixture",
        authLabel = "fixture-auth", savedFingerprint = "SHA256:fixture", credentialRefDigest = "fixture-digest",
    )

    private val readiness = object : SshReadinessPort {
        var previews = 0
        override suspend fun listForExactServer(serverId: String) = LocalSshAccessList.Available(listOf(access))
        override suspend fun previewExact(serverId: String, accessId: String): LocalSshReadinessResult {
            previews++
            return LocalSshReadinessResult.MetadataPresent(access)
        }
    }

    private val discovery = object : XuiReadOnlyDiscoveryPort {
        var readinessChecks = 0
        override val supportsFreshInstallReadiness = true
        override suspend fun checkFreshInstallReadiness(
            serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
            repeatedTarget: String, consent: Boolean,
        ): XuiReadOnlyDiscoveryResult {
            readinessChecks++
            return XuiReadOnlyDiscoveryResult.Observation("Fixture ready", "fixture", freshInstallReady = true)
        }
        override suspend fun inspectExact(
            serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
            repeatedTarget: String, consent: Boolean,
        ): XuiReadOnlyDiscoveryResult = XuiReadOnlyDiscoveryResult.Blocked("fixture: not used")
    }

    /** Fake local journal: a recorded request stays pending and is only ever read back, never re-sent. */
    private val install = object : XuiFreshInstallActionPort {
        val starts = mutableListOf<String>()
        private val pending = mutableListOf<XuiFreshInstallObservation>()
        override suspend fun startConfirmed(serverId: String, reviewed: LocalSshAccessSummary): XuiFreshInstallStart {
            starts += serverId
            val id = "fixture-op-${starts.size}"
            pending += XuiFreshInstallObservation(id, "Fixture pending request", terminal = false, mayCancelBeforeDispatch = true)
            return XuiFreshInstallStart.Recorded(id)
        }
        override suspend fun recoverExact(serverId: String, reviewed: LocalSshAccessSummary) =
            XuiFreshInstallRecovery(own = pending.toList(), otherProfileBlockers = 0)
        override suspend fun statusExact(operationId: String, serverId: String, reviewed: LocalSshAccessSummary) =
            pending.firstOrNull { it.operationId == operationId }
        override suspend fun checkResultConfirmed(operationId: String, serverId: String, reviewed: LocalSshAccessSummary): String? = null
        override suspend fun cancelBeforeDispatch(operationId: String, serverId: String, reviewed: LocalSshAccessSummary): String? = null
    }

    private fun AndroidComposeTestRule<*, *>.await(tag: String) =
        waitUntil(10_000) { onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }

    private fun AndroidComposeTestRule<*, *>.tap(tag: String) {
        await(tag)
        onNodeWithTag(tag).performScrollTo().performClick()
    }

    private fun showScreen(shown: androidx.compose.runtime.MutableState<Boolean>) = compose.setContent {
        if (shown.value) {
            XuiReadOnlyDiscoveryScreen("fixture-server", "Fixture", readiness, discovery, onBack = {}, installPort = install)
        }
    }

    private fun selectAccess() = compose.tap("xui_discovery_select_${access.accessId}")

    private fun reachReadyAndOpenDialog() {
        selectAccess()
        compose.tap("xui_discovery_consent")
        compose.tap("xui_fresh_install_readiness_start")
        compose.tap("xui_fresh_install_open")
        compose.await("xui_fresh_install_dialog")
    }

    @Test fun dialogNeverStartsWithoutExplicitAckAndCancelDoesNotStart() {
        showScreen(mutableStateOf(true))
        reachReadyAndOpenDialog()
        // Readiness alone and an open dialog record nothing; confirm is disabled until the explicit tick.
        compose.onNodeWithTag("xui_fresh_install_confirm").assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, install.starts.size) }
        compose.onNodeWithTag("xui_fresh_install_ack").performClick()
        compose.onNodeWithTag("xui_fresh_install_confirm").assertIsEnabled()
        compose.runOnIdle { assertEquals(0, install.starts.size) }
        // Cancel after ticking: still nothing recorded, and reopening resets the tick.
        compose.onNodeWithText("Отмена").performClick()
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("xui_fresh_install_dialog").fetchSemanticsNodes().isEmpty() }
        compose.tap("xui_fresh_install_open")
        compose.await("xui_fresh_install_confirm")
        compose.onNodeWithTag("xui_fresh_install_confirm").assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, install.starts.size) }
    }

    @Test fun confirmRecordsExactlyOnceAndReshownScreenShowsPendingWithoutResend() {
        val shown = mutableStateOf(true)
        showScreen(shown)
        reachReadyAndOpenDialog()
        compose.onNodeWithTag("xui_fresh_install_ack").performClick()
        compose.onNodeWithTag("xui_fresh_install_confirm").performClick()
        compose.await("xui_fresh_install_status")
        compose.onNodeWithTag("xui_fresh_install_status").assertTextContains("Fixture pending request")
        compose.runOnIdle { assertEquals(1, install.starts.size) }
        // Hide and show the screen again: a fresh composition only reads the local journal.
        val checksBefore = discovery.readinessChecks
        compose.runOnIdle { shown.value = false }
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("xui_discovery_screen").fetchSemanticsNodes().isEmpty() }
        compose.runOnIdle { shown.value = true }
        selectAccess()
        compose.await("xui_fresh_install_status")
        compose.onNodeWithTag("xui_fresh_install_status").assertTextContains("Fixture pending request")
        compose.onAllNodesWithTag("xui_fresh_install_dialog").fetchSemanticsNodes().let { assertEquals(0, it.size) }
        compose.runOnIdle {
            assertEquals(1, install.starts.size)
            assertEquals(checksBefore, discovery.readinessChecks)
        }
    }
}
