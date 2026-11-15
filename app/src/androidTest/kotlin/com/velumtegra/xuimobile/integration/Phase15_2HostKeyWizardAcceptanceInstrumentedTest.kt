package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import com.velumtegra.xuimobile.enrollment.EnrollmentResult
import com.velumtegra.xuimobile.enrollment.HostKeyDiscoveryResult
import com.velumtegra.xuimobile.enrollment.ServerEnrollmentPort
import com.velumtegra.xuimobile.enrollment.ServerEnrollmentScreen
import com.velumtegra.xuimobile.enrollment.ServerHostKeyDiscoveryPort
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

@RunWith(AndroidJUnit4::class)
class Phase15_2HostKeyWizardAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val validPin = "SHA256:" + "A".repeat(43)

    private class FakeEnrollment : ServerEnrollmentPort {
        var saved = 0
        var lastPin: String? = null
        override suspend fun addServer(displayName: String) = EnrollmentResult.Saved("created-server-id")
        override suspend fun addPasswordAccess(
            serverId: String, host: String, port: String, username: String,
            hostFingerprint: String, independentlyVerified: Boolean, passwordBytes: ByteArray,
        ): EnrollmentResult {
            assertEquals("exact-id", serverId)
            assertTrue(independentlyVerified)
            lastPin = hostFingerprint
            saved++
            passwordBytes.fill(0)
            return EnrollmentResult.Saved("access")
        }
        override suspend fun addPrivateKeyAccess(
            serverId: String, host: String, port: String, username: String,
            hostFingerprint: String, independentlyVerified: Boolean,
            privateKeyBytes: ByteArray, passphraseBytes: ByteArray?,
        ): EnrollmentResult = error("Unexpected private key enrollment")
    }

    private fun enterAccessCredentials() {
        compose.onNodeWithTag("enrollment_host").performScrollTo().performTextInput("example.org")
        compose.onNodeWithTag("enrollment_username").performScrollTo().performTextInput("root")
        compose.onNodeWithTag("enrollment_password").performScrollTo().performTextInput("test-only")
    }

    @Test fun fetchedHostKeyNeverAutoConfirmsIdentityOrSavesCredentials() {
        val enrollment = FakeEnrollment()
        var discoveryCount = 0
        compose.setContent {
            ServerEnrollmentScreen("exact-id", "Server A", enrollment, {}, {},
                hostKeyDiscoveryPort = object : ServerHostKeyDiscoveryPort {
                    override suspend fun discover(host: String, port: String): HostKeyDiscoveryResult {
                        discoveryCount++
                        return HostKeyDiscoveryResult.Unverified(host, port, validPin, "ssh-ed25519")
                    }
                },
            )
        }
        enterAccessCredentials()
        compose.onNodeWithTag("enrollment_discover_host_key").performScrollTo().performClick()
        compose.waitUntil(5_000) {
            discoveryCount == 1 && compose.onAllNodesWithTag("enrollment_discovered_warning").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("enrollment_discovered_warning").assertExists()
        compose.onNodeWithTag("enrollment_save").performScrollTo().performClick()
        compose.onNodeWithTag("enrollment_error").assertExists()
        compose.runOnIdle { assertEquals(0, enrollment.saved) }
    }

    @Test fun explicitIndependentConfirmationCanSaveObservedPin() {
        val enrollment = FakeEnrollment()
        var completed = false
        compose.setContent {
            ServerEnrollmentScreen("exact-id", "Server A", enrollment, {}, { completed = true },
                hostKeyDiscoveryPort = object : ServerHostKeyDiscoveryPort {
                    override suspend fun discover(host: String, port: String) =
                        HostKeyDiscoveryResult.Unverified(host, port, validPin, "ssh-ed25519")
                },
            )
        }
        enterAccessCredentials()
        compose.onNodeWithTag("enrollment_discover_host_key").performScrollTo().performClick()
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("enrollment_discovered_warning").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("enrollment_discovered_warning").assertExists()
        compose.onNodeWithTag("enrollment_pin_verified").performScrollTo().performClick()
        compose.onNodeWithTag("enrollment_save").performScrollTo().performClick()
        compose.waitUntil(5_000) { completed }
        compose.runOnIdle { assertEquals(validPin, enrollment.lastPin); assertEquals(1, enrollment.saved) }
    }

    @Test fun changingHostRevokesObservedPinAndConsent() {
        val enrollment = FakeEnrollment()
        compose.setContent {
            ServerEnrollmentScreen("exact-id", "Server A", enrollment, {}, {},
                hostKeyDiscoveryPort = object : ServerHostKeyDiscoveryPort {
                    override suspend fun discover(host: String, port: String) =
                        HostKeyDiscoveryResult.Unverified(host, port, validPin, "ssh-ed25519")
                },
            )
        }
        enterAccessCredentials()
        compose.onNodeWithTag("enrollment_discover_host_key").performScrollTo().performClick()
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("enrollment_discovered_warning").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("enrollment_discovered_warning").assertExists()
        compose.onNodeWithTag("enrollment_pin_verified").performScrollTo().performClick()
        compose.onNodeWithTag("enrollment_host").performScrollTo().performTextReplacement("other.example.org")
        compose.onNodeWithTag("enrollment_save").performScrollTo().performClick()
        compose.onNodeWithTag("enrollment_error").assertExists()
        compose.runOnIdle { assertEquals(0, enrollment.saved) }
    }

    @Test fun createServerLeadsToExactCreatedIdentityWithoutNetwork() {
        val enrollment = FakeEnrollment()
        var createdId: String? = null
        var createdName: String? = null
        compose.setContent {
            ServerEnrollmentScreen(null, null, enrollment, {}, {},
                onServerCreated = { id, name -> createdId = id; createdName = name },
            )
        }
        compose.onNodeWithTag("enrollment_server_name").performTextInput("  New VPS  ")
        compose.onNodeWithTag("enrollment_save").performScrollTo().performClick()
        compose.waitUntil(5_000) { createdId != null }
        compose.runOnIdle { assertEquals("created-server-id", createdId); assertEquals("New VPS", createdName) }
    }
}
