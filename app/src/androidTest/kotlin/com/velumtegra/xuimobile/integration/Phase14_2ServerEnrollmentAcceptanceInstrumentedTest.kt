package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.MainActivity
import com.velumtegra.xuimobile.enrollment.EnrollmentResult
import com.velumtegra.xuimobile.enrollment.ServerEnrollmentPort
import com.velumtegra.xuimobile.enrollment.ServerEnrollmentScreen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase14_2MainActivityEnrollmentNavigationTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Test fun addServerEntryAndCancelAreAccessibleWithoutPersistenceMutation() {
        compose.onNodeWithTag("nav_servers").performClick()
        compose.onNodeWithTag("inventory_servers").assertExists()
        compose.onNodeWithTag("inventory_add_server").performClick()
        compose.onNodeWithTag("server_enrollment_root").assertExists()
        compose.onNodeWithTag("enrollment_server_name").assertExists()
        compose.onNodeWithTag("enrollment_cancel").performClick()
        compose.onNodeWithTag("inventory_servers").assertExists()
    }
}

@RunWith(AndroidJUnit4::class)
class Phase14_2PasswordPinConsentUiTest {
    @get:Rule val compose = createComposeRule()
    private var calls = 0
    private var wipedCredential: ByteArray? = null

    @Test fun userMustVerifyExactPinBeforeSecretIsSubmitted() {
        val fake = object : ServerEnrollmentPort {
            override suspend fun addServer(displayName: String): EnrollmentResult =
                error("Not expected")
            override suspend fun addPasswordAccess(
                serverId: String, host: String, port: String, username: String,
                hostFingerprint: String, independentlyVerified: Boolean, passwordBytes: ByteArray,
            ): EnrollmentResult {
                calls++
                assertEquals("exact-server-id", serverId)
                assertEquals("example.org", host)
                assertEquals("22", port)
                assertEquals("operator", username)
                assertTrue(independentlyVerified)
                assertTrue(passwordBytes.isNotEmpty())
                wipedCredential = passwordBytes
                return EnrollmentResult.Saved("new-access")
            }
            override suspend fun addPrivateKeyAccess(
                serverId: String, host: String, port: String, username: String,
                hostFingerprint: String, independentlyVerified: Boolean,
                privateKeyBytes: ByteArray, passphraseBytes: ByteArray?,
            ): EnrollmentResult = error("Not expected")
        }
        var completed = false
        compose.setContent {
            ServerEnrollmentScreen(
                serverId = "exact-server-id", serverName = "Target A",
                port = fake, onBack = {}, onSaved = { completed = true },
            )
        }
        compose.onNodeWithTag("enrollment_exact_target").assertExists()
        compose.onNodeWithTag("enrollment_host").performScrollTo().performTextInput("example.org")
        compose.onNodeWithTag("enrollment_username").performScrollTo().performTextInput("operator")
        compose.onNodeWithTag("enrollment_fingerprint").performScrollTo().performTextInput("SHA256:" + "A".repeat(43))
        compose.onNodeWithTag("enrollment_password").performScrollTo().performTextInput("test-password")
        compose.onNodeWithTag("enrollment_save").performScrollTo().performClick()
        compose.onNodeWithTag("enrollment_error").assertExists()
        compose.runOnIdle { assertEquals(0, calls) }
        compose.onNodeWithTag("enrollment_pin_verified").performScrollTo().performClick()
        compose.onNodeWithTag("enrollment_save").performScrollTo().performClick()
        compose.waitUntil(5_000) { completed && wipedCredential?.all { it == 0.toByte() } == true }
        compose.runOnIdle {
            assertEquals(1, calls)
            assertTrue(requireNotNull(wipedCredential).all { it == 0.toByte() })
        }
    }
}
