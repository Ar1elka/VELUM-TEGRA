package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import com.velumtegra.xuimobile.enrollment.EnrollmentResult
import com.velumtegra.xuimobile.enrollment.ServerEnrollmentPort
import com.velumtegra.xuimobile.enrollment.ServerEnrollmentScreen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

/** Fixture-only input: no real private key, no persistent writes, no network/SSH. */
@RunWith(AndroidJUnit4::class)
class Phase14_2BPrivateKeyEnrollmentAcceptanceInstrumentedTest {
    @get:Rule val compose = createComposeRule()

    @Test fun privateKeyRequiresExactPinAndWipesSubmittedBuffers() {
        val fixtureKey = ("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "ZmFrZS1maXh0dXJlLW5vdC1hLXJlYWwta2V5\n" +
            "-----END OPENSSH PRIVATE KEY-----\n").toByteArray()
        var privateKeySubmissions = 0
        var capturedKey: ByteArray? = null
        var capturedPassphrase: ByteArray? = null
        var completed = false
        val fake = object : ServerEnrollmentPort {
            override suspend fun addServer(displayName: String): EnrollmentResult = error("Not expected")
            override suspend fun addPasswordAccess(
                serverId: String, host: String, port: String, username: String,
                hostFingerprint: String, independentlyVerified: Boolean, passwordBytes: ByteArray,
            ): EnrollmentResult = error("Password fallback forbidden")
            override suspend fun addPrivateKeyAccess(
                serverId: String, host: String, port: String, username: String,
                hostFingerprint: String, independentlyVerified: Boolean,
                privateKeyBytes: ByteArray, passphraseBytes: ByteArray?,
            ): EnrollmentResult {
                privateKeySubmissions++
                assertEquals("target-B", serverId)
                assertEquals("example.org", host)
                assertEquals("22", port)
                assertEquals("operator", username)
                assertTrue(independentlyVerified)
                assertTrue(privateKeyBytes.contentEquals(fixtureKey))
                assertTrue(requireNotNull(passphraseBytes).contentEquals("key-pass".toByteArray()))
                capturedKey = privateKeyBytes
                capturedPassphrase = passphraseBytes
                return EnrollmentResult.Saved("access-key")
            }
        }
        compose.setContent {
            ServerEnrollmentScreen(
                serverId = "target-B", serverName = "Server B", port = fake,
                onBack = {}, onSaved = { completed = true },
                privateKeyPickerOverride = { receive -> receive(fixtureKey.copyOf()) },
            )
        }
        compose.onNodeWithTag("enrollment_exact_target").assertExists()
        compose.onNodeWithTag("enrollment_auth_private_key").performScrollTo().performClick()
        compose.onNodeWithTag("enrollment_pick_private_key").performScrollTo().performClick()
        compose.onNodeWithTag("enrollment_host").performScrollTo().performTextInput("example.org")
        compose.onNodeWithTag("enrollment_username").performScrollTo().performTextInput("operator")
        compose.onNodeWithTag("enrollment_fingerprint").performScrollTo().performTextInput("SHA256:" + "A".repeat(43))
        compose.onNodeWithTag("enrollment_key_passphrase").performScrollTo().performTextInput("key-pass")
        compose.onNodeWithTag("enrollment_save").performScrollTo().performClick()
        compose.onNodeWithTag("enrollment_error").assertExists()
        compose.runOnIdle { assertEquals(0, privateKeySubmissions) }
        compose.onNodeWithTag("enrollment_pin_verified").performScrollTo().performClick()
        compose.onNodeWithTag("enrollment_save").performScrollTo().performClick()
        compose.waitUntil(5_000) {
            completed && capturedKey?.all { it == 0.toByte() } == true &&
                capturedPassphrase?.all { it == 0.toByte() } == true
        }
        compose.runOnIdle {
            assertEquals(1, privateKeySubmissions)
            assertTrue(requireNotNull(capturedKey).all { it == 0.toByte() })
            assertTrue(requireNotNull(capturedPassphrase).all { it == 0.toByte() })
        }
        fixtureKey.fill(0)
    }
}
