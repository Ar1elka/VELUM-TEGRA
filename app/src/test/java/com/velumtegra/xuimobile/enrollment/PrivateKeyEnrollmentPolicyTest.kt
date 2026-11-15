package com.velumtegra.xuimobile.enrollment

import java.io.ByteArrayInputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivateKeyEnrollmentPolicyTest {
    private val pin = "SHA256:" + "A".repeat(43)
    private fun sampleKey() = ("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
        "b25seS1mb3Itc3ludGF4LXRlc3Q=\n" +
        "-----END OPENSSH PRIVATE KEY-----\n").toByteArray()

    @Test fun `read stream with exact size cap and never accept oversized or empty`() {
        val key = sampleKey()
        assertArrayEquals(key, BoundedPrivateKeyDocumentReader.read(ByteArrayInputStream(key)))
        assertNull(BoundedPrivateKeyDocumentReader.read(ByteArrayInputStream(byteArrayOf())))
        assertNull(BoundedPrivateKeyDocumentReader.read(ByteArrayInputStream(ByteArray(1024 * 1024 + 1))))
    }

    @Test fun `rejects public key wrong footer and unverified pin`() {
        assertNotNull(EnrollmentInputPolicy.validatePrivateKeyDocument("ssh-ed25519 AAAA".toByteArray()))
        assertNotNull(EnrollmentInputPolicy.validatePrivateKeyDocument("-----BEGIN PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----".toByteArray()))
        val key = sampleKey()
        assertNotNull(EnrollmentInputPolicy.validatePrivateKeyAccess("server", "example.org", "22", "operator", pin, false, key, 0))
        assertNotNull(EnrollmentInputPolicy.validatePrivateKeyAccess("", "example.org", "22", "operator", pin, true, key, 0))
        assertNotNull(EnrollmentInputPolicy.validatePrivateKeyAccess("server", "example.org", "22", "operator", "", true, key, 0))
        assertNotNull(EnrollmentInputPolicy.validatePrivateKeyAccess("server", "example.org", "22", "operator", pin, true, key, 16_385))
        assertNull(EnrollmentInputPolicy.validatePrivateKeyAccess("server", "example.org", "22", "operator", pin, true, key, 0))
        key.fill(0)
    }

    @Test fun `transient key selection overwrites and zeroes prior buffers`() {
        val first = sampleKey()
        val second = sampleKey()
        val selection = TransientPrivateKeySelection()
        selection.replace(first)
        selection.replace(second)
        assertTrue(first.all { it == 0.toByte() })
        val copy = requireNotNull(selection.copyForSubmission())
        assertEquals(second.size, copy.size)
        selection.close()
        assertTrue(second.all { it == 0.toByte() })
        assertNull(selection.copyForSubmission())
        copy.fill(0)
    }
}
