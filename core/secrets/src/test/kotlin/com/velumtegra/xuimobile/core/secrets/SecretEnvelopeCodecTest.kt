package com.velumtegra.xuimobile.core.secrets

import com.velumtegra.xuimobile.core.model.SecretId
import java.util.Arrays
import javax.crypto.KeyGenerator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecretEnvelopeCodecTest {
    private val codec = SecretEnvelopeCodec()

    @Test
    fun `envelope round trip preserves exact id and bytes`() {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val secret = "ssh-private-key-material".toByteArray()
        val envelope = codec.encode(SecretId("secret-123"), secret, 1, key)

        try {
            val parsed = codec.parse(envelope) as EnvelopeDecodeResult.KeyRequired
            try {
                val decoded = codec.decrypt(parsed.parsed, key) as EnvelopeDecodeResult.Success
                try {
                    assertEquals(SecretId("secret-123"), decoded.secretId)
                    assertArrayEquals(secret, decoded.secretBytes)
                    assertEquals(1, decoded.keyVersion)
                } finally {
                    Arrays.fill(decoded.secretBytes, 0)
                }
            } finally {
                parsed.parsed.wipe()
            }
        } finally {
            Arrays.fill(secret, 0)
            Arrays.fill(envelope, 0)
        }
    }

    @Test
    fun `cipher provider generates a fresh gcm iv for each envelope`() {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val first = codec.encode(SecretId("same-id"), byteArrayOf(1, 2, 3), 1, key)
        val second = codec.encode(SecretId("same-id"), byteArrayOf(1, 2, 3), 1, key)

        val firstParsed = codec.parse(first) as EnvelopeDecodeResult.KeyRequired
        val secondParsed = codec.parse(second) as EnvelopeDecodeResult.KeyRequired
        try {
            assertEquals(SecretEnvelopeFormat.NONCE_BYTES, firstParsed.parsed.nonce.size)
            assertEquals(SecretEnvelopeFormat.NONCE_BYTES, secondParsed.parsed.nonce.size)
            assertFalse(firstParsed.parsed.nonce.contentEquals(secondParsed.parsed.nonce))
        } finally {
            firstParsed.parsed.wipe()
            secondParsed.parsed.wipe()
            Arrays.fill(first, 0)
            Arrays.fill(second, 0)
        }
    }

    @Test
    fun `ciphertext does not contain plaintext secret`() {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val secretText = "plain-text-must-not-appear"
        val secret = secretText.toByteArray()
        val envelope = codec.encode(SecretId("id"), secret, 1, key)
        try {
            assertFalse(envelope.toString(Charsets.ISO_8859_1).contains(secretText))
        } finally {
            Arrays.fill(secret, 0)
            Arrays.fill(envelope, 0)
        }
    }

    @Test
    fun `tampering is authenticated and rejected`() {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val envelope = codec.encode(SecretId("secret-123"), byteArrayOf(1, 2, 3, 4), 1, key)
        envelope[envelope.lastIndex] = (envelope.last().toInt() xor 0x01).toByte()

        val parsed = codec.parse(envelope) as EnvelopeDecodeResult.KeyRequired
        try {
            assertTrue(codec.decrypt(parsed.parsed, key) is EnvelopeDecodeResult.Corrupt)
        } finally {
            parsed.parsed.wipe()
            Arrays.fill(envelope, 0)
        }
    }

    @Test
    fun `wrong key cannot decrypt ciphertext`() {
        val key1 = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val key2 = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val envelope = codec.encode(SecretId("secret-123"), byteArrayOf(9, 8, 7), 1, key1)

        val parsed = codec.parse(envelope) as EnvelopeDecodeResult.KeyRequired
        try {
            assertTrue(codec.decrypt(parsed.parsed, key2) is EnvelopeDecodeResult.Corrupt)
        } finally {
            parsed.parsed.wipe()
            Arrays.fill(envelope, 0)
        }
    }

    @Test
    fun `published filename is deterministic but does not expose raw SecretId`() {
        val id = SecretId("credential-production-server")
        val first = SecretFileNames.publishedName(id)
        val second = SecretFileNames.publishedName(id)

        assertEquals(first, second)
        assertTrue(first.endsWith(SecretFileNames.PUBLISHED_SUFFIX))
        assertFalse(first.contains(id.value))
        assertTrue(SecretFileNames.matches(id, first))
    }
}
