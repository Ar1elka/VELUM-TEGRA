package com.velumtegra.xuimobile.core.ssh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivateKeySecretEnvelopeCodecTest {
    @Test
    fun `round trip preserves private key and optional passphrase without exposing them`() {
        val key = "-----BEGIN TEST PRIVATE KEY-----\nsecret-key\n-----END TEST PRIVATE KEY-----\n".encodeToByteArray()
        val passphrase = "fixture-passphrase".encodeToByteArray()
        val encoded = PrivateKeySecretEnvelopeCodec.encode(key, passphrase)

        val decoded = PrivateKeySecretEnvelopeCodec.decode(encoded)
        assertTrue(decoded is PrivateKeySecretDecodeResult.Valid)
        val material = (decoded as PrivateKeySecretDecodeResult.Valid).material
        material.useForIdentity { decodedKey, decodedPassphrase ->
            assertArrayEquals(key, decodedKey)
            assertArrayEquals(passphrase, decodedPassphrase)
        }
        assertEquals("PrivateKeySecretMaterial([REDACTED])", material.toString())
        material.close()
    }

    @Test
    fun `round trip preserves explicit absence of passphrase`() {
        val key = "key-material".encodeToByteArray()
        val decoded = PrivateKeySecretEnvelopeCodec.decode(PrivateKeySecretEnvelopeCodec.encode(key))
        assertTrue(decoded is PrivateKeySecretDecodeResult.Valid)
        val material = (decoded as PrivateKeySecretDecodeResult.Valid).material
        material.useForIdentity { decodedKey, decodedPassphrase ->
            assertArrayEquals(key, decodedKey)
            assertEquals(null, decodedPassphrase)
        }
        material.close()
    }

    @Test
    fun `decoder rejects unsupported or truncated envelope fail closed`() {
        assertTrue(
            PrivateKeySecretEnvelopeCodec.decode("not-a-velum-key-envelope".encodeToByteArray()) is
                PrivateKeySecretDecodeResult.Invalid,
        )

        val valid = PrivateKeySecretEnvelopeCodec.encode("key".encodeToByteArray())
        assertTrue(
            PrivateKeySecretEnvelopeCodec.decode(valid.copyOf(valid.size - 1)) is
                PrivateKeySecretDecodeResult.Invalid,
        )
    }

    @Test
    fun `decoder rejects trailing bytes rather than accepting ambiguous payload`() {
        val valid = PrivateKeySecretEnvelopeCodec.encode("key".encodeToByteArray())
        val withTrailing = valid + byteArrayOf(1)
        assertTrue(PrivateKeySecretEnvelopeCodec.decode(withTrailing) is PrivateKeySecretDecodeResult.Invalid)
    }
}
