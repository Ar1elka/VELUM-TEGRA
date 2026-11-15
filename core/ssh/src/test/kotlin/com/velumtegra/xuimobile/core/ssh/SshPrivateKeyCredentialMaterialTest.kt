package com.velumtegra.xuimobile.core.ssh

import java.util.Arrays
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SshPrivateKeyCredentialMaterialTest {
    @Test
    fun `public material factory uses canonical envelope without leaking secret text`() {
        val key = "acceptance-private-key".encodeToByteArray()
        val passphrase = "acceptance-passphrase".encodeToByteArray()
        val material = SshPrivateKeyCredentialMaterial.create(key, passphrase)
        var encoded: ByteArray? = null
        try {
            assertEquals("SecretMaterial([REDACTED])", material.toString())
            encoded = material.useBytes { it.copyOf() }
            val decoded = PrivateKeySecretEnvelopeCodec.decode(encoded)
            assertTrue(decoded is PrivateKeySecretDecodeResult.Valid)
            val decodedMaterial = (decoded as PrivateKeySecretDecodeResult.Valid).material
            try {
                decodedMaterial.useForIdentity { decodedKey, decodedPassphrase ->
                    assertArrayEquals(key, decodedKey)
                    assertArrayEquals(passphrase, decodedPassphrase)
                }
                assertFalse(decodedMaterial.toString().contains("acceptance-private-key"))
                assertFalse(decodedMaterial.toString().contains("acceptance-passphrase"))
            } finally {
                decodedMaterial.close()
            }
        } finally {
            material.close()
            encoded?.let { Arrays.fill(it, 0) }
            Arrays.fill(key, 0)
            Arrays.fill(passphrase, 0)
        }
    }
}
