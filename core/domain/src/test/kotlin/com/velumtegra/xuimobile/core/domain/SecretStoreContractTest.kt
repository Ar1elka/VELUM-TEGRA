package com.velumtegra.xuimobile.core.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class SecretStoreContractTest {
    @Test
    fun `secret material never prints plaintext`() {
        val material = SecretMaterial.fromBytes("super-secret".toByteArray())
        try {
            assertEquals("SecretMaterial([REDACTED])", material.toString())
            assertFalse(material.toString().contains("super-secret"))
        } finally {
            material.close()
        }
    }

    @Test
    fun `closed secret material cannot be read again`() {
        val material = SecretMaterial.fromBytes(byteArrayOf(1, 2, 3))
        material.close()

        assertThrows(IllegalStateException::class.java) {
            material.useBytes { it.size }
        }
    }

    @Test
    fun `secret store exposes no overwrite API`() {
        val methodNames = SecretStore::class.java.methods.map { it.name.lowercase() }
        val forbidden = setOf("put", "update", "replace", "upsert", "write")
        assertFalse(methodNames.any { it in forbidden })
    }
}
