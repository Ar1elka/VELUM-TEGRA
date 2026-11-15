package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HostKeyFingerprintPolicyTest {
    @Test
    fun `canonical fingerprint round trips and matches exact raw host key blob`() {
        val keyBlob = "ssh-host-key-blob-A".encodeToByteArray()
        val canonical = CanonicalHostKeyFingerprint.fromRawHostKey(keyBlob)
        val parsed = CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(canonical.asString()))

        assertTrue(parsed is HostKeyFingerprintParseResult.Valid)
        val value = (parsed as HostKeyFingerprintParseResult.Valid).fingerprint
        assertTrue(value.matchesRawHostKey(keyBlob))
        assertFalse(value.matchesRawHostKey("ssh-host-key-blob-B".encodeToByteArray()))
        assertEquals(canonical.asString(), value.asString())
    }

    @Test
    fun `non canonical padded lowercase or whitespace forms fail closed`() {
        val canonical = CanonicalHostKeyFingerprint.fromRawHostKey("key".encodeToByteArray()).asString()
        val invalid = listOf(
            canonical + "=",
            canonical.lowercase(),
            " $canonical",
            canonical.replace("SHA256:", "MD5:"),
            "SHA256:not-a-valid-fingerprint",
        )

        invalid.forEach { raw ->
            assertTrue(
                "Expected invalid: $raw",
                CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(raw)) is HostKeyFingerprintParseResult.Invalid,
            )
        }
    }
}
