package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import org.junit.Assert.assertEquals
import org.junit.Test

class VerifiedHostKeyEvidenceTest {
    @Test
    fun `canonical fingerprint exposes same digest as lowercase hex evidence`() {
        val raw = ByteArray(32) { it.toByte() }
        val fingerprint = CanonicalHostKeyFingerprint.fromRawHostKey(raw)
        val reparsed = CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fingerprint.asString())) as HostKeyFingerprintParseResult.Valid
        assertEquals(fingerprint.asHexSha256(), reparsed.fingerprint.asHexSha256())
        assertEquals(64, fingerprint.asHexSha256().length)
    }
}
