package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.HostKeyRepository
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExactPinnedHostKeyRepositoryTest {
    @Test
    fun `exact lookup host and exact raw key are accepted`() {
        val key = "host-key-A".encodeToByteArray()
        val pin = CanonicalHostKeyFingerprint.fromRawHostKey(key)
        val repository = ExactPinnedHostKeyRepository("[example.test]:2222", pin)

        assertEquals(HostKeyRepository.OK, repository.check("[example.test]:2222", key))
        assertFalse(repository.didObserveMismatch())
        assertEquals(pin.asString(), repository.presentedFingerprintOrNull())
    }

    @Test
    fun `repository exposes no key before proof then only exact accepted host key`() {
        val key = Base64.getDecoder().decode(VALID_RSA_HOST_KEY_BASE64)
        val pin = CanonicalHostKeyFingerprint.fromRawHostKey(key)
        val repository = ExactPinnedHostKeyRepository("[example.test]:2222", pin)

        assertTrue(repository.getHostKey().isEmpty())
        assertTrue(repository.getHostKey("[example.test]:2222", null).isEmpty())
        assertEquals(HostKeyRepository.OK, repository.check("[example.test]:2222", key))

        val accepted = repository.getHostKey("[example.test]:2222", "rsa-sha2-512")
        assertEquals(1, accepted.size)
        assertEquals("[example.test]:2222", accepted.single().host)
        assertEquals(VALID_RSA_HOST_KEY_BASE64, accepted.single().key)
        assertEquals("", accepted.single().marker)
        assertTrue(repository.getHostKey("other.test", null).isEmpty())

        // A later mismatch (for example during re-key) must revoke the previously accepted snapshot.
        assertEquals(
            HostKeyRepository.CHANGED,
            repository.check("[example.test]:2222", "different-key".encodeToByteArray()),
        )
        assertTrue(repository.getHostKey("[example.test]:2222", null).isEmpty())
    }

    @Test
    fun `wrong host or wrong key fail closed and capture presented fingerprint`() {
        val key = "host-key-A".encodeToByteArray()
        val wrong = "host-key-B".encodeToByteArray()
        val pin = CanonicalHostKeyFingerprint.fromRawHostKey(key)

        val wrongHost = ExactPinnedHostKeyRepository("example.test", pin)
        assertEquals(HostKeyRepository.CHANGED, wrongHost.check("other.test", key))
        assertTrue(wrongHost.didObserveMismatch())
        assertTrue(wrongHost.getHostKey("example.test", null).isEmpty())

        val wrongKey = ExactPinnedHostKeyRepository("example.test", pin)
        assertEquals(HostKeyRepository.CHANGED, wrongKey.check("example.test", wrong))
        assertTrue(wrongKey.didObserveMismatch())
        assertNotNull(wrongKey.presentedFingerprintOrNull())
        assertFalse(wrongKey.presentedFingerprintOrNull() == pin.asString())
        assertTrue(wrongKey.getHostKey("example.test", null).isEmpty())
    }

    @Test
    fun `non standard port uses exact bracketed JSch lookup form`() {
        assertEquals("host.test", ExactPinnedHostKeyRepository.lookupHost("host.test", 22))
        assertEquals("[host.test]:22022", ExactPinnedHostKeyRepository.lookupHost("host.test", 22022))
        assertEquals("[2001:db8::1]:22022", ExactPinnedHostKeyRepository.lookupHost("2001:db8::1", 22022))
    }

    private companion object {
        // Valid SSH wire-format RSA public key blob, used only to exercise JSch HostKey parsing.
        const val VALID_RSA_HOST_KEY_BASE64 =
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQDEY8wBhb8ifzbg2kbTBmI9IYlOmSexAaGLAYf6h8Dl7e1Tk0qyHRwfPXj0HhJWboB+8v21/aMJAjizD9scxcz+qG+SiXcFCSuF0LaUdEd4ICWJ8Zd/x7lcsi89wQQko+QIFUszSgh4iFFLRUq26nt9osRXozyQjHJt2lY8mW59wZx3vv8GNw85xu1i5gj4fNXyNfchC0v3QrYKkkkMKC+e5ZDegpGmNfOZxP7Rj9V34wLFWh9oedLkmI9SV8wpaberjd6E/hTc/M9fznbw2DvqMW0qLfboNHadjE94mjAai8oeAb+Rtu6r90dwZEIAW3/6wlWFMHGtpWzrOZaWDOeL"
    }
}
