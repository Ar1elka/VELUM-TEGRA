package com.velumtegra.xuimobile.enrollment

import java.io.ByteArrayOutputStream
import java.util.Base64
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic key containers (no real key material): only the unencrypted public-blob type string matters. */
class UnsupportedPrivateKeyDetectorTest {
    private fun ByteArrayOutputStream.u32(v: Int) { for (s in intArrayOf(24, 16, 8, 0)) write((v shr s) and 0xFF) }
    private fun ByteArrayOutputStream.str(b: ByteArray) { u32(b.size); write(b) }
    private fun ByteArrayOutputStream.str(s: String) = str(s.toByteArray(Charsets.US_ASCII))

    private fun opensshKey(type: String, cipher: String = "none"): ByteArray {
        val blob = ByteArrayOutputStream().also { it.str(type); it.str(ByteArray(32)) }.toByteArray()
        val body = ByteArrayOutputStream().also {
            it.write("openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII))
            it.str(cipher); it.str(if (cipher == "none") "none" else "bcrypt"); it.str(ByteArray(0))
            it.u32(1); it.str(blob); it.str(ByteArray(16))
        }.toByteArray()
        val b64 = Base64.getMimeEncoder(70, "\n".toByteArray()).encodeToString(body)
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n$b64\n-----END OPENSSH PRIVATE KEY-----\n".toByteArray()
    }

    @Test fun `ed25519 openssh key gets a clear message, also when passphrase protected`() {
        val plain = EnrollmentInputPolicy.validatePrivateKeyDocument(opensshKey("ssh-ed25519"))
        assertNotNull(plain)
        assertTrue(plain!!.contains("Ed25519") && plain.contains("ecdsa"))
        assertNotNull(EnrollmentInputPolicy.validatePrivateKeyDocument(opensshKey("ssh-ed25519", cipher = "aes256-ctr")))
    }

    @Test fun `ecdsa and rsa openssh keys are accepted`() {
        assertNull(EnrollmentInputPolicy.validatePrivateKeyDocument(opensshKey("ecdsa-sha2-nistp256")))
        assertNull(EnrollmentInputPolicy.validatePrivateKeyDocument(opensshKey("ssh-rsa")))
    }

    @Test fun `dsa and hardware token keys are explained`() {
        assertTrue(EnrollmentInputPolicy.validatePrivateKeyDocument(opensshKey("ssh-dss"))!!.contains("DSA"))
        assertTrue(EnrollmentInputPolicy.validatePrivateKeyDocument(opensshKey("sk-ssh-ed25519@openssh.com"))!!.contains("sk-"))
        val pemDsa = "-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n".toByteArray()
        assertNotNull(EnrollmentInputPolicy.validatePrivateKeyDocument(pemDsa))
    }

    @Test fun `pkcs8 ed25519 is explained and pkcs8 rsa is not`() {
        fun pkcs8(vararg oid: Int): ByteArray {
            val der = byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03) + oid.map { it.toByte() } +
                ByteArray(40)
            val b64 = Base64.getEncoder().encodeToString(der)
            return "-----BEGIN PRIVATE KEY-----\n$b64\n-----END PRIVATE KEY-----\n".toByteArray()
        }
        assertNotNull(EnrollmentInputPolicy.validatePrivateKeyDocument(pkcs8(0x2B, 0x65, 0x70)))
        assertNull(EnrollmentInputPolicy.validatePrivateKeyDocument(pkcs8(0x2A, 0x86, 0x48)))
    }

    @Test fun `unparseable containers fall through to the normal flow`() {
        val garbage = "-----BEGIN OPENSSH PRIVATE KEY-----\nb25seS1mb3Itc3ludGF4LXRlc3Q=\n-----END OPENSSH PRIVATE KEY-----\n"
        assertNull(EnrollmentInputPolicy.validatePrivateKeyDocument(garbage.toByteArray()))
        val truncated = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n"
        assertNull(EnrollmentInputPolicy.validatePrivateKeyDocument(truncated.toByteArray()))
    }
}
