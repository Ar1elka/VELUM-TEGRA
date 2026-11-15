package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import java.security.MessageDigest
import java.util.Base64

sealed interface HostKeyFingerprintParseResult {
    data class Valid(val fingerprint: CanonicalHostKeyFingerprint) : HostKeyFingerprintParseResult
    data class Invalid(val reason: String) : HostKeyFingerprintParseResult
}

/** Canonical OpenSSH-style SHA-256 fingerprint: SHA256:<43-char unpadded base64 digest>. */
class CanonicalHostKeyFingerprint private constructor(private val digest: ByteArray) {
    fun matchesRawHostKey(rawHostKeyBlob: ByteArray): Boolean {
        val actual = MessageDigest.getInstance("SHA-256").digest(rawHostKeyBlob)
        return MessageDigest.isEqual(digest, actual)
    }

    fun asModel(): HostKeyFingerprint = HostKeyFingerprint(asString())

    fun asString(): String = "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest)

    fun asHexSha256(): String = digest.joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    override fun toString(): String = asString()

    companion object {
        private const val PREFIX = "SHA256:"
        private val BODY = Regex("^[A-Za-z0-9+/]{43}$")

        fun parse(value: HostKeyFingerprint): HostKeyFingerprintParseResult {
            val raw = value.value
            if (!raw.startsWith(PREFIX)) {
                return HostKeyFingerprintParseResult.Invalid("Host-key fingerprint must use SHA256: prefix")
            }
            val body = raw.removePrefix(PREFIX)
            if (!BODY.matches(body)) {
                return HostKeyFingerprintParseResult.Invalid(
                    "Host-key fingerprint must be canonical unpadded SHA-256 base64",
                )
            }
            val decoded = try {
                Base64.getDecoder().decode(body)
            } catch (_: IllegalArgumentException) {
                return HostKeyFingerprintParseResult.Invalid("Host-key fingerprint base64 is malformed")
            }
            if (decoded.size != 32) {
                return HostKeyFingerprintParseResult.Invalid("Host-key fingerprint digest must be 32 bytes")
            }
            return HostKeyFingerprintParseResult.Valid(CanonicalHostKeyFingerprint(decoded.copyOf()))
        }

        fun fromRawHostKey(rawHostKeyBlob: ByteArray): CanonicalHostKeyFingerprint =
            CanonicalHostKeyFingerprint(MessageDigest.getInstance("SHA-256").digest(rawHostKeyBlob))
    }
}
