package com.velumtegra.xuimobile.core.secrets

import com.velumtegra.xuimobile.core.model.SecretId
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.Arrays
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal object SecretEnvelopeFormat {
    val MAGIC: ByteArray = byteArrayOf('V'.code.toByte(), 'T'.code.toByte(), 'S'.code.toByte(), '1'.code.toByte())
    const val ENVELOPE_VERSION = 1
    const val PAYLOAD_VERSION = 1
    const val NONCE_BYTES = 12
    const val GCM_TAG_BITS = 128
    const val MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
    const val MAX_SECRET_BYTES = 3 * 1024 * 1024
    const val MAX_ID_BYTES = 16 * 1024
}

internal sealed interface EnvelopeDecodeResult {
    data class Success(
        val secretId: SecretId,
        val secretBytes: ByteArray,
        val keyVersion: Int,
    ) : EnvelopeDecodeResult

    data class KeyRequired(val keyVersion: Int, val parsed: ParsedEnvelope) : EnvelopeDecodeResult
    data class Corrupt(val reason: String) : EnvelopeDecodeResult
}

internal data class ParsedEnvelope(
    val version: Int,
    val keyVersion: Int,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
) {
    fun wipe() {
        Arrays.fill(nonce, 0)
        Arrays.fill(ciphertext, 0)
    }
}

internal class SecretEnvelopeCodec {
    fun encode(
        secretId: SecretId,
        secretBytes: ByteArray,
        keyVersion: Int,
        key: SecretKey,
    ): ByteArray {
        require(keyVersion > 0) { "Keystore key version must be positive" }
        require(secretBytes.size <= SecretEnvelopeFormat.MAX_SECRET_BYTES) { "Secret material is too large" }
        val idBytes = secretId.value.toByteArray(Charsets.UTF_8)
        require(idBytes.size <= SecretEnvelopeFormat.MAX_ID_BYTES) { "SecretId is too large" }

        val payload = ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { output ->
                output.writeInt(SecretEnvelopeFormat.PAYLOAD_VERSION)
                output.writeInt(idBytes.size)
                output.write(idBytes)
                output.writeInt(secretBytes.size)
                output.write(secretBytes)
            }
            buffer.toByteArray()
        }

        var nonce: ByteArray? = null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            // Android Keystore keys created with randomized encryption required reject caller-provided IVs
            // for encryption. Let the provider generate a fresh GCM IV, then persist it in the envelope.
            cipher.init(Cipher.ENCRYPT_MODE, key)
            nonce = cipher.iv?.copyOf()
                ?: throw java.security.GeneralSecurityException("AES-GCM provider did not return an IV")
            if (nonce.size != SecretEnvelopeFormat.NONCE_BYTES) {
                throw java.security.GeneralSecurityException(
                    "Unexpected AES-GCM IV length ${nonce.size}",
                )
            }
            val aad = aad(SecretEnvelopeFormat.ENVELOPE_VERSION, keyVersion)
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(payload)
            Arrays.fill(aad, 0)

            ByteArrayOutputStream().use { buffer ->
                DataOutputStream(buffer).use { output ->
                    output.write(SecretEnvelopeFormat.MAGIC)
                    output.writeInt(SecretEnvelopeFormat.ENVELOPE_VERSION)
                    output.writeInt(keyVersion)
                    output.writeInt(nonce.size)
                    output.write(nonce)
                    output.writeInt(ciphertext.size)
                    output.write(ciphertext)
                }
                buffer.toByteArray()
            }.also {
                Arrays.fill(ciphertext, 0)
            }
        } finally {
            Arrays.fill(payload, 0)
            nonce?.let { Arrays.fill(it, 0) }
            Arrays.fill(idBytes, 0)
        }
    }

    fun parse(envelopeBytes: ByteArray): EnvelopeDecodeResult {
        if (envelopeBytes.isEmpty() || envelopeBytes.size > SecretEnvelopeFormat.MAX_ENVELOPE_BYTES) {
            return EnvelopeDecodeResult.Corrupt("Secret envelope size is invalid")
        }
        return try {
            DataInputStream(ByteArrayInputStream(envelopeBytes)).use { input ->
                val magic = ByteArray(SecretEnvelopeFormat.MAGIC.size)
                input.readFully(magic)
                if (!magic.contentEquals(SecretEnvelopeFormat.MAGIC)) {
                    return EnvelopeDecodeResult.Corrupt("Secret envelope magic is invalid")
                }
                val version = input.readInt()
                if (version != SecretEnvelopeFormat.ENVELOPE_VERSION) {
                    return EnvelopeDecodeResult.Corrupt("Unsupported secret envelope version $version")
                }
                val keyVersion = input.readInt()
                if (keyVersion <= 0) return EnvelopeDecodeResult.Corrupt("Secret envelope key version is invalid")
                val nonceLength = input.readInt()
                if (nonceLength != SecretEnvelopeFormat.NONCE_BYTES) {
                    return EnvelopeDecodeResult.Corrupt("Secret envelope nonce length is invalid")
                }
                val nonce = ByteArray(nonceLength)
                input.readFully(nonce)
                val cipherLength = input.readInt()
                if (cipherLength <= 0 || cipherLength > SecretEnvelopeFormat.MAX_ENVELOPE_BYTES) {
                    Arrays.fill(nonce, 0)
                    return EnvelopeDecodeResult.Corrupt("Secret envelope ciphertext length is invalid")
                }
                val ciphertext = ByteArray(cipherLength)
                input.readFully(ciphertext)
                if (input.available() != 0) {
                    Arrays.fill(nonce, 0)
                    Arrays.fill(ciphertext, 0)
                    return EnvelopeDecodeResult.Corrupt("Secret envelope contains trailing data")
                }
                EnvelopeDecodeResult.KeyRequired(
                    keyVersion,
                    ParsedEnvelope(version, keyVersion, nonce, ciphertext),
                )
            }
        } catch (error: Exception) {
            EnvelopeDecodeResult.Corrupt("Secret envelope is truncated or malformed")
        }
    }

    fun decrypt(parsed: ParsedEnvelope, key: SecretKey): EnvelopeDecodeResult {
        val plaintext = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(SecretEnvelopeFormat.GCM_TAG_BITS, parsed.nonce),
            )
            val aad = aad(parsed.version, parsed.keyVersion)
            cipher.updateAAD(aad)
            try {
                cipher.doFinal(parsed.ciphertext)
            } finally {
                Arrays.fill(aad, 0)
            }
        } catch (error: AEADBadTagException) {
            return EnvelopeDecodeResult.Corrupt("Secret envelope authentication failed")
        }

        return try {
            DataInputStream(ByteArrayInputStream(plaintext)).use { input ->
                val payloadVersion = input.readInt()
                if (payloadVersion != SecretEnvelopeFormat.PAYLOAD_VERSION) {
                    return EnvelopeDecodeResult.Corrupt("Unsupported secret payload version $payloadVersion")
                }
                val idLength = input.readInt()
                if (idLength < 0 || idLength > SecretEnvelopeFormat.MAX_ID_BYTES || idLength > input.available()) {
                    return EnvelopeDecodeResult.Corrupt("Secret payload id length is invalid")
                }
                val idBytes = ByteArray(idLength)
                input.readFully(idBytes)
                val secretLength = input.readInt()
                if (secretLength < 0 || secretLength > SecretEnvelopeFormat.MAX_SECRET_BYTES || secretLength > input.available()) {
                    Arrays.fill(idBytes, 0)
                    return EnvelopeDecodeResult.Corrupt("Secret payload material length is invalid")
                }
                val secretBytes = ByteArray(secretLength)
                input.readFully(secretBytes)
                if (input.available() != 0) {
                    Arrays.fill(idBytes, 0)
                    Arrays.fill(secretBytes, 0)
                    return EnvelopeDecodeResult.Corrupt("Secret payload contains trailing data")
                }
                val id = try {
                    SecretId(idBytes.toString(Charsets.UTF_8))
                } finally {
                    Arrays.fill(idBytes, 0)
                }
                EnvelopeDecodeResult.Success(id, secretBytes, parsed.keyVersion)
            }
        } catch (error: Exception) {
            EnvelopeDecodeResult.Corrupt("Secret payload is malformed")
        } finally {
            Arrays.fill(plaintext, 0)
        }
    }

    private fun aad(envelopeVersion: Int, keyVersion: Int): ByteArray = ByteArrayOutputStream().use { buffer ->
        DataOutputStream(buffer).use { output ->
            output.write(SecretEnvelopeFormat.MAGIC)
            output.writeInt(envelopeVersion)
            output.writeInt(keyVersion)
        }
        buffer.toByteArray()
    }
}

internal object SecretFileNames {
    fun publishedName(secretId: SecretId): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(secretId.value.toByteArray(Charsets.UTF_8))
        return try {
            buildString(digest.size * 2 + PUBLISHED_SUFFIX.length) {
                digest.forEach { byte -> append("%02x".format(byte.toInt() and 0xff)) }
                append(PUBLISHED_SUFFIX)
            }
        } finally {
            Arrays.fill(digest, 0)
        }
    }

    fun matches(secretId: SecretId, fileName: String): Boolean = publishedName(secretId) == fileName

    const val PUBLISHED_SUFFIX = ".vts"
    const val STAGING_SUFFIX = ".stage"
}
