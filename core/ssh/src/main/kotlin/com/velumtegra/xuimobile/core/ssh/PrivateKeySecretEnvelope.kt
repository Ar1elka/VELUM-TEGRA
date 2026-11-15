package com.velumtegra.xuimobile.core.ssh

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Arrays

/**
 * Versioned payload stored inside SecretStore for SshAuthRef.PrivateKey.
 *
 * SecretStore already authenticates/encrypts the outer payload. This inner envelope exists only so one exact
 * SecretId can carry the private-key file bytes plus its optional passphrase without delimiter ambiguity.
 */
internal object PrivateKeySecretEnvelopeCodec {
    private val MAGIC = byteArrayOf(0x56, 0x54, 0x53, 0x4b, 0x01) // "VTSK" + version 1
    private const val HEADER_BYTES = 5 + Int.SIZE_BYTES + Int.SIZE_BYTES
    const val MAX_PRIVATE_KEY_BYTES = 1024 * 1024
    const val MAX_PASSPHRASE_BYTES = 16 * 1024

    fun encode(privateKey: ByteArray, passphrase: ByteArray? = null): ByteArray {
        require(privateKey.isNotEmpty()) { "Private key must not be empty" }
        require(privateKey.size <= MAX_PRIVATE_KEY_BYTES) { "Private key is too large" }
        require(passphrase == null || passphrase.size <= MAX_PASSPHRASE_BYTES) { "Passphrase is too large" }

        val passphraseLength = passphrase?.size ?: -1
        val total = HEADER_BYTES + privateKey.size + (passphrase?.size ?: 0)
        return ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN).apply {
            put(MAGIC)
            putInt(privateKey.size)
            putInt(passphraseLength)
            put(privateKey)
            if (passphrase != null) put(passphrase)
        }.array()
    }

    fun decode(payload: ByteArray): PrivateKeySecretDecodeResult {
        if (payload.size < HEADER_BYTES) {
            return PrivateKeySecretDecodeResult.Invalid("Private-key secret envelope is truncated")
        }
        val buffer = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(MAGIC.size)
        buffer.get(magic)
        if (!magic.contentEquals(MAGIC)) {
            return PrivateKeySecretDecodeResult.Invalid("Private-key secret envelope version is unsupported")
        }

        val privateKeyLength = buffer.int
        val passphraseLength = buffer.int
        if (privateKeyLength !in 1..MAX_PRIVATE_KEY_BYTES) {
            return PrivateKeySecretDecodeResult.Invalid("Private-key secret contains an invalid key length")
        }
        if (passphraseLength < -1 || passphraseLength > MAX_PASSPHRASE_BYTES) {
            return PrivateKeySecretDecodeResult.Invalid("Private-key secret contains an invalid passphrase length")
        }

        val expectedRemaining = privateKeyLength.toLong() + if (passphraseLength >= 0) passphraseLength.toLong() else 0L
        if (buffer.remaining().toLong() != expectedRemaining) {
            return PrivateKeySecretDecodeResult.Invalid("Private-key secret envelope length does not match its contents")
        }

        val privateKey = ByteArray(privateKeyLength)
        buffer.get(privateKey)
        val passphrase = if (passphraseLength >= 0) {
            ByteArray(passphraseLength).also { buffer.get(it) }
        } else {
            null
        }
        return PrivateKeySecretDecodeResult.Valid(
            PrivateKeySecretMaterial(privateKey, passphrase),
        )
    }
}

internal sealed interface PrivateKeySecretDecodeResult {
    class Valid(val material: PrivateKeySecretMaterial) : PrivateKeySecretDecodeResult
    data class Invalid(val reason: String) : PrivateKeySecretDecodeResult
}

/** Owns decoded sensitive bytes and wipes them deterministically. */
internal class PrivateKeySecretMaterial(
    private var privateKey: ByteArray?,
    private var passphrase: ByteArray?,
) : AutoCloseable {
    fun <T> useForIdentity(block: (privateKey: ByteArray, passphrase: ByteArray?) -> T): T {
        val key = privateKey ?: error("PrivateKeySecretMaterial is already closed")
        val keyCopy = key.copyOf()
        val passCopy = passphrase?.copyOf()
        return try {
            block(keyCopy, passCopy)
        } finally {
            Arrays.fill(keyCopy, 0)
            passCopy?.let { Arrays.fill(it, 0) }
        }
    }

    override fun close() {
        privateKey?.let { Arrays.fill(it, 0) }
        passphrase?.let { Arrays.fill(it, 0) }
        privateKey = null
        passphrase = null
    }

    override fun toString(): String = "PrivateKeySecretMaterial([REDACTED])"
}
