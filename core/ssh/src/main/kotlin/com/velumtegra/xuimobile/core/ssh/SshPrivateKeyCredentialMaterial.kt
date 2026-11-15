package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.SecretMaterial
import java.util.Arrays

/**
 * Builds the canonical SecretStore payload for [com.velumtegra.xuimobile.core.model.SshAuthRef.PrivateKey].
 *
 * Callers retain ownership of [privateKey] and [passphrase]. This function never exposes their content through
 * toString/logging and wipes its temporary encoded envelope after [SecretMaterial] takes its defensive copy.
 */
object SshPrivateKeyCredentialMaterial {
    fun create(
        privateKey: ByteArray,
        passphrase: ByteArray? = null,
    ): SecretMaterial {
        val encoded = PrivateKeySecretEnvelopeCodec.encode(privateKey, passphrase)
        return try {
            SecretMaterial.fromBytes(encoded)
        } finally {
            Arrays.fill(encoded, 0)
        }
    }
}
