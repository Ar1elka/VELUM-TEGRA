package com.velumtegra.xuimobile.core.secrets

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

internal sealed interface KeyLookupResult {
    data class Found(val key: SecretKey) : KeyLookupResult
    data object Missing : KeyLookupResult
    data class Unavailable(val reason: String) : KeyLookupResult
    data class Failure(val reason: String) : KeyLookupResult
}

internal sealed interface CurrentKeyResult {
    data class Available(val version: Int, val key: SecretKey) : CurrentKeyResult
    data class RefusedRecreation(val reason: String) : CurrentKeyResult
    data class Failure(val reason: String) : CurrentKeyResult
}

internal class AndroidKeystoreKeyProvider {
    companion object {
        const val CURRENT_KEY_VERSION = 1
        private const val PROVIDER = "AndroidKeyStore"
        private const val ALIAS_PREFIX = "com.velumtegra.xuimobile.secret-master.v"
    }

    private fun alias(version: Int): String = "$ALIAS_PREFIX$version"

    fun getExisting(version: Int): KeyLookupResult {
        if (version <= 0) return KeyLookupResult.Failure("Invalid Keystore key version")
        return try {
            val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
            if (!keyStore.containsAlias(alias(version))) return KeyLookupResult.Missing
            val key = keyStore.getKey(alias(version), null) as? SecretKey
                ?: return KeyLookupResult.Failure("Keystore alias v$version is not an AES SecretKey")
            KeyLookupResult.Found(key)
        } catch (error: KeyPermanentlyInvalidatedException) {
            KeyLookupResult.Unavailable("Keystore key v$version is permanently invalidated")
        } catch (error: UserNotAuthenticatedException) {
            KeyLookupResult.Unavailable("Keystore key v$version is currently unavailable")
        } catch (error: UnrecoverableKeyException) {
            KeyLookupResult.Unavailable("Keystore key v$version cannot be recovered")
        } catch (error: Exception) {
            KeyLookupResult.Failure("Keystore lookup failed for key v$version: ${error.javaClass.simpleName}")
        }
    }

    fun getOrCreateCurrent(hasPublishedCiphertext: Boolean): CurrentKeyResult {
        return when (val existing = getExisting(CURRENT_KEY_VERSION)) {
            is KeyLookupResult.Found -> CurrentKeyResult.Available(CURRENT_KEY_VERSION, existing.key)
            is KeyLookupResult.Unavailable -> CurrentKeyResult.Failure(existing.reason)
            is KeyLookupResult.Failure -> CurrentKeyResult.Failure(existing.reason)
            KeyLookupResult.Missing -> {
                if (hasPublishedCiphertext) {
                    CurrentKeyResult.RefusedRecreation(
                        "Keystore key v$CURRENT_KEY_VERSION is missing while ciphertext exists; refusing alias reuse",
                    )
                } else {
                    createCurrent()
                }
            }
        }
    }

    private fun createCurrent(): CurrentKeyResult = try {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            alias(CURRENT_KEY_VERSION),
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .build()
        generator.init(spec)
        CurrentKeyResult.Available(CURRENT_KEY_VERSION, generator.generateKey())
    } catch (error: Exception) {
        CurrentKeyResult.Failure("Keystore key creation failed: ${error.javaClass.simpleName}")
    }
}
