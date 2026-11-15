package com.velumtegra.xuimobile.core.secrets

import android.content.Context
import android.system.ErrnoException
import android.system.Os
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.SecretId
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.GeneralSecurityException
import java.util.Arrays
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Android SecretStore backed by Android Keystore AES-GCM and app-private no-backup ciphertext files.
 *
 * Published files are logically create-only within the supported single-process runtime. A fully fsynced
 * staging file is atomically renamed into place, so an app/process crash cannot expose a partially written
 * final SecretId file. All store instances for the same directory share one process-wide mutex; Android
 * multi-process execution is forbidden by the Phase 2 constitution until an inter-process writer design exists.
 */
class AndroidKeystoreSecretStore(
    context: Context,
) : SecretStore {
    companion object {
        private const val STORE_DIRECTORY = "velum_secret_store_v1"
        private val locks = ConcurrentHashMap<String, Mutex>()
    }

    private val keyProvider = AndroidKeystoreKeyProvider()
    private val codec = SecretEnvelopeCodec()
    private val directory = File(context.applicationContext.noBackupFilesDir, STORE_DIRECTORY)
    private val mutex: Mutex = locks.computeIfAbsent(directory.absolutePath) { Mutex() }

    override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult = withIoLock {
        when (val dir = ensureDirectory()) {
            is DirectoryResult.Failure -> return@withIoLock SecretCreateResult.StorageFailure(dir.reason)
            DirectoryResult.Ready -> Unit
        }
        cleanupStagingFiles()
        val target = publishedFile(secretId)
        if (target.exists()) return@withIoLock SecretCreateResult.AlreadyExists

        val filesBeforeCreate = when (val result = publishedFiles()) {
            is PublishedFilesResult.Success -> result.files
            is PublishedFilesResult.Failure -> return@withIoLock SecretCreateResult.StorageFailure(result.reason)
        }
        val hasPublishedCiphertext = filesBeforeCreate.isNotEmpty()
        val currentKey = when (val result = keyProvider.getOrCreateCurrent(hasPublishedCiphertext)) {
            is CurrentKeyResult.Available -> result
            is CurrentKeyResult.RefusedRecreation -> return@withIoLock SecretCreateResult.StorageFailure(result.reason)
            is CurrentKeyResult.Failure -> return@withIoLock SecretCreateResult.StorageFailure(result.reason)
        }

        val envelope = try {
            material.useBytes { plaintext ->
                codec.encode(secretId, plaintext, currentKey.version, currentKey.key)
            }
        } catch (error: IllegalArgumentException) {
            return@withIoLock SecretCreateResult.StorageFailure(error.message ?: "Secret cannot be encoded")
        } catch (error: GeneralSecurityException) {
            return@withIoLock SecretCreateResult.StorageFailure("Secret encryption failed: ${error.javaClass.simpleName}")
        } catch (error: Exception) {
            return@withIoLock SecretCreateResult.StorageFailure("Secret encoding failed: ${error.javaClass.simpleName}")
        }

        val stage = File(directory, ".${target.name}.${UUID.randomUUID()}${SecretFileNames.STAGING_SUFFIX}")
        try {
            if (!stage.createNewFile()) {
                return@withIoLock SecretCreateResult.StorageFailure("Could not allocate secret staging file")
            }
            FileOutputStream(stage).use { output ->
                output.write(envelope)
                output.flush()
                output.fd.sync()
            }

            // Android app sandboxes may reject hard-link creation even inside app-private storage.
            // rename(2) is the supported atomic publish primitive here. It can replace an existing target,
            // therefore create-only semantics depend on the process-wide per-directory mutex + the precheck
            // above. Multi-process writers are explicitly out of scope until an inter-process single-writer
            // design is introduced.
            if (target.exists()) return@withIoLock SecretCreateResult.AlreadyExists
            try {
                Os.rename(stage.absolutePath, target.absolutePath)
            } catch (error: ErrnoException) {
                return@withIoLock SecretCreateResult.StorageFailure(
                    "Atomic secret publish failed: rename errno ${error.errno}",
                )
            }
            if (!target.isFile) {
                return@withIoLock SecretCreateResult.StorageFailure(
                    "Atomic secret publish did not produce a regular ciphertext file",
                )
            }
            SecretCreateResult.Created
        } catch (error: Exception) {
            SecretCreateResult.StorageFailure("Secret file write failed: ${error.javaClass.simpleName}")
        } finally {
            Arrays.fill(envelope, 0)
            stage.delete()
        }
    }

    override suspend fun read(secretId: SecretId): SecretReadResult = withIoLock {
        val target = publishedFile(secretId)
        if (!target.exists()) return@withIoLock SecretReadResult.NotFound
        when (val decoded = decodeFile(target, expectedId = secretId)) {
            is FileDecodeResult.Success -> {
                val material = try {
                    SecretMaterial.fromBytes(decoded.secretBytes)
                } finally {
                    Arrays.fill(decoded.secretBytes, 0)
                }
                SecretReadResult.Found(material)
            }
            is FileDecodeResult.Unavailable -> SecretReadResult.Unavailable(decoded.reason)
            is FileDecodeResult.Corrupt -> SecretReadResult.Corrupt(decoded.reason)
            is FileDecodeResult.Failure -> SecretReadResult.StorageFailure(decoded.reason)
        }
    }

    override suspend fun delete(secretId: SecretId): SecretDeleteResult = withIoLock {
        val target = publishedFile(secretId)
        if (!target.exists()) return@withIoLock SecretDeleteResult.AlreadyAbsent
        if (target.delete()) SecretDeleteResult.Deleted
        else SecretDeleteResult.StorageFailure("Secret ciphertext could not be deleted")
    }

    override suspend fun listIds(): SecretListResult = withIoLock {
        when (val dir = ensureDirectory()) {
            is DirectoryResult.Failure -> return@withIoLock SecretListResult.StorageFailure(dir.reason)
            DirectoryResult.Ready -> Unit
        }
        cleanupStagingFiles()
        val files = when (val result = publishedFiles()) {
            is PublishedFilesResult.Success -> result.files
            is PublishedFilesResult.Failure -> return@withIoLock SecretListResult.StorageFailure(result.reason)
        }
        val ids = linkedSetOf<SecretId>()
        for (file in files) {
            when (val decoded = decodeFile(file, expectedId = null)) {
                is FileDecodeResult.Success -> {
                    try {
                        if (!SecretFileNames.matches(decoded.secretId, file.name)) {
                            return@withIoLock SecretListResult.StorageFailure(
                                "Secret filename does not match authenticated SecretId",
                            )
                        }
                        if (!ids.add(decoded.secretId)) {
                            return@withIoLock SecretListResult.StorageFailure("Duplicate SecretId ciphertext detected")
                        }
                    } finally {
                        Arrays.fill(decoded.secretBytes, 0)
                    }
                }
                is FileDecodeResult.Unavailable -> return@withIoLock SecretListResult.StorageFailure(decoded.reason)
                is FileDecodeResult.Corrupt -> return@withIoLock SecretListResult.StorageFailure(decoded.reason)
                is FileDecodeResult.Failure -> return@withIoLock SecretListResult.StorageFailure(decoded.reason)
            }
        }
        SecretListResult.Success(ids)
    }

    private suspend fun <T> withIoLock(block: () -> T): T = withContext(Dispatchers.IO) {
        mutex.withLock { block() }
    }

    private fun publishedFile(secretId: SecretId): File = File(directory, SecretFileNames.publishedName(secretId))

    private fun publishedFiles(): PublishedFilesResult {
        val entries = directory.listFiles()
            ?: return PublishedFilesResult.Failure("Secret store directory could not be enumerated completely")
        return PublishedFilesResult.Success(
            entries.filter { it.isFile && it.name.endsWith(SecretFileNames.PUBLISHED_SUFFIX) }
                .sortedBy { it.name },
        )
    }

    private fun cleanupStagingFiles() {
        directory.listFiles()
            ?.filter { it.isFile && it.name.endsWith(SecretFileNames.STAGING_SUFFIX) }
            ?.forEach { it.delete() }
    }

    private fun decodeFile(file: File, expectedId: SecretId?): FileDecodeResult {
        val envelope = try {
            if (file.length() <= 0 || file.length() > SecretEnvelopeFormat.MAX_ENVELOPE_BYTES) {
                return FileDecodeResult.Corrupt("Secret ciphertext file size is invalid")
            }
            FileInputStream(file).use { it.readBytes() }.also { bytes ->
                if (bytes.size > SecretEnvelopeFormat.MAX_ENVELOPE_BYTES) {
                    Arrays.fill(bytes, 0)
                    return FileDecodeResult.Corrupt("Secret ciphertext file grew beyond the maximum envelope size")
                }
            }
        } catch (error: Exception) {
            return FileDecodeResult.Failure("Secret ciphertext read failed: ${error.javaClass.simpleName}")
        }

        try {
            val parsed = when (val result = codec.parse(envelope)) {
                is EnvelopeDecodeResult.KeyRequired -> result.parsed
                is EnvelopeDecodeResult.Corrupt -> return FileDecodeResult.Corrupt(result.reason)
                is EnvelopeDecodeResult.Success -> return FileDecodeResult.Corrupt("Unexpected parsed envelope state")
            }
            try {
                val key = when (val lookup = keyProvider.getExisting(parsed.keyVersion)) {
                    is KeyLookupResult.Found -> lookup.key
                    KeyLookupResult.Missing -> return FileDecodeResult.Unavailable(
                        "Keystore key v${parsed.keyVersion} is missing",
                    )
                    is KeyLookupResult.Unavailable -> return FileDecodeResult.Unavailable(lookup.reason)
                    is KeyLookupResult.Failure -> return FileDecodeResult.Failure(lookup.reason)
                }
                val decrypted = try {
                    codec.decrypt(parsed, key)
                } catch (error: KeyPermanentlyInvalidatedException) {
                    return FileDecodeResult.Unavailable("Keystore key v${parsed.keyVersion} is permanently invalidated")
                } catch (error: UserNotAuthenticatedException) {
                    return FileDecodeResult.Unavailable("Keystore key v${parsed.keyVersion} is currently unavailable")
                } catch (error: GeneralSecurityException) {
                    return FileDecodeResult.Failure("Secret cryptographic operation failed: ${error.javaClass.simpleName}")
                }
                return when (decrypted) {
                    is EnvelopeDecodeResult.Success -> {
                        if (expectedId != null && decrypted.secretId != expectedId) {
                            Arrays.fill(decrypted.secretBytes, 0)
                            FileDecodeResult.Corrupt("Authenticated SecretId does not match requested SecretId")
                        } else if (!SecretFileNames.matches(decrypted.secretId, file.name)) {
                            Arrays.fill(decrypted.secretBytes, 0)
                            FileDecodeResult.Corrupt("Secret ciphertext is bound to a different filename")
                        } else {
                            FileDecodeResult.Success(decrypted.secretId, decrypted.secretBytes)
                        }
                    }
                    is EnvelopeDecodeResult.Corrupt -> FileDecodeResult.Corrupt(decrypted.reason)
                    is EnvelopeDecodeResult.KeyRequired -> FileDecodeResult.Corrupt("Unexpected encrypted payload state")
                }
            } finally {
                parsed.wipe()
            }
        } catch (error: Exception) {
            return FileDecodeResult.Failure("Secret read failed: ${error.javaClass.simpleName}")
        } finally {
            Arrays.fill(envelope, 0)
        }
    }

    private fun ensureDirectory(): DirectoryResult {
        if (directory.isDirectory) return DirectoryResult.Ready
        if (directory.exists()) return DirectoryResult.Failure("Secret store path is not a directory")
        return if (directory.mkdirs() && directory.isDirectory) DirectoryResult.Ready
        else DirectoryResult.Failure("Secret store directory could not be created")
    }
}

private sealed interface DirectoryResult {
    data object Ready : DirectoryResult
    data class Failure(val reason: String) : DirectoryResult
}

private sealed interface FileDecodeResult {
    data class Success(val secretId: SecretId, val secretBytes: ByteArray) : FileDecodeResult
    data class Unavailable(val reason: String) : FileDecodeResult
    data class Corrupt(val reason: String) : FileDecodeResult
    data class Failure(val reason: String) : FileDecodeResult
}

private sealed interface PublishedFilesResult {
    data class Success(val files: List<File>) : PublishedFilesResult
    data class Failure(val reason: String) : PublishedFilesResult
}
