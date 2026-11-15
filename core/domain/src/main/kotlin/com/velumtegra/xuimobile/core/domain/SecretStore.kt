package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.SecretId
import java.util.Arrays

/**
 * Short-lived plaintext holder. It never exposes its bytes through toString and wipes its own buffer on close.
 */
class SecretMaterial private constructor(private var bytes: ByteArray?) : AutoCloseable {
    companion object {
        fun fromBytes(source: ByteArray): SecretMaterial = SecretMaterial(source.copyOf())
    }

    fun <T> useBytes(block: (ByteArray) -> T): T {
        val current = bytes ?: error("SecretMaterial is already closed")
        val temporary = current.copyOf()
        return try {
            block(temporary)
        } finally {
            Arrays.fill(temporary, 0)
        }
    }

    override fun close() {
        bytes?.let { Arrays.fill(it, 0) }
        bytes = null
    }

    override fun toString(): String = "SecretMaterial([REDACTED])"
}

sealed interface SecretCreateResult {
    data object Created : SecretCreateResult
    data object AlreadyExists : SecretCreateResult
    data class StorageFailure(val reason: String) : SecretCreateResult
}

sealed interface SecretReadResult {
    data class Found(val material: SecretMaterial) : SecretReadResult
    data object NotFound : SecretReadResult
    data class Unavailable(val reason: String) : SecretReadResult
    data class Corrupt(val reason: String) : SecretReadResult
    data class StorageFailure(val reason: String) : SecretReadResult
}

sealed interface SecretDeleteResult {
    data object Deleted : SecretDeleteResult
    data object AlreadyAbsent : SecretDeleteResult
    data class StorageFailure(val reason: String) : SecretDeleteResult
}

sealed interface SecretListResult {
    data class Success(val secretIds: Set<SecretId>) : SecretListResult
    data class StorageFailure(val reason: String) : SecretListResult
}

/** Exact SecretId storage. There is intentionally no update/overwrite method. */
interface SecretStore {
    suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult
    suspend fun read(secretId: SecretId): SecretReadResult
    suspend fun delete(secretId: SecretId): SecretDeleteResult
    suspend fun listIds(): SecretListResult
}

/**
 * Must return the COMPLETE set of every SecretId referenced by durable metadata, or an error.
 * Partial success is forbidden because cleanup is destructive.
 */
interface SecretReferenceRepository {
    suspend fun listReferencedSecretIds(): RepositoryResult<Set<SecretId>>
}

/**
 * Serializes credential writes and orphan cleanup so GC cannot race a newly staged secret.
 */
interface CredentialMutationCoordinator {
    suspend fun <T> runExclusive(block: suspend () -> T): T
}
