package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import java.security.MessageDigest

/**
 * Cross-store result. Secret failures and durable metadata failures remain distinguishable.
 */
sealed interface CredentialTransactionResult<out T> {
    data class Success<T>(val value: T) : CredentialTransactionResult<T>
    data object NotFound : CredentialTransactionResult<Nothing>
    data object SecretAlreadyExists : CredentialTransactionResult<Nothing>
    data class SecretUnavailable(val reason: String) : CredentialTransactionResult<Nothing>
    data class ConstraintConflict(val reason: String) : CredentialTransactionResult<Nothing>
    data class StaleRevision(
        val expected: RecordRevision,
        val actual: RecordRevision,
    ) : CredentialTransactionResult<Nothing>
    data class Corruption(val reason: String) : CredentialTransactionResult<Nothing>
    data class StorageFailure(val reason: String) : CredentialTransactionResult<Nothing>
}

/**
 * Safe cross-store credential ordering.
 *
 * SecretStore and Room do not share ACID, so successful create/replace always publishes and verifies
 * ciphertext before committing a durable SecretId reference. If the database step later fails, the
 * new secret is merely orphaned and reference-proven GC can remove it later.
 */
class CredentialTransactionService(
    private val secretStore: SecretStore,
    private val serverAccessRepository: ServerAccessRepository,
    private val webPanelAccessRepository: WebPanelAccessRepository,
    private val credentialReferenceWriter: CredentialReferenceWriter,
    private val coordinator: CredentialMutationCoordinator,
) {
    /**
     * Used for both initial ServerAccess creation and copy-on-write replacement versions.
     * The caller supplies the exact new ServerAccessId/SecretId; existing IDs are never overwritten.
     */
    suspend fun createServerAccess(
        access: ServerAccess,
        secret: SecretMaterial,
    ): CredentialTransactionResult<Unit> = coordinator.runExclusive {
        when (val secretResult = createAndVerifySecret(access.auth.secretId, secret)) {
            is CredentialTransactionResult.Success -> Unit
            else -> return@runExclusive secretResult.castFailure()
        }
        credentialReferenceWriter.createServerAccess(access).toCredentialResult()
    }

    suspend fun createWebPanelAccess(
        access: WebPanelAccess,
        password: SecretMaterial,
    ): CredentialTransactionResult<RecordRevision> = coordinator.runExclusive {
        when (val secretResult = createAndVerifySecret(access.passwordSecretId, password)) {
            is CredentialTransactionResult.Success -> Unit
            else -> return@runExclusive secretResult.castFailure()
        }
        credentialReferenceWriter.createWebPanelAccess(access).toCredentialResult()
    }

    /**
     * Copy-on-write WebPanel credential rotation under the same WebPanelAccessId.
     * Username + password SecretId move atomically together; route/link fields remain unchanged.
     */
    suspend fun replaceWebPanelCredential(
        webPanelAccessId: WebPanelAccessId,
        expectedRevision: RecordRevision,
        newUsername: String,
        newSecretId: SecretId,
        newPassword: SecretMaterial,
    ): CredentialTransactionResult<RecordRevision> = coordinator.runExclusive {
        val current = when (val read = webPanelAccessRepository.get(webPanelAccessId)) {
            is RepositoryResult.Success -> read.value
            else -> return@runExclusive read.toCredentialFailure()
        }
        if (current.revision != expectedRevision) {
            return@runExclusive CredentialTransactionResult.StaleRevision(expectedRevision, current.revision)
        }
        val oldSecretId = current.value.passwordSecretId
        if (newUsername.isBlank()) {
            return@runExclusive CredentialTransactionResult.ConstraintConflict(
                "WebPanel username must not be blank",
            )
        }
        if (newSecretId == oldSecretId) {
            return@runExclusive CredentialTransactionResult.ConstraintConflict(
                "WebPanel password replacement requires a new SecretId",
            )
        }

        when (val secretResult = createAndVerifySecret(newSecretId, newPassword)) {
            is CredentialTransactionResult.Success -> Unit
            else -> return@runExclusive secretResult.castFailure()
        }

        credentialReferenceWriter.swapWebPanelCredential(
            webPanelAccessId = webPanelAccessId,
            expectedSecretId = oldSecretId,
            newSecretId = newSecretId,
            newUsername = newUsername,
            expectedRevision = expectedRevision,
        ).toCredentialResult()
    }

    /**
     * DB reference is removed first. Physical secret cleanup is deliberately deferred to proven GC.
     */
    suspend fun deleteWebPanelAccess(
        webPanelAccessId: WebPanelAccessId,
        expectedRevision: RecordRevision,
    ): CredentialTransactionResult<Unit> = coordinator.runExclusive {
        webPanelAccessRepository.delete(webPanelAccessId, expectedRevision).toCredentialResult()
    }

    /**
     * Repository FK/blocker checks keep exact accesses pinned by durable relations/operations.
     * On success its SecretId may become an orphan; GC decides only from the complete reference graph.
     */
    suspend fun deleteServerAccess(
        serverAccessId: ServerAccessId,
    ): CredentialTransactionResult<Unit> = coordinator.runExclusive {
        serverAccessRepository.delete(serverAccessId).toCredentialResult()
    }

    private suspend fun createAndVerifySecret(
        secretId: SecretId,
        material: SecretMaterial,
    ): CredentialTransactionResult<Unit> {
        when (val create = secretStore.create(secretId, material)) {
            SecretCreateResult.Created -> Unit
            SecretCreateResult.AlreadyExists -> return CredentialTransactionResult.SecretAlreadyExists
            is SecretCreateResult.StorageFailure -> return CredentialTransactionResult.StorageFailure(create.reason)
        }

        return when (val read = secretStore.read(secretId)) {
            is SecretReadResult.Found -> {
                val matches = try {
                    material.useBytes { expected ->
                        read.material.useBytes { actual -> MessageDigest.isEqual(expected, actual) }
                    }
                } catch (error: IllegalStateException) {
                    false
                } finally {
                    read.material.close()
                }
                if (matches) CredentialTransactionResult.Success(Unit)
                else CredentialTransactionResult.Corruption(
                    "Secret read-back did not match the staged credential; DB reference was not committed",
                )
            }
            SecretReadResult.NotFound -> CredentialTransactionResult.Corruption(
                "Secret disappeared before read-back verification; DB reference was not committed",
            )
            is SecretReadResult.Unavailable -> CredentialTransactionResult.SecretUnavailable(read.reason)
            is SecretReadResult.Corrupt -> CredentialTransactionResult.Corruption(read.reason)
            is SecretReadResult.StorageFailure -> CredentialTransactionResult.StorageFailure(read.reason)
        }
    }
}

sealed interface SecretGarbageCollectionResult {
    data class Completed(
        val deleted: Set<SecretId>,
        val retainedReferenced: Set<SecretId>,
    ) : SecretGarbageCollectionResult

    /** No secret deletion occurred. */
    data class Aborted(val reason: String) : SecretGarbageCollectionResult

    /** Some already-proven orphan deletions completed before a later safe failure. Retrying is valid. */
    data class PartialFailure(
        val deleted: Set<SecretId>,
        val failedSecretId: SecretId?,
        val reason: String,
    ) : SecretGarbageCollectionResult
}

/**
 * Deletes only SecretIds proven absent from the COMPLETE durable reference graph.
 * Enumeration/reference failures are fail-closed. All credential writers and this collector share
 * the same coordinator, preventing a legitimate new reference from racing the final proof/delete window.
 */
class ReferenceProvenSecretGarbageCollector(
    private val secretStore: SecretStore,
    private val referenceRepository: SecretReferenceRepository,
    private val coordinator: CredentialMutationCoordinator,
) {
    suspend fun collect(): SecretGarbageCollectionResult = coordinator.runExclusive {
        val firstStored = when (val stored = secretStore.listIds()) {
            is SecretListResult.Success -> stored.secretIds
            is SecretListResult.StorageFailure -> return@runExclusive SecretGarbageCollectionResult.Aborted(
                "Secret enumeration failed: ${stored.reason}",
            )
        }
        val firstReferenced = when (val references = referenceRepository.listReferencedSecretIds()) {
            is RepositoryResult.Success -> references.value
            else -> return@runExclusive SecretGarbageCollectionResult.Aborted(
                "Durable secret-reference scan failed: ${references.failureReason()}",
            )
        }

        val preliminary = firstStored - firstReferenced
        if (preliminary.isEmpty()) {
            return@runExclusive SecretGarbageCollectionResult.Completed(
                deleted = emptySet(),
                retainedReferenced = firstStored intersect firstReferenced,
            )
        }

        // Second complete inventory is required immediately before destructive work.
        val secondStored = when (val stored = secretStore.listIds()) {
            is SecretListResult.Success -> stored.secretIds
            is SecretListResult.StorageFailure -> return@runExclusive SecretGarbageCollectionResult.Aborted(
                "Secret re-enumeration failed: ${stored.reason}",
            )
        }
        val secondReferenced = when (val references = referenceRepository.listReferencedSecretIds()) {
            is RepositoryResult.Success -> references.value
            else -> return@runExclusive SecretGarbageCollectionResult.Aborted(
                "Durable secret-reference re-scan failed: ${references.failureReason()}",
            )
        }

        // Never delete secrets that appeared only after the first inventory.
        val candidates = preliminary.intersect(secondStored).minus(secondReferenced).sortedBy { it.value }
        val deleted = linkedSetOf<SecretId>()
        val retainedReferenced = linkedSetOf<SecretId>().apply {
            addAll(secondStored.intersect(secondReferenced))
        }

        for (candidate in candidates) {
            // Defensive final reference proof per candidate. With correct coordinator wiring this set cannot
            // gain a credential reference concurrently; the extra scan also catches accidental bypasses.
            val referencesNow = when (val references = referenceRepository.listReferencedSecretIds()) {
                is RepositoryResult.Success -> references.value
                else -> {
                    val reason = "Final durable secret-reference scan failed: ${references.failureReason()}"
                    return@runExclusive if (deleted.isEmpty()) {
                        SecretGarbageCollectionResult.Aborted(reason)
                    } else {
                        SecretGarbageCollectionResult.PartialFailure(deleted, candidate, reason)
                    }
                }
            }
            if (candidate in referencesNow) {
                retainedReferenced += candidate
                continue
            }

            when (val deletion = secretStore.delete(candidate)) {
                SecretDeleteResult.Deleted,
                SecretDeleteResult.AlreadyAbsent,
                -> deleted += candidate
                is SecretDeleteResult.StorageFailure -> {
                    return@runExclusive SecretGarbageCollectionResult.PartialFailure(
                        deleted = deleted,
                        failedSecretId = candidate,
                        reason = deletion.reason,
                    )
                }
            }
        }

        SecretGarbageCollectionResult.Completed(
            deleted = deleted,
            retainedReferenced = retainedReferenced,
        )
    }
}

private fun <T> RepositoryResult<T>.toCredentialResult(): CredentialTransactionResult<T> = when (this) {
    is RepositoryResult.Success -> CredentialTransactionResult.Success(value)
    RepositoryResult.NotFound -> CredentialTransactionResult.NotFound
    is RepositoryResult.ConstraintConflict -> CredentialTransactionResult.ConstraintConflict(reason)
    is RepositoryResult.StaleRevision -> CredentialTransactionResult.StaleRevision(expected, actual)
    is RepositoryResult.Corruption -> CredentialTransactionResult.Corruption(reason)
    is RepositoryResult.StorageFailure -> CredentialTransactionResult.StorageFailure(reason)
}

private fun RepositoryResult<*>.toCredentialFailure(): CredentialTransactionResult<Nothing> = when (this) {
    is RepositoryResult.Success -> error("Success cannot be converted to a failure")
    RepositoryResult.NotFound -> CredentialTransactionResult.NotFound
    is RepositoryResult.ConstraintConflict -> CredentialTransactionResult.ConstraintConflict(reason)
    is RepositoryResult.StaleRevision -> CredentialTransactionResult.StaleRevision(expected, actual)
    is RepositoryResult.Corruption -> CredentialTransactionResult.Corruption(reason)
    is RepositoryResult.StorageFailure -> CredentialTransactionResult.StorageFailure(reason)
}

@Suppress("UNCHECKED_CAST")
private fun <T> CredentialTransactionResult<*>.castFailure(): CredentialTransactionResult<T> {
    require(this !is CredentialTransactionResult.Success<*>) { "Success cannot be cast as failure" }
    return this as CredentialTransactionResult<T>
}

private fun RepositoryResult<*>.failureReason(): String = when (this) {
    is RepositoryResult.Success -> "unexpected success"
    RepositoryResult.NotFound -> "reference graph was unexpectedly unavailable"
    is RepositoryResult.ConstraintConflict -> reason
    is RepositoryResult.StaleRevision -> "stale revision ${expected.value}/${actual.value}"
    is RepositoryResult.Corruption -> reason
    is RepositoryResult.StorageFailure -> reason
}
