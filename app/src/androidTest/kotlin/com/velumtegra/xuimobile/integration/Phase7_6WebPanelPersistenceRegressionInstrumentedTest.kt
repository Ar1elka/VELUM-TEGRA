package com.velumtegra.xuimobile.integration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomSecretReferenceRepository
import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomWebPanelAccessRepository
import com.velumtegra.xuimobile.core.domain.CredentialTransactionResult
import com.velumtegra.xuimobile.core.domain.CredentialTransactionService
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.ReferenceProvenSecretGarbageCollector
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretGarbageCollectionResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.secrets.ProcessCredentialMutationCoordinator
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 7.6 local-only persistence regression gate.
 *
 * The test deliberately has no SSH/WebPanel HTTP collaborator. It exercises real Room persistence plus the
 * canonical credential transaction/GC boundaries, so an unreachable Direct route cannot participate in delete.
 */
@RunWith(AndroidJUnit4::class)
class Phase7_6WebPanelPersistenceRegressionInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun realRoomWebPanelCasCredentialRotationAndLocalDeleteRemainExact() = runBlocking {
        val token = token()
        val dbName = "phase7_6_webpanel_$token.db"
        val panelId = WebPanelAccessId("phase7-6-panel-$token")
        val oldSecretId = SecretId("phase7-6-old-$token")
        val newSecretId = SecretId("phase7-6-new-$token")
        val staleSecretId = SecretId("phase7-6-stale-$token")
        val secretStore = InMemorySecretStore()
        var database: VelumDatabase? = null

        try {
            context.deleteDatabase(dbName)
            val opened = VelumDatabaseFactory.open(context, dbName)
            database = opened
            val webRepo = RoomWebPanelAccessRepository(opened)
            val coordinator = ProcessCredentialMutationCoordinator()
            val credentials = CredentialTransactionService(
                secretStore = secretStore,
                serverAccessRepository = RoomServerAccessRepository(opened),
                webPanelAccessRepository = webRepo,
                credentialReferenceWriter = RoomCredentialReferenceWriter(opened),
                coordinator = coordinator,
            )
            val gc = ReferenceProvenSecretGarbageCollector(
                secretStore = secretStore,
                referenceRepository = RoomSecretReferenceRepository(opened),
                coordinator = coordinator,
            )

            val initial = WebPanelAccess(
                id = panelId,
                installationLink = WebPanelInstallationLink.Standalone,
                username = "admin",
                passwordSecretId = oldSecretId,
                route = WebPanelRoute.Direct("phase7-6-$token.invalid"),
            )

            val createdRevision = "old-password-$token".asMaterial { material ->
                credentials.createWebPanelAccess(initial, material).requireCredentialSuccess()
            }
            assertEquals(RecordRevision(0), createdRevision)
            assertEquals(initial, webRepo.get(panelId).requireRepositorySuccess().value)
            assertTrue(secretStore.contains(oldSecretId))

            val forbiddenSecretRewrite = webRepo.updateMetadata(
                initial.copy(passwordSecretId = newSecretId),
                expectedRevision = RecordRevision(0),
            )
            assertTrue(forbiddenSecretRewrite is RepositoryResult.ConstraintConflict)
            assertEquals(oldSecretId, webRepo.get(panelId).requireRepositorySuccess().value.passwordSecretId)
            assertFalse(secretStore.contains(newSecretId))

            val metadataUpdated = initial.copy(
                username = "metadata-user",
                route = WebPanelRoute.Direct("still-offline-$token.invalid"),
            )
            val metadataRevision = webRepo.updateMetadata(
                metadataUpdated,
                expectedRevision = RecordRevision(0),
            ).requireRepositorySuccess()
            assertEquals(RecordRevision(1), metadataRevision)

            val staleMetadata = webRepo.updateMetadata(
                metadataUpdated.copy(username = "stale-writer"),
                expectedRevision = RecordRevision(0),
            )
            assertTrue(staleMetadata is RepositoryResult.StaleRevision)
            val afterStaleMetadata = webRepo.get(panelId).requireRepositorySuccess()
            assertEquals(RecordRevision(1), afterStaleMetadata.revision)
            assertEquals("metadata-user", afterStaleMetadata.value.username)
            assertEquals(oldSecretId, afterStaleMetadata.value.passwordSecretId)

            val staleCredentialReplace = "stale-password-$token".asMaterial { material ->
                credentials.replaceWebPanelCredential(
                    webPanelAccessId = panelId,
                    expectedRevision = RecordRevision(0),
                    newUsername = "stale-credential",
                    newSecretId = staleSecretId,
                    newPassword = material,
                )
            }
            assertTrue(staleCredentialReplace is CredentialTransactionResult.StaleRevision)
            assertFalse(secretStore.contains(staleSecretId))

            val credentialRevision = "new-password-$token".asMaterial { material ->
                credentials.replaceWebPanelCredential(
                    webPanelAccessId = panelId,
                    expectedRevision = RecordRevision(1),
                    newUsername = "rotated-user",
                    newSecretId = newSecretId,
                    newPassword = material,
                ).requireCredentialSuccess()
            }
            assertEquals(RecordRevision(2), credentialRevision)

            val rotated = webRepo.get(panelId).requireRepositorySuccess()
            assertEquals(RecordRevision(2), rotated.revision)
            assertEquals("rotated-user", rotated.value.username)
            assertEquals(newSecretId, rotated.value.passwordSecretId)
            assertEquals(metadataUpdated.installationLink, rotated.value.installationLink)
            assertEquals(metadataUpdated.route, rotated.value.route)
            assertTrue(secretStore.contains(oldSecretId))
            assertTrue(secretStore.contains(newSecretId))

            val staleDelete = credentials.deleteWebPanelAccess(panelId, RecordRevision(1))
            assertTrue(staleDelete is CredentialTransactionResult.StaleRevision)
            assertTrue(webRepo.get(panelId) is RepositoryResult.Success)

            val preDeleteGc = gc.collect()
            assertTrue(preDeleteGc is SecretGarbageCollectionResult.Completed)
            preDeleteGc as SecretGarbageCollectionResult.Completed
            assertTrue(oldSecretId in preDeleteGc.deleted)
            assertTrue(newSecretId in preDeleteGc.retainedReferenced)
            assertFalse(secretStore.contains(oldSecretId))
            assertTrue(secretStore.contains(newSecretId))

            credentials.deleteWebPanelAccess(panelId, RecordRevision(2)).requireCredentialSuccess()
            assertTrue(webRepo.get(panelId) is RepositoryResult.NotFound)
            // Local metadata disappears first. Physical secret removal is a separate reference-proven GC step.
            assertTrue(secretStore.contains(newSecretId))

            val postDeleteGc = gc.collect()
            assertTrue(postDeleteGc is SecretGarbageCollectionResult.Completed)
            postDeleteGc as SecretGarbageCollectionResult.Completed
            assertTrue(newSecretId in postDeleteGc.deleted)
            assertFalse(secretStore.contains(newSecretId))
        } finally {
            database?.close()
            context.deleteDatabase(dbName)
        }
    }

    private suspend fun <T> String.asMaterial(block: suspend (SecretMaterial) -> T): T {
        val material = SecretMaterial.fromBytes(toByteArray())
        return try {
            block(material)
        } finally {
            material.close()
        }
    }

    private fun <T> RepositoryResult<T>.requireRepositorySuccess(): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("Expected RepositoryResult.Success, got $this")
    }

    private fun <T> CredentialTransactionResult<T>.requireCredentialSuccess(): T = when (this) {
        is CredentialTransactionResult.Success -> value
        else -> throw AssertionError("Expected CredentialTransactionResult.Success, got $this")
    }

    private fun token(): String = UUID.randomUUID().toString().replace("-", "").take(12)

    private class InMemorySecretStore : SecretStore {
        private val values = linkedMapOf<SecretId, ByteArray>()

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult {
            if (secretId in values) return SecretCreateResult.AlreadyExists
            values[secretId] = material.useBytes { it.copyOf() }
            return SecretCreateResult.Created
        }

        override suspend fun read(secretId: SecretId): SecretReadResult =
            values[secretId]?.let { SecretReadResult.Found(SecretMaterial.fromBytes(it)) }
                ?: SecretReadResult.NotFound

        override suspend fun delete(secretId: SecretId): SecretDeleteResult {
            val removed = values.remove(secretId) ?: return SecretDeleteResult.AlreadyAbsent
            removed.fill(0)
            return SecretDeleteResult.Deleted
        }

        override suspend fun listIds(): SecretListResult = SecretListResult.Success(values.keys.toSet())

        fun contains(secretId: SecretId): Boolean = secretId in values
    }
}
