package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialTransactionsTest {
    @Test
    fun `secret create failure prevents durable credential reference write`() = runBlocking {
        val fixture = Fixture()
        fixture.secretStore.createFailure = "disk unavailable"

        val result = material("pw").useMaterial { secret ->
            fixture.service.createServerAccess(serverAccess(SECRET_A), secret)
        }

        assertTrue(result is CredentialTransactionResult.StorageFailure)
        assertEquals(0, fixture.writer.createServerAccessCalls)
        assertFalse(SECRET_A in fixture.secretStore.ids())
    }

    @Test
    fun `database failure after verified secret leaves only an orphan`() = runBlocking {
        val fixture = Fixture()
        fixture.writer.serverAccessCreateResult = RepositoryResult.ConstraintConflict("server missing")

        val result = material("pw").useMaterial { secret ->
            fixture.service.createServerAccess(serverAccess(SECRET_A), secret)
        }

        assertTrue(result is CredentialTransactionResult.ConstraintConflict)
        assertTrue(SECRET_A in fixture.secretStore.ids())
        assertTrue(fixture.serverRepo.items.isEmpty())
        assertEquals(1, fixture.writer.createServerAccessCalls)
    }

    @Test
    fun `readback mismatch prevents database commit and leaves cleanup candidate`() = runBlocking {
        val fixture = Fixture()
        fixture.secretStore.readTransform = { "different".toByteArray() }

        val result = material("pw").useMaterial { secret ->
            fixture.service.createWebPanelAccess(webPanel(SECRET_A), secret)
        }

        assertTrue(result is CredentialTransactionResult.Corruption)
        assertEquals(0, fixture.writer.createWebPanelCalls)
        assertTrue(SECRET_A in fixture.secretStore.ids())
    }

    @Test
    fun `stale web panel revision creates no new secret`() = runBlocking {
        val fixture = Fixture()
        fixture.webPanelRepo.items[WEB_ID] = VersionedRecord(webPanel(SECRET_OLD), RecordRevision(2))

        val result = material("new").useMaterial { secret ->
            fixture.service.replaceWebPanelCredential(
                webPanelAccessId = WEB_ID,
                expectedRevision = RecordRevision(1),
                newUsername = "admin-new",
                newSecretId = SECRET_NEW,
                newPassword = secret,
            )
        }

        assertTrue(result is CredentialTransactionResult.StaleRevision)
        assertFalse(SECRET_NEW in fixture.secretStore.ids())
        assertEquals(0, fixture.writer.swapCalls)
    }

    @Test
    fun `failed password CAS preserves old reference and new secret becomes orphan`() = runBlocking {
        val fixture = Fixture()
        fixture.secretStore.seed(SECRET_OLD, "old")
        fixture.webPanelRepo.items[WEB_ID] = VersionedRecord(webPanel(SECRET_OLD), RecordRevision(0))
        fixture.writer.swapResult = RepositoryResult.StorageFailure("injected after secret create")

        val result = material("new").useMaterial { secret ->
            fixture.service.replaceWebPanelCredential(
                webPanelAccessId = WEB_ID,
                expectedRevision = RecordRevision(0),
                newUsername = "admin-new",
                newSecretId = SECRET_NEW,
                newPassword = secret,
            )
        }

        assertTrue(result is CredentialTransactionResult.StorageFailure)
        assertEquals(SECRET_OLD, fixture.webPanelRepo.items.getValue(WEB_ID).value.passwordSecretId)
        assertEquals("admin", fixture.webPanelRepo.items.getValue(WEB_ID).value.username)
        assertTrue(SECRET_NEW in fixture.secretStore.ids())

        val gc = ReferenceProvenSecretGarbageCollector(
            fixture.secretStore,
            FixedReferenceRepository { setOf(SECRET_OLD) },
            fixture.coordinator,
        )
        val gcResult = gc.collect()
        assertTrue(gcResult is SecretGarbageCollectionResult.Completed)
        assertFalse(SECRET_NEW in fixture.secretStore.ids())
        assertTrue(SECRET_OLD in fixture.secretStore.ids())
    }


    @Test
    fun `successful web panel credential replace commits username and secret together`() = runBlocking {
        val fixture = Fixture()
        fixture.secretStore.seed(SECRET_OLD, "old")
        fixture.webPanelRepo.items[WEB_ID] = VersionedRecord(webPanel(SECRET_OLD), RecordRevision(0))

        val result = material("new").useMaterial { secret ->
            fixture.service.replaceWebPanelCredential(
                webPanelAccessId = WEB_ID,
                expectedRevision = RecordRevision(0),
                newUsername = "admin-new",
                newSecretId = SECRET_NEW,
                newPassword = secret,
            )
        }

        assertTrue(result is CredentialTransactionResult.Success)
        val stored = fixture.webPanelRepo.items.getValue(WEB_ID)
        assertEquals("admin-new", stored.value.username)
        assertEquals(SECRET_NEW, stored.value.passwordSecretId)
        assertEquals(RecordRevision(1), stored.revision)
    }

    @Test
    fun `delete removes DB reference first and later GC removes orphan`() = runBlocking {
        val fixture = Fixture()
        fixture.secretStore.seed(SECRET_OLD, "old")
        fixture.webPanelRepo.items[WEB_ID] = VersionedRecord(webPanel(SECRET_OLD), RecordRevision(0))

        val delete = fixture.service.deleteWebPanelAccess(WEB_ID, RecordRevision(0))
        assertTrue(delete is CredentialTransactionResult.Success)
        assertFalse(WEB_ID in fixture.webPanelRepo.items)
        assertTrue(SECRET_OLD in fixture.secretStore.ids())

        val gc = ReferenceProvenSecretGarbageCollector(
            fixture.secretStore,
            FixedReferenceRepository { emptySet() },
            fixture.coordinator,
        )
        val gcResult = gc.collect()
        assertTrue(gcResult is SecretGarbageCollectionResult.Completed)
        assertFalse(SECRET_OLD in fixture.secretStore.ids())
    }

    @Test
    fun `GC aborts without deleting when durable reference scan fails`() = runBlocking {
        val fixture = Fixture()
        fixture.secretStore.seed(SECRET_A, "a")
        val refs = SequenceReferenceRepository(
            mutableListOf(RepositoryResult.StorageFailure("db unavailable")),
        )
        val gc = ReferenceProvenSecretGarbageCollector(fixture.secretStore, refs, fixture.coordinator)

        val result = gc.collect()

        assertTrue(result is SecretGarbageCollectionResult.Aborted)
        assertTrue(SECRET_A in fixture.secretStore.ids())
        assertTrue(fixture.secretStore.deleteCalls.isEmpty())
    }

    @Test
    fun `GC second proof protects candidate that becomes referenced`() = runBlocking {
        val fixture = Fixture()
        fixture.secretStore.seed(SECRET_A, "a")
        val refs = SequenceReferenceRepository(
            mutableListOf(
                RepositoryResult.Success(emptySet()),
                RepositoryResult.Success(setOf(SECRET_A)),
            ),
        )
        val gc = ReferenceProvenSecretGarbageCollector(fixture.secretStore, refs, fixture.coordinator)

        val result = gc.collect()

        assertTrue(result is SecretGarbageCollectionResult.Completed)
        assertTrue(SECRET_A in fixture.secretStore.ids())
        assertTrue(fixture.secretStore.deleteCalls.isEmpty())
    }

    @Test
    fun `GC partial delete failure is retry safe`() = runBlocking {
        val fixture = Fixture()
        fixture.secretStore.seed(SECRET_A, "a")
        fixture.secretStore.seed(SECRET_B, "b")
        fixture.secretStore.failDeleteFor = SECRET_B
        val refs = FixedReferenceRepository { emptySet() }
        val gc = ReferenceProvenSecretGarbageCollector(fixture.secretStore, refs, fixture.coordinator)

        val first = gc.collect()
        assertTrue(first is SecretGarbageCollectionResult.PartialFailure)
        assertFalse(SECRET_A in fixture.secretStore.ids())
        assertTrue(SECRET_B in fixture.secretStore.ids())

        fixture.secretStore.failDeleteFor = null
        val second = gc.collect()
        assertTrue(second is SecretGarbageCollectionResult.Completed)
        assertTrue(fixture.secretStore.ids().isEmpty())
    }

    @Test
    fun `credential writer calls occur inside coordinator lane`() = runBlocking {
        val fixture = Fixture()
        fixture.writer.requireExclusive = true

        val result = material("pw").useMaterial { secret ->
            fixture.service.createServerAccess(serverAccess(SECRET_A), secret)
        }

        assertTrue(result is CredentialTransactionResult.Success)
        assertEquals(1, fixture.coordinator.entries)
    }

    private class Fixture {
        val coordinator = TrackingCoordinator()
        val secretStore = FakeSecretStore()
        val serverRepo = FakeServerAccessRepository()
        val webPanelRepo = FakeWebPanelAccessRepository()
        val writer = FakeCredentialReferenceWriter(serverRepo, webPanelRepo, coordinator)
        val service = CredentialTransactionService(
            secretStore = secretStore,
            serverAccessRepository = serverRepo,
            webPanelAccessRepository = webPanelRepo,
            credentialReferenceWriter = writer,
            coordinator = coordinator,
        )
    }

    private class TrackingCoordinator : CredentialMutationCoordinator {
        var inside = false
        var entries = 0

        override suspend fun <T> runExclusive(block: suspend () -> T): T {
            check(!inside) { "test coordinator is intentionally non-reentrant" }
            inside = true
            entries += 1
            return try {
                block()
            } finally {
                inside = false
            }
        }
    }

    private class FakeSecretStore : SecretStore {
        private val values = linkedMapOf<SecretId, ByteArray>()
        var createFailure: String? = null
        var readTransform: ((ByteArray) -> ByteArray)? = null
        var failDeleteFor: SecretId? = null
        val deleteCalls = mutableListOf<SecretId>()

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult {
            createFailure?.let { return SecretCreateResult.StorageFailure(it) }
            if (secretId in values) return SecretCreateResult.AlreadyExists
            values[secretId] = material.useBytes { it.copyOf() }
            return SecretCreateResult.Created
        }

        override suspend fun read(secretId: SecretId): SecretReadResult {
            val value = values[secretId] ?: return SecretReadResult.NotFound
            val output = readTransform?.invoke(value.copyOf()) ?: value.copyOf()
            return SecretReadResult.Found(SecretMaterial.fromBytes(output))
        }

        override suspend fun delete(secretId: SecretId): SecretDeleteResult {
            deleteCalls += secretId
            if (secretId == failDeleteFor) return SecretDeleteResult.StorageFailure("injected delete failure")
            return if (values.remove(secretId) != null) SecretDeleteResult.Deleted else SecretDeleteResult.AlreadyAbsent
        }

        override suspend fun listIds(): SecretListResult = SecretListResult.Success(values.keys.toSet())

        fun seed(secretId: SecretId, value: String) {
            values[secretId] = value.toByteArray()
        }

        fun ids(): Set<SecretId> = values.keys.toSet()
    }

    private class FakeServerAccessRepository : ServerAccessRepository {
        val items = linkedMapOf<ServerAccessId, ServerAccess>()

        override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> =
            items[serverAccessId]?.let { RepositoryResult.Success(it) } ?: RepositoryResult.NotFound

        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> =
            RepositoryResult.Success(items.values.filter { it.serverId == serverId })

        override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> =
            if (items.remove(serverAccessId) != null) RepositoryResult.Success(Unit) else RepositoryResult.NotFound
    }

    private class FakeWebPanelAccessRepository : WebPanelAccessRepository {
        val items = linkedMapOf<WebPanelAccessId, VersionedRecord<WebPanelAccess>>()

        override suspend fun get(webPanelAccessId: WebPanelAccessId): RepositoryResult<VersionedRecord<WebPanelAccess>> =
            items[webPanelAccessId]?.let { RepositoryResult.Success(it) } ?: RepositoryResult.NotFound

        override suspend fun list(): RepositoryResult<List<VersionedRecord<WebPanelAccess>>> =
            RepositoryResult.Success(items.values.toList())

        override suspend fun updateMetadata(
            access: WebPanelAccess,
            expectedRevision: RecordRevision,
        ): RepositoryResult<RecordRevision> {
            val current = items[access.id] ?: return RepositoryResult.NotFound
            if (current.revision != expectedRevision) {
                return RepositoryResult.StaleRevision(expectedRevision, current.revision)
            }
            if (current.value.passwordSecretId != access.passwordSecretId) {
                return RepositoryResult.ConstraintConflict("secret change forbidden")
            }
            val next = RecordRevision(expectedRevision.value + 1)
            items[access.id] = VersionedRecord(access, next)
            return RepositoryResult.Success(next)
        }

        override suspend fun delete(
            webPanelAccessId: WebPanelAccessId,
            expectedRevision: RecordRevision,
        ): RepositoryResult<Unit> {
            val current = items[webPanelAccessId] ?: return RepositoryResult.NotFound
            if (current.revision != expectedRevision) {
                return RepositoryResult.StaleRevision(expectedRevision, current.revision)
            }
            items.remove(webPanelAccessId)
            return RepositoryResult.Success(Unit)
        }
    }

    private class FakeCredentialReferenceWriter(
        private val serverRepo: FakeServerAccessRepository,
        private val webPanelRepo: FakeWebPanelAccessRepository,
        private val coordinator: TrackingCoordinator,
    ) : CredentialReferenceWriter {
        var createServerAccessCalls = 0
        var createWebPanelCalls = 0
        var swapCalls = 0
        var requireExclusive = false
        var serverAccessCreateResult: RepositoryResult<Unit>? = null
        var swapResult: RepositoryResult<RecordRevision>? = null

        override suspend fun createServerAccess(serverAccess: ServerAccess): RepositoryResult<Unit> {
            checkLane()
            createServerAccessCalls += 1
            serverAccessCreateResult?.let { return it }
            if (serverAccess.id in serverRepo.items) return RepositoryResult.ConstraintConflict("exists")
            serverRepo.items[serverAccess.id] = serverAccess
            return RepositoryResult.Success(Unit)
        }

        override suspend fun createWebPanelAccess(access: WebPanelAccess): RepositoryResult<RecordRevision> {
            checkLane()
            createWebPanelCalls += 1
            if (access.id in webPanelRepo.items) return RepositoryResult.ConstraintConflict("exists")
            val revision = RecordRevision(0)
            webPanelRepo.items[access.id] = VersionedRecord(access, revision)
            return RepositoryResult.Success(revision)
        }

        override suspend fun swapWebPanelCredential(
            webPanelAccessId: WebPanelAccessId,
            expectedSecretId: SecretId,
            newSecretId: SecretId,
            newUsername: String,
            expectedRevision: RecordRevision,
        ): RepositoryResult<RecordRevision> {
            checkLane()
            swapCalls += 1
            swapResult?.let { return it }
            val current = webPanelRepo.items[webPanelAccessId] ?: return RepositoryResult.NotFound
            if (current.revision != expectedRevision) {
                return RepositoryResult.StaleRevision(expectedRevision, current.revision)
            }
            if (current.value.passwordSecretId != expectedSecretId) {
                return RepositoryResult.ConstraintConflict("secret changed")
            }
            val next = RecordRevision(expectedRevision.value + 1)
            webPanelRepo.items[webPanelAccessId] = VersionedRecord(
                current.value.copy(username = newUsername, passwordSecretId = newSecretId),
                next,
            )
            return RepositoryResult.Success(next)
        }

        private fun checkLane() {
            if (requireExclusive) check(coordinator.inside) { "credential writer bypassed coordinator" }
        }
    }

    private class FixedReferenceRepository(
        private val values: () -> Set<SecretId>,
    ) : SecretReferenceRepository {
        override suspend fun listReferencedSecretIds(): RepositoryResult<Set<SecretId>> =
            RepositoryResult.Success(values())
    }

    private class SequenceReferenceRepository(
        private val results: MutableList<RepositoryResult<Set<SecretId>>>,
    ) : SecretReferenceRepository {
        override suspend fun listReferencedSecretIds(): RepositoryResult<Set<SecretId>> =
            if (results.size > 1) results.removeAt(0) else results.first()
    }

    private fun serverAccess(secretId: SecretId) = ServerAccess(
        id = SERVER_ACCESS_ID,
        serverId = SERVER_ID,
        endpoint = SshEndpoint("example.test", 22),
        username = "root",
        auth = SshAuthRef.Password(secretId),
        pinnedHostKey = HostKeyFingerprint("SHA256:test"),
    )

    private fun webPanel(secretId: SecretId) = WebPanelAccess(
        id = WEB_ID,
        installationLink = WebPanelInstallationLink.Standalone,
        username = "admin",
        passwordSecretId = secretId,
        route = WebPanelRoute.Direct("panel.example.test"),
    )

    private fun material(value: String): SecretMaterial = SecretMaterial.fromBytes(value.toByteArray())

    private suspend fun <T> SecretMaterial.useMaterial(block: suspend (SecretMaterial) -> T): T = try {
        block(this)
    } finally {
        close()
    }

    private companion object {
        val SERVER_ID = ServerId("server-1")
        val SERVER_ACCESS_ID = ServerAccessId("access-1")
        val WEB_ID = WebPanelAccessId("web-1")
        val SECRET_A = SecretId("secret-a")
        val SECRET_B = SecretId("secret-b")
        val SECRET_OLD = SecretId("secret-old")
        val SECRET_NEW = SecretId("secret-new")
    }
}
