package com.velumtegra.xuimobile.integration

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomManagementAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.data.repository.RoomSecretReferenceRepository
import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.data.repository.RoomWebPanelAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomXuiInstallationRepository
import com.velumtegra.xuimobile.core.domain.CredentialTransactionResult
import com.velumtegra.xuimobile.core.domain.CredentialTransactionService
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.ReferenceProvenSecretGarbageCollector
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ResumeAction
import com.velumtegra.xuimobile.core.domain.ResumePolicy
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretGarbageCollectionResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretReferenceRepository
import com.velumtegra.xuimobile.core.domain.TerminalOperationRetentionReport
import com.velumtegra.xuimobile.core.domain.TerminalOperationRetentionRequest
import com.velumtegra.xuimobile.core.domain.TerminalRetentionBatchSize
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.InterruptionReason
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.secrets.ProcessCredentialMutationCoordinator
import java.io.File
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 2.7 device/emulator gates.
 *
 * These tests intentionally live in app/androidTest so production feature/UI code still has no dependency on
 * persistence or secrets. They exercise the real AndroidSQLiteDriver, a real persistent Room file and the real
 * Android Keystore/noBackupFilesDir implementation.
 */
@RunWith(AndroidJUnit4::class)
class Phase2PersistenceSecretsInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun roomCloseReopenPreservesExactGraphAndUnsafeOperationRequiresReconcile() = runBlocking {
        val token = token()
        val dbName = "phase2_7_reopen_$token.db"
        val sshSecretId = SecretId("phase2-7-$token-ssh")
        val panelSecretId = SecretId("phase2-7-$token-panel")
        val sshPlaintext = "phase2-7-ssh-plaintext-$token"
        val panelPlaintext = "phase2-7-panel-plaintext-$token"

        var database: VelumDatabase? = null
        val secretStore = AndroidKeystoreSecretStore(context)
        try {
            context.deleteDatabase(dbName)
            val opened = VelumDatabaseFactory.open(context, dbName)
            database = opened
            val serverRepo = RoomServerRepository(opened)
            val accessRepo = RoomServerAccessRepository(opened)
            val installationRepo = RoomXuiInstallationRepository(opened)
            val managementRepo = RoomManagementAccessRepository(opened)
            val webRepo = RoomWebPanelAccessRepository(opened)
            val writer = RoomCredentialReferenceWriter(opened)
            val journal = RoomOperationJournal(opened)
            val coordinator = ProcessCredentialMutationCoordinator()
            val credentials = CredentialTransactionService(
                secretStore = secretStore,
                serverAccessRepository = accessRepo,
                webPanelAccessRepository = webRepo,
                credentialReferenceWriter = writer,
                coordinator = coordinator,
            )

            val server = Server(
                id = ServerId("server-$token"),
                displayName = "Phase 2.7 server",
                createdAt = Instant.ofEpochSecond(1_900_000_000L, 123_456_789L),
            )
            val access = ServerAccess(
                id = ServerAccessId("access-$token"),
                serverId = server.id,
                endpoint = SshEndpoint("phase27.example.test", 2222),
                username = "root",
                auth = SshAuthRef.Password(sshSecretId),
                pinnedHostKey = HostKeyFingerprint("SHA256:phase27-$token"),
            )
            val installation = installation(token, server.id)
            val management = ManagementAccess(installation.id, access.id)
            val webPanel = WebPanelAccess(
                id = WebPanelAccessId("panel-$token"),
                installationLink = WebPanelInstallationLink.Linked(installation.id),
                username = "admin",
                passwordSecretId = panelSecretId,
                route = WebPanelRoute.SshTunnel(access.id),
            )

            assertEquals(RecordRevision(0), serverRepo.create(server).requireSuccess())
            sshPlaintext.asMaterial { material ->
                credentials.createServerAccess(access, material).requireCredentialSuccess()
            }
            assertEquals(RecordRevision(0), installationRepo.create(installation).requireSuccess())
            managementRepo.create(management).requireSuccess()
            panelPlaintext.asMaterial { material ->
                assertEquals(RecordRevision(0), credentials.createWebPanelAccess(webPanel, material).requireCredentialSuccess())
            }

            val startedAt = Instant.ofEpochSecond(1_900_000_100L, 111_222_333L)
            val initial = OperationSnapshot(
                operationId = OperationId("operation-$token"),
                type = OperationType.RECOVERY,
                target = OperationTarget.InstallationTarget(server.id, access.id, installation.id),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PREPARE",
                    semantics = CheckpointSemantics.MUTATION_NOT_STARTED,
                    recordedAt = startedAt.plusSeconds(1),
                ),
                startedAt = startedAt,
                updatedAt = startedAt.plusSeconds(1),
            )
            journal.create(initial).requireOperationSuccess()
            val unsafe = initial.copy(
                checkpoint = OperationCheckpoint(
                    phaseName = "MUTATE",
                    semantics = CheckpointSemantics.MUTATION_IN_FLIGHT,
                    recordedAt = startedAt.plusSeconds(2),
                ),
                updatedAt = startedAt.plusSeconds(2),
            )
            assertEquals(
                OperationRevision(1),
                journal.advance(initial.operationId, OperationRevision(0), unsafe).requireOperationSuccess().revision,
            )

            opened.close()
            database = null

            // Reopen from the canonical production factory: this validates the real schema and driver path.
            val reopened = VelumDatabaseFactory.open(context, dbName)
            database = reopened
            val reopenedServerRepo = RoomServerRepository(reopened)
            val reopenedAccessRepo = RoomServerAccessRepository(reopened)
            val reopenedInstallationRepo = RoomXuiInstallationRepository(reopened)
            val reopenedManagementRepo = RoomManagementAccessRepository(reopened)
            val reopenedWebRepo = RoomWebPanelAccessRepository(reopened)
            val reopenedJournal = RoomOperationJournal(reopened)

            assertEquals(server, reopenedServerRepo.get(server.id).requireSuccess().value)
            assertEquals(access, reopenedAccessRepo.get(access.id).requireSuccess())
            assertEquals(installation, reopenedInstallationRepo.get(installation.id).requireSuccess().value)
            assertEquals(management, reopenedManagementRepo.get(installation.id, access.id).requireSuccess())
            assertEquals(webPanel, reopenedWebRepo.get(webPanel.id).requireSuccess().value)

            val reopenedOperation = reopenedJournal.get(initial.operationId).requireOperationSuccess()
            assertEquals(OperationRevision(1), reopenedOperation.revision)
            assertEquals(unsafe, reopenedOperation.snapshot)
            val history = reopenedJournal.history(initial.operationId).requireOperationSuccess()
            assertEquals(listOf(OperationRevision(0), OperationRevision(1)), history.map { it.revision })

            val resume = ResumePolicy.plan(
                operation = reopenedOperation.snapshot,
                interruption = InterruptionReason.PROCESS_DEATH,
                connectivity = ConnectivityState.ONLINE,
            )
            assertEquals(ResumeAction.RECONCILE_READ_ONLY, resume.action)
            assertTrue(resume.automaticAllowed)

            val references = RoomSecretReferenceRepository(reopened).listReferencedSecretIds().requireSuccess()
            assertTrue(sshSecretId in references)
            assertTrue(panelSecretId in references)

            // New SecretStore instance proves ciphertext + Android Keystore material survive store reconstruction.
            assertSecretEquals(AndroidKeystoreSecretStore(context), sshSecretId, sshPlaintext)
            assertSecretEquals(AndroidKeystoreSecretStore(context), panelSecretId, panelPlaintext)

            reopened.close()
            database = null

            // Plaintext must not leak into the Room database/WAL side of the persistence boundary.
            assertDatabaseSideDoesNotContain(dbName, sshPlaintext.toByteArray())
            assertDatabaseSideDoesNotContain(dbName, panelPlaintext.toByteArray())
        } finally {
            database?.close()
            secretStore.delete(sshSecretId)
            secretStore.delete(panelSecretId)
            context.deleteDatabase(dbName)
        }
    }

    @Test
    fun terminalRetentionReleasesPinnedAccessThenReferenceProvenGcDeletesOnlyOrphanSecret() = runBlocking {
        val token = token()
        val dbName = "phase2_7_retention_$token.db"
        val secretId = SecretId("phase2-7-$token-retained")
        val secretText = "phase2-7-retained-secret-$token"
        var database: VelumDatabase? = null
        val secretStore = AndroidKeystoreSecretStore(context)
        val protectedPreexistingSecrets = existingSecretIds(secretStore)
        try {
            context.deleteDatabase(dbName)
            val opened = VelumDatabaseFactory.open(context, dbName)
            database = opened
            val serverRepo = RoomServerRepository(opened)
            val accessRepo = RoomServerAccessRepository(opened)
            val webRepo = RoomWebPanelAccessRepository(opened)
            val writer = RoomCredentialReferenceWriter(opened)
            val coordinator = ProcessCredentialMutationCoordinator()
            val credentials = CredentialTransactionService(secretStore, accessRepo, webRepo, writer, coordinator)
            val journal = RoomOperationJournal(opened)

            val server = Server(ServerId("server-$token"), "Retention", Instant.ofEpochSecond(1_800_000_000L, 5))
            val access = ServerAccess(
                ServerAccessId("access-$token"),
                server.id,
                SshEndpoint("retention.example.test", 22),
                "root",
                SshAuthRef.Password(secretId),
                HostKeyFingerprint("SHA256:retention-$token"),
            )
            serverRepo.create(server).requireSuccess()
            secretText.asMaterial { material -> credentials.createServerAccess(access, material).requireCredentialSuccess() }

            val old = Instant.ofEpochSecond(1_800_000_100L, 1)
            val terminal = OperationSnapshot(
                operationId = OperationId("terminal-$token"),
                type = OperationType.QUICK_INSPECT,
                target = OperationTarget.ServerTarget(server.id, access.id),
                status = OperationStatus.SUCCEEDED,
                checkpoint = OperationCheckpoint("DONE", CheckpointSemantics.TERMINAL, old),
                startedAt = old.minusSeconds(1),
                updatedAt = old,
            )
            journal.create(terminal).requireOperationSuccess()

            val pinnedDelete = credentials.deleteServerAccess(access.id)
            assertTrue(pinnedDelete is CredentialTransactionResult.ConstraintConflict)
            assertSecretEquals(secretStore, secretId, secretText)

            val now = old.plusSeconds(3_600)
            val report: TerminalOperationRetentionReport = journal.pruneTerminalOperations(
                TerminalOperationRetentionRequest(
                    updatedBefore = now.minusSeconds(60),
                    observedAt = now,
                    batchSize = TerminalRetentionBatchSize(10),
                ),
            ).requireOperationSuccess()
            assertEquals(listOf(terminal.operationId), report.prunedOperationIds)
            assertTrue(journal.get(terminal.operationId) is OperationJournalResult.NotFound)

            credentials.deleteServerAccess(access.id).requireCredentialSuccess()
            val gc = ReferenceProvenSecretGarbageCollector(
                secretStore = secretStore,
                referenceRepository = protectingReferenceRepository(
                    RoomSecretReferenceRepository(opened),
                    protectedPreexistingSecrets,
                ),
                coordinator = coordinator,
            ).collect()
            assertTrue(gc is SecretGarbageCollectionResult.Completed)
            gc as SecretGarbageCollectionResult.Completed
            assertTrue(secretId in gc.deleted)
            assertTrue(secretStore.read(secretId) is SecretReadResult.NotFound)
        } finally {
            database?.close()
            secretStore.delete(secretId)
            context.deleteDatabase(dbName)
        }
    }

    @Test
    fun realRoomRejectsCrossServerManagementWebPanelAndOperationTargets() = runBlocking {
        val token = token()
        val dbName = "phase2_7_cross_server_$token.db"
        val secretA = SecretId("phase2-7-$token-a")
        val secretB = SecretId("phase2-7-$token-b")
        val panelOrphan = SecretId("phase2-7-$token-panel-orphan")
        var database: VelumDatabase? = null
        val secretStore = AndroidKeystoreSecretStore(context)
        val protectedPreexistingSecrets = existingSecretIds(secretStore)
        try {
            context.deleteDatabase(dbName)
            val opened = VelumDatabaseFactory.open(context, dbName)
            database = opened
            val serverRepo = RoomServerRepository(opened)
            val accessRepo = RoomServerAccessRepository(opened)
            val installationRepo = RoomXuiInstallationRepository(opened)
            val managementRepo = RoomManagementAccessRepository(opened)
            val webRepo = RoomWebPanelAccessRepository(opened)
            val writer = RoomCredentialReferenceWriter(opened)
            val coordinator = ProcessCredentialMutationCoordinator()
            val credentials = CredentialTransactionService(secretStore, accessRepo, webRepo, writer, coordinator)
            val journal = RoomOperationJournal(opened)

            val serverA = Server(ServerId("server-a-$token"), "A", Instant.ofEpochSecond(1_700_000_000L, 1))
            val serverB = Server(ServerId("server-b-$token"), "B", Instant.ofEpochSecond(1_700_000_000L, 2))
            serverRepo.create(serverA).requireSuccess()
            serverRepo.create(serverB).requireSuccess()
            val accessA = access("access-a-$token", serverA.id, secretA)
            val accessB = access("access-b-$token", serverB.id, secretB)
            "secret-a-$token".asMaterial { credentials.createServerAccess(accessA, it).requireCredentialSuccess() }
            "secret-b-$token".asMaterial { credentials.createServerAccess(accessB, it).requireCredentialSuccess() }
            val installationA = installation("a-$token", serverA.id)
            installationRepo.create(installationA).requireSuccess()

            val managementResult = managementRepo.create(ManagementAccess(installationA.id, accessB.id))
            assertTrue(managementResult is RepositoryResult.ConstraintConflict)

            val badPanel = WebPanelAccess(
                id = WebPanelAccessId("bad-panel-$token"),
                installationLink = WebPanelInstallationLink.Linked(installationA.id),
                username = "admin",
                passwordSecretId = panelOrphan,
                route = WebPanelRoute.SshTunnel(accessB.id),
            )
            val panelResult = "panel-secret-$token".asMaterial { credentials.createWebPanelAccess(badPanel, it) }
            assertTrue(panelResult is CredentialTransactionResult.ConstraintConflict)
            assertTrue(webRepo.get(badPanel.id) is RepositoryResult.NotFound)
            // Cross-store failure is safe: only an orphan ciphertext may exist, never a live wrong DB relation.
            assertSecretEquals(secretStore, panelOrphan, "panel-secret-$token")

            val time = Instant.ofEpochSecond(1_700_000_100L, 1)
            val badOperation = OperationSnapshot(
                operationId = OperationId("bad-op-$token"),
                type = OperationType.RECOVERY,
                target = OperationTarget.InstallationTarget(serverA.id, accessB.id, installationA.id),
                status = OperationStatus.PENDING,
                checkpoint = OperationCheckpoint("PREPARE", CheckpointSemantics.MUTATION_NOT_STARTED, time),
                startedAt = time,
                updatedAt = time,
            )
            assertTrue(journal.create(badOperation) is OperationJournalResult.InvalidTransition)

            val gc = ReferenceProvenSecretGarbageCollector(
                secretStore,
                protectingReferenceRepository(
                    RoomSecretReferenceRepository(opened),
                    protectedPreexistingSecrets,
                ),
                coordinator,
            ).collect()
            assertTrue(gc is SecretGarbageCollectionResult.Completed)
            gc as SecretGarbageCollectionResult.Completed
            assertTrue(panelOrphan in gc.deleted)
            assertFalse(secretA in gc.deleted)
            assertFalse(secretB in gc.deleted)
        } finally {
            database?.close()
            secretStore.delete(secretA)
            secretStore.delete(secretB)
            secretStore.delete(panelOrphan)
            context.deleteDatabase(dbName)
        }
    }

    @Test
    fun realSecretStorePublishIsCreateOnlyAndReconstructible() = runBlocking {
        val id = SecretId("phase2-7-publish-${token()}")
        val first = "first-secret-${token()}"
        val replacementAttempt = "must-not-overwrite-${token()}"
        val store = AndroidKeystoreSecretStore(context)
        try {
            val created = first.asMaterial { material -> store.create(id, material) }
            assertEquals(SecretCreateResult.Created, created)

            val duplicate = replacementAttempt.asMaterial { material ->
                AndroidKeystoreSecretStore(context).create(id, material)
            }
            assertEquals(SecretCreateResult.AlreadyExists, duplicate)

            // A fresh store instance must still read the first value, proving duplicate create did not overwrite.
            assertSecretEquals(AndroidKeystoreSecretStore(context), id, first)
        } finally {
            when (val deleted = AndroidKeystoreSecretStore(context).delete(id)) {
                SecretDeleteResult.Deleted, SecretDeleteResult.AlreadyAbsent -> Unit
                is SecretDeleteResult.StorageFailure -> throw AssertionError(
                    "Test secret cleanup failed: ${deleted.reason}",
                )
            }
        }
    }

    @Test
    fun operationalStateIsExplicitlyExcludedFromBackupAndTransferConfiguration() {
        val appInfo = context.packageManager.getApplicationInfo(context.packageName, 0)
        assertEquals(0, appInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP)
        assertTrue(context.resources.getIdentifier("backup_rules", "xml", context.packageName) != 0)
        assertTrue(context.resources.getIdentifier("data_extraction_rules", "xml", context.packageName) != 0)
    }

    private fun installation(token: String, serverId: ServerId): XuiInstallation = XuiInstallation(
        id = XuiInstallationId("installation-$token"),
        serverId = serverId,
        ownership = InstallationOwnership.ADOPTED,
        identity = InstallationIdentity(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            managedInstallId = null,
        ),
        baseline = InstallationBaseline(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            panelPort = 54321,
            webBasePath = "/panel/",
            listenAddress = "127.0.0.1",
            capturedAt = Instant.ofEpochSecond(1_900_000_050L, 444_555_666L),
        ),
    )

    private fun access(id: String, serverId: ServerId, secretId: SecretId) = ServerAccess(
        id = ServerAccessId(id),
        serverId = serverId,
        endpoint = SshEndpoint("$id.example.test", 22),
        username = "root",
        auth = SshAuthRef.Password(secretId),
        pinnedHostKey = HostKeyFingerprint("SHA256:$id"),
    )

    private suspend fun assertSecretEquals(store: AndroidKeystoreSecretStore, secretId: SecretId, expected: String) {
        val read = store.read(secretId)
        assertTrue("Secret $secretId was not readable: $read", read is SecretReadResult.Found)
        read as SecretReadResult.Found
        try {
            val actual = read.material.useBytes { bytes -> String(bytes, Charsets.UTF_8) }
            assertEquals(expected, actual)
        } finally {
            read.material.close()
        }
    }

    private fun assertDatabaseSideDoesNotContain(databaseName: String, needle: ByteArray) {
        val base = context.getDatabasePath(databaseName)
        listOf(base, File(base.path + "-wal"), File(base.path + "-shm"))
            .filter { it.isFile }
            .forEach { file ->
                assertFalse("Plaintext credential leaked into ${file.name}", file.readBytes().containsBytes(needle))
            }
    }

    private fun ByteArray.containsBytes(needle: ByteArray): Boolean {
        if (needle.isEmpty()) return true
        if (needle.size > size) return false
        outer@ for (start in 0..size - needle.size) {
            for (offset in needle.indices) {
                if (this[start + offset] != needle[offset]) continue@outer
            }
            return true
        }
        return false
    }

    private suspend fun <T> String.asMaterial(block: suspend (SecretMaterial) -> T): T {
        val material = SecretMaterial.fromBytes(toByteArray())
        return try {
            block(material)
        } finally {
            material.close()
        }
    }

    private suspend fun existingSecretIds(store: AndroidKeystoreSecretStore): Set<SecretId> = when (val listed = store.listIds()) {
        is SecretListResult.Success -> listed.secretIds
        is SecretListResult.StorageFailure -> throw AssertionError(
            "Pre-existing SecretStore inventory is not trustworthy: ${listed.reason}",
        )
    }

    /**
     * Instrumented GC must never treat unrelated debug-app secrets as orphans just because the test uses a
     * temporary Room database. Everything that existed before this test is conservatively pinned.
     */
    private fun protectingReferenceRepository(
        delegate: SecretReferenceRepository,
        protectedSecretIds: Set<SecretId>,
    ): SecretReferenceRepository = object : SecretReferenceRepository {
        override suspend fun listReferencedSecretIds(): RepositoryResult<Set<SecretId>> =
            when (val result = delegate.listReferencedSecretIds()) {
                is RepositoryResult.Success -> RepositoryResult.Success(result.value + protectedSecretIds)
                else -> result
            }
    }

    private fun <T> RepositoryResult<T>.requireSuccess(): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("Expected RepositoryResult.Success, got $this")
    }

    private fun <T> CredentialTransactionResult<T>.requireCredentialSuccess(): T = when (this) {
        is CredentialTransactionResult.Success -> value
        else -> throw AssertionError("Expected CredentialTransactionResult.Success, got $this")
    }

    private fun <T> OperationJournalResult<T>.requireOperationSuccess(): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("Expected OperationJournalResult.Success, got $this")
    }

    private fun token(): String = UUID.randomUUID().toString().replace("-", "").take(12)
}
