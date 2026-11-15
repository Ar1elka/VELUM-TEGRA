package com.velumtegra.xuimobile.integration

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.domain.ManagementAccessRepository
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagementAccess
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.management.LocalManagementReview
import com.velumtegra.xuimobile.management.RepositoryManagementLocalReviewPort
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Check every binding before any access lookup: fake repositories, no SSH or saved-state writes. */
@RunWith(AndroidJUnit4::class)
class Phase14_3JBindingInventoryPreflightAcceptanceInstrumentedTest {
    private class Fixture(
        private val bindingSpecs: List<Pair<String, String>> = listOf("install-7" to "ssh-11"),
    ) {
        var bindingReads = 0
            private set
        var accessReads = 0
            private set

        private val server = Server(ServerId("server-7"), "Fixture", Instant.EPOCH)
        private val installation = XuiInstallation(
            id = XuiInstallationId("install-7"),
            serverId = ServerId("server-7"),
            ownership = InstallationOwnership.MANAGED,
            identity = InstallationIdentity(
                serviceUnit = "x-ui.service", binaryPath = "/opt/x-ui/x-ui",
                rootPath = "/opt/x-ui", databasePath = "/opt/x-ui/x-ui.db",
                managedInstallId = ManagedInstallId("fixture-managed"),
            ),
            baseline = InstallationBaseline(
                serviceUnit = "x-ui.service", binaryPath = "/opt/x-ui/x-ui",
                rootPath = "/opt/x-ui", databasePath = "/opt/x-ui/x-ui.db",
                panelPort = 2053, webBasePath = "/panel", listenAddress = null,
                capturedAt = Instant.EPOCH,
            ),
        )
        private val access = ServerAccess(
            id = ServerAccessId("ssh-11"), serverId = ServerId("server-7"),
            endpoint = SshEndpoint("127.0.0.1", 22), username = "fixture",
            auth = SshAuthRef.Password(SecretId("reference-only-no-secret")),
            pinnedHostKey = HostKeyFingerprint("dummy-fingerprint"),
        )
        private val servers = object : ServerRepository {
            override suspend fun get(serverId: ServerId) =
                RepositoryResult.Success(VersionedRecord(server, RecordRevision(0)))
            override suspend fun list(): RepositoryResult<List<VersionedRecord<Server>>> = error("unexpected list")
            override suspend fun create(server: Server): RepositoryResult<RecordRevision> = error("no writes")
            override suspend fun update(server: Server, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("no writes")
            override suspend fun delete(serverId: ServerId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("no writes")
        }
        private val installations = object : XuiInstallationRepository {
            override suspend fun get(installationId: XuiInstallationId) =
                RepositoryResult.Success(VersionedRecord(installation, RecordRevision(0)))
            override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<VersionedRecord<XuiInstallation>>> = error("unexpected list")
            override suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision> = error("no writes")
            override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("no writes")
            override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("no writes")
        }
        private val management = object : ManagementAccessRepository {
            override suspend fun listForInstallation(installationId: XuiInstallationId): RepositoryResult<List<ManagementAccess>> {
                bindingReads++
                return RepositoryResult.Success(bindingSpecs.map { (installationKey, accessKey) ->
                    ManagementAccess(XuiInstallationId(installationKey), ServerAccessId(accessKey))
                })
            }
            override suspend fun get(installationId: XuiInstallationId, serverAccessId: ServerAccessId): RepositoryResult<ManagementAccess> = error("unexpected get")
            override suspend fun listForServerAccess(serverAccessId: ServerAccessId): RepositoryResult<List<ManagementAccess>> = error("unexpected list")
            override suspend fun create(access: ManagementAccess): RepositoryResult<Unit> = error("no writes")
            override suspend fun delete(installationId: XuiInstallationId, serverAccessId: ServerAccessId): RepositoryResult<Unit> = error("no writes")
        }
        private val accesses = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> {
                accessReads++
                return RepositoryResult.Success(access.copy(id = serverAccessId))
            }
            override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> = error("unexpected list")
            override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> = error("no writes")
        }
        fun read(): LocalManagementReview = runBlocking {
            RepositoryManagementLocalReviewPort(servers, installations, management, accesses)
                .readExact("server-7", "install-7")
        }
    }

    @Test fun laterForeignInstallationBindingBlocksAllAccessReads() {
        val fixture = Fixture(listOf("install-7" to "ssh-11", "foreign-install" to "ssh-22"))
        assertTrue(fixture.read() is LocalManagementReview.Unavailable)
        assertEquals(1, fixture.bindingReads)
        assertEquals(0, fixture.accessReads)
    }

    @Test fun laterBlankAccessBindingBlocksAllAccessReads() {
        val fixture = Fixture(listOf("install-7" to "ssh-11", "install-7" to "  "))
        assertTrue(fixture.read() is LocalManagementReview.Unavailable)
        assertEquals(1, fixture.bindingReads)
        assertEquals(0, fixture.accessReads)
    }

    @Test fun laterDuplicateAccessBindingBlocksAllAccessReads() {
        val fixture = Fixture(listOf("install-7" to "ssh-11", "install-7" to "ssh-11"))
        assertTrue(fixture.read() is LocalManagementReview.Unavailable)
        assertEquals(1, fixture.bindingReads)
        assertEquals(0, fixture.accessReads)
    }

    @Test fun validMultipleBindingsAreReadOnceAndSortedForOfflineReview() {
        val fixture = Fixture(listOf("install-7" to "ssh-22", "install-7" to "ssh-11"))
        val review = fixture.read()
        assertTrue(review is LocalManagementReview.Ready)
        val ready = review as LocalManagementReview.Ready
        assertEquals(listOf("ssh-11", "ssh-22"), ready.accessIds)
        assertEquals(2, ready.managementBindings)
        assertEquals(1, fixture.bindingReads)
        assertEquals(2, fixture.accessReads)
    }
}
