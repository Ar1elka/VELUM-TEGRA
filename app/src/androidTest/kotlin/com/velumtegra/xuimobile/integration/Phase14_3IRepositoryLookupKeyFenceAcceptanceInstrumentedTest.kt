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

/** Repository ID fidelity: in-memory stubs, no SSH/network/secrets or persistent writes. */
@RunWith(AndroidJUnit4::class)
class Phase14_3IRepositoryLookupKeyFenceAcceptanceInstrumentedTest {
    private class Fixture(
        private val returnedServerId: String = "server-7",
        private val returnedInstallationId: String = "install-7",
        private val returnedAccessId: String = "ssh-11",
    ) {
        var installationReads = 0
            private set
        var bindingReads = 0
            private set
        var accessReads = 0
            private set

        private val server = Server(ServerId(returnedServerId), "Fixture", Instant.EPOCH)
        private val installation = XuiInstallation(
            id = XuiInstallationId(returnedInstallationId),
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
        private val binding = ManagementAccess(XuiInstallationId("install-7"), ServerAccessId("ssh-11"))
        private val access = ServerAccess(
            id = ServerAccessId(returnedAccessId), serverId = ServerId("server-7"),
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
            override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> {
                installationReads++
                return RepositoryResult.Success(VersionedRecord(installation, RecordRevision(0)))
            }
            override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<VersionedRecord<XuiInstallation>>> = error("unexpected list")
            override suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision> = error("no writes")
            override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> = error("no writes")
            override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("no writes")
        }
        private val management = object : ManagementAccessRepository {
            override suspend fun listForInstallation(installationId: XuiInstallationId): RepositoryResult<List<ManagementAccess>> {
                bindingReads++
                return RepositoryResult.Success(listOf(binding))
            }
            override suspend fun get(installationId: XuiInstallationId, serverAccessId: ServerAccessId): RepositoryResult<ManagementAccess> = error("unexpected get")
            override suspend fun listForServerAccess(serverAccessId: ServerAccessId): RepositoryResult<List<ManagementAccess>> = error("unexpected list")
            override suspend fun create(access: ManagementAccess): RepositoryResult<Unit> = error("no writes")
            override suspend fun delete(installationId: XuiInstallationId, serverAccessId: ServerAccessId): RepositoryResult<Unit> = error("no writes")
        }
        private val accesses = object : ServerAccessRepository {
            override suspend fun get(serverAccessId: ServerAccessId): RepositoryResult<ServerAccess> {
                accessReads++
                return RepositoryResult.Success(access)
            }
            override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<ServerAccess>> = error("unexpected list")
            override suspend fun delete(serverAccessId: ServerAccessId): RepositoryResult<Unit> = error("no writes")
        }
        fun read(): LocalManagementReview = runBlocking {
            RepositoryManagementLocalReviewPort(servers, installations, management, accesses)
                .readExact("server-7", "install-7")
        }
    }

    @Test fun foreignServerRecordIsRejectedBeforeReadingInstallations() {
        val fixture = Fixture(returnedServerId = "foreign-server")
        assertTrue(fixture.read() is LocalManagementReview.Unavailable)
        assertEquals(0, fixture.installationReads)
        assertEquals(0, fixture.bindingReads)
        assertEquals(0, fixture.accessReads)
    }

    @Test fun foreignInstallationRecordIsRejectedBeforeReadingBindings() {
        val fixture = Fixture(returnedInstallationId = "foreign-installation")
        assertTrue(fixture.read() is LocalManagementReview.Unavailable)
        assertEquals(1, fixture.installationReads)
        assertEquals(0, fixture.bindingReads)
        assertEquals(0, fixture.accessReads)
    }

    @Test fun foreignAccessRecordIsRejectedInsteadOfAdvertisingUnverifiedBinding() {
        val fixture = Fixture(returnedAccessId = "foreign-ssh-access")
        assertTrue(fixture.read() is LocalManagementReview.Unavailable)
        assertEquals(1, fixture.installationReads)
        assertEquals(1, fixture.bindingReads)
        assertEquals(1, fixture.accessReads)
    }

    @Test fun exactlyMatchedRepositoryRecordsRemainVisibleAsReadOnlyMetadata() {
        val fixture = Fixture()
        val result = fixture.read()
        assertTrue(result is LocalManagementReview.Ready)
        val ready = result as LocalManagementReview.Ready
        assertEquals("server-7", ready.serverId)
        assertEquals("install-7", ready.installationId)
        assertEquals(listOf("ssh-11"), ready.accessIds)
        assertEquals(1, ready.managementBindings)
        assertEquals(1, fixture.installationReads)
        assertEquals(1, fixture.bindingReads)
        assertEquals(1, fixture.accessReads)
    }
}
