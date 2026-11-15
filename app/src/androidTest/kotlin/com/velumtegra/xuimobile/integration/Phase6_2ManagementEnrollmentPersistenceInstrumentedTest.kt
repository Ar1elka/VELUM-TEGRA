package com.velumtegra.xuimobile.integration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomManagementAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomManagementEnrollmentPublisher
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.data.repository.RoomWebPanelAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomXuiInstallationRepository
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublicationResult
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentRejection
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentRequest
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.model.DiscoveryProof
import com.velumtegra.xuimobile.core.model.DiscoveryProofId
import com.velumtegra.xuimobile.core.model.DiscoveryProofSignal
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase6_2ManagementEnrollmentPersistenceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun atomicEnrollmentPublishesOrReusesExactManagementWithoutHalfState() = runBlocking {
        val token = java.util.UUID.randomUUID().toString().replace("-", "").take(12)
        val dbName = "phase6_2_enrollment_$token.db"
        var database: VelumDatabase? = null
        try {
            context.deleteDatabase(dbName)
            val db = VelumDatabaseFactory.open(context, dbName)
            database = db
            val serverRepo = RoomServerRepository(db)
            val accessWriter = RoomCredentialReferenceWriter(db)
            val installationRepo = RoomXuiInstallationRepository(db)
            val managementRepo = RoomManagementAccessRepository(db)
            val webRepo = RoomWebPanelAccessRepository(db)
            val publisher = RoomManagementEnrollmentPublisher(db)

            val serverA = Server(
                id = ServerId("server-a-$token"),
                displayName = "Phase 6.2 A",
                createdAt = Instant.parse("2026-09-06T10:00:00Z"),
            )
            val serverB = Server(
                id = ServerId("server-b-$token"),
                displayName = "Phase 6.2 B",
                createdAt = Instant.parse("2026-09-06T10:00:01Z"),
            )
            val accessA = access("access-a-$token", serverA.id)
            val accessB = access("access-b-$token", serverB.id)
            requireSuccess(serverRepo.create(serverA))
            requireSuccess(serverRepo.create(serverB))
            requireSuccess(accessWriter.createServerAccess(accessA))
            requireSuccess(accessWriter.createServerAccess(accessB))

            val adoptedProof = proof(
                serverId = serverA.id,
                serverAccessId = accessA.id,
                identity = identity(root = "/usr/local/x-ui", managedInstallId = null),
                token = token,
            )
            val adoptedBaseline = baseline(adoptedProof.observedIdentity)
            val first = requirePublished(
                publisher.publish(
                    ManagementEnrollmentRequest(
                        proof = adoptedProof,
                        baseline = adoptedBaseline,
                        proposedInstallationId = XuiInstallationId("installation-a-$token"),
                    ),
                ),
            )
            assertTrue(first.installationCreated)
            assertTrue(first.managementAccessCreated)
            assertEquals(adoptedProof.scope.serverId, first.installation.value.serverId)
            assertEquals(adoptedProof.scope.serverAccessId, first.managementAccess.serverAccessId)
            assertEquals(1, requireSuccess(installationRepo.listForServer(serverA.id)).size)
            requireSuccess(managementRepo.get(first.installation.value.id, accessA.id))
            assertTrue(requireSuccess(webRepo.list()).isEmpty())

            // A second explicit enrollment of the exact same ADOPTED identity reuses durable identity.
            val reused = requirePublished(
                publisher.publish(
                    ManagementEnrollmentRequest(
                        proof = adoptedProof.copy(id = DiscoveryProofId("proof-reuse-$token")),
                        baseline = adoptedBaseline.copy(panelPort = 54322),
                        proposedInstallationId = XuiInstallationId("installation-should-not-exist-$token"),
                    ),
                ),
            )
            assertFalse(reused.installationCreated)
            assertFalse(reused.managementAccessCreated)
            assertEquals(first.installation.value.id, reused.installation.value.id)
            assertEquals(adoptedBaseline, reused.installation.value.baseline)
            assertEquals(1, requireSuccess(installationRepo.listForServer(serverA.id)).size)

            // Wrong exact ServerAccess is rejected before either half of publication can appear.
            val wrongAccessProof = adoptedProof.copy(
                id = DiscoveryProofId("proof-wrong-access-$token"),
                scope = adoptedProof.scope.copy(serverAccessId = accessB.id),
            )
            val rejectedCrossServer = publisher.publish(
                ManagementEnrollmentRequest(
                    proof = wrongAccessProof,
                    baseline = adoptedBaseline,
                    proposedInstallationId = XuiInstallationId("installation-cross-$token"),
                ),
            )
            assertEquals(
                ManagementEnrollmentPublicationResult.Rejected(ManagementEnrollmentRejection.SERVER_ACCESS_SCOPE_MISMATCH),
                rejectedCrossServer,
            )
            assertEquals(1, requireSuccess(installationRepo.listForServer(serverA.id)).size)
            assertTrue(requireSuccess(managementRepo.listForServerAccess(accessB.id)).isEmpty())

            // A managed marker cannot silently claim the already-enrolled adopted physical identity.
            val managedConflictIdentity = adoptedProof.observedIdentity.copy(
                managedInstallId = ManagedInstallId("managed-$token"),
            )
            val managedConflict = publisher.publish(
                ManagementEnrollmentRequest(
                    proof = proof(
                        serverId = serverA.id,
                        serverAccessId = accessA.id,
                        identity = managedConflictIdentity,
                        token = "managed-$token",
                    ),
                    baseline = baseline(managedConflictIdentity),
                    proposedInstallationId = XuiInstallationId("installation-managed-conflict-$token"),
                ),
            )
            assertEquals(
                ManagementEnrollmentPublicationResult.Rejected(ManagementEnrollmentRejection.INSTALLATION_IDENTITY_CONFLICT),
                managedConflict,
            )
            assertEquals(1, requireSuccess(installationRepo.listForServer(serverA.id)).size)
            assertTrue(requireSuccess(webRepo.list()).isEmpty())
        } finally {
            database?.close()
            context.deleteDatabase(dbName)
        }
    }

    private fun access(id: String, serverId: ServerId) = ServerAccess(
        id = ServerAccessId(id),
        serverId = serverId,
        endpoint = SshEndpoint("phase62.example.test", 22),
        username = "root",
        auth = SshAuthRef.Password(SecretId("secret-$id")),
        pinnedHostKey = HostKeyFingerprint("SHA256:$id"),
    )

    private fun identity(root: String, managedInstallId: ManagedInstallId?) = InstallationIdentity(
        serviceUnit = "x-ui.service",
        binaryPath = "$root/x-ui",
        rootPath = root,
        databasePath = "/etc/x-ui/x-ui.db",
        managedInstallId = managedInstallId,
    )

    private fun baseline(identity: InstallationIdentity) = InstallationBaseline(
        serviceUnit = identity.serviceUnit,
        binaryPath = identity.binaryPath,
        rootPath = identity.rootPath,
        databasePath = identity.databasePath,
        panelPort = 54321,
        webBasePath = "/panel/",
        listenAddress = "127.0.0.1",
        capturedAt = Instant.parse("2026-09-06T10:00:05Z"),
    )

    private fun proof(
        serverId: ServerId,
        serverAccessId: ServerAccessId,
        identity: InstallationIdentity,
        token: String,
    ): DiscoveryProof {
        val signals = linkedSetOf(
            DiscoveryProofSignal.SERVICE_UNIT,
            DiscoveryProofSignal.BINARY_PATH,
            DiscoveryProofSignal.ROOT_PATH,
            DiscoveryProofSignal.DATABASE_PATH,
        )
        if (identity.managedInstallId != null) signals += DiscoveryProofSignal.MANAGED_INSTALL_MARKER
        return DiscoveryProof(
            id = DiscoveryProofId("proof-$token"),
            scope = DiscoveryScope(
                operationId = OperationId("discovery-$token"),
                serverId = serverId,
                serverAccessId = serverAccessId,
            ),
            observedIdentity = identity,
            candidateBaseline = null,
            supportingSignals = signals,
            observedAt = Instant.parse("2026-09-06T10:00:02Z"),
        )
    }

    private fun requirePublished(
        result: ManagementEnrollmentPublicationResult,
    ): ManagementEnrollmentPublicationResult.Published = when (result) {
        is ManagementEnrollmentPublicationResult.Published -> result
        else -> error("Expected Published, got $result")
    }

    private fun <T> requireSuccess(result: RepositoryResult<T>): T = when (result) {
        is RepositoryResult.Success -> result.value
        else -> error("Expected RepositoryResult.Success, got $result")
    }
}
