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
import com.velumtegra.xuimobile.core.domain.InstallerPostInstallFacts
import com.velumtegra.xuimobile.core.domain.InstallerPostInstallPolicy
import com.velumtegra.xuimobile.core.domain.InstallerPostInstallVerificationDecision
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublicationResult
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentRejection
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InstallerWorkerScope
import com.velumtegra.xuimobile.core.model.ManagedInstallId
import com.velumtegra.xuimobile.core.model.ManagedInstallMarkerReadbackState
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase8_5InstallerPublicationInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun verifiedInstallerPublicationIsAtomicExactIdempotentAndNeverCreatesWebPanelAccess() = runBlocking {
        val token = UUID.randomUUID().toString().replace("-", "")
        val dbName = "phase8_5_installer_${token.take(12)}.db"
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
                id = ServerId("p85-server-a-${token.take(8)}"),
                displayName = "Phase 8.5 A",
                createdAt = Instant.parse("2026-09-12T07:30:00Z"),
            )
            val serverB = Server(
                id = ServerId("p85-server-b-${token.take(8)}"),
                displayName = "Phase 8.5 B",
                createdAt = Instant.parse("2026-09-12T07:30:01Z"),
            )
            val accessA = access("p85-access-a-${token.take(8)}", serverA.id)
            val accessB = access("p85-access-b-${token.take(8)}", serverB.id)
            requireSuccess(serverRepo.create(serverA))
            requireSuccess(serverRepo.create(serverB))
            requireSuccess(accessWriter.createServerAccess(accessA))
            requireSuccess(accessWriter.createServerAccess(accessB))

            val scope = InstallerWorkerScope(
                operationId = OperationId("p85-install-${token.take(12)}"),
                serverId = serverA.id,
                serverAccessId = accessA.id,
                managedInstallId = ManagedInstallId("v1-${token.take(32)}"),
            )
            val request = requireVerifiedRequest(scope)
            val first = requirePublished(publisher.publishInstaller(request))

            assertTrue(first.installationCreated)
            assertTrue(first.managementAccessCreated)
            assertEquals(InstallerPostInstallPolicy.installationIdFor(scope), first.installation.value.id)
            assertEquals(scope.serverId, first.installation.value.serverId)
            assertEquals(scope.managedInstallId, first.installation.value.identity.managedInstallId)
            assertEquals(request.baseline, first.installation.value.baseline)
            assertEquals(scope.serverAccessId, first.managementAccess.serverAccessId)
            assertEquals(1, requireSuccess(installationRepo.listForServer(serverA.id)).size)
            requireSuccess(managementRepo.get(first.installation.value.id, accessA.id))
            assertTrue(requireSuccess(webRepo.list()).isEmpty())

            val replay = requirePublished(
                publisher.publishInstaller(
                    request.copy(baseline = request.baseline.copy(capturedAt = request.baseline.capturedAt.plusSeconds(30))),
                ),
            )
            assertFalse(replay.installationCreated)
            assertFalse(replay.managementAccessCreated)
            assertEquals(first.installation, replay.installation)
            assertEquals(1, requireSuccess(installationRepo.listForServer(serverA.id)).size)
            assertTrue(requireSuccess(webRepo.list()).isEmpty())

            val driftedBaseline = publisher.publishInstaller(
                request.copy(baseline = request.baseline.copy(panelPort = request.baseline.panelPort + 1)),
            )
            assertEquals(
                ManagementEnrollmentPublicationResult.Rejected(
                    ManagementEnrollmentRejection.INSTALLATION_BASELINE_CONFLICT,
                ),
                driftedBaseline,
            )
            assertEquals(1, requireSuccess(installationRepo.listForServer(serverA.id)).size)
            assertTrue(requireSuccess(webRepo.list()).isEmpty())

            val wrongScope = scope.copy(serverAccessId = accessB.id)
            val rejected = publisher.publishInstaller(requireVerifiedRequest(wrongScope))
            assertEquals(
                ManagementEnrollmentPublicationResult.Rejected(
                    ManagementEnrollmentRejection.SERVER_ACCESS_SCOPE_MISMATCH,
                ),
                rejected,
            )
            assertEquals(1, requireSuccess(installationRepo.listForServer(serverA.id)).size)
            assertTrue(requireSuccess(managementRepo.listForServerAccess(accessB.id)).isEmpty())
            assertTrue(requireSuccess(webRepo.list()).isEmpty())
        } finally {
            database?.close()
            context.deleteDatabase(dbName)
        }
    }

    private fun requireVerifiedRequest(scope: InstallerWorkerScope) = when (
        val decision = InstallerPostInstallPolicy.verify(
            scope,
            InstallerPostInstallFacts(
                markerReadback = ManagedInstallMarkerReadbackState.MATCH,
                serviceUnitPresent = true,
                binaryPresent = true,
                rootPresent = true,
                databasePresent = true,
                serviceState = ManagementServiceState.ACTIVE,
                panelPort = 23456,
                webBasePath = "/phase85/",
                listenAddress = null,
                listenerPresent = true,
                observedAt = Instant.parse("2026-09-12T07:31:00Z"),
            ),
        )
    ) {
        is InstallerPostInstallVerificationDecision.Verified -> decision.request
        is InstallerPostInstallVerificationDecision.Rejected -> error("Expected verified Installer facts, got $decision")
    }

    private fun access(id: String, serverId: ServerId) = ServerAccess(
        id = ServerAccessId(id),
        serverId = serverId,
        endpoint = SshEndpoint("phase85.example.test", 22),
        username = "root",
        auth = SshAuthRef.Password(SecretId("secret-$id")),
        pinnedHostKey = HostKeyFingerprint("SHA256:$id"),
    )

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
