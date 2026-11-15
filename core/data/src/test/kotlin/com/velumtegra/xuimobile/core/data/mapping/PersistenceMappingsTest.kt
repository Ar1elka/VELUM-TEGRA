package com.velumtegra.xuimobile.core.data.mapping

import com.velumtegra.xuimobile.core.data.db.OperationSnapshotEntity
import com.velumtegra.xuimobile.core.data.db.ServerAccessEntity
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
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
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PersistenceMappingsTest {
    @Test
    fun `server round trip preserves nanosecond instant exactly`() {
        val source = Server(
            id = ServerId("srv-1"),
            displayName = "Primary",
            createdAt = Instant.ofEpochSecond(1_700_000_000L, 987_654_321L),
        )

        val mapped = source.toEntity(RecordRevision(4)).toDomain()

        assertTrue(mapped is PersistenceMappingResult.Success)
        mapped as PersistenceMappingResult.Success
        assertEquals(source, mapped.value.value)
        assertEquals(RecordRevision(4), mapped.value.revision)
    }

    @Test
    fun `server access round trip keeps exact secret auth kind`() {
        val source = ServerAccess(
            id = ServerAccessId("access-1"),
            serverId = ServerId("srv-1"),
            endpoint = SshEndpoint("example.org", 2222),
            username = "root",
            auth = SshAuthRef.PrivateKey(SecretId("secret-key-v3")),
            pinnedHostKey = HostKeyFingerprint("SHA256:abc"),
        )

        val mapped = source.toEntity().toDomain()

        assertEquals(PersistenceMappingResult.Success(source), mapped)
    }

    @Test
    fun `unknown persisted auth code is corruption not fallback`() {
        val row = ServerAccessEntity(
            serverAccessId = "access-1",
            serverId = "srv-1",
            host = "example.org",
            port = 22,
            username = "root",
            authKind = "LATEST_PASSWORD",
            secretId = "secret-1",
            pinnedHostKey = "SHA256:abc",
        )

        assertTrue(row.toDomain() is PersistenceMappingResult.Corruption)
    }

    @Test
    fun `installation round trip preserves ownership invariant and nanos`() {
        val capturedAt = Instant.ofEpochSecond(1_800_000_000L, 123_456_789L)
        val source = XuiInstallation(
            id = XuiInstallationId("inst-1"),
            serverId = ServerId("srv-1"),
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
                capturedAt = capturedAt,
            ),
        )

        val mapped = source.toEntity(RecordRevision(2)).toDomain()

        assertTrue(mapped is PersistenceMappingResult.Success)
        mapped as PersistenceMappingResult.Success
        assertEquals(source, mapped.value.value)
    }

    @Test
    fun `linked ssh panel requires one exact bound server`() {
        val source = WebPanelAccess(
            id = WebPanelAccessId("panel-1"),
            installationLink = WebPanelInstallationLink.Linked(XuiInstallationId("inst-1")),
            username = "admin",
            passwordSecretId = SecretId("panel-secret-1"),
            route = WebPanelRoute.SshTunnel(ServerAccessId("access-1")),
        )

        assertTrue(
            source.toEntity(
                revision = RecordRevision(0),
                boundServerId = null,
            ) is PersistenceMappingResult.Corruption,
        )

        val mapped = source.toEntity(
            revision = RecordRevision(0),
            boundServerId = ServerId("srv-1"),
        )
        assertTrue(mapped is PersistenceMappingResult.Success)
        mapped as PersistenceMappingResult.Success
        assertEquals("srv-1", mapped.value.boundServerId)
        assertEquals(PersistenceMappingResult.Success(source), mapped.value.toDomain().mapValue())
    }

    @Test
    fun `standalone direct panel cannot invent server ownership`() {
        val source = WebPanelAccess(
            id = WebPanelAccessId("panel-1"),
            installationLink = WebPanelInstallationLink.Standalone,
            username = "admin",
            passwordSecretId = SecretId("panel-secret-1"),
            route = WebPanelRoute.Direct("panel.example.org"),
        )

        assertTrue(
            source.toEntity(
                revision = RecordRevision(0),
                boundServerId = ServerId("srv-1"),
            ) is PersistenceMappingResult.Corruption,
        )
    }

    @Test
    fun `operation round trip preserves exact target identity and nanoseconds`() {
        val startedAt = Instant.ofEpochSecond(1_900_000_000L, 111_222_333L)
        val checkpointAt = Instant.ofEpochSecond(1_900_000_001L, 444_555_666L)
        val updatedAt = Instant.ofEpochSecond(1_900_000_002L, 777_888_999L)
        val source = OperationSnapshot(
            operationId = OperationId("op-1"),
            type = OperationType.RECOVERY,
            target = OperationTarget.InstallationTarget(
                serverId = ServerId("srv-1"),
                serverAccessId = ServerAccessId("access-7"),
                installationId = XuiInstallationId("inst-4"),
            ),
            status = OperationStatus.RECONCILIATION_REQUIRED,
            checkpoint = OperationCheckpoint(
                phaseName = "POST_VERIFY",
                semantics = CheckpointSemantics.POST_VERIFY_REQUIRED,
                recordedAt = checkpointAt,
            ),
            startedAt = startedAt,
            updatedAt = updatedAt,
        )

        val mapped = source.toEntity(OperationRevision(9)).toDomain()

        assertEquals(
            PersistenceMappingResult.Success(
                com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot(source, OperationRevision(9)),
            ),
            mapped,
        )
    }

    @Test
    fun `server target row carrying installation id is corruption`() {
        val row = validOperationRow().copy(
            targetKind = PersistenceCodes.TARGET_SERVER,
            installationId = "inst-should-not-be-here",
        )

        assertTrue(row.toDomain() is PersistenceMappingResult.Corruption)
    }

    @Test
    fun `negative operation revision is corruption`() {
        val row = validOperationRow().copy(revision = -1)

        assertTrue(row.toDomain() is PersistenceMappingResult.Corruption)
    }

    @Test
    fun `management mapper carries resolved server discriminator`() {
        val source = ManagementAccess(
            installationId = XuiInstallationId("inst-1"),
            serverAccessId = ServerAccessId("access-1"),
        )

        val row = source.toEntity(ServerId("srv-1"))

        assertEquals("srv-1", row.serverId)
        assertEquals(PersistenceMappingResult.Success(source), row.toDomain())
    }

    private fun validOperationRow() = OperationSnapshotEntity(
        operationId = "op-1",
        operationType = PersistenceCodes.OP_DISCOVERY,
        targetKind = PersistenceCodes.TARGET_SERVER,
        serverId = "srv-1",
        serverAccessId = "access-1",
        installationId = null,
        status = PersistenceCodes.STATUS_RUNNING,
        checkpointPhaseName = "READ",
        checkpointSemantics = PersistenceCodes.CHECKPOINT_READ_ONLY,
        checkpointEpochSecond = 10,
        checkpointNano = 1,
        startedAtEpochSecond = 9,
        startedAtNano = 999_999_999,
        updatedAtEpochSecond = 10,
        updatedAtNano = 2,
        revision = 0,
    )
}

private fun PersistenceMappingResult<com.velumtegra.xuimobile.core.domain.VersionedRecord<WebPanelAccess>>.mapValue(): PersistenceMappingResult<WebPanelAccess> =
    when (this) {
        is PersistenceMappingResult.Success -> PersistenceMappingResult.Success(value.value)
        is PersistenceMappingResult.Corruption -> this
    }
