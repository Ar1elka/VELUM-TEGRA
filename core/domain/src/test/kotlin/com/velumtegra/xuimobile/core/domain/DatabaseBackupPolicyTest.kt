package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class DatabaseBackupPolicyTest {
    private val at = Instant.parse("2026-10-17T01:00:00Z")
    private val id = OperationId("copy")
    private val install = XuiInstallation(XuiInstallationId("install"), ServerId("server"), InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", null, at))
    private val access = ServerAccess(ServerAccessId("ssh"), install.serverId, SshEndpoint("fixture.invalid", 22), "root",
        SshAuthRef.Password(SecretId("ref")), HostKeyFingerprint("SHA256:fixture"))
    private val binding = DatabaseBackupBindingPolicy.bind(id, install, access, "3.10.0", UpdateServerArchitecture.AMD64)
    private val target = OperationTarget.InstallationTarget(install.serverId, access.id, install.id)
    private val scope = ManagementScope(id, install.serverId, access.id, install.id)
    private val initial = VersionedOperationSnapshot(OperationSnapshot(id, OperationType.DATABASE_BACKUP, target, OperationStatus.RUNNING,
        OperationCheckpoint(binding.phaseName(DatabaseBackupPhase.PENDING), CheckpointSemantics.MUTATION_NOT_STARTED, at), at, at), OperationRevision(0))
    private fun report() = UpdatePreflightSnapshot(scope, UpdateRootStatus.DIRECT_ROOT, UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD,
        DeepDiagnosticServiceDefinitionStatus.CONSISTENT, "3.10.0", ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, at,
        UpdateServerArchitecture.AMD64, UpdateRecoverySourceSnapshot(scope, UpdateRecoveryTool.values().associateWith { UpdateRecoveryToolState.AVAILABLE },
            UpdateRecoveryDatabaseState.PRIVATE_REGULAR, 4096, UpdateRecoveryRuntimeState.STANDARD_FILES_PRESENT,
            DeepDiagnosticDatabaseIntegrityStatus.OK, DeepDiagnosticDatabaseSchemaStatus.SUPPORTED, UpdateRecoveryPanelTlsState.NOT_CONFIGURED, at))
    private fun space() = DatabaseBackupStorageObservation(scope, true, true, 0, 512L * 1024 * 1024, at)
    private fun confirmation() = requireNotNull(DatabaseBackupConfirmationPolicy.confirm(initial, install, access, report(), at))
    private fun authorize(current: VersionedOperationSnapshot = initial, fresh: UpdatePreflightSnapshot = report(),
        storage: DatabaseBackupStorageObservation = space(), now: Instant = at) =
        DatabaseBackupDispatchPolicy.authorize(confirmation(), current, fresh, storage, now)

    @Test fun bindingRoundTripsAllPhasesWithoutRawEndpointOrSecretReference() {
        DatabaseBackupPhase.values().forEach { assertEquals(it to binding, DatabaseBackupBinding.parse(binding.phaseName(it))) }
        assertFalse(binding.phaseName(DatabaseBackupPhase.PENDING).contains("fixture.invalid"))
        assertFalse(binding.phaseName(DatabaseBackupPhase.PENDING).contains("ref"))
        assertEquals(32, binding.artifactId.length)
    }
    @Test fun everyExactAccessChangeInvalidatesBindingEvenWithSameAccessId() {
        listOf(access.copy(endpoint = SshEndpoint("changed.invalid", 22)), access.copy(username = "other"),
            access.copy(auth = SshAuthRef.Password(SecretId("changed"))),
            access.copy(pinnedHostKey = HostKeyFingerprint("SHA256:changed"))).forEach {
            assertFalse(DatabaseBackupBindingPolicy.matches(initial, install, it))
        }
    }
    @Test fun installationBaselineOrOperationChangeCannotReuseBinding() {
        assertFalse(DatabaseBackupBindingPolicy.matches(initial, install.copy(baseline = install.baseline.copy(panelPort = 9999)), access))
        assertFalse(DatabaseBackupBindingPolicy.matches(initial.copy(snapshot = initial.snapshot.copy(operationId = OperationId("other"))), install, access))
    }
    @Test fun malformedOrInjectedDurableBindingIsNeverACommandPath() {
        listOf("DBB1_PENDING:AMD64:3.10.0:../../oops", binding.phaseName(DatabaseBackupPhase.PENDING) + ":extra",
            "DBB1_PENDING:FOREIGN:3.10.0:" + "a".repeat(64)).forEach { assertNull(DatabaseBackupBinding.parse(it)) }
    }
    @Test fun healthyFreshEvidenceAdmitsOnlyOneDispatch() {
        val permit = requireNotNull(authorize())
        assertEquals(scope, permit.scope)
        assertFalse(permit.consumeOnce(OperationRevision(0)))
        assertTrue(permit.consumeOnce(OperationRevision(1)))
        assertFalse(permit.consumeOnce(OperationRevision(1)))
    }
    @Test fun expiredOrFutureConfirmationCannotAuthorize() {
        assertNull(authorize(now = at.plusSeconds(90)))
        assertNull(authorize(now = at.minusSeconds(1)))
    }
    @Test fun staleRevisionOrAlreadyDispatchedCheckpointCannotCreateNewAuthority() {
        assertNull(authorize(current = initial.copy(revision = OperationRevision(1))))
        assertNull(authorize(current = initial.copy(snapshot = initial.snapshot.copy(
            checkpoint = initial.snapshot.checkpoint.copy(semantics = CheckpointSemantics.MUTATION_IN_FLIGHT)))))
    }
    @Test fun foreignReadOnlyReportOrChangedServerVersionBlocksWrites() {
        val foreign = scope.copy(operationId = OperationId("other"))
        assertNull(authorize(fresh = report().copy(scope = foreign, recovery = report().recovery!!.copy(scope = foreign))))
        assertNull(authorize(fresh = report().copy(currentVersion = "3.10.1")))
        assertNull(authorize(fresh = report().copy(architecture = UpdateServerArchitecture.ARM64)))
    }
    @Test fun capacityAndMissingBoundedToolsAreIndependentBlockers() {
        listOf(space().copy(slotsUsed = 4), space().copy(availableBytes = 1),
            space().copy(safePrivateRoot = false), space().copy(limitedToolsAvailable = false)).forEach { assertNull(authorize(storage = it)) }
    }
    @Test fun expiredStorageAndFailedIntegrityCannotBePromotedByFreshLocalStatus() {
        assertNull(authorize(storage = space().copy(observedAt = at.minusSeconds(31))))
        assertNull(authorize(fresh = report().copy(recovery = report().recovery!!.copy(integrity = DeepDiagnosticDatabaseIntegrityStatus.FAILED))))
    }
    @Test fun confirmationRequiresAnExactHealthySourceButNotAReusedSourceOperationId() {
        val oldScope = scope.copy(operationId = OperationId("preflight"))
        val source = report().copy(scope = oldScope, recovery = report().recovery!!.copy(scope = oldScope))
        assertNotNull(DatabaseBackupConfirmationPolicy.confirm(initial, install, access, source, at))
        assertNull(DatabaseBackupConfirmationPolicy.confirm(initial, install, access, report().copy(root = UpdateRootStatus.NOT_ROOT), at))
    }
}
