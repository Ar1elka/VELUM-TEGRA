package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class InstallationBackupPolicyTest {
    private val at = Instant.parse("2026-10-17T01:00:00Z")
    private val id = OperationId("copy")
    private val install = XuiInstallation(XuiInstallationId("install"), ServerId("server"), InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", null, at))
    private val access = ServerAccess(ServerAccessId("ssh"), install.serverId, SshEndpoint("fixture.invalid", 22), "root",
        SshAuthRef.Password(SecretId("ref")), HostKeyFingerprint("SHA256:fixture"))
    private val binding = InstallationBackupBindingPolicy.bind(id, install, access, "3.10.0", UpdateServerArchitecture.AMD64)
    private val target = OperationTarget.InstallationTarget(install.serverId, access.id, install.id)
    private val scope = ManagementScope(id, install.serverId, access.id, install.id)
    private val initial = VersionedOperationSnapshot(OperationSnapshot(id, OperationType.INSTALLATION_BACKUP, target, OperationStatus.RUNNING,
        OperationCheckpoint(binding.phaseName(InstallationBackupPhase.PENDING), CheckpointSemantics.MUTATION_NOT_STARTED, at), at, at), OperationRevision(0))
    private fun report() = UpdatePreflightSnapshot(scope, UpdateRootStatus.DIRECT_ROOT, UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD,
        DeepDiagnosticServiceDefinitionStatus.CONSISTENT, "3.10.0", ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, at,
        UpdateServerArchitecture.AMD64, UpdateRecoverySourceSnapshot(scope, UpdateRecoveryTool.values().associateWith { UpdateRecoveryToolState.AVAILABLE },
            UpdateRecoveryDatabaseState.PRIVATE_REGULAR, 4096, UpdateRecoveryRuntimeState.STANDARD_FILES_PRESENT,
            DeepDiagnosticDatabaseIntegrityStatus.OK, DeepDiagnosticDatabaseSchemaStatus.SUPPORTED, UpdateRecoveryPanelTlsState.NOT_CONFIGURED, at), known(scope))
    private fun known(scope: ManagementScope) = RecoveryFileInventory(scope,
        RecoveryFileGroup.values().associateWith { group -> when(group) {
            RecoveryFileGroup.RUNTIME -> RecoveryFileGroupObservation(2, 8192)
            RecoveryFileGroup.SERVICE -> RecoveryFileGroupObservation(1, 4096)
            else -> RecoveryFileGroupObservation(0, 0)
        } }, 3, 12288, emptySet(), "c".repeat(64), at, "e".repeat(64))
    private fun space() = InstallationBackupStorageObservation(scope, true, true, 0, 512L * 1024 * 1024, at)
    private fun confirmation() = requireNotNull(InstallationBackupConfirmationPolicy.confirm(initial, install, access, report(), at))
    private fun authorize(current: VersionedOperationSnapshot = initial, fresh: UpdatePreflightSnapshot = report(),
        storage: InstallationBackupStorageObservation = space(), now: Instant = at) =
        InstallationBackupDispatchPolicy.authorize(confirmation(), current, fresh, storage, now)

    @Test fun missingStaleUnsafeOrForeignFileInventoryCannotAuthorizeArchive() {
        val source = report()
        assertNull(authorize(fresh = source.copy(recoveryFiles = null)))
        assertNull(authorize(fresh = source.copy(recoveryFiles = known(scope).copy(sourceSetDigest = null))))
        assertNull(authorize(fresh = source.copy(recoveryFiles = known(scope).copy(sourceSetDigest = "f".repeat(64)))))
        assertNull(authorize(fresh = source.copy(recoveryFiles = known(scope).copy(observedAt = at.minusSeconds(301)))))
        assertThrows(IllegalArgumentException::class.java) {
            source.copy(recoveryFiles = known(scope).copy(scope = scope.copy(installationId = XuiInstallationId("foreign"))))
        }
        assertNull(authorize(fresh = source.copy(recoveryFiles = known(scope).copy(issues = setOf(RecoveryFileIssue.UNKNOWN_REFERENCE), knownSetDigest = null, sourceSetDigest = null))))
    }
    @Test fun databaseOnlyBindingOrOldTypeCannotBeUsedForInstallationArchive() {
        val old = DatabaseBackupBindingPolicy.bind(id, install, access, "3.10.0", UpdateServerArchitecture.AMD64)
        assertNotEquals(old.digest, binding.digest)
        assertNull(InstallationBackupBinding.parse(old.phaseName(DatabaseBackupPhase.PENDING)))
        assertFalse(InstallationBackupBindingPolicy.matches(initial.copy(snapshot = initial.snapshot.copy(type = OperationType.DATABASE_BACKUP)), install, access))
    }
    @Test fun bindingRoundTripsAllPhasesWithoutRawEndpointOrSecretReference() {
        InstallationBackupPhase.values().forEach { assertEquals(it to binding, InstallationBackupBinding.parse(binding.phaseName(it))) }
        assertFalse(binding.phaseName(InstallationBackupPhase.PENDING).contains("fixture.invalid"))
        assertFalse(binding.phaseName(InstallationBackupPhase.PENDING).contains("ref"))
        assertEquals(32, binding.artifactId.length)
    }
    @Test fun everyExactAccessChangeInvalidatesBindingEvenWithSameAccessId() {
        listOf(access.copy(endpoint = SshEndpoint("changed.invalid", 22)), access.copy(username = "other"),
            access.copy(auth = SshAuthRef.Password(SecretId("changed"))),
            access.copy(pinnedHostKey = HostKeyFingerprint("SHA256:changed"))).forEach {
            assertFalse(InstallationBackupBindingPolicy.matches(initial, install, it))
        }
    }
    @Test fun installationBaselineOrOperationChangeCannotReuseBinding() {
        assertFalse(InstallationBackupBindingPolicy.matches(initial, install.copy(baseline = install.baseline.copy(panelPort = 9999)), access))
        assertFalse(InstallationBackupBindingPolicy.matches(initial.copy(snapshot = initial.snapshot.copy(operationId = OperationId("other"))), install, access))
    }
    @Test fun malformedOrInjectedDurableBindingIsNeverACommandPath() {
        listOf("IBB1_PENDING:AMD64:3.10.0:../../oops", binding.phaseName(InstallationBackupPhase.PENDING) + ":extra",
            "IBB1_PENDING:FOREIGN:3.10.0:" + "a".repeat(64)).forEach { assertNull(InstallationBackupBinding.parse(it)) }
    }
    @Test fun healthyFreshEvidenceAdmitsOnlyOneDispatch() {
        val permit = requireNotNull(authorize())
        assertEquals(scope, permit.scope)
        assertFalse(permit.consumeOnce(OperationRevision(0), at))
        assertTrue(permit.consumeOnce(OperationRevision(1), at))
        assertFalse(permit.consumeOnce(OperationRevision(1), at))
    }
    @Test fun expiredOrFutureConfirmationCannotAuthorize() {
        assertNull(authorize(now = at.plusSeconds(90)))
        assertNull(authorize(now = at.minusSeconds(1)))
        val late = requireNotNull(authorize())
        assertFalse(late.consumeOnce(OperationRevision(1), at.plusSeconds(90)))
        assertFalse(late.consumeOnce(OperationRevision(1), at.minusSeconds(1)))
    }
    @Test fun staleRevisionOrAlreadyDispatchedCheckpointCannotCreateNewAuthority() {
        assertNull(authorize(current = initial.copy(revision = OperationRevision(1))))
        assertNull(authorize(current = initial.copy(snapshot = initial.snapshot.copy(
            checkpoint = initial.snapshot.checkpoint.copy(semantics = CheckpointSemantics.MUTATION_IN_FLIGHT)))))
    }
    @Test fun foreignReadOnlyReportOrChangedServerVersionBlocksWrites() {
        val foreign = scope.copy(operationId = OperationId("other"))
        assertNull(authorize(fresh = report().copy(scope = foreign, recovery = report().recovery!!.copy(scope = foreign), recoveryFiles = known(foreign))))
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
        val source = report().copy(scope = oldScope, recovery = report().recovery!!.copy(scope = oldScope), recoveryFiles = known(oldScope))
        assertNotNull(InstallationBackupConfirmationPolicy.confirm(initial, install, access, source, at))
        assertNull(InstallationBackupConfirmationPolicy.confirm(initial, install, access, report().copy(root = UpdateRootStatus.NOT_ROOT), at))
    }
}
