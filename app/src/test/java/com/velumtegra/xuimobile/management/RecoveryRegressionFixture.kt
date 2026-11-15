package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant

internal object RecoveryRegressionFixture {
    val at: Instant = Instant.parse("2026-11-15T00:00:00Z")
    val server = ServerId("server")
    val access = ServerAccess(ServerAccessId("ssh"), server, SshEndpoint("fixture.invalid", 22), "root",
        SshAuthRef.Password(SecretId("fixture-ref")), HostKeyFingerprint("SHA256:fixture"))
    val installation = XuiInstallation(XuiInstallationId("install"), server, InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", "127.0.0.1", at.minusSeconds(60)))
    val review = ManagementRestartReview("VPS", installation, access)
    val local = ManagementRestartLocalPort { _, _, _ -> ManagementRestartLocalReview.Ready(review) }
    private val target = OperationTarget.InstallationTarget(server, access.id, installation.id)
    fun snapshot(id: String, type: OperationType, phase: String, revision: Long = 1,
        status: OperationStatus = OperationStatus.SUCCEEDED, semantics: CheckpointSemantics = CheckpointSemantics.TERMINAL) =
        VersionedOperationSnapshot(OperationSnapshot(OperationId(id), type, target, status,
            OperationCheckpoint(phase, semantics, at), at, at), OperationRevision(revision))
    val backup = snapshot("backup", OperationType.INSTALLATION_BACKUP,
        InstallationBackupBindingPolicy.bind(OperationId("backup"), installation, access, "3.11.0", UpdateServerArchitecture.AMD64).phaseName(InstallationBackupPhase.VERIFIED))
    val checkBinding = RestoreCheckBindingPolicy.bind(OperationId("check"), installation, access, backup,
        "b".repeat(64), "c".repeat(64), "d".repeat(64), 4096, 3)
    val check = snapshot("check", OperationType.INSTALLATION_RESTORE_CHECK, checkBinding.phaseName(RestoreCheckPhase.VERIFIED))
    val comparisonBinding = RestoreCompatibilityBindingPolicy.bind(OperationId("comparison"), installation, access, check, backup)
    val comparison = snapshot("comparison", OperationType.RESTORE_COMPATIBILITY, comparisonBinding.phaseName(RestoreCompatibilityPhase.OBSERVED))
    val restoreBinding = WorkingDatabaseRestoreBindingPolicy.bind(OperationId("restore"), installation, access, comparison, check, backup)
    val restore = snapshot("restore", OperationType.WORKING_DATABASE_RESTORE, restoreBinding.phaseName(WorkingDatabaseRestorePhase.VERIFIED))
    val report = RestoreCompatibilityReport(ManagementScope(comparison.snapshot.operationId, server, access.id, installation.id),
        comparisonBinding, "3.11.0", UpdateServerArchitecture.AMD64, "e".repeat(64), "e".repeat(64),
        RestoreFileSetComparison.MATCH, 0, 1, 1, ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, at)
}
