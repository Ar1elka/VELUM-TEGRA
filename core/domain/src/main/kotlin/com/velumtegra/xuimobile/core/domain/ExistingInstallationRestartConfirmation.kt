package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.time.Duration
import java.time.Instant

/** A process-local explicit UI confirmation. It permits preflight, never mutation by itself.
 * No credentials/session are retained; never serialize or rebuild this value from the journal. */
class ExistingInstallationRestartConfirmation internal constructor(
    val operationId: OperationId,
    val operationRevision: OperationRevision,
    val target: OperationTarget.InstallationTarget,
    val expectedInstallation: XuiInstallation,
    val expectedAccess: ServerAccess,
    val confirmedAt: Instant,
    val validUntil: Instant,
)
sealed interface ExistingInstallationRestartConfirmationResult {
    data class Confirmed(val confirmation: ExistingInstallationRestartConfirmation) : ExistingInstallationRestartConfirmationResult
    data object Rejected : ExistingInstallationRestartConfirmationResult
}
object ExistingInstallationRestartConfirmationPolicy {
    val VALIDITY: Duration = Duration.ofSeconds(90)
    fun confirm(current: VersionedOperationSnapshot, installation: XuiInstallation, access: ServerAccess,
        now: Instant): ExistingInstallationRestartConfirmationResult {
        val s = current.snapshot
        val t = s.target as? OperationTarget.InstallationTarget ?: return ExistingInstallationRestartConfirmationResult.Rejected
        if (s.type != OperationType.RESTART || s.status != OperationStatus.RUNNING ||
            s.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED || s.operationId.value.isBlank() ||
            t.serverId != installation.serverId || t.installationId != installation.id || t.serverAccessId != access.id ||
            access.serverId != installation.serverId || now.isBefore(s.updatedAt) || installation.identity.serviceUnit != "x-ui.service" ||
            installation.identity.serviceUnit != installation.baseline.serviceUnit ||
            installation.identity.binaryPath != installation.baseline.binaryPath || installation.identity.rootPath != installation.baseline.rootPath ||
            installation.identity.databasePath != installation.baseline.databasePath
        ) return ExistingInstallationRestartConfirmationResult.Rejected
        return ExistingInstallationRestartConfirmationResult.Confirmed(ExistingInstallationRestartConfirmation(
            s.operationId, current.revision, t, installation, access, now, now.plus(VALIDITY),
        ))
    }
}
