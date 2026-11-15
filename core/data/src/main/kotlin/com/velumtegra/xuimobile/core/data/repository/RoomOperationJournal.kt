package com.velumtegra.xuimobile.core.data.repository

import androidx.room3.withWriteTransaction
import com.velumtegra.xuimobile.core.data.db.OperationSnapshotEntity
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.mapping.PersistenceMappingResult
import com.velumtegra.xuimobile.core.data.mapping.toDomain
import com.velumtegra.xuimobile.core.data.mapping.toEntity
import com.velumtegra.xuimobile.core.domain.OperationDurabilityPolicy
import com.velumtegra.xuimobile.core.domain.OperationDurabilityValidation
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.InstallationBackupArchiveInventory
import com.velumtegra.xuimobile.core.domain.InstallationInspectionInventory
import com.velumtegra.xuimobile.core.domain.RestoreCheckResultInventory
import com.velumtegra.xuimobile.core.domain.OperationJournalContractPolicy
import com.velumtegra.xuimobile.core.domain.OperationJournalEntry
import com.velumtegra.xuimobile.core.domain.OperationJournalEvidence
import com.velumtegra.xuimobile.core.domain.OperationJournalMaintenance
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.OperationSnapshotValidation
import com.velumtegra.xuimobile.core.domain.TerminalOperationRetentionReport
import com.velumtegra.xuimobile.core.domain.TerminalOperationRetentionRequest
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallationId

class RoomOperationJournal(
    private val database: VelumDatabase,
) : OperationJournal, OperationJournalMaintenance, InstallationInspectionInventory, InstallationBackupArchiveInventory,
    RestoreCheckResultInventory {
    private val dao get() = database.operationDao()

    override suspend fun create(
        initial: OperationSnapshot,
    ): OperationJournalResult<VersionedOperationSnapshot> = operationDbCall {
        when (val validation = OperationJournalContractPolicy.validateInitial(initial)) {
            OperationSnapshotValidation.Valid -> Unit
            is OperationSnapshotValidation.Invalid -> return@operationDbCall OperationJournalResult.InvalidTransition(
                validation.reason,
            )
        }

        database.withWriteTransaction<OperationJournalResult<VersionedOperationSnapshot>> {
            if (dao.get(initial.operationId.value) != null) {
                return@withWriteTransaction OperationJournalResult.AlreadyExists
            }
            val targetValidation = validateTargetExists(initial.target)
            if (targetValidation != null) {
                return@withWriteTransaction OperationJournalResult.InvalidTransition(targetValidation)
            }

            val revision = OperationRevision(0)
            val versioned = VersionedOperationSnapshot(initial, revision)
            val snapshotInserted = dao.insertSnapshot(initial.toEntity(revision))
            if (snapshotInserted == -1L) {
                return@withWriteTransaction OperationJournalResult.AlreadyExists
            }

            dao.insertJournal(
                OperationJournalEntry(
                    operationId = initial.operationId,
                    revision = revision,
                    status = initial.status,
                    checkpoint = initial.checkpoint,
                    recordedAt = initial.updatedAt,
                ).toEntity(),
            )
            OperationJournalResult.Success(versioned)
        }
    }

    /**
     * A reopen/read never trusts the snapshot row alone. Snapshot + journal evidence are read under one
     * Room transaction and must prove one contiguous durable operation before the snapshot is returned.
     */
    override suspend fun get(
        operationId: OperationId,
    ): OperationJournalResult<VersionedOperationSnapshot> = operationDbCall {
        database.withWriteTransaction<OperationJournalResult<VersionedOperationSnapshot>> {
            val entity = dao.get(operationId.value) ?: return@withWriteTransaction OperationJournalResult.NotFound
            validateDurableEntity(entity).toOperationResult()
        }
    }

    override suspend fun listNonTerminal(): OperationJournalResult<List<VersionedOperationSnapshot>> = operationDbCall {
        database.withWriteTransaction<OperationJournalResult<List<VersionedOperationSnapshot>>> {
            val values = ArrayList<VersionedOperationSnapshot>()
            for (entity in dao.listNonTerminal()) {
                when (val validated = validateDurableEntity(entity)) {
                    is DurableEntityValidation.Valid -> values += validated.current
                    is DurableEntityValidation.Corrupt -> return@withWriteTransaction OperationJournalResult.Corruption(
                        validated.reason,
                    )
                }
            }
            OperationJournalResult.Success(values)
        }
    }

    /** Bounded read under the same consistent snapshot/evidence transaction as get(). */
    override suspend fun recentInspections(
        serverId: ServerId,
        installationId: XuiInstallationId,
    ): OperationJournalResult<List<VersionedOperationSnapshot>> = operationDbCall {
        database.withWriteTransaction<OperationJournalResult<List<VersionedOperationSnapshot>>> {
            val values = ArrayList<VersionedOperationSnapshot>()
            for (entity in dao.recentInspections(serverId.value, installationId.value)) {
                val current = when (val validated = validateDurableEntity(entity)) {
                    is DurableEntityValidation.Valid -> validated.current
                    is DurableEntityValidation.Corrupt -> return@withWriteTransaction OperationJournalResult.Corruption(
                        validated.reason,
                    )
                }
                val target = current.snapshot.target as? OperationTarget.InstallationTarget
                if (target == null || target.serverId != serverId || target.installationId != installationId ||
                    current.snapshot.type !in setOf(OperationType.QUICK_INSPECT, OperationType.DEEP_DIAGNOSTIC)) {
                    return@withWriteTransaction OperationJournalResult.Corruption("Inspection inventory scope mismatch")
                }
                values += current
            }
            OperationJournalResult.Success(values)
        }
    }

    /** Bounded read of verified installation archives for one exact access, validated like get(). */
    override suspend fun recentVerifiedArchives(
        serverId: ServerId,
        installationId: XuiInstallationId,
        accessId: ServerAccessId,
    ): OperationJournalResult<List<VersionedOperationSnapshot>> = operationDbCall {
        database.withWriteTransaction<OperationJournalResult<List<VersionedOperationSnapshot>>> {
            val values = ArrayList<VersionedOperationSnapshot>()
            for (entity in dao.recentVerifiedInstallationBackups(serverId.value, installationId.value, accessId.value)) {
                val current = when (val validated = validateDurableEntity(entity)) {
                    is DurableEntityValidation.Valid -> validated.current
                    is DurableEntityValidation.Corrupt -> return@withWriteTransaction OperationJournalResult.Corruption(
                        validated.reason,
                    )
                }
                val target = current.snapshot.target as? OperationTarget.InstallationTarget
                if (target == null || target.serverId != serverId || target.installationId != installationId ||
                    target.serverAccessId != accessId || current.snapshot.type != OperationType.INSTALLATION_BACKUP) {
                    return@withWriteTransaction OperationJournalResult.Corruption("Backup archive inventory scope mismatch")
                }
                values += current
            }
            OperationJournalResult.Success(values)
        }
    }

    /** Bounded read of verified restore checks for one exact parent prefix, validated like get(). */
    override suspend fun recentVerifiedRestoreChecks(
        serverId: ServerId,
        installationId: XuiInstallationId,
        accessId: ServerAccessId,
        phasePrefix: String,
    ): OperationJournalResult<List<VersionedOperationSnapshot>> = operationDbCall {
        database.withWriteTransaction<OperationJournalResult<List<VersionedOperationSnapshot>>> {
            val values = ArrayList<VersionedOperationSnapshot>()
            for (entity in dao.recentVerifiedRestoreChecks(serverId.value, installationId.value, accessId.value, phasePrefix)) {
                val current = when (val validated = validateDurableEntity(entity)) {
                    is DurableEntityValidation.Valid -> validated.current
                    is DurableEntityValidation.Corrupt -> return@withWriteTransaction OperationJournalResult.Corruption(
                        validated.reason,
                    )
                }
                val target = current.snapshot.target as? OperationTarget.InstallationTarget
                if (target == null || target.serverId != serverId || target.installationId != installationId ||
                    target.serverAccessId != accessId || current.snapshot.type != OperationType.INSTALLATION_RESTORE_CHECK) {
                    return@withWriteTransaction OperationJournalResult.Corruption("Restore check inventory scope mismatch")
                }
                values += current
            }
            OperationJournalResult.Success(values)
        }
    }

    override suspend fun advance(
        operationId: OperationId,
        expectedRevision: OperationRevision,
        next: OperationSnapshot,
    ): OperationJournalResult<VersionedOperationSnapshot> = operationDbCall {
        database.withWriteTransaction<OperationJournalResult<VersionedOperationSnapshot>> {
            val currentEntity = dao.get(operationId.value) ?: return@withWriteTransaction OperationJournalResult.NotFound
            val durableCurrent = when (val validated = validateDurableEntity(currentEntity)) {
                is DurableEntityValidation.Valid -> validated.current
                is DurableEntityValidation.Corrupt -> return@withWriteTransaction OperationJournalResult.Corruption(
                    validated.reason,
                )
            }
            if (durableCurrent.revision != expectedRevision) {
                return@withWriteTransaction OperationJournalResult.StaleRevision(expectedRevision, durableCurrent.revision)
            }
            when (val validation = OperationJournalContractPolicy.validateAdvance(durableCurrent.snapshot, next)) {
                OperationSnapshotValidation.Valid -> Unit
                is OperationSnapshotValidation.Invalid -> return@withWriteTransaction OperationJournalResult.InvalidTransition(
                    validation.reason,
                )
            }
            val nextRevision = when (val result = expectedRevision.nextRevision()) {
                is RevisionAdvance.Success -> result.value
                RevisionAdvance.Exhausted -> return@withWriteTransaction OperationJournalResult.StorageFailure(
                    "Operation revision exhausted",
                )
            }
            val nextEntity = next.toEntity(nextRevision)
            val changed = dao.advanceSnapshotCas(
                operationId = operationId.value,
                status = nextEntity.status,
                checkpointPhaseName = nextEntity.checkpointPhaseName,
                checkpointSemantics = nextEntity.checkpointSemantics,
                checkpointEpochSecond = nextEntity.checkpointEpochSecond,
                checkpointNano = nextEntity.checkpointNano,
                updatedAtEpochSecond = nextEntity.updatedAtEpochSecond,
                updatedAtNano = nextEntity.updatedAtNano,
                expectedRevision = expectedRevision.value,
                nextRevision = nextRevision.value,
            )
            if (changed != 1) {
                val actual = dao.get(operationId.value)
                return@withWriteTransaction if (actual == null) {
                    OperationJournalResult.NotFound
                } else {
                    OperationJournalResult.StaleRevision(
                        expectedRevision,
                        OperationRevision(actual.revision),
                    )
                }
            }

            // Deliberately after CAS but inside the same Room write transaction.
            // Any exception here rolls the snapshot update back.
            dao.insertJournal(
                OperationJournalEntry(
                    operationId = operationId,
                    revision = nextRevision,
                    status = next.status,
                    checkpoint = next.checkpoint,
                    recordedAt = next.updatedAt,
                ).toEntity(),
            )
            OperationJournalResult.Success(VersionedOperationSnapshot(next, nextRevision))
        }
    }

    override suspend fun history(
        operationId: OperationId,
    ): OperationJournalResult<List<OperationJournalEntry>> = operationDbCall {
        database.withWriteTransaction<OperationJournalResult<List<OperationJournalEntry>>> {
            val entity = dao.get(operationId.value) ?: return@withWriteTransaction OperationJournalResult.NotFound
            val current = when (val mapped = entity.toDomain()) {
                is PersistenceMappingResult.Success -> mapped.value
                is PersistenceMappingResult.Corruption -> return@withWriteTransaction OperationJournalResult.Corruption(mapped.reason)
            }
            val values = ArrayList<OperationJournalEntry>()
            for (journalEntity in dao.history(operationId.value)) {
                when (val mapped = journalEntity.toDomain()) {
                    is PersistenceMappingResult.Success -> values += mapped.value
                    is PersistenceMappingResult.Corruption -> return@withWriteTransaction OperationJournalResult.Corruption(mapped.reason)
                }
            }
            when (val validation = OperationDurabilityPolicy.validateHistory(current, values)) {
                OperationDurabilityValidation.Valid -> OperationJournalResult.Success(values)
                is OperationDurabilityValidation.Corrupt -> OperationJournalResult.Corruption(validation.reason)
            }
        }
    }

    /**
     * Retention removes complete terminal operations only. It never prunes a non-terminal checkpoint history
     * and never directly deletes ServerAccess, Installation, or SecretStore payloads.
     */
    override suspend fun pruneTerminalOperations(
        request: TerminalOperationRetentionRequest,
    ): OperationJournalResult<TerminalOperationRetentionReport> = operationDbCall {
        database.withWriteTransaction<OperationJournalResult<TerminalOperationRetentionReport>> {
            val candidates = dao.listTerminalBefore(
                cutoffEpochSecond = request.updatedBefore.epochSecond,
                cutoffNano = request.updatedBefore.nano,
                limit = request.batchSize.value,
            )
            if (candidates.isEmpty()) {
                return@withWriteTransaction OperationJournalResult.Success(TerminalOperationRetentionReport(emptyList()))
            }

            // Validate the entire batch before the first destructive statement. A corrupt candidate blocks the pass.
            val validated = ArrayList<ValidatedTerminalCandidate>(candidates.size)
            for (entity in candidates) {
                val durable = when (val result = validateDurableEntity(entity)) {
                    is DurableEntityValidation.Valid -> result
                    is DurableEntityValidation.Corrupt -> return@withWriteTransaction OperationJournalResult.Corruption(
                        result.reason,
                    )
                }
                val snapshot = durable.current.snapshot
                if (snapshot.status !in TERMINAL_STATUSES || snapshot.checkpoint.semantics != CheckpointSemantics.TERMINAL) {
                    return@withWriteTransaction OperationJournalResult.Corruption(
                        "Terminal retention candidate is not coherently terminal",
                    )
                }
                if (!snapshot.updatedAt.isBefore(request.updatedBefore)) {
                    return@withWriteTransaction OperationJournalResult.Corruption(
                        "Terminal retention candidate violates the requested cutoff",
                    )
                }
                if (durable.entryCount > Int.MAX_VALUE.toLong()) {
                    return@withWriteTransaction OperationJournalResult.StorageFailure(
                        "Terminal operation history is too large to prune safely",
                    )
                }
                validated += ValidatedTerminalCandidate(durable.current, durable.entryCount)
            }

            val prunedIds = ArrayList<OperationId>(validated.size)
            for (candidate in validated) {
                val operationId = candidate.current.snapshot.operationId
                val deletedHistory = dao.deleteJournalForOperation(operationId.value)
                if (deletedHistory.toLong() != candidate.entryCount) {
                    // Throw instead of returning: Room must roll back any journal deletions already made in this batch.
                    error("Terminal retention journal delete count changed inside locked transaction")
                }
                val deletedSnapshot = dao.deleteTerminalSnapshotCas(
                    operationId = operationId.value,
                    expectedRevision = candidate.current.revision.value,
                )
                if (deletedSnapshot != 1) {
                    // Throw so the journal deletion above is rolled back too.
                    error("Terminal retention snapshot CAS lost its locked terminal row")
                }
                prunedIds += operationId
            }
            OperationJournalResult.Success(TerminalOperationRetentionReport(prunedIds))
        }
    }

    private suspend fun validateDurableEntity(entity: OperationSnapshotEntity): DurableEntityValidation {
        val current = when (val mapped = entity.toDomain()) {
            is PersistenceMappingResult.Success -> mapped.value
            is PersistenceMappingResult.Corruption -> return DurableEntityValidation.Corrupt(mapped.reason)
        }
        val stats = dao.journalStats(entity.operationId)
        val latest = dao.latestJournal(entity.operationId)?.let { latestEntity ->
            when (val mapped = latestEntity.toDomain()) {
                is PersistenceMappingResult.Success -> mapped.value
                is PersistenceMappingResult.Corruption -> return DurableEntityValidation.Corrupt(mapped.reason)
            }
        }
        val evidence = OperationJournalEvidence(
            entryCount = stats.entryCount,
            minRevision = stats.minRevision,
            maxRevision = stats.maxRevision,
            latestEntry = latest,
        )
        return when (val validation = OperationDurabilityPolicy.validateEvidence(current, evidence)) {
            OperationDurabilityValidation.Valid -> DurableEntityValidation.Valid(current, stats.entryCount)
            is OperationDurabilityValidation.Corrupt -> DurableEntityValidation.Corrupt(validation.reason)
        }
    }

    /** Returns an error message or null when exact persisted parents prove the target relation. */
    private suspend fun validateTargetExists(target: OperationTarget): String? {
        if (database.serverDao().get(target.serverId.value) == null) {
            return "Operation target Server does not exist"
        }
        val accessServer = database.serverAccessDao().serverIdFor(target.serverAccessId.value)
            ?: return "Operation target ServerAccess does not exist"
        if (accessServer != target.serverId.value) {
            return "Operation ServerAccess belongs to a different Server"
        }
        if (target is OperationTarget.InstallationTarget) {
            val installationServer = database.installationDao().serverIdFor(target.installationId.value)
                ?: return "Operation target installation does not exist"
            if (installationServer != target.serverId.value) {
                return "Operation installation belongs to a different Server"
            }
        }
        return null
    }

    private sealed interface DurableEntityValidation {
        data class Valid(
            val current: VersionedOperationSnapshot,
            val entryCount: Long,
        ) : DurableEntityValidation

        data class Corrupt(val reason: String) : DurableEntityValidation
    }

    private data class ValidatedTerminalCandidate(
        val current: VersionedOperationSnapshot,
        val entryCount: Long,
    )

    private fun DurableEntityValidation.toOperationResult(): OperationJournalResult<VersionedOperationSnapshot> = when (this) {
        is DurableEntityValidation.Valid -> OperationJournalResult.Success(current)
        is DurableEntityValidation.Corrupt -> OperationJournalResult.Corruption(reason)
    }

    private companion object {
        val TERMINAL_STATUSES = setOf(
            OperationStatus.SUCCEEDED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        )
    }
}
