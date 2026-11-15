package com.velumtegra.xuimobile.core.data.db.dao

import androidx.room3.ColumnInfo
import androidx.room3.Dao
import androidx.room3.Insert
import androidx.room3.OnConflictStrategy
import androidx.room3.Query
import com.velumtegra.xuimobile.core.data.db.OperationJournalEntity
import com.velumtegra.xuimobile.core.data.db.OperationSnapshotEntity

data class OperationJournalStatsRow(
    @ColumnInfo(name = "entry_count")
    val entryCount: Long,
    @ColumnInfo(name = "min_revision")
    val minRevision: Long?,
    @ColumnInfo(name = "max_revision")
    val maxRevision: Long?,
)

@Dao
interface OperationDao {
    @Query("SELECT * FROM operation_snapshots WHERE operation_id = :operationId LIMIT 1")
    suspend fun get(operationId: String): OperationSnapshotEntity?

    @Query(
        """
        SELECT * FROM operation_snapshots
        WHERE status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
        ORDER BY started_at_epoch_second, started_at_nano, operation_id
        """,
    )
    suspend fun listNonTerminal(): List<OperationSnapshotEntity>

    @Query(
        """
        SELECT * FROM operation_snapshots
        WHERE server_id = :serverId AND installation_id = :installationId
          AND target_kind = 'INSTALLATION'
          AND operation_type IN ('QUICK_INSPECT', 'DEEP_DIAGNOSTIC')
        ORDER BY started_at_epoch_second DESC, started_at_nano DESC, operation_id ASC
        LIMIT 51
        """,
    )
    suspend fun recentInspections(serverId: String, installationId: String): List<OperationSnapshotEntity>

    @Query(
        """
        SELECT * FROM operation_snapshots
        WHERE server_id = :serverId AND installation_id = :installationId AND server_access_id = :accessId
          AND target_kind = 'INSTALLATION' AND operation_type = 'INSTALLATION_BACKUP'
          AND status = 'SUCCEEDED' AND checkpoint_semantics = 'TERMINAL'
          AND substr(checkpoint_phase_name, 1, 14) = 'IBB1_VERIFIED:'
        ORDER BY started_at_epoch_second DESC, started_at_nano DESC, operation_id ASC
        LIMIT 10
        """,
    )
    suspend fun recentVerifiedInstallationBackups(serverId: String, installationId: String, accessId: String): List<OperationSnapshotEntity>

    @Query(
        """
        SELECT * FROM operation_snapshots
        WHERE server_id = :serverId AND installation_id = :installationId AND server_access_id = :accessId
          AND target_kind = 'INSTALLATION' AND operation_type = 'INSTALLATION_RESTORE_CHECK'
          AND status = 'SUCCEEDED' AND checkpoint_semantics = 'TERMINAL'
          AND substr(checkpoint_phase_name, 1, length(:phasePrefix)) = :phasePrefix
        ORDER BY updated_at_epoch_second DESC, updated_at_nano DESC, operation_id ASC
        LIMIT 5
        """,
    )
    suspend fun recentVerifiedRestoreChecks(serverId: String, installationId: String, accessId: String, phasePrefix: String): List<OperationSnapshotEntity>

    @Query(
        """
        SELECT * FROM operation_snapshots
        WHERE status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
          AND (
              updated_at_epoch_second < :cutoffEpochSecond OR
              (updated_at_epoch_second = :cutoffEpochSecond AND updated_at_nano < :cutoffNano)
          )
        ORDER BY updated_at_epoch_second, updated_at_nano, operation_id
        LIMIT :limit
        """,
    )
    suspend fun listTerminalBefore(
        cutoffEpochSecond: Long,
        cutoffNano: Int,
        limit: Int,
    ): List<OperationSnapshotEntity>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertSnapshot(entity: OperationSnapshotEntity): Long

    @Query(
        """
        UPDATE operation_snapshots
        SET status = :status,
            checkpoint_phase_name = :checkpointPhaseName,
            checkpoint_semantics = :checkpointSemantics,
            checkpoint_epoch_second = :checkpointEpochSecond,
            checkpoint_nano = :checkpointNano,
            updated_at_epoch_second = :updatedAtEpochSecond,
            updated_at_nano = :updatedAtNano,
            revision = :nextRevision
        WHERE operation_id = :operationId AND revision = :expectedRevision
        """,
    )
    suspend fun advanceSnapshotCas(
        operationId: String,
        status: String,
        checkpointPhaseName: String,
        checkpointSemantics: String,
        checkpointEpochSecond: Long,
        checkpointNano: Int,
        updatedAtEpochSecond: Long,
        updatedAtNano: Int,
        expectedRevision: Long,
        nextRevision: Long,
    ): Int

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertJournal(entity: OperationJournalEntity)

    @Query("SELECT * FROM operation_journal WHERE operation_id = :operationId ORDER BY revision")
    suspend fun history(operationId: String): List<OperationJournalEntity>

    @Query(
        """
        SELECT COUNT(*) AS entry_count,
               MIN(revision) AS min_revision,
               MAX(revision) AS max_revision
        FROM operation_journal
        WHERE operation_id = :operationId
        """,
    )
    suspend fun journalStats(operationId: String): OperationJournalStatsRow

    @Query(
        """
        SELECT * FROM operation_journal
        WHERE operation_id = :operationId
        ORDER BY revision DESC
        LIMIT 1
        """,
    )
    suspend fun latestJournal(operationId: String): OperationJournalEntity?

    @Query("DELETE FROM operation_journal WHERE operation_id = :operationId")
    suspend fun deleteJournalForOperation(operationId: String): Int

    @Query(
        """
        DELETE FROM operation_snapshots
        WHERE operation_id = :operationId
          AND revision = :expectedRevision
          AND status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
          AND checkpoint_semantics = 'TERMINAL'
        """,
    )
    suspend fun deleteTerminalSnapshotCas(
        operationId: String,
        expectedRevision: Long,
    ): Int
}
