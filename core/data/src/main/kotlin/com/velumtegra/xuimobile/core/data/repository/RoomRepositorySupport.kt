package com.velumtegra.xuimobile.core.data.repository

import android.database.SQLException
import android.database.sqlite.SQLiteConstraintException
import android.database.sqlite.SQLiteDatabaseCorruptException
import com.velumtegra.xuimobile.core.data.mapping.PersistenceMappingResult
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult

internal suspend fun <T> repositoryDbCall(
    block: suspend () -> RepositoryResult<T>,
): RepositoryResult<T> = try {
    block()
} catch (error: SQLiteConstraintException) {
    RepositoryResult.ConstraintConflict(error.message ?: "SQLite constraint rejected the write")
} catch (error: SQLiteDatabaseCorruptException) {
    RepositoryResult.Corruption(error.message ?: "SQLite database is corrupt")
} catch (error: SQLException) {
    RepositoryResult.StorageFailure(error.message ?: "SQLite storage failure")
} catch (error: IllegalArgumentException) {
    RepositoryResult.Corruption(error.message ?: "Persisted data violates domain invariants")
} catch (error: IllegalStateException) {
    RepositoryResult.StorageFailure(error.message ?: "Database is unavailable")
}

internal suspend fun <T> operationDbCall(
    block: suspend () -> OperationJournalResult<T>,
): OperationJournalResult<T> = try {
    block()
} catch (error: SQLiteConstraintException) {
    OperationJournalResult.Corruption(error.message ?: "Operation journal constraint was violated")
} catch (error: SQLiteDatabaseCorruptException) {
    OperationJournalResult.Corruption(error.message ?: "SQLite database is corrupt")
} catch (error: SQLException) {
    OperationJournalResult.StorageFailure(error.message ?: "SQLite storage failure")
} catch (error: IllegalArgumentException) {
    OperationJournalResult.Corruption(error.message ?: "Persisted operation violates domain invariants")
} catch (error: IllegalStateException) {
    OperationJournalResult.StorageFailure(error.message ?: "Database is unavailable")
}

internal fun <T> PersistenceMappingResult<T>.asRepositoryResult(): RepositoryResult<T> = when (this) {
    is PersistenceMappingResult.Success -> RepositoryResult.Success(value)
    is PersistenceMappingResult.Corruption -> RepositoryResult.Corruption(reason)
}

internal fun <T> PersistenceMappingResult<T>.asOperationResult(): OperationJournalResult<T> = when (this) {
    is PersistenceMappingResult.Success -> OperationJournalResult.Success(value)
    is PersistenceMappingResult.Corruption -> OperationJournalResult.Corruption(reason)
}
