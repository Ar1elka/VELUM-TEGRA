package com.velumtegra.xuimobile.core.data.repository

import androidx.room3.withWriteTransaction
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretReferenceRepository
import com.velumtegra.xuimobile.core.model.SecretId

/**
 * Complete v1 durable SecretId reference scan.
 *
 * The two schema columns are read inside one Room transaction so GC receives one coherent durable graph.
 * Any DB failure is converted to an explicit RepositoryResult failure; partial sets are never returned.
 */
class RoomSecretReferenceRepository(
    private val database: VelumDatabase,
) : SecretReferenceRepository {
    override suspend fun listReferencedSecretIds(): RepositoryResult<Set<SecretId>> = repositoryDbCall {
        database.withWriteTransaction {
            val ids = linkedSetOf<SecretId>()
            database.serverAccessDao().listSecretIds().forEach { ids += SecretId(it) }
            database.webPanelAccessDao().listPasswordSecretIds().forEach { ids += SecretId(it) }
            RepositoryResult.Success(ids)
        }
    }
}
