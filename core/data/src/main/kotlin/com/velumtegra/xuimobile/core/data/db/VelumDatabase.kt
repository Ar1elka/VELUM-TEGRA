package com.velumtegra.xuimobile.core.data.db

import androidx.room3.Database
import androidx.room3.RoomDatabase
import com.velumtegra.xuimobile.core.data.db.dao.ManagementAccessDao
import com.velumtegra.xuimobile.core.data.db.dao.OperationDao
import com.velumtegra.xuimobile.core.data.db.dao.ServerAccessDao
import com.velumtegra.xuimobile.core.data.db.dao.ServerDao
import com.velumtegra.xuimobile.core.data.db.dao.WebPanelAccessDao
import com.velumtegra.xuimobile.core.data.db.dao.XuiInstallationDao

/**
 * Phase 2 schema boundary. No destructive migration fallback is permitted by architecture.
 * Production opening is centralized in [VelumDatabaseFactory] so driver/migration policy cannot drift by caller.
 */
@Database(
    entities = [
        ServerEntity::class,
        ServerAccessEntity::class,
        XuiInstallationEntity::class,
        ManagementAccessEntity::class,
        WebPanelAccessEntity::class,
        OperationSnapshotEntity::class,
        OperationJournalEntity::class,
    ],
    version = 1,
    exportSchema = true,
)
abstract class VelumDatabase : RoomDatabase() {
    abstract fun serverDao(): ServerDao
    abstract fun serverAccessDao(): ServerAccessDao
    abstract fun installationDao(): XuiInstallationDao
    abstract fun managementAccessDao(): ManagementAccessDao
    abstract fun webPanelAccessDao(): WebPanelAccessDao
    abstract fun operationDao(): OperationDao
    abstract fun serverPurgeDao(): com.velumtegra.xuimobile.core.data.db.dao.ServerPurgeDao
}
