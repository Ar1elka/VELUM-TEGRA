package com.velumtegra.xuimobile.core.data.db

import android.content.Context
import androidx.room3.Room
import androidx.sqlite.driver.AndroidSQLiteDriver

/**
 * Canonical Phase 2 production open-path for the operational database.
 *
 * Room 3 requires an explicit SQLiteDriver. AndroidSQLiteDriver keeps the database on the platform
 * SQLite implementation without introducing a second bundled native SQLite. No destructive migration
 * fallback is ever installed here: a missing future migration must fail instead of erasing exact identity,
 * operation history, or SecretId references.
 */
object VelumDatabaseFactory {
    const val DEFAULT_DATABASE_NAME = "velum_tegra.db"

    fun open(
        context: Context,
        databaseName: String = DEFAULT_DATABASE_NAME,
    ): VelumDatabase {
        require(databaseName.isNotBlank()) { "Database name must not be blank" }
        require('/' !in databaseName && '\\' !in databaseName) {
            "Database name must be a file name, not a path"
        }
        return Room.databaseBuilder(
            context.applicationContext,
            VelumDatabase::class.java,
            databaseName,
        )
            .setDriver(AndroidSQLiteDriver())
            .build()
    }
}
