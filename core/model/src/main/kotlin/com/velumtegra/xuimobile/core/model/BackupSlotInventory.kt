package com.velumtegra.xuimobile.core.model

import java.time.Instant

/**
 * Read-only, process-local observation of private backup directory occupancy on one server.
 * It is display evidence only: never create/restore/cleanup authority and never persisted.
 * [Known.used] counts every directory entry below the private backup root (including unfinished
 * ones) except the writer lock, exactly as the existing storage observation does.
 */
sealed interface BackupSlotInventory {
    val observedAt: Instant

    data class Known(val used: Int, val max: Int, override val observedAt: Instant) : BackupSlotInventory {
        init { require(max > 0); require(used >= 0) }
        val free: Int get() = (max - used).coerceAtLeast(0)
        val saturated: Boolean get() = used >= max
        /** The remote probe may report more entries than the cap; the exact count is then unknown. */
        val overflow: Boolean get() = used > max
    }

    /** The storage read failed or did not match the exact scope; this never means "slots are free". */
    data class Unavailable(override val observedAt: Instant) : BackupSlotInventory
}
