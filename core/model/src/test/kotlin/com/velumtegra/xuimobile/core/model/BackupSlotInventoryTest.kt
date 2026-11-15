package com.velumtegra.xuimobile.core.model

import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class BackupSlotInventoryTest {
    private val at = Instant.parse("2026-11-03T10:00:00Z")
    @Test fun emptyRootHasAllSlotsFree() {
        val i = BackupSlotInventory.Known(0, 4, at)
        assertEquals(4, i.free); assertFalse(i.saturated); assertFalse(i.overflow)
    }
    @Test fun lastFreeSlotIsNotSaturated() {
        val i = BackupSlotInventory.Known(3, 4, at)
        assertEquals(1, i.free); assertFalse(i.saturated)
    }
    @Test fun fullRootIsSaturatedWithoutOverflow() {
        val i = BackupSlotInventory.Known(4, 4, at)
        assertEquals(0, i.free); assertTrue(i.saturated); assertFalse(i.overflow)
    }
    @Test fun countAboveCapIsOverflowAndNeverNegativeFree() {
        val i = BackupSlotInventory.Known(5, 4, at)
        assertEquals(0, i.free); assertTrue(i.saturated); assertTrue(i.overflow)
    }
    @Test fun invalidCountsAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { BackupSlotInventory.Known(-1, 4, at) }
        assertThrows(IllegalArgumentException::class.java) { BackupSlotInventory.Known(0, 0, at) }
    }
    @Test fun unavailableIsNotKnownAndCarriesOnlyTime() {
        val i: BackupSlotInventory = BackupSlotInventory.Unavailable(at)
        assertFalse(i is BackupSlotInventory.Known); assertEquals(at, i.observedAt)
    }
    @Test fun slotCapMatchesBothBackupBindings() {
        assertEquals(4, DatabaseBackupBinding.MAX_SLOTS); assertEquals(4, InstallationBackupBinding.MAX_SLOTS)
    }
}
