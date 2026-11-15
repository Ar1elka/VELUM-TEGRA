package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.model.BackupSlotInventory
import java.time.Instant
import java.time.ZoneOffset
import org.junit.Assert.*
import org.junit.Test

class BackupSlotInventoryTextTest {
    private val at = Instant.parse("2026-11-03T10:00:05Z")
    private fun text(i: BackupSlotInventory?) = backupSlotInventoryText(i, ZoneOffset.UTC)
    @Test fun neverObservedSaysSoWithoutClaimingFreeSlots() {
        val t = text(null); assertTrue("не наблюдалась" in t); assertFalse("свободн" in t)
    }
    @Test fun partialOccupancyShowsCountOfFourAndUnfinishedNote() {
        val t = text(BackupSlotInventory.Known(2, 4, at))
        assertTrue("2 из 4" in t); assertTrue("незавершённые" in t); assertTrue("10:00:05" in t)
        assertTrue("Результат последней проверки" in t); assertTrue("проверит хранилище снова" in t)
    }
    @Test fun fullOccupancyIsLastCheckResultWithoutBanOrManualCleanupAdvice() {
        val t = text(BackupSlotInventory.Known(4, 4, at))
        assertTrue("4 из 4" in t); assertTrue("Результат последней проверки" in t); assertTrue("проверит хранилище снова" in t)
        assertFalse("невозможно" in t); assertFalse("вручную" in t); assertFalse("освобожд" in t); assertFalse("не удаляет" in t)
    }
    @Test fun overflowIsShownAsMoreThanCap() { assertTrue("более 4 из 4" in text(BackupSlotInventory.Known(5, 4, at))) }
    @Test fun unavailableNeverImpliesFree() {
        val t = text(BackupSlotInventory.Unavailable(at))
        assertTrue("не удалось прочитать" in t); assertTrue("не означает, что слоты свободны" in t)
    }
}
