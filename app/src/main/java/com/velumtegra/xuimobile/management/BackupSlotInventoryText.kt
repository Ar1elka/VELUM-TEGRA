package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.model.BackupSlotInventory
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** Pure display text for the read-only slot observation. It never offers or implies cleanup. */
internal fun backupSlotInventoryText(inventory: BackupSlotInventory?, zone: ZoneId = ZoneId.systemDefault()): String {
    fun time(i: BackupSlotInventory) = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(zone).format(i.observedAt)
    return when (inventory) {
        null -> "Занятость слотов для этого SSH-профиля в этом запуске приложения не наблюдалась. Она читается только при предварительной проверке перед созданием копии; отдельного обращения к серверу здесь нет."
        is BackupSlotInventory.Unavailable ->
            "Занятость слотов не удалось прочитать (" + time(inventory) + "). Это не означает, что слоты свободны."
        is BackupSlotInventory.Known -> {
            val count = if (inventory.overflow) "более ${inventory.max} из ${inventory.max}" else "${inventory.used} из ${inventory.max}"
            "Результат последней проверки (" + time(inventory) + "): занято слотов $count, включая незавершённые каталоги. " +
                "Это не текущее состояние сервера: перед созданием копии приложение проверит хранилище снова."
        }
    }
}
