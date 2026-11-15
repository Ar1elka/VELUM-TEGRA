package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.model.BackupSlotInventory
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerId

/**
 * Bounded process-local memory of the latest slot observation per server. Display only: nothing
 * here grants write authority, and an older observation never replaces a newer one.
 * Each observation is bound to the exact verified SSH profile ([ServerAccess]: endpoint, user,
 * auth reference and pinned host key); it is never shown for a different profile of the same server.
 */
class BackupSlotInventoryRegistry(private val maxServers: Int = 8) {
    private data class Entry(val profile: ServerAccess, val observation: BackupSlotInventory)
    private val values = linkedMapOf<ServerId, Entry>()
    @Synchronized fun record(serverId: ServerId, profile: ServerAccess, observation: BackupSlotInventory) {
        if (profile.serverId != serverId) return
        val old = values[serverId]
        if (old != null && observation.observedAt.isBefore(old.observation.observedAt)) return
        values.remove(serverId)
        values[serverId] = Entry(profile, observation)
        while (values.size > maxServers) values.remove(values.keys.first())
    }
    @Synchronized fun latest(serverId: ServerId, profile: ServerAccess): BackupSlotInventory? =
        values[serverId]?.takeIf { it.profile == profile && profile.serverId == serverId }?.observation
}
