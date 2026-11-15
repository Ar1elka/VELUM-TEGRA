package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner

sealed interface SessionInstallResult {
    data object Installed : SessionInstallResult
    data object AlreadyRegistered : SessionInstallResult
    data class Replaced(val priorSessionId: SessionId) : SessionInstallResult
    data class SessionIdCollisionRejected(val sessionId: SessionId) : SessionInstallResult
}

/**
 * In-process registry keyed only by exact owner + exact access.
 * It intentionally exposes no active/latest/first/by-server lookup.
 */
class ExactSessionRegistry : AutoCloseable {
    private data class Key(
        val owner: SessionOwner,
        val accessId: ServerAccessId,
    )

    private val monitor = Any()
    private val sessions = LinkedHashMap<Key, SshSessionHandle>()

    fun install(handle: SshSessionHandle): SessionInstallResult {
        val binding = handle.binding
        val key = Key(binding.owner, binding.serverAccessId)
        var handleToClose: SshSessionHandle? = null
        val result = synchronized(monitor) {
            val prior = sessions[key]
            when {
                prior == null -> {
                    sessions[key] = handle
                    SessionInstallResult.Installed
                }

                prior === handle -> SessionInstallResult.AlreadyRegistered

                prior.binding.sessionId == binding.sessionId -> {
                    // SessionId is a unique live-session identity. Keep the already-published handle and
                    // reject/close the colliding newcomer instead of creating ambiguous cleanup semantics.
                    handleToClose = handle
                    SessionInstallResult.SessionIdCollisionRejected(binding.sessionId)
                }

                else -> {
                    sessions[key] = handle
                    handleToClose = prior
                    SessionInstallResult.Replaced(prior.binding.sessionId)
                }
            }
        }
        handleToClose?.close()
        return result
    }

    fun find(owner: SessionOwner, accessId: ServerAccessId): SshSessionHandle? = synchronized(monitor) {
        val key = Key(owner, accessId)
        val current = sessions[key] ?: return@synchronized null
        if (current.isOpen) {
            current
        } else {
            sessions.remove(key)
            null
        }
    }

    /** Exact SessionId guard prevents a stale cleanup from removing a replacement session. */
    fun remove(
        owner: SessionOwner,
        accessId: ServerAccessId,
        sessionId: SessionId,
        close: Boolean = true,
    ): Boolean {
        var removed: SshSessionHandle? = null
        val didRemove = synchronized(monitor) {
            val key = Key(owner, accessId)
            val current = sessions[key]
            if (current?.binding?.sessionId != sessionId) {
                false
            } else {
                removed = sessions.remove(key)
                true
            }
        }
        if (close) removed?.close()
        return didRemove
    }

    fun size(): Int = synchronized(monitor) { sessions.size }

    override fun close() {
        val toClose = synchronized(monitor) {
            val copy = sessions.values.toList()
            sessions.clear()
            copy
        }
        toClose.forEach { it.close() }
    }
}
