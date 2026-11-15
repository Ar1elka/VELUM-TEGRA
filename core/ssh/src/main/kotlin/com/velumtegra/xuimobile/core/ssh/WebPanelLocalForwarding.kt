package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget
import com.velumtegra.xuimobile.core.domain.WebPanelHost
import com.velumtegra.xuimobile.core.model.SessionBinding
import java.time.Duration

/** Internal transport limits for one WebPanel local-forward registration. These are not UI settings. */
data class WebPanelLocalForwardConfig(
    val remoteConnectTimeout: Duration = Duration.ofSeconds(10),
) {
    init {
        require(!remoteConnectTimeout.isZero && !remoteConnectTimeout.isNegative) {
            "WebPanel forward remote-connect timeout must be > 0"
        }
        require(remoteConnectTimeout <= MAX_REMOTE_CONNECT_TIMEOUT) {
            "WebPanel forward remote-connect timeout must be <= $MAX_REMOTE_CONNECT_TIMEOUT"
        }
    }

    private companion object {
        val MAX_REMOTE_CONNECT_TIMEOUT: Duration = Duration.ofMinutes(30)
    }
}

/** The only local bind shape exposed by Phase 7.3: numeric IPv4 loopback plus an OS-assigned port. */
class WebPanelLoopbackEndpoint internal constructor(
    val port: Int,
) {
    val host: String
        get() = WEB_PANEL_LOOPBACK_HOST

    init {
        require(port in 1..65535) { "WebPanel local forward port must be in 1..65535" }
    }

    override fun toString(): String = "WebPanelLoopbackEndpoint(host=$WEB_PANEL_LOOPBACK_HOST, port=$port)"
}

enum class WebPanelLocalForwardFailure {
    UNSUPPORTED_SESSION_CAPABILITY,
    SESSION_NOT_OPEN,
    ROUTE_NOT_SSH_TUNNEL,
    SESSION_OWNER_MISMATCH,
    SERVER_ACCESS_MISMATCH,
    DIFFERENT_TARGET_ALREADY_FORWARDED,
    LOCAL_FORWARD_OPEN_FAILED,
    INVALID_ALLOCATED_LOCAL_PORT,
}

sealed interface WebPanelLocalForwardOpenResult {
    data class Opened(val handle: WebPanelLocalForwardHandle) : WebPanelLocalForwardOpenResult
    data class AlreadyOpen(val handle: WebPanelLocalForwardHandle) : WebPanelLocalForwardOpenResult
    data class Rejected(val failure: WebPanelLocalForwardFailure) : WebPanelLocalForwardOpenResult
}

/**
 * One process-local WebPanel forward subordinate to one exact authenticated SSH session.
 * Closing this handle releases only the local forward; closing the owning SSH session must also close it.
 */
interface WebPanelLocalForwardHandle : AutoCloseable {
    val sessionBinding: SessionBinding
    val target: ResolvedWebPanelTarget
    val localEndpoint: WebPanelLoopbackEndpoint
    val isOpen: Boolean

    override fun close()
}

/** Optional capability implemented only by SSH handles that own a concrete forwarding-capable session. */
interface WebPanelForwardingSshSessionHandle : SshSessionHandle {
    fun openWebPanelLocalForward(
        target: ResolvedWebPanelTarget,
        config: WebPanelLocalForwardConfig = WebPanelLocalForwardConfig(),
    ): WebPanelLocalForwardOpenResult
}

/**
 * WebPanel-specific entry point. It accepts no arbitrary bind address, local port, remote host or remote port.
 * The remote destination must already be present in an exact [ResolvedWebPanelTarget] produced by Phase 7.2.
 */
fun SshSessionHandle.openWebPanelLocalForward(
    target: ResolvedWebPanelTarget,
    config: WebPanelLocalForwardConfig = WebPanelLocalForwardConfig(),
): WebPanelLocalForwardOpenResult = when (this) {
    is WebPanelForwardingSshSessionHandle -> openWebPanelLocalForward(target, config)
    else -> WebPanelLocalForwardOpenResult.Rejected(
        WebPanelLocalForwardFailure.UNSUPPORTED_SESSION_CAPABILITY,
    )
}

internal const val WEB_PANEL_LOOPBACK_HOST: String = "127.0.0.1"

/** URI brackets are not part of the socket host handed to SSH direct-tcpip. */
internal fun WebPanelHost.toSshForwardDestinationHost(): String =
    if (value.length >= 4 && value.startsWith('[') && value.endsWith(']')) {
        value.substring(1, value.length - 1)
    } else {
        value
    }
