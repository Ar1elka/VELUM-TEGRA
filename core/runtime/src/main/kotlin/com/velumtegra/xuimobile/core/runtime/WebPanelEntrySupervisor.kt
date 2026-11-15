package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelRouteTarget
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.WebPanelHost
import com.velumtegra.xuimobile.core.domain.WebPanelTargetConflictReason
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionRequest
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionResult
import com.velumtegra.xuimobile.core.domain.WebPanelTargetUnresolvedReason
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardFailure
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardHandle
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardOpenResult
import com.velumtegra.xuimobile.core.ssh.openWebPanelLocalForward
import com.velumtegra.xuimobile.core.webpanel.CredentialSubmissionState
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticatedSession
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationClient
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationConfig
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationFailureEvidence
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationRequest
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationResult
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationTransport
import com.velumtegra.xuimobile.core.webpanel.WebPanelSecondFactor
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Explicit process-local Phase 7.5 WebPanel entry request.
 *
 * [sshAuthorityHost] is required only for an SSH-tunneled target. It is the logical HTTP/TLS
 * authority from Phase 7.4 and is deliberately not inferred from the forwarding destination.
 * [secondFactor] remains caller-owned volatile material.
 */
data class WebPanelEntryRequest(
    val targetRequest: WebPanelTargetResolutionRequest,
    val sshAuthorityHost: WebPanelHost? = null,
    val secondFactor: WebPanelSecondFactor? = null,
    val authenticationConfig: WebPanelAuthenticationConfig = WebPanelAuthenticationConfig(),
)

enum class WebPanelEntryRouteKind {
    DIRECT,
    SSH_TUNNEL,
}

enum class WebPanelEntryStatus {
    OPEN,
    ALREADY_OPEN,
    FAILED,
}

enum class WebPanelEntryLocalFailure {
    ENTRY_ALREADY_IN_PROGRESS,
    ENTRY_CANCELLED,
    SSH_AUTHORITY_REQUIRED,
    SSH_AUTHORITY_NOT_ALLOWED_FOR_DIRECT,
    SSH_ACCESS_NOT_FOUND,
    SSH_ACCESS_READ_CONFLICT,
    SSH_ACCESS_CORRUPTION,
    SSH_ACCESS_STORAGE_FAILURE,
    SSH_ACCESS_IDENTITY_MISMATCH,
    SSH_ACCESS_SERVER_SCOPE_MISMATCH,
    SSH_SESSION_BINDING_MISMATCH,
    SSH_SESSION_ID_COLLISION,
}

sealed interface WebPanelEntryFailure {
    data class TargetUnresolved(val reason: WebPanelTargetUnresolvedReason) : WebPanelEntryFailure
    data class TargetConflict(val reason: WebPanelTargetConflictReason) : WebPanelEntryFailure
    data object TargetCorruption : WebPanelEntryFailure
    data object TargetStorageFailure : WebPanelEntryFailure

    data class Local(val kind: WebPanelEntryLocalFailure) : WebPanelEntryFailure

    /** Safe normalized transport evidence. Raw SSH/network reason text never crosses this boundary. */
    data class SshConnect(
        val category: RetryFailureCategory,
        val retryableOnFreshConnectivity: Boolean,
    ) : WebPanelEntryFailure

    data class Forward(val failure: WebPanelLocalForwardFailure) : WebPanelEntryFailure
    data class Authentication(val evidence: WebPanelAuthenticationFailureEvidence) : WebPanelEntryFailure
}

/**
 * Safe process-local feature projection. It intentionally contains no host, port, base path,
 * SessionId, local forwarding port, password/OTP/cookie/CSRF material or raw exception text.
 */
data class WebPanelEntryProjection(
    val webPanelAccessId: WebPanelAccessId,
    val routeKind: WebPanelEntryRouteKind?,
    val status: WebPanelEntryStatus,
    val failure: WebPanelEntryFailure? = null,
)

sealed interface WebPanelEntryResult {
    data class Opened(val session: WebPanelEntrySession) : WebPanelEntryResult
    data class AlreadyOpen(val projection: WebPanelEntryProjection) : WebPanelEntryResult
    data class Failed(val projection: WebPanelEntryProjection) : WebPanelEntryResult
}

/** Opaque process-local ownership handle for one successful explicit WebPanel entry. */
interface WebPanelEntrySession : AutoCloseable {
    val projection: WebPanelEntryProjection
    val isOpen: Boolean

    override fun close()
}

enum class WebPanelEntryCloseResult {
    CLOSED,
    OPENING_CANCELLED,
    ALREADY_CLOSED,
}

/**
 * Thin Phase 7.5 coordinator over the already-canonical target resolver, exact SSH registry/
 * one-attempt transport and Phase 7.4 one-attempt WebPanel authentication client.
 *
 * It owns no generic retry loop, durable operation, journal entry, background resurrection or route
 * fallback. A transient SSH connect failure is only classified through the canonical Phase 4 retry
 * classifier and returned as normalized evidence; a later attempt still requires a fresh explicit
 * [open] call, which re-resolves durable target/revision state from scratch.
 */
class WebPanelEntrySupervisor(
    private val targetResolver: ExactWebPanelTargetResolver,
    private val serverAccessRepository: ServerAccessRepository,
    private val connectionFactory: SshConnectionFactory,
    private val sessionRegistry: ExactSessionRegistry,
    private val authenticationClient: WebPanelAuthenticationClient,
) : AutoCloseable {
    private val monitor = Any()
    private val active = LinkedHashMap<WebPanelAccessId, ManagedEntrySession>()
    private val opening = LinkedHashMap<WebPanelAccessId, Long>()
    private var nextOpenToken = 1L

    suspend fun open(request: WebPanelEntryRequest): WebPanelEntryResult {
        val accessId = request.targetRequest.webPanelAccessId
        val claim = claimOpening(accessId)
        when (claim) {
            is OpenClaim.AlreadyOpen -> return WebPanelEntryResult.AlreadyOpen(claim.projection)
            OpenClaim.AlreadyOpening -> return failed(
                accessId = accessId,
                routeKind = null,
                failure = WebPanelEntryFailure.Local(WebPanelEntryLocalFailure.ENTRY_ALREADY_IN_PROGRESS),
            )
            is OpenClaim.Claimed -> claim.stale?.dispose()
        }
        val token = claim.token

        try {
            val target = when (val resolved = targetResolver.resolve(request.targetRequest)) {
                is WebPanelTargetResolutionResult.Resolved -> resolved.target
                is WebPanelTargetResolutionResult.Unresolved -> return failed(
                    accessId,
                    null,
                    WebPanelEntryFailure.TargetUnresolved(resolved.reason),
                )
                is WebPanelTargetResolutionResult.Conflict -> return failed(
                    accessId,
                    null,
                    WebPanelEntryFailure.TargetConflict(resolved.reason),
                )
                WebPanelTargetResolutionResult.Corruption -> return failed(
                    accessId,
                    null,
                    WebPanelEntryFailure.TargetCorruption,
                )
                WebPanelTargetResolutionResult.StorageFailure -> return failed(
                    accessId,
                    null,
                    WebPanelEntryFailure.TargetStorageFailure,
                )
            }
            if (!isOpeningCurrent(accessId, token)) {
                return failed(
                    accessId,
                    routeKindOf(target),
                    WebPanelEntryFailure.Local(WebPanelEntryLocalFailure.ENTRY_CANCELLED),
                )
            }

            return when (val route = target.routeTarget) {
                is ResolvedWebPanelRouteTarget.Direct -> openDirect(request, target, token)
                is ResolvedWebPanelRouteTarget.SshTunnel -> openSsh(request, target, route, token)
            }
        } finally {
            finishOpening(accessId, token)
        }
    }

    fun projection(webPanelAccessId: WebPanelAccessId): WebPanelEntryProjection? {
        var stale: ManagedEntrySession? = null
        val result = synchronized(monitor) {
            val current = active[webPanelAccessId] ?: return@synchronized null
            if (current.isOpen) {
                current.projection
            } else {
                if (active[webPanelAccessId] === current) {
                    stale = active.remove(webPanelAccessId)
                }
                null
            }
        }
        // A dead SSH/forward path must also release the authenticated HTTP session/cookie jar.
        // Dispose outside the supervisor monitor because disposal performs exact registry cleanup and
        // calls back into forget(); the identity guard there prevents stale cleanup from touching
        // a newer replacement entry.
        stale?.dispose()
        return result
    }

    fun close(webPanelAccessId: WebPanelAccessId): WebPanelEntryCloseResult {
        val removed: ManagedEntrySession?
        val cancelledOpening: Boolean
        synchronized(monitor) {
            removed = active.remove(webPanelAccessId)
            cancelledOpening = opening.remove(webPanelAccessId) != null
        }
        removed?.dispose()
        return when {
            removed != null -> WebPanelEntryCloseResult.CLOSED
            cancelledOpening -> WebPanelEntryCloseResult.OPENING_CANCELLED
            else -> WebPanelEntryCloseResult.ALREADY_CLOSED
        }
    }

    override fun close() {
        val sessions = synchronized(monitor) {
            opening.clear()
            val copy = active.values.toList()
            active.clear()
            copy
        }
        sessions.forEach { it.dispose() }
    }

    private suspend fun openDirect(
        request: WebPanelEntryRequest,
        target: ResolvedWebPanelTarget,
        token: Long,
    ): WebPanelEntryResult {
        if (request.sshAuthorityHost != null) {
            return failed(
                target.webPanelAccessId,
                WebPanelEntryRouteKind.DIRECT,
                WebPanelEntryFailure.Local(WebPanelEntryLocalFailure.SSH_AUTHORITY_NOT_ALLOWED_FOR_DIRECT),
            )
        }
        if (!isOpeningCurrent(target.webPanelAccessId, token)) {
            return cancelled(target, WebPanelEntryRouteKind.DIRECT)
        }
        val auth = authenticationClient.authenticate(
            WebPanelAuthenticationRequest(
                target = target,
                transport = WebPanelAuthenticationTransport.Direct,
                secondFactor = request.secondFactor,
                config = request.authenticationConfig,
            ),
        )
        if (!isOpeningCurrent(target.webPanelAccessId, token)) {
            if (auth is WebPanelAuthenticationResult.Authenticated) auth.session.close()
            return cancelled(target, WebPanelEntryRouteKind.DIRECT)
        }
        return when (auth) {
            is WebPanelAuthenticationResult.Failed -> failed(
                target.webPanelAccessId,
                WebPanelEntryRouteKind.DIRECT,
                WebPanelEntryFailure.Authentication(auth.evidence),
            )
            is WebPanelAuthenticationResult.Authenticated -> publish(
                target = target,
                routeKind = WebPanelEntryRouteKind.DIRECT,
                authenticated = auth.session,
                forward = null,
                sshOwnership = null,
            )
        }
    }

    private suspend fun openSsh(
        request: WebPanelEntryRequest,
        target: ResolvedWebPanelTarget,
        route: ResolvedWebPanelRouteTarget.SshTunnel,
        token: Long,
    ): WebPanelEntryResult {
        val authority = request.sshAuthorityHost ?: return failed(
            target.webPanelAccessId,
            WebPanelEntryRouteKind.SSH_TUNNEL,
            WebPanelEntryFailure.Local(WebPanelEntryLocalFailure.SSH_AUTHORITY_REQUIRED),
        )
        val access = when (val read = serverAccessRepository.get(route.serverAccessId)) {
            is RepositoryResult.Success -> read.value
            RepositoryResult.NotFound -> return failedLocal(target, WebPanelEntryLocalFailure.SSH_ACCESS_NOT_FOUND)
            is RepositoryResult.ConstraintConflict,
            is RepositoryResult.StaleRevision,
            -> return failedLocal(target, WebPanelEntryLocalFailure.SSH_ACCESS_READ_CONFLICT)
            is RepositoryResult.Corruption -> return failedLocal(target, WebPanelEntryLocalFailure.SSH_ACCESS_CORRUPTION)
            is RepositoryResult.StorageFailure -> return failedLocal(target, WebPanelEntryLocalFailure.SSH_ACCESS_STORAGE_FAILURE)
        }
        if (access.id != route.serverAccessId) {
            return failedLocal(target, WebPanelEntryLocalFailure.SSH_ACCESS_IDENTITY_MISMATCH)
        }
        if (access.serverId != route.serverId) {
            return failedLocal(target, WebPanelEntryLocalFailure.SSH_ACCESS_SERVER_SCOPE_MISMATCH)
        }
        if (!isOpeningCurrent(target.webPanelAccessId, token)) {
            return cancelled(target, WebPanelEntryRouteKind.SSH_TUNNEL)
        }

        val owner = SessionOwner.WebPanel(target.webPanelAccessId)
        val session = when (val current = sessionRegistry.find(owner, route.serverAccessId)) {
            null -> when (val connected = connectionFactory.connect(access, owner)) {
                is SshConnectResult.Failed -> return failed(
                    target.webPanelAccessId,
                    WebPanelEntryRouteKind.SSH_TUNNEL,
                    sshConnectFailure(connected.failure),
                )
                is SshConnectResult.Connected -> {
                    val bindingFailure = validateBinding(connected.handle, owner, route.serverAccessId)
                    if (bindingFailure != null) {
                        connected.handle.close()
                        return failedLocal(target, bindingFailure)
                    }
                    when (sessionRegistry.install(connected.handle)) {
                        is SessionInstallResult.SessionIdCollisionRejected -> {
                            return failedLocal(target, WebPanelEntryLocalFailure.SSH_SESSION_ID_COLLISION)
                        }
                        SessionInstallResult.Installed,
                        SessionInstallResult.AlreadyRegistered,
                        is SessionInstallResult.Replaced,
                        -> Unit
                    }
                    connected.handle
                }
            }
            else -> current
        }
        val bindingFailure = validateBinding(session, owner, route.serverAccessId)
        if (bindingFailure != null) {
            cleanupExactSession(session.binding)
            return failedLocal(target, bindingFailure)
        }
        val binding = session.binding
        if (!isOpeningCurrent(target.webPanelAccessId, token)) {
            cleanupExactSession(binding)
            return cancelled(target, WebPanelEntryRouteKind.SSH_TUNNEL)
        }

        val forward = when (val opened = session.openWebPanelLocalForward(target)) {
            is WebPanelLocalForwardOpenResult.Opened -> opened.handle
            is WebPanelLocalForwardOpenResult.AlreadyOpen -> opened.handle
            is WebPanelLocalForwardOpenResult.Rejected -> {
                cleanupExactSession(binding)
                return failed(
                    target.webPanelAccessId,
                    WebPanelEntryRouteKind.SSH_TUNNEL,
                    WebPanelEntryFailure.Forward(opened.failure),
                )
            }
        }
        if (!isOpeningCurrent(target.webPanelAccessId, token)) {
            forward.close()
            cleanupExactSession(binding)
            return cancelled(target, WebPanelEntryRouteKind.SSH_TUNNEL)
        }

        val auth = authenticationClient.authenticate(
            WebPanelAuthenticationRequest(
                target = target,
                transport = WebPanelAuthenticationTransport.SshTunnel(
                    forward = forward,
                    authorityHost = authority,
                ),
                secondFactor = request.secondFactor,
                config = request.authenticationConfig,
            ),
        )
        if (!isOpeningCurrent(target.webPanelAccessId, token)) {
            if (auth is WebPanelAuthenticationResult.Authenticated) auth.session.close()
            forward.close()
            cleanupExactSession(binding)
            return cancelled(target, WebPanelEntryRouteKind.SSH_TUNNEL)
        }
        return when (auth) {
            is WebPanelAuthenticationResult.Failed -> {
                forward.close()
                cleanupExactSession(binding)
                failed(
                    target.webPanelAccessId,
                    WebPanelEntryRouteKind.SSH_TUNNEL,
                    WebPanelEntryFailure.Authentication(auth.evidence),
                )
            }
            is WebPanelAuthenticationResult.Authenticated -> publish(
                target = target,
                routeKind = WebPanelEntryRouteKind.SSH_TUNNEL,
                authenticated = auth.session,
                forward = forward,
                sshOwnership = SshOwnership(owner, route.serverAccessId, binding.sessionId),
            )
        }
    }

    private fun publish(
        target: ResolvedWebPanelTarget,
        routeKind: WebPanelEntryRouteKind,
        authenticated: WebPanelAuthenticatedSession,
        forward: WebPanelLocalForwardHandle?,
        sshOwnership: SshOwnership?,
    ): WebPanelEntryResult {
        val session = ManagedEntrySession(
            projection = WebPanelEntryProjection(
                webPanelAccessId = target.webPanelAccessId,
                routeKind = routeKind,
                status = WebPanelEntryStatus.OPEN,
            ),
            authenticated = authenticated,
            forward = forward,
            sshOwnership = sshOwnership,
            sessionRegistry = sessionRegistry,
            onDisposed = { disposed -> forget(disposed) },
        )
        val existing = synchronized(monitor) {
            val current = active[target.webPanelAccessId]
            if (current != null && current.isOpen) {
                current
            } else {
                if (current != null) active.remove(target.webPanelAccessId)
                active[target.webPanelAccessId] = session
                null
            }
        }
        if (existing != null) {
            session.dispose()
            return WebPanelEntryResult.AlreadyOpen(
                existing.projection.copy(status = WebPanelEntryStatus.ALREADY_OPEN),
            )
        }
        return WebPanelEntryResult.Opened(session)
    }

    private fun claimOpening(accessId: WebPanelAccessId): OpenClaim = synchronized(monitor) {
        val current = active[accessId]
        if (current != null && current.isOpen) {
            return@synchronized OpenClaim.AlreadyOpen(
                current.projection.copy(status = WebPanelEntryStatus.ALREADY_OPEN),
            )
        }
        if (opening.containsKey(accessId)) return@synchronized OpenClaim.AlreadyOpening
        val stale = if (current == null) null else active.remove(accessId)
        check(nextOpenToken != Long.MAX_VALUE) { "WebPanel entry token exhausted" }
        val token = nextOpenToken++
        opening[accessId] = token
        OpenClaim.Claimed(token, stale)
    }

    private fun isOpeningCurrent(accessId: WebPanelAccessId, token: Long): Boolean = synchronized(monitor) {
        opening[accessId] == token
    }

    private fun finishOpening(accessId: WebPanelAccessId, token: Long) {
        synchronized(monitor) {
            if (opening[accessId] == token) opening.remove(accessId)
        }
    }

    private fun forget(session: ManagedEntrySession) {
        synchronized(monitor) {
            val accessId = session.projection.webPanelAccessId
            if (active[accessId] === session) active.remove(accessId)
        }
    }

    private fun cleanupExactSession(binding: SessionBinding) {
        sessionRegistry.remove(
            owner = binding.owner,
            accessId = binding.serverAccessId,
            sessionId = binding.sessionId,
            close = true,
        )
    }

    private fun validateBinding(
        handle: SshSessionHandle,
        owner: SessionOwner.WebPanel,
        accessId: ServerAccessId,
    ): WebPanelEntryLocalFailure? {
        val binding = handle.binding
        return if (binding.owner != owner || binding.serverAccessId != accessId) {
            WebPanelEntryLocalFailure.SSH_SESSION_BINDING_MISMATCH
        } else {
            null
        }
    }

    private fun sshConnectFailure(failure: SshConnectFailure): WebPanelEntryFailure.SshConnect {
        val classification = SshConnectRetryClassifier.classify(failure)
        return WebPanelEntryFailure.SshConnect(
            category = classification.category,
            retryableOnFreshConnectivity = classification is RetryFailureClassification.Retryable,
        )
    }

    private fun failedLocal(
        target: ResolvedWebPanelTarget,
        failure: WebPanelEntryLocalFailure,
    ): WebPanelEntryResult.Failed = failed(
        target.webPanelAccessId,
        routeKindOf(target),
        WebPanelEntryFailure.Local(failure),
    )

    private fun cancelled(
        target: ResolvedWebPanelTarget,
        routeKind: WebPanelEntryRouteKind,
    ): WebPanelEntryResult.Failed = failed(
        target.webPanelAccessId,
        routeKind,
        WebPanelEntryFailure.Local(WebPanelEntryLocalFailure.ENTRY_CANCELLED),
    )

    private fun failed(
        accessId: WebPanelAccessId,
        routeKind: WebPanelEntryRouteKind?,
        failure: WebPanelEntryFailure,
    ) = WebPanelEntryResult.Failed(
        WebPanelEntryProjection(
            webPanelAccessId = accessId,
            routeKind = routeKind,
            status = WebPanelEntryStatus.FAILED,
            failure = failure,
        ),
    )

    private fun routeKindOf(target: ResolvedWebPanelTarget): WebPanelEntryRouteKind = when (target.routeTarget) {
        is ResolvedWebPanelRouteTarget.Direct -> WebPanelEntryRouteKind.DIRECT
        is ResolvedWebPanelRouteTarget.SshTunnel -> WebPanelEntryRouteKind.SSH_TUNNEL
    }

    private sealed interface OpenClaim {
        data class Claimed(val token: Long, val stale: ManagedEntrySession?) : OpenClaim
        data class AlreadyOpen(val projection: WebPanelEntryProjection) : OpenClaim
        data object AlreadyOpening : OpenClaim
    }

    private data class SshOwnership(
        val owner: SessionOwner.WebPanel,
        val accessId: ServerAccessId,
        val sessionId: SessionId,
    )

    private class ManagedEntrySession(
        override val projection: WebPanelEntryProjection,
        private val authenticated: WebPanelAuthenticatedSession,
        private val forward: WebPanelLocalForwardHandle?,
        private val sshOwnership: SshOwnership?,
        private val sessionRegistry: ExactSessionRegistry,
        private val onDisposed: (ManagedEntrySession) -> Unit,
    ) : WebPanelEntrySession {
        private val disposed = AtomicBoolean(false)

        override val isOpen: Boolean
            get() {
                if (disposed.get() || !authenticated.isOpen || forward?.isOpen == false) return false
                val ownership = sshOwnership ?: return true
                val current = sessionRegistry.find(ownership.owner, ownership.accessId) ?: return false
                return current.binding.sessionId == ownership.sessionId
            }

        override fun close() = dispose()

        fun dispose() {
            if (!disposed.compareAndSet(false, true)) return
            try {
                authenticated.close()
            } finally {
                try {
                    forward?.close()
                } finally {
                    sshOwnership?.let {
                        sessionRegistry.remove(
                            owner = it.owner,
                            accessId = it.accessId,
                            sessionId = it.sessionId,
                            close = true,
                        )
                    }
                    onDisposed(this)
                }
            }
        }
    }
}
