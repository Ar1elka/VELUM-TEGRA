package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.model.XuiInstallationId

/** Explicit scheme selection. There is deliberately no HTTP/HTTPS default. */
enum class WebPanelScheme {
    HTTP,
    HTTPS,
}

/** Exact host text. It is never a URL, host:port pair, wildcard bind, or guessed fallback. */
@JvmInline
value class WebPanelHost(val value: String) {
    init {
        require(isValidWebPanelHost(value)) { "Invalid WebPanel host" }
    }
}

/** Exact normalized Web Base Path. The resolver never invents `/`. */
@JvmInline
value class WebPanelBasePath(val value: String) {
    init {
        require(isValidWebPanelBasePath(value)) { "Invalid WebPanel base path" }
    }
}

data class DirectWebPanelOrigin(
    val scheme: WebPanelScheme,
    val host: WebPanelHost,
    val port: Int,
    val webBasePath: WebPanelBasePath,
) {
    init {
        require(port in 1..65535) { "WebPanel port must be in 1..65535" }
    }
}

data class WebPanelRemoteEndpoint(
    val host: WebPanelHost,
    val port: Int,
) {
    init {
        require(port in 1..65535) { "WebPanel remote port must be in 1..65535" }
    }
}

/** Explicit process-local target structure required to open a Standalone access. */
sealed interface StandaloneWebPanelTargetDetails {
    data class Direct(
        val port: Int,
        val webBasePath: String,
    ) : StandaloneWebPanelTargetDetails

    data class SshTunnel(
        val remoteHost: String,
        val port: Int,
        val webBasePath: String,
    ) : StandaloneWebPanelTargetDetails
}

sealed interface ResolvedWebPanelInstallation {
    data object Standalone : ResolvedWebPanelInstallation

    data class Linked(
        val installationId: XuiInstallationId,
        val installationRevision: RecordRevision,
        val serverId: ServerId,
    ) : ResolvedWebPanelInstallation
}

/**
 * Direct exposes a complete logical origin. SSH exposes only the exact remote forwarding target,
 * scheme and path. It deliberately does not pretend that the remote socket host is the TLS/HTTP
 * authority host; that trust/origin binding remains a later explicit policy.
 */
sealed interface ResolvedWebPanelRouteTarget {
    data class Direct(
        val origin: DirectWebPanelOrigin,
    ) : ResolvedWebPanelRouteTarget

    data class SshTunnel(
        val serverAccessId: ServerAccessId,
        val serverId: ServerId,
        val remoteEndpoint: WebPanelRemoteEndpoint,
        val scheme: WebPanelScheme,
        val webBasePath: WebPanelBasePath,
    ) : ResolvedWebPanelRouteTarget
}

/** Process-local exact result. It is not persisted and is not remote success/proof. */
data class ResolvedWebPanelTarget internal constructor(
    val webPanelAccessId: WebPanelAccessId,
    val webPanelAccessRevision: RecordRevision,
    val installation: ResolvedWebPanelInstallation,
    val routeTarget: ResolvedWebPanelRouteTarget,
)

data class WebPanelTargetResolutionRequest(
    val webPanelAccessId: WebPanelAccessId,
    val scheme: WebPanelScheme,
    val standaloneTarget: StandaloneWebPanelTargetDetails? = null,
    /** Explicit private SSH remote host only when linked installation has no usable listenAddress. */
    val linkedSshRemoteHost: String? = null,
) {
    init {
        require(webPanelAccessId.value.isNotBlank()) { "webPanelAccessId must not be blank" }
    }
}

enum class WebPanelTargetUnresolvedReason {
    WEB_PANEL_ACCESS_NOT_FOUND,
    STANDALONE_TARGET_DETAILS_REQUIRED,
    LINKED_INSTALLATION_NOT_FOUND,
    LINKED_SERVER_NOT_FOUND,
    SSH_SERVER_ACCESS_NOT_FOUND,
    SSH_SERVER_NOT_FOUND,
    SSH_REMOTE_HOST_UNRESOLVED,
}

enum class WebPanelTargetConflictReason {
    REPOSITORY_READ_CONFLICT,
    STANDALONE_DETAILS_FOR_LINKED_ACCESS,
    STANDALONE_ROUTE_DETAILS_MISMATCH,
    INVALID_DIRECT_ORIGIN_HOST,
    INVALID_WEB_BASE_PATH,
    INVALID_SSH_REMOTE_HOST,
    INVALID_PANEL_PORT,
    SSH_SERVER_SCOPE_MISMATCH,
}

sealed interface WebPanelTargetResolutionResult {
    data class Resolved(val target: ResolvedWebPanelTarget) : WebPanelTargetResolutionResult
    data class Unresolved(val reason: WebPanelTargetUnresolvedReason) : WebPanelTargetResolutionResult
    data class Conflict(val reason: WebPanelTargetConflictReason) : WebPanelTargetResolutionResult
    data object Corruption : WebPanelTargetResolutionResult
    data object StorageFailure : WebPanelTargetResolutionResult
}

/**
 * Exact-id, read-only resolver. No network, SSH connection, SecretStore read, persistence write,
 * retry, route fallback, access fallback, or collection-order selection is reachable here.
 */
class ExactWebPanelTargetResolver(
    private val webPanelAccessRepository: WebPanelAccessRepository,
    private val installationRepository: XuiInstallationRepository,
    private val serverRepository: ServerRepository,
    private val serverAccessRepository: ServerAccessRepository,
) {
    suspend fun resolve(request: WebPanelTargetResolutionRequest): WebPanelTargetResolutionResult {
        val accessRecord = when (val result = webPanelAccessRepository.get(request.webPanelAccessId)) {
            is RepositoryResult.Success -> result.value
            RepositoryResult.NotFound -> return unresolved(WebPanelTargetUnresolvedReason.WEB_PANEL_ACCESS_NOT_FOUND)
            is RepositoryResult.ConstraintConflict,
            is RepositoryResult.StaleRevision,
            -> return conflict(WebPanelTargetConflictReason.REPOSITORY_READ_CONFLICT)
            is RepositoryResult.Corruption -> return WebPanelTargetResolutionResult.Corruption
            is RepositoryResult.StorageFailure -> return WebPanelTargetResolutionResult.StorageFailure
        }
        if (accessRecord.value.id != request.webPanelAccessId) {
            return WebPanelTargetResolutionResult.Corruption
        }

        return when (val link = accessRecord.value.installationLink) {
            WebPanelInstallationLink.Standalone -> resolveStandalone(
                request = request,
                accessRevision = accessRecord.revision,
                route = accessRecord.value.route,
            )
            is WebPanelInstallationLink.Linked -> resolveLinked(
                request = request,
                accessRevision = accessRecord.revision,
                installationId = link.installationId,
                route = accessRecord.value.route,
                linkedSshRemoteHost = request.linkedSshRemoteHost,
            )
        }
    }

    private suspend fun resolveStandalone(
        request: WebPanelTargetResolutionRequest,
        accessRevision: RecordRevision,
        route: WebPanelRoute,
    ): WebPanelTargetResolutionResult {
        val details = request.standaloneTarget
            ?: return unresolved(WebPanelTargetUnresolvedReason.STANDALONE_TARGET_DETAILS_REQUIRED)

        return when (route) {
            is WebPanelRoute.Direct -> {
                if (details !is StandaloneWebPanelTargetDetails.Direct) {
                    return conflict(WebPanelTargetConflictReason.STANDALONE_ROUTE_DETAILS_MISMATCH)
                }
                val host = hostOrNull(route.originHost)
                    ?: return conflict(WebPanelTargetConflictReason.INVALID_DIRECT_ORIGIN_HOST)
                val path = basePathOrNull(details.webBasePath)
                    ?: return conflict(WebPanelTargetConflictReason.INVALID_WEB_BASE_PATH)
                if (details.port !in 1..65535) {
                    return conflict(WebPanelTargetConflictReason.INVALID_PANEL_PORT)
                }
                resolved(
                    request = request,
                    accessRevision = accessRevision,
                    installation = ResolvedWebPanelInstallation.Standalone,
                    routeTarget = ResolvedWebPanelRouteTarget.Direct(
                        DirectWebPanelOrigin(
                            scheme = request.scheme,
                            host = host,
                            port = details.port,
                            webBasePath = path,
                        ),
                    ),
                )
            }

            is WebPanelRoute.SshTunnel -> {
                if (details !is StandaloneWebPanelTargetDetails.SshTunnel) {
                    return conflict(WebPanelTargetConflictReason.STANDALONE_ROUTE_DETAILS_MISMATCH)
                }
                val serverAccess = when (val read = readServerAccess(route.serverAccessId)) {
                    is ExactRead.Value -> read.value
                    is ExactRead.Failure -> return read.result
                }
                when (val read = readServer(serverAccess.serverId, WebPanelTargetUnresolvedReason.SSH_SERVER_NOT_FOUND)) {
                    is ExactRead.Value -> Unit
                    is ExactRead.Failure -> return read.result
                }
                val host = hostOrNull(details.remoteHost)
                    ?: return conflict(WebPanelTargetConflictReason.INVALID_SSH_REMOTE_HOST)
                val path = basePathOrNull(details.webBasePath)
                    ?: return conflict(WebPanelTargetConflictReason.INVALID_WEB_BASE_PATH)
                if (details.port !in 1..65535) {
                    return conflict(WebPanelTargetConflictReason.INVALID_PANEL_PORT)
                }
                resolved(
                    request = request,
                    accessRevision = accessRevision,
                    installation = ResolvedWebPanelInstallation.Standalone,
                    routeTarget = ResolvedWebPanelRouteTarget.SshTunnel(
                        serverAccessId = route.serverAccessId,
                        serverId = serverAccess.serverId,
                        remoteEndpoint = WebPanelRemoteEndpoint(host, details.port),
                        scheme = request.scheme,
                        webBasePath = path,
                    ),
                )
            }
        }
    }

    private suspend fun resolveLinked(
        request: WebPanelTargetResolutionRequest,
        accessRevision: RecordRevision,
        installationId: XuiInstallationId,
        route: WebPanelRoute,
        linkedSshRemoteHost: String?,
    ): WebPanelTargetResolutionResult {
        if (request.standaloneTarget != null) {
            return conflict(WebPanelTargetConflictReason.STANDALONE_DETAILS_FOR_LINKED_ACCESS)
        }

        val installationRecord = when (val result = installationRepository.get(installationId)) {
            is RepositoryResult.Success -> result.value
            RepositoryResult.NotFound -> return unresolved(WebPanelTargetUnresolvedReason.LINKED_INSTALLATION_NOT_FOUND)
            is RepositoryResult.ConstraintConflict,
            is RepositoryResult.StaleRevision,
            -> return conflict(WebPanelTargetConflictReason.REPOSITORY_READ_CONFLICT)
            is RepositoryResult.Corruption -> return WebPanelTargetResolutionResult.Corruption
            is RepositoryResult.StorageFailure -> return WebPanelTargetResolutionResult.StorageFailure
        }
        val installation = installationRecord.value
        if (installation.id != installationId) return WebPanelTargetResolutionResult.Corruption

        when (val read = readServer(installation.serverId, WebPanelTargetUnresolvedReason.LINKED_SERVER_NOT_FOUND)) {
            is ExactRead.Value -> Unit
            is ExactRead.Failure -> return read.result
        }

        val path = basePathOrNull(installation.baseline.webBasePath)
            ?: return conflict(WebPanelTargetConflictReason.INVALID_WEB_BASE_PATH)
        val panelPort = installation.baseline.panelPort
        if (panelPort !in 1..65535) return conflict(WebPanelTargetConflictReason.INVALID_PANEL_PORT)
        val resolvedInstallation = ResolvedWebPanelInstallation.Linked(
            installationId = installation.id,
            installationRevision = installationRecord.revision,
            serverId = installation.serverId,
        )

        return when (route) {
            is WebPanelRoute.Direct -> {
                val host = hostOrNull(route.originHost)
                    ?: return conflict(WebPanelTargetConflictReason.INVALID_DIRECT_ORIGIN_HOST)
                resolved(
                    request = request,
                    accessRevision = accessRevision,
                    installation = resolvedInstallation,
                    routeTarget = ResolvedWebPanelRouteTarget.Direct(
                        DirectWebPanelOrigin(
                            scheme = request.scheme,
                            host = host,
                            port = panelPort,
                            webBasePath = path,
                        ),
                    ),
                )
            }

            is WebPanelRoute.SshTunnel -> {
                val serverAccess = when (val read = readServerAccess(route.serverAccessId)) {
                    is ExactRead.Value -> read.value
                    is ExactRead.Failure -> return read.result
                }
                if (serverAccess.serverId != installation.serverId) {
                    return conflict(WebPanelTargetConflictReason.SSH_SERVER_SCOPE_MISMATCH)
                }

                val listenAddress = installation.baseline.listenAddress
                val usableSavedAddress = !listenAddress.isNullOrBlank() && !isKnownWildcardBindAddress(listenAddress)
                // Explicit override is admitted only for an unresolved wildcard/blank listener.
                // It must name the VPS's loopback; no arbitrary SSH remote redirect.
                val chosenAddress = if (usableSavedAddress) {
                    if (linkedSshRemoteHost != null && linkedSshRemoteHost != listenAddress) {
                        return conflict(WebPanelTargetConflictReason.INVALID_SSH_REMOTE_HOST)
                    }
                    requireNotNull(listenAddress)
                } else {
                    if (linkedSshRemoteHost == null) {
                        return unresolved(WebPanelTargetUnresolvedReason.SSH_REMOTE_HOST_UNRESOLVED)
                    }
                    if (linkedSshRemoteHost !in setOf("127.0.0.1", "localhost", "[::1]")) {
                        return conflict(WebPanelTargetConflictReason.INVALID_SSH_REMOTE_HOST)
                    }
                    linkedSshRemoteHost
                }
                val host = hostOrNull(chosenAddress)
                    ?: return conflict(WebPanelTargetConflictReason.INVALID_SSH_REMOTE_HOST)

                resolved(
                    request = request,
                    accessRevision = accessRevision,
                    installation = resolvedInstallation,
                    routeTarget = ResolvedWebPanelRouteTarget.SshTunnel(
                        serverAccessId = route.serverAccessId,
                        serverId = installation.serverId,
                        remoteEndpoint = WebPanelRemoteEndpoint(host, panelPort),
                        scheme = request.scheme,
                        webBasePath = path,
                    ),
                )
            }
        }
    }

    private sealed interface ExactRead<out T> {
        data class Value<T>(val value: T) : ExactRead<T>
        data class Failure(val result: WebPanelTargetResolutionResult) : ExactRead<Nothing>
    }

    private suspend fun readServerAccess(serverAccessId: ServerAccessId): ExactRead<ServerAccess> =
        when (val result = serverAccessRepository.get(serverAccessId)) {
            is RepositoryResult.Success -> if (result.value.id == serverAccessId) {
                ExactRead.Value(result.value)
            } else {
                ExactRead.Failure(WebPanelTargetResolutionResult.Corruption)
            }
            RepositoryResult.NotFound -> ExactRead.Failure(
                unresolved(WebPanelTargetUnresolvedReason.SSH_SERVER_ACCESS_NOT_FOUND),
            )
            is RepositoryResult.ConstraintConflict,
            is RepositoryResult.StaleRevision,
            -> ExactRead.Failure(conflict(WebPanelTargetConflictReason.REPOSITORY_READ_CONFLICT))
            is RepositoryResult.Corruption -> ExactRead.Failure(WebPanelTargetResolutionResult.Corruption)
            is RepositoryResult.StorageFailure -> ExactRead.Failure(WebPanelTargetResolutionResult.StorageFailure)
        }

    private suspend fun readServer(
        serverId: ServerId,
        notFoundReason: WebPanelTargetUnresolvedReason,
    ): ExactRead<Server> = when (val result = serverRepository.get(serverId)) {
        is RepositoryResult.Success -> if (result.value.value.id == serverId) {
            ExactRead.Value(result.value.value)
        } else {
            ExactRead.Failure(WebPanelTargetResolutionResult.Corruption)
        }
        RepositoryResult.NotFound -> ExactRead.Failure(unresolved(notFoundReason))
        is RepositoryResult.ConstraintConflict,
        is RepositoryResult.StaleRevision,
        -> ExactRead.Failure(conflict(WebPanelTargetConflictReason.REPOSITORY_READ_CONFLICT))
        is RepositoryResult.Corruption -> ExactRead.Failure(WebPanelTargetResolutionResult.Corruption)
        is RepositoryResult.StorageFailure -> ExactRead.Failure(WebPanelTargetResolutionResult.StorageFailure)
    }

    private fun resolved(
        request: WebPanelTargetResolutionRequest,
        accessRevision: RecordRevision,
        installation: ResolvedWebPanelInstallation,
        routeTarget: ResolvedWebPanelRouteTarget,
    ) = WebPanelTargetResolutionResult.Resolved(
        ResolvedWebPanelTarget(
            webPanelAccessId = request.webPanelAccessId,
            webPanelAccessRevision = accessRevision,
            installation = installation,
            routeTarget = routeTarget,
        ),
    )

    private fun hostOrNull(value: String): WebPanelHost? = try {
        WebPanelHost(value)
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun basePathOrNull(value: String): WebPanelBasePath? = try {
        WebPanelBasePath(value)
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun unresolved(reason: WebPanelTargetUnresolvedReason) = WebPanelTargetResolutionResult.Unresolved(reason)
    private fun conflict(reason: WebPanelTargetConflictReason) = WebPanelTargetResolutionResult.Conflict(reason)

    private fun isKnownWildcardBindAddress(value: String): Boolean {
        val host = unwrapIpv6BracketsOrNull(value) ?: value
        return host == "*" || host == "0.0.0.0" || isIpv6Unspecified(host)
    }
}

private fun isValidWebPanelBasePath(value: String): Boolean {
    if (value.isBlank() || value != value.trim() || value.length > 1024 || !value.startsWith('/')) return false
    if (value.contains("//") || '\\' in value || '?' in value || '#' in value) return false
    if (value.any { it.isWhitespace() || it == '\u0000' || it == '\n' || it == '\r' }) return false
    return value.split('/').none { it == "." || it == ".." }
}

private fun isValidWebPanelHost(value: String): Boolean {
    if (value.isBlank() || value != value.trim() || value.length > 255) return false
    if (value.any { it.isWhitespace() || it == '\u0000' || it == '\n' || it == '\r' }) return false
    if ("://" in value || '/' in value || '?' in value || '#' in value || '@' in value) return false
    if (value == "*") return false

    val bracketed = value.startsWith('[') || value.endsWith(']')
    val host = if (bracketed) unwrapIpv6BracketsOrNull(value) ?: return false else value

    return when {
        ':' in host -> isValidIpv6Literal(host) && !isIpv6Unspecified(host)
        host.all { it.isDigit() || it == '.' } -> isValidIpv4Literal(host) && host != "0.0.0.0"
        bracketed -> false
        else -> isValidDnsHost(host)
    }
}

private fun unwrapIpv6BracketsOrNull(value: String): String? =
    if (value.length >= 4 && value.startsWith('[') && value.endsWith(']')) {
        value.substring(1, value.length - 1)
    } else {
        null
    }

private fun isValidIpv4Literal(value: String): Boolean {
    val parts = value.split('.')
    if (parts.size != 4) return false
    return parts.all { part ->
        part.isNotEmpty() &&
            part.length <= 3 &&
            part.all(Char::isDigit) &&
            (part.toIntOrNull() ?: 256) in 0..255
    }
}

private fun isValidIpv6Literal(value: String): Boolean {
    if (value.isEmpty() || '%' in value || value.count { it == ':' } < 2) return false
    if (value.indexOf("::") != value.lastIndexOf("::")) return false

    val compressed = "::" in value
    val parts = value.split(':')
    var groups = 0
    for ((index, part) in parts.withIndex()) {
        if (part.isEmpty()) continue
        val isLast = index == parts.lastIndex
        if ('.' in part) {
            if (!isLast || !isValidIpv4Literal(part)) return false
            groups += 2
        } else {
            if (part.length !in 1..4 || !part.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return false
            groups += 1
        }
    }
    return if (compressed) groups < 8 else groups == 8
}

private fun isIpv6Unspecified(value: String): Boolean {
    if (!isValidIpv6Literal(value)) return false
    val compact = value.replace(":", "").replace(".", "")
    return compact.all { it == '0' }
}

private fun isValidDnsHost(value: String): Boolean {
    if (value.length > 253 || value.startsWith('.') || value.endsWith('.')) return false
    val labels = value.split('.')
    return labels.all { label ->
        label.length in 1..63 &&
            label[0].isLetterOrDigit() &&
            label[label.lastIndex].isLetterOrDigit() &&
            label.all { (it.isLetterOrDigit() || it == '-') && it.code < 128 }
    }
}
