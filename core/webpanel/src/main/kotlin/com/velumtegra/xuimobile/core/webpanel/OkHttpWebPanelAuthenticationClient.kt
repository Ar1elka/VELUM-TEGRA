package com.velumtegra.xuimobile.core.webpanel

import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelRouteTarget
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.domain.VersionedRecord
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.core.domain.WebPanelHost
import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardHandle
import java.io.IOException
import java.net.InetAddress
import java.net.Proxy
import java.nio.charset.StandardCharsets
import java.util.Arrays
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLException
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okio.BufferedSink
import kotlin.coroutines.resume

private val FORM_MEDIA_TYPE = "application/x-www-form-urlencoded".toMediaType()
private val EMPTY_NON_CREDENTIAL_BODY = object : RequestBody() {
    override fun contentType() = FORM_MEDIA_TYPE
    override fun contentLength(): Long = 0L
    override fun writeTo(sink: BufferedSink) = Unit
}

/**
 * Phase 7.4 implementation for the reviewed current 3X-UI login protocol.
 * Bounded preflight is allowed, but credentials are carried by one non-replayable request body only.
 */
class OkHttpWebPanelAuthenticationClient internal constructor(
    private val webPanelAccessRepository: WebPanelAccessRepository,
    private val secretStore: SecretStore,
    private val callFactory: (OkHttpClient, Request) -> Call,
) : WebPanelAuthenticationClient {
    constructor(
        webPanelAccessRepository: WebPanelAccessRepository,
        secretStore: SecretStore,
    ) : this(webPanelAccessRepository, secretStore, { client, request -> client.newCall(request) })
    override suspend fun authenticate(request: WebPanelAuthenticationRequest): WebPanelAuthenticationResult {
        val initialAccess = when (val read = readExactAccess(request.target)) {
            is AccessRead.Found -> read.record
            is AccessRead.Failed -> return failed(WebPanelAuthenticationStage.BINDING, read.failure)
        }
        val endpoint = when (val binding = bindEndpoint(request, initialAccess.value)) {
            is EndpointBinding.Bound -> binding.value
            is EndpointBinding.Failed -> return failed(WebPanelAuthenticationStage.BINDING, binding.failure)
        }

        val cookieJar = InMemoryPanelCookieJar()
        val client = buildClient(request.config, endpoint, cookieJar,
            (request.transport as? WebPanelAuthenticationTransport.SshTunnel)?.pinnedCertificate)
        var clientOwnershipTransferred = false

        try {
            val csrfRequest = endpoint.applyHostHeader(
                Request.Builder().url(endpoint.urlFor("csrf-token")).get().build(),
            )
            val csrf = when (val step = executeJsonStep(client, csrfRequest, request.config)) {
                is StepResult.Json -> parseCsrf(step.objectValue)
                    ?: return closeAndFail(
                        client,
                        cookieJar,
                        WebPanelAuthenticationStage.PREFLIGHT_CSRF,
                        WebPanelAuthenticationFailure.PROTOCOL_INCOMPATIBLE,
                    )
                is StepResult.Failed -> return closeAndFail(
                    client,
                    cookieJar,
                    WebPanelAuthenticationStage.PREFLIGHT_CSRF,
                    step.failure,
                )
            }

            val twoFactorRequest = endpoint.applyHostHeader(
                Request.Builder()
                    .url(endpoint.urlFor("getTwoFactorEnable"))
                    .header(CSRF_HEADER, csrf)
                    .post(EMPTY_NON_CREDENTIAL_BODY)
                    .build(),
            )
            val twoFactorEnabled = when (val step = executeJsonStep(client, twoFactorRequest, request.config)) {
                is StepResult.Json -> parseTwoFactor(step.objectValue)
                    ?: return closeAndFail(
                        client,
                        cookieJar,
                        WebPanelAuthenticationStage.PREFLIGHT_TWO_FACTOR,
                        WebPanelAuthenticationFailure.PROTOCOL_INCOMPATIBLE,
                    )
                is StepResult.Failed -> return closeAndFail(
                    client,
                    cookieJar,
                    WebPanelAuthenticationStage.PREFLIGHT_TWO_FACTOR,
                    step.failure,
                )
            }
            if (twoFactorEnabled && request.secondFactor == null) {
                return closeAndFail(
                    client,
                    cookieJar,
                    WebPanelAuthenticationStage.PREFLIGHT_TWO_FACTOR,
                    WebPanelAuthenticationFailure.SECOND_FACTOR_REQUIRED,
                )
            }
            if (twoFactorEnabled && request.secondFactor != null && !request.secondFactor.isUsableTotp()) {
                return closeAndFail(
                    client,
                    cookieJar,
                    WebPanelAuthenticationStage.PREFLIGHT_TWO_FACTOR,
                    WebPanelAuthenticationFailure.SECOND_FACTOR_INVALID,
                )
            }

            // Preflight can suspend. Re-read the exact revision before reading or submitting its password secret.
            val finalAccess = when (val read = readExactAccess(request.target)) {
                is AccessRead.Found -> read.record
                is AccessRead.Failed -> return closeAndFail(
                    client,
                    cookieJar,
                    WebPanelAuthenticationStage.BINDING,
                    read.failure,
                )
            }
            if (finalAccess.value != initialAccess.value) {
                return closeAndFail(
                    client,
                    cookieJar,
                    WebPanelAuthenticationStage.BINDING,
                    WebPanelAuthenticationFailure.WEB_PANEL_ACCESS_CORRUPTION,
                )
            }

            if (!request.credentialAuthority()) return closeAndFail(client, cookieJar,
                WebPanelAuthenticationStage.BINDING, WebPanelAuthenticationFailure.WEB_PANEL_ACCESS_REVISION_CHANGED)
            val password = when (val secret = secretStore.read(finalAccess.value.passwordSecretId)) {
                is SecretReadResult.Found -> secret.material
                SecretReadResult.NotFound -> return closeAndFail(
                    client,
                    cookieJar,
                    WebPanelAuthenticationStage.CREDENTIAL_SECRET,
                    WebPanelAuthenticationFailure.PASSWORD_SECRET_NOT_FOUND,
                )
                is SecretReadResult.Unavailable -> return closeAndFail(
                    client,
                    cookieJar,
                    WebPanelAuthenticationStage.CREDENTIAL_SECRET,
                    WebPanelAuthenticationFailure.PASSWORD_SECRET_UNAVAILABLE,
                )
                is SecretReadResult.Corrupt -> return closeAndFail(
                    client,
                    cookieJar,
                    WebPanelAuthenticationStage.CREDENTIAL_SECRET,
                    WebPanelAuthenticationFailure.PASSWORD_SECRET_CORRUPT,
                )
                is SecretReadResult.StorageFailure -> return closeAndFail(
                    client,
                    cookieJar,
                    WebPanelAuthenticationStage.CREDENTIAL_SECRET,
                    WebPanelAuthenticationFailure.PASSWORD_SECRET_STORAGE_FAILURE,
                )
            }

            val loginBody = try {
                password.useBytes { passwordBytes ->
                    if (twoFactorEnabled) {
                        request.secondFactor!!.useBytes { secondFactorBytes ->
                            OneShotFormBody.create(finalAccess.value.username, passwordBytes, secondFactorBytes)
                        }
                    } else {
                        OneShotFormBody.create(finalAccess.value.username, passwordBytes, null)
                    }
                }
            } finally {
                password.close()
            }

            val authenticatedCookieUrl = endpoint.urlFor("panel/")
            val authCookieGenerationBeforeLogin =
                cookieJar.latestMatchingGeneration(AUTH_COOKIE_NAME, authenticatedCookieUrl)
            val loginRequest = endpoint.applyHostHeader(
                Request.Builder()
                    .url(endpoint.urlFor("login"))
                    .header(CSRF_HEADER, csrf)
                    .post(loginBody)
                    .build(),
            )
            val loginStep = try {
                executeJsonStep(client, loginRequest, request.config)
            } finally {
                loginBody.close()
            }

            when (loginStep) {
                is StepResult.Failed -> {
                    val writeStarted = loginBody.writeStarted
                    val state = if (writeStarted) {
                        CredentialSubmissionState.OUTCOME_UNKNOWN
                    } else {
                        CredentialSubmissionState.NOT_STARTED
                    }
                    val failure = if (writeStarted && loginStep.failure in AMBIGUOUS_AFTER_SUBMISSION) {
                        WebPanelAuthenticationFailure.LOGIN_OUTCOME_UNKNOWN
                    } else {
                        loginStep.failure
                    }
                    return closeAndFail(client, cookieJar, WebPanelAuthenticationStage.LOGIN, failure, state)
                }
                is StepResult.Json -> {
                    val success = parseSuccess(loginStep.objectValue)
                        ?: return closeAndFail(
                            client,
                            cookieJar,
                            WebPanelAuthenticationStage.LOGIN,
                            WebPanelAuthenticationFailure.PROTOCOL_INCOMPATIBLE,
                            if (loginBody.writeStarted) {
                                CredentialSubmissionState.STARTED
                            } else {
                                CredentialSubmissionState.NOT_STARTED
                            },
                        )
                    if (!success) {
                        return closeAndFail(
                            client,
                            cookieJar,
                            WebPanelAuthenticationStage.LOGIN,
                            WebPanelAuthenticationFailure.AUTHENTICATION_REJECTED,
                            CredentialSubmissionState.REJECTED,
                        )
                    }
                }
            }

            if (!cookieJar.hasMatchingCookieWrittenAfter(
                    AUTH_COOKIE_NAME,
                    authenticatedCookieUrl,
                    authCookieGenerationBeforeLogin,
                )
            ) {
                return closeAndFail(
                    client,
                    cookieJar,
                    WebPanelAuthenticationStage.LOGIN,
                    WebPanelAuthenticationFailure.AUTHENTICATED_SESSION_COOKIE_MISSING,
                    CredentialSubmissionState.OUTCOME_UNKNOWN,
                )
            }

            val session = OkHttpWebPanelAuthenticatedSession(request.target, client, cookieJar, endpoint, request.config.maxResponseBytes, callFactory)
            clientOwnershipTransferred = true
            return WebPanelAuthenticationResult.Authenticated(session)
        } finally {
            // Coroutine cancellation may bypass typed StepResult returns. The attempt still owns cleanup
            // until a successful session transfer, so no client/cookie state can leak from an abandoned attempt.
            if (!clientOwnershipTransferred) {
                closeAttemptResources(client, cookieJar)
            }
        }
    }

    private suspend fun readExactAccess(target: ResolvedWebPanelTarget): AccessRead =
        when (val result = webPanelAccessRepository.get(target.webPanelAccessId)) {
            is RepositoryResult.Success -> {
                val record = result.value
                when {
                    record.value.id != target.webPanelAccessId -> AccessRead.Failed(WebPanelAuthenticationFailure.WEB_PANEL_ACCESS_IDENTITY_MISMATCH)
                    record.revision != target.webPanelAccessRevision -> AccessRead.Failed(WebPanelAuthenticationFailure.WEB_PANEL_ACCESS_REVISION_CHANGED)
                    else -> AccessRead.Found(record)
                }
            }
            RepositoryResult.NotFound -> AccessRead.Failed(WebPanelAuthenticationFailure.WEB_PANEL_ACCESS_NOT_FOUND)
            is RepositoryResult.ConstraintConflict, is RepositoryResult.StaleRevision -> AccessRead.Failed(WebPanelAuthenticationFailure.WEB_PANEL_ACCESS_READ_CONFLICT)
            is RepositoryResult.Corruption -> AccessRead.Failed(WebPanelAuthenticationFailure.WEB_PANEL_ACCESS_CORRUPTION)
            is RepositoryResult.StorageFailure -> AccessRead.Failed(WebPanelAuthenticationFailure.WEB_PANEL_ACCESS_STORAGE_FAILURE)
        }

    private fun bindEndpoint(request: WebPanelAuthenticationRequest, access: WebPanelAccess): EndpointBinding {
        val accessRoute = access.route
        return when (val routeTarget = request.target.routeTarget) {
            is ResolvedWebPanelRouteTarget.Direct -> {
                if (request.transport != WebPanelAuthenticationTransport.Direct || accessRoute !is WebPanelRoute.Direct) {
                    EndpointBinding.Failed(WebPanelAuthenticationFailure.ROUTE_TRANSPORT_MISMATCH)
                } else if (accessRoute.originHost != routeTarget.origin.host.value) {
                    EndpointBinding.Failed(WebPanelAuthenticationFailure.WEB_PANEL_ACCESS_CORRUPTION)
                } else {
                    EndpointBinding.Bound(
                        PhysicalEndpoint.direct(
                            routeTarget.origin.scheme,
                            routeTarget.origin.host,
                            routeTarget.origin.port,
                            routeTarget.origin.webBasePath.value,
                        ),
                    )
                }
            }
            is ResolvedWebPanelRouteTarget.SshTunnel -> {
                val transport = request.transport as? WebPanelAuthenticationTransport.SshTunnel
                    ?: return EndpointBinding.Failed(WebPanelAuthenticationFailure.ROUTE_TRANSPORT_MISMATCH)
                if (accessRoute !is WebPanelRoute.SshTunnel || accessRoute.serverAccessId != routeTarget.serverAccessId) {
                    return EndpointBinding.Failed(WebPanelAuthenticationFailure.ROUTE_TRANSPORT_MISMATCH)
                }
                if (transport.pinnedCertificate?.permits(request) == false) {
                    return EndpointBinding.Failed(WebPanelAuthenticationFailure.ROUTE_TRANSPORT_MISMATCH)
                }
                validateForward(request.target, transport.forward, routeTarget)?.let {
                    return EndpointBinding.Failed(it)
                }
                EndpointBinding.Bound(
                    PhysicalEndpoint.tunneled(
                        routeTarget.scheme,
                        transport.authorityHost,
                        transport.forward.localEndpoint.port,
                        routeTarget.remoteEndpoint.port,
                        routeTarget.webBasePath.value,
                    ),
                )
            }
        }
    }

    private fun validateForward(
        target: ResolvedWebPanelTarget,
        forward: WebPanelLocalForwardHandle,
        routeTarget: ResolvedWebPanelRouteTarget.SshTunnel,
    ): WebPanelAuthenticationFailure? {
        if (!forward.isOpen) return WebPanelAuthenticationFailure.FORWARD_NOT_OPEN
        if (forward.target != target) return WebPanelAuthenticationFailure.FORWARD_TARGET_MISMATCH
        val binding = forward.sessionBinding
        if (binding.owner != SessionOwner.WebPanel(target.webPanelAccessId)) return WebPanelAuthenticationFailure.FORWARD_OWNER_MISMATCH
        if (binding.serverAccessId != routeTarget.serverAccessId) return WebPanelAuthenticationFailure.FORWARD_SERVER_ACCESS_MISMATCH
        return null
    }

    private fun buildClient(
        config: WebPanelAuthenticationConfig,
        endpoint: PhysicalEndpoint,
        cookieJar: InMemoryPanelCookieJar,
        pin: PinnedSshPanelCertificate? = null,
    ): OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(config.connectTimeout.toMillis(), TimeUnit.MILLISECONDS)
        .readTimeout(config.readTimeout.toMillis(), TimeUnit.MILLISECONDS)
        .writeTimeout(config.writeTimeout.toMillis(), TimeUnit.MILLISECONDS)
        .callTimeout(config.callTimeout.toMillis(), TimeUnit.MILLISECONDS)
        .retryOnConnectionFailure(false)
        .followRedirects(false)
        .followSslRedirects(false)
        .proxy(Proxy.NO_PROXY)
        .protocols(listOf(Protocol.HTTP_1_1))
        .cookieJar(cookieJar)
        .dns(endpoint.dns)
        .scopedPanelPin(pin)
        .build()

    private suspend fun executeJsonStep(
        client: OkHttpClient,
        request: Request,
        config: WebPanelAuthenticationConfig,
    ): StepResult = suspendCancellableCoroutine { continuation ->
        val call = callFactory(client, request)
        continuation.invokeOnCancellation { call.cancel() }
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (!continuation.isActive) return
                continuation.resume(
                    StepResult.Failed(
                        when {
                            call.isCanceled() -> WebPanelAuthenticationFailure.CANCELLED
                            e.hasSslCause() -> WebPanelAuthenticationFailure.TLS_FAILURE
                            else -> WebPanelAuthenticationFailure.NETWORK_FAILURE
                        },
                    ),
                )
            }

            override fun onResponse(call: Call, response: Response) {
                val result = try {
                    response.use { current ->
                        if (current.code !in 200..299) {
                            StepResult.Failed(WebPanelAuthenticationFailure.HTTP_STATUS_FAILURE)
                        } else {
                            when (val body = current.readBoundedUtf8(config.maxResponseBytes)) {
                                BoundedBody.TooLarge -> StepResult.Failed(WebPanelAuthenticationFailure.RESPONSE_TOO_LARGE)
                                BoundedBody.InvalidUtf8 -> StepResult.Failed(WebPanelAuthenticationFailure.PROTOCOL_INCOMPATIBLE)
                                is BoundedBody.Text -> {
                                    val parsed = BoundedJson.parseObject(body.value)
                                    if (parsed == null) StepResult.Failed(WebPanelAuthenticationFailure.PROTOCOL_INCOMPATIBLE) else StepResult.Json(parsed)
                                }
                            }
                        }
                    }
                } catch (e: IOException) {
                    StepResult.Failed(if (e.hasSslCause()) WebPanelAuthenticationFailure.TLS_FAILURE else WebPanelAuthenticationFailure.NETWORK_FAILURE)
                }
                if (continuation.isActive) continuation.resume(result)
            }
        })
    }

    private fun parseCsrf(obj: BoundedJson.Value.Obj): String? {
        val success = (obj.fields["success"] as? BoundedJson.Value.Bool)?.value ?: return null
        if (!success) return null
        val token = (obj.fields["obj"] as? BoundedJson.Value.Str)?.value ?: return null
        return token.takeIf { it.isNotBlank() && it.length <= MAX_CSRF_CHARS && !it.hasHeaderControl() }
    }

    private fun parseTwoFactor(obj: BoundedJson.Value.Obj): Boolean? {
        val success = (obj.fields["success"] as? BoundedJson.Value.Bool)?.value ?: return null
        if (!success) return null
        return (obj.fields["obj"] as? BoundedJson.Value.Bool)?.value
    }

    private fun parseSuccess(obj: BoundedJson.Value.Obj): Boolean? =
        (obj.fields["success"] as? BoundedJson.Value.Bool)?.value

    private fun closeAndFail(
        client: OkHttpClient,
        cookieJar: InMemoryPanelCookieJar,
        stage: WebPanelAuthenticationStage,
        failure: WebPanelAuthenticationFailure,
        credentialState: CredentialSubmissionState = CredentialSubmissionState.NOT_STARTED,
    ): WebPanelAuthenticationResult.Failed {
        closeAttemptResources(client, cookieJar)
        return failed(stage, failure, credentialState)
    }

    private fun failed(
        stage: WebPanelAuthenticationStage,
        failure: WebPanelAuthenticationFailure,
        state: CredentialSubmissionState = CredentialSubmissionState.NOT_STARTED,
    ) = WebPanelAuthenticationResult.Failed(WebPanelAuthenticationFailureEvidence(stage, failure, state))

    private sealed interface AccessRead {
        data class Found(val record: VersionedRecord<WebPanelAccess>) : AccessRead
        data class Failed(val failure: WebPanelAuthenticationFailure) : AccessRead
    }

    private sealed interface EndpointBinding {
        data class Bound(val value: PhysicalEndpoint) : EndpointBinding
        data class Failed(val failure: WebPanelAuthenticationFailure) : EndpointBinding
    }

    private sealed interface StepResult {
        data class Json(val objectValue: BoundedJson.Value.Obj) : StepResult
        data class Failed(val failure: WebPanelAuthenticationFailure) : StepResult
    }

    private companion object {
        const val CSRF_HEADER = "X-CSRF-Token"
        const val AUTH_COOKIE_NAME = "3x-ui"
        const val MAX_CSRF_CHARS = 4096
        val AMBIGUOUS_AFTER_SUBMISSION = setOf(
            WebPanelAuthenticationFailure.NETWORK_FAILURE,
            WebPanelAuthenticationFailure.CANCELLED,
            WebPanelAuthenticationFailure.TLS_FAILURE,
        )
    }
}

private class PhysicalEndpoint private constructor(
    private val scheme: WebPanelScheme,
    private val authorityHost: WebPanelHost,
    private val physicalPort: Int,
    private val originPort: Int,
    private val basePath: String,
    val dns: Dns,
    private val overrideHostHeader: Boolean,
) {
    fun urlFor(suffix: String): HttpUrl {
        val base = if (basePath.endsWith('/')) basePath else "$basePath/"
        val endpointPath = base + suffix.removePrefix("/")
        return HttpUrl.Builder()
            .scheme(if (scheme == WebPanelScheme.HTTPS) "https" else "http")
            .host(authorityHost.asHttpHost())
            .port(physicalPort)
            .encodedPath(endpointPath)
            .build()
    }

    fun applyHostHeader(request: Request): Request = if (overrideHostHeader) {
        request.newBuilder().header("Host", authorityHost.asAuthorityHeader(originPort)).build()
    } else {
        request
    }

    companion object {
        fun direct(
            scheme: WebPanelScheme,
            authorityHost: WebPanelHost,
            port: Int,
            basePath: String,
        ) = PhysicalEndpoint(scheme, authorityHost, port, port, basePath, Dns.SYSTEM, false)

        fun tunneled(
            scheme: WebPanelScheme,
            authorityHost: WebPanelHost,
            localPort: Int,
            originPort: Int,
            basePath: String,
        ) = PhysicalEndpoint(
            scheme,
            authorityHost,
            localPort,
            originPort,
            basePath,
            ExactLoopbackDns(authorityHost.asHttpHost()),
            true,
        )
    }
}

private class ExactLoopbackDns(private val authorityHost: String) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        if (!hostname.equals(authorityHost, ignoreCase = true)) {
            throw java.net.UnknownHostException("Unexpected WebPanel authority")
        }
        return listOf(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
    }

    override fun toString(): String = "ExactLoopbackDns(authority=[REDACTED])"
}

private class InMemoryPanelCookieJar : CookieJar {
    private data class StoredCookie(
        val cookie: Cookie,
        val generation: Long,
    )

    private val lock = Any()
    private val cookies = mutableListOf<StoredCookie>()
    private var generation = 0L

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) = synchronized(lock) {
        for (cookie in cookies) {
            this.cookies.removeAll { existing ->
                existing.cookie.name == cookie.name &&
                    existing.cookie.domain == cookie.domain &&
                    existing.cookie.path == cookie.path
            }
            if (cookie.expiresAt > System.currentTimeMillis()) {
                generation += 1L
                this.cookies += StoredCookie(cookie, generation)
            }
        }
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> = synchronized(lock) {
        val now = System.currentTimeMillis()
        cookies.removeAll { it.cookie.expiresAt <= now }
        cookies.filter { it.cookie.matches(url) }.map { it.cookie }
    }

    fun latestMatchingGeneration(name: String, url: HttpUrl): Long = synchronized(lock) {
        val now = System.currentTimeMillis()
        cookies.removeAll { it.cookie.expiresAt <= now }
        cookies.asSequence()
            .filter { it.cookie.name == name && it.cookie.matches(url) }
            .maxOfOrNull { it.generation }
            ?: 0L
    }

    fun hasMatchingCookieWrittenAfter(name: String, url: HttpUrl, generation: Long): Boolean = synchronized(lock) {
        val now = System.currentTimeMillis()
        cookies.removeAll { it.cookie.expiresAt <= now }
        cookies.any {
            it.generation > generation && it.cookie.name == name && it.cookie.matches(url)
        }
    }

    fun clear() = synchronized(lock) { cookies.clear() }

    override fun toString(): String = "InMemoryPanelCookieJar([REDACTED])"
}

private fun closeAttemptResources(client: OkHttpClient, cookieJar: InMemoryPanelCookieJar) {
    client.dispatcher.cancelAll()
    client.connectionPool.evictAll()
    cookieJar.clear()
}

private class OkHttpWebPanelAuthenticatedSession(
    override val target: ResolvedWebPanelTarget,
    private val client: OkHttpClient,
    private val cookieJar: InMemoryPanelCookieJar,
    private val endpoint: PhysicalEndpoint,
    private val maxBytes: Int,
    private val callFactory: (OkHttpClient, Request) -> Call,
) : WebPanelInboundReadSession, WebPanelServerStatusSession, WebPanelClientCountSession, WebPanelClientTrafficSession, WebPanelClientQuotaExpirySession, WebPanelInboundDetailsSession {
    private val open = AtomicBoolean(true)

    override val webPanelAccessId = target.webPanelAccessId
    override val isOpen: Boolean get() = open.get()
    private val reading = AtomicBoolean(false)

    /** One bounded GET on the authenticated client; never follows redirects or exposes raw JSON. */
    override suspend fun readInboundsOnce(): WebPanelInboundReadResult {
        fun failed(reason: WebPanelInboundReadFailure) = WebPanelInboundReadResult.Failed(reason)
        if (!open.get()) return failed(WebPanelInboundReadFailure.SESSION_CLOSED)
        if (!reading.compareAndSet(false, true)) return failed(WebPanelInboundReadFailure.HTTP_FAILURE)
        try {
            if (!open.get()) return failed(WebPanelInboundReadFailure.SESSION_CLOSED)
            val request = endpoint.applyHostHeader(
                Request.Builder().url(endpoint.urlFor("panel/api/inbounds/list")).get().build()
            )
            return suspendCancellableCoroutine { continuation ->
                val call = callFactory(client, request)
                continuation.invokeOnCancellation { call.cancel() }
                call.enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        if (!continuation.isActive) return
                        val reason = when {
                            call.isCanceled() -> WebPanelInboundReadFailure.CANCELLED
                            e.hasSslCause() -> WebPanelInboundReadFailure.TLS_FAILURE
                            else -> WebPanelInboundReadFailure.NETWORK_FAILURE
                        }
                        continuation.resume(failed(reason))
                    }
                    override fun onResponse(call: Call, response: Response) {
                        val result = try {
                            response.use { current ->
                                when {
                                    !open.get() -> failed(WebPanelInboundReadFailure.SESSION_CLOSED)
                                    current.code == 401 || current.code == 403 || current.code in 300..399 ->
                                        failed(WebPanelInboundReadFailure.AUTH_REQUIRED)
                                    current.code !in 200..299 -> failed(WebPanelInboundReadFailure.HTTP_FAILURE)
                                    else -> when (val body = current.readBoundedUtf8(maxBytes)) {
                                        BoundedBody.TooLarge -> failed(WebPanelInboundReadFailure.RESPONSE_TOO_LARGE)
                                        BoundedBody.InvalidUtf8 -> failed(WebPanelInboundReadFailure.PROTOCOL_INCOMPATIBLE)
                                        is BoundedBody.Text -> {
                                            val items = WebPanelInboundOverviewParser.parse(body.value)
                                            if (items == null) failed(WebPanelInboundReadFailure.PROTOCOL_INCOMPATIBLE)
                                            else WebPanelInboundReadResult.Success(items)
                                        }
                                    }
                                }
                            }
                        } catch (e: IOException) {
                            failed(if (e.hasSslCause()) WebPanelInboundReadFailure.TLS_FAILURE
                                else WebPanelInboundReadFailure.NETWORK_FAILURE)
                        } catch (_: RuntimeException) {
                            failed(WebPanelInboundReadFailure.PROTOCOL_INCOMPATIBLE)
                        }
                        if (continuation.isActive) continuation.resume(result)
                    }
                })
            }
        } finally {
            reading.set(false)
        }
    }

    /** One bounded client-count GET with redaction; no raw payload leaves this method. */
    override suspend fun readClientCountsOnce(): WebPanelClientCountResult {
        fun failed(reason: WebPanelClientCountFailure) = WebPanelClientCountResult.Failed(reason)
        if (!open.get()) return failed(WebPanelClientCountFailure.SESSION_CLOSED)
        if (!reading.compareAndSet(false, true)) return failed(WebPanelClientCountFailure.HTTP_FAILURE)
        try {
            if (!open.get()) return failed(WebPanelClientCountFailure.SESSION_CLOSED)
            val request = endpoint.applyHostHeader(
                Request.Builder().url(endpoint.urlFor("panel/api/inbounds/list")).get().build()
            )
            return suspendCancellableCoroutine { continuation ->
                val call = callFactory(client, request)
                continuation.invokeOnCancellation { call.cancel() }
                call.enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        if (!continuation.isActive) return
                        val reason = when {
                            call.isCanceled() -> WebPanelClientCountFailure.CANCELLED
                            e.hasSslCause() -> WebPanelClientCountFailure.TLS_FAILURE
                            else -> WebPanelClientCountFailure.NETWORK_FAILURE
                        }
                        continuation.resume(failed(reason))
                    }
                    override fun onResponse(call: Call, response: Response) {
                        val result = try {
                            response.use { current ->
                                when {
                                    !open.get() -> failed(WebPanelClientCountFailure.SESSION_CLOSED)
                                    current.code == 401 || current.code == 403 || current.code in 300..399 ->
                                        failed(WebPanelClientCountFailure.AUTH_REQUIRED)
                                    current.code !in 200..299 -> failed(WebPanelClientCountFailure.HTTP_FAILURE)
                                    else -> when (val body = current.readBoundedUtf8(maxBytes)) {
                                        BoundedBody.TooLarge -> failed(WebPanelClientCountFailure.RESPONSE_TOO_LARGE)
                                        BoundedBody.InvalidUtf8 -> failed(WebPanelClientCountFailure.PROTOCOL_INCOMPATIBLE)
                                        is BoundedBody.Text -> {
                                            val items = WebPanelClientCountParser.parse(body.value)
                                            if (items == null) failed(WebPanelClientCountFailure.PROTOCOL_INCOMPATIBLE)
                                            else WebPanelClientCountResult.Success(items)
                                        }
                                    }
                                }
                            }
                        } catch (e: IOException) {
                            failed(if (e.hasSslCause()) WebPanelClientCountFailure.TLS_FAILURE
                                else WebPanelClientCountFailure.NETWORK_FAILURE)
                        } catch (_: RuntimeException) {
                            failed(WebPanelClientCountFailure.PROTOCOL_INCOMPATIBLE)
                        }
                        if (continuation.isActive) continuation.resume(result)
                    }
                })
            }
        } finally {
            reading.set(false)
        }
    }

    /** One bounded client-traffic GET with redaction; no raw payload leaves this method. */
    override suspend fun readClientTrafficOnce(): WebPanelClientTrafficResult {
        fun failed(reason: WebPanelClientTrafficFailure) = WebPanelClientTrafficResult.Failed(reason)
        if (!open.get()) return failed(WebPanelClientTrafficFailure.SESSION_CLOSED)
        if (!reading.compareAndSet(false, true)) return failed(WebPanelClientTrafficFailure.HTTP_FAILURE)
        try {
            if (!open.get()) return failed(WebPanelClientTrafficFailure.SESSION_CLOSED)
            val request = endpoint.applyHostHeader(
                Request.Builder().url(endpoint.urlFor("panel/api/inbounds/list")).get().build()
            )
            return suspendCancellableCoroutine { continuation ->
                val call = callFactory(client, request)
                continuation.invokeOnCancellation { call.cancel() }
                call.enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        if (!continuation.isActive) return
                        val reason = when {
                            call.isCanceled() -> WebPanelClientTrafficFailure.CANCELLED
                            e.hasSslCause() -> WebPanelClientTrafficFailure.TLS_FAILURE
                            else -> WebPanelClientTrafficFailure.NETWORK_FAILURE
                        }
                        continuation.resume(failed(reason))
                    }
                    override fun onResponse(call: Call, response: Response) {
                        val result = try {
                            response.use { current ->
                                when {
                                    !open.get() -> failed(WebPanelClientTrafficFailure.SESSION_CLOSED)
                                    current.code == 401 || current.code == 403 || current.code in 300..399 ->
                                        failed(WebPanelClientTrafficFailure.AUTH_REQUIRED)
                                    current.code !in 200..299 -> failed(WebPanelClientTrafficFailure.HTTP_FAILURE)
                                    else -> when (val body = current.readBoundedUtf8(maxBytes)) {
                                        BoundedBody.TooLarge -> failed(WebPanelClientTrafficFailure.RESPONSE_TOO_LARGE)
                                        BoundedBody.InvalidUtf8 -> failed(WebPanelClientTrafficFailure.PROTOCOL_INCOMPATIBLE)
                                        is BoundedBody.Text -> {
                                            val items = WebPanelClientTrafficParser.parse(body.value)
                                            if (items == null) failed(WebPanelClientTrafficFailure.PROTOCOL_INCOMPATIBLE)
                                            else WebPanelClientTrafficResult.Success(items)
                                        }
                                    }
                                }
                            }
                        } catch (e: IOException) {
                            failed(if (e.hasSslCause()) WebPanelClientTrafficFailure.TLS_FAILURE
                                else WebPanelClientTrafficFailure.NETWORK_FAILURE)
                        } catch (_: RuntimeException) {
                            failed(WebPanelClientTrafficFailure.PROTOCOL_INCOMPATIBLE)
                        }
                        if (continuation.isActive) continuation.resume(result)
                    }
                })
            }
        } finally {
            reading.set(false)
        }
    }

    /** One bounded client-quota-expiry GET with redaction; no raw payload leaves this method. */
    override suspend fun readClientQuotaExpiryOnce(): WebPanelClientQuotaExpiryResult {
        fun failed(reason: WebPanelClientQuotaExpiryFailure) = WebPanelClientQuotaExpiryResult.Failed(reason)
        if (!open.get()) return failed(WebPanelClientQuotaExpiryFailure.SESSION_CLOSED)
        if (!reading.compareAndSet(false, true)) return failed(WebPanelClientQuotaExpiryFailure.HTTP_FAILURE)
        try {
            if (!open.get()) return failed(WebPanelClientQuotaExpiryFailure.SESSION_CLOSED)
            val request = endpoint.applyHostHeader(
                Request.Builder().url(endpoint.urlFor("panel/api/inbounds/list")).get().build()
            )
            return suspendCancellableCoroutine { continuation ->
                val call = callFactory(client, request)
                continuation.invokeOnCancellation { call.cancel() }
                call.enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        if (!continuation.isActive) return
                        val reason = when {
                            call.isCanceled() -> WebPanelClientQuotaExpiryFailure.CANCELLED
                            e.hasSslCause() -> WebPanelClientQuotaExpiryFailure.TLS_FAILURE
                            else -> WebPanelClientQuotaExpiryFailure.NETWORK_FAILURE
                        }
                        continuation.resume(failed(reason))
                    }
                    override fun onResponse(call: Call, response: Response) {
                        val result = try {
                            response.use { current ->
                                when {
                                    !open.get() -> failed(WebPanelClientQuotaExpiryFailure.SESSION_CLOSED)
                                    current.code == 401 || current.code == 403 || current.code in 300..399 ->
                                        failed(WebPanelClientQuotaExpiryFailure.AUTH_REQUIRED)
                                    current.code !in 200..299 -> failed(WebPanelClientQuotaExpiryFailure.HTTP_FAILURE)
                                    else -> when (val body = current.readBoundedUtf8(maxBytes)) {
                                        BoundedBody.TooLarge -> failed(WebPanelClientQuotaExpiryFailure.RESPONSE_TOO_LARGE)
                                        BoundedBody.InvalidUtf8 -> failed(WebPanelClientQuotaExpiryFailure.PROTOCOL_INCOMPATIBLE)
                                        is BoundedBody.Text -> {
                                            val items = WebPanelClientQuotaExpiryParser.parse(body.value)
                                            if (items == null) failed(WebPanelClientQuotaExpiryFailure.PROTOCOL_INCOMPATIBLE)
                                            else WebPanelClientQuotaExpiryResult.Success(items)
                                        }
                                    }
                                }
                            }
                        } catch (e: IOException) {
                            failed(if (e.hasSslCause()) WebPanelClientQuotaExpiryFailure.TLS_FAILURE
                                else WebPanelClientQuotaExpiryFailure.NETWORK_FAILURE)
                        } catch (_: RuntimeException) {
                            failed(WebPanelClientQuotaExpiryFailure.PROTOCOL_INCOMPATIBLE)
                        }
                        if (continuation.isActive) continuation.resume(result)
                    }
                })
            }
        } finally {
            reading.set(false)
        }
    }

    /** One bounded inbound-detail GET with redaction; no raw payload leaves this method. */
    override suspend fun readInboundDetailsOnce(): WebPanelInboundDetailsResult {
        fun failed(reason: WebPanelInboundDetailsFailure) = WebPanelInboundDetailsResult.Failed(reason)
        if (!open.get()) return failed(WebPanelInboundDetailsFailure.SESSION_CLOSED)
        if (!reading.compareAndSet(false, true)) return failed(WebPanelInboundDetailsFailure.HTTP_FAILURE)
        try {
            if (!open.get()) return failed(WebPanelInboundDetailsFailure.SESSION_CLOSED)
            val request = endpoint.applyHostHeader(
                Request.Builder().url(endpoint.urlFor("panel/api/inbounds/list")).get().build()
            )
            return suspendCancellableCoroutine { continuation ->
                val call = callFactory(client, request)
                continuation.invokeOnCancellation { call.cancel() }
                call.enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        if (!continuation.isActive) return
                        val reason = when {
                            call.isCanceled() -> WebPanelInboundDetailsFailure.CANCELLED
                            e.hasSslCause() -> WebPanelInboundDetailsFailure.TLS_FAILURE
                            else -> WebPanelInboundDetailsFailure.NETWORK_FAILURE
                        }
                        continuation.resume(failed(reason))
                    }
                    override fun onResponse(call: Call, response: Response) {
                        val result = try {
                            response.use { current ->
                                when {
                                    !open.get() -> failed(WebPanelInboundDetailsFailure.SESSION_CLOSED)
                                    current.code == 401 || current.code == 403 || current.code in 300..399 ->
                                        failed(WebPanelInboundDetailsFailure.AUTH_REQUIRED)
                                    current.code !in 200..299 -> failed(WebPanelInboundDetailsFailure.HTTP_FAILURE)
                                    else -> when (val body = current.readBoundedUtf8(maxBytes)) {
                                        BoundedBody.TooLarge -> failed(WebPanelInboundDetailsFailure.RESPONSE_TOO_LARGE)
                                        BoundedBody.InvalidUtf8 -> failed(WebPanelInboundDetailsFailure.PROTOCOL_INCOMPATIBLE)
                                        is BoundedBody.Text -> {
                                            val items = WebPanelInboundDetailsParser.parse(body.value)
                                            if (items == null) failed(WebPanelInboundDetailsFailure.PROTOCOL_INCOMPATIBLE)
                                            else WebPanelInboundDetailsResult.Success(items)
                                        }
                                    }
                                }
                            }
                        } catch (e: IOException) {
                            failed(if (e.hasSslCause()) WebPanelInboundDetailsFailure.TLS_FAILURE
                                else WebPanelInboundDetailsFailure.NETWORK_FAILURE)
                        } catch (_: RuntimeException) {
                            failed(WebPanelInboundDetailsFailure.PROTOCOL_INCOMPATIBLE)
                        }
                        if (continuation.isActive) continuation.resume(result)
                    }
                })
            }
        } finally {
            reading.set(false)
        }
    }

    /** One bounded status GET on the authenticated client; returns only a sanitized snapshot. */
    override suspend fun readServerStatusOnce(): WebPanelServerStatusResult {
        fun failed(reason: WebPanelServerStatusFailure) = WebPanelServerStatusResult.Failed(reason)
        if (!open.get()) return failed(WebPanelServerStatusFailure.SESSION_CLOSED)
        if (!reading.compareAndSet(false, true)) return failed(WebPanelServerStatusFailure.HTTP_FAILURE)
        try {
            if (!open.get()) return failed(WebPanelServerStatusFailure.SESSION_CLOSED)
            val request = endpoint.applyHostHeader(
                Request.Builder().url(endpoint.urlFor("panel/api/server/status")).get().build()
            )
            return suspendCancellableCoroutine { continuation ->
                val call = callFactory(client, request)
                continuation.invokeOnCancellation { call.cancel() }
                call.enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        if (!continuation.isActive) return
                        val reason = when {
                            call.isCanceled() -> WebPanelServerStatusFailure.CANCELLED
                            e.hasSslCause() -> WebPanelServerStatusFailure.TLS_FAILURE
                            else -> WebPanelServerStatusFailure.NETWORK_FAILURE
                        }
                        continuation.resume(failed(reason))
                    }
                    override fun onResponse(call: Call, response: Response) {
                        val result = try {
                            response.use { current ->
                                when {
                                    !open.get() -> failed(WebPanelServerStatusFailure.SESSION_CLOSED)
                                    current.code == 401 || current.code == 403 || current.code in 300..399 ->
                                        failed(WebPanelServerStatusFailure.AUTH_REQUIRED)
                                    current.code !in 200..299 -> failed(WebPanelServerStatusFailure.HTTP_FAILURE)
                                    else -> when (val body = current.readBoundedUtf8(maxBytes)) {
                                        BoundedBody.TooLarge -> failed(WebPanelServerStatusFailure.RESPONSE_TOO_LARGE)
                                        BoundedBody.InvalidUtf8 -> failed(WebPanelServerStatusFailure.PROTOCOL_INCOMPATIBLE)
                                        is BoundedBody.Text -> {
                                            val snapshot = WebPanelServerStatusParser.parse(body.value)
                                            if (snapshot == null) failed(WebPanelServerStatusFailure.PROTOCOL_INCOMPATIBLE)
                                            else WebPanelServerStatusResult.Success(snapshot)
                                        }
                                    }
                                }
                            }
                        } catch (e: IOException) {
                            failed(if (e.hasSslCause()) WebPanelServerStatusFailure.TLS_FAILURE
                                else WebPanelServerStatusFailure.NETWORK_FAILURE)
                        } catch (_: RuntimeException) {
                            failed(WebPanelServerStatusFailure.PROTOCOL_INCOMPATIBLE)
                        }
                        if (continuation.isActive) continuation.resume(result)
                    }
                })
            }
        } finally {
            reading.set(false)
        }
    }


    override fun close() {
        if (!open.compareAndSet(true, false)) return
        closeAttemptResources(client, cookieJar)
    }

    override fun toString(): String =
        "WebPanelAuthenticatedSession(webPanelAccessId=$webPanelAccessId, state=${if (isOpen) "OPEN" else "CLOSED"}, material=[REDACTED])"
}

internal class OneShotFormBody private constructor(
    private var bytes: ByteArray?,
) : RequestBody(), AutoCloseable {
    private val started = AtomicBoolean(false)
    val writeStarted: Boolean get() = started.get()

    override fun contentType() = FORM_MEDIA_TYPE
    override fun contentLength(): Long = bytes?.size?.toLong() ?: 0L
    override fun isOneShot(): Boolean = true

    override fun writeTo(sink: BufferedSink) {
        check(started.compareAndSet(false, true)) { "Credential body replay blocked" }
        val current = bytes ?: error("Credential body is closed")
        sink.write(current)
    }

    override fun close() {
        bytes?.let { Arrays.fill(it, 0) }
        bytes = null
    }

    override fun toString(): String = "OneShotFormBody([REDACTED])"

    companion object {
        private val USERNAME_FIELD = "username".encodeToByteArray()
        private val PASSWORD_FIELD = "password".encodeToByteArray()
        private val TWO_FACTOR_FIELD = "twoFactorCode".encodeToByteArray()

        fun create(username: String, password: ByteArray, secondFactor: ByteArray?): OneShotFormBody {
            val usernameBytes = username.encodeToByteArray()
            return try {
                val totalSize = fieldSize(USERNAME_FIELD, usernameBytes, first = true) +
                    fieldSize(PASSWORD_FIELD, password, first = false) +
                    (secondFactor?.let { fieldSize(TWO_FACTOR_FIELD, it, first = false) } ?: 0L)
                require(totalSize <= Int.MAX_VALUE.toLong()) { "Credential form body is too large" }

                val body = ByteArray(totalSize.toInt())
                var offset = 0
                offset = appendField(body, offset, USERNAME_FIELD, usernameBytes, first = true)
                offset = appendField(body, offset, PASSWORD_FIELD, password, first = false)
                if (secondFactor != null) {
                    offset = appendField(body, offset, TWO_FACTOR_FIELD, secondFactor, first = false)
                }
                check(offset == body.size) { "Credential form body size mismatch" }
                OneShotFormBody(body)
            } finally {
                Arrays.fill(usernameBytes, 0)
            }
        }

        private fun fieldSize(name: ByteArray, value: ByteArray, first: Boolean): Long =
            (if (first) 0L else 1L) + encodedSize(name) + 1L + encodedSize(value)

        private fun encodedSize(input: ByteArray): Long {
            var size = 0L
            for (raw in input) {
                val value = raw.toInt() and 0xff
                size += if (isFormSafe(value) || value == 0x20) 1L else 3L
            }
            return size
        }

        private fun appendField(
            output: ByteArray,
            initialOffset: Int,
            name: ByteArray,
            value: ByteArray,
            first: Boolean,
        ): Int {
            var offset = initialOffset
            if (!first) output[offset++] = '&'.code.toByte()
            offset = writeFormEncoded(output, offset, name)
            output[offset++] = '='.code.toByte()
            return writeFormEncoded(output, offset, value)
        }

        private fun writeFormEncoded(output: ByteArray, initialOffset: Int, input: ByteArray): Int {
            var offset = initialOffset
            for (raw in input) {
                val value = raw.toInt() and 0xff
                when {
                    value == 0x20 -> output[offset++] = '+'.code.toByte()
                    isFormSafe(value) -> output[offset++] = value.toByte()
                    else -> {
                        output[offset++] = '%'.code.toByte()
                        output[offset++] = HEX[value ushr 4].code.toByte()
                        output[offset++] = HEX[value and 0x0f].code.toByte()
                    }
                }
            }
            return offset
        }

        private fun isFormSafe(value: Int): Boolean =
            value in 'a'.code..'z'.code || value in 'A'.code..'Z'.code || value in '0'.code..'9'.code ||
                value == '-'.code || value == '_'.code || value == '.'.code || value == '*'.code

        private const val HEX = "0123456789ABCDEF"
    }
}

private sealed interface BoundedBody {
    data class Text(val value: String) : BoundedBody
    data object TooLarge : BoundedBody
    data object InvalidUtf8 : BoundedBody
}

private fun Response.readBoundedUtf8(maxBytes: Int): BoundedBody {
    val responseBody = body
    if (responseBody.contentLength() > maxBytes) return BoundedBody.TooLarge

    val input = responseBody.byteStream()
    val buffer = ByteArray(maxBytes + 1)
    var total = 0
    return try {
        while (true) {
            val count = input.read(buffer, total, buffer.size - total)
            if (count < 0) break
            total += count
            if (total > maxBytes) return BoundedBody.TooLarge
        }

        val decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        BoundedBody.Text(
            decoder.decode(java.nio.ByteBuffer.wrap(buffer, 0, total)).toString(),
        )
    } catch (_: java.nio.charset.CharacterCodingException) {
        BoundedBody.InvalidUtf8
    } finally {
        Arrays.fill(buffer, 0)
    }
}

private fun IOException.hasSslCause(): Boolean {
    var current: Throwable? = this
    repeat(8) {
        if (current is SSLException) return true
        current = current?.cause
    }
    return false
}

private fun String.hasHeaderControl(): Boolean = any { it == '\r' || it == '\n' || it == '\u0000' }

private fun WebPanelHost.asHttpHost(): String =
    if (value.length >= 4 && value.startsWith('[') && value.endsWith(']')) value.substring(1, value.length - 1) else value

private fun WebPanelHost.asAuthorityHeader(port: Int): String {
    val host = if (value.contains(':') && !value.startsWith('[')) "[$value]" else value
    return "$host:$port"
}

private fun WebPanelSecondFactor.isUsableTotp(): Boolean = useBytes { bytes ->
    bytes.size == 6 && bytes.all { raw -> (raw.toInt() and 0xff) in '0'.code..'9'.code }
}
