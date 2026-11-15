package com.velumtegra.xuimobile.core.webpanel

import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.WebPanelHost
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardHandle
import java.time.Duration

/** Internal network limits for one explicit WebPanel authentication attempt. They are not UI knobs. */
data class WebPanelAuthenticationConfig(
    val connectTimeout: Duration = Duration.ofSeconds(10),
    val readTimeout: Duration = Duration.ofSeconds(10),
    val writeTimeout: Duration = Duration.ofSeconds(10),
    val callTimeout: Duration = Duration.ofSeconds(20),
    val maxResponseBytes: Int = 64 * 1024,
) {
    init {
        listOf(connectTimeout, readTimeout, writeTimeout, callTimeout).forEach { timeout ->
            require(!timeout.isZero && !timeout.isNegative) { "WebPanel timeouts must be > 0" }
            require(timeout <= MAX_TIMEOUT) { "WebPanel timeouts must be <= $MAX_TIMEOUT" }
        }
        require(maxResponseBytes in 1..MAX_RESPONSE_BYTES) {
            "WebPanel maxResponseBytes must be in 1..$MAX_RESPONSE_BYTES"
        }
    }

    private companion object {
        val MAX_TIMEOUT: Duration = Duration.ofMinutes(2)
        const val MAX_RESPONSE_BYTES: Int = 1024 * 1024
    }
}

/** Route-specific physical transport. Neither variant may silently fall back to the other. */
sealed interface WebPanelAuthenticationTransport {
    data object Direct : WebPanelAuthenticationTransport

    /**
     * The forward is the physical TCP path. [authorityHost] remains the logical HTTP/TLS identity.
     * It stays explicit/process-local because Phase 7.2 deliberately did not persist or invent it.
     */
    data class SshTunnel(
        val forward: WebPanelLocalForwardHandle,
        val authorityHost: WebPanelHost,
        val pinnedCertificate: PinnedSshPanelCertificate? = null,
    ) : WebPanelAuthenticationTransport
}

/** Optional volatile second factor. It is never durable and its plaintext buffer is wipeable. */
class WebPanelSecondFactor private constructor(
    private val material: SecretMaterial,
) : AutoCloseable {
    companion object {
        fun fromBytes(source: ByteArray): WebPanelSecondFactor {
            require(source.isNotEmpty()) { "Second factor must not be empty" }
            require(source.size <= 128) { "Second factor is unexpectedly large" }
            return WebPanelSecondFactor(SecretMaterial.fromBytes(source))
        }
    }

    internal fun <T> useBytes(block: (ByteArray) -> T): T = material.useBytes(block)

    override fun close() = material.close()

    override fun toString(): String = "WebPanelSecondFactor([REDACTED])"
}

class WebPanelAuthenticationRequest(
    val target: ResolvedWebPanelTarget,
    val transport: WebPanelAuthenticationTransport,
    val secondFactor: WebPanelSecondFactor? = null,
    val config: WebPanelAuthenticationConfig = WebPanelAuthenticationConfig(),
    val credentialAuthority: suspend () -> Boolean = { true },
) {
    override fun toString(): String {
        val route = when (transport) {
            WebPanelAuthenticationTransport.Direct -> "DIRECT"
            is WebPanelAuthenticationTransport.SshTunnel -> "SSH_TUNNEL"
        }
        return "WebPanelAuthenticationRequest(target=$target, transport=$route, secondFactor=${if (secondFactor == null) "none" else "[REDACTED]"})"
    }
}

enum class WebPanelAuthenticationStage {
    BINDING,
    PREFLIGHT_CSRF,
    PREFLIGHT_TWO_FACTOR,
    CREDENTIAL_SECRET,
    LOGIN,
}

enum class WebPanelAuthenticationFailure {
    WEB_PANEL_ACCESS_NOT_FOUND,
    WEB_PANEL_ACCESS_IDENTITY_MISMATCH,
    WEB_PANEL_ACCESS_REVISION_CHANGED,
    WEB_PANEL_ACCESS_READ_CONFLICT,
    WEB_PANEL_ACCESS_CORRUPTION,
    WEB_PANEL_ACCESS_STORAGE_FAILURE,
    ROUTE_TRANSPORT_MISMATCH,
    FORWARD_NOT_OPEN,
    FORWARD_TARGET_MISMATCH,
    FORWARD_OWNER_MISMATCH,
    FORWARD_SERVER_ACCESS_MISMATCH,
    PASSWORD_SECRET_NOT_FOUND,
    PASSWORD_SECRET_UNAVAILABLE,
    PASSWORD_SECRET_CORRUPT,
    PASSWORD_SECRET_STORAGE_FAILURE,
    SECOND_FACTOR_REQUIRED,
    SECOND_FACTOR_INVALID,
    HTTP_STATUS_FAILURE,
    PROTOCOL_INCOMPATIBLE,
    RESPONSE_TOO_LARGE,
    TLS_FAILURE,
    NETWORK_FAILURE,
    AUTHENTICATION_REJECTED,
    LOGIN_OUTCOME_UNKNOWN,
    AUTHENTICATED_SESSION_COOKIE_MISSING,
    CANCELLED,
}

enum class CredentialSubmissionState {
    NOT_STARTED,
    STARTED,
    REJECTED,
    ACCEPTED,
    OUTCOME_UNKNOWN,
}

data class WebPanelAuthenticationFailureEvidence(
    val stage: WebPanelAuthenticationStage,
    val failure: WebPanelAuthenticationFailure,
    val credentialSubmission: CredentialSubmissionState,
)

sealed interface WebPanelAuthenticationResult {
    data class Authenticated(val session: WebPanelAuthenticatedSession) : WebPanelAuthenticationResult
    data class Failed(val evidence: WebPanelAuthenticationFailureEvidence) : WebPanelAuthenticationResult
}

/** Opaque process-local authenticated state. Raw cookies, CSRF material and client state are not exposed. */
interface WebPanelAuthenticatedSession : AutoCloseable {
    val webPanelAccessId: WebPanelAccessId
    val target: ResolvedWebPanelTarget
    val isOpen: Boolean

    override fun close()
}

interface WebPanelAuthenticationClient {
    suspend fun authenticate(request: WebPanelAuthenticationRequest): WebPanelAuthenticationResult
}
