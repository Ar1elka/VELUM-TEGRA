package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionOwner
import java.time.Duration

/** Internal transport limits. These are not UI settings. */
data class SshTransportConfig(
    val tcpConnectTimeout: Duration = Duration.ofSeconds(10),
    val handshakeAndAuthTimeout: Duration = Duration.ofSeconds(15),
    val channelOpenTimeout: Duration = Duration.ofSeconds(10),
    val commandExecutionTimeout: Duration = Duration.ofSeconds(30),
    val stdoutCaptureLimitBytes: Int = 256 * 1024,
    val stderrCaptureLimitBytes: Int = 256 * 1024,
) {
    init {
        requirePositiveBounded(tcpConnectTimeout, "TCP connect timeout")
        requirePositiveBounded(handshakeAndAuthTimeout, "Handshake/auth timeout")
        requirePositiveBounded(channelOpenTimeout, "Channel-open timeout")
        requirePositiveBounded(commandExecutionTimeout, "Command-execution timeout")
        require(stdoutCaptureLimitBytes in 1..MAX_CAPTURE_BYTES) {
            "stdout capture limit must be in 1..$MAX_CAPTURE_BYTES bytes"
        }
        require(stderrCaptureLimitBytes in 1..MAX_CAPTURE_BYTES) {
            "stderr capture limit must be in 1..$MAX_CAPTURE_BYTES bytes"
        }
    }

    companion object {
        private val MAX_TIMEOUT: Duration = Duration.ofMinutes(30)
        const val MAX_CAPTURE_BYTES: Int = 4 * 1024 * 1024

        private fun requirePositiveBounded(value: Duration, label: String) {
            require(!value.isZero && !value.isNegative && value <= MAX_TIMEOUT) {
                "$label must be > 0 and <= $MAX_TIMEOUT"
            }
        }
    }
}

/**
 * SSH exec remains a remote shell command string. Raw text is deliberately redacted from toString().
 * Business modules remain responsible for safe command construction/quoting.
 */
class RemoteCommand private constructor(
    private val raw: String,
    val redactedLabel: String,
) {
    companion object {
        fun create(raw: String, redactedLabel: String = "remote-exec"): RemoteCommand {
            require(raw.isNotBlank()) { "Remote command must not be blank" }
            require(redactedLabel.isNotBlank()) { "Remote command label must not be blank" }
            return RemoteCommand(raw, redactedLabel)
        }
    }

    internal fun rawForTransport(): String = raw

    override fun toString(): String = "RemoteCommand(label=$redactedLabel, raw=[REDACTED])"
}

enum class CommandDispatchState {
    NOT_DISPATCHED,
    DISPATCHED,
}

/** Defensive output capture. Raw bytes are never included in toString(). */
class CapturedOutput private constructor(
    source: ByteArray,
    val truncated: Boolean,
) {
    private val bytes: ByteArray = source.copyOf()

    val sizeBytes: Int
        get() = bytes.size

    fun copyBytes(): ByteArray = bytes.copyOf()

    override fun toString(): String = "CapturedOutput(sizeBytes=$sizeBytes, truncated=$truncated, bytes=[REDACTED])"

    companion object {
        fun of(source: ByteArray, truncated: Boolean): CapturedOutput = CapturedOutput(source, truncated)
        val EMPTY: CapturedOutput = CapturedOutput(ByteArray(0), truncated = false)
    }
}

data class SshCommandResult(
    val dispatchState: CommandDispatchState,
    val completion: CommandCompletion,
    val stdout: CapturedOutput,
    val stderr: CapturedOutput,
)

enum class SshTimeoutPhase {
    TCP_CONNECT,
    HANDSHAKE_OR_AUTH,
    CHANNEL_OPEN,
    COMMAND_EXECUTION,
}

sealed interface SshConnectFailure {
    data class InvalidConfiguration(val reason: String) : SshConnectFailure
    data class SecretUnavailable(val reason: String) : SshConnectFailure
    data class SecretCorrupt(val reason: String) : SshConnectFailure
    data class SecretStorageFailure(val reason: String) : SshConnectFailure
    data class Timeout(val phase: SshTimeoutPhase) : SshConnectFailure
    data class Unreachable(val reason: String) : SshConnectFailure
    data class NegotiationFailure(val reason: String) : SshConnectFailure
    data class HostIdentityMismatch(
        val expectedFingerprint: String,
        val presentedFingerprint: String?,
    ) : SshConnectFailure
    data object AuthenticationRejected : SshConnectFailure
    data object Cancelled : SshConnectFailure
    data class Unexpected(val reason: String) : SshConnectFailure
}

sealed interface SshConnectResult {
    data class Connected(val handle: SshSessionHandle) : SshConnectResult
    data class Failed(val failure: SshConnectFailure) : SshConnectResult
}

/** One exact physical SSH session. Implementations must make close() idempotent. */
interface VerifiedHostKeySshSessionHandle : SshSessionHandle {
    /** SHA-256 digest of the host key proven during this exact SSH handshake, lowercase hex. */
    val verifiedHostKeySha256: String
}

interface SshSessionHandle : AutoCloseable {
    val binding: SessionBinding
    val isOpen: Boolean

    suspend fun execute(
        command: RemoteCommand,
        config: SshTransportConfig = SshTransportConfig(),
    ): SshCommandResult

    override fun close()
}

/** Stateless one-attempt connection factory. Retry/backoff remains outside core:ssh. */
interface SshConnectionFactory {
    suspend fun connect(
        access: ServerAccess,
        owner: SessionOwner,
        config: SshTransportConfig = SshTransportConfig(),
    ): SshConnectResult
}
