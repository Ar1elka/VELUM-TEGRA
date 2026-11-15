package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean

/**
 * One-shot continuation for exactly one later retry inside the same reconnect sequence.
 *
 * The token carries no mutable target/access/owner override. A retry always re-resolves the same
 * persisted ServerAccessId and reuses the same exact Operation owner and connectivity permit.
 */
class ExactReconnectRetryPermit internal constructor(
    val operationId: OperationId,
    val generation: Long,
    val nextAttemptNumber: Int,
    internal val admission: RecoveryRuntimeAdmission,
    internal val reconnectPermit: ReconnectPermit,
    internal val budget: RetryBudget,
    internal val sequenceStartedNanos: Long,
) {
    private val consumed = AtomicBoolean(false)

    internal fun tryConsume(): Boolean = consumed.compareAndSet(false, true)
}

enum class ReconnectPreparationFailureKind {
    ACCESS_STORAGE_FAILURE,
    ACCESS_CORRUPTION,
    ACCESS_CONTRACT_VIOLATION,
    TRANSPORT_CONTRACT_VIOLATION,
    SESSION_ID_COLLISION,
}

sealed interface ExactReconnectResult {
    data class Connected(
        val binding: SessionBinding,
        val attemptNumber: Int,
        val installation: SessionInstallResult,
    ) : ExactReconnectResult

    data object WaitForNetwork : ExactReconnectResult
    data object StaleConnectivityGeneration : ExactReconnectResult
    data object AlreadyScheduledForGeneration : ExactReconnectResult
    data object AdmissionLost : ExactReconnectResult
    data object RetryPermitAlreadyConsumed : ExactReconnectResult

    data class RecoveryBlocked(
        val reason: RecoveryBlockReason,
        val transportFailure: SshConnectFailure? = null,
    ) : ExactReconnectResult

    data class PreparationFailed(
        val kind: ReconnectPreparationFailureKind,
        val reason: String,
    ) : ExactReconnectResult

    data class RetryPermitted(
        val failure: SshConnectFailure,
        val permit: ExactReconnectRetryPermit,
    ) : ExactReconnectResult

    data class Failed(
        val failure: SshConnectFailure,
        val retryDecision: RetryDecision.Denied,
    ) : ExactReconnectResult
}

/**
 * Exact-owner transport orchestration for one admitted recovery runtime.
 *
 * This component establishes only a fresh SSH transport. It executes no remote command, advances no
 * OperationJournal state and performs no feature reconciliation. RECONNECT_EXACT_OWNER and
 * RECONCILE_READ_ONLY are both transport-capable plans; what happens after a successful transport is
 * intentionally left to later coordinator/feature policy.
 *
 * A reconnect sequence is linearized by one connectivity permit. Retry continuations are one-shot
 * and remain bound to that permit, so a newer connectivity generation invalidates all stale retry
 * work. Every attempt re-resolves the exact persisted ServerAccessId; no latest/first/fallback access
 * lookup exists.
 */
class ExactReconnectOrchestrator(
    private val runtimeRegistry: OperationRuntimeLeaseRegistry,
    private val connectivityGate: ConnectivityReconnectPermitGate,
    private val accessRepository: ServerAccessRepository,
    private val connectionFactory: SshConnectionFactory,
    private val sessionRegistry: ExactSessionRegistry,
    private val nanoTime: () -> Long = System::nanoTime,
) {
    suspend fun begin(
        admission: RecoveryRuntimeAdmission,
        observation: ConnectivityObservation,
        budget: RetryBudget,
    ): ExactReconnectResult {
        if (!isTransportCapable(admission.plan.action)) {
            return ExactReconnectResult.PreparationFailed(
                kind = ReconnectPreparationFailureKind.ACCESS_CONTRACT_VIOLATION,
                reason = "Recovery admission action does not authorize transport establishment",
            )
        }
        if (!runtimeRegistry.isCurrent(admission.runtimeLease)) {
            return ExactReconnectResult.AdmissionLost
        }

        val reconnectPermit = when (val result = connectivityGate.tryPermit(admission.plan.operationId, observation)) {
            is ReconnectPermitResult.Permitted -> result.permit
            ReconnectPermitResult.WaitForNetwork -> return ExactReconnectResult.WaitForNetwork
            ReconnectPermitResult.StaleGeneration -> return ExactReconnectResult.StaleConnectivityGeneration
            ReconnectPermitResult.AlreadyPermittedForGeneration -> {
                return ExactReconnectResult.AlreadyScheduledForGeneration
            }
        }

        return attempt(
            AttemptState(
                admission = admission,
                reconnectPermit = reconnectPermit,
                budget = budget,
                attemptNumber = 1,
                sequenceStartedNanos = nanoTime(),
            ),
        )
    }

    suspend fun retry(permit: ExactReconnectRetryPermit): ExactReconnectResult {
        if (!permit.tryConsume()) {
            return ExactReconnectResult.RetryPermitAlreadyConsumed
        }
        return attempt(
            AttemptState(
                admission = permit.admission,
                reconnectPermit = permit.reconnectPermit,
                budget = permit.budget,
                attemptNumber = permit.nextAttemptNumber,
                sequenceStartedNanos = permit.sequenceStartedNanos,
            ),
        )
    }

    private suspend fun attempt(state: AttemptState): ExactReconnectResult {
        if (!runtimeRegistry.isCurrent(state.admission.runtimeLease)) {
            return ExactReconnectResult.AdmissionLost
        }
        if (connectivityGate.status(state.reconnectPermit) != ReconnectPermitStatus.CURRENT) {
            return ExactReconnectResult.StaleConnectivityGeneration
        }

        val access = when (val result = accessRepository.get(state.admission.plan.target.serverAccessId)) {
            is RepositoryResult.Success -> result.value
            RepositoryResult.NotFound -> {
                return ExactReconnectResult.RecoveryBlocked(RecoveryBlockReason.EXACT_ACCESS_MISSING)
            }
            is RepositoryResult.Corruption -> {
                return ExactReconnectResult.PreparationFailed(
                    kind = ReconnectPreparationFailureKind.ACCESS_CORRUPTION,
                    reason = result.reason,
                )
            }
            is RepositoryResult.StorageFailure -> {
                return ExactReconnectResult.PreparationFailed(
                    kind = ReconnectPreparationFailureKind.ACCESS_STORAGE_FAILURE,
                    reason = result.reason,
                )
            }
            else -> {
                return ExactReconnectResult.PreparationFailed(
                    kind = ReconnectPreparationFailureKind.ACCESS_CONTRACT_VIOLATION,
                    reason = "Exact ServerAccess lookup returned ${result::class.simpleName}",
                )
            }
        }

        validateExactAccess(state.admission, access)?.let { return it }

        // Repository I/O may have allowed a newer network observation or local cancellation to win.
        if (!runtimeRegistry.isCurrent(state.admission.runtimeLease)) {
            return ExactReconnectResult.AdmissionLost
        }
        if (connectivityGate.status(state.reconnectPermit) != ReconnectPermitStatus.CURRENT) {
            return ExactReconnectResult.StaleConnectivityGeneration
        }

        val owner = SessionOwner.Operation(state.admission.plan.operationId)
        return when (val connect = connectionFactory.connect(access, owner)) {
            is SshConnectResult.Failed -> handleConnectFailure(state, connect.failure)
            is SshConnectResult.Connected -> publishConnected(state, access, owner, connect.handle)
        }
    }

    private fun handleConnectFailure(
        state: AttemptState,
        failure: SshConnectFailure,
    ): ExactReconnectResult {
        if (!runtimeRegistry.isCurrent(state.admission.runtimeLease)) {
            return ExactReconnectResult.AdmissionLost
        }
        if (connectivityGate.status(state.reconnectPermit) != ReconnectPermitStatus.CURRENT) {
            return ExactReconnectResult.StaleConnectivityGeneration
        }

        recoveryBlockFor(failure)?.let {
            return ExactReconnectResult.RecoveryBlocked(
                reason = it,
                transportFailure = failure,
            )
        }

        val decision = SshConnectRetryPolicy.evaluate(
            failure = failure,
            budget = state.budget,
            progress = RetryProgress(
                attemptsStarted = state.attemptNumber,
                elapsed = elapsedSince(state.sequenceStartedNanos),
            ),
        )
        return when (decision) {
            is RetryDecision.Denied -> ExactReconnectResult.Failed(failure, decision)
            is RetryDecision.PermitNextAttempt -> ExactReconnectResult.RetryPermitted(
                failure = failure,
                permit = ExactReconnectRetryPermit(
                    operationId = state.admission.plan.operationId,
                    generation = state.reconnectPermit.generation,
                    nextAttemptNumber = decision.nextAttemptNumber,
                    admission = state.admission,
                    reconnectPermit = state.reconnectPermit,
                    budget = state.budget,
                    sequenceStartedNanos = state.sequenceStartedNanos,
                ),
            )
        }
    }

    private fun publishConnected(
        state: AttemptState,
        access: ServerAccess,
        owner: SessionOwner.Operation,
        handle: com.velumtegra.xuimobile.core.ssh.SshSessionHandle,
    ): ExactReconnectResult {
        val binding = handle.binding
        if (binding.owner != owner || binding.serverAccessId != access.id) {
            handle.close()
            return ExactReconnectResult.PreparationFailed(
                kind = ReconnectPreparationFailureKind.TRANSPORT_CONTRACT_VIOLATION,
                reason = "SSH factory returned a session bound to a different exact owner/access",
            )
        }

        if (!runtimeRegistry.isCurrent(state.admission.runtimeLease)) {
            handle.close()
            return ExactReconnectResult.AdmissionLost
        }
        if (connectivityGate.status(state.reconnectPermit) != ReconnectPermitStatus.CURRENT) {
            handle.close()
            return ExactReconnectResult.StaleConnectivityGeneration
        }

        val installation = sessionRegistry.install(handle)
        if (installation is SessionInstallResult.SessionIdCollisionRejected) {
            return ExactReconnectResult.PreparationFailed(
                kind = ReconnectPreparationFailureKind.SESSION_ID_COLLISION,
                reason = "Fresh reconnect SessionId collided with an already-published live session",
            )
        }

        // Close/remove exactly this newly installed SessionId if it became stale during publication.
        if (!runtimeRegistry.isCurrent(state.admission.runtimeLease)) {
            sessionRegistry.remove(owner, access.id, binding.sessionId, close = true)
            return ExactReconnectResult.AdmissionLost
        }
        if (connectivityGate.status(state.reconnectPermit) != ReconnectPermitStatus.CURRENT) {
            sessionRegistry.remove(owner, access.id, binding.sessionId, close = true)
            return ExactReconnectResult.StaleConnectivityGeneration
        }

        return ExactReconnectResult.Connected(
            binding = binding,
            attemptNumber = state.attemptNumber,
            installation = installation,
        )
    }

    private fun validateExactAccess(
        admission: RecoveryRuntimeAdmission,
        access: ServerAccess,
    ): ExactReconnectResult.PreparationFailed? {
        val target = admission.plan.target
        if (access.id != target.serverAccessId) {
            return ExactReconnectResult.PreparationFailed(
                kind = ReconnectPreparationFailureKind.ACCESS_CONTRACT_VIOLATION,
                reason = "ServerAccessRepository returned a different ServerAccessId for exact lookup",
            )
        }
        if (access.serverId != target.serverId) {
            return ExactReconnectResult.PreparationFailed(
                kind = ReconnectPreparationFailureKind.ACCESS_CORRUPTION,
                reason = "Exact ServerAccess no longer belongs to the persisted target ServerId",
            )
        }
        return null
    }

    private fun recoveryBlockFor(failure: SshConnectFailure): RecoveryBlockReason? = when (failure) {
        // SshConnectFailure.SecretUnavailable intentionally conflates exact NotFound with other
        // SecretStore unavailability, so this layer must not overclaim REQUIRED_SECRET_MISSING.
        // It remains a typed non-retryable credential failure unless an earlier exact prerequisite
        // established NotFound directly.
        is SshConnectFailure.HostIdentityMismatch -> RecoveryBlockReason.HOST_IDENTITY_MISMATCH
        SshConnectFailure.AuthenticationRejected -> RecoveryBlockReason.AUTHENTICATION_REJECTED
        else -> null
    }

    private fun elapsedSince(startedNanos: Long): Duration {
        val delta = nanoTime() - startedNanos
        return if (delta <= 0L) Duration.ZERO else Duration.ofNanos(delta)
    }

    private fun isTransportCapable(action: RecoveryAction): Boolean =
        action == RecoveryAction.RECONNECT_EXACT_OWNER || action == RecoveryAction.RECONCILE_READ_ONLY

    private data class AttemptState(
        val admission: RecoveryRuntimeAdmission,
        val reconnectPermit: ReconnectPermit,
        val budget: RetryBudget,
        val attemptNumber: Int,
        val sequenceStartedNanos: Long,
    )
}
