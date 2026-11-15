package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.core.ssh.SshTimeoutPhase
import java.time.Duration

enum class RetryFailureCategory {
    TRANSIENT_TRANSPORT,
    INVALID_CONFIGURATION,
    CREDENTIAL_UNAVAILABLE,
    CREDENTIAL_CORRUPT,
    CREDENTIAL_STORAGE_FAILURE,
    HOST_IDENTITY_MISMATCH,
    AUTHENTICATION_REJECTED,
    ALGORITHM_NEGOTIATION_REJECTED,
    CANCELLED,
    UNEXPECTED_FAILURE,
    UNSAFE_TIMEOUT_PHASE,
}

sealed interface RetryFailureClassification {
    val category: RetryFailureCategory

    data class Retryable(
        override val category: RetryFailureCategory,
    ) : RetryFailureClassification

    data class NotRetryable(
        override val category: RetryFailureCategory,
    ) : RetryFailureClassification
}

/**
 * Conservative classifier for one bounded SSH connect attempt.
 *
 * Only explicit transient transport/environment failures enter automatic retry. Trust, auth,
 * credential, exact-configuration and algorithm-policy failures fail closed. Timeout phases that
 * should never describe a connect result also fail closed instead of being reinterpreted as a
 * generic network problem.
 */
object SshConnectRetryClassifier {
    fun classify(failure: SshConnectFailure): RetryFailureClassification = when (failure) {
        is SshConnectFailure.Timeout -> when (failure.phase) {
            SshTimeoutPhase.TCP_CONNECT,
            SshTimeoutPhase.HANDSHAKE_OR_AUTH,
            -> RetryFailureClassification.Retryable(RetryFailureCategory.TRANSIENT_TRANSPORT)

            SshTimeoutPhase.CHANNEL_OPEN,
            SshTimeoutPhase.COMMAND_EXECUTION,
            -> RetryFailureClassification.NotRetryable(RetryFailureCategory.UNSAFE_TIMEOUT_PHASE)
        }

        is SshConnectFailure.Unreachable ->
            RetryFailureClassification.Retryable(RetryFailureCategory.TRANSIENT_TRANSPORT)

        is SshConnectFailure.InvalidConfiguration ->
            RetryFailureClassification.NotRetryable(RetryFailureCategory.INVALID_CONFIGURATION)

        is SshConnectFailure.SecretUnavailable ->
            RetryFailureClassification.NotRetryable(RetryFailureCategory.CREDENTIAL_UNAVAILABLE)

        is SshConnectFailure.SecretCorrupt ->
            RetryFailureClassification.NotRetryable(RetryFailureCategory.CREDENTIAL_CORRUPT)

        is SshConnectFailure.SecretStorageFailure ->
            RetryFailureClassification.NotRetryable(RetryFailureCategory.CREDENTIAL_STORAGE_FAILURE)

        is SshConnectFailure.HostIdentityMismatch ->
            RetryFailureClassification.NotRetryable(RetryFailureCategory.HOST_IDENTITY_MISMATCH)

        SshConnectFailure.AuthenticationRejected ->
            RetryFailureClassification.NotRetryable(RetryFailureCategory.AUTHENTICATION_REJECTED)

        is SshConnectFailure.NegotiationFailure ->
            RetryFailureClassification.NotRetryable(RetryFailureCategory.ALGORITHM_NEGOTIATION_REJECTED)

        SshConnectFailure.Cancelled ->
            RetryFailureClassification.NotRetryable(RetryFailureCategory.CANCELLED)

        is SshConnectFailure.Unexpected ->
            RetryFailureClassification.NotRetryable(RetryFailureCategory.UNEXPECTED_FAILURE)
    }
}

/**
 * Finite budget for one logical reconnect sequence.
 *
 * [maxAttempts] is the total number of connection attempts, including the initial attempt. A value
 * of 1 therefore permits no retry. [maxElapsed] is an optional second bound measured by the caller
 * with a monotonic clock; reaching either bound closes the budget.
 */
data class RetryBudget(
    val maxAttempts: Int,
    val maxElapsed: Duration? = null,
) {
    init {
        require(maxAttempts > 0) { "maxAttempts must be > 0" }
        require(maxAttempts <= MAX_ATTEMPTS) { "maxAttempts must be <= $MAX_ATTEMPTS" }
        maxElapsed?.let {
            require(!it.isZero && !it.isNegative) { "maxElapsed must be > 0 when present" }
            require(it <= MAX_ELAPSED) { "maxElapsed must be <= $MAX_ELAPSED" }
        }
    }

    companion object {
        const val MAX_ATTEMPTS: Int = 100
        val MAX_ELAPSED: Duration = Duration.ofDays(1)
    }
}

/** Inputs captured after one failed connection attempt. */
data class RetryProgress(
    val attemptsStarted: Int,
    val elapsed: Duration,
) {
    init {
        require(attemptsStarted > 0) { "attemptsStarted must include the failed attempt and be > 0" }
        require(!elapsed.isNegative) { "elapsed must be >= 0" }
    }
}

enum class RetryDeniedReason {
    FAILURE_NOT_RETRYABLE,
    ATTEMPT_LIMIT_REACHED,
    DEADLINE_REACHED,
}

sealed interface RetryDecision {
    data class PermitNextAttempt(
        val nextAttemptNumber: Int,
        val failureCategory: RetryFailureCategory,
    ) : RetryDecision

    data class Denied(
        val reason: RetryDeniedReason,
        val failureCategory: RetryFailureCategory,
    ) : RetryDecision
}

/**
 * Pure one-step retry policy. It schedules nothing and owns no clock, coroutine or backoff loop.
 *
 * A permit authorizes only one later exact connection attempt. It carries no target/access/owner
 * override, so retry cannot silently switch endpoint, credential, SessionOwner or trust policy.
 */
object SshConnectRetryPolicy {
    fun evaluate(
        failure: SshConnectFailure,
        budget: RetryBudget,
        progress: RetryProgress,
    ): RetryDecision {
        val classification = SshConnectRetryClassifier.classify(failure)
        if (classification is RetryFailureClassification.NotRetryable) {
            return RetryDecision.Denied(
                reason = RetryDeniedReason.FAILURE_NOT_RETRYABLE,
                failureCategory = classification.category,
            )
        }

        if (progress.attemptsStarted >= budget.maxAttempts) {
            return RetryDecision.Denied(
                reason = RetryDeniedReason.ATTEMPT_LIMIT_REACHED,
                failureCategory = classification.category,
            )
        }

        val maxElapsed = budget.maxElapsed
        if (maxElapsed != null && progress.elapsed >= maxElapsed) {
            return RetryDecision.Denied(
                reason = RetryDeniedReason.DEADLINE_REACHED,
                failureCategory = classification.category,
            )
        }

        return RetryDecision.PermitNextAttempt(
            nextAttemptNumber = progress.attemptsStarted + 1,
            failureCategory = classification.category,
        )
    }
}
