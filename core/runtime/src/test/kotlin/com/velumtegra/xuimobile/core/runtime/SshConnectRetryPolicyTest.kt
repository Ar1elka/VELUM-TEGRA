package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.core.ssh.SshTimeoutPhase
import java.time.Duration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SshConnectRetryPolicyTest {
    @Test
    fun `unreachable connect failure is retryable transient transport`() {
        assertEquals(
            RetryFailureClassification.Retryable(RetryFailureCategory.TRANSIENT_TRANSPORT),
            SshConnectRetryClassifier.classify(SshConnectFailure.Unreachable("NoRouteToHostException")),
        )
    }

    @Test
    fun `tcp and handshake timeouts are retryable but later timeout phases fail closed`() {
        assertEquals(
            RetryFailureClassification.Retryable(RetryFailureCategory.TRANSIENT_TRANSPORT),
            SshConnectRetryClassifier.classify(SshConnectFailure.Timeout(SshTimeoutPhase.TCP_CONNECT)),
        )
        assertEquals(
            RetryFailureClassification.Retryable(RetryFailureCategory.TRANSIENT_TRANSPORT),
            SshConnectRetryClassifier.classify(SshConnectFailure.Timeout(SshTimeoutPhase.HANDSHAKE_OR_AUTH)),
        )
        assertEquals(
            RetryFailureClassification.NotRetryable(RetryFailureCategory.UNSAFE_TIMEOUT_PHASE),
            SshConnectRetryClassifier.classify(SshConnectFailure.Timeout(SshTimeoutPhase.CHANNEL_OPEN)),
        )
        assertEquals(
            RetryFailureClassification.NotRetryable(RetryFailureCategory.UNSAFE_TIMEOUT_PHASE),
            SshConnectRetryClassifier.classify(SshConnectFailure.Timeout(SshTimeoutPhase.COMMAND_EXECUTION)),
        )
    }

    @Test
    fun `trust auth credentials configuration algorithm cancellation and unexpected failures never auto retry`() {
        val failures = listOf(
            SshConnectFailure.InvalidConfiguration("invalid exact access"),
            SshConnectFailure.SecretUnavailable("missing"),
            SshConnectFailure.SecretCorrupt("corrupt"),
            SshConnectFailure.SecretStorageFailure("storage"),
            SshConnectFailure.HostIdentityMismatch("expected", "presented"),
            SshConnectFailure.AuthenticationRejected,
            SshConnectFailure.NegotiationFailure("policy"),
            SshConnectFailure.Cancelled,
            SshConnectFailure.Unexpected("unexpected"),
        )

        failures.forEach { failure ->
            assertTrue(
                "Expected fail-closed classification for $failure",
                SshConnectRetryClassifier.classify(failure) is RetryFailureClassification.NotRetryable,
            )
        }
    }

    @Test
    fun `max attempts includes initial attempt and permits only remaining attempts`() {
        val budget = RetryBudget(maxAttempts = 3)
        val failure = SshConnectFailure.Unreachable("temporary")

        assertEquals(
            RetryDecision.PermitNextAttempt(2, RetryFailureCategory.TRANSIENT_TRANSPORT),
            SshConnectRetryPolicy.evaluate(failure, budget, RetryProgress(1, Duration.ZERO)),
        )
        assertEquals(
            RetryDecision.PermitNextAttempt(3, RetryFailureCategory.TRANSIENT_TRANSPORT),
            SshConnectRetryPolicy.evaluate(failure, budget, RetryProgress(2, Duration.ZERO)),
        )
        assertEquals(
            RetryDecision.Denied(
                RetryDeniedReason.ATTEMPT_LIMIT_REACHED,
                RetryFailureCategory.TRANSIENT_TRANSPORT,
            ),
            SshConnectRetryPolicy.evaluate(failure, budget, RetryProgress(3, Duration.ZERO)),
        )
    }

    @Test
    fun `single attempt budget permits no automatic retry`() {
        assertEquals(
            RetryDecision.Denied(
                RetryDeniedReason.ATTEMPT_LIMIT_REACHED,
                RetryFailureCategory.TRANSIENT_TRANSPORT,
            ),
            SshConnectRetryPolicy.evaluate(
                failure = SshConnectFailure.Timeout(SshTimeoutPhase.TCP_CONNECT),
                budget = RetryBudget(maxAttempts = 1),
                progress = RetryProgress(attemptsStarted = 1, elapsed = Duration.ZERO),
            ),
        )
    }

    @Test
    fun `elapsed deadline permits before boundary and denies at or after boundary`() {
        val budget = RetryBudget(maxAttempts = 5, maxElapsed = Duration.ofSeconds(30))
        val failure = SshConnectFailure.Unreachable("temporary")

        assertTrue(
            SshConnectRetryPolicy.evaluate(
                failure,
                budget,
                RetryProgress(1, Duration.ofMillis(29_999)),
            ) is RetryDecision.PermitNextAttempt,
        )
        assertEquals(
            RetryDecision.Denied(
                RetryDeniedReason.DEADLINE_REACHED,
                RetryFailureCategory.TRANSIENT_TRANSPORT,
            ),
            SshConnectRetryPolicy.evaluate(failure, budget, RetryProgress(1, Duration.ofSeconds(30))),
        )
        assertEquals(
            RetryDecision.Denied(
                RetryDeniedReason.DEADLINE_REACHED,
                RetryFailureCategory.TRANSIENT_TRANSPORT,
            ),
            SshConnectRetryPolicy.evaluate(failure, budget, RetryProgress(1, Duration.ofSeconds(31))),
        )
    }

    @Test
    fun `non retryable failure is denied even when budget has room`() {
        assertEquals(
            RetryDecision.Denied(
                RetryDeniedReason.FAILURE_NOT_RETRYABLE,
                RetryFailureCategory.HOST_IDENTITY_MISMATCH,
            ),
            SshConnectRetryPolicy.evaluate(
                failure = SshConnectFailure.HostIdentityMismatch("expected", "presented"),
                budget = RetryBudget(maxAttempts = 10, maxElapsed = Duration.ofMinutes(5)),
                progress = RetryProgress(attemptsStarted = 1, elapsed = Duration.ZERO),
            ),
        )
    }

    @Test
    fun `attempt limit wins before elapsed deadline when both are exhausted`() {
        assertEquals(
            RetryDecision.Denied(
                RetryDeniedReason.ATTEMPT_LIMIT_REACHED,
                RetryFailureCategory.TRANSIENT_TRANSPORT,
            ),
            SshConnectRetryPolicy.evaluate(
                failure = SshConnectFailure.Unreachable("temporary"),
                budget = RetryBudget(maxAttempts = 3, maxElapsed = Duration.ofSeconds(30)),
                progress = RetryProgress(attemptsStarted = 3, elapsed = Duration.ofSeconds(30)),
            ),
        )
    }

    @Test
    fun `same policy inputs are deterministic and do not consume budget internally`() {
        val failure = SshConnectFailure.Unreachable("temporary")
        val budget = RetryBudget(maxAttempts = 3)
        val progress = RetryProgress(attemptsStarted = 1, elapsed = Duration.ofSeconds(1))

        val first = SshConnectRetryPolicy.evaluate(failure, budget, progress)
        val second = SshConnectRetryPolicy.evaluate(failure, budget, progress)

        assertEquals(first, second)
        assertEquals(
            RetryDecision.PermitNextAttempt(2, RetryFailureCategory.TRANSIENT_TRANSPORT),
            first,
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `zero max attempts is rejected`() {
        RetryBudget(maxAttempts = 0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `zero optional elapsed bound is rejected`() {
        RetryBudget(maxAttempts = 3, maxElapsed = Duration.ZERO)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `negative retry elapsed progress is rejected`() {
        RetryProgress(attemptsStarted = 1, elapsed = Duration.ofMillis(-1))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `retry progress cannot exist before any failed attempt`() {
        RetryProgress(attemptsStarted = 0, elapsed = Duration.ZERO)
    }
}
