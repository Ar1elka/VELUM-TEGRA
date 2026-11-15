package com.velumtegra.xuimobile.runtime

import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.DiscoveryResult
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.runtime.ConnectivityObservation
import com.velumtegra.xuimobile.core.runtime.DiscoveryRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimePreparationResult
import com.velumtegra.xuimobile.core.runtime.ExistingInstallationRestartPreparationResult
import com.velumtegra.xuimobile.core.runtime.ExistingInstallationRestartRuntimeResult
import com.velumtegra.xuimobile.core.runtime.ConnectivityReconnectPermitGate
import com.velumtegra.xuimobile.core.runtime.RetryBudget
import com.velumtegra.xuimobile.core.runtime.RetryDecision
import com.velumtegra.xuimobile.core.runtime.RetryDeniedReason
import com.velumtegra.xuimobile.core.runtime.RetryFailureCategory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine

class ExactOperationHostTransportSequenceTest {
    @Test
    fun connectedSessionIsClosedImmediatelyByExactBinding() {
        val operationId = OperationId("op-connected")
        val runtimeToken = FakeRuntimeToken("runtime-connected")
        val session = session(operationId, "session-connected")
        val port = ScriptedTransportPort(
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.Connected(
                    binding = session,
                    attemptNumber = 1,
                    installation = SessionInstallResult.Installed,
                ),
            ),
            closeResult = ExactOperationHostSessionClosePortResult.Closed,
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )
        val runtimeBinding = ExactOperationHostRuntimeBinding(operationId, runtimeToken)

        val result = runSuspend {
            sequence.run(runtimeBinding, RetryBudget(maxAttempts = 2))
        }

        assertTrue(result is ExactOperationHostTransportSequenceResult.ConnectedSessionCleaned)
        result as ExactOperationHostTransportSequenceResult.ConnectedSessionCleaned
        assertSame(session, result.binding)
        assertSame(ExactOperationHostSessionCloseResult.Closed, result.cleanup)
        assertEquals(1, port.beginCalls)
        assertEquals(0, port.retryCalls)
        assertEquals(1, port.closeCalls)
        assertSame(runtimeToken, port.seenCloseRuntimeToken)
        assertSame(session, port.seenCloseBinding)
    }

    @Test
    fun connectedDiscoveryRunsFeatureBeforeExactSessionCleanup() {
        val operationId = OperationId("op-discovery-consumer")
        val session = session(operationId, "session-discovery-consumer")
        val resultValue = DiscoveryResult.NoSupportedInstallation(
            scope = DiscoveryScope(
                operationId = operationId,
                serverId = ServerId("server-discovery-consumer"),
                serverAccessId = session.serverAccessId,
            ),
            completedAt = Instant.parse("2026-09-06T08:00:00Z"),
        )
        val port = ScriptedTransportPort(
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.Connected(
                    binding = session,
                    attemptNumber = 1,
                    installation = SessionInstallResult.Installed,
                ),
            ),
            discoveryResult = DiscoveryRuntimeExecutionResult.Completed(
                result = resultValue,
                committedRevision = com.velumtegra.xuimobile.core.domain.OperationRevision(1),
            ),
            closeResult = ExactOperationHostSessionClosePortResult.Closed,
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(operationId, FakeRuntimeToken("runtime-discovery-consumer")),
                RetryBudget(maxAttempts = 1),
            )
        }

        assertTrue(result is ExactOperationHostTransportSequenceResult.DiscoveryCompleted)
        result as ExactOperationHostTransportSequenceResult.DiscoveryCompleted
        assertEquals(resultValue, result.result)
        assertEquals(1, port.discoveryCalls)
        assertEquals(1, port.closeCalls)
        assertTrue(port.discoveryCallOrder < port.closeCallOrder)
    }

    @Test
    fun connectedDeepDiagnosticRunsAfterOtherReadOnlyConsumersAndBeforeExactCleanup() {
        val operationId = OperationId("op-deep-consumer")
        val session = session(operationId, "session-deep-consumer")
        val observedAt = Instant.parse("2026-09-06T17:00:00Z")
        val installationId = com.velumtegra.xuimobile.core.model.XuiInstallationId("installation-deep-consumer")
        val scope = com.velumtegra.xuimobile.core.model.DeepDiagnosticScope(
            operationId = operationId,
            serverId = ServerId("server-deep-consumer"),
            serverAccessId = session.serverAccessId,
            installationId = installationId,
        )
        val managementSnapshot = com.velumtegra.xuimobile.core.model.ManagementLiveSnapshot(
            scope = com.velumtegra.xuimobile.core.model.ManagementScope(
                operationId = operationId,
                serverId = scope.serverId,
                serverAccessId = scope.serverAccessId,
                installationId = installationId,
            ),
            identityStatus = com.velumtegra.xuimobile.core.model.ManagementIdentityStatus.Matched,
            serviceState = com.velumtegra.xuimobile.core.model.ManagementServiceState.ACTIVE,
            baselineStatus = com.velumtegra.xuimobile.core.model.ManagementBaselineStatus.Matched,
            freshProof = null,
            observedAt = observedAt,
        )
        val snapshot = com.velumtegra.xuimobile.core.model.DeepDiagnosticSnapshot(
            scope = scope,
            managementSnapshot = managementSnapshot,
            findings = emptySet(),
            overallStatus = com.velumtegra.xuimobile.core.model.DeepDiagnosticOverallStatus.HEALTHY,
            observedAt = observedAt.plusSeconds(1),
        )
        val port = ScriptedTransportPort(
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.Connected(
                    binding = session,
                    attemptNumber = 1,
                    installation = SessionInstallResult.Installed,
                ),
            ),
            deepDiagnosticResult = com.velumtegra.xuimobile.core.runtime.DeepDiagnosticRuntimeExecutionResult.Completed(
                snapshot = snapshot,
                committedRevision = com.velumtegra.xuimobile.core.domain.OperationRevision(3),
            ),
            closeResult = ExactOperationHostSessionClosePortResult.Closed,
        )
        val sequence = ExactOperationHostTransportSequence(ExactOperationHostRuntimeTransportBridge(port))

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(operationId, FakeRuntimeToken("runtime-deep-consumer")),
                RetryBudget(maxAttempts = 1),
            )
        }

        assertTrue(result is ExactOperationHostTransportSequenceResult.DeepDiagnosticCompleted)
        result as ExactOperationHostTransportSequenceResult.DeepDiagnosticCompleted
        assertEquals(snapshot, result.snapshot)
        assertEquals(com.velumtegra.xuimobile.core.domain.OperationRevision(3), result.committedRevision)
        assertEquals(1, port.discoveryCalls)
        assertEquals(1, port.managementCalls)
        assertEquals(1, port.deepDiagnosticCalls)
        assertEquals(1, port.closeCalls)
        assertTrue(port.discoveryCallOrder < port.managementCallOrder)
        assertTrue(port.managementCallOrder < port.deepDiagnosticCallOrder)
        assertTrue(port.deepDiagnosticCallOrder < port.closeCallOrder)
    }

    @Test
    fun oneExactRetryPermitCanLeadToConnectedAndCleanedSession() {
        val operationId = OperationId("op-retry")
        val retryToken = FakeRetryToken("retry-2")
        val session = session(operationId, "session-retry")
        val port = ScriptedTransportPort(
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.RetryPermitted(
                    failure = SshConnectFailure.Unreachable("temporary"),
                    operationId = operationId,
                    generation = 8L,
                    nextAttemptNumber = 2,
                    token = retryToken,
                ),
            ),
            retryResults = mutableListOf(
                ExactOperationHostTransportPortResult.Connected(
                    binding = session,
                    attemptNumber = 2,
                    installation = SessionInstallResult.Installed,
                ),
            ),
            closeResult = ExactOperationHostSessionClosePortResult.Closed,
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(operationId, FakeRuntimeToken("runtime-retry")),
                RetryBudget(maxAttempts = 2),
            )
        }

        assertTrue(result is ExactOperationHostTransportSequenceResult.ConnectedSessionCleaned)
        assertEquals(1, port.beginCalls)
        assertEquals(1, port.retryCalls)
        assertSame(retryToken, port.seenRetryToken)
        assertEquals(1, port.closeCalls)
    }

    @Test
    fun offlineWaitEndsWithoutRetryOrSessionCleanup() {
        val operationId = OperationId("op-offline")
        val port = ScriptedTransportPort(
            beginResults = mutableListOf(ExactOperationHostTransportPortResult.WaitForNetwork),
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(operationId, FakeRuntimeToken("runtime-offline")),
                RetryBudget(maxAttempts = 2),
            )
        }

        assertEquals(
            ExactOperationHostTransportSequenceResult.Ended(
                ExactOperationHostTransportResult.WaitForNetwork,
            ),
            result,
        )
        assertEquals(1, port.beginCalls)
        assertEquals(0, port.retryCalls)
        assertEquals(0, port.closeCalls)
    }

    @Test
    fun permitBeyondHostBudgetFailsClosedWithoutConsumingRetry() {
        val operationId = OperationId("op-budget")
        val port = ScriptedTransportPort(
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.RetryPermitted(
                    failure = SshConnectFailure.Unreachable("temporary"),
                    operationId = operationId,
                    generation = 2L,
                    nextAttemptNumber = 3,
                    token = FakeRetryToken("too-far"),
                ),
            ),
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(operationId, FakeRuntimeToken("runtime-budget")),
                RetryBudget(maxAttempts = 2),
            )
        }

        assertTrue(result is ExactOperationHostTransportSequenceResult.ContractViolation)
        assertEquals(0, port.retryCalls)
        assertEquals(0, port.closeCalls)
    }

    @Test
    fun retryPermitCannotChangeConnectivityGeneration() {
        val operationId = OperationId("op-generation")
        val port = ScriptedTransportPort(
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.RetryPermitted(
                    failure = SshConnectFailure.Unreachable("first"),
                    operationId = operationId,
                    generation = 4L,
                    nextAttemptNumber = 2,
                    token = FakeRetryToken("retry-2"),
                ),
            ),
            retryResults = mutableListOf(
                ExactOperationHostTransportPortResult.RetryPermitted(
                    failure = SshConnectFailure.Unreachable("second"),
                    operationId = operationId,
                    generation = 5L,
                    nextAttemptNumber = 3,
                    token = FakeRetryToken("retry-3"),
                ),
            ),
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(operationId, FakeRuntimeToken("runtime-generation")),
                RetryBudget(maxAttempts = 3),
            )
        }

        assertTrue(result is ExactOperationHostTransportSequenceResult.ContractViolation)
        assertEquals(1, port.retryCalls)
        assertEquals(0, port.closeCalls)
    }

    @Test
    fun newerOnlineGenerationCanSupersedeOfflineWaitInsideBoundedHost() {
        val operationId = OperationId("op-supersede-online")
        val connectivity = ConnectivityReconnectPermitGate(ConnectivityState.OFFLINE)
        val firstObservation = connectivity.snapshot()
        val secondObservation = connectivity.observe(ConnectivityState.ONLINE)
        val session = session(operationId, "session-supersede-online")
        val port = ScriptedTransportPort(
            connectivitySnapshots = mutableListOf(firstObservation, secondObservation),
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.WaitForNetwork,
                ExactOperationHostTransportPortResult.Connected(
                    binding = session,
                    attemptNumber = 1,
                    installation = SessionInstallResult.Installed,
                ),
            ),
            closeResult = ExactOperationHostSessionClosePortResult.Closed,
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(
                    operationId,
                    FakeRuntimeToken("runtime-supersede-online"),
                ),
                RetryBudget(maxAttempts = 2),
                maxConnectivityGenerations = 2,
            )
        }

        assertTrue(result is ExactOperationHostTransportSequenceResult.ConnectedSessionCleaned)
        assertEquals(2, port.beginCalls)
        assertEquals(listOf(firstObservation, secondObservation), port.seenBeginObservations)
        assertEquals(1, port.closeCalls)
    }

    @Test
    fun newerOnlineGenerationCanSupersedeStaleSchedulingOutcome() {
        val operationId = OperationId("op-supersede-stale")
        val connectivity = ConnectivityReconnectPermitGate(ConnectivityState.ONLINE)
        val firstObservation = connectivity.snapshot()
        val secondObservation = connectivity.observe(ConnectivityState.UNKNOWN)
        val session = session(operationId, "session-supersede-stale")
        val port = ScriptedTransportPort(
            connectivitySnapshots = mutableListOf(firstObservation, secondObservation),
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.StaleConnectivityGeneration,
                ExactOperationHostTransportPortResult.Connected(
                    binding = session,
                    attemptNumber = 1,
                    installation = SessionInstallResult.Installed,
                ),
            ),
            closeResult = ExactOperationHostSessionClosePortResult.Closed,
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(
                    operationId,
                    FakeRuntimeToken("runtime-supersede-stale"),
                ),
                RetryBudget(maxAttempts = 2),
                maxConnectivityGenerations = 2,
            )
        }

        assertTrue(result is ExactOperationHostTransportSequenceResult.ConnectedSessionCleaned)
        assertEquals(2, port.beginCalls)
        assertEquals(listOf(firstObservation, secondObservation), port.seenBeginObservations)
        assertEquals(1, port.closeCalls)
    }

    @Test
    fun alreadyScheduledOutcomeNeverCompetesAcrossConnectivityGenerations() {
        val operationId = OperationId("op-already-scheduled")
        val connectivity = ConnectivityReconnectPermitGate(ConnectivityState.ONLINE)
        val firstObservation = connectivity.snapshot()
        val secondObservation = connectivity.observe(ConnectivityState.UNKNOWN)
        val port = ScriptedTransportPort(
            connectivitySnapshots = mutableListOf(firstObservation, secondObservation),
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.AlreadyScheduledForGeneration,
            ),
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(
                    operationId,
                    FakeRuntimeToken("runtime-already-scheduled"),
                ),
                RetryBudget(maxAttempts = 2),
                maxConnectivityGenerations = 2,
            )
        }

        assertEquals(
            ExactOperationHostTransportSequenceResult.Ended(
                ExactOperationHostTransportResult.AlreadyScheduledForGeneration,
            ),
            result,
        )
        assertEquals(1, port.beginCalls)
        assertEquals(1, port.connectivitySnapshotCalls)
        assertEquals(listOf(firstObservation), port.seenBeginObservations)
        assertEquals(0, port.closeCalls)
    }

    @Test
    fun newerOfflineGenerationConvergesToCurrentWaitWithoutReconnect() {
        val operationId = OperationId("op-newer-offline")
        val connectivity = ConnectivityReconnectPermitGate(ConnectivityState.ONLINE)
        val firstObservation = connectivity.snapshot()
        val secondObservation = connectivity.observe(ConnectivityState.OFFLINE)
        val port = ScriptedTransportPort(
            connectivitySnapshots = mutableListOf(firstObservation, secondObservation),
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.StaleConnectivityGeneration,
            ),
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(
                    operationId,
                    FakeRuntimeToken("runtime-newer-offline"),
                ),
                RetryBudget(maxAttempts = 2),
                maxConnectivityGenerations = 2,
            )
        }

        assertEquals(
            ExactOperationHostTransportSequenceResult.Ended(
                ExactOperationHostTransportResult.WaitForNetwork,
            ),
            result,
        )
        assertEquals(1, port.beginCalls)
        assertEquals(2, port.connectivitySnapshotCalls)
        assertEquals(listOf(firstObservation), port.seenBeginObservations)
        assertEquals(0, port.closeCalls)
    }

    @Test
    fun regressingConnectivityGenerationFailsClosed() {
        val operationId = OperationId("op-generation-regression")
        val newerGate = ConnectivityReconnectPermitGate(ConnectivityState.ONLINE)
        val firstObservation = newerGate.observe(ConnectivityState.UNKNOWN)
        val olderObservation = ConnectivityReconnectPermitGate(ConnectivityState.ONLINE).snapshot()
        val port = ScriptedTransportPort(
            connectivitySnapshots = mutableListOf(firstObservation, olderObservation),
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.WaitForNetwork,
            ),
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(
                    operationId,
                    FakeRuntimeToken("runtime-generation-regression"),
                ),
                RetryBudget(maxAttempts = 2),
                maxConnectivityGenerations = 2,
            )
        }

        assertTrue(result is ExactOperationHostTransportSequenceResult.ContractViolation)
        assertEquals(1, port.beginCalls)
        assertEquals(2, port.connectivitySnapshotCalls)
        assertEquals(0, port.closeCalls)
    }

    @Test
    fun sameConnectivityGenerationNeverSpinsAfterStaleSchedulingOutcome() {
        val operationId = OperationId("op-same-generation")
        val observation = ConnectivityReconnectPermitGate(ConnectivityState.ONLINE).snapshot()
        val port = ScriptedTransportPort(
            connectivitySnapshots = mutableListOf(observation),
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.StaleConnectivityGeneration,
            ),
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(
                    operationId,
                    FakeRuntimeToken("runtime-same-generation"),
                ),
                RetryBudget(maxAttempts = 2),
                maxConnectivityGenerations = 2,
            )
        }

        assertEquals(
            ExactOperationHostTransportSequenceResult.Ended(
                ExactOperationHostTransportResult.StaleConnectivityGeneration,
            ),
            result,
        )
        assertEquals(1, port.beginCalls)
        assertEquals(2, port.connectivitySnapshotCalls)
        assertEquals(0, port.closeCalls)
    }

    @Test
    fun connectivityGenerationBudgetStopsRepeatedSupersession() {
        val operationId = OperationId("op-generation-budget")
        val connectivity = ConnectivityReconnectPermitGate(ConnectivityState.OFFLINE)
        val firstObservation = connectivity.snapshot()
        val secondObservation = connectivity.observe(ConnectivityState.ONLINE)
        val thirdObservation = connectivity.observe(ConnectivityState.UNKNOWN)
        val port = ScriptedTransportPort(
            connectivitySnapshots = mutableListOf(
                firstObservation,
                secondObservation,
                thirdObservation,
            ),
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.WaitForNetwork,
                ExactOperationHostTransportPortResult.StaleConnectivityGeneration,
            ),
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(
                    operationId,
                    FakeRuntimeToken("runtime-generation-budget"),
                ),
                RetryBudget(maxAttempts = 2),
                maxConnectivityGenerations = 2,
            )
        }

        assertEquals(
            ExactOperationHostTransportSequenceResult.Ended(
                ExactOperationHostTransportResult.StaleConnectivityGeneration,
            ),
            result,
        )
        assertEquals(2, port.beginCalls)
        assertEquals(listOf(firstObservation, secondObservation), port.seenBeginObservations)
        assertEquals(2, port.connectivitySnapshotCalls)
        assertEquals(0, port.closeCalls)
    }

    @Test
    fun nonRetryableFailureEndsWithoutSessionCleanup() {
        val failure = SshConnectFailure.AuthenticationRejected
        val portResult = ExactOperationHostTransportPortResult.Failed(
            failure = failure,
            retryDecision = RetryDecision.Denied(
                reason = RetryDeniedReason.FAILURE_NOT_RETRYABLE,
                failureCategory = RetryFailureCategory.AUTHENTICATION_REJECTED,
            ),
        )
        val port = ScriptedTransportPort(beginResults = mutableListOf(portResult))
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(
                    OperationId("op-auth"),
                    FakeRuntimeToken("runtime-auth"),
                ),
                RetryBudget(maxAttempts = 2),
            )
        }

        assertTrue(result is ExactOperationHostTransportSequenceResult.Ended)
        result as ExactOperationHostTransportSequenceResult.Ended
        assertTrue(result.transportResult is ExactOperationHostTransportResult.Failed)
        assertEquals(0, port.retryCalls)
        assertEquals(0, port.closeCalls)
    }


    @Test
    fun installerPreparationCanStopBeforeConnectivityOrSsh() {
        val operationId = OperationId("op-installer-local-stop")
        val port = ScriptedTransportPort(
            installerPreparationResult = InstallerRuntimePreparationResult.FreshAuthorizationRequired,
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(operationId, FakeRuntimeToken("runtime-installer-local-stop")),
                RetryBudget(maxAttempts = 1),
            )
        }

        assertEquals(
            ExactOperationHostTransportSequenceResult.InstallerPrepared(
                InstallerRuntimePreparationResult.FreshAuthorizationRequired,
            ),
            result,
        )
        assertEquals(1, port.installerPrepareCalls)
        assertEquals(0, port.connectivitySnapshotCalls)
        assertEquals(0, port.beginCalls)
        assertEquals(0, port.closeCalls)
    }

    @Test
    fun connectedInstallerRunsAfterReadOnlyConsumersAndBeforeExactCleanup() {
        val operationId = OperationId("op-installer-consumer")
        val session = session(operationId, "session-installer-consumer")
        val installerResult = InstallerRuntimeExecutionResult.ContractViolation("installer-fixture-result")
        val port = ScriptedTransportPort(
            beginResults = mutableListOf(
                ExactOperationHostTransportPortResult.Connected(
                    binding = session,
                    attemptNumber = 1,
                    installation = SessionInstallResult.Installed,
                ),
            ),
            installerPreparationResult = InstallerRuntimePreparationResult.TransportRequired,
            installerExecutionResult = installerResult,
            closeResult = ExactOperationHostSessionClosePortResult.Closed,
        )
        val sequence = ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(port),
        )

        val result = runSuspend {
            sequence.run(
                ExactOperationHostRuntimeBinding(operationId, FakeRuntimeToken("runtime-installer-consumer")),
                RetryBudget(maxAttempts = 1),
            )
        }

        assertTrue(result is ExactOperationHostTransportSequenceResult.InstallerEnded)
        result as ExactOperationHostTransportSequenceResult.InstallerEnded
        assertSame(session, result.binding)
        assertEquals(installerResult, result.installer)
        assertSame(ExactOperationHostSessionCloseResult.Closed, result.cleanup)
        assertEquals(1, port.installerPrepareCalls)
        assertEquals(1, port.installerExecuteCalls)
        assertTrue(port.discoveryCallOrder < port.managementCallOrder)
        assertTrue(port.managementCallOrder < port.deepDiagnosticCallOrder)
        assertTrue(port.deepDiagnosticCallOrder < port.installerExecuteCallOrder)
        assertTrue(port.installerExecuteCallOrder < port.closeCallOrder)
    }

    @Test
    fun restartWithoutFreshConsentStopsBeforeConnectivityAndSsh() {
        val port = ScriptedTransportPort(restartPreparationResult = ExistingInstallationRestartPreparationResult.FreshPreflightRequired)
        val result = runSuspend { ExactOperationHostTransportSequence(ExactOperationHostRuntimeTransportBridge(port)).run(
            ExactOperationHostRuntimeBinding(OperationId("restart-no-consent"), FakeRuntimeToken("restart-no-consent")), RetryBudget(1)) }
        assertEquals(ExactOperationHostTransportSequenceResult.RestartPrepared(ExistingInstallationRestartPreparationResult.FreshPreflightRequired), result)
        assertEquals(1, port.restartPrepareCalls)
        assertEquals(0, port.connectivitySnapshotCalls)
        assertEquals(0, port.beginCalls)
        assertEquals(0, port.restartExecuteCalls)
    }

    @Test
    fun restartUsesExactConnectedSessionOnceAndAlwaysClosesIt() {
        val operation = OperationId("restart-exact-session")
        val session = session(operation, "restart-exact-session")
        val outcome = ExistingInstallationRestartRuntimeResult.ContractViolation("fixture-stops-before-dispatch")
        val port = ScriptedTransportPort(beginResults = mutableListOf(ExactOperationHostTransportPortResult.Connected(session, 1, SessionInstallResult.Installed)),
            restartPreparationResult = ExistingInstallationRestartPreparationResult.TransportRequired,
            restartExecutionResult = outcome, closeResult = ExactOperationHostSessionClosePortResult.Closed)
        val result = runSuspend { ExactOperationHostTransportSequence(ExactOperationHostRuntimeTransportBridge(port)).run(
            ExactOperationHostRuntimeBinding(operation, FakeRuntimeToken("restart-exact-session")), RetryBudget(1)) }
            as ExactOperationHostTransportSequenceResult.RestartEnded
        assertSame(session, result.binding)
        assertSame(outcome, result.restart)
        assertSame(ExactOperationHostSessionCloseResult.Closed, result.cleanup)
        assertEquals(1, port.restartExecuteCalls)
        assertEquals(1, port.beginCalls)
        assertEquals(0, port.retryCalls)
        assertEquals(1, port.closeCalls)
        assertTrue(port.installerExecuteCallOrder < port.restartExecuteCallOrder)
        assertTrue(port.restartExecuteCallOrder < port.closeCallOrder)
    }

    @Test
    fun readOnlyConsumerNeverFallsThroughIntoRestart() {
        val operation = OperationId("quick-inspect-is-not-restart")
        val session = session(operation, "read-only-session")
        val port = ScriptedTransportPort(beginResults = mutableListOf(ExactOperationHostTransportPortResult.Connected(session, 1, SessionInstallResult.Installed)),
            managementResult = com.velumtegra.xuimobile.core.runtime.ManagementRuntimeExecutionResult.ContractViolation("fixture-read-only-outcome"),
            closeResult = ExactOperationHostSessionClosePortResult.Closed)
        val result = runSuspend { ExactOperationHostTransportSequence(ExactOperationHostRuntimeTransportBridge(port)).run(
            ExactOperationHostRuntimeBinding(operation, FakeRuntimeToken("read-only-session")), RetryBudget(1)) }
        assertTrue(result is ExactOperationHostTransportSequenceResult.ManagementEnded)
        assertEquals(0, port.restartExecuteCalls)
        assertEquals(1, port.closeCalls)
    }

    private class ScriptedTransportPort(
        private val connectivitySnapshots: MutableList<ConnectivityObservation> = mutableListOf(
            ConnectivityReconnectPermitGate(ConnectivityState.ONLINE).snapshot(),
        ),
        private val beginResults: MutableList<ExactOperationHostTransportPortResult> = mutableListOf(),
        private val retryResults: MutableList<ExactOperationHostTransportPortResult> = mutableListOf(),
        private val discoveryResult: DiscoveryRuntimeExecutionResult =
            DiscoveryRuntimeExecutionResult.NotDiscoveryOperation(com.velumtegra.xuimobile.core.model.OperationType.QUICK_INSPECT),
        private val managementResult: com.velumtegra.xuimobile.core.runtime.ManagementRuntimeExecutionResult =
            com.velumtegra.xuimobile.core.runtime.ManagementRuntimeExecutionResult.NotQuickInspectOperation(
                com.velumtegra.xuimobile.core.model.OperationType.DEEP_DIAGNOSTIC,
            ),
        private val deepDiagnosticResult: com.velumtegra.xuimobile.core.runtime.DeepDiagnosticRuntimeExecutionResult =
            com.velumtegra.xuimobile.core.runtime.DeepDiagnosticRuntimeExecutionResult.NotDeepDiagnosticOperation(
                com.velumtegra.xuimobile.core.model.OperationType.INSTALL,
            ),
        private val installerPreparationResult: InstallerRuntimePreparationResult =
            InstallerRuntimePreparationResult.NotInstallerOperation,
        private val installerExecutionResult: InstallerRuntimeExecutionResult =
            InstallerRuntimeExecutionResult.NotInstallerOperation,
        private val restartPreparationResult: ExistingInstallationRestartPreparationResult =
            ExistingInstallationRestartPreparationResult.NotRestartOperation,
        private val restartExecutionResult: ExistingInstallationRestartRuntimeResult =
            ExistingInstallationRestartRuntimeResult.NotRestartOperation,
        private val closeResult: ExactOperationHostSessionClosePortResult =
            ExactOperationHostSessionClosePortResult.StaleOrAlreadyClosed,
    ) : ExactOperationHostRuntimeTransportPort {
        var beginCalls = 0
        var retryCalls = 0
        var closeCalls = 0
        var discoveryCalls = 0
        var managementCalls = 0
        var deepDiagnosticCalls = 0
        var installerPrepareCalls = 0
        var installerExecuteCalls = 0
        var restartPrepareCalls = 0
        var restartExecuteCalls = 0
        var restartExecuteCallOrder = 0
        var callOrder = 0
        var discoveryCallOrder = 0
        var managementCallOrder = 0
        var deepDiagnosticCallOrder = 0
        var installerExecuteCallOrder = 0
        var closeCallOrder = 0
        var connectivitySnapshotCalls = 0
        val seenBeginObservations = mutableListOf<ConnectivityObservation>()
        var seenRetryToken: ExactOperationHostReconnectRetryToken? = null
        var seenCloseRuntimeToken: ExactOperationHostRuntimeToken? = null
        var seenCloseBinding: SessionBinding? = null
        private var lastConnectivityObservation: ConnectivityObservation? = null

        override fun connectivitySnapshot(): ConnectivityObservation {
            connectivitySnapshotCalls += 1
            val next = connectivitySnapshots.removeFirstOrNull()
            if (next != null) {
                lastConnectivityObservation = next
                return next
            }
            return checkNotNull(lastConnectivityObservation) {
                "No scripted connectivity observation"
            }
        }

        override suspend fun begin(
            runtimeToken: ExactOperationHostRuntimeToken,
            observation: ConnectivityObservation,
            budget: RetryBudget,
        ): ExactOperationHostTransportPortResult {
            beginCalls += 1
            seenBeginObservations += observation
            return beginResults.removeFirstOrNull()
                ?: error("No scripted begin result")
        }

        override suspend fun retry(
            retryToken: ExactOperationHostReconnectRetryToken,
        ): ExactOperationHostTransportPortResult {
            retryCalls += 1
            seenRetryToken = retryToken
            return retryResults.removeFirstOrNull()
                ?: error("No scripted retry result")
        }

        override suspend fun executeDiscovery(
            runtimeToken: ExactOperationHostRuntimeToken,
            binding: SessionBinding,
        ): DiscoveryRuntimeExecutionResult {
            discoveryCalls += 1
            discoveryCallOrder = ++callOrder
            return discoveryResult
        }

        override suspend fun executeManagementQuickInspect(
            runtimeToken: ExactOperationHostRuntimeToken,
            binding: SessionBinding,
        ): com.velumtegra.xuimobile.core.runtime.ManagementRuntimeExecutionResult {
            managementCalls += 1
            managementCallOrder = ++callOrder
            return managementResult
        }

        override suspend fun executeDeepDiagnostic(
            runtimeToken: ExactOperationHostRuntimeToken,
            binding: SessionBinding,
        ): com.velumtegra.xuimobile.core.runtime.DeepDiagnosticRuntimeExecutionResult {
            deepDiagnosticCalls += 1
            deepDiagnosticCallOrder = ++callOrder
            return deepDiagnosticResult
        }


        override suspend fun prepareInstaller(
            runtimeToken: ExactOperationHostRuntimeToken,
        ): InstallerRuntimePreparationResult {
            installerPrepareCalls += 1
            return installerPreparationResult
        }

        override suspend fun executeInstaller(
            runtimeToken: ExactOperationHostRuntimeToken,
            binding: SessionBinding,
        ): InstallerRuntimeExecutionResult {
            installerExecuteCalls += 1
            installerExecuteCallOrder = ++callOrder
            return installerExecutionResult
        }

        override fun closeSession(
            runtimeToken: ExactOperationHostRuntimeToken,
            binding: SessionBinding,
        ): ExactOperationHostSessionClosePortResult {
            closeCalls += 1
            closeCallOrder = ++callOrder
            seenCloseRuntimeToken = runtimeToken
            seenCloseBinding = binding
            return closeResult
        }

        override suspend fun prepareRestart(runtimeToken: ExactOperationHostRuntimeToken): ExistingInstallationRestartPreparationResult {
            restartPrepareCalls++
            return restartPreparationResult
        }

        override suspend fun executeRestart(runtimeToken: ExactOperationHostRuntimeToken, binding: SessionBinding): ExistingInstallationRestartRuntimeResult {
            restartExecuteCalls++
            restartExecuteCallOrder = ++callOrder
            return restartExecutionResult
        }
    }

    private fun session(operationId: OperationId, sessionValue: String): SessionBinding = SessionBinding(
        sessionId = SessionId(sessionValue),
        serverAccessId = ServerAccessId("access-${operationId.value}"),
        owner = SessionOwner.Operation(operationId),
    )

    private data class FakeRuntimeToken(val value: String) : ExactOperationHostRuntimeToken
    private data class FakeRetryToken(val value: String) : ExactOperationHostReconnectRetryToken

    private fun <T> runSuspend(block: suspend () -> T): T {
        var outcome: Result<T>? = null
        block.startCoroutine(
            object : Continuation<T> {
                override val context = EmptyCoroutineContext
                override fun resumeWith(result: Result<T>) {
                    outcome = result
                }
            },
        )
        return checkNotNull(outcome).getOrThrow()
    }
}
