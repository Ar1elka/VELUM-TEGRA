package com.velumtegra.xuimobile.integration

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.room3.withWriteTransaction
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.Server
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.runtime.ConnectivityObservation
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeReleaseResult
import com.velumtegra.xuimobile.core.runtime.RecoveryBlockReason
import com.velumtegra.xuimobile.core.runtime.RetryBudget
import com.velumtegra.xuimobile.core.runtime.RetryDeniedReason
import com.velumtegra.xuimobile.core.runtime.RetryFailureCategory
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeAdmissionBridge
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeBindResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostRuntimeTransportBridge
import com.velumtegra.xuimobile.runtime.ExactOperationHostTransportResult
import java.nio.charset.StandardCharsets
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 4.6G real-device exact recovery-block acceptance.
 *
 * One local SSH fixture is exposed only through USB adb reverse. This test proves four adjacent
 * safety properties without any VPS or remote command:
 * 1) Room refuses deletion of the exact ServerAccess while a nonterminal Operation still references it;
 * 2) losing that access's exact SecretId fails before TCP and cannot fall back to another valid access;
 * 3) a real wrong pinned host key is a typed recovery block with no retry permit;
 * 4) a real password-auth rejection is a typed recovery block with no retry permit.
 *
 * The host fixture independently fails if any path authenticates successfully or sends an exec
 * request. OperationJournal snapshots/revisions must remain byte-for-byte equivalent throughout.
 */
@RunWith(AndroidJUnit4::class)
class Phase4_6GExactRecoveryBlockingInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun exactMissingSecretWrongHostAndAuthRejectNeverFallbackOrRetry() = runBlocking {
        val database = VelumDatabaseFactory.open(context)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val accessRepository = RoomServerAccessRepository(database)
        val credentialWriter = RoomCredentialReferenceWriter(database)
        val secretStore = AndroidKeystoreSecretStore(context)
        val connectivityManager = requireNotNull(
            context.getSystemService(ConnectivityManager::class.java),
        ) { "ConnectivityManager is unavailable" }
        val admissionBridge = ExactOperationHostRuntimeAdmissionBridge(
            coordinator = application.operationRuntimeCoordinator,
            previousExitProvenance = application.exitInfoAdapter::previousExitProvenance,
        )
        val transportBridge = ExactOperationHostRuntimeTransportBridge(application.operationRuntimeCoordinator)

        val fixturePort = readFixturePort()
        val fixtureFingerprint = readFixtureFingerprint()
        var observerRegistered = false

        try {
            cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
            awaitValidatedDefaultNetwork(connectivityManager)

            createSecret(secretStore, MISSING_SECRET_ID, FIXTURE_VALID_PASSWORD)
            createSecret(secretStore, VALID_SECRET_ID, FIXTURE_VALID_PASSWORD)
            createSecret(secretStore, WRONG_PASSWORD_SECRET_ID, FIXTURE_WRONG_PASSWORD)

            val startedAt = Instant.now()
            serverRepository.create(
                Server(
                    id = SERVER_ID,
                    displayName = "Phase 4.6G exact recovery blocking acceptance",
                    createdAt = startedAt,
                ),
            ).requireRepositorySuccess("create acceptance Server")

            val accesses = listOf(
                ServerAccess(
                    id = MISSING_SECRET_ACCESS_ID,
                    serverId = SERVER_ID,
                    endpoint = SshEndpoint("127.0.0.1", fixturePort),
                    username = FIXTURE_USERNAME,
                    auth = SshAuthRef.Password(MISSING_SECRET_ID),
                    pinnedHostKey = HostKeyFingerprint(fixtureFingerprint),
                ),
                ServerAccess(
                    id = FALLBACK_ACCESS_ID,
                    serverId = SERVER_ID,
                    endpoint = SshEndpoint("127.0.0.1", fixturePort),
                    username = FIXTURE_USERNAME,
                    auth = SshAuthRef.Password(VALID_SECRET_ID),
                    pinnedHostKey = HostKeyFingerprint(fixtureFingerprint),
                ),
                ServerAccess(
                    id = WRONG_HOST_ACCESS_ID,
                    serverId = SERVER_ID,
                    endpoint = SshEndpoint("127.0.0.1", fixturePort),
                    username = FIXTURE_USERNAME,
                    auth = SshAuthRef.Password(VALID_SECRET_ID),
                    pinnedHostKey = HostKeyFingerprint(DETERMINISTIC_WRONG_FINGERPRINT),
                ),
                ServerAccess(
                    id = AUTH_REJECT_ACCESS_ID,
                    serverId = SERVER_ID,
                    endpoint = SshEndpoint("127.0.0.1", fixturePort),
                    username = FIXTURE_USERNAME,
                    auth = SshAuthRef.Password(WRONG_PASSWORD_SECRET_ID),
                    pinnedHostKey = HostKeyFingerprint(fixtureFingerprint),
                ),
            )
            accesses.forEach { access ->
                credentialWriter.createServerAccess(access)
                    .requireRepositorySuccess("create acceptance ServerAccess ${access.id.value}")
            }

            val missingSecretCreated = createOperation(
                journal = journal,
                operationId = MISSING_SECRET_OPERATION_ID,
                accessId = MISSING_SECRET_ACCESS_ID,
                startedAt = startedAt,
                phaseName = "PHASE4_6G_MISSING_SECRET",
            )
            val wrongHostCreated = createOperation(
                journal = journal,
                operationId = WRONG_HOST_OPERATION_ID,
                accessId = WRONG_HOST_ACCESS_ID,
                startedAt = startedAt.plusNanos(1),
                phaseName = "PHASE4_6G_WRONG_HOST",
            )
            val authRejectCreated = createOperation(
                journal = journal,
                operationId = AUTH_REJECT_OPERATION_ID,
                accessId = AUTH_REJECT_ACCESS_ID,
                startedAt = startedAt.plusNanos(2),
                phaseName = "PHASE4_6G_AUTH_REJECT",
            )

            val deleteReferencedAccess = accessRepository.delete(MISSING_SECRET_ACCESS_ID)
            assertTrue(
                "Referenced exact ServerAccess must not be deletable while the durable Operation still targets it",
                deleteReferencedAccess is RepositoryResult.ConstraintConflict,
            )
            assertTrue(
                "Exact ServerAccess must remain present after rejected delete",
                accessRepository.get(MISSING_SECRET_ACCESS_ID) is RepositoryResult.Success,
            )

            ensureSecretAbsent(secretStore, MISSING_SECRET_ID)

            val baselineObservation = application.operationRuntimeCoordinator.connectivitySnapshot()
            assertTrue(
                "Acceptance must own the only production default-network observer registration",
                application.connectivityObserver.register(),
            )
            observerRegistered = true
            awaitValidatedDefaultNetwork(connectivityManager)
            val online = awaitStableOnlineObservationAfter(baselineObservation.generation)

            val missingSecretResult = beginExact(
                admissionBridge = admissionBridge,
                transportBridge = transportBridge,
                operationId = MISSING_SECRET_OPERATION_ID,
                observation = online,
            )
            val missingFailed = missingSecretResult as? ExactOperationHostTransportResult.Failed
                ?: throw AssertionError(
                    "Missing exact SecretId must fail closed without fallback; got ${missingSecretResult::class.java.simpleName}",
                )
            assertTrue(missingFailed.failure is SshConnectFailure.SecretUnavailable)
            assertEquals(RetryDeniedReason.FAILURE_NOT_RETRYABLE, missingFailed.retryDecision.reason)
            assertEquals(RetryFailureCategory.CREDENTIAL_UNAVAILABLE, missingFailed.retryDecision.failureCategory)
            assertEquals(
                missingSecretCreated,
                journal.get(MISSING_SECRET_OPERATION_ID).requireOperationSuccess("read missing-secret durable state"),
            )

            val wrongHostResult = beginExact(
                admissionBridge = admissionBridge,
                transportBridge = transportBridge,
                operationId = WRONG_HOST_OPERATION_ID,
                observation = online,
            )
            val wrongHostBlocked = wrongHostResult as? ExactOperationHostTransportResult.RecoveryBlocked
                ?: throw AssertionError(
                    "Wrong real host pin must become RecoveryBlocked; got ${wrongHostResult::class.java.simpleName}",
                )
            assertEquals(RecoveryBlockReason.HOST_IDENTITY_MISMATCH, wrongHostBlocked.reason)
            assertTrue(wrongHostBlocked.transportFailure is SshConnectFailure.HostIdentityMismatch)
            assertEquals(
                wrongHostCreated,
                journal.get(WRONG_HOST_OPERATION_ID).requireOperationSuccess("read wrong-host durable state"),
            )

            val authRejectResult = beginExact(
                admissionBridge = admissionBridge,
                transportBridge = transportBridge,
                operationId = AUTH_REJECT_OPERATION_ID,
                observation = online,
            )
            val authBlocked = authRejectResult as? ExactOperationHostTransportResult.RecoveryBlocked
                ?: throw AssertionError(
                    "Real SSH auth rejection must become RecoveryBlocked; got ${authRejectResult::class.java.simpleName}",
                )
            assertEquals(RecoveryBlockReason.AUTHENTICATION_REJECTED, authBlocked.reason)
            assertEquals(SshConnectFailure.AuthenticationRejected, authBlocked.transportFailure)
            assertEquals(
                authRejectCreated,
                journal.get(AUTH_REJECT_OPERATION_ID).requireOperationSuccess("read auth-reject durable state"),
            )

            assertTrue(
                "Fallback ServerAccess must remain available only as a witness, never as a substituted target",
                accessRepository.get(FALLBACK_ACCESS_ID) is RepositoryResult.Success,
            )
        } finally {
            try {
                if (observerRegistered) {
                    assertTrue(
                        "Acceptance must unregister the exact production connectivity callback it registered",
                        application.connectivityObserver.unregister(),
                    )
                }
            } finally {
                try {
                    cleanupFixture(database, journal, serverRepository, accessRepository, secretStore)
                } finally {
                    database.close()
                }
            }
        }
    }

    private suspend fun beginExact(
        admissionBridge: ExactOperationHostRuntimeAdmissionBridge,
        transportBridge: ExactOperationHostRuntimeTransportBridge,
        operationId: OperationId,
        observation: ConnectivityObservation,
    ): ExactOperationHostTransportResult {
        val bind = admissionBridge.bind(operationId)
        val bound = bind as? ExactOperationHostRuntimeBindResult.Bound
            ?: throw AssertionError(
                "Exact production recovery admission must bind ${operationId.value}; got ${bind::class.java.simpleName}",
            )
        var result: ExactOperationHostTransportResult? = null
        return try {
            transportBridge.begin(
                binding = bound.binding,
                observation = observation,
                budget = RetryBudget(maxAttempts = 5),
            ).also { result = it }
        } finally {
            val connected = result as? ExactOperationHostTransportResult.Connected
            if (connected != null) {
                transportBridge.closeSession(bound.binding, connected.binding)
            }
            assertEquals(
                OperationRuntimeReleaseResult.RELEASED,
                admissionBridge.release(bound.binding),
            )
        }
    }

    private suspend fun createOperation(
        journal: RoomOperationJournal,
        operationId: OperationId,
        accessId: ServerAccessId,
        startedAt: Instant,
        phaseName: String,
    ) = journal.create(
        OperationSnapshot(
            operationId = operationId,
            type = OperationType.QUICK_INSPECT,
            target = OperationTarget.ServerTarget(SERVER_ID, accessId),
            status = OperationStatus.RUNNING,
            checkpoint = OperationCheckpoint(
                phaseName = phaseName,
                semantics = CheckpointSemantics.READ_ONLY,
                recordedAt = startedAt,
            ),
            startedAt = startedAt,
            updatedAt = startedAt,
        ),
    ).requireOperationSuccess("create acceptance Operation ${operationId.value}")

    private fun readFixturePort(): Int {
        val raw = InstrumentationRegistry.getArguments().getString(ARG_FIXTURE_PORT)
            ?: throw AssertionError("Runner did not provide $ARG_FIXTURE_PORT")
        return raw.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw AssertionError("Runner provided invalid fixture port")
    }

    private fun readFixtureFingerprint(): String {
        val value = InstrumentationRegistry.getArguments().getString(ARG_FIXTURE_FINGERPRINT)
            ?: throw AssertionError("Runner did not provide $ARG_FIXTURE_FINGERPRINT")
        if (!value.startsWith("SHA256:") || value.length <= 7) {
            throw AssertionError("Runner provided invalid canonical fixture host-key fingerprint")
        }
        return value
    }

    private suspend fun createSecret(
        secretStore: AndroidKeystoreSecretStore,
        secretId: SecretId,
        value: String,
    ) {
        ensureSecretAbsent(secretStore, secretId)
        val material = SecretMaterial.fromBytes(value.toByteArray(StandardCharsets.UTF_8))
        try {
            assertEquals(SecretCreateResult.Created, secretStore.create(secretId, material))
        } finally {
            material.close()
        }
    }

    private fun awaitValidatedDefaultNetwork(connectivityManager: ConnectivityManager) {
        val deadlineNanos = System.nanoTime() + NETWORK_TIMEOUT_MILLIS * 1_000_000L
        while (System.nanoTime() < deadlineNanos) {
            val network = connectivityManager.activeNetwork
            val capabilities = network?.let { connectivityManager.getNetworkCapabilities(it) }
            if (
                capabilities != null &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            ) {
                return
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError("Timed out waiting for a validated Android default network")
    }

    private fun awaitStableOnlineObservationAfter(afterGeneration: Long): ConnectivityObservation {
        val deadlineNanos = System.nanoTime() + NETWORK_TIMEOUT_MILLIS * 1_000_000L
        var candidateGeneration: Long? = null
        var stableSinceNanos = 0L
        while (System.nanoTime() < deadlineNanos) {
            val now = System.nanoTime()
            val observation = application.operationRuntimeCoordinator.connectivitySnapshot()
            if (observation.generation > afterGeneration && observation.state == ConnectivityState.ONLINE) {
                if (candidateGeneration != observation.generation) {
                    candidateGeneration = observation.generation
                    stableSinceNanos = now
                } else if (now - stableSinceNanos >= NETWORK_STABILITY_MILLIS * 1_000_000L) {
                    return observation
                }
            } else {
                candidateGeneration = null
                stableSinceNanos = 0L
            }
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        throw AssertionError(
            "Timed out waiting for a stable newer production ONLINE observation; latest=" +
                application.operationRuntimeCoordinator.connectivitySnapshot(),
        )
    }

    private suspend fun cleanupFixture(
        database: VelumDatabase,
        journal: RoomOperationJournal,
        serverRepository: RoomServerRepository,
        accessRepository: RoomServerAccessRepository,
        secretStore: AndroidKeystoreSecretStore,
    ) {
        OPERATION_IDS.forEach { operationId ->
            val current = when (val result = journal.get(operationId)) {
                is OperationJournalResult.Success -> result.value
                OperationJournalResult.NotFound -> null
                else -> throw AssertionError(
                    "Acceptance cleanup could not read ${operationId.value}: ${result::class.java.simpleName}",
                )
            }
            if (current != null) {
                val cleanupAt = laterThan(current.snapshot.updatedAt)
                val terminal = if (
                    current.snapshot.status == OperationStatus.CANCELLED &&
                    current.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL
                ) {
                    current
                } else {
                    journal.advance(
                        operationId,
                        current.revision,
                        current.snapshot.copy(
                            status = OperationStatus.CANCELLED,
                            checkpoint = OperationCheckpoint(
                                phaseName = "PHASE4_6G_ACCEPTANCE_CLEANUP",
                                semantics = CheckpointSemantics.TERMINAL,
                                recordedAt = cleanupAt,
                            ),
                            updatedAt = cleanupAt,
                        ),
                    ).requireOperationSuccess("terminalize ${operationId.value}")
                }
                database.withWriteTransaction {
                    database.operationDao().deleteJournalForOperation(operationId.value)
                    check(
                        database.operationDao().deleteTerminalSnapshotCas(
                            operationId = operationId.value,
                            expectedRevision = terminal.revision.value,
                        ) == 1,
                    ) { "Acceptance cleanup lost exact terminal Operation row ${operationId.value}" }
                }
            }
        }

        ACCESS_IDS.forEach { accessId ->
            when (val result = accessRepository.delete(accessId)) {
                is RepositoryResult.Success, RepositoryResult.NotFound -> Unit
                else -> throw AssertionError(
                    "Acceptance cleanup could not delete ${accessId.value}: ${result::class.java.simpleName}",
                )
            }
        }

        when (val current = serverRepository.get(SERVER_ID)) {
            is RepositoryResult.Success -> when (val result = serverRepository.delete(SERVER_ID, current.value.revision)) {
                is RepositoryResult.Success -> Unit
                else -> throw AssertionError("Acceptance cleanup could not delete Server: ${result::class.java.simpleName}")
            }
            RepositoryResult.NotFound -> Unit
            else -> throw AssertionError("Acceptance cleanup could not read Server: ${current::class.java.simpleName}")
        }

        SECRET_IDS.forEach { secretId -> ensureSecretAbsent(secretStore, secretId) }
    }

    private suspend fun ensureSecretAbsent(secretStore: AndroidKeystoreSecretStore, secretId: SecretId) {
        when (val result = secretStore.delete(secretId)) {
            SecretDeleteResult.Deleted, SecretDeleteResult.AlreadyAbsent -> Unit
            is SecretDeleteResult.StorageFailure -> throw AssertionError(
                "Acceptance SecretStore cleanup failed for ${secretId.value}: ${result.reason}",
            )
        }
    }

    private fun laterThan(value: Instant): Instant {
        val now = Instant.now()
        return if (now.isAfter(value)) now else value.plusNanos(1)
    }

    private fun <T> RepositoryResult<T>.requireRepositorySuccess(label: String): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("$label failed: ${this::class.java.simpleName}")
    }

    private fun <T> OperationJournalResult<T>.requireOperationSuccess(label: String): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("$label failed: ${this::class.java.simpleName}")
    }

    private companion object {
        val SERVER_ID = ServerId("phase4-6g-recovery-block-server")

        val MISSING_SECRET_ACCESS_ID = ServerAccessId("phase4-6g-missing-secret-access")
        val FALLBACK_ACCESS_ID = ServerAccessId("phase4-6g-valid-fallback-witness-access")
        val WRONG_HOST_ACCESS_ID = ServerAccessId("phase4-6g-wrong-host-access")
        val AUTH_REJECT_ACCESS_ID = ServerAccessId("phase4-6g-auth-reject-access")
        val ACCESS_IDS = listOf(
            MISSING_SECRET_ACCESS_ID,
            FALLBACK_ACCESS_ID,
            WRONG_HOST_ACCESS_ID,
            AUTH_REJECT_ACCESS_ID,
        )

        val MISSING_SECRET_OPERATION_ID = OperationId("phase4-6g-missing-secret-operation")
        val WRONG_HOST_OPERATION_ID = OperationId("phase4-6g-wrong-host-operation")
        val AUTH_REJECT_OPERATION_ID = OperationId("phase4-6g-auth-reject-operation")
        val OPERATION_IDS = listOf(
            MISSING_SECRET_OPERATION_ID,
            WRONG_HOST_OPERATION_ID,
            AUTH_REJECT_OPERATION_ID,
        )

        val MISSING_SECRET_ID = SecretId("phase4-6g-missing-secret")
        val VALID_SECRET_ID = SecretId("phase4-6g-valid-secret")
        val WRONG_PASSWORD_SECRET_ID = SecretId("phase4-6g-wrong-password-secret")
        val SECRET_IDS = listOf(MISSING_SECRET_ID, VALID_SECRET_ID, WRONG_PASSWORD_SECRET_ID)

        const val FIXTURE_USERNAME = "velum-phase46g"
        const val FIXTURE_VALID_PASSWORD = "VELUM-phase46g-test-only-password"
        const val FIXTURE_WRONG_PASSWORD = "VELUM-phase46g-intentionally-wrong-password"
        const val DETERMINISTIC_WRONG_FINGERPRINT = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        const val ARG_FIXTURE_PORT = "phase46g.fixturePort"
        const val ARG_FIXTURE_FINGERPRINT = "phase46g.fixtureFingerprint"
        const val NETWORK_TIMEOUT_MILLIS = 30_000L
        const val NETWORK_STABILITY_MILLIS = 1_500L
        const val POLL_INTERVAL_MILLIS = 50L
    }
}
