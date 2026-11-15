package com.velumtegra.xuimobile.integration

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.data.db.VelumDatabase
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomManagementAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomManagementEnrollmentPublisher
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.data.repository.RoomWebPanelAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomXuiInstallationRepository
import com.velumtegra.xuimobile.core.domain.DiscoveryClassifier
import com.velumtegra.xuimobile.core.domain.DiscoveryProbePlan
import com.velumtegra.xuimobile.core.domain.FreshInstallAuthorizationPolicy
import com.velumtegra.xuimobile.core.domain.FreshInstallVerificationResult
import com.velumtegra.xuimobile.core.domain.ManagedInstallIdentityPolicy
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ConnectivityState
import com.velumtegra.xuimobile.core.model.DiscoveryClassification
import com.velumtegra.xuimobile.core.model.DiscoveryObservation
import com.velumtegra.xuimobile.core.model.DiscoveryPathKind
import com.velumtegra.xuimobile.core.model.DiscoveryPlatform
import com.velumtegra.xuimobile.core.model.DiscoveryPresence
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.FreshInstallConflictState
import com.velumtegra.xuimobile.core.model.FreshInstallInstallerCapability
import com.velumtegra.xuimobile.core.model.FreshInstallPreflightProof
import com.velumtegra.xuimobile.core.model.FreshInstallPrivilegeCapability
import com.velumtegra.xuimobile.core.model.FreshInstallScope
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
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.TargetProofId
import com.velumtegra.xuimobile.core.runtime.ExactReconnectResult
import com.velumtegra.xuimobile.core.runtime.InstallerPostInstallCoordinatorResult
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimeEntryRegistrationResult
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimeExecutionResult
import com.velumtegra.xuimobile.core.runtime.InstallerRuntimePreparationResult
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeReleaseResult
import com.velumtegra.xuimobile.core.runtime.RecoveryAdmissionAuthority
import com.velumtegra.xuimobile.core.runtime.RecoveryAdmissionResult
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapItem
import com.velumtegra.xuimobile.core.runtime.RecoveryBootstrapResult
import com.velumtegra.xuimobile.core.runtime.RecoveryExitProvenance
import com.velumtegra.xuimobile.core.runtime.RetryBudget
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.ssh.CommandDispatchState
import com.velumtegra.xuimobile.core.ssh.DiscoverySshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.DiscoverySshProbeRunResult
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.RemoteCommand
import com.velumtegra.xuimobile.core.ssh.SshPrivateKeyCredentialMaterial
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import java.io.File
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Phase 8.9 destructive acceptance against one explicitly authorized disposable VPS.
 *
 * The test is opt-in and cannot run without the one-shot file injected by the guarded host runner.
 * One exact operation-owned SSH session is opened with no reconnect retry. That same session first
 * performs bounded read-only Discovery + capability/root/conflict preflight. Mutation authority is
 * created only after that preflight proves a fresh supported target. The production Phase 8.7
 * runtime then consumes that one-shot authority and executes the canonical Phase 8 Installer path.
 *
 * IMPORTANT: any failure after the durable mutation boundary is fail-closed evidence. This test does
 * not uninstall, roll back, reinstall or retry a partially changed VPS. The Test Lab VPS is expected
 * to be disposable and must be destroyed externally after evidence collection.
 */
@RunWith(AndroidJUnit4::class)
class Phase8_9DisposableVpsInstallerAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun sameSessionFreshPreflightThenProductionInstallerPublishesVerifiedManagementExactlyOnce() = runBlocking {
        val configFile = File(context.noBackupFilesDir, CONFIG_FILE_NAME)
        assumeTrue(
            "Phase 8.9 config was not injected; destructive disposable-VPS acceptance is opt-in",
            configFile.isFile,
        )
        assertInternetPermissionDeclared()

        val parsed = Phase89OneShotAcceptanceConfig.readAndDelete(configFile)
        require(parsed.destructiveAuthorized) { "Phase 8.9 destructive authorization marker is absent" }
        require(parsed.targetLabel.isNotBlank()) { "Disposable Test Lab target label must not be blank" }

        val runTag = UUID.randomUUID().toString().replace("-", "").take(12)
        val dbName = "phase8_9_disposable_vps_${runTag}.db"
        val secretId = SecretId("phase8-9-vps-secret-$runTag")
        var database: VelumDatabase? = null
        var sessions: ExactSessionRegistry? = null
        val secretStore = AndroidKeystoreSecretStore(context)

        try {
            context.deleteDatabase(dbName)
            secretStore.delete(secretId)

            val secretMaterial = parsed.toSecretMaterial()
            try {
                assertEquals(SecretCreateResult.Created, secretStore.create(secretId, secretMaterial))
            } finally {
                secretMaterial.close()
                parsed.closeSensitiveBytes()
            }

            val db = VelumDatabaseFactory.open(context, dbName)
            database = db
            val journal = RoomOperationJournal(db)
            val serverRepo = RoomServerRepository(db)
            val accessRepo = RoomServerAccessRepository(db)
            val credentialWriter = RoomCredentialReferenceWriter(db)
            val installationRepo = RoomXuiInstallationRepository(db)
            val managementRepo = RoomManagementAccessRepository(db)
            val webPanelRepo = RoomWebPanelAccessRepository(db)
            val publisher = RoomManagementEnrollmentPublisher(db)

            val serverId = ServerId("phase8-9-server-$runTag")
            val accessId = ServerAccessId("phase8-9-access-$runTag")
            val operationId = OperationId("phase8-9-install-$runTag")
            val auth = when (parsed.authMethod) {
                Phase89AcceptanceAuthMethod.PASSWORD -> SshAuthRef.Password(secretId)
                Phase89AcceptanceAuthMethod.PRIVATE_KEY -> SshAuthRef.PrivateKey(secretId)
            }
            val access = ServerAccess(
                id = accessId,
                serverId = serverId,
                endpoint = SshEndpoint(parsed.host, parsed.port),
                username = parsed.username,
                auth = auth,
                pinnedHostKey = HostKeyFingerprint(parsed.hostKeySha256),
            )
            val startedAt = Instant.now()
            serverRepo.create(Server(serverId, "Phase 8.9 disposable Test Lab", startedAt))
                .requireRepositorySuccess("create exact Phase 8.9 Server")
            credentialWriter.createServerAccess(access)
                .requireRepositorySuccess("create exact Phase 8.9 ServerAccess")

            // Acceptance uses an isolated temporary DB. Prove no unrelated saved Server/Access can
            // participate in the destructive run.
            val servers = serverRepo.list().requireRepositorySuccess("list isolated Phase 8.9 Servers")
            assertEquals(1, servers.size)
            assertEquals(serverId, servers.single().value.id)
            val accesses = accessRepo.listForServer(serverId)
                .requireRepositorySuccess("list isolated Phase 8.9 ServerAccess")
            assertEquals(listOf(accessId), accesses.map { it.id })

            val initial = OperationSnapshot(
                operationId = operationId,
                type = OperationType.INSTALL,
                target = OperationTarget.ServerTarget(serverId, accessId),
                status = OperationStatus.RUNNING,
                checkpoint = OperationCheckpoint(
                    phaseName = "PHASE8_9_FRESH_PREFLIGHT",
                    semantics = CheckpointSemantics.MUTATION_NOT_STARTED,
                    recordedAt = startedAt,
                ),
                startedAt = startedAt,
                updatedAt = startedAt,
            )
            val current = journal.create(initial).requireOperationSuccess("create exact Phase 8.9 INSTALL operation")

            val registry = ExactSessionRegistry()
            sessions = registry
            val sessionCounter = AtomicInteger(0)
            val runtime = OperationRuntimeCoordinator(
                journal = journal,
                accessRepository = accessRepo,
                connectionFactory = JschSshConnectionFactory(secretStore) {
                    SessionId("phase8-9-session-${sessionCounter.incrementAndGet()}-$runTag")
                },
                sessionRegistry = registry,
                installationRepository = installationRepo,
                managementAccessRepository = managementRepo,
                managementEnrollmentPublisher = publisher,
            )

            val bootstrap = runtime.bootstrapRecovery(RecoveryExitProvenance.UNKNOWN).requireSuccess()
            val plan = bootstrap.items.asSequence()
                .filterIsInstance<RecoveryBootstrapItem.Planned>()
                .map { it.plan }
                .singleOrNull { it.operationId == operationId }
                ?: throw AssertionError("Phase 8.9 bootstrap did not produce exactly one plan for the INSTALL operation")
            val admission = (runtime.admitRecovery(plan, RecoveryAdmissionAuthority.EXPLICIT_USER_ALLOWED)
                as? RecoveryAdmissionResult.Admitted)?.admission
                ?: throw AssertionError("Phase 8.9 exact runtime admission was not granted")

            try {
                val online = runtime.observeConnectivity(ConnectivityState.ONLINE)
                val reconnect = runtime.beginReconnect(
                    admission = admission,
                    observation = online,
                    budget = RetryBudget(maxAttempts = 1),
                )
                val connected = reconnect as? ExactReconnectResult.Connected
                    ?: throw AssertionError("Phase 8.9 exact SSH connect failed closed: ${reconnect::class.java.simpleName}")
                assertEquals(1, connected.attemptNumber)
                assertEquals(1, sessionCounter.get())

                val owner = SessionOwner.Operation(operationId)
                val session = registry.find(owner, accessId)
                    ?: throw AssertionError("Phase 8.9 exact connected session was not published")
                assertEquals(connected.binding, session.binding)
                assertTrue(session.isOpen)

                // SAME-SESSION READ-ONLY PREFLIGHT — no Installer mutation authority exists yet.
                val scope = DiscoveryScope(operationId, serverId, accessId)
                val discoveryRun = DiscoverySshProbeExecutor().executeInitialPlan(scope, session)
                val evidence = (discoveryRun as? DiscoverySshProbeRunResult.Completed)?.evidence
                    ?: throw AssertionError("Phase 8.9 read-only Discovery preflight failed: $discoveryRun")
                val classification = DiscoveryClassifier.classify(evidence)
                assertEquals(
                    "Disposable VPS is not proven fresh for supported 3x-ui installation",
                    DiscoveryClassification.NoSupportedInstallation,
                    classification,
                )
                val platform = evidence.observations.filterIsInstance<DiscoveryObservation.Platform>()
                    .singleOrNull()?.platform
                    ?: throw AssertionError("Phase 8.9 preflight did not produce one exact platform observation")
                assertEquals("ubuntu", platform.distributionId.lowercase())
                assertSupportedRootPathsExplicitlyAbsent(evidence.observations)

                val managedInstallId = ManagedInstallIdentityPolicy.forOperation(operationId)
                val capabilityResult = session.execute(
                    command = RemoteCommand.create(
                        raw = capabilityPreflightCommand(managedInstallId.value),
                        redactedLabel = "phase8-9-disposable-vps-read-only-capability-preflight",
                    ),
                    config = SshTransportConfig(
                        channelOpenTimeout = Duration.ofSeconds(5),
                        commandExecutionTimeout = Duration.ofSeconds(15),
                        stdoutCaptureLimitBytes = 256,
                        stderrCaptureLimitBytes = 512,
                    ),
                )
                assertEquals(CommandDispatchState.DISPATCHED, capabilityResult.dispatchState)
                assertEquals(CommandCompletion.ConfirmedSuccess, capabilityResult.completion)
                assertFalse(capabilityResult.stdout.truncated)
                assertFalse(capabilityResult.stderr.truncated)
                val preflightBytes = capabilityResult.stdout.copyBytes()
                try {
                    assertEquals(PREFLIGHT_OK, preflightBytes.toString(StandardCharsets.UTF_8))
                } finally {
                    Arrays.fill(preflightBytes, 0)
                }
                assertEquals(0, capabilityResult.stderr.sizeBytes)

                // Only now may process-local mutation authority exist. It stays bound to the exact
                // operation/server/access just observed on this same live pinned SSH session.
                val observedAt = Instant.now()
                val proof = FreshInstallPreflightProof(
                    id = TargetProofId("phase8-9-proof-$runTag"),
                    scope = FreshInstallScope(operationId, serverId, accessId),
                    platform = DiscoveryPlatform(platform.distributionId, platform.versionId),
                    installerCapability = FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1,
                    privilegeCapability = FreshInstallPrivilegeCapability.DIRECT_ROOT,
                    conflictState = FreshInstallConflictState.PROVEN_CLEAR,
                    observedAt = observedAt,
                    validUntil = observedAt.plusSeconds(PROOF_VALIDITY_SECONDS),
                )
                val verified = FreshInstallAuthorizationPolicy.verify(current.snapshot, proof, observedAt)
                val freshTarget = (verified as? FreshInstallVerificationResult.Verified)?.target
                    ?: throw AssertionError("Phase 8.9 fresh-install proof was rejected: $verified")
                assertEquals(managedInstallId, freshTarget.managedInstallId)
                assertEquals(
                    InstallerRuntimeEntryRegistrationResult.Registered,
                    runtime.registerInstallerFreshAuthorization(freshTarget),
                )
                assertEquals(
                    InstallerRuntimePreparationResult.TransportRequired,
                    runtime.prepareInstallerTransport(admission),
                )

                // DESTRUCTIVE BOUNDARY: one production Installer execution, on this same exact
                // connection, with no retry path in this acceptance.
                val executed = runtime.executeInstaller(admission, connected.binding)
                val postInstall = (executed as? InstallerRuntimeExecutionResult.PostInstall)?.result
                    ?: throw AssertionError("Phase 8.9 production Installer did not reach post-install result: $executed")
                val succeeded = postInstall as? InstallerPostInstallCoordinatorResult.Succeeded
                    ?: throw AssertionError("Phase 8.9 post-install verification/publication did not succeed: $postInstall")
                assertEquals(OperationStatus.SUCCEEDED, succeeded.durable.snapshot.status)
                assertEquals(CheckpointSemantics.TERMINAL, succeeded.durable.snapshot.checkpoint.semantics)

                val finalJournal = journal.get(operationId).requireOperationSuccess("read final Phase 8.9 operation")
                assertEquals(OperationStatus.SUCCEEDED, finalJournal.snapshot.status)
                assertEquals(CheckpointSemantics.TERMINAL, finalJournal.snapshot.checkpoint.semantics)

                val installations = installationRepo.listForServer(serverId)
                    .requireRepositorySuccess("list Phase 8.9 XuiInstallation")
                assertEquals(1, installations.size)
                val installed = installations.single().value
                assertEquals(serverId, installed.serverId)
                assertEquals(managedInstallId, installed.identity.managedInstallId)

                val management = managementRepo.listForServerAccess(accessId)
                    .requireRepositorySuccess("list Phase 8.9 ManagementAccess")
                assertEquals(1, management.size)
                assertEquals(installed.id, management.single().installationId)
                assertEquals(accessId, management.single().serverAccessId)
                assertTrue(
                    webPanelRepo.list().requireRepositorySuccess("list Phase 8.9 WebPanelAccess").isEmpty(),
                )
                assertEquals(1, sessionCounter.get())
            } finally {
                // Exact cleanup is local/session only. We intentionally do not change the remote VPS
                // again after the Installer result, including on failure or uncertainty.
                runtime.discardInstallerFreshAuthorization(operationId)
                val handle = registry.find(SessionOwner.Operation(operationId), accessId)
                if (handle != null) {
                    runtime.closeExactSession(admission, handle.binding)
                }
                assertEquals(OperationRuntimeReleaseResult.RELEASED, runtime.release(admission))
            }
        } finally {
            parsed.closeSensitiveBytes()
            sessions?.close()
            secretStore.delete(secretId)
            database?.close()
            context.deleteDatabase(dbName)
            runCatching { configFile.delete() }
        }
    }

    private fun assertSupportedRootPathsExplicitlyAbsent(observations: List<DiscoveryObservation>) {
        val roots = observations.filterIsInstance<DiscoveryObservation.InstallationPath>()
            .filter { it.pathKind == DiscoveryPathKind.ROOT }
            .associate { it.path to it.presence }
        for (path in DiscoveryProbePlan.supportedRootProbePaths) {
            assertEquals(
                "Supported root path must be explicitly absent before destructive fresh install: $path",
                DiscoveryPresence.ABSENT,
                roots[path],
            )
        }
    }

    private fun capabilityPreflightCommand(managedInstallId: String): String {
        require(managedInstallId.matches(Regex("v1-[0-9a-f]{32}")))
        val workDir = "/var/lib/velum-tegra/installer/v1/$managedInstallId"
        return """
            set -eu
            [ "${'$'}(id -u)" = "0" ] || exit 41
            for c in install curl sha1sum wc tr awk chmod mv setsid nohup date sleep cat dirname rm sh; do
              command -v "${'$'}c" >/dev/null 2>&1 || exit 42
            done
            [ ! -e '/var/lib/velum-tegra/managed-install/v1/identity' ] || exit 43
            [ ! -e '$workDir' ] || exit 44
            printf '$PREFLIGHT_OK'
        """.trimIndent()
    }

    private fun RecoveryBootstrapResult.requireSuccess(): RecoveryBootstrapResult.Success =
        this as? RecoveryBootstrapResult.Success
            ?: throw AssertionError("Phase 8.9 recovery bootstrap failed: ${this::class.java.simpleName}")

    private fun <T> RepositoryResult<T>.requireRepositorySuccess(action: String): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("$action failed: ${this::class.java.simpleName}")
    }

    private fun <T> OperationJournalResult<T>.requireOperationSuccess(action: String): T = when (this) {
        is OperationJournalResult.Success -> value
        else -> throw AssertionError("$action failed: ${this::class.java.simpleName}")
    }

    private fun assertInternetPermissionDeclared() {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        assertTrue(
            "Target debug app must declare android.permission.INTERNET before Phase 8.9",
            info.requestedPermissions?.contains(Manifest.permission.INTERNET) == true,
        )
    }

    private companion object {
        const val CONFIG_FILE_NAME = "phase8_9_disposable_vps_acceptance.properties"
        const val PREFLIGHT_OK = "VELUM_PHASE8_9_PREFLIGHT_OK"
        const val PROOF_VALIDITY_SECONDS = 300L
    }
}

private enum class Phase89AcceptanceAuthMethod {
    PASSWORD,
    PRIVATE_KEY,
}

/** Sensitive fields are byte arrays so they can be wiped immediately after SecretStore handoff. */
private class Phase89OneShotAcceptanceConfig private constructor(
    val host: String,
    val port: Int,
    val username: String,
    val hostKeySha256: String,
    val targetLabel: String,
    val destructiveAuthorized: Boolean,
    val authMethod: Phase89AcceptanceAuthMethod,
    private var password: ByteArray?,
    private var privateKey: ByteArray?,
    private var passphrase: ByteArray?,
) {
    fun toSecretMaterial(): SecretMaterial = when (authMethod) {
        Phase89AcceptanceAuthMethod.PASSWORD -> SecretMaterial.fromBytes(
            password ?: error("Phase 8.9 password material is already closed"),
        )
        Phase89AcceptanceAuthMethod.PRIVATE_KEY -> SshPrivateKeyCredentialMaterial.create(
            privateKey ?: error("Phase 8.9 private-key material is already closed"),
            passphrase,
        )
    }

    fun closeSensitiveBytes() {
        password?.let { Arrays.fill(it, 0) }
        privateKey?.let { Arrays.fill(it, 0) }
        passphrase?.let { Arrays.fill(it, 0) }
        password = null
        privateKey = null
        passphrase = null
    }

    companion object {
        private const val MAX_CONFIG_BYTES = 2 * 1024 * 1024

        fun readAndDelete(file: File): Phase89OneShotAcceptanceConfig {
            val bytes = file.readBytes()
            try {
                require(bytes.size in 1..MAX_CONFIG_BYTES) { "Phase 8.9 config size is invalid" }
                val text = bytes.toString(StandardCharsets.US_ASCII)
                val values = text.lineSequence()
                    .map { it.trimEnd('\r') }
                    .filter { it.isNotBlank() }
                    .associate { line ->
                        val separator = line.indexOf('=')
                        require(separator > 0) { "Phase 8.9 config line is malformed" }
                        line.substring(0, separator) to line.substring(separator + 1)
                    }

                require(values["version"] == "1") { "Phase 8.9 config version is unsupported" }
                require(values["destructive_authorized"] == "1") { "Phase 8.9 destructive authorization is absent" }
                val host = decodeUtf8(values.require("host_b64"), "host")
                val username = decodeUtf8(values.require("username_b64"), "username")
                val hostKey = decodeUtf8(values.require("hostkey_b64"), "host key fingerprint")
                val targetLabel = decodeUtf8(values.require("target_label_b64"), "disposable target label")
                require(hostKey.startsWith("SHA256:") && hostKey.length > 7) {
                    "Phase 8.9 host-key fingerprint must use canonical SHA256: form"
                }
                val port = values.require("port").toIntOrNull()
                    ?: throw IllegalArgumentException("Phase 8.9 SSH port is invalid")
                require(port in 1..65535) { "Phase 8.9 SSH port is invalid" }

                return when (values.require("auth")) {
                    "password" -> Phase89OneShotAcceptanceConfig(
                        host = host,
                        port = port,
                        username = username,
                        hostKeySha256 = hostKey,
                        targetLabel = targetLabel,
                        destructiveAuthorized = true,
                        authMethod = Phase89AcceptanceAuthMethod.PASSWORD,
                        password = decodeBytes(values.require("password_b64"), "password").also {
                            require(it.isNotEmpty()) { "Phase 8.9 password must not be empty" }
                        },
                        privateKey = null,
                        passphrase = null,
                    )
                    "privatekey" -> {
                        val hasPassphrase = when (values.require("passphrase_present")) {
                            "0" -> false
                            "1" -> true
                            else -> throw IllegalArgumentException("Phase 8.9 passphrase_present is invalid")
                        }
                        Phase89OneShotAcceptanceConfig(
                            host = host,
                            port = port,
                            username = username,
                            hostKeySha256 = hostKey,
                            targetLabel = targetLabel,
                            destructiveAuthorized = true,
                            authMethod = Phase89AcceptanceAuthMethod.PRIVATE_KEY,
                            password = null,
                            privateKey = decodeBytes(values.require("private_key_b64"), "private key").also {
                                require(it.isNotEmpty()) { "Phase 8.9 private key must not be empty" }
                            },
                            passphrase = if (hasPassphrase) decodeBytes(values.require("passphrase_b64"), "passphrase") else null,
                        )
                    }
                    else -> throw IllegalArgumentException("Phase 8.9 SSH auth method is unsupported")
                }
            } finally {
                Arrays.fill(bytes, 0)
                runCatching { file.delete() }
            }
        }

        private fun Map<String, String>.require(key: String): String =
            get(key) ?: throw IllegalArgumentException("Phase 8.9 config is missing $key")

        private fun decodeUtf8(value: String, field: String): String {
            val bytes = decodeBytes(value, field)
            return try {
                bytes.toString(StandardCharsets.UTF_8).also {
                    require(it.isNotBlank()) { "Phase 8.9 $field must not be blank" }
                }
            } finally {
                Arrays.fill(bytes, 0)
            }
        }

        private fun decodeBytes(value: String, field: String): ByteArray = try {
            Base64.decode(value, Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Phase 8.9 $field is not valid base64")
        }
    }
}
