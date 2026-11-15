package com.velumtegra.xuimobile.sitedeployer

import android.util.Log
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteCaddyServingPlan
import com.velumtegra.xuimobile.core.site.SiteCaddyServingPlanner
import com.velumtegra.xuimobile.core.site.SiteServingBackend
import com.velumtegra.xuimobile.core.site.SiteServingFailureCategory
import com.velumtegra.xuimobile.core.site.SiteServingOutcome
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SiteCaddyApplyObservation
import com.velumtegra.xuimobile.core.ssh.SiteCaddyApplyResult
import com.velumtegra.xuimobile.core.ssh.SiteCaddyCommandFailedException
import com.velumtegra.xuimobile.core.ssh.SiteCaddyRollbackResult
import com.velumtegra.xuimobile.core.ssh.SiteCaddyServingSshAdapter
import com.velumtegra.xuimobile.core.ssh.SiteExternalReachabilityProbe
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.time.Duration
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Opens exactly one pinned-host-key SSH session from one fresh one-shot credential lease, runs
 * [block] and always closes the session. No retry and no fallback.
 */
internal object SiteProductionDeploymentAndroidVerifiedSession {
    suspend fun <T> use(
        serverAccess: ServerAccess,
        credential: SiteProductionDeploymentRealVpsExecutionCredential,
        label: String,
        block: suspend (VerifiedHostKeySshSessionHandle) -> T,
    ): T {
        val proof = credential.proof
        val lease = credential.lease
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.validateProof(proof)
        require(
            proof.status == SiteProductionDeploymentRealVpsCredentialResolutionExecutionStatus.RESOLVED_TO_EPHEMERAL_LEASE,
        ) { "Fresh credential was not resolved" }
        require(proof.serverAccessId == serverAccess.id.value) { "Credential belongs to a different ServerAccess" }
        require(lease.serverAccessId == serverAccess.id.value) { "Credential lease belongs to a different ServerAccess" }
        require(lease.credentialResolutionConsumptionReceiptSha256 == proof.credentialResolutionConsumptionReceiptSha256)
        require(credential.executedAtEpochMillis <= proof.authorizationExpiresAtEpochMillis) {
            "Fresh credential authorization expired"
        }
        val expectedHostKeySha256 = when (val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
            is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
        }
        val nonce = UUID.randomUUID().toString().replace("-", "").take(24)
        val owner = SessionOwner.Operation(OperationId("${label}_owner_$nonce"))
        val sessionId = SessionId("${label}_session_$nonce")
        val factory = JschSshConnectionFactory(
            secretStore = OneShotLeaseSecretStore(serverAccess.auth.secretId, lease),
            sessionIdFactory = { sessionId },
        )
        val registry = ExactSessionRegistry()
        var handle: VerifiedHostKeySshSessionHandle? = null
        try {
            val connect = factory.connect(
                access = serverAccess,
                owner = owner,
                config = SshTransportConfig(
                    tcpConnectTimeout = Duration.ofSeconds(8),
                    handshakeAndAuthTimeout = Duration.ofSeconds(12),
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(30),
                    stdoutCaptureLimitBytes = 64 * 1024,
                    stderrCaptureLimitBytes = 64 * 1024,
                ),
            )
            val connected = connect as? SshConnectResult.Connected
                ?: error("SSH-подключение к серверу не удалось (${(connect as SshConnectResult.Failed).failure::class.java.simpleName})")
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                error("SSH session lacks verified host-key evidence")
            }
            handle = verified
            require(verified.verifiedHostKeySha256 == expectedHostKeySha256) { "Server host key differs from the pinned key" }
            require(registry.install(verified) == SessionInstallResult.Installed)
            val result = block(verified)
            require(registry.remove(owner, serverAccess.id, verified.binding.sessionId, close = true))
            handle = null
            return result
        } finally {
            runCatching { handle?.close() }
            registry.close()
            runCatching { lease.close() }
        }
    }

    private class OneShotLeaseSecretStore(
        private val expectedSecretId: SecretId,
        private val credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
    ) : SecretStore {
        private val readStarted = AtomicBoolean(false)

        override suspend fun read(secretId: SecretId): SecretReadResult {
            if (secretId != expectedSecretId) return SecretReadResult.NotFound
            if (!readStarted.compareAndSet(false, true)) {
                return SecretReadResult.Unavailable("Ephemeral credential lease is single-use")
            }
            val copy = credentialLease.useMaterialOnce { material -> material.useBytes { SecretMaterial.fromBytes(it) } }
            return SecretReadResult.Found(copy)
        }

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            SecretCreateResult.StorageFailure("Caddy serving lease adapter is read-only")

        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Caddy serving lease adapter is read-only")

        override suspend fun listIds(): SecretListResult =
            SecretListResult.StorageFailure("Caddy serving lease adapter does not enumerate secrets")
    }
}

/**
 * Caddy serving after one successful exact-static-tree commit.
 *
 * Action: apply the reviewed [SiteCaddyServingPlan] (backup, one managed site file, one import line,
 * `caddy validate`, reload), then verify through loopback with the exact SNI and from the device.
 * Consequence: the site is reported as published only when the device fetched the exact index.html.
 * Counteraction: invalid config never reaches reload; a failed reload restores the backup in the
 * same remote script; a failed on-server verification restores the backup and reloads again. No
 * DNS, firewall or package change is ever made, and nothing is retried automatically.
 */
internal object SiteProductionDeploymentAndroidCaddyServingOrchestrator {
    suspend fun executeOnce(
        plan: SiteCaddyServingPlan,
        serverAccess: ServerAccess,
        credentialProvider: SiteProductionDeploymentPostCoordinatorFreshExecutionCredentialProvider,
        externalProbe: SiteExternalReachabilityProbe = SiteExternalReachabilityProbe(),
    ): SiteServingOutcome {
        SiteCaddyServingPlanner.validate(plan)
        require(plan.remoteHostIdentity == serverAccess.endpoint.host) { "Caddy plan targets a different server" }
        val adapter = SiteCaddyServingSshAdapter()

        val applyCredential = credentialProvider.acquire(SiteProductionDeploymentPostCoordinatorCredentialPurpose.CADDY_APPLY)
        val applied: SiteCaddyApplyObservation = try {
            SiteProductionDeploymentAndroidVerifiedSession.use(serverAccess, applyCredential, "caddy_apply") {
                adapter.apply(plan, it)
            }
        } catch (failure: SiteCaddyCommandFailedException) {
            // The remote apply ended without a RESULT (non-zero exit, timeout, lost channel), so the
            // Caddyfile state is unknown. One bounded rollback from the backup is the counteraction;
            // the consumed publication itself is never retried.
            Log.e(
                TAG,
                "Caddy apply ended without result: stage=${failure.stage} exit=${failure.exitCode} " +
                    "timedOut=${failure.timedOut} stderr=${failure.stderrTail}",
            )
            val rollback = rollbackOnce(plan, serverAccess, credentialProvider, adapter)
            return notPublished(
                plan,
                SiteServingFailureCategory.SERVER_COMMAND_FAILED,
                (failure.message ?: "Команда Caddy завершилась с ошибкой") + rollbackSuffix(plan, rollback),
                rolledBack = rollback == SiteCaddyRollbackResult.ROLLED_BACK,
                served = false,
            )
        }
        if (applied.result != SiteCaddyApplyResult.APPLIED) {
            val (category, message) = when (applied.result) {
                SiteCaddyApplyResult.CADDY_NOT_ACTIVE ->
                    SiteServingFailureCategory.RELOAD_FAILED to "Caddy не в состоянии active (${applied.detail.orEmpty().trim()}). " +
                        "Ничего не изменено; приложение не перезапускает Caddy само — проверьте journalctl -u caddy"
                SiteCaddyApplyResult.CERTIFICATE_UNREADABLE ->
                    SiteServingFailureCategory.CERTIFICATE to "Служба Caddy не может прочитать файл сертификата " +
                        "(${applied.detail.orEmpty().trim()}). Ничего не изменено"
                SiteCaddyApplyResult.CADDYFILE_CHANGED ->
                    SiteServingFailureCategory.CONFIG_INVALID to "Caddyfile изменился после проверки сервера — проверьте сервер ещё раз"
                SiteCaddyApplyResult.SITE_FILE_EXISTS ->
                    SiteServingFailureCategory.PORT_CONFLICT to "Сайт с этим адресом уже добавлен в Caddy"
                SiteCaddyApplyResult.BACKUP_EXISTS ->
                    SiteServingFailureCategory.CONFIG_INVALID to "Осталась резервная копия Caddyfile от прошлой попытки: ${plan.backupPath}"
                SiteCaddyApplyResult.BACKUP_FAILED, SiteCaddyApplyResult.WRITE_FAILED ->
                    SiteServingFailureCategory.CONFIG_INVALID to "Не удалось записать конфиг Caddy (нет прав?)"
                SiteCaddyApplyResult.VALIDATE_FAILED ->
                    SiteServingFailureCategory.CONFIG_INVALID to "Caddy не принял конфиг: ${applied.detail.orEmpty().trim().take(300)}"
                SiteCaddyApplyResult.RELOAD_FAILED_ROLLED_BACK ->
                    SiteServingFailureCategory.RELOAD_FAILED to "Caddy не перезагрузился, прежний конфиг восстановлен: ${applied.detail.orEmpty().trim().take(300)}"
                SiteCaddyApplyResult.RELOAD_FAILED_ROLLBACK_FAILED ->
                    SiteServingFailureCategory.RELOAD_FAILED to "Caddy не перезагрузился и откат не удался. Резервная копия: ${plan.backupPath}"
                SiteCaddyApplyResult.APPLIED -> error("unreachable")
            }
            Log.w(TAG, "Caddy apply refused: result=${applied.result} detail=${applied.detail.orEmpty()}")
            return notPublished(plan, category, "Этап «применение конфига Caddy»: $message", rolledBack = applied.result != SiteCaddyApplyResult.RELOAD_FAILED_ROLLBACK_FAILED, served = false)
        }

        val verifyCredential = credentialProvider.acquire(SiteProductionDeploymentPostCoordinatorCredentialPurpose.CADDY_VERIFY)
        val verified = runCatching {
            SiteProductionDeploymentAndroidVerifiedSession.use(serverAccess, verifyCredential, "caddy_verify") {
                adapter.verify(plan, it)
            }
        }.getOrElse { error ->
            Log.e(TAG, "On-server verification failed: ${error.message}")
            null
        }
        val lostPorts = verified?.let { plan.preservedListeningPorts - it.listeningPorts }.orEmpty()
        val servedOnServer = verified != null && verified.caddyActive && verified.bodySha256 == plan.indexSha256 && lostPorts.isEmpty()
        if (!servedOnServer) {
            val rollback = rollbackOnce(plan, serverAccess, credentialProvider, adapter)
            val (category, reason) = when {
                verified == null -> SiteServingFailureCategory.SERVING_VERIFICATION to "Не удалось проверить сайт на сервере"
                !verified.caddyActive -> SiteServingFailureCategory.RELOAD_FAILED to "Caddy перестал работать после перезагрузки"
                lostPorts.isNotEmpty() -> SiteServingFailureCategory.SERVING_VERIFICATION to
                    "После перезагрузки Caddy перестали слушаться порты ${lostPorts.sorted().joinToString()}"
                verified.curlExitCode in setOf(35, 51, 58, 60) -> SiteServingFailureCategory.CERTIFICATE to
                    "Caddy не смог выдать сертификат для ${plan.domain} (проверьте DNS и доступность портов 80/443)"
                else -> SiteServingFailureCategory.SERVING_VERIFICATION to "Caddy отдаёт не опубликованную страницу"
            }
            return notPublished(plan, category, "Этап «проверка сайта на сервере»: " + reason + rollbackSuffix(plan, rollback), rolledBack = rollback == SiteCaddyRollbackResult.ROLLED_BACK, served = false)
        }

        val external = externalProbe.fetch(plan.plannedUrl + "index.html", plan.indexSha256)
        return if (external.reachable) {
            SiteServingOutcome(
                backend = SiteServingBackend.CADDY,
                plannedUrl = plan.plannedUrl,
                verifiedUrl = plan.plannedUrl,
                servedOnServer = true,
                externallyReachable = true,
                configRolledBack = false,
                failureCategory = null,
                failureMessage = null,
            )
        } else {
            // Caddy serves the site on the server; keep it (DNS/firewall may simply need time) but
            // report honestly that it is not reachable from outside yet.
            notPublished(
                plan,
                external.failureCategory ?: SiteServingFailureCategory.EXTERNAL_UNREACHABLE,
                (external.failureMessage ?: "Сайт недоступен снаружи") + " Caddy уже обслуживает сайт на сервере.",
                rolledBack = false,
                served = true,
            )
        }
    }

    private const val TAG = "SiteCaddyServing"

    private suspend fun rollbackOnce(
        plan: SiteCaddyServingPlan,
        serverAccess: ServerAccess,
        credentialProvider: SiteProductionDeploymentPostCoordinatorFreshExecutionCredentialProvider,
        adapter: SiteCaddyServingSshAdapter,
    ): SiteCaddyRollbackResult = runCatching {
        val rollbackCredential = credentialProvider.acquire(SiteProductionDeploymentPostCoordinatorCredentialPurpose.CADDY_ROLLBACK)
        SiteProductionDeploymentAndroidVerifiedSession.use(serverAccess, rollbackCredential, "caddy_rollback") {
            adapter.rollback(plan, it)
        }
    }.getOrElse { error ->
        Log.e(TAG, "Caddy rollback failed: ${error.message}")
        SiteCaddyRollbackResult.ROLLBACK_FAILED
    }

    private fun rollbackSuffix(plan: SiteCaddyServingPlan, rollback: SiteCaddyRollbackResult): String = when (rollback) {
        SiteCaddyRollbackResult.ROLLED_BACK -> " Конфиг Caddy возвращён как был."
        SiteCaddyRollbackResult.NO_BACKUP -> " Резервная копия не найдена: изменения в Caddyfile не вносились или уже откатаны."
        SiteCaddyRollbackResult.ROLLBACK_FAILED -> " Откат не удался, резервная копия: ${plan.backupPath}."
    }

    private fun notPublished(
        plan: SiteCaddyServingPlan,
        category: SiteServingFailureCategory,
        message: String,
        rolledBack: Boolean,
        served: Boolean,
    ) = SiteServingOutcome(
        backend = SiteServingBackend.CADDY,
        plannedUrl = plan.plannedUrl,
        verifiedUrl = null,
        servedOnServer = served,
        externallyReachable = false,
        configRolledBack = rolledBack,
        failureCategory = category,
        failureMessage = message,
    )
}
