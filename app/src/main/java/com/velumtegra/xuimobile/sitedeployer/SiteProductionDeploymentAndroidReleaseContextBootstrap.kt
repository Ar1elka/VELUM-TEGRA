package com.velumtegra.xuimobile.sitedeployer

import android.os.Build
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteCaddyCertificateCandidate
import com.velumtegra.xuimobile.core.site.SiteCaddyCertificatePolicy
import com.velumtegra.xuimobile.core.site.SiteCaddyCertificateSelection
import com.velumtegra.xuimobile.core.site.SiteCaddyServingPlan
import com.velumtegra.xuimobile.core.site.SiteCaddyServingPlanner
import com.velumtegra.xuimobile.core.site.SiteDeployerRemoteTreeExpectation
import com.velumtegra.xuimobile.core.site.SiteFirewallPolicy
import com.velumtegra.xuimobile.core.site.SiteServingBackend
import com.velumtegra.xuimobile.core.site.SiteServingBackendPolicy
import com.velumtegra.xuimobile.core.site.SiteServingFailureCategory
import com.velumtegra.xuimobile.core.site.SiteWebServerInventory
import com.velumtegra.xuimobile.core.site.SiteDeploymentCoordinatorRequest
import com.velumtegra.xuimobile.core.site.SiteEndpointObservation
import com.velumtegra.xuimobile.core.site.SiteExistingSiteMode
import com.velumtegra.xuimobile.core.site.SiteExistingSitePolicy
import com.velumtegra.xuimobile.core.site.SiteExistingSiteReport
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityBoundary
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityStatus
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentExecutionApproval
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentExecutionRequest
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReadinessBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReadinessRequest
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentReadinessStatus
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeIdentity
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationApproval
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationBoundary
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationRequest
import com.velumtegra.xuimobile.core.site.SiteProductionObservationFreshnessPolicy
import com.velumtegra.xuimobile.core.site.SiteProductionOperatorApproval
import com.velumtegra.xuimobile.core.site.SiteProductionServiceBindingIntent
import com.velumtegra.xuimobile.core.site.SiteProductionServiceBindingObservation
import com.velumtegra.xuimobile.core.site.SiteProductionServiceBindingReadinessMode
import com.velumtegra.xuimobile.core.site.SiteRemoteCertificateObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployBoundary
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployRequest
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightObservation
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightTrust
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportPolicy
import com.velumtegra.xuimobile.core.site.ThemeFamily
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SessionInstallResult
import com.velumtegra.xuimobile.core.ssh.SiteCaddyServingSshAdapter
import com.velumtegra.xuimobile.core.ssh.SiteExternalReachabilityProbe
import com.velumtegra.xuimobile.core.ssh.SiteFirstPublicationReadOnlyObservationSshAdapter
import com.velumtegra.xuimobile.core.ssh.SiteRemoteReadOnlyObservationSshAdapter
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpPrimitiveFactory
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshTransportConfig
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import java.io.File
import java.time.Duration
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Exact stored target shown to the operator. No entry is selected implicitly. */
data class SiteDeployerReleaseTargetOption(
    val serverId: String,
    val serverAccessId: String,
    val serverDisplayName: String,
    val remoteHostIdentity: String,
    val sshPort: Int,
    val sshUsername: String,
)

data class SiteDeployerReleaseBootstrapRequest(
    val serverId: String,
    val serverAccessId: String,
    val rootSeed: Long,
    val siteName: String?,
    val tagline: String?,
    val themeFamily: ThemeFamily?,
    val domain: String,
    val servicePort: Int,
    val targetRoot: String,
    val reuseExisting3xUiCertificate: Boolean,
    val existingSiteMode: SiteExistingSiteMode = SiteExistingSiteMode.DETECT_ONLY,
    /** Files-only replacement: the existing nginx config serves HTTPS, so verify over https. */
    val existingSiteServedOverHttps: Boolean = false,
)

/**
 * Thrown by the read-only preparation when the selected server already has a site in the requested
 * folder or something already listens on the requested port. Nothing was changed on the server;
 * the UI shows [report] and lets the operator choose another port or an explicit replacement.
 */
class SiteDeployerExistingSiteConflictException(
    val report: SiteExistingSiteReport,
    message: String,
) : IllegalStateException(message)

/**
 * Thrown by the read-only preparation when publication cannot work on this server as configured:
 * incompatible web server, DNS not pointing to the server, or the port closed by UFW. Nothing was
 * changed; the UI shows [category] and the concrete [message].
 */
class SiteDeployerServingBlockedException(
    val category: SiteServingFailureCategory,
    message: String,
) : IllegalStateException(message)

data class SiteDeployerReleaseBootstrapResult(
    val serverId: String,
    val serverAccessId: String,
    val remoteObservation: SiteRemotePreflightObservation,
    val serviceBindingConfigured: Boolean,
    val releaseBootstrapAdmissionSha256: String,
    val coordinatorPermitExpiresAtEpochMillis: Long,
    /** True when an existing site in the same folder will be replaced. */
    val replacesExistingSite: Boolean = false,
    /** Web server that will serve the site (null for a files-only replacement). */
    val servingBackend: SiteServingBackend? = null,
    /** Address that will be verified from the device after publication. */
    val plannedUrl: String? = null,
)

/**
 * Phase 11.100 UI-facing bootstrap seam. Loading targets is local read-only persistence access;
 * prepareReviewedFirstPublicationContext performs bounded read-only live evidence collection and
 * composes already-reviewed authorization records. It does not execute deployment itself.
 */
interface SiteDeployerReleaseBootstrapPort {
    suspend fun loadTargets(): List<SiteDeployerReleaseTargetOption>
    suspend fun prepareReviewedFirstPublicationContext(
        request: SiteDeployerReleaseBootstrapRequest,
    ): SiteDeployerReleaseBootstrapResult
    fun clearPendingContext()

    /** Separately confirmed: install and start distro nginx on the exact selected server. */
    suspend fun installWebServer(serverId: String, serverAccessId: String): String =
        "Установка веб-сервера недоступна в этой сборке."
}

object DisabledSiteDeployerReleaseBootstrapPort : SiteDeployerReleaseBootstrapPort {
    override suspend fun loadTargets(): List<SiteDeployerReleaseTargetOption> = emptyList()
    override suspend fun prepareReviewedFirstPublicationContext(
        request: SiteDeployerReleaseBootstrapRequest,
    ): SiteDeployerReleaseBootstrapResult = error("Production release bootstrap is not configured")
    override fun clearPendingContext() = Unit
}

/**
 * Phase 11.100 production composition.
 *
 * Action: the operator explicitly selects one persisted ServerId + ServerAccessId and presses the
 * preparation button for the exact domain/port/target shown on screen.
 * Consequence: one fresh pinned-SSH read-only observation proves target/staging/capacity/ownership
 * plus the exact future nginx config/listen-port state, then the existing Phase 11 readiness,
 * execution and runtime-authorization chain is composed and published through the Phase 11.96 gate.
 * Counteraction: no target is auto-selected; any missing/mismatched record, stale/blocked evidence,
 * occupied endpoint, unavailable credential, absent requested 3x-ui certificate, or expired permit
 * fails closed before the deployment button becomes available. No new primitive mutation authority
 * is introduced here.
 */
internal class SiteProductionDeploymentAndroidReleaseContextBootstrapPort(
    private val application: VelumTegraApplication,
    private val serverRepositoryProvider: () -> ServerRepository,
    private val serverAccessRepositoryProvider: () -> ServerAccessRepository,
    private val cacheRoot: File,
    private val nowEpochMillis: () -> Long = System::currentTimeMillis,
    private val externalProbe: SiteExternalReachabilityProbe = SiteExternalReachabilityProbe(),
    private val connectionFactoryProvider: (() -> com.velumtegra.xuimobile.core.ssh.SshConnectionFactory)? = null,
) : SiteDeployerReleaseBootstrapPort {
    private val credentialSequence = AtomicInteger(0)

    override suspend fun installWebServer(serverId: String, serverAccessId: String): String = withContext(Dispatchers.IO) {
        val factory = connectionFactoryProvider?.invoke() ?: return@withContext "Установка веб-сервера недоступна в этой сборке."
        val server = serverRepositoryProvider().get(ServerId(serverId)).successValue("Сервер больше не существует").value
        val access = serverAccessRepositoryProvider().get(ServerAccessId(serverAccessId))
            .successValue("SSH-доступ больше не существует")
        require(access.serverId == server.id) { "SSH-доступ относится к другому серверу" }
        val owner = com.velumtegra.xuimobile.core.model.SessionOwner.Operation(
            com.velumtegra.xuimobile.core.model.OperationId("site-nginx-install-" + UUID.randomUUID()),
        )
        val connected = factory.connect(access, owner) as? com.velumtegra.xuimobile.core.ssh.SshConnectResult.Connected
            ?: return@withContext "Не удалось подключиться к серверу по SSH. nginx не устанавливался."
        connected.handle.use { session ->
            if (session.binding.serverAccessId != access.id) return@withContext "SSH-сессия относится к другому доступу."
            com.velumtegra.xuimobile.core.ssh.SiteNginxInstaller.install(session).message
        }
    }

    override suspend fun loadTargets(): List<SiteDeployerReleaseTargetOption> = withContext(Dispatchers.IO) {
        val serverRepository = serverRepositoryProvider()
        val serverAccessRepository = serverAccessRepositoryProvider()
        val servers = serverRepository.list().successValue("Unable to load stored servers")
        buildList {
            servers.forEach { versioned ->
                val server = versioned.value
                val accesses = serverAccessRepository.listForServer(server.id)
                    .successValue("Unable to load SSH access records for ${server.id.value}")
                accesses.forEach { access ->
                    add(
                        SiteDeployerReleaseTargetOption(
                            serverId = server.id.value,
                            serverAccessId = access.id.value,
                            serverDisplayName = server.displayName,
                            remoteHostIdentity = access.endpoint.host,
                            sshPort = access.endpoint.port,
                            sshUsername = access.username,
                        ),
                    )
                }
            }
        }.sortedWith(compareBy({ it.serverDisplayName }, { it.serverId }, { it.serverAccessId }))
    }

    override suspend fun prepareReviewedFirstPublicationContext(
        request: SiteDeployerReleaseBootstrapRequest,
    ): SiteDeployerReleaseBootstrapResult = withContext(Dispatchers.IO) {
        validateRequest(request)
        application.clearSiteDeployerProductionExecutionContext()
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            error("Production release bootstrap requires Android API 26+ for the accepted local Path-based export boundary")
        }

        val serverRepository = serverRepositoryProvider()
        val serverAccessRepository = serverAccessRepositoryProvider()
        val serverId = ServerId(request.serverId)
        val accessId = ServerAccessId(request.serverAccessId)
        val server = serverRepository.get(serverId).successValue("Selected ServerId no longer exists").value
        val access = serverAccessRepository.get(accessId).successValue("Selected ServerAccessId no longer exists")
        require(access.serverId == server.id) {
            "Selected ServerAccessId does not belong to the explicitly selected ServerId"
        }

        // Read-only DNS check from the device: the domain must already point to this server.
        // DNS records are never created or changed by the app.
        val dns = externalProbe.checkDns(SiteCaddyServingPlanner.canonicalDomain(request.domain), access.endpoint.host)
        if (!dns.pointsToServer) {
            throw SiteDeployerServingBlockedException(
                SiteServingFailureCategory.DNS,
                dns.failureMessage ?: "Домен не указывает на выбранный сервер",
            )
        }

        val replaceRequested = request.existingSiteMode == SiteExistingSiteMode.REPLACE_EXISTING
        val existingTargetPolicy = if (replaceRequested) {
            SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE
        } else {
            SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT
        }

        val nonce = UUID.randomUUID().toString().replace("-", "")
        val phaseRoot = File(cacheRoot, "phase11_100_$nonce")
        val localRoot = File(phaseRoot, "prepare")
        val coordinatorRoot = File(phaseRoot, "coordinator")
        require(localRoot.isDirectory || localRoot.mkdirs()) {
            "Unable to create Phase 11.100 local preparation directory"
        }
        require(coordinatorRoot.isDirectory || coordinatorRoot.mkdirs()) {
            "Unable to create Phase 11.100 coordinator directory"
        }

        val preparation = SiteDeployerLocalPreparationBoundary.prepare(
            SiteDeployerLocalPreparationRequest(
                rootSeed = DesignSeed(request.rootSeed),
                siteName = request.siteName,
                tagline = request.tagline,
                themeFamily = request.themeFamily,
                domain = request.domain,
                servicePort = request.servicePort,
                remoteHostIdentity = access.endpoint.host,
                targetRoot = request.targetRoot,
                owner = PRODUCTION_OWNER,
                group = PRODUCTION_GROUP,
                existingTargetPolicy = existingTargetPolicy,
                reuseExisting3xUiCertificate = request.reuseExisting3xUiCertificate,
            ),
            localRoot.toPath(),
        )
        SiteDeployerLocalPreparationBoundary.validate(preparation)

        val trustedKeySha256 = canonicalPinnedKey(access)
        val bootstrapCredential = resolveFreshCredential(access, preparation, "bootstrap")
        val live = try {
            observeReadOnlyBootstrap(
                access = access,
                preparation = preparation,
                resolved = bootstrapCredential,
                existingSiteMode = request.existingSiteMode,
                certificateReuseRequested = request.reuseExisting3xUiCertificate,
            )
        } finally {
            bootstrapCredential.lease.close()
        }

        // Replacing a site that nginx already serves for this exact folder/domain/port only swaps
        // files: no nginx activation, reload or certificate change is involved.
        val replacementKeepsServing = replaceRequested && live.endpoint.configPresent
        require(!(replacementKeepsServing && request.reuseExisting3xUiCertificate)) {
            "Сайт уже обслуживается nginx: для замены файлов сертификат не нужен — отключите повторное использование сертификата"
        }
        val certificateObservation = if (request.reuseExisting3xUiCertificate) {
            val certCredential = resolveFreshCredential(access, preparation, "certificate")
            val certProof = try {
                application.siteProductionDeploymentObserveRealVpsExisting3xUiCertificateReuseEligibilityOnce(
                    plan = SiteExisting3xUiCertificateReuseEligibilityBoundary.prepare(access.endpoint.host),
                    freshResolutionProof = certCredential.proof,
                    freshCredentialLease = certCredential.lease,
                    serverAccess = access,
                    executionAttemptId = canonicalId("phase11_100_cert_exec"),
                    executedAtEpochMillis = nowEpochMillis(),
                )
            } finally {
                certCredential.lease.close()
            }
            val report = certProof.eligibilityReport
            require(report.status == SiteExisting3xUiCertificateReuseEligibilityStatus.ELIGIBLE_FOR_EXACT_DOMAIN_BINDING) {
                "Requested existing 3x-ui certificate reuse is not currently eligible on the exact selected server"
            }
            val ref = requireNotNull(report.certificateReference)
            require(request.domain.trim().lowercase() in ref.dnsNames) {
                "Eligible 3x-ui certificate does not contain the exact requested domain"
            }
            SiteRemoteCertificateObservation(
                serverKeySha256 = trustedKeySha256,
                dnsNames = ref.dnsNames,
                certificateSha256 = ref.certificateSha256,
                usableNow = ref.usableNow,
                privateKeyPresentOnServer = ref.privateKeyPresentOnServer,
            )
        } else null

        val observedAt = live.observedAtEpochMillis
        val remoteObservation = live.remoteObservation.copy(certificate = certificateObservation)
        if (!replacementKeepsServing) {
            require(!live.serviceBindingConfigured) {
                "Порт ${request.servicePort} уже занят на сервере — выберите другой порт"
            }
        }
        val remoteRequest = SiteRemoteDeployRequest(
            remoteHostIdentity = access.endpoint.host,
            targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
            owner = PRODUCTION_OWNER,
            group = PRODUCTION_GROUP,
            existingTargetPolicy = existingTargetPolicy,
            certificateReuse = if (request.reuseExisting3xUiCertificate) {
                SiteCertificateReuseRequest(
                    mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                    requestedDomain = preparation.serviceBinding.domain,
                )
            } else {
                SiteCertificateReuseRequest()
            },
        )
        val readinessEvaluatedAt = maxOf(nowEpochMillis(), observedAt)
        val readinessRequest = SiteProductionDeploymentReadinessRequest(
            exportPlan = preparation.previewExport.export,
            localReceipt = preparation.localExportReceipt,
            remoteRequest = remoteRequest,
            trust = SiteRemotePreflightTrust(trustedKeySha256),
            remoteObservation = remoteObservation,
            remoteObservationObservedAtEpochMillis = observedAt,
            serviceBindingIntent = SiteProductionServiceBindingIntent(
                domain = preparation.serviceBinding.domain,
                port = preparation.serviceBinding.port,
            ),
            serviceBindingObservation = SiteProductionServiceBindingObservation(
                remoteHostIdentity = access.endpoint.host,
                serverKeySha256 = trustedKeySha256,
                domain = preparation.serviceBinding.domain,
                port = preparation.serviceBinding.port,
                configured = live.serviceBindingConfigured,
                observedAtEpochMillis = observedAt,
            ),
            freshnessPolicy = SiteProductionObservationFreshnessPolicy(
                evaluatedAtEpochMillis = readinessEvaluatedAt,
                maxAgeMillis = READINESS_EVIDENCE_MAX_AGE_MILLIS,
            ),
            serviceBindingReadinessMode = if (replacementKeepsServing) {
                SiteProductionServiceBindingReadinessMode.REQUIRE_ALREADY_CONFIGURED
            } else {
                SiteProductionServiceBindingReadinessMode.REQUIRE_POST_COORDINATOR_ACTIVATION
            },
        )
        val readinessDraft = SiteProductionDeploymentReadinessBoundary.prepare(readinessRequest)
        check(readinessDraft.status != SiteProductionDeploymentReadinessStatus.BLOCKED) {
            readinessDraft.blockers.joinToString("\n") { blocker ->
                when (blocker.code) {
                    "TARGET_STATE" ->
                        "Путь ${remoteRequest.targetRoot} уже занят. Для первой публикации укажите новую папку."
                    "STAGING_STATE" ->
                        "Занята временная папка ${preparation.remoteDeployPlan.publish.stagingRoot}. Укажите другую целевую папку."
                    "AVAILABLE_CAPACITY" -> "На VPS недостаточно свободного места для публикации."
                    "OWNER_ACCOUNT", "GROUP_ACCOUNT" -> "На VPS отсутствует учётная запись или группа владельца сайта."
                    "OWNERSHIP_APPLICABLE", "MODE_APPLICABLE" ->
                        "SSH-профилю не хватает прав для настройки владельца и доступа к файлам сайта."
                    "REMOTE_OBSERVATION_STALE", "SERVICE_BINDING_OBSERVATION_STALE" ->
                        "Результат проверки устарел. Подготовьте контекст заново."
                    else -> "${blocker.code} — ${blocker.detail}"
                }
            }.ifBlank { "Проверка перед публикацией не пройдена." }
        }
        val readyRecord = SiteProductionDeploymentReadinessBoundary.approve(
            readinessDraft,
            SiteProductionOperatorApproval(
                operatorApprovalChallengeSha256 = readinessDraft.operatorApprovalChallengeSha256,
                confirmed = true,
            ),
        )

        val executionAt = nowEpochMillis()
        val executionRequest = SiteProductionDeploymentExecutionRequest(
            readyRecord = readyRecord,
            readinessRequest = readinessRequest,
            coordinatorRequest = SiteDeploymentCoordinatorRequest(
                exportPlan = preparation.previewExport.export,
                localOutputRoot = coordinatorRoot.toPath(),
                remoteRequest = remoteRequest,
                trust = readinessRequest.trust,
            ),
            transportCapabilities = SiteRemoteSftpPrimitiveFactory.CAPABILITIES,
            executionAttemptId = canonicalId("phase11_100_execution"),
            evaluatedAtEpochMillis = executionAt,
        )
        val executionDraft = SiteProductionDeploymentExecutionBoundary.prepare(executionRequest)
        val executionAuthorization = SiteProductionDeploymentExecutionBoundary.authorize(
            executionDraft,
            SiteProductionDeploymentExecutionApproval(
                executionApprovalChallengeSha256 = executionDraft.executionApprovalChallengeSha256,
                confirmed = true,
            ),
        )

        val runtimeAt = nowEpochMillis()
        val runtimeRequest = SiteProductionDeploymentRuntimeMutationRequest(
            executionAuthorization = executionAuthorization,
            executionRequest = executionRequest,
            runtimeIdentity = SiteProductionDeploymentRuntimeIdentity(
                runtimeSessionId = canonicalId("phase11_100_runtime"),
                remoteHostIdentity = access.endpoint.host,
                transportImplementationId = SiteRemoteSftpPrimitiveFactory.CAPABILITIES.implementationId,
                capabilityProfileSha256 = SiteRemoteTransportPolicy.capabilityProfileSha256(
                    SiteRemoteSftpPrimitiveFactory.CAPABILITIES,
                ),
            ),
            coordinatorInvocationId = canonicalId("phase11_100_invoke"),
            evaluatedAtEpochMillis = runtimeAt,
            requestedPermitLifetimeMillis = RUNTIME_PERMIT_LIFETIME_MILLIS,
        )
        val runtimeDraft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(runtimeRequest)
        val runtimePermit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
            runtimeDraft,
            SiteProductionDeploymentRuntimeMutationApproval(
                runtimeMutationApprovalChallengeSha256 = runtimeDraft.runtimeMutationApprovalChallengeSha256,
                confirmed = true,
            ),
        )
        val invocationAuthorization = SiteProductionDeploymentRuntimeMutationBoundary
            .consumeForSingleCoordinatorInvocation(
                permit = runtimePermit,
                request = runtimeRequest,
                consumedAtEpochMillis = nowEpochMillis(),
                consumptionPort = application.siteProductionDeploymentReplayFence.runtimeMutationConsumptionPort(),
            )
        val coordinatorAdmission =
            SiteProductionDeploymentAndroidPolicyBoundCoordinatorInvocationExecutionBoundary.admit(
                invocationAuthorization = invocationAuthorization,
                runtimeMutationRequest = runtimeRequest,
                preparation = preparation,
                serverAccess = access,
                evaluatedAtEpochMillis = nowEpochMillis(),
            )

        val staticCredentialProvider = object : SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider {
            override suspend fun acquire(
                step: SiteProductionDeploymentRealVpsStaticFileTransactionStep,
            ): SiteProductionDeploymentRealVpsExecutionCredential =
                freshExecutionCredential(access, preparation, "static_${step.name.lowercase()}")
        }
        val servingCredentialProvider = SiteProductionDeploymentPostCoordinatorFreshExecutionCredentialProvider { purpose ->
            freshExecutionCredential(access, preparation, "serve_${purpose.name.lowercase()}")
        }
        val replacementUrl = if (replacementKeepsServing) {
            SiteProductionDeploymentAndroidProductionExecutionPort.plannedNginxUrl(preparation, request.existingSiteServedOverHttps)
        } else {
            null
        }
        val caddyPlan: SiteCaddyServingPlan? = if (live.backend == SiteServingBackend.CADDY && !replacementKeepsServing) {
            SiteCaddyServingPlanner.prepare(
                remoteHostIdentity = access.endpoint.host,
                domain = preparation.serviceBinding.domain,
                port = preparation.serviceBinding.port,
                targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
                tlsMode = SiteCaddyServingPlanner.tlsModeFor(
                    live.inventory,
                    SiteCaddyServingPlanner.canonicalDomain(preparation.serviceBinding.domain),
                    request.reuseExisting3xUiCertificate,
                ),
                caddy = live.inventory.caddy,
                indexSha256 = preparation.bundle.documents.single { it.path == "index.html" }.sha256,
                preservedListeningPorts = live.inventory.listeningPorts,
                // The 3x-ui reference only proves a certificate exists for the domain; Caddy itself
                // references the pair it already loads (readable by its service user).
                certificate = live.caddyCertificate?.let { SiteCaddyCertificatePolicy.reference(access.endpoint.host, it) },
            )
        } else {
            null
        }
        val context = SiteProductionDeploymentAndroidProductionExecutionContext(
            preparation = preparation,
            coordinatorAdmission = coordinatorAdmission,
            invocationAuthorization = invocationAuthorization,
            runtimeMutationRequest = runtimeRequest,
            serverAccess = access,
            credentialProvider = staticCredentialProvider,
            postCoordinatorCredentialProvider = if (replacementKeepsServing) null else servingCredentialProvider,
            previousTargetTree = live.previousTargetTree,
            uiPreparedAtEpochMillis = nowEpochMillis(),
            caddyServingPlan = caddyPlan,
            replacementVerificationUrl = replacementUrl,
        )
        val releaseAdmission = if (replacementKeepsServing) {
            application.publishReviewedReplacementSiteDeployerExecutionContext(context)
        } else {
            application.publishReviewedFirstPublicationSiteDeployerExecutionContext(context)
        }

        SiteDeployerReleaseBootstrapResult(
            serverId = server.id.value,
            serverAccessId = access.id.value,
            remoteObservation = remoteObservation,
            serviceBindingConfigured = live.serviceBindingConfigured,
            releaseBootstrapAdmissionSha256 = releaseAdmission.bootstrapAdmissionSha256,
            coordinatorPermitExpiresAtEpochMillis = coordinatorAdmission.permitExpiresAtEpochMillis,
            replacesExistingSite = replaceRequested,
            servingBackend = if (replacementKeepsServing) null else live.backend,
            plannedUrl = caddyPlan?.plannedUrl ?: replacementUrl
                ?: SiteProductionDeploymentAndroidProductionExecutionPort.plannedNginxUrl(preparation),
        )
    }

    override fun clearPendingContext() {
        application.clearSiteDeployerProductionExecutionContext()
    }

    private suspend fun observeReadOnlyBootstrap(
        access: ServerAccess,
        preparation: SiteDeployerLocalPreparationResult,
        resolved: SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved,
        existingSiteMode: SiteExistingSiteMode,
        certificateReuseRequested: Boolean,
    ): LiveBootstrapObservation {
        val expectedSecretId = access.auth.secretId
        val leaseStore = OneShotLeaseSecretStore(expectedSecretId, resolved.lease)
        val sessionId = SessionId(canonicalId("phase11_100_probe_session"))
        val owner = SessionOwner.Operation(OperationId(canonicalId("phase11_100_probe_owner")))
        val factory = JschSshConnectionFactory(secretStore = leaseStore, sessionIdFactory = { sessionId })
        val registry = ExactSessionRegistry()
        var connectedHandle: VerifiedHostKeySshSessionHandle? = null
        try {
            val connectResult = factory.connect(
                access = access,
                owner = owner,
                config = SshTransportConfig(
                    // Keep the release-bootstrap transport budget aligned with the already accepted
                    // real-VPS read-only boundary. This is still one attempt: no retry/fallback is
                    // introduced, but a transient TCP/auth handshake must not be cut off earlier
                    // than the production boundary it is proving compatible with.
                    tcpConnectTimeout = Duration.ofSeconds(8),
                    handshakeAndAuthTimeout = Duration.ofSeconds(12),
                    channelOpenTimeout = Duration.ofSeconds(5),
                    commandExecutionTimeout = Duration.ofSeconds(5),
                    stdoutCaptureLimitBytes = 32 * 1024,
                    stderrCaptureLimitBytes = 16 * 1024,
                ),
            )
            val connected = connectResult as? SshConnectResult.Connected
                ?: error(
                    "Phase 11.100 read-only SSH acquisition failed closed: " +
                        ((connectResult as SshConnectResult.Failed).failure::class.java.simpleName),
                )
            val verified = connected.handle as? VerifiedHostKeySshSessionHandle ?: run {
                connected.handle.close()
                error("Phase 11.100 read-only probe lacks verified host-key evidence")
            }
            connectedHandle = verified
            require(registry.install(verified) == SessionInstallResult.Installed)
            require(registry.find(owner, access.id) === verified)

            // Existing-site detection (read-only): exact VELUM nginx config, listening ports and
            // the requested folder. A conflict is returned to the operator instead of failing
            // with a low-level error, so they can choose another port or an explicit replacement.
            val serviceAdapter = SiteFirstPublicationReadOnlyObservationSshAdapter()
            val targetRoot = preparation.remoteDeployPlan.publish.targetRoot
            val configPath = serviceAdapter.exactFutureConfigPath(
                remoteHostIdentity = access.endpoint.host,
                targetRoot = targetRoot,
                domain = preparation.serviceBinding.domain,
                port = preparation.serviceBinding.port,
            )
            val nginxEndpoint = serviceAdapter.observeEndpoint(
                configPath = configPath,
                port = preparation.serviceBinding.port,
                session = verified,
            )
            val servingProbe = SiteCaddyServingSshAdapter().probe(
                domain = preparation.serviceBinding.domain,
                port = preparation.serviceBinding.port,
                session = verified,
            )
            val inventory = servingProbe.inventory
            val decision = SiteServingBackendPolicy.select(inventory)
            val backend = decision.backend ?: throw SiteDeployerServingBlockedException(
                decision.blockedCategory ?: SiteServingFailureCategory.BACKEND_INCOMPATIBLE,
                decision.blockedReason ?: "Веб-сервер на сервере не поддерживается",
            )
            val endpoint = when (backend) {
                SiteServingBackend.NGINX -> nginxEndpoint
                SiteServingBackend.CADDY -> SiteServingBackendPolicy.caddyEndpoint(
                    inventory = inventory,
                    domain = SiteCaddyServingPlanner.canonicalDomain(preparation.serviceBinding.domain),
                    port = preparation.serviceBinding.port,
                    managedSitePresent = SiteCaddyServingPlanner.siteFilePath(
                        caddyfilePath = inventory.caddy.caddyfilePath,
                        remoteHostIdentity = access.endpoint.host,
                        targetRoot = targetRoot,
                        domain = SiteCaddyServingPlanner.canonicalDomain(preparation.serviceBinding.domain),
                        port = preparation.serviceBinding.port,
                    ).substringAfterLast('/') in servingProbe.managedSiteFileNames,
                )
            }
            // Fail closed before any upload: a closed port or an unreadable UFW state stops here.
            // The app never opens the firewall itself.
            SiteFirewallPolicy.publicationBlock(inventory.firewall, preparation.serviceBinding.port)?.let { message ->
                throw SiteDeployerServingBlockedException(SiteServingFailureCategory.FIREWALL, message)
            }

            // Certificate reuse with Caddy: only files Caddy already loads and its service user can
            // read are eligible (never the 3x-ui copy under /root). Checked read-only, before upload.
            val caddyCertificate: SiteCaddyCertificateCandidate? =
                if (backend == SiteServingBackend.CADDY && certificateReuseRequested) {
                    val serviceUser = inventory.caddy.serviceUser ?: throw SiteDeployerServingBlockedException(
                        SiteServingFailureCategory.CERTIFICATE,
                        "Не удалось определить, от какого пользователя работает Caddy (systemctl show caddy -p User). " +
                            "Без этого нельзя доказать, что Caddy прочитает сертификат. Файлы не загружены",
                    )
                    val candidates = SiteCaddyServingSshAdapter().probeCertificates(
                        pairs = inventory.caddy.tlsFilePairs,
                        serviceUser = serviceUser,
                        session = verified,
                    )
                    when (val selection = SiteCaddyCertificatePolicy.select(preparation.serviceBinding.domain, candidates)) {
                        is SiteCaddyCertificateSelection.Selected -> selection.candidate
                        is SiteCaddyCertificateSelection.Blocked -> throw SiteDeployerServingBlockedException(
                            SiteServingFailureCategory.CERTIFICATE,
                            selection.message,
                        )
                    }
                } else {
                    null
                }

            val existingTarget = serviceAdapter.observeExistingTarget(targetRoot, verified)
            val report = SiteExistingSitePolicy.report(
                targetRoot = targetRoot,
                port = preparation.serviceBinding.port,
                target = existingTarget,
                endpoint = endpoint,
            )
            val previousTargetTree: SiteDeployerRemoteTreeExpectation? = when (existingSiteMode) {
                SiteExistingSiteMode.DETECT_ONLY -> {
                    if (report.conflict) {
                        throw SiteDeployerExistingSiteConflictException(
                            report,
                            "На сервере уже есть сайт в этой папке или занят порт ${report.port}",
                        )
                    }
                    null
                }
                SiteExistingSiteMode.REPLACE_EXISTING -> {
                    if (!report.replaceAvailable) {
                        throw SiteDeployerExistingSiteConflictException(
                            report,
                            "Существующий сайт нельзя заменить автоматически",
                        )
                    }
                    val observedTree = SiteRemoteReadOnlyObservationSshAdapter().observeTree(
                        rootPath = targetRoot,
                        entries = SiteExistingSitePolicy.treeEntries(existingTarget),
                        session = verified,
                    )
                    SiteExistingSitePolicy.previousTreeExpectation(existingTarget, observedTree.treeSha256)
                        ?: throw SiteDeployerExistingSiteConflictException(
                            report.copy(replaceBlocker = com.velumtegra.xuimobile.core.site.SiteReplaceBlocker.UNSUPPORTED_FILE),
                            "Существующий сайт нельзя заменить автоматически",
                        )
                }
            }

            // Phase 11.10 path/capacity/ownership observation intentionally carries no
            // certificate evidence. For HTTPS reuse we therefore derive an observation-only plan
            // with the same host/root/tree/ownership and certificate mode NONE, then attach the
            // separately reviewed Phase 11.65 certificate observation above.
            val observationPlan = SiteRemoteDeployBoundary.prepare(
                exportPlan = preparation.previewExport.export,
                localReceipt = preparation.localExportReceipt,
                request = SiteRemoteDeployRequest(
                    remoteHostIdentity = access.endpoint.host,
                    targetRoot = preparation.remoteDeployPlan.publish.targetRoot,
                    owner = preparation.remoteDeployPlan.publish.owner,
                    group = preparation.remoteDeployPlan.publish.group,
                    existingTargetPolicy = preparation.remoteDeployPlan.publish.existingTargetPolicy,
                    certificateReuse = SiteCertificateReuseRequest(),
                ),
            )
            require(observationPlan.publish == preparation.remoteDeployPlan.publish) {
                "Observation-only plan changed exact publish paths or ownership"
            }
            val remoteObservation = SiteRemoteReadOnlyObservationSshAdapter().collectPreflight(
                observationPlan,
                access,
                verified,
            )
            val configured = endpoint.configPresent || endpoint.portInUse
            val observedAt = nowEpochMillis()
            require(registry.remove(owner, access.id, verified.binding.sessionId, close = true))
            require(registry.size() == 0 && !verified.isOpen)
            connectedHandle = null
            return LiveBootstrapObservation(
                remoteObservation,
                configured,
                observedAt,
                endpoint,
                previousTargetTree,
                backend,
                inventory,
                caddyCertificate,
            )
        } finally {
            runCatching { connectedHandle?.close() }
            registry.close()
        }
    }

    private suspend fun freshExecutionCredential(
        access: ServerAccess,
        preparation: SiteDeployerLocalPreparationResult,
        purpose: String,
    ): SiteProductionDeploymentRealVpsExecutionCredential {
        val resolved = resolveFreshCredential(access, preparation, purpose)
        return SiteProductionDeploymentRealVpsExecutionCredential(
            proof = resolved.proof,
            lease = resolved.lease,
            executionAttemptId = canonicalId("phase11_100_${safePurpose(purpose)}_exec"),
            executedAtEpochMillis = nowEpochMillis(),
        )
    }

    private suspend fun resolveFreshCredential(
        access: ServerAccess,
        preparation: SiteDeployerLocalPreparationResult,
        purpose: String,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved {
        val plan = preparation.remoteDeployPlan
        val backupRoot = plan.publish.backupRoot ?: "${plan.publish.targetRoot}.velum-bootstrap-backup"
        val expectedEntries = plan.entries.map { it.path.substringBefore('/') }.distinct().sorted()
        require(expectedEntries.isNotEmpty())
        val sequence = credentialSequence.incrementAndGet()
        val safe = safePurpose(purpose)
        val base = nowEpochMillis()
        val admission = application.siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            serverAccess = access,
            targetRoot = plan.publish.targetRoot,
            stagingRoot = plan.publish.stagingRoot,
            backupRoot = backupRoot,
            expectedTargetEntryNames = expectedEntries,
            admissionAttemptId = canonicalId("phase11_100_${safe}_admission_$sequence"),
            evaluatedAtEpochMillis = base,
        )
        val preflightDraft = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
            admission = admission,
            authorizationAttemptId = canonicalId("phase11_100_${safe}_preflight_$sequence"),
            evaluatedAtEpochMillis = base + 1L,
            requestedAuthorizationLifetimeMillis = CREDENTIAL_AUTHORIZATION_LIFETIME_MILLIS,
        )
        val preflightAuthorization = application.siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
            preflightDraft,
            SiteProductionDeploymentRealVpsReadOnlyPreflightApproval(
                preflightDraft.approvalChallengeSha256,
                true,
            ),
        )
        val preflightReceipt = application.siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
            preflightAuthorization,
            base + 2L,
        )
        val credentialDraft = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
            receipt = preflightReceipt,
            serverAccess = access,
            authorizationAttemptId = canonicalId("phase11_100_${safe}_credential_$sequence"),
            evaluatedAtEpochMillis = base + 3L,
            requestedAuthorizationLifetimeMillis = CREDENTIAL_AUTHORIZATION_LIFETIME_MILLIS,
        )
        val credentialAuthorization = application.siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
            credentialDraft,
            SiteProductionDeploymentRealVpsCredentialResolutionApproval(
                credentialDraft.approvalChallengeSha256,
                true,
            ),
        )
        val credentialHandoff = application.siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
            credentialAuthorization,
            base + 4L,
        )
        val result = application.siteProductionDeploymentResolveRealVpsCredentialOnce(
            credentialHandoff,
            access,
            nowEpochMillis(),
        )
        return result as? SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult.Resolved
            ?: error("Selected ServerAccess credential is unavailable for reviewed production bootstrap")
    }

    private fun canonicalPinnedKey(access: ServerAccess): String = when (
        val parsed = CanonicalHostKeyFingerprint.parse(access.pinnedHostKey)
    ) {
        is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
        is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
    }

    private fun validateRequest(request: SiteDeployerReleaseBootstrapRequest) {
        require(request.serverId.isNotBlank() && request.serverAccessId.isNotBlank()) {
            "An exact stored ServerId and ServerAccessId must be explicitly selected"
        }
        require(request.domain.isNotBlank()) { "Production domain must not be blank" }
        require(request.servicePort in 1..65535) { "Production service port must be inside 1..65535" }
        require(request.targetRoot.isNotBlank()) { "Production target root must not be blank" }
    }

    private fun canonicalId(prefix: String): String {
        val normalized = prefix.lowercase().replace(Regex("[^a-z0-9._-]+"), "_").trim('_')
        val nonce = UUID.randomUUID().toString().replace("-", "")
        return "${normalized.take(80)}_${nonce.take(24)}"
    }

    private fun safePurpose(value: String): String = value.lowercase()
        .replace(Regex("[^a-z0-9_-]+"), "_")
        .trim('_')
        .take(40)
        .ifEmpty { "purpose" }

    private fun <T> RepositoryResult<T>.successValue(message: String): T = when (this) {
        is RepositoryResult.Success -> value
        RepositoryResult.NotFound -> error(message)
        is RepositoryResult.ConstraintConflict -> error("$message: $reason")
        is RepositoryResult.StaleRevision -> error("$message: stale repository revision")
        is RepositoryResult.Corruption -> error("$message: $reason")
        is RepositoryResult.StorageFailure -> error("$message: $reason")
    }

    private data class LiveBootstrapObservation(
        val remoteObservation: SiteRemotePreflightObservation,
        val serviceBindingConfigured: Boolean,
        val observedAtEpochMillis: Long,
        val endpoint: SiteEndpointObservation,
        val previousTargetTree: SiteDeployerRemoteTreeExpectation?,
        val backend: SiteServingBackend,
        val inventory: SiteWebServerInventory,
        /** Caddy-loaded certificate pair proven readable by the caddy service user (reuse only). */
        val caddyCertificate: SiteCaddyCertificateCandidate?,
    )

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
            val copy = credentialLease.useMaterialOnce { material ->
                material.useBytes { SecretMaterial.fromBytes(it) }
            }
            return SecretReadResult.Found(copy)
        }

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            SecretCreateResult.StorageFailure("Phase 11.100 bootstrap lease adapter is read-only")

        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Phase 11.100 bootstrap lease adapter is read-only")

        override suspend fun listIds(): SecretListResult =
            SecretListResult.StorageFailure("Phase 11.100 bootstrap lease adapter does not enumerate secrets")
    }

    companion object {
        private const val PRODUCTION_OWNER = "root"
        private const val PRODUCTION_GROUP = "root"
        private const val READINESS_EVIDENCE_MAX_AGE_MILLIS = 300_000L
        private const val CREDENTIAL_AUTHORIZATION_LIFETIME_MILLIS = 15_000L
        private const val RUNTIME_PERMIT_LIFETIME_MILLIS = 60_000L
    }
}
