package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.domain.DiscoveryClassifier
import com.velumtegra.xuimobile.core.domain.DiscoveryProofAttempt
import com.velumtegra.xuimobile.core.domain.DiscoveryProver
import com.velumtegra.xuimobile.core.model.ManagementBaselineReadbackResult
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublicationResult
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentPublisher
import com.velumtegra.xuimobile.core.domain.ManagementEnrollmentRequest
import com.velumtegra.xuimobile.core.domain.ManagementReadbackPolicy
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.model.DiscoveryProof
import com.velumtegra.xuimobile.core.model.DiscoveryProofId
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ManagementScope
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.DiscoverySshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.DiscoverySshProbeRunResult
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.ManagementSshProbeRunResult
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import com.velumtegra.xuimobile.management.isSafeLocalPanelPath
import com.velumtegra.xuimobile.readiness.LiveSshConnectionPolicy
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessPolicy
import java.time.Duration
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Review is one explicit read-only pinned SSH session. Confirm is a separate LOCAL Room transaction. */
interface XuiVerifiedEnrollmentPort {
    suspend fun reviewExact(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean, candidate: XuiCandidateIdentityEvidence,
    ): XuiEnrollmentReview
    suspend fun saveReviewed(reviewToken: String, serverId: String, accessId: String): XuiEnrollmentSave
    fun discard(reviewToken: String)
}

sealed interface XuiEnrollmentReview {
    data class Ready(
        val reviewToken: String,
        val exactTarget: String,
        val serviceUnit: String,
        val binaryPath: String,
        val databasePath: String,
        val panelPort: Int,
        val webBasePath: String,
        val expiresAt: Instant,
    ) : XuiEnrollmentReview
    data class Blocked(val message: String) : XuiEnrollmentReview
}

sealed interface XuiEnrollmentSave {
    data class Saved(val installationId: String, val alreadyKnown: Boolean) : XuiEnrollmentSave
    data class Blocked(val message: String) : XuiEnrollmentSave
}

/** Pure fail-closed policy: no inferred panel settings and no mixing discovery identities. */
object XuiEnrollmentReviewPolicy {
    fun matches(candidate: XuiCandidateIdentityEvidence, proof: DiscoveryProof, baseline: InstallationBaseline): Boolean =
        XuiServiceVerificationPolicy.approvedCandidate(candidate) &&
            proof.observedIdentity.serviceUnit == candidate.serviceUnit &&
            proof.observedIdentity.binaryPath == candidate.binaryPath &&
            proof.observedIdentity.rootPath == candidate.rootPath &&
            proof.observedIdentity.databasePath == candidate.databasePath &&
            baseline.serviceUnit == candidate.serviceUnit &&
            baseline.binaryPath == candidate.binaryPath &&
            baseline.rootPath == candidate.rootPath &&
            baseline.databasePath == candidate.databasePath &&
            isSafeLocalPanelPath(baseline.webBasePath)
}

class RepositoryXuiVerifiedEnrollmentPort(
    private val servers: ServerRepository,
    private val accesses: ServerAccessRepository,
    private val connections: SshConnectionFactory,
    private val publisher: ManagementEnrollmentPublisher,
    private val discovery: DiscoverySshProbeExecutor = DiscoverySshProbeExecutor(),
    private val management: ManagementSshProbeExecutor = ManagementSshProbeExecutor(),
    private val now: () -> Instant = Instant::now,
) : XuiVerifiedEnrollmentPort {
    private data class Pending(
        val token: String, val serverId: String, val accessId: String,
        val access: ServerAccess, val request: ManagementEnrollmentRequest,
        val expiresAt: Instant,
    )
    private var pending: Pending? = null

    override fun discard(reviewToken: String) {
        synchronized(this) { if (pending?.token == reviewToken) pending = null }
    }

    override suspend fun reviewExact(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean, candidate: XuiCandidateIdentityEvidence,
    ): XuiEnrollmentReview = withContext(Dispatchers.IO) {
        fun block(reason: String) = XuiEnrollmentReview.Blocked(reason)
        synchronized(this@RepositoryXuiVerifiedEnrollmentPort) { pending = null }
        try {
            if (!consent || serverId.isBlank() || accessId.isBlank() || reviewed.accessId != accessId ||
                repeatedTarget != LiveSshConnectionPolicy.exactTarget(reviewed) ||
                !XuiServiceVerificationPolicy.approvedCandidate(candidate)) {
                return@withContext block("Подтвердите точную SSH-цель и ранее обнаруженную 3x-ui.")
            }
            val server = (servers.get(ServerId(serverId)) as? RepositoryResult.Success)?.value?.value
                ?: return@withContext block("Сервер больше не найден.")
            if (server.id.value != serverId) return@withContext block("Неверная запись сервера.")
            val access = (accesses.get(ServerAccessId(accessId)) as? RepositoryResult.Success)?.value
                ?: return@withContext block("SSH-доступ больше не найден.")
            if (access.id.value != accessId || access.serverId.value != serverId) return@withContext block("SSH-доступ принадлежит другому серверу.")
            val fresh = LocalSshReadinessPolicy.inspect(serverId, accessId, access)
            XuiDiscoveryConsentPolicy.reject(serverId, accessId, reviewed, fresh, repeatedTarget, consent)
                ?.let { return@withContext block(it) }
            val fingerprint = (CanonicalHostKeyFingerprint.parse(access.pinnedHostKey)
                as? HostKeyFingerprintParseResult.Valid)?.fingerprint
                ?: return@withContext block("SSH-отпечаток не подтверждён.")
            val op = OperationId(UUID.randomUUID().toString())
            val owner = SessionOwner.Operation(op)
            when (val connection = connections.connect(access, owner)) {
                is SshConnectResult.Failed -> block("SSH-подключение или проверка ключа отклонены. VPS не изменён.")
                is SshConnectResult.Connected -> {
                    val handle = connection.handle
                    try {
                        val pinned = handle as? VerifiedHostKeySshSessionHandle
                        if (!handle.isOpen || handle.binding.serverAccessId != access.id || handle.binding.owner != owner ||
                            pinned?.verifiedHostKeySha256 != fingerprint.asHexSha256()) {
                            block("Точная SSH-сессия или отпечаток сервера не подтверждены.")
                        } else {
                            val discoveryScope = DiscoveryScope(op, server.id, access.id)
                            val discoveryRun = discovery.executeInitialPlan(discoveryScope, handle)
                            if (discoveryRun !is DiscoverySshProbeRunResult.Completed) {
                                block("Не удалось повторно подтвердить установленную 3x-ui.")
                            } else {
                                val evidence = discoveryRun.evidence
                                val attempt = DiscoveryProver.prove(
                                    evidence, DiscoveryClassifier.classify(evidence),
                                    DiscoveryProofId(UUID.randomUUID().toString()),
                                )
                                if (attempt !is DiscoveryProofAttempt.Proven ||
                                    attempt.proof.scope != discoveryScope ||
                                    attempt.proof.observedIdentity.serviceUnit != candidate.serviceUnit ||
                                    attempt.proof.observedIdentity.binaryPath != candidate.binaryPath ||
                                    attempt.proof.observedIdentity.rootPath != candidate.rootPath ||
                                    attempt.proof.observedIdentity.databasePath != candidate.databasePath) {
                                    block("Идентичность 3x-ui изменилась или недостаточно доказательств.")
                                } else {
                                    val proof = attempt.proof
                                    val proposedId = XuiInstallationId(UUID.randomUUID().toString())
                                    val scope = ManagementScope(op, server.id, access.id, proposedId)
                                    when (val observed = management.executeEnrollmentBaseline(scope, proof.observedIdentity, handle)) {
                                        is ManagementSshProbeRunResult.Failed ->
                                            block(XuiEnrollmentReadFailurePolicy.message(observed))
                                        is ManagementSshProbeRunResult.Completed -> {
                                            when (val baseline = ManagementReadbackPolicy.buildEnrollmentBaseline(proof.observedIdentity, observed.evidence)) {
                                                is ManagementBaselineReadbackResult.Complete -> {
                                                    if (!XuiEnrollmentReviewPolicy.matches(candidate, proof, baseline.baseline)) {
                                                        block("Параметры панели не соответствуют установленной 3x-ui.")
                                                    } else {
                                                        val token = UUID.randomUUID().toString()
                                                        val expires = now().plus(Duration.ofSeconds(90))
                                                        val request = ManagementEnrollmentRequest(proof, baseline.baseline, proposedId)
                                                        synchronized(this@RepositoryXuiVerifiedEnrollmentPort) {
                                                            pending = Pending(token, serverId, accessId, access, request, expires)
                                                        }
                                                        XuiEnrollmentReview.Ready(
                                                            token, repeatedTarget, proof.observedIdentity.serviceUnit,
                                                            proof.observedIdentity.binaryPath, proof.observedIdentity.databasePath,
                                                            baseline.baseline.panelPort, baseline.baseline.webBasePath, expires,
                                                        )
                                                    }
                                                }
                                                else -> block("Порт и веб-путь не подтверждены. Ничего не сохраняем.")
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } finally { handle.close() }
                }
            }
        } catch (cancel: CancellationException) { throw cancel }
          catch (_: Exception) { block("Проверка прервана или данные несовместимы. Нет новых записей.") }
    }

    override suspend fun saveReviewed(reviewToken: String, serverId: String, accessId: String): XuiEnrollmentSave =
        withContext(Dispatchers.IO) {
            // Consume first, before any repository call: no duplicate publication on retries.
            val snapshot = synchronized(this@RepositoryXuiVerifiedEnrollmentPort) {
                val value = pending
                pending = null
                value
            } ?: return@withContext XuiEnrollmentSave.Blocked("Согласование устарело. Повторите проверку.")
            if (reviewToken != snapshot.token || serverId != snapshot.serverId || accessId != snapshot.accessId ||
                now().isAfter(snapshot.expiresAt)) {
                return@withContext XuiEnrollmentSave.Blocked("Цель или срок согласования изменились. Повторите проверку.")
            }
            try {
                val currentServer = (servers.get(ServerId(serverId)) as? RepositoryResult.Success)?.value?.value
                val currentAccess = (accesses.get(ServerAccessId(accessId)) as? RepositoryResult.Success)?.value
                if (currentServer?.id?.value != serverId || currentAccess != snapshot.access) {
                    return@withContext XuiEnrollmentSave.Blocked("Сервер или SSH-доступ изменился. Сохранение отменено.")
                }
                when (val outcome = publisher.publish(snapshot.request)) {
                    is ManagementEnrollmentPublicationResult.Published -> XuiEnrollmentSave.Saved(
                        outcome.installation.value.id.value, !outcome.installationCreated,
                    )
                    is ManagementEnrollmentPublicationResult.Rejected -> XuiEnrollmentSave.Blocked(
                        "Запись не создана: ${outcome.reason}. Данные существующей установки сохранены.",
                    )
                    ManagementEnrollmentPublicationResult.Corruption -> XuiEnrollmentSave.Blocked("Локальная база неоднозначна. Запись не создана.")
                    ManagementEnrollmentPublicationResult.StorageFailure -> XuiEnrollmentSave.Blocked("Не удалось атомарно сохранить локальную привязку.")
                }
            } catch (cancel: CancellationException) { throw cancel }
              catch (_: Exception) { XuiEnrollmentSave.Blocked("Итог локальной записи не подтверждён. Обновите список X-UI.") }
        }
}
