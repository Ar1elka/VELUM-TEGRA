package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.runtime.*
import com.velumtegra.xuimobile.core.ssh.*
import com.velumtegra.xuimobile.core.webpanel.*
import com.velumtegra.xuimobile.inventory.panelCertificateTrustScope
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

/** Public UI projection: no passwords, cookie, raw API, private key or SSH command. */
data class RecoveryPanelChoice(val accessId: String, val username: String, val route: String)
data class RecoveryPanelReview(val token: String, val operationId: String, val accessId: String,
    val username: String, val route: String, val endpoint: String, val certificate: String?, val reviewedAt: Instant)
sealed interface RecoveryPanelCheckResult {
    data class Verified(val accessId: String, val observedAt: Instant) : RecoveryPanelCheckResult
    data class Unverified(val message: String) : RecoveryPanelCheckResult
}
interface RecoveryPanelCheckPort {
    suspend fun choices(server: String, installation: String, ssh: String, operation: String): List<RecoveryPanelChoice>
    suspend fun review(server: String, installation: String, ssh: String, operation: String, panel: String): RecoveryPanelReview?
    suspend fun check(review: RecoveryPanelReview): RecoveryPanelCheckResult
    fun discard(review: RecoveryPanelReview)
}

internal data class RecoveryPanelAuthority(val local: ManagementRestartReview,
    val source: VersionedOperationSnapshot, val panel: VersionedRecord<WebPanelAccess>,
    val target: ResolvedWebPanelTarget, val pinScope: String?, val pin: String?)
internal object RecoveryPanelCheckPolicy {
    fun recent(at: Instant, now: Instant, seconds: Long = 90): Boolean =
        !at.isAfter(now) && !now.isAfter(at.plusSeconds(seconds))
    fun permitted(r: ManagementRestartReview, c: VersionedOperationSnapshot, p: VersionedRecord<WebPanelAccess>,
        target: ResolvedWebPanelTarget): Boolean {
        val source = RestoredPanelStartBinding.parse(c.snapshot.checkpoint.phaseName)
        val compensated = CompensatedPanelStartBinding.parse(c.snapshot.checkpoint.phaseName)
        val acceptedSource = (source?.first == RestoredPanelStartPhase.VERIFIED && c.snapshot.type == OperationType.RESTORED_PANEL_START &&
            c.snapshot.status == OperationStatus.SUCCEEDED && c.snapshot.checkpoint.semantics == CheckpointSemantics.TERMINAL) ||
            (compensated?.first == CompensatedPanelStartPhase.ACTIVE_VERIFIED && c.snapshot.type == OperationType.WORKING_DATABASE_RESTORE &&
            c.snapshot.status == OperationStatus.RECONCILIATION_REQUIRED && c.snapshot.checkpoint.semantics == CheckpointSemantics.POST_VERIFY_REQUIRED)
        if (!acceptedSource) return false
        val linked = p.value.installationLink as? WebPanelInstallationLink.Linked ?: return false
        val installation = target.installation as? ResolvedWebPanelInstallation.Linked ?: return false
        val scope = c.snapshot.target as? OperationTarget.InstallationTarget ?: return false
        if (linked.installationId != r.installation.id || installation.installationId != r.installation.id ||
            installation.serverId != r.installation.serverId || scope.serverId != r.installation.serverId ||
            scope.installationId != r.installation.id || scope.serverAccessId != r.access.id ||
            target.webPanelAccessId != p.value.id || target.webPanelAccessRevision != p.revision) return false
        return when (val route = target.routeTarget) {
            is ResolvedWebPanelRouteTarget.Direct -> p.value.route is WebPanelRoute.Direct && route.origin.scheme == WebPanelScheme.HTTPS &&
                route.origin.port == r.installation.baseline.panelPort && route.origin.webBasePath.value == r.installation.baseline.webBasePath
            is ResolvedWebPanelRouteTarget.SshTunnel -> (p.value.route as? WebPanelRoute.SshTunnel)?.serverAccessId == r.access.id &&
                route.serverAccessId == r.access.id && route.serverId == r.installation.serverId && route.scheme == WebPanelScheme.HTTPS &&
                route.remoteEndpoint.port == r.installation.baseline.panelPort && route.webBasePath.value == r.installation.baseline.webBasePath
        }
    }
}

/** One process-wide instance in the existing app graph. Review tokens are consumed before any network.
 * Entries are bounded; exhausting them blocks new attempts until process exit. Never evict/replay tokens.
 */
internal class RepositoryRecoveryPanelCheckPort(
    private val local: ManagementRestartLocalPort, private val journal: OperationJournal,
    private val statuses: RestoredPanelStartStatusPort, private val panels: WebPanelAccessRepository,
    private val resolver: ExactWebPanelTargetResolver, private val authenticator: WebPanelAuthenticationClient,
    private val sshFactory: SshConnectionFactory, private val pinRead: (String) -> String?,
    private val lease: suspend (ServerId, OperationId, suspend () -> RecoveryPanelCheckResult) -> RecoveryPanelCheckResult?,
    private val now: () -> Instant = Instant::now,
    private val compensatedSource: suspend (String,String,String,String) -> VersionedOperationSnapshot? = { _,_,_,_ -> null },
) : RecoveryPanelCheckPort {
    private data class Entry(val review: RecoveryPanelReview, val authority: RecoveryPanelAuthority)
    private val pending = linkedMapOf<String, Entry>()
    private val attempts = mutableSetOf<Pair<String, String>>()
    private var active = false
    @Synchronized private fun remember(e: Entry): Boolean {
        pending.entries.removeAll { !RecoveryPanelCheckPolicy.recent(it.value.review.reviewedAt, now()) }
        if (pending.size >= 8 || attempts.size >= 32) return false
        pending[e.review.token] = e; return true
    }
    @Synchronized override fun discard(review: RecoveryPanelReview) { pending.remove(review.token) }
    @Synchronized private fun consume(review: RecoveryPanelReview): Entry? {
        if (active) return null
        val entry = pending.remove(review.token) ?: return null
        if (entry.review != review || !RecoveryPanelCheckPolicy.recent(review.reviewedAt, now()) || attempts.size >= 32 ||
            !attempts.add(review.operationId to review.accessId)) return null
        active = true; return entry
    }
    @Synchronized private fun finish() { active = false }
    override suspend fun choices(server: String, installation: String, ssh: String, operation: String): List<RecoveryPanelChoice> {
        val r = ready(server, installation, ssh) ?: return emptyList()
        if (source(r, operation) == null) return emptyList()
        val records = (panels.list() as? RepositoryResult.Success)?.value ?: return emptyList()
        val owned = records.filter { (it.value.installationLink as? WebPanelInstallationLink.Linked)?.installationId == r.installation.id }
        if (owned.size > 20) return emptyList()
        return owned.sortedBy { it.value.id.value }.map {
            RecoveryPanelChoice(it.value.id.value, it.value.username, if (it.value.route is WebPanelRoute.Direct) "Прямой HTTPS" else "Приватный HTTPS через SSH")
        }
    }
    override suspend fun review(server: String, installation: String, ssh: String, operation: String, panel: String): RecoveryPanelReview? {
        val a = authority(server, installation, ssh, operation, panel) ?: return null
        val route = a.target.routeTarget
        val endpoint = when (route) {
            is ResolvedWebPanelRouteTarget.Direct -> "https://" + route.origin.host.value + ":" + route.origin.port + route.origin.webBasePath.value
            is ResolvedWebPanelRouteTarget.SshTunnel -> "HTTPS через " + a.local.sshLabel + " → порт " + route.remoteEndpoint.port
        }
        val review = RecoveryPanelReview(UUID.randomUUID().toString(), operation, panel, a.panel.value.username,
            if (route is ResolvedWebPanelRouteTarget.Direct) "Прямой HTTPS" else "Приватный HTTPS через SSH", endpoint, a.pin, now())
        return review.takeIf { remember(Entry(it, a)) }
    }
    override suspend fun check(review: RecoveryPanelReview): RecoveryPanelCheckResult {
        val entry = consume(review) ?: return deny("Разрешение истекло или уже использовано. Пароль повторно не отправлен.")
        try {
            return withContext(Dispatchers.IO) { withTimeout(95_000) {
                lease(entry.authority.local.installation.serverId, entry.authority.source.snapshot.operationId) {
                    val a = entry.authority
                    if (!same(a) || !RecoveryPanelCheckPolicy.recent(review.reviewedAt, now()))
                        return@lease deny("Цель, источник, реквизиты или сертификат изменились.")
                    authenticate(a)
                } ?: deny("Сервер занят другой операцией. Проверка входа не начата.")
            } }
        } catch (_: TimeoutCancellationException) { return deny("Проверка превысила время ожидания. Итог входа неизвестен; повтора нет.") } catch (c: CancellationException) { throw c } catch (_: Exception) { return deny("Итог входа неизвестен. Автоматического повтора пароля не будет.") } finally { finish() }
    }
    private suspend fun authenticate(a: RecoveryPanelAuthority): RecoveryPanelCheckResult {
        var ssh: SshSessionHandle? = null; var forward: WebPanelLocalForwardHandle? = null
        try {
            val transport = when (val route = a.target.routeTarget) {
                is ResolvedWebPanelRouteTarget.Direct -> WebPanelAuthenticationTransport.Direct
                is ResolvedWebPanelRouteTarget.SshTunnel -> {
                    when (val opened = sshFactory.connect(a.local.access, SessionOwner.WebPanel(a.panel.value.id))) {
                        is SshConnectResult.Failed -> return deny("SSH-подключение не подтверждено. Реквизиты панели не переданы.")
                        is SshConnectResult.Connected -> ssh = opened.handle
                    }
                    val connection = requireNotNull(ssh)
                    if (!connection.isOpen || connection.binding.owner != SessionOwner.WebPanel(a.panel.value.id) ||
                        connection.binding.serverAccessId != route.serverAccessId) return deny("Владелец SSH-сессии изменился.")
                    currentCoroutineContext().ensureActive()
                    when (val opened = connection.openWebPanelLocalForward(a.target)) {
                        is WebPanelLocalForwardOpenResult.Opened -> forward = opened.handle
                        is WebPanelLocalForwardOpenResult.AlreadyOpen -> forward = opened.handle
                        is WebPanelLocalForwardOpenResult.Rejected -> return deny("Точный SSH-маршрут недоступен.")
                    }
                    val tunnel = requireNotNull(forward)
                    if (!tunnel.isOpen || tunnel.target != a.target || tunnel.sessionBinding != connection.binding)
                        return deny("SSH-проброс не совпал с выбранным доступом.")
                    WebPanelAuthenticationTransport.SshTunnel(tunnel, WebPanelHost("127.0.0.1"), PinnedSshPanelCertificate(a.target, requireNotNull(a.pin)))
                }
            }
            if (!same(a)) return deny("Цель изменилась до отправки реквизитов.")
            currentCoroutineContext().ensureActive()
            return when (val auth = authenticator.authenticate(WebPanelAuthenticationRequest(a.target, transport, credentialAuthority = { same(a) }))) {
                is WebPanelAuthenticationResult.Failed -> deny(when {
                    auth.evidence.failure == WebPanelAuthenticationFailure.SECOND_FACTOR_REQUIRED -> "Панель требует 2FA. Используйте отдельный ручной вход в WebPanel."
                    auth.evidence.credentialSubmission == CredentialSubmissionState.OUTCOME_UNKNOWN -> "Итог входа неизвестен; повторной отправки пароля не будет."
                    auth.evidence.failure == WebPanelAuthenticationFailure.TLS_FAILURE -> "Сертификат не прошёл проверку. Вход не подтверждён."
                    else -> "Авторизация не подтверждена. Повтор пароля автоматически не выполняется."
                })
                is WebPanelAuthenticationResult.Authenticated -> auth.session.use { session ->
                    if (!session.isOpen || session.target != a.target || session.webPanelAccessId != a.panel.value.id || !same(a))
                        return@use deny("Сессия или источник изменились. Результат входа не принимается.")
                    val reader = session as? WebPanelServerStatusSession ?: return@use deny("Сессия не поддерживает проверку API.")
                    when (reader.readServerStatusOnce()) {
                        is WebPanelServerStatusResult.Failed -> deny("Вход принят, но чтение API не подтверждено. Полного подтверждения восстановления нет.")
                        is WebPanelServerStatusResult.Success -> if (same(a)) RecoveryPanelCheckResult.Verified(a.panel.value.id.value, now())
                            else deny("После чтения изменилась точная цель. Результат не принят.")
                    }
                }
            }
        } finally { runCatching { forward?.close() }; runCatching { ssh?.close() } }
    }
    private suspend fun same(a: RecoveryPanelAuthority): Boolean =
        authority(a.local.serverId, a.local.installationId, a.local.accessId, a.source.snapshot.operationId.value, a.panel.value.id.value) == a
    private suspend fun ready(s: String, i: String, a: String) =
        (local.readExact(s, i, a) as? ManagementRestartLocalReview.Ready)?.review?.takeIf { it.matches(s, i, a) }
    private suspend fun source(r: ManagementRestartReview, id: String): VersionedOperationSnapshot? {
        if (id.isBlank()) return null
        val c = (journal.get(OperationId(id)) as? OperationJournalResult.Success)?.value ?: return null
        if (CompensatedPanelStartBinding.parse(c.snapshot.checkpoint.phaseName) != null)
            return compensatedSource(r.serverId,r.installationId,r.accessId,id)?.takeIf { it == c }
        val observation = statuses.read(r.serverId, r.installationId, r.accessId, id) ?: return null
        if (!observation.terminal || observation.operationId != id || c.snapshot.status != OperationStatus.SUCCEEDED ||
            RestoredPanelStartBinding.parse(c.snapshot.checkpoint.phaseName)?.first != RestoredPanelStartPhase.VERIFIED) return null
        val all = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value ?: return null
        if (all.any { it.snapshot.target.serverId == r.installation.serverId }) return null
        return c
    }
    private suspend fun authority(s: String, i: String, a: String, operation: String, panel: String): RecoveryPanelAuthority? {
        if (listOf(s, i, a, operation, panel).any { it.isBlank() }) return null
        val r = ready(s, i, a) ?: return null; val c = source(r, operation) ?: return null
        val p = (panels.get(WebPanelAccessId(panel)) as? RepositoryResult.Success)?.value ?: return null
        val target = (resolver.resolve(WebPanelTargetResolutionRequest(p.value.id, WebPanelScheme.HTTPS)) as? WebPanelTargetResolutionResult.Resolved)?.target ?: return null
        if (!RecoveryPanelCheckPolicy.permitted(r, c, p, target)) return null
        val route = target.routeTarget as? ResolvedWebPanelRouteTarget.SshTunnel
        val scope = route?.let { panelCertificateTrustScope(panel, a, it.remoteEndpoint.host.value, it.remoteEndpoint.port, it.webBasePath.value, "HTTPS") }
        val pin = scope?.let(pinRead)
        if (scope != null && (pin == null || !Regex("[0-9A-F]{64}").matches(pin))) return null
        if (ready(s, i, a) != r || source(r, operation) != c || (panels.get(p.value.id) as? RepositoryResult.Success)?.value != p) return null
        return RecoveryPanelAuthority(r, c, p, target, scope, pin)
    }
    private fun deny(message: String) = RecoveryPanelCheckResult.Unverified(message)
}
