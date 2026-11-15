package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.domain.DiscoveryClassifier
import com.velumtegra.xuimobile.core.model.DiscoveryEvidence
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.model.DiscoveryClassification
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.FreshInstallScope
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.DiscoverySshProbeExecutor
import com.velumtegra.xuimobile.core.ssh.DiscoverySshProbeRunResult
import com.velumtegra.xuimobile.core.ssh.FreshInstallConflict
import com.velumtegra.xuimobile.core.ssh.FreshInstallPrerequisiteGap
import com.velumtegra.xuimobile.core.ssh.FreshInstallReadinessObservationResult
import com.velumtegra.xuimobile.core.ssh.FreshInstallReadinessSshAdapter
import com.velumtegra.xuimobile.core.ssh.XuiObservedServiceState
import com.velumtegra.xuimobile.core.ssh.XuiReadOnlyServiceStateProbe
import com.velumtegra.xuimobile.core.ssh.XuiReadOnlyVersionProbe
import com.velumtegra.xuimobile.core.ssh.XuiVersionProbeOutcome
import com.velumtegra.xuimobile.core.ssh.XuiServiceProbeOutcome
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.VerifiedHostKeySshSessionHandle
import com.velumtegra.xuimobile.readiness.LiveSshConnectionPolicy
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessPolicy
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** A SINGLE explicitly authorized read-only discovery. This port never writes Room or executes mutations. */
interface XuiReadOnlyDiscoveryPort {
    val supportsFreshInstallReadiness: Boolean get() = false

    suspend fun checkFreshInstallReadiness(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean,
    ): XuiReadOnlyDiscoveryResult = XuiReadOnlyDiscoveryResult.Blocked("Проверка готовности недоступна.")

    suspend fun inspectExact(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean,
    ): XuiReadOnlyDiscoveryResult

    /** Same exact read-only plan with finite diagnostic projection; never broadens target/probe authority. */
    suspend fun inspectDiagnosticExact(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean,
    ): XuiReadOnlyDiscoveryResult = XuiReadOnlyDiscoveryResult.Blocked("Диагностика обнаружения недоступна.")

    /** A second explicit user gesture; the default is denial for existing mock implementations. */
    suspend fun verifyServiceExact(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean, candidate: XuiCandidateIdentityEvidence,
    ): XuiServiceVerificationResult = XuiServiceVerificationResult.Blocked("Проверка службы недоступна.")

    /** Independent third one-shot permission; default-deny for existing fixture adapters. */
    suspend fun verifyVersionExact(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean, candidate: XuiCandidateIdentityEvidence,
    ): XuiVersionVerificationResult = XuiVersionVerificationResult.Blocked("Проверка версии недоступна.")
}

sealed interface XuiServiceVerificationResult {
    data class Observed(val state: XuiObservedServiceState) : XuiServiceVerificationResult
    data class Blocked(val message: String) : XuiServiceVerificationResult
}

/** Reject forged/unsupported paths before any second SSH connection. */
object XuiServiceVerificationPolicy {
    fun approvedCandidate(candidate: XuiCandidateIdentityEvidence): Boolean {
        if (candidate.serviceUnit != "x-ui.service") return false
        val root = candidate.rootPath
        if (root != "/usr/local/x-ui" && root != "/opt/x-ui") return false
        if (candidate.binaryPath != "$root/x-ui") return false
        return candidate.databasePath == "/etc/x-ui/x-ui.db" ||
            candidate.databasePath == "$root/db/x-ui.db" ||
            candidate.databasePath == "$root/x-ui.db"
    }
}


/** Only a sanitized, strictly parsed version token may cross to the UI. */
sealed interface XuiVersionVerificationResult {
    data class Observed(val version: String) : XuiVersionVerificationResult
    data class Blocked(val message: String) : XuiVersionVerificationResult
}

object XuiVersionVerificationPolicy {
    fun approvedCandidate(candidate: XuiCandidateIdentityEvidence): Boolean =
        XuiServiceVerificationPolicy.approvedCandidate(candidate) &&
            candidate.binaryPath in setOf("/usr/local/x-ui/x-ui", "/opt/x-ui/x-ui")
}

sealed interface XuiReadOnlyDiscoveryResult {
    /** Initial read-only detection only: no version, port, path or persisted installation proof. */
    data class Observation(
        val label: String,
        val detail: String,
        val candidateIdentity: XuiCandidateIdentityEvidence? = null,
        val diagnostics: XuiDiscoveryDiagnostics? = null,
        /** True only for a typed FreshInstallReadinessObservationResult.Ready; never inferred from text. */
        val freshInstallReady: Boolean = false,
    ) : XuiReadOnlyDiscoveryResult
    data class Blocked(val message: String) : XuiReadOnlyDiscoveryResult
}

/** The same pre-network freshness fence as the explicit Phase15.3 SSH connection. */
object XuiDiscoveryConsentPolicy {
    fun reject(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        fresh: LocalSshReadinessResult, repeatedTarget: String, consent: Boolean,
    ): String? = LiveSshConnectionPolicy.preflight(
        serverId, accessId, reviewed, fresh, repeatedTarget, consent,
    )

    fun presentEvidence(evidence: DiscoveryEvidence): XuiReadOnlyDiscoveryResult.Observation {
        val classification = DiscoveryClassifier.classify(evidence)
        return present(classification).copy(
            candidateIdentity = XuiCandidateIdentityProofPolicy.project(evidence, classification),
        )
    }

    fun present(classification: DiscoveryClassification): XuiReadOnlyDiscoveryResult.Observation = when (classification) {
        is DiscoveryClassification.SupportedCandidate -> XuiReadOnlyDiscoveryResult.Observation(
            "Обнаружены признаки 3x-ui", "Только первичное обнаружение. Версия, порт, TLS, веб-путь и права управления ещё не подтверждены.",
        )
        DiscoveryClassification.NoSupportedInstallation -> XuiReadOnlyDiscoveryResult.Observation(
            "3x-ui не обнаружена", "В проверенных известных местах и службах признаки установки отсутствуют. Другие пути не исключены.",
        )
        DiscoveryClassification.ForeignPanel -> XuiReadOnlyDiscoveryResult.Observation(
            "Найдены признаки другой панели", "Это не подтверждает установленную 3x-ui. Изменения на сервере не выполнялись.",
        )
        is DiscoveryClassification.UnsupportedPlatform -> XuiReadOnlyDiscoveryResult.Observation(
            "Неизвестная совместимость ОС", "Найденная ОС не входит в проверенный набор платформ для обнаружения 3x-ui.",
        )
        is DiscoveryClassification.Ambiguous -> XuiReadOnlyDiscoveryResult.Observation(
            "Противоречивые сведения", "Результат неоднозначен. Никакая установка не подтверждена и не сохранена.",
        )
        is DiscoveryClassification.InsufficientEvidence -> XuiReadOnlyDiscoveryResult.Observation(
            "Недостаточно сведений", "Удалённые признаки не позволяют достоверно определить 3x-ui.",
        )
    }
}

/** Exact pinned, credential-fresh SSH sessions for explicitly requested read-only checks. */
class RepositoryXuiReadOnlyDiscoveryPort(
    private val servers: ServerRepository,
    private val accesses: ServerAccessRepository,
    private val connections: SshConnectionFactory,
    private val probe: DiscoverySshProbeExecutor = DiscoverySshProbeExecutor(),
) : XuiReadOnlyDiscoveryPort {
    private val installReadiness = FreshInstallReadinessSshAdapter()
    override val supportsFreshInstallReadiness = true

    override suspend fun checkFreshInstallReadiness(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean,
    ): XuiReadOnlyDiscoveryResult = withExactReadOnlySession(
        serverId, accessId, reviewed, repeatedTarget, consent,
        failureMessage = "Не удалось завершить проверку готовности. Установка не запускалась.",
    ) { operation, handle ->
        val scope = FreshInstallScope(operation, ServerId(serverId), ServerAccessId(accessId))
        presentFreshInstallReadiness(installReadiness.observe(scope, handle))
    }

    override suspend fun inspectExact(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean,
    ): XuiReadOnlyDiscoveryResult = inspect(serverId,accessId,reviewed,repeatedTarget,consent,false)

    override suspend fun inspectDiagnosticExact(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean,
    ): XuiReadOnlyDiscoveryResult = inspect(serverId,accessId,reviewed,repeatedTarget,consent,true)

    private suspend fun inspect(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean, diagnostic: Boolean,
    ): XuiReadOnlyDiscoveryResult = withExactReadOnlySession(
        serverId, accessId, reviewed, repeatedTarget, consent,
        failureMessage = "Не удалось завершить read-only обнаружение. Статус неизвестен; VPS не изменялся.",
    ) { operation, handle ->
        val scope = DiscoveryScope(operation, ServerId(serverId), ServerAccessId(accessId))
        when (val answer = probe.executeInitialPlan(scope, handle)) {
            is DiscoverySshProbeRunResult.Completed ->
                XuiDiscoveryConsentPolicy.presentEvidence(answer.evidence).let { observation ->
                    if (diagnostic) observation.copy(diagnostics = XuiDiscoveryDiagnosticsProjector.completed(answer.evidence)) else observation
                }
            is DiscoverySshProbeRunResult.Failed ->
                XuiReadOnlyDiscoveryResult.Observation(
                    "Статус неизвестен",
                    "Read-only проверка не завершена: нет достаточных данных или прав. Установка не изменена.",
                    diagnostics = if (diagnostic) XuiDiscoveryDiagnosticsProjector.failed(answer) else null,
                )
        }
    }

    private suspend fun withExactReadOnlySession(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean, failureMessage: String,
        check: suspend (OperationId, SshSessionHandle) -> XuiReadOnlyDiscoveryResult,
    ): XuiReadOnlyDiscoveryResult = withContext(Dispatchers.IO) {
        fun deny(message: String) = XuiReadOnlyDiscoveryResult.Blocked(message)
        try {
            // No socket, secret lookup or command if the *original* user gesture is invalid.
            if (!consent || serverId.isBlank() || accessId.isBlank() || reviewed.accessId != accessId ||
                repeatedTarget != LiveSshConnectionPolicy.exactTarget(reviewed)) {
                return@withContext deny("Укажите точный VPS и подтвердите одну read-only проверку.")
            }
            val server = (servers.get(ServerId(serverId)) as? RepositoryResult.Success)?.value?.value
                ?: return@withContext deny("Сервер больше не найден. Обновите список.")
            if (server.id.value != serverId) return@withContext deny("Получена запись другого сервера.")
            val access = (accesses.get(ServerAccessId(accessId)) as? RepositoryResult.Success)?.value
                ?: return@withContext deny("Выбранный SSH-доступ больше не найден.")
            val fresh = LocalSshReadinessPolicy.inspect(serverId, accessId, access)
            XuiDiscoveryConsentPolicy.reject(serverId, accessId, reviewed, fresh, repeatedTarget, consent)
                ?.let { return@withContext deny(it) }
            val pin = (CanonicalHostKeyFingerprint.parse(access.pinnedHostKey)
                as? HostKeyFingerprintParseResult.Valid)?.fingerprint
                ?: return@withContext deny("Закреплённый SSH-отпечаток недействителен.")
            val operation = OperationId(UUID.randomUUID().toString())
            val owner = SessionOwner.Operation(operation)
            when (val connected = connections.connect(access, owner)) {
                is SshConnectResult.Failed -> deny(safeConnectionFailure(connected.failure))
                is SshConnectResult.Connected -> {
                    val handle = connected.handle
                    try {
                        val verified = handle as? VerifiedHostKeySshSessionHandle
                        if (!handle.isOpen || handle.binding.serverAccessId != access.id ||
                            handle.binding.owner != owner ||
                            verified?.verifiedHostKeySha256 != pin.asHexSha256()) {
                            deny("SSH-ключ или точная привязка сессии не подтвердились. Команды не отправлены.")
                        } else {
                            check(operation, handle)
                        }
                    } finally { handle.close() }
                }
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            deny(failureMessage)
        }
    }

    override suspend fun verifyServiceExact(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean, candidate: XuiCandidateIdentityEvidence,
    ): XuiServiceVerificationResult = withContext(Dispatchers.IO) {
        fun deny(message: String) = XuiServiceVerificationResult.Blocked(message)
        try {
            // A prior UI discovery is not a reusable network authorization.
            if (!consent || serverId.isBlank() || accessId.isBlank() || reviewed.accessId != accessId ||
                repeatedTarget != LiveSshConnectionPolicy.exactTarget(reviewed) ||
                !XuiServiceVerificationPolicy.approvedCandidate(candidate)) {
                return@withContext deny("Нужно заново подтвердить точный SSH-доступ и кандидата 3x-ui.")
            }
            val server = (servers.get(ServerId(serverId)) as? RepositoryResult.Success)?.value?.value
                ?: return@withContext deny("Сервер больше не найден.")
            if (server.id.value != serverId) return@withContext deny("Чужая запись сервера.")
            val access = (accesses.get(ServerAccessId(accessId)) as? RepositoryResult.Success)?.value
                ?: return@withContext deny("SSH-доступ больше не найден.")
            val fresh = LocalSshReadinessPolicy.inspect(serverId, accessId, access)
            XuiDiscoveryConsentPolicy.reject(serverId, accessId, reviewed, fresh, repeatedTarget, consent)
                ?.let { return@withContext deny(it) }
            val pin = (CanonicalHostKeyFingerprint.parse(access.pinnedHostKey)
                as? HostKeyFingerprintParseResult.Valid)?.fingerprint
                ?: return@withContext deny("SSH-отпечаток недействителен.")
            val owner = SessionOwner.Operation(OperationId(UUID.randomUUID().toString()))
            when (val connected = connections.connect(access, owner)) {
                is SshConnectResult.Failed -> deny(safeConnectionFailure(connected.failure))
                is SshConnectResult.Connected -> {
                    val handle = connected.handle
                    try {
                        val verified = handle as? VerifiedHostKeySshSessionHandle
                        if (!handle.isOpen || handle.binding.serverAccessId != access.id ||
                            handle.binding.owner != owner ||
                            verified?.verifiedHostKeySha256 != pin.asHexSha256()) {
                            deny("SSH-ключ или привязка сессии не подтвердились. Команды не отправлены.")
                        } else {
                            when (val check = XuiReadOnlyServiceStateProbe.inspect(handle, candidate.serviceUnit)) {
                                is XuiServiceProbeOutcome.Observed -> XuiServiceVerificationResult.Observed(check.state)
                                XuiServiceProbeOutcome.Unavailable -> deny("Состояние службы не подтверждено; не интерпретируем его как остановку.")
                            }
                        }
                    } finally { handle.close() }
                }
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            deny("Не удалось безопасно прочитать состояние службы. VPS не изменялся.")
        }
    }


    override suspend fun verifyVersionExact(
        serverId: String, accessId: String, reviewed: LocalSshAccessSummary,
        repeatedTarget: String, consent: Boolean, candidate: XuiCandidateIdentityEvidence,
    ): XuiVersionVerificationResult = withContext(Dispatchers.IO) {
        fun deny(message: String) = XuiVersionVerificationResult.Blocked(message)
        try {
            // Service-state check is NOT an authorization for this new request.
            if (!consent || serverId.isBlank() || accessId.isBlank() || reviewed.accessId != accessId ||
                repeatedTarget != LiveSshConnectionPolicy.exactTarget(reviewed) ||
                !XuiVersionVerificationPolicy.approvedCandidate(candidate)) {
                return@withContext deny("Повторно подтвердите точную SSH-цель и кандидата 3x-ui.")
            }
            val server = (servers.get(ServerId(serverId)) as? RepositoryResult.Success)?.value?.value
                ?: return@withContext deny("Сервер больше не найден.")
            if (server.id.value != serverId) return@withContext deny("Чужая запись сервера.")
            val access = (accesses.get(ServerAccessId(accessId)) as? RepositoryResult.Success)?.value
                ?: return@withContext deny("SSH-доступ больше не найден.")
            val fresh = LocalSshReadinessPolicy.inspect(serverId, accessId, access)
            XuiDiscoveryConsentPolicy.reject(serverId, accessId, reviewed, fresh, repeatedTarget, consent)
                ?.let { return@withContext deny(it) }
            val pin = (CanonicalHostKeyFingerprint.parse(access.pinnedHostKey)
                as? HostKeyFingerprintParseResult.Valid)?.fingerprint
                ?: return@withContext deny("SSH-отпечаток недействителен.")
            val owner = SessionOwner.Operation(OperationId(UUID.randomUUID().toString()))
            when (val connected = connections.connect(access, owner)) {
                is SshConnectResult.Failed -> deny(safeConnectionFailure(connected.failure))
                is SshConnectResult.Connected -> {
                    val handle = connected.handle
                    try {
                        val verified = handle as? VerifiedHostKeySshSessionHandle
                        if (!handle.isOpen || handle.binding.serverAccessId != access.id ||
                            handle.binding.owner != owner ||
                            verified?.verifiedHostKeySha256 != pin.asHexSha256()) {
                            deny("SSH-ключ или привязка сессии не подтвердились. Команды не отправлены.")
                        } else {
                            when (val check = XuiReadOnlyVersionProbe.inspect(handle, candidate.binaryPath)) {
                                is XuiVersionProbeOutcome.Observed -> XuiVersionVerificationResult.Observed(check.version)
                                XuiVersionProbeOutcome.Unavailable -> deny("Версия не подтверждена: вывод несовместим или недоступен.")
                            }
                        }
                    } finally { handle.close() }
                }
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            deny("Не удалось безопасно прочитать версию. VPS не изменялся.")
        }
    }

    private fun safeConnectionFailure(failure: SshConnectFailure): String = when (failure) {
        is SshConnectFailure.HostIdentityMismatch -> "SSH-ключ сервера изменился. Проверка запрещена."
        SshConnectFailure.AuthenticationRejected -> "SSH-аутентификация отклонена."
        is SshConnectFailure.Timeout -> "SSH-подключение превысило время ожидания."
        is SshConnectFailure.SecretUnavailable, is SshConnectFailure.SecretCorrupt,
        is SshConnectFailure.SecretStorageFailure -> "Защищённые SSH-реквизиты недоступны."
        SshConnectFailure.Cancelled -> "SSH-подключение отменено."
        else -> "SSH-соединение недоступно. Статус X-UI неизвестен."
    }
}

private fun presentFreshInstallReadiness(answer: FreshInstallReadinessObservationResult): XuiReadOnlyDiscoveryResult =
    when (answer) {
        is FreshInstallReadinessObservationResult.Ready -> XuiReadOnlyDiscoveryResult.Observation(
            "Предварительная проверка пройдена",
            "Система, права root и инструменты подтверждены. В проверенных местах признаков другой установки нет. Установка не запускалась.",
            freshInstallReady = true,
        )
        is FreshInstallReadinessObservationResult.Conflict -> XuiReadOnlyDiscoveryResult.Observation(
            "Обнаружен конфликт с новой установкой",
            answer.conflicts.joinToString("\n") {
                when (it) {
                    is FreshInstallConflict.ExistingServiceUnit -> "Найдена служба: " + it.serviceUnit
                    is FreshInstallConflict.ExistingPath -> "Занят путь: " + it.path
                }
            } + "\nУстановка не запускалась.",
        )
        is FreshInstallReadinessObservationResult.PrerequisitesUnmet -> XuiReadOnlyDiscoveryResult.Observation(
            "Не выполнены условия новой установки",
            answer.prerequisiteGaps.joinToString("\n") {
                when (it) {
                    FreshInstallPrerequisiteGap.NotDirectRoot -> "Нужен SSH-профиль с прямым доступом root."
                    FreshInstallPrerequisiteGap.NotLinux -> "Не подтверждена система Linux."
                    FreshInstallPrerequisiteGap.UnsupportedArchitecture -> "Архитектура не поддерживается."
                    is FreshInstallPrerequisiteGap.UnsupportedPlatform -> "Дистрибутив не поддерживается."
                    FreshInstallPrerequisiteGap.SystemdUnavailable -> "systemd недоступен."
                    is FreshInstallPrerequisiteGap.RequiredToolMissing -> "Не найден инструмент: " + it.tool
                }
            } + "\nУстановка не запускалась.",
        )
        is FreshInstallReadinessObservationResult.Indeterminate ->
            XuiReadOnlyDiscoveryResult.Blocked("Готовность не подтверждена: ответ сервера неполный или проверка прервалась. Установка не запускалась.")
        is FreshInstallReadinessObservationResult.Rejected ->
            XuiReadOnlyDiscoveryResult.Blocked("SSH-сессия не соответствует выбранному профилю или закрыта. Команды не отправлены.")
    }
