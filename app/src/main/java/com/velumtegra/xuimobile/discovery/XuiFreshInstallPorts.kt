package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.domain.InstallerCheckpointPolicy
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ServerAccessRepository
import com.velumtegra.xuimobile.core.domain.ServerRepository
import com.velumtegra.xuimobile.core.domain.VersionedOperationSnapshot
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.CheckpointSemantics
import com.velumtegra.xuimobile.core.model.InstallerPhase
import com.velumtegra.xuimobile.core.model.OperationCheckpoint
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.OperationSnapshot
import com.velumtegra.xuimobile.core.model.OperationStatus
import com.velumtegra.xuimobile.core.model.OperationTarget
import com.velumtegra.xuimobile.core.model.OperationType
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.runtime.DurableServerMutationBarrierPolicy
import com.velumtegra.xuimobile.core.runtime.InstallerExplicitConsentRegistrationResult
import com.velumtegra.xuimobile.core.runtime.InstallerExplicitInstallConsent
import com.velumtegra.xuimobile.core.runtime.ServerMutationBarrierDecision
import com.velumtegra.xuimobile.readiness.LiveSshConnectionPolicy
import com.velumtegra.xuimobile.readiness.LocalSshAccessSummary
import com.velumtegra.xuimobile.readiness.LocalSshReadinessPolicy
import com.velumtegra.xuimobile.readiness.LocalSshReadinessResult
import com.velumtegra.xuimobile.runtime.ExactOperationHostStartResult
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * Durable binding of one INSTALL operation to the exact reviewed SSH profile, without a migration and
 * without storing secrets: the OperationId itself carries a SHA-256 over the non-secret profile identity
 * (server, access id, endpoint, user, auth kind, pinned host key, credential-reference digest).
 * A different profile (even with the same access id) yields a different digest, so a journal row can
 * never be adopted by, or replayed through, another profile.
 */
object XuiFreshInstallProfileBinding {
    private val idPattern = Regex("xui-install-([0-9a-f]{32})-([0-9a-f]{32})")

    fun digest(serverId: String, profile: LocalSshAccessSummary): String {
        val canonical = listOf(
            "velum-tegra:fresh-install-profile:v1", serverId, profile.accessId, profile.host,
            profile.port.toString(), profile.username, profile.authLabel.substringBefore(" ("),
            profile.savedFingerprint, profile.credentialRefDigest,
        ).joinToString("\u0000")
        return MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }.take(32)
    }

    fun operationId(randomHex: String, serverId: String, profile: LocalSshAccessSummary): OperationId {
        require(Regex("[0-9a-f]{32}").matches(randomHex)) { "OperationId entropy must be 32 lowercase hex chars" }
        return OperationId("xui-install-$randomHex-${digest(serverId, profile)}")
    }

    /** True only for ids created by this feature that are bound to exactly this profile. */
    fun belongsTo(operationId: OperationId, serverId: String, profile: LocalSshAccessSummary): Boolean =
        idPattern.matchEntire(operationId.value)?.groupValues?.get(2) == digest(serverId, profile)

    fun isFeatureId(operationId: OperationId): Boolean = idPattern.matches(operationId.value)
}

data class XuiFreshInstallObservation(
    val operationId: String,
    val text: String,
    val terminal: Boolean,
    /** True only for a durable SUCCEEDED/TERMINAL INSTALLER_RESULT_SUCCESS row (verified publish done). */
    val succeeded: Boolean = false,
    val mayCheckReadOnly: Boolean = false,
    val mayCancelBeforeDispatch: Boolean = false,
    val observedAt: Instant? = null,
)

/** Local journal view only: no SSH. [otherProfileBlockers] are unfinished INSTALL rows of other profiles. */
data class XuiFreshInstallRecovery(
    val own: List<XuiFreshInstallObservation>,
    val otherProfileBlockers: Int,
)

sealed interface XuiFreshInstallStart {
    data class Recorded(val operationId: String) : XuiFreshInstallStart
    data class Blocked(val message: String) : XuiFreshInstallStart
}

interface XuiFreshInstallActionPort {
    suspend fun startConfirmed(serverId: String, reviewed: LocalSshAccessSummary): XuiFreshInstallStart
    suspend fun recoverExact(serverId: String, reviewed: LocalSshAccessSummary): XuiFreshInstallRecovery
    suspend fun statusExact(operationId: String, serverId: String, reviewed: LocalSshAccessSummary): XuiFreshInstallObservation?
    suspend fun checkResultConfirmed(operationId: String, serverId: String, reviewed: LocalSshAccessSummary): String?
    suspend fun cancelBeforeDispatch(operationId: String, serverId: String, reviewed: LocalSshAccessSummary): String?
}

/** Process-local consent registry boundary (wired to OperationRuntimeCoordinator in production). */
internal interface XuiFreshInstallConsentRuntime {
    fun register(consent: InstallerExplicitInstallConsent): InstallerExplicitConsentRegistrationResult
    fun discard(operationId: OperationId): Boolean
}

internal class ProductionXuiFreshInstallActionPort(
    private val servers: ServerRepository,
    private val accesses: ServerAccessRepository,
    private val installations: XuiInstallationRepository,
    private val journal: OperationJournal,
    private val runtime: XuiFreshInstallConsentRuntime,
    private val hostStart: suspend (OperationId) -> ExactOperationHostStartResult,
    private val now: () -> Instant = Instant::now,
    private val randomHex: () -> String = { UUID.randomUUID().toString().replace("-", "") },
) : XuiFreshInstallActionPort {

    override suspend fun startConfirmed(serverId: String, reviewed: LocalSshAccessSummary): XuiFreshInstallStart {
        val access = freshAccess(serverId, reviewed)
            ?: return XuiFreshInstallStart.Blocked("SSH-профиль или сервер изменились. Выберите профиль и повторите проверку.")
        when (val local = installations.listForServer(ServerId(serverId))) {
            is RepositoryResult.Success ->
                if (local.value.isNotEmpty()) return XuiFreshInstallStart.Blocked("Для этого сервера уже сохранена установка 3x-ui. Новая установка не запускается.")
            else -> return XuiFreshInstallStart.Blocked("Не удалось проверить локальные записи установок.")
        }
        val unfinished = journal.listNonTerminal()
        if (unfinished !is OperationJournalResult.Success) return XuiFreshInstallStart.Blocked("Не удалось проверить журнал операций.")
        val snapshots = unfinished.value.map { it.snapshot }
        if (DurableServerMutationBarrierPolicy.evaluate(ServerId(serverId), snapshots) is ServerMutationBarrierDecision.BlockedByUncertainMutation) {
            return XuiFreshInstallStart.Blocked("У VPS есть неподтверждённое изменение. Сначала проверьте его результат.")
        }
        if (snapshots.any { it.type == OperationType.INSTALL && serverOf(it) == serverId }) {
            return XuiFreshInstallStart.Blocked("У этого VPS есть незавершённая установка. Проверьте её результат или отмените ожидающий запрос.")
        }
        val id = XuiFreshInstallProfileBinding.operationId(randomHex(), serverId, reviewed)
        val at = now()
        val initial = OperationSnapshot(
            id, OperationType.INSTALL, OperationTarget.ServerTarget(ServerId(serverId), access.id), OperationStatus.RUNNING,
            OperationCheckpoint(InstallerPhase.PREPARING.name, InstallerCheckpointPolicy.forPhase(InstallerPhase.PREPARING), at), at, at,
        )
        val created = journal.create(initial)
        if (created !is OperationJournalResult.Success) return XuiFreshInstallStart.Blocked("Не удалось записать запрос. Установка не отправлена.")
        try {
            val consent = InstallerExplicitInstallConsent(id, created.value.revision, access, at, at.plus(CONSENT_TTL))
            if (runtime.register(consent) != InstallerExplicitConsentRegistrationResult.Registered) {
                failBeforeDispatch(created.value); return XuiFreshInstallStart.Recorded(id.value)
            }
            if (freshAccess(serverId, reviewed) != access || hostStart(id) != ExactOperationHostStartResult.START_REQUEST_ACCEPTED) {
                runtime.discard(id); failBeforeDispatch(created.value)
            }
        } catch (cancel: CancellationException) {
            withContext(NonCancellable) { runtime.discard(id); failBeforeDispatch(created.value) }
            throw cancel
        } catch (_: Exception) {
            runtime.discard(id); failBeforeDispatch(created.value)
        }
        return XuiFreshInstallStart.Recorded(id.value)
    }

    override suspend fun recoverExact(serverId: String, reviewed: LocalSshAccessSummary): XuiFreshInstallRecovery {
        val list = journal.listNonTerminal() as? OperationJournalResult.Success ?: return XuiFreshInstallRecovery(emptyList(), 0)
        val install = list.value.filter { it.snapshot.type == OperationType.INSTALL && serverOf(it.snapshot) == serverId }
        val (own, other) = install.partition { owns(it.snapshot, serverId, reviewed) }
        return XuiFreshInstallRecovery(own.map { observe(it) }, other.size)
    }

    override suspend fun statusExact(operationId: String, serverId: String, reviewed: LocalSshAccessSummary): XuiFreshInstallObservation? =
        exact(operationId, serverId, reviewed)?.let { observe(it) }

    override suspend fun checkResultConfirmed(operationId: String, serverId: String, reviewed: LocalSshAccessSummary): String? {
        freshAccess(serverId, reviewed) ?: return "SSH-профиль изменился. Проверка результата запрещена."
        val c = exact(operationId, serverId, reviewed) ?: return "Операция не соответствует выбранному SSH-профилю."
        if (c.snapshot.status in TERMINAL || c.snapshot.checkpoint.semantics !in CHECKABLE) {
            return "Разрешена только проверка уже отправленной установки."
        }
        return if (hostStart(c.snapshot.operationId) == ExactOperationHostStartResult.START_REQUEST_ACCEPTED) null
        else "Android не принял проверку результата. Состояние VPS пока не подтверждено."
    }

    override suspend fun cancelBeforeDispatch(operationId: String, serverId: String, reviewed: LocalSshAccessSummary): String? {
        val c = exact(operationId, serverId, reviewed) ?: return "Операция не соответствует выбранному SSH-профилю."
        if (c.snapshot.checkpoint.semantics != CheckpointSemantics.MUTATION_NOT_STARTED || c.snapshot.status in TERMINAL) {
            return "Установка могла быть отправлена. Используйте проверку результата."
        }
        val at = now(); if (at.isBefore(c.snapshot.updatedAt)) return "Не удалось подтвердить время отмены."
        val next = c.snapshot.copy(status = OperationStatus.CANCELLED,
            checkpoint = OperationCheckpoint("INSTALL_CANCELLED_BEFORE_DISPATCH", CheckpointSemantics.TERMINAL, at), updatedAt = at)
        if (journal.advance(c.snapshot.operationId, c.revision, next) !is OperationJournalResult.Success) {
            return "Состояние операции изменилось. Обновите результат."
        }
        runtime.discard(c.snapshot.operationId)
        return null
    }

    private suspend fun freshAccess(serverId: String, reviewed: LocalSshAccessSummary): ServerAccess? {
        if (serverId.isBlank() || reviewed.accessId.isBlank()) return null
        val server = (servers.get(ServerId(serverId)) as? RepositoryResult.Success)?.value?.value ?: return null
        if (server.id.value != serverId) return null
        val access = (accesses.get(ServerAccessId(reviewed.accessId)) as? RepositoryResult.Success)?.value ?: return null
        val fresh = LocalSshReadinessPolicy.inspect(serverId, reviewed.accessId, access)
        XuiDiscoveryConsentPolicy.reject(serverId, reviewed.accessId, reviewed, fresh, LiveSshConnectionPolicy.exactTarget(reviewed), true)
            ?.let { return null }
        return access.takeIf { it.id.value == reviewed.accessId && it.serverId.value == serverId }
    }

    private suspend fun exact(operationId: String, serverId: String, reviewed: LocalSshAccessSummary): VersionedOperationSnapshot? {
        if (operationId.isBlank()) return null
        val read = journal.get(OperationId(operationId)) as? OperationJournalResult.Success ?: return null
        return read.value.takeIf { it.snapshot.operationId.value == operationId && owns(it.snapshot, serverId, reviewed) }
    }

    /** Exact type, server, access id AND durable profile digest; nothing is chosen by "latest". */
    private fun owns(s: OperationSnapshot, serverId: String, reviewed: LocalSshAccessSummary): Boolean {
        val t = s.target as? OperationTarget.ServerTarget ?: return false
        return s.type == OperationType.INSTALL && t.serverId.value == serverId && t.serverAccessId.value == reviewed.accessId &&
            XuiFreshInstallProfileBinding.belongsTo(s.operationId, serverId, reviewed)
    }

    private fun serverOf(s: OperationSnapshot): String = s.target.serverId.value

    private fun observe(v: VersionedOperationSnapshot): XuiFreshInstallObservation {
        val s = v.snapshot; val cp = s.checkpoint.semantics; val terminal = s.status in TERMINAL
        val succeeded = s.status == OperationStatus.SUCCEEDED && cp == CheckpointSemantics.TERMINAL &&
            s.checkpoint.phaseName == "INSTALLER_RESULT_SUCCESS"
        val text = when {
            succeeded -> "Установка завершена: служба и запись установки подтверждены новым подключением."
            s.status == OperationStatus.CANCELLED -> "Ожидающий запрос отменён до отправки установки."
            s.checkpoint.phaseName == "INSTALL_HOST_NOT_STARTED" -> "Android не принял запуск. Установка не отправлена."
            terminal -> "Операция завершена без подтверждённого успеха. Установка не повторяется автоматически; проверьте диагностику."
            cp in CHECKABLE -> "Установка могла быть отправлена и идёт на VPS независимо от телефона. Проверьте результат новым подключением; повторный запуск не выполняется."
            else -> "Запрос записан, установка ещё не отправлялась. После перезапуска приложения подтверждение недействительно: запрос можно только отменить."
        }
        return XuiFreshInstallObservation(
            s.operationId.value, text, terminal, succeeded, !terminal && cp in CHECKABLE,
            !terminal && cp == CheckpointSemantics.MUTATION_NOT_STARTED, s.updatedAt,
        )
    }

    /** CAS from the created revision: a host that already advanced the row is never overwritten. */
    private suspend fun failBeforeDispatch(c: VersionedOperationSnapshot) {
        val at = now(); if (at.isBefore(c.snapshot.updatedAt)) return
        journal.advance(c.snapshot.operationId, c.revision, c.snapshot.copy(status = OperationStatus.FAILED,
            checkpoint = OperationCheckpoint("INSTALL_HOST_NOT_STARTED", CheckpointSemantics.TERMINAL, at), updatedAt = at))
    }

    private companion object {
        val CONSENT_TTL: Duration = Duration.ofSeconds(90)
        val TERMINAL = setOf(OperationStatus.SUCCEEDED, OperationStatus.FAILED, OperationStatus.CANCELLED)
        val CHECKABLE = setOf(CheckpointSemantics.MUTATION_IN_FLIGHT, CheckpointSemantics.POST_VERIFY_REQUIRED, CheckpointSemantics.COMMIT_VERIFIED)
    }
}
