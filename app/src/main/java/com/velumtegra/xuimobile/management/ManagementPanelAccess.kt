package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.CredentialTransactionResult
import com.velumtegra.xuimobile.core.domain.CredentialTransactionService
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.domain.OperationJournalResult
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator
import com.velumtegra.xuimobile.core.ssh.SshConnectResult
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SshSessionHandle
import com.velumtegra.xuimobile.core.ssh.XuiGeneratedPanelCredentials
import com.velumtegra.xuimobile.core.ssh.XuiInstallResultProbe
import com.velumtegra.xuimobile.core.ssh.XuiInstallResultRead
import com.velumtegra.xuimobile.core.ssh.XuiPanelAccessControl
import com.velumtegra.xuimobile.core.ssh.XuiPanelAccessRead
import com.velumtegra.xuimobile.core.ssh.XuiPanelAccessState
import com.velumtegra.xuimobile.core.ssh.XuiPanelChangeResult
import com.velumtegra.xuimobile.core.ssh.XuiPanelExposure
import com.velumtegra.xuimobile.inventory.LinkedPanelCredentialResult
import com.velumtegra.xuimobile.inventory.LinkedWebPanelCredentialPort
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** What the operator sees on the «Доступ к панели» card. */
internal data class PanelAccessOverview(
    val server: XuiPanelAccessState,
    /** Saved SSH-tunnel sign-ins for exactly this installation and SSH profile. */
    val tunnelProfiles: Int,
    /** Saved direct (internet) sign-ins for this installation. */
    val directProfiles: Int,
)

internal sealed interface PanelAccessOutcome {
    data class Done(val message: String, val overview: PanelAccessOverview?) : PanelAccessOutcome
    /** A new sign-in was set; shown once in a secure window and already saved on this phone. */
    data class NewSignIn(val username: String, val password: String, val message: String, val overview: PanelAccessOverview?) :
        PanelAccessOutcome {
        override fun toString(): String = "NewSignIn(<redacted>)"
    }
    data class Failed(val reason: String) : PanelAccessOutcome
}

/**
 * Situations for a 3x-ui installation the app manages:
 *  1. panel open to the internet  → save a tunnel (or direct) sign-in, optionally close it;
 *  2. panel closed (loopback)     → only a tunnel sign-in works;
 *  3. sign-in lost                → reset it to app-generated values saved straight into this phone.
 * Every change runs under the server maintenance lease and never touches inbounds or clients.
 */
internal class ManagementPanelAccessPort(
    private val local: ManagementRestartLocalPort,
    private val factory: SshConnectionFactory,
    private val journal: OperationJournal,
    private val runtime: OperationRuntimeCoordinator,
    private val panels: WebPanelAccessRepository,
    private val credentials: CredentialTransactionService,
    private val linker: LinkedWebPanelCredentialPort,
    private val installations: XuiInstallationRepository,
    /** Called after a sign-in rotation leaves the previous encrypted password unreferenced. */
    private val onLocalLeftovers: () -> Unit = {},
) {
    /**
     * After the app's own 3x-ui install (its sign-in is known from the installer's result file): close the
     * panel to the internet and save an SSH-tunnel sign-in on this phone. Idempotent; the install consent covers it.
     */
    suspend fun secureFreshInstallation(serverId: String, accessId: String): PanelAccessOutcome {
        val installationId = withContext(Dispatchers.IO) {
            ((installations.listForServer(ServerId(serverId)) as? RepositoryResult.Success)?.value)
                ?.singleOrNull()?.value?.id?.value
        } ?: return PanelAccessOutcome.Failed("Запись установки ещё не сохранена на телефоне.")
        val current = inspect(serverId, installationId, accessId) as? PanelAccessOutcome.Done
            ?: return PanelAccessOutcome.Failed("Не удалось прочитать настройки панели.")
        val overview = requireNotNull(current.overview)
        val steps = mutableListOf<String>()
        if (overview.server.exposure != XuiPanelExposure.LOOPBACK) {
            when (val closed = closeToInternet(serverId, installationId, accessId)) {
                is PanelAccessOutcome.Failed -> return PanelAccessOutcome.Failed("Не удалось закрыть панель: ${closed.reason}")
                else -> steps += "панель закрыта от интернета"
            }
        } else steps += "панель уже закрыта от интернета"
        if (overview.tunnelProfiles == 0) {
            when (val saved = saveTunnelFromInstaller(serverId, installationId, accessId)) {
                is PanelAccessOutcome.Failed -> return PanelAccessOutcome.Failed(
                    steps.joinToString(", ").replaceFirstChar(Char::uppercase) + ", но вход не сохранён: ${saved.reason}",
                )
                else -> steps += "вход через SSH-туннель сохранён на телефоне"
            }
        } else steps += "вход через SSH-туннель уже сохранён"
        return PanelAccessOutcome.Done(steps.joinToString(", ").replaceFirstChar(Char::uppercase) + ".", null)
    }

    suspend fun inspect(serverId: String, installationId: String, accessId: String): PanelAccessOutcome =
        session(serverId, installationId, accessId, mutate = false) { review, ssh ->
            when (val read = XuiPanelAccessControl.read(ssh)) {
                is XuiPanelAccessRead.Observed -> PanelAccessOutcome.Done("", overview(review, read.state))
                XuiPanelAccessRead.NotInstalled -> PanelAccessOutcome.Failed("3x-ui не найдена по стандартному пути.")
                XuiPanelAccessRead.Unavailable -> PanelAccessOutcome.Failed("Не удалось прочитать настройки панели.")
            }
        }

    suspend fun closeToInternet(serverId: String, installationId: String, accessId: String): PanelAccessOutcome =
        session(serverId, installationId, accessId, mutate = true) { review, ssh ->
            when (val r = XuiPanelAccessControl.closeToInternet(ssh)) {
                is XuiPanelChangeResult.Applied -> PanelAccessOutcome.Done(
                    "Панель закрыта от интернета: она слушает только ${r.state.boundAddresses.joinToString()}. " +
                        "Открывается через SSH-туннель." + baselineNote(rememberListenAddress(review, r.state)),
                    overview(review, r.state),
                )
                is XuiPanelChangeResult.Failed -> PanelAccessOutcome.Failed(r.reason)
            }
        }

    suspend fun openToInternet(serverId: String, installationId: String, accessId: String): PanelAccessOutcome =
        session(serverId, installationId, accessId, mutate = true) { review, ssh ->
            when (val r = XuiPanelAccessControl.openToInternet(ssh)) {
                is XuiPanelChangeResult.Applied -> PanelAccessOutcome.Done(
                    "Панель снова открыта в интернет на порту ${r.state.panelPort}." +
                        (if (r.state.tlsEnabled) "" else " Сертификата нет: пароль пойдёт по сети открытым текстом.") +
                        baselineNote(rememberListenAddress(review, r.state)),
                    overview(review, r.state),
                )
                is XuiPanelChangeResult.Failed -> PanelAccessOutcome.Failed(r.reason)
            }
        }

    /** Reads the installer's sign-in on the server and saves it as an SSH-tunnel profile; nothing changes on the VPS. */
    suspend fun saveTunnelFromInstaller(serverId: String, installationId: String, accessId: String): PanelAccessOutcome {
        val read = session(serverId, installationId, accessId, mutate = false) { _, ssh ->
            when (val r = XuiInstallResultProbe.read(ssh)) {
                is XuiInstallResultRead.Observed -> PanelAccessOutcome.NewSignIn(r.credentials.username, r.credentials.password, "", null)
                XuiInstallResultRead.NotRecorded -> PanelAccessOutcome.Failed(
                    "На сервере нет записи установщика. Введите логин и пароль вручную или сбросьте их.",
                )
                XuiInstallResultRead.Unavailable -> PanelAccessOutcome.Failed("Не удалось прочитать запись установщика.")
            }
        }
        val signIn = read as? PanelAccessOutcome.NewSignIn ?: return read
        return saveTunnel(serverId, installationId, accessId, signIn.username, signIn.password.toByteArray(Charsets.UTF_8))
    }

    /** Operator-typed sign-in for a panel the app did not install. Takes ownership of [password] and wipes it. */
    suspend fun saveTunnel(
        serverId: String, installationId: String, accessId: String, username: String, password: ByteArray,
    ): PanelAccessOutcome = try {
        when (val saved = linker.saveViaSsh(serverId, installationId, accessId, username, password, true)) {
            is LinkedPanelCredentialResult.Saved -> PanelAccessOutcome.Done(
                "Вход через SSH-туннель сохранён на телефоне. Откройте «Открыть веб-панель».", null,
            )
            is LinkedPanelCredentialResult.Rejected -> PanelAccessOutcome.Failed(saved.reason)
        }
    } finally {
        password.fill(0)
    }

    /**
     * Situation 3: sets an app-generated sign-in, then stores it: the existing tunnel profile of this installation
     * is rotated in place, otherwise a new tunnel profile is created.
     */
    suspend fun resetSignIn(
        serverId: String, installationId: String, accessId: String, resetTwoFactor: Boolean,
    ): PanelAccessOutcome {
        val generated = XuiGeneratedPanelCredentials.generate()
        val applied = session(serverId, installationId, accessId, mutate = true) { review, ssh ->
            when (val r = XuiPanelAccessControl.resetSignIn(ssh, generated, resetTwoFactor)) {
                is XuiPanelChangeResult.Applied -> PanelAccessOutcome.Done("", overview(review, r.state))
                is XuiPanelChangeResult.Failed -> PanelAccessOutcome.Failed(r.reason)
            }
        }
        if (applied !is PanelAccessOutcome.Done) return applied
        val stored = storeSignIn(serverId, installationId, accessId, generated)
        if (stored) onLocalLeftovers()
        val note = if (stored) "Новый логин и пароль сохранены на этом телефоне."
        else "Логин и пароль изменены, но сохранить их на телефоне не удалось — запишите их сейчас."
        return PanelAccessOutcome.NewSignIn(generated.username, generated.password,
            "Логин и пароль панели заменены. Все открытые в браузерах сеансы панели завершены. $note", applied.overview)
    }

    private suspend fun storeSignIn(
        serverId: String, installationId: String, accessId: String, signIn: XuiGeneratedPanelCredentials,
    ): Boolean =
        withContext(Dispatchers.IO) {
            val existing = (panels.list() as? RepositoryResult.Success)?.value.orEmpty().filter {
                (it.value.installationLink as? WebPanelInstallationLink.Linked)?.installationId?.value == installationId &&
                    (it.value.route as? WebPanelRoute.SshTunnel)?.serverAccessId?.value == accessId
            }
            if (existing.size > 1) return@withContext false
            val target = existing.singleOrNull()
                ?: return@withContext linker.saveViaSsh(serverId, installationId, accessId, signIn.username,
                    signIn.password.toByteArray(Charsets.UTF_8), true) is LinkedPanelCredentialResult.Saved
            SecretMaterial.fromBytes(signIn.password.toByteArray(Charsets.UTF_8)).use { secret ->
                credentials.replaceWebPanelCredential(target.value.id, target.revision, signIn.username,
                    SecretId(UUID.randomUUID().toString()), secret) is CredentialTransactionResult.Success
            }
        }

    /**
     * The app itself just changed and verified the listen address, so the saved baseline follows it; otherwise
     * every later check would report the app's own change as drift. Only this one field is rewritten, only for
     * the exact reviewed record, and only while the saved panel port still matches the server.
     */
    private suspend fun rememberListenAddress(review: ManagementRestartReview, state: XuiPanelAccessState): Boolean =
        rememberPanelListenAddress(installations, review.installation, state)

    private fun baselineNote(remembered: Boolean): String =
        if (remembered) "" else " Сохранённые сведения об установке обновить не удалось: проверка покажет изменение адреса панели."

    private suspend fun overview(review: ManagementRestartReview, state: XuiPanelAccessState): PanelAccessOverview {
        val linked = (panels.list() as? RepositoryResult.Success)?.value.orEmpty().filter {
            (it.value.installationLink as? WebPanelInstallationLink.Linked)?.installationId == review.installation.id
        }
        return PanelAccessOverview(
            server = state,
            tunnelProfiles = linked.count { (it.value.route as? WebPanelRoute.SshTunnel)?.serverAccessId == review.access.id },
            directProfiles = linked.count { it.value.route is WebPanelRoute.Direct },
        )
    }

    private suspend fun session(
        serverId: String, installationId: String, accessId: String, mutate: Boolean,
        action: suspend (ManagementRestartReview, SshSessionHandle) -> PanelAccessOutcome,
    ): PanelAccessOutcome = withContext(Dispatchers.IO) {
        try {
            val review = (local.readExact(serverId, installationId, accessId) as? ManagementRestartLocalReview.Ready)?.review
                ?.takeIf { it.matches(serverId, installationId, accessId) }
                ?: return@withContext PanelAccessOutcome.Failed("Установка или SSH-профиль изменились. Обновите экран.")
            val run: suspend () -> PanelAccessOutcome = {
                val owner = SessionOwner.Management(review.installation.id, review.access.id)
                when (val connected = factory.connect(review.access, owner)) {
                    is SshConnectResult.Failed -> PanelAccessOutcome.Failed("Не удалось подключиться к серверу по SSH.")
                    is SshConnectResult.Connected -> connected.handle.use { ssh ->
                        if (ssh.binding.owner != owner || ssh.binding.serverAccessId != review.access.id) {
                            PanelAccessOutcome.Failed("SSH-сессия не соответствует выбранному профилю.")
                        } else action(review, ssh)
                    }
                }
            }
            if (!mutate) return@withContext run()
            val unfinished = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                ?: return@withContext PanelAccessOutcome.Failed("Не удалось проверить журнал операций VPS.")
            if (unfinished.any { it.snapshot.target.serverId == review.installation.serverId }) {
                return@withContext PanelAccessOutcome.Failed("На VPS есть незавершённая операция. Дождитесь её завершения.")
            }
            runtime.withExclusiveServerMaintenanceLease(ServerId(serverId), OperationId(UUID.randomUUID().toString())) { run() }
                ?: PanelAccessOutcome.Failed("Сейчас с этим VPS выполняется другая операция. Повторите позже.")
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            PanelAccessOutcome.Failed("Связь с сервером прервалась. Проверьте состояние панели перед повтором.")
        }
    }

    companion object {
        fun exposureLabel(state: XuiPanelAccessState): String = when (state.exposure) {
            XuiPanelExposure.LOOPBACK -> "Закрыта от интернета: доступна только через SSH-туннель."
            XuiPanelExposure.PUBLIC -> "Открыта в интернет на порту ${state.panelPort}" +
                if (state.tlsEnabled) " (HTTPS)." else " без сертификата — пароль идёт открытым текстом."
            XuiPanelExposure.SPECIFIC -> "Слушает только адрес ${state.listenAddress}, порт ${state.panelPort}."
        }
    }
}
