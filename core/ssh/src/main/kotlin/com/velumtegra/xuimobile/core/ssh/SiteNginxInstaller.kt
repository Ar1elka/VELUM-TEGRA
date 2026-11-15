package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import java.time.Duration

enum class SiteNginxInstallOutcome(val message: String) {
    INSTALLED("nginx установлен и запущен. Нажмите «Проверить сервер» ещё раз."),
    ALREADY_RUNNING("nginx уже установлен и работает. Нажмите «Проверить сервер» ещё раз."),
    NO_APT("На сервере нет apt-get: автоматическая установка поддерживается только на Ubuntu/Debian."),
    INSTALL_FAILED("apt-get не смог установить nginx (нет сети к репозиториям или занят менеджер пакетов). Повторите позже."),
    START_FAILED("nginx установлен, но не запустился. Скорее всего порт 80 уже занят другой программой."),
    UNKNOWN("Не удалось подтвердить результат установки nginx. Проверьте сервер ещё раз."),
}

/**
 * Explicit, separately confirmed web-server provisioning for the site builder: installs the distro
 * nginx package and starts it. One fixed command, no caller text reaches the shell. Existing nginx is
 * never reinstalled or reconfigured. Waits for the dpkg lock (fresh VPS run unattended-upgrades).
 */
object SiteNginxInstaller {
    private const val CODE_NO_APT = 69
    private const val CODE_INSTALL = 70
    private const val CODE_START = 71

    internal val COMMAND: String = """
        set -u
        if command -v nginx >/dev/null 2>&1 && systemctl is-active --quiet nginx; then echo ALREADY_RUNNING; exit 0; fi
        command -v apt-get >/dev/null 2>&1 || exit $CODE_NO_APT
        export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
        if ! command -v nginx >/dev/null 2>&1; then
            apt-get install -y -q --no-install-recommends -o DPkg::Lock::Timeout=300 nginx >/dev/null 2>&1 ||
                { apt-get update -q -o DPkg::Lock::Timeout=300 >/dev/null 2>&1 &&
                  apt-get install -y -q --no-install-recommends -o DPkg::Lock::Timeout=300 nginx >/dev/null 2>&1; } ||
                exit $CODE_INSTALL
            # The distro package ships a placeholder "Welcome to nginx" site on port 80 (default_server).
            # It would make the site builder see port 80 as occupied. Disable it only in this pristine
            # state: the stock symlink is the sole enabled site and conf.d has no configs.
            if [ -L /etc/nginx/sites-enabled/default ] &&
               [ "${'$'}(readlink /etc/nginx/sites-enabled/default)" = /etc/nginx/sites-available/default ] &&
               [ "${'$'}(ls -A /etc/nginx/sites-enabled | wc -l)" -eq 1 ] &&
               [ -z "${'$'}(ls -A /etc/nginx/conf.d 2>/dev/null)" ]; then
                rm -f /etc/nginx/sites-enabled/default
                systemctl reload nginx >/dev/null 2>&1 || true
            fi
        fi
        systemctl enable --now nginx >/dev/null 2>&1 || exit $CODE_START
        systemctl is-active --quiet nginx || exit $CODE_START
        echo INSTALLED
    """.trimIndent()

    private val config = SshTransportConfig(
        channelOpenTimeout = Duration.ofSeconds(5),
        commandExecutionTimeout = Duration.ofSeconds(420),
        stdoutCaptureLimitBytes = 256,
        stderrCaptureLimitBytes = 4096,
    )

    suspend fun install(session: SshSessionHandle): SiteNginxInstallOutcome {
        if (!session.isOpen) return SiteNginxInstallOutcome.UNKNOWN
        val result = session.execute(RemoteCommand.create(COMMAND, "site-nginx-install"), config)
        if (result.dispatchState != CommandDispatchState.DISPATCHED) return SiteNginxInstallOutcome.UNKNOWN
        return when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> {
                val bytes = result.stdout.copyBytes()
                val text = try { bytes.decodeToString().trim() } finally { bytes.fill(0) }
                when (text) {
                    "INSTALLED" -> SiteNginxInstallOutcome.INSTALLED
                    "ALREADY_RUNNING" -> SiteNginxInstallOutcome.ALREADY_RUNNING
                    else -> SiteNginxInstallOutcome.UNKNOWN
                }
            }
            is CommandCompletion.ConfirmedFailure -> when (completion.exitCode) {
                CODE_NO_APT -> SiteNginxInstallOutcome.NO_APT
                CODE_INSTALL -> SiteNginxInstallOutcome.INSTALL_FAILED
                CODE_START -> SiteNginxInstallOutcome.START_FAILED
                else -> SiteNginxInstallOutcome.UNKNOWN
            }
            else -> SiteNginxInstallOutcome.UNKNOWN
        }
    }
}
