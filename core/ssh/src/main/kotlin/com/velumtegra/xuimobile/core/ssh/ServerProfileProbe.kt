package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import java.time.Duration
import java.util.Locale

/** What kind of server this is, read once and read-only, so the app can adapt and explain limits. */
data class ServerProfile(
    val osPrettyName: String?,
    val osId: String?,
    val osVersion: String?,
    val architecture: String?,
    val loginUser: String,
    val privilege: RemotePrivilegeMode,
    val packageManager: String?,
    val systemd: Boolean,
    val provider: String?,
    val virtualization: String?,
    val firewall: String?,
    val memoryMb: Long?,
    val freeDiskMb: Long?,
) {
    val osSupported: Boolean get() = osId in SUPPORTED_OS
    val architectureSupported: Boolean get() = architecture in SUPPORTED_ARCH
    val hasRoot: Boolean get() = privilege != RemotePrivilegeMode.UNPRIVILEGED

    /** Human-readable blockers for installing 3x-ui / publishing a site through the app. Empty = can install. */
    val blockers: List<String>
        get() = buildList {
            if (!hasRoot) add("У пользователя $loginUser нет прав root и нет sudo без запроса пароля. Войдите как root или выдайте sudo.")
            if (!osSupported) add("Система ${osPrettyName ?: osId ?: "неизвестна"} не поддерживается: нужна Ubuntu или Debian.")
            if (!architectureSupported) add("Архитектура ${architecture ?: "неизвестна"} не поддерживается установщиком 3x-ui.")
            if (!systemd) add("Нет systemd: службы 3x-ui и nginx не смогут работать.")
            if (packageManager != "apt" && osSupported) add("Не найден apt-get.")
            if (freeDiskMb != null && freeDiskMb < 1024) add("Мало места на диске: свободно ${freeDiskMb} МБ, нужно хотя бы 1 ГБ.")
        }

    /** Things that will not stop installation but the operator must know about. */
    val notes: List<String>
        get() = buildList {
            when (privilege) {
                RemotePrivilegeMode.SUDO_NOPASSWD -> add("Вход под $loginUser: команды выполняются через sudo.")
                RemotePrivilegeMode.SUDO_PASSWORD -> add("Вход под $loginUser: sudo запрашивает пароль, приложение подставляет пароль входа.")
                else -> Unit
            }
            if (provider in CLOUDS_WITH_EXTERNAL_FIREWALL) {
                add("$provider: порты 80/443 и порт панели нужно открыть ещё и в группе безопасности облака — приложение этого сделать не может.")
            }
            if (firewall == "ufw" || firewall == "firewalld") add("Включён файрвол $firewall: нужные порты придётся разрешить.")
            if (memoryMb != null && memoryMb < 512) add("Мало памяти: $memoryMb МБ. 3x-ui может работать нестабильно.")
        }

    companion object {
        val SUPPORTED_OS = setOf("ubuntu", "debian")
        val SUPPORTED_ARCH = setOf("x86_64", "aarch64", "armv7l", "armv8", "i686", "i386", "s390x")
        val CLOUDS_WITH_EXTERNAL_FIREWALL = setOf("Yandex Cloud", "AWS", "Google Cloud", "Azure", "Oracle Cloud", "VK Cloud")
    }
}

object ServerProfileProbe {
    internal val COMMAND: String = """
. /etc/os-release 2>/dev/null
printf 'OS=%s\nOS_ID=%s\nOS_VER=%s\n' "${'$'}{PRETTY_NAME:-}" "${'$'}{ID:-}" "${'$'}{VERSION_ID:-}"
printf 'ARCH=%s\n' "${'$'}(uname -m 2>/dev/null)"
for p in apt-get dnf yum zypper apk pacman; do if command -v "${'$'}p" >/dev/null 2>&1; then printf 'PM=%s\n' "${'$'}p"; break; fi; done
if [ -d /run/systemd/system ]; then printf 'SYSTEMD=1\n'; fi
printf 'VENDOR=%s\n' "${'$'}(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"
printf 'PRODUCT=%s\n' "${'$'}(cat /sys/class/dmi/id/product_name 2>/dev/null)"
printf 'CLOUD=%s\n' "${'$'}(cloud-id 2>/dev/null)"
printf 'VIRT=%s\n' "${'$'}(systemd-detect-virt 2>/dev/null)"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then printf 'FW=ufw\n'
elif command -v firewall-cmd >/dev/null 2>&1 && [ "${'$'}(firewall-cmd --state 2>/dev/null)" = running ]; then printf 'FW=firewalld\n'
fi
printf 'MEM_KB=%s\n' "${'$'}(awk '/^MemTotal:/ {print ${'$'}2}' /proc/meminfo 2>/dev/null)"
printf 'DISK_KB=%s\n' "${'$'}(df -Pk / 2>/dev/null | awk 'NR==2 {print ${'$'}4}')"
exit 0
"""

    private val config = SshTransportConfig(
        channelOpenTimeout = Duration.ofSeconds(5),
        commandExecutionTimeout = Duration.ofSeconds(15),
        stdoutCaptureLimitBytes = 8192,
        stderrCaptureLimitBytes = 4096,
    )

    suspend fun read(session: SshSessionHandle): ServerProfile? {
        if (!session.isOpen) return null
        val result = session.execute(RemoteCommand.create(COMMAND.trim(), "server-profile"), config)
        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.completion != CommandCompletion.ConfirmedSuccess ||
            result.stdout.truncated) return null
        val aware = session as? PrivilegeAwareSshSessionHandle
        return parse(
            result.stdout.copyBytes().decodeToString(),
            aware?.remoteLoginUser ?: "root",
            aware?.privilegeMode ?: RemotePrivilegeMode.ROOT,
        )
    }

    fun parse(text: String, loginUser: String, privilege: RemotePrivilegeMode): ServerProfile {
        val v = text.lineSequence().filter { '=' in it }
            .associate { it.substringBefore('=') to it.substringAfter('=').trim().take(200) }
        fun get(key: String) = v[key]?.takeIf { it.isNotBlank() }
        val pm = when (get("PM")) { "apt-get" -> "apt"; null -> null; else -> get("PM") }
        return ServerProfile(
            osPrettyName = get("OS"),
            osId = get("OS_ID")?.lowercase(Locale.ROOT),
            osVersion = get("OS_VER"),
            architecture = get("ARCH"),
            loginUser = loginUser,
            privilege = privilege,
            packageManager = pm,
            systemd = get("SYSTEMD") == "1",
            provider = provider(get("VENDOR"), get("PRODUCT"), get("CLOUD")),
            virtualization = get("VIRT")?.takeIf { it != "none" },
            firewall = get("FW"),
            memoryMb = get("MEM_KB")?.toLongOrNull()?.div(1024),
            freeDiskMb = get("DISK_KB")?.toLongOrNull()?.div(1024),
        )
    }

    /** Best-effort hosting/cloud name from DMI and cloud-init; null when it is a generic VM. */
    internal fun provider(vendor: String?, product: String?, cloudId: String?): String? {
        val all = listOfNotNull(vendor, product, cloudId).joinToString(" ").lowercase(Locale.ROOT)
        return when {
            "yandex" in all -> "Yandex Cloud"
            "amazon" in all || cloudId == "aws" -> "AWS"
            "google" in all || cloudId == "gce" -> "Google Cloud"
            "microsoft" in all || cloudId == "azure" -> "Azure"
            "oracle" in all || cloudId == "oracle" -> "Oracle Cloud"
            "digitalocean" in all -> "DigitalOcean"
            "hetzner" in all -> "Hetzner"
            "vultr" in all -> "Vultr"
            "selectel" in all -> "Selectel"
            "vk cloud" in all || "mcs" == cloudId -> "VK Cloud"
            "timeweb" in all -> "Timeweb Cloud"
            else -> null
        }
    }
}
