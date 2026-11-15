package com.velumtegra.xuimobile.enrollment

import com.velumtegra.xuimobile.core.ssh.JschSshHostKeyProbe
import com.velumtegra.xuimobile.core.ssh.SshHostKeyObservation
import com.velumtegra.xuimobile.core.ssh.SshHostKeyProbe

sealed interface HostKeyDiscoveryResult {
    /** Untrusted information learned from the addressed network peer, NOT a verified identity. */
    data class Unverified(val host: String, val port: String, val sha256: String, val algorithm: String) : HostKeyDiscoveryResult
    data class Failure(val message: String) : HostKeyDiscoveryResult
}

interface ServerHostKeyDiscoveryPort {
    suspend fun discover(host: String, port: String): HostKeyDiscoveryResult
}

/** The only network-capable enrollment adapter; it has no access to secrets or persistence. */
class JschServerHostKeyDiscoveryPort(
    private val probe: SshHostKeyProbe = JschSshHostKeyProbe(),
) : ServerHostKeyDiscoveryPort {
    override suspend fun discover(host: String, port: String): HostKeyDiscoveryResult {
        EnrollmentInputPolicy.validateHostAndPort(host, port)?.let { return HostKeyDiscoveryResult.Failure(it) }
        val result = probe.observe(host, requireNotNull(port.toIntOrNull()))
        return when (result) {
            is SshHostKeyObservation.Presented -> HostKeyDiscoveryResult.Unverified(host, port, result.fingerprint, result.algorithm)
            is SshHostKeyObservation.Failed -> HostKeyDiscoveryResult.Failure(when (result.reason) {
                SshHostKeyObservation.Failure.INVALID_TARGET -> "Недопустимый SSH-адрес или порт."
                SshHostKeyObservation.Failure.DNS_OR_CONNECTION -> "Не удалось установить соединение с этим адресом и портом."
                SshHostKeyObservation.Failure.TIMEOUT -> "SSH-сервер не ответил вовремя. Проверьте сеть и порт."
                SshHostKeyObservation.Failure.NO_HOST_KEY -> "Сервер не представил SSH host key."
                SshHostKeyObservation.Failure.NEGOTIATION -> "Не удалось получить SSH host key: проверьте, что это SSH-порт и алгоритмы совместимы."
            })
        }
    }
}
