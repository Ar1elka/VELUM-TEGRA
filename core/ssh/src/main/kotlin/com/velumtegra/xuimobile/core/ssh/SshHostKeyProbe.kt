package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.HostKey
import com.jcraft.jsch.HostKeyRepository
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.UserInfo
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible

/** A one-shot public-host-key observation; this is NOT identity verification or SSH authentication. */
sealed interface SshHostKeyObservation {
    data class Presented(val fingerprint: String, val algorithm: String) : SshHostKeyObservation
    data class Failed(val reason: Failure) : SshHostKeyObservation
    enum class Failure { INVALID_TARGET, DNS_OR_CONNECTION, TIMEOUT, NO_HOST_KEY, NEGOTIATION }
}

/** No password, private key, global known_hosts, accepted trust, or remote execution capability. */
interface SshHostKeyProbe {
    suspend fun observe(host: String, port: Int): SshHostKeyObservation
}

class JschSshHostKeyProbe : SshHostKeyProbe {
    override suspend fun observe(host: String, port: Int): SshHostKeyObservation {
        if (host.isEmpty() || host.length > 253 || !host.matches(Regex("[A-Za-z0-9.\\-:\\[\\]]+")) ||
            port !in 1..65535
        ) return SshHostKeyObservation.Failed(SshHostKeyObservation.Failure.INVALID_TARGET)
        val lookupHost = ExactPinnedHostKeyRepository.lookupHost(host, port)
        val rejectingRepository = ObserveAndRejectHostKeyRepository(lookupHost)
        var session: Session? = null
        return try {
            val jsch = JSch().apply { setHostKeyRepository(rejectingRepository) }
            val probeSession = jsch.getSession("velum-public-hostkey-probe", host, port)
            session = probeSession
            probeSession.setHostKeyRepository(rejectingRepository)
            probeSession.setSocketFactory(BoundedSocketFactory(4_000))
            probeSession.setConfig("StrictHostKeyChecking", "yes")
            probeSession.setConfig("PreferredAuthentications", "none")
            // Observe the same host-key type the real login will negotiate. Without this JSch's default
            // prefers ssh-ed25519, the user pins that fingerprint, and the policy-restricted login (which
            // presents ECDSA/RSA) then fails with a host identity mismatch.
            probeSession.setConfig("server_host_key", VelumSshAlgorithmPolicy.serverHostKey.joinToString(","))
            // check() always rejects; connect must never authenticate, open a channel, or succeed.
            runInterruptible(Dispatchers.IO) { probeSession.connect(8_000) }
            SshHostKeyObservation.Failed(SshHostKeyObservation.Failure.NO_HOST_KEY)
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (failure: Exception) {
            rejectingRepository.observed() ?: run {
                val chain = generateSequence(failure as Throwable) { it.cause }.toList()
                val kind = when {
                    chain.any { it is SocketTimeoutException } -> SshHostKeyObservation.Failure.TIMEOUT
                    chain.any { it is UnknownHostException || it is java.net.ConnectException || it is java.net.NoRouteToHostException } ->
                        SshHostKeyObservation.Failure.DNS_OR_CONNECTION
                    else -> SshHostKeyObservation.Failure.NEGOTIATION
                }
                SshHostKeyObservation.Failed(kind)
            }
        } finally {
            runCatching { session?.disconnect() }
        }
    }
}

/** Deliberately rejects every key: presenting a key is not an act of trust. */
internal class ObserveAndRejectHostKeyRepository(private val expectedLookupHost: String) : HostKeyRepository {
    private val first = AtomicReference<SshHostKeyObservation.Presented?>(null)
    override fun check(host: String, key: ByteArray): Int {
        if (host == expectedLookupHost && key.isNotEmpty()) {
            val observed = runCatching {
                SshHostKeyObservation.Presented(
                    CanonicalHostKeyFingerprint.fromRawHostKey(key).asString(),
                    HostKey(host, key).type,
                )
            }.getOrNull()
            if (observed != null) first.compareAndSet(null, observed)
        }
        return HostKeyRepository.CHANGED // No TOFU; no auth even if key is seen.
    }
    fun observed(): SshHostKeyObservation.Presented? = first.get()
    override fun add(hostkey: HostKey, ui: UserInfo?) = error("Host-key probe may not mutate trust")
    override fun remove(host: String, type: String) = error("Host-key probe may not mutate trust")
    override fun remove(host: String, type: String, key: ByteArray?) = error("Host-key probe may not mutate trust")
    override fun getKnownHostsRepositoryID(): String = "VELUM host-key observation (untrusted)"
    override fun getHostKey(): Array<HostKey> = emptyArray()
    override fun getHostKey(host: String?, type: String?): Array<HostKey> = emptyArray()
}
