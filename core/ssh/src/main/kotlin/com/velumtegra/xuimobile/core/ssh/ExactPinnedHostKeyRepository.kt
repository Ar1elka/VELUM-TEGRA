package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.HostKey
import com.jcraft.jsch.HostKeyRepository
import com.jcraft.jsch.UserInfo

/**
 * Per-attempt, immutable-from-the-caller's-view exact host-key repository.
 *
 * It never consults or mutates global/system known_hosts and never learns a first-seen key. Before
 * JSch has proved the peer key against the configured fingerprint, host-key enumeration is empty so
 * the repository cannot influence algorithm ordering. After an exact [check] match, only the raw key
 * that just matched the exact host + exact fingerprint is exposed back to JSch. This satisfies JSch's
 * post-check HostKeyRepository contract without broadening trust.
 */
internal class ExactPinnedHostKeyRepository(
    private val expectedLookupHost: String,
    private val expectedFingerprint: CanonicalHostKeyFingerprint,
) : HostKeyRepository {
    @Volatile
    private var lastPresented: CanonicalHostKeyFingerprint? = null

    @Volatile
    private var mismatchObserved: Boolean = false

    @Volatile
    private var acceptedRawHostKey: ByteArray? = null

    override fun check(host: String, key: ByteArray): Int {
        // A later check must never inherit an earlier accepted raw key (for example during re-key).
        acceptedRawHostKey = null

        val presented = CanonicalHostKeyFingerprint.fromRawHostKey(key)
        lastPresented = presented
        val exactHost = host == expectedLookupHost
        val exactKey = expectedFingerprint.matchesRawHostKey(key)
        return if (exactHost && exactKey) {
            // Snapshot the exact key JSch presented. Never retain its mutable input array directly.
            acceptedRawHostKey = key.copyOf()
            HostKeyRepository.OK
        } else {
            mismatchObserved = true
            HostKeyRepository.CHANGED
        }
    }

    fun didObserveMismatch(): Boolean = mismatchObserved

    fun presentedFingerprintOrNull(): String? = lastPresented?.asString()

    override fun add(hostkey: HostKey, ui: UserInfo?) {
        error("Exact pinned host-key repository is immutable")
    }

    override fun remove(host: String, type: String) {
        error("Exact pinned host-key repository is immutable")
    }

    override fun remove(host: String, type: String, key: ByteArray?) {
        error("Exact pinned host-key repository is immutable")
    }

    override fun getKnownHostsRepositoryID(): String = "VELUM//TEGRA exact pin"

    /**
     * Never expose a broad pre-existing host-key catalog. An empty array is intentional: JSch treats
     * it as "no known keys for reordering" while avoiding its null-unsafe post-check path.
     */
    override fun getHostKey(): Array<HostKey> = emptyArray()

    /**
     * Before [check] succeeds this is empty, so no key can be trusted or used for reordering. After
     * an exact match, JSch may ask for the accepted key again to inspect markers; return only that
     * one exact key and only for the exact lookup host.
     */
    override fun getHostKey(host: String?, type: String?): Array<HostKey> {
        if (host != expectedLookupHost) return emptyArray()
        val raw = acceptedRawHostKey?.copyOf() ?: return emptyArray()
        return arrayOf(HostKey(expectedLookupHost, raw))
    }

    companion object {
        fun lookupHost(host: String, port: Int): String = if (port == 22) host else "[$host]:$port"
    }
}
