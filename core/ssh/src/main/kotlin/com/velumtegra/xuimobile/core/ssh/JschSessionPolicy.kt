package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.Session

/** Exact per-session policy. No global JSch defaults are trusted for security-sensitive choices. */
internal object JschPasswordSessionPolicy {
    fun applyTo(session: Session) {
        JschSessionSecurityPolicy.applyBase(session)
        session.setConfig("PreferredAuthentications", "password")
    }
}

/** Exact private-key-only authentication policy. It never falls back to password/interactive/agent auth. */
internal object JschPrivateKeySessionPolicy {
    fun applyTo(session: Session) {
        JschSessionSecurityPolicy.applyBase(session)
        session.setConfig("PreferredAuthentications", "publickey")
        session.setConfig("PubkeyAcceptedAlgorithms", VelumSshAlgorithmPolicy.userPublicKey.joinToString(","))
        // A different signature algorithm is not an excuse to wander outside the explicit allow-list.
        session.setConfig("try_additional_pubkey_algorithms", "no")
    }
}

private object JschSessionSecurityPolicy {
    fun applyBase(session: Session) {
        session.setConfig("StrictHostKeyChecking", "yes")
        session.setConfig("MaxAuthTries", "1")
        session.setConfig("kex", VelumSshAlgorithmPolicy.keyExchange.joinToString(","))
        session.setConfig("server_host_key", VelumSshAlgorithmPolicy.serverHostKey.joinToString(","))
        session.setConfig("cipher.c2s", VelumSshAlgorithmPolicy.ciphers.joinToString(","))
        session.setConfig("cipher.s2c", VelumSshAlgorithmPolicy.ciphers.joinToString(","))
        session.setConfig("mac.c2s", VelumSshAlgorithmPolicy.macs.joinToString(","))
        session.setConfig("mac.s2c", VelumSshAlgorithmPolicy.macs.joinToString(","))
        session.setConfig("compression.c2s", VelumSshAlgorithmPolicy.compression)
        session.setConfig("compression.s2c", VelumSshAlgorithmPolicy.compression)
        session.setConfig("enable_strict_kex", "yes")
        session.setDaemonThread(true)
        session.setServerAliveCountMax(0)
    }
}
