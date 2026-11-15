package com.velumtegra.xuimobile.core.ssh

/**
 * Explicit VELUM//TEGRA allow-list for mwiede/JSch.
 *
 * Deliberately excludes every diffie-hellman-group-exchange-* variant while upstream issue #1089
 * remains open. Also excludes SHA-1 signatures/MACs, CBC/3DES, DSA, ssh-rsa/SHA-1 and algorithms
 * that currently need extra Android crypto-provider assumptions (for example Ed25519/Curve25519).
 */
object VelumSshAlgorithmPolicy {
    val keyExchange: List<String> = listOf(
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group14-sha256",
    )

    val serverHostKey: List<String> = listOf(
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
    )

    /** Allowed user public-key signature algorithms. SHA-1 ssh-rsa and DSA are intentionally absent. */
    val userPublicKey: List<String> = listOf(
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
    )

    val ciphers: List<String> = listOf(
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
    )

    val macs: List<String> = listOf(
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
    )

    const val compression: String = "none"
}
