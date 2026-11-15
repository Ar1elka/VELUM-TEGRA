package com.velumtegra.xuimobile.core.model

data class SshEndpoint(
    val host: String,
    val port: Int,
) {
    init {
        require(host.isNotBlank()) { "SSH host must not be blank" }
        require(port in 1..65535) { "SSH port must be in 1..65535" }
    }
}

@JvmInline
value class HostKeyFingerprint(val value: String) {
    init {
        require(value.isNotBlank()) { "Host-key fingerprint must not be blank" }
    }
}

sealed interface SshAuthRef {
    val secretId: SecretId

    data class Password(override val secretId: SecretId) : SshAuthRef
    data class PrivateKey(override val secretId: SecretId) : SshAuthRef
}

/** Exact SSH access method for one Server. Secret material is referenced, never embedded. */
data class ServerAccess(
    val id: ServerAccessId,
    val serverId: ServerId,
    val endpoint: SshEndpoint,
    val username: String,
    val auth: SshAuthRef,
    val pinnedHostKey: HostKeyFingerprint,
) {
    init {
        require(username.isNotBlank()) { "SSH username must not be blank" }
    }
}
