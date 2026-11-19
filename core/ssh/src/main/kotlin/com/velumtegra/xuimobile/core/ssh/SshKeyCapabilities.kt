package com.velumtegra.xuimobile.core.ssh

/**
 * Runtime capability probe for user-key types. Ed25519 needs BouncyCastle's lightweight
 * `Ed25519Signer` and RFC 8032 math classes. On some older Android releases a platform copy of
 * `org.bouncycastle` on the boot classpath can win over the app's copy and lack them; the probe then
 * answers "not supported" and callers must explain that instead of failing at login.
 */
object SshKeyCapabilities {
    private val REQUIRED_CLASSES = listOf(
        "org.bouncycastle.crypto.signers.Ed25519Signer",
        "org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters",
        "org.bouncycastle.math.ec.rfc8032.Ed25519",
    )

    val ed25519UserKeys: Boolean by lazy { classesPresent(REQUIRED_CLASSES) }

    internal fun classesPresent(names: List<String>): Boolean = names.all { name ->
        try {
            Class.forName(name, false, SshKeyCapabilities::class.java.classLoader)
            true
        } catch (_: Throwable) {
            false
        }
    }
}
