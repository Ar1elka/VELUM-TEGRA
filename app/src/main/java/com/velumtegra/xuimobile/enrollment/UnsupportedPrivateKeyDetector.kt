package com.velumtegra.xuimobile.enrollment

/**
 * Recognises private-key types that the pinned SSH client policy (`VelumSshAlgorithmPolicy`) can never
 * authenticate with, so the user gets a clear message at import time instead of a generic
 * "server rejected SSH authentication" later.
 *
 * Only the public part of the key is inspected (the OpenSSH container keeps it unencrypted even for
 * passphrase-protected keys). The secret part is never decoded. Anything that cannot be classified is
 * reported as "unknown" and left to the normal flow, so this check can only add clarity, never block a
 * key that could work.
 */
internal object UnsupportedPrivateKeyDetector {
    private const val ED25519_ADVICE =
        "Ключи Ed25519 пока не поддерживаются: приложение принимает ключи ECDSA и RSA. " +
            "Создайте такой ключ командой ssh-keygen -t ecdsa -b 256, добавьте открытую часть на сервер " +
            "и выберите новый файл."
    private const val DSA_ADVICE =
        "Ключи DSA считаются небезопасными и не поддерживаются. Используйте ключ ECDSA или RSA " +
            "(например, ssh-keygen -t ecdsa -b 256)."
    private const val HARDWARE_ADVICE =
        "Ключи, привязанные к аппаратному токену (sk-…), на телефоне не поддерживаются. " +
            "Используйте обычный ключ ECDSA или RSA."

    private val OPENSSH_MAGIC = "openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII)

    /** Returns a user-facing explanation when the key is of a known unsupported type, otherwise null. */
    fun explain(document: ByteArray): String? {
        val text = document.toString(Charsets.ISO_8859_1)
        return when {
            text.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----") ->
                openSshKeyType(decodeBody(text, "OPENSSH PRIVATE KEY"))?.let(::adviceForType)
            text.startsWith("-----BEGIN DSA PRIVATE KEY-----") -> DSA_ADVICE
            text.startsWith("-----BEGIN PRIVATE KEY-----") ->
                if (isPkcs8Ed25519(decodeBody(text, "PRIVATE KEY"))) ED25519_ADVICE else null
            else -> null
        }
    }

    private fun adviceForType(type: String): String? = when {
        type == "ssh-ed25519" -> ED25519_ADVICE
        type == "ssh-dss" -> DSA_ADVICE
        type.startsWith("sk-") -> HARDWARE_ADVICE
        else -> null
    }

    /** Reads the key type from the unencrypted public-key blob of an OpenSSH private key container. */
    private fun openSshKeyType(body: ByteArray?): String? {
        if (body == null || body.size < OPENSSH_MAGIC.size) return null
        for (i in OPENSSH_MAGIC.indices) if (body[i] != OPENSSH_MAGIC[i]) return null
        val reader = Reader(body, OPENSSH_MAGIC.size)
        reader.string() ?: return null // cipher name
        reader.string() ?: return null // kdf name
        reader.string() ?: return null // kdf options
        val keyCount = reader.uint32() ?: return null
        if (keyCount < 1L) return null
        val publicBlob = reader.string() ?: return null
        val type = Reader(publicBlob, 0).string() ?: return null
        return type.toString(Charsets.US_ASCII).takeIf { it.length in 1..64 && it.all { c -> c in ' '..'~' } }
    }

    /** PKCS#8 PrivateKeyInfo carrying the Ed25519 algorithm identifier (OID 1.3.101.112). */
    private fun isPkcs8Ed25519(der: ByteArray?): Boolean {
        if (der == null || der.size < 16) return false
        val oid = byteArrayOf(0x06, 0x03, 0x2B, 0x65, 0x70)
        val limit = minOf(der.size - oid.size, 16)
        return (0..limit).any { start -> oid.indices.all { der[start + it] == oid[it] } }
    }

    private fun decodeBody(text: String, kind: String): ByteArray? {
        val begin = "-----BEGIN $kind-----"
        val end = "-----END $kind-----"
        val from = text.indexOf(begin).takeIf { it >= 0 }?.plus(begin.length) ?: return null
        val to = text.indexOf(end, from).takeIf { it >= 0 } ?: return null
        return decodeBase64(text.substring(from, to))
    }

    /** Tiny tolerant Base64 decoder; avoids java.util.Base64, which needs API 26 on minSdk 24. */
    private fun decodeBase64(input: String): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        var buffer = 0
        var bits = 0
        for (c in input) {
            if (c == '=' || c == ' ' || c == '\n' || c == '\r' || c == '\t') continue
            val v = when (c) {
                in 'A'..'Z' -> c - 'A'
                in 'a'..'z' -> c - 'a' + 26
                in '0'..'9' -> c - '0' + 52
                '+' -> 62
                '/' -> 63
                else -> return null
            }
            buffer = (buffer shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((buffer shr bits) and 0xFF)
            }
        }
        return out.toByteArray()
    }

    private class Reader(private val data: ByteArray, private var pos: Int) {
        fun uint32(): Long? {
            if (pos + 4 > data.size) return null
            var v = 0L
            repeat(4) { v = (v shl 8) or (data[pos + it].toLong() and 0xFF) }
            pos += 4
            return v
        }

        fun string(): ByteArray? {
            val len = uint32() ?: return null
            if (len < 0 || len > data.size - pos) return null
            val bytes = data.copyOfRange(pos, pos + len.toInt())
            pos += len.toInt()
            return bytes
        }
    }
}
