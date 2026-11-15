package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.UpdatePackageReceipt
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.Arrays

sealed interface UpdatePackageIntegrityResult {
    data class Matched(val sizeBytes: Long, val sha256: String) : UpdatePackageIntegrityResult
    data object Empty : UpdatePackageIntegrityResult
    data object TooLarge : UpdatePackageIntegrityResult
    data object DigestMismatch : UpdatePackageIntegrityResult
}

/** Bounded streaming only: no archive extraction, shell, remote action or whole-file allocation. */
object UpdatePackageIntegrity {
    fun copyAndVerify(input: InputStream, output: OutputStream, expectedSha256: String,
        maxBytes: Long = UpdatePackageReceipt.MAX_BYTES, checkActive: () -> Unit = {}): UpdatePackageIntegrityResult {
        require(Regex("[0-9a-f]{64}").matches(expectedSha256))
        require(maxBytes in 1..UpdatePackageReceipt.MAX_BYTES)
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        try {
            while (true) {
                checkActive()
                var count = input.read(buffer)
                if (count < 0) break
                if (count == 0) {
                    val single = input.read()
                    if (single < 0) break
                    buffer[0] = single.toByte(); count = 1
                }
                if (count > maxBytes - total) return UpdatePackageIntegrityResult.TooLarge
                output.write(buffer, 0, count); digest.update(buffer, 0, count); total += count
            }
            checkActive()
            if (total == 0L) return UpdatePackageIntegrityResult.Empty
            val actual = digest.digest().joinToString("") { "%02x".format(it) }
            if (actual != expectedSha256) return UpdatePackageIntegrityResult.DigestMismatch
            output.flush()
            return UpdatePackageIntegrityResult.Matched(total, actual)
        } finally { Arrays.fill(buffer, 0) }
    }
}
