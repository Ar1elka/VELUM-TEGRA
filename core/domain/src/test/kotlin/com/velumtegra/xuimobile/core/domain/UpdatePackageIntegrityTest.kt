package com.velumtegra.xuimobile.core.domain

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.CancellationException
import org.junit.Assert.*
import org.junit.Test

class UpdatePackageIntegrityTest {
    private val bytes = "local reviewed package fixture".toByteArray()
    private fun digest(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it) }

    @Test fun exactBytesAreStreamedAndVerifiedWithoutAnArchiveExecutor() {
        val output = ByteArrayOutputStream()
        val result = UpdatePackageIntegrity.copyAndVerify(ByteArrayInputStream(bytes), output, digest(bytes))
        assertEquals(UpdatePackageIntegrityResult.Matched(bytes.size.toLong(), digest(bytes)), result)
        assertArrayEquals(bytes, output.toByteArray())
    }
    @Test fun differentBytesNeverProduceAValidReceipt() {
        assertEquals(UpdatePackageIntegrityResult.DigestMismatch,
            UpdatePackageIntegrity.copyAndVerify(ByteArrayInputStream(bytes + byteArrayOf(1)), ByteArrayOutputStream(), digest(bytes)))
    }
    @Test fun emptyInputIsRejectedEvenWhenItsDigestMatches() {
        assertEquals(UpdatePackageIntegrityResult.Empty,
            UpdatePackageIntegrity.copyAndVerify(ByteArrayInputStream(byteArrayOf()), ByteArrayOutputStream(), digest(byteArrayOf())))
    }
    @Test fun oversizedStreamNeverWritesPastTheBound() {
        val output = ByteArrayOutputStream()
        assertEquals(UpdatePackageIntegrityResult.TooLarge,
            UpdatePackageIntegrity.copyAndVerify(ByteArrayInputStream(bytes), output, digest(bytes), maxBytes = 8))
        assertTrue(output.size() <= 8)
    }
    @Test fun cancellationIsPropagatedBeforeAnyPayloadWrite() {
        val output = ByteArrayOutputStream()
        try {
            UpdatePackageIntegrity.copyAndVerify(ByteArrayInputStream(bytes), output, digest(bytes), checkActive = { throw CancellationException() })
            fail("Cancellation ignored")
        } catch (_: CancellationException) { assertEquals(0, output.size()) }
    }
    @Test fun readFailureIsNotConvertedIntoACompleteDigest() {
        val input = object : InputStream() {
            override fun read(): Int = throw IOException("fixture read failed")
        }
        try { UpdatePackageIntegrity.copyAndVerify(input, ByteArrayOutputStream(), digest(bytes)); fail("Failure ignored") }
        catch (_: IOException) { }
    }
    @Test fun zeroLengthBulkReadDoesNotInventEndOfFile() {
        val input = object : ByteArrayInputStream(bytes) {
            var first = true
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                if (first) { first = false; return 0 }
                return super.read(buffer, offset, length)
            }
        }
        val output = ByteArrayOutputStream()
        assertTrue(UpdatePackageIntegrity.copyAndVerify(input, output, digest(bytes)) is UpdatePackageIntegrityResult.Matched)
        assertArrayEquals(bytes, output.toByteArray())
    }
    @Test fun payloadIsReadInBoundedChunks() {
        val payload = ByteArray(1024 * 1024) { (it % 127).toByte() }
        var maxRead = 0
        val input = object : ByteArrayInputStream(payload) {
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                maxRead = maxOf(maxRead, length); return super.read(buffer, offset, length)
            }
        }
        assertTrue(UpdatePackageIntegrity.copyAndVerify(input, ByteArrayOutputStream(), digest(payload)) is UpdatePackageIntegrityResult.Matched)
        assertTrue(maxRead <= 64 * 1024)
    }
}
