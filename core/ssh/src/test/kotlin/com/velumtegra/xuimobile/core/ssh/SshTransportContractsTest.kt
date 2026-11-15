package com.velumtegra.xuimobile.core.ssh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Duration

class SshTransportContractsTest {
    @Test
    fun `remote command never exposes raw shell text through toString`() {
        val secretBearingCommand = RemoteCommand.create(
            raw = "echo super-secret-token",
            redactedLabel = "probe",
        )

        val rendered = secretBearingCommand.toString()
        assertTrue("probe" in rendered)
        assertTrue("[REDACTED]" in rendered)
        assertFalse("super-secret-token" in rendered)
    }

    @Test
    fun `captured output defensively copies input and output`() {
        val source = byteArrayOf(1, 2, 3)
        val captured = CapturedOutput.of(source, truncated = true)
        source[0] = 9

        val firstCopy = captured.copyBytes()
        assertArrayEquals(byteArrayOf(1, 2, 3), firstCopy)
        firstCopy[1] = 8
        assertArrayEquals(byteArrayOf(1, 2, 3), captured.copyBytes())
        assertTrue(captured.truncated)
        assertFalse(captured.toString().contains("1, 2, 3"))
    }

    @Test
    fun `timeouts and output caps are bounded`() {
        assertThrows(IllegalArgumentException::class.java) {
            SshTransportConfig(tcpConnectTimeout = Duration.ZERO)
        }
        assertThrows(IllegalArgumentException::class.java) {
            SshTransportConfig(commandExecutionTimeout = Duration.ofHours(1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            SshTransportConfig(stdoutCaptureLimitBytes = SshTransportConfig.MAX_CAPTURE_BYTES + 1)
        }
    }
}
