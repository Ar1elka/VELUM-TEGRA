package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class XuiReadOnlyVersionProbeTest {
    private class Fake(
        private val output: String,
        private val truncated: Boolean = false,
        private val completion: CommandCompletion = CommandCompletion.ConfirmedSuccess,
        private val stderr: String = "",
    ) : SshSessionHandle {
        var calls = 0
        var raw = ""
        override val binding = SessionBinding(SessionId("fake"), ServerAccessId("access"),
            SessionOwner.Operation(OperationId("operation")))
        override val isOpen = true
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            calls++
            raw = command.rawForTransport()
            assertTrue(config.stdoutCaptureLimitBytes <= 96)
            assertTrue(config.commandExecutionTimeout.seconds <= 12)
            return SshCommandResult(CommandDispatchState.DISPATCHED, completion,
                CapturedOutput.of(output.toByteArray(Charsets.UTF_8), truncated),
                CapturedOutput.of(stderr.toByteArray(Charsets.UTF_8), truncated = false))
        }
        override fun close() = Unit
    }

    @Test fun versionReadUsesOneFixedReviewedBinaryCommand() = runBlocking {
        val fake = Fake("v3.7.0\n")
        assertEquals(XuiVersionProbeOutcome.Observed("v3.7.0"),
            XuiReadOnlyVersionProbe.inspect(fake, "/usr/local/x-ui/x-ui"))
        assertEquals(1, fake.calls)
        assertEquals("'/usr/local/x-ui/x-ui' -v", fake.raw)
    }

    @Test fun alternateApprovedBinaryCannotChangeCommandShape() = runBlocking {
        val fake = Fake("2.6.6\r\n")
        assertEquals(XuiVersionProbeOutcome.Observed("2.6.6"),
            XuiReadOnlyVersionProbe.inspect(fake, "/opt/x-ui/x-ui"))
        assertEquals("'/opt/x-ui/x-ui' -v", fake.raw)
    }

    @Test fun pathInjectionFailsBeforeNetwork() = runBlocking {
        val fake = Fake("v3.7.0\n")
        for (path in listOf("/opt/x-ui/x-ui; reboot", "/tmp/x-ui", "/usr/local/x-ui/../x-ui")) {
            assertEquals(XuiVersionProbeOutcome.Unavailable, XuiReadOnlyVersionProbe.inspect(fake, path))
        }
        assertEquals(0, fake.calls)
    }

    @Test fun bannersCredentialsErrorsAndTruncationAreNeverPresentedAsVersion() = runBlocking {
        val bad = listOf(
            Fake("password=secret"), Fake("https://panel.example.org/secret"),
            Fake("v3.7.0\nadmin:token"), Fake("v3.7.0\n\n"),
            Fake("v3.7.0\n", truncated = true), Fake("v3.7.0\n", stderr = "secret"),
            Fake("v3.7.0\n", completion = CommandCompletion.ConfirmedFailure("denied", 1)),
        )
        bad.forEach { fake ->
            assertEquals(XuiVersionProbeOutcome.Unavailable,
                XuiReadOnlyVersionProbe.inspect(fake, "/usr/local/x-ui/x-ui"))
            assertEquals(1, fake.calls)
        }
    }
}
