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

class XuiReadOnlyServiceStateProbeTest {
    private class Fake(private val text: String, private val truncated: Boolean = false,
        private val state: CommandCompletion = CommandCompletion.ConfirmedSuccess
    ) : SshSessionHandle {
        var calls = 0
        var command = ""
        override val binding = SessionBinding(SessionId("fake-session"), ServerAccessId("fake-access"),
            SessionOwner.Operation(OperationId("fake-operation")))
        override val isOpen = true
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            calls++
            this.command = command.rawForTransport()
            assertTrue(config.stdoutCaptureLimitBytes <= 128)
            assertTrue(config.commandExecutionTimeout.seconds <= 12)
            return SshCommandResult(CommandDispatchState.DISPATCHED, state,
                CapturedOutput.of(text.toByteArray(Charsets.UTF_8), truncated), CapturedOutput.EMPTY)
        }
        override fun close() = Unit
    }

    @Test fun exactlyOneFixedReadOnlyCommandAndNormalizedActiveState() = runBlocking {
        val fake = Fake("active\n")
        assertEquals(XuiServiceProbeOutcome.Observed(XuiObservedServiceState.ACTIVE),
            XuiReadOnlyServiceStateProbe.inspect(fake, "x-ui.service"))
        assertEquals(1, fake.calls)
        assertEquals("systemctl show --property=ActiveState --value -- x-ui.service", fake.command)
    }

    @Test fun maliciousServiceUnitDoesNotDispatchAnyCommand() = runBlocking {
        val fake = Fake("active\n")
        assertEquals(XuiServiceProbeOutcome.Unavailable,
            XuiReadOnlyServiceStateProbe.inspect(fake, "x-ui.service; shutdown -h now"))
        assertEquals(0, fake.calls)
    }

    @Test fun malformedTruncatedAndFailedOutputNeverConfirmsServiceState() = runBlocking {
        listOf(Fake("active\nfailed\n"), Fake("active\n", truncated = true),
            Fake("active\n", state = CommandCompletion.ConfirmedFailure("denied", 1)))
            .forEach { fake ->
                assertEquals(XuiServiceProbeOutcome.Unavailable,
                    XuiReadOnlyServiceStateProbe.inspect(fake, "x-ui.service"))
                assertEquals(1, fake.calls)
            }
    }
}
