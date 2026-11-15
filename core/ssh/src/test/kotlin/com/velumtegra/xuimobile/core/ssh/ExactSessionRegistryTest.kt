package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ExactSessionRegistryTest {
    @Test
    fun `foreign owner and wrong access are misses`() {
        val registry = ExactSessionRegistry()
        val accessA = ServerAccessId("access-a")
        val owner = SessionOwner.Operation(OperationId("op-a"))
        val handle = FakeHandle(SessionBinding(SessionId("s-a"), accessA, owner))
        registry.install(handle)

        assertSame(handle, registry.find(owner, accessA))
        assertNull(registry.find(owner, ServerAccessId("access-b")))
        assertNull(
            registry.find(
                SessionOwner.Management(XuiInstallationId("xui-a"), accessA),
                accessA,
            ),
        )
    }

    @Test
    fun `replacement closes prior and stale removal cannot remove replacement`() {
        val registry = ExactSessionRegistry()
        val access = ServerAccessId("access-a")
        val owner = SessionOwner.Operation(OperationId("op-a"))
        val first = FakeHandle(SessionBinding(SessionId("s-1"), access, owner))
        val second = FakeHandle(SessionBinding(SessionId("s-2"), access, owner))

        assertEquals(SessionInstallResult.Installed, registry.install(first))
        assertEquals(SessionInstallResult.Replaced(SessionId("s-1")), registry.install(second))
        assertTrue(first.closed)
        assertFalse(second.closed)

        assertFalse(registry.remove(owner, access, SessionId("s-1")))
        assertSame(second, registry.find(owner, access))
        assertTrue(registry.remove(owner, access, SessionId("s-2")))
        assertTrue(second.closed)
        assertEquals(0, registry.size())
    }


    @Test
    fun `same SessionId on a different handle is rejected and newcomer is closed`() {
        val registry = ExactSessionRegistry()
        val access = ServerAccessId("access-a")
        val owner = SessionOwner.Operation(OperationId("op-a"))
        val first = FakeHandle(SessionBinding(SessionId("same-id"), access, owner))
        val collision = FakeHandle(SessionBinding(SessionId("same-id"), access, owner))

        assertEquals(SessionInstallResult.Installed, registry.install(first))
        assertEquals(
            SessionInstallResult.SessionIdCollisionRejected(SessionId("same-id")),
            registry.install(collision),
        )
        assertFalse(first.closed)
        assertTrue(collision.closed)
        assertSame(first, registry.find(owner, access))
    }

    @Test
    fun `closed exact session is pruned and returned as a miss`() {
        val registry = ExactSessionRegistry()
        val access = ServerAccessId("access-a")
        val owner = SessionOwner.Operation(OperationId("op-a"))
        val handle = FakeHandle(SessionBinding(SessionId("s-a"), access, owner))
        registry.install(handle)
        handle.close()

        assertNull(registry.find(owner, access))
        assertEquals(0, registry.size())
    }

    private class FakeHandle(
        override val binding: SessionBinding,
    ) : SshSessionHandle {
        var closed: Boolean = false

        override val isOpen: Boolean
            get() = !closed

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult =
            SshCommandResult(
                dispatchState = CommandDispatchState.NOT_DISPATCHED,
                completion = CommandCompletion.Unknown("fake"),
                stdout = CapturedOutput.EMPTY,
                stderr = CapturedOutput.EMPTY,
            )

        override fun close() {
            closed = true
        }
    }
}
