package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionOwnershipPolicyTest {
    @Test
    fun `management cannot borrow foreign operation session`() {
        val access = ServerAccessId("access-a")
        val session = SessionBinding(
            sessionId = SessionId("session-a"),
            serverAccessId = access,
            owner = SessionOwner.Operation(OperationId("operation-a")),
        )
        val managementOwner = SessionOwner.Management(XuiInstallationId("xui-a"), access)

        assertFalse(SessionOwnershipPolicy.matches(session, managementOwner, access))
    }

    @Test
    fun `same owner on wrong access path is rejected`() {
        val requiredAccess = ServerAccessId("access-a")
        val owner = SessionOwner.Management(XuiInstallationId("xui-a"), requiredAccess)
        val session = SessionBinding(
            sessionId = SessionId("session-a"),
            serverAccessId = ServerAccessId("access-b"),
            owner = owner,
        )

        assertFalse(SessionOwnershipPolicy.matches(session, owner, requiredAccess))
    }

    @Test
    fun `exact owner and access match`() {
        val access = ServerAccessId("access-a")
        val owner = SessionOwner.Management(XuiInstallationId("xui-a"), access)
        val session = SessionBinding(SessionId("session-a"), access, owner)

        assertTrue(SessionOwnershipPolicy.matches(session, owner, access))
    }
}
