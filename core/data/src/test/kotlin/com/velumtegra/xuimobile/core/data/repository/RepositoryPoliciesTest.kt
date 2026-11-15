package com.velumtegra.xuimobile.core.data.repository

import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.model.ServerId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RepositoryPoliciesTest {
    @Test
    fun `record revision increments monotonically`() {
        val result = RecordRevision(7).nextRevision()
        assertEquals(RecordRevision(8), (result as RevisionAdvance.Success).value)
    }

    @Test
    fun `record revision never wraps through Long overflow`() {
        assertEquals(RevisionAdvance.Exhausted, RecordRevision(Long.MAX_VALUE).nextRevision())
    }

    @Test
    fun `operation revision never wraps through Long overflow`() {
        assertEquals(RevisionAdvance.Exhausted, OperationRevision(Long.MAX_VALUE).nextRevision())
    }

    @Test
    fun `standalone direct panel remains unbound`() {
        val result = resolveBoundServer(
            installationRequired = false,
            installationServerId = null,
            routeAccessRequired = false,
            routeServerId = null,
        )
        assertEquals(BoundServerResolution.Success(null), result)
    }

    @Test
    fun `standalone ssh panel binds exact route server`() {
        val serverId = ServerId("server-a")
        val result = resolveBoundServer(
            installationRequired = false,
            installationServerId = null,
            routeAccessRequired = true,
            routeServerId = serverId,
        )
        assertEquals(BoundServerResolution.Success(serverId), result)
    }

    @Test
    fun `linked tunnel panel rejects cross server relation`() {
        val result = resolveBoundServer(
            installationRequired = true,
            installationServerId = ServerId("server-a"),
            routeAccessRequired = true,
            routeServerId = ServerId("server-b"),
        )
        assertTrue(result is BoundServerResolution.CrossServer)
    }

    @Test
    fun `required missing relation cannot degrade to standalone`() {
        val result = resolveBoundServer(
            installationRequired = true,
            installationServerId = null,
            routeAccessRequired = false,
            routeServerId = null,
        )
        assertTrue(result is BoundServerResolution.MissingReference)
    }
}
