package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import org.junit.Assert.assertEquals
import org.junit.Test

class LocalDeletionPolicyTest {
    @Test
    fun `deleting web panel access produces only local deletion plan`() {
        val id = WebPanelAccessId("web-a")
        val plan = LocalDeletionPolicy.webPanelAccess(id)
        assertEquals(LocalDeletionPlan.DeleteWebPanelAccess(id), plan)
    }
}
