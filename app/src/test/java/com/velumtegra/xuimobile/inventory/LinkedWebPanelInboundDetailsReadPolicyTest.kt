package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.webpanel.WebPanelInboundDetailsFailure
import org.junit.Assert.assertTrue
import org.junit.Test

class LinkedWebPanelInboundDetailsReadPolicyTest {
    @Test fun `transport errors never include endpoint or credentials`() {
        WebPanelInboundDetailsFailure.entries.forEach { failure ->
            val message = LinkedWebPanelInboundDetailsReadPolicy.message(failure)
            assertTrue(message.isNotBlank())
            assertTrue(!message.contains("password", ignoreCase = true))
            assertTrue(!message.contains("uuid", ignoreCase = true))
            assertTrue(!message.contains("https://"))
        }
    }
}
