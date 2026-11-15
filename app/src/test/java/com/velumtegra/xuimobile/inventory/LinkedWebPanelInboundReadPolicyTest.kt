package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.webpanel.WebPanelInboundReadFailure
import org.junit.Assert.assertTrue
import org.junit.Test

class LinkedWebPanelInboundReadPolicyTest {
    @Test fun `TLS errors never propose bypass`() {
        val message = LinkedWebPanelInboundReadPolicy.message(WebPanelInboundReadFailure.TLS_FAILURE)
        assertTrue(message.contains("TLS"))
        assertTrue(!message.contains("пропустите"))
    }
    @Test fun `oversized responses fail closed`() {
        val message = LinkedWebPanelInboundReadPolicy.message(WebPanelInboundReadFailure.RESPONSE_TOO_LARGE)
        assertTrue(message.contains("слишком большой"))
    }
}
