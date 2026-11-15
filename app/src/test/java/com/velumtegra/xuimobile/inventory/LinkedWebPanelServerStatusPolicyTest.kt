package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.webpanel.WebPanelServerStatusFailure
import org.junit.Assert.assertTrue
import org.junit.Test

class LinkedWebPanelServerStatusPolicyTest {
    @Test fun `TLS failure does not suggest disabling certificate checks`() {
        val message = LinkedWebPanelServerStatusReadPolicy.message(WebPanelServerStatusFailure.TLS_FAILURE)
        assertTrue(message.contains("TLS"))
        assertTrue(message.contains("не игнорируется"))
    }
    @Test fun `response bounds are visible`() {
        val message = LinkedWebPanelServerStatusReadPolicy.message(WebPanelServerStatusFailure.RESPONSE_TOO_LARGE)
        assertTrue(message.contains("слишком большой"))
    }
}
