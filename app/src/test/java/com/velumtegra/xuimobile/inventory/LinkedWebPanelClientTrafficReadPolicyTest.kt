package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.webpanel.WebPanelClientTrafficFailure
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LinkedWebPanelClientTrafficReadPolicyTest {
    @Test fun `TLS failure must not offer insecure fallback`() {
        val text = LinkedWebPanelClientTrafficReadPolicy.message(WebPanelClientTrafficFailure.TLS_FAILURE)
        assertTrue(text.contains("TLS"))
        assertFalse(text.contains("игнорируйте"))
    }
    @Test fun `bounded response and malformed payload are refused`() {
        assertTrue(LinkedWebPanelClientTrafficReadPolicy.message(WebPanelClientTrafficFailure.RESPONSE_TOO_LARGE)
            .contains("слишком большой"))
        assertTrue(LinkedWebPanelClientTrafficReadPolicy.message(WebPanelClientTrafficFailure.PROTOCOL_INCOMPATIBLE)
            .contains("не соответствует"))
    }
}
