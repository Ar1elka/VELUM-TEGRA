package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.webpanel.WebPanelClientQuotaExpiryFailure
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LinkedWebPanelClientQuotaExpiryReadPolicyTest {
    @Test fun `TLS failure never offers insecure fallback`() {
        val message = LinkedWebPanelClientQuotaExpiryReadPolicy.message(WebPanelClientQuotaExpiryFailure.TLS_FAILURE)
        assertTrue(message.contains("TLS"))
        assertFalse(message.contains("игнорируйте"))
    }
    @Test fun `large and malformed responses are refused`() {
        assertTrue(LinkedWebPanelClientQuotaExpiryReadPolicy.message(WebPanelClientQuotaExpiryFailure.RESPONSE_TOO_LARGE).contains("слишком большой"))
        assertTrue(LinkedWebPanelClientQuotaExpiryReadPolicy.message(WebPanelClientQuotaExpiryFailure.PROTOCOL_INCOMPATIBLE).contains("не соответствует"))
    }
}
