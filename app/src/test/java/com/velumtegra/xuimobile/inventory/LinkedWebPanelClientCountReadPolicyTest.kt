package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.webpanel.WebPanelClientCountFailure
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LinkedWebPanelClientCountReadPolicyTest {
    @Test fun `never suggest bypassing HTTPS checks`() {
        val text = LinkedWebPanelClientCountReadPolicy.message(WebPanelClientCountFailure.TLS_FAILURE)
        assertTrue(text.contains("TLS"))
        assertFalse(text.contains("игнорируйте"))
    }
    @Test fun `oversized response blocks secret exposure`() {
        assertTrue(LinkedWebPanelClientCountReadPolicy.message(WebPanelClientCountFailure.RESPONSE_TOO_LARGE)
            .contains("слишком большой"))
    }
}
