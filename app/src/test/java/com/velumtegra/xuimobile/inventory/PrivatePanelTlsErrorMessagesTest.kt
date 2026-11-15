package com.velumtegra.xuimobile.inventory

import android.net.http.SslError
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** TLS diagnostic feedback never permits insecure SSL bypass. */
class PrivatePanelTlsErrorMessagesTest {
    @Test fun `untrusted self signed certificate remains blocked`() {
        val message = privatePanelTlsErrorMessage(SslError.SSL_UNTRUSTED)
        assertTrue(message.contains("самоподписанный"))
        assertTrue(message.contains("заблокирован"))
        assertFalse(message.contains("Продолжить без проверки"))
    }

    @Test fun `hostname mismatch is distinct from untrusted issuer`() {
        val message = privatePanelTlsErrorMessage(SslError.SSL_IDMISMATCH)
        assertTrue(message.contains("SAN"))
        assertTrue(message.contains("заблокирован"))
    }

    @Test fun `unknown TLS failures also reject`() {
        assertTrue(privatePanelTlsErrorMessage(-999).contains("заблокирован"))
    }
}
