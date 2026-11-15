package com.velumtegra.xuimobile.inventory

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class PrivatePanelCertificateTrustPolicyTest {
    private val first = "A".repeat(64)
    private val second = "B".repeat(64)

    @Test fun `first use always requires explicit confirmation`() {
        assertEquals(CertificatePinDecision.FIRST_USE, certificatePinDecision(null, first))
    }
    @Test fun `only exact SHA256 fingerprint can be reused`() {
        assertEquals(CertificatePinDecision.MATCH, certificatePinDecision(first, first))
        assertEquals(CertificatePinDecision.CHANGED, certificatePinDecision(first, second))
        assertEquals(CertificatePinDecision.INVALID, certificatePinDecision(first, ""))
        assertEquals(CertificatePinDecision.INVALID, certificatePinDecision(first, "untrusted"))
        assertEquals(CertificatePinDecision.INVALID, certificatePinDecision("broken", first))
    }
    @Test fun `trust is scoped to exact saved SSH identity target path and protocol`() {
        val expected = panelCertificateTrustScope("panel", "ssh", "127.0.0.1", 40916, "/private/", "HTTPS")
        assertEquals(expected, panelCertificateTrustScope("panel", "ssh", "127.0.0.1", 40916, "/private/", "HTTPS"))
        assertNotEquals(expected, panelCertificateTrustScope("panel", "ssh2", "127.0.0.1", 40916, "/private/", "HTTPS"))
        assertNotEquals(expected, panelCertificateTrustScope("panel", "ssh", "127.0.0.1", 40917, "/private/", "HTTPS"))
        assertNotEquals(expected, panelCertificateTrustScope("panel", "ssh", "127.0.0.1", 40916, "/changed/", "HTTPS"))
        assertNotEquals(expected, panelCertificateTrustScope("panel", "ssh", "127.0.0.1", 40916, "/private/", "HTTP"))
    }
}
