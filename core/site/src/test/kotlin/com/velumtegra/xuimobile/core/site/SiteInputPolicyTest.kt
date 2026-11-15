package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertThrows
import org.junit.Test

class SiteInputPolicyTest {
    @Test
    fun `blank or control-character names are rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            SiteInputPolicy.normalizeName("   ")
        }
        assertThrows(IllegalArgumentException::class.java) {
            SiteInputPolicy.normalizeName("Nova\u0000Gate")
        }
    }

    @Test
    fun `overlong tagline is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            SiteInputPolicy.normalizeTagline("x".repeat(141))
        }
    }
}
