package com.velumtegra.xuimobile.enrollment

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class EnrollmentInputPolicyTest {
    private val fingerprint = "SHA256:" + "A".repeat(43)

    @Test fun `no target no credential enrollment`() {
        assertNotNull(EnrollmentInputPolicy.validateAccess("", "example.org", "22", "operator", fingerprint, true, 12))
    }

    @Test fun `pin must be canonical and independently verified`() {
        assertNotNull(EnrollmentInputPolicy.validateAccess("server-1", "example.org", "22", "operator", "SHA256:bad", true, 12))
        assertNotNull(EnrollmentInputPolicy.validateAccess("server-1", "example.org", "22", "operator", fingerprint, false, 12))
        assertNull(EnrollmentInputPolicy.validateAccess("server-1", "example.org", "22", "operator", fingerprint, true, 12))
    }

    @Test fun `rejects unsafe endpoints or blank credentials`() {
        assertNotNull(EnrollmentInputPolicy.validateAccess("server-1", "https://example.org", "22", "operator", fingerprint, true, 12))
        assertNotNull(EnrollmentInputPolicy.validateAccess("server-1", "example.org", "0", "operator", fingerprint, true, 12))
        assertNotNull(EnrollmentInputPolicy.validateAccess("server-1", "example.org", "22", "operator", fingerprint, true, 0))
        assertNotNull(EnrollmentInputPolicy.validateAccess("server-1", "example.org", "22", "", fingerprint, true, 12))
        assertNotNull(EnrollmentInputPolicy.validateName(" \n "))
        assertNull(EnrollmentInputPolicy.validateName("Мой VPS"))
    }
}
