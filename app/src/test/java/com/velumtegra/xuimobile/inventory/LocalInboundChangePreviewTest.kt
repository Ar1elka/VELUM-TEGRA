package com.velumtegra.xuimobile.inventory

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalInboundChangePreviewTest {
    private fun input(id: String = "3", old: String = "443", new: String = "8443",
        enabled: Boolean = true, target: Boolean = true,
    ) = LocalInboundChangeInput(id, old, new, enabled, target)

    @Test fun `valid changes expose only numeric local before and after values`() {
        val r = LocalInboundChangePlanner.preview(input()) as LocalInboundChangeResult.Preview
        assertEquals(3, r.inboundId)
        assertEquals(443, r.currentPort)
        assertEquals(8443, r.proposedPort)
        assertTrue(r.portWillChange)
        assertFalse(r.enabledWillChange)
    }

    @Test fun `enable state alone is a valid proposed change`() {
        val r = LocalInboundChangePlanner.preview(input(new = "443", target = false))
            as LocalInboundChangeResult.Preview
        assertFalse(r.portWillChange)
        assertTrue(r.enabledWillChange)
    }

    @Test fun `no change is not an executable plan`() {
        assertEquals(LocalInboundChangeIssue.NO_CHANGES,
            (LocalInboundChangePlanner.preview(input(new = "443")) as LocalInboundChangeResult.Invalid).issue)
    }

    @Test fun `id rejects zero whitespace overflow leading zero and injection`() {
        listOf("0", "01", " 3", "3 ", "2147483648", "3;curl", "3\n4", "3/4", "9".repeat(30))
            .forEach { bad ->
                assertEquals(LocalInboundChangeIssue.INVALID_INBOUND_ID,
                    (LocalInboundChangePlanner.preview(input(id = bad)) as LocalInboundChangeResult.Invalid).issue)
            }
    }

    @Test fun `ports reject zero out of range overflow whitespace and hostile strings`() {
        listOf("0", "65536", "00080", "-1", "+80", "443 ", "999999999999", "80;token", "80\n1")
            .forEach { bad ->
                assertEquals(LocalInboundChangeIssue.INVALID_CURRENT_PORT,
                    (LocalInboundChangePlanner.preview(input(old = bad)) as LocalInboundChangeResult.Invalid).issue)
                assertEquals(LocalInboundChangeIssue.INVALID_PROPOSED_PORT,
                    (LocalInboundChangePlanner.preview(input(new = bad)) as LocalInboundChangeResult.Invalid).issue)
            }
    }

    @Test fun `boundary values remain valid and output contains no user strings`() {
        val r = LocalInboundChangePlanner.preview(input(id = "2147483647", old = "1", new = "65535"))
            as LocalInboundChangeResult.Preview
        assertEquals(2147483647, r.inboundId)
        assertEquals(65535, r.proposedPort)
        // Untrusted input never appears in error output and cannot pass numeric validation.
        val hostile = LocalInboundChangePlanner.preview(input(id = "7;secret-token"))
        assertTrue(hostile is LocalInboundChangeResult.Invalid)
        assertFalse(hostile.toString().contains("secret-token"))
    }
}
