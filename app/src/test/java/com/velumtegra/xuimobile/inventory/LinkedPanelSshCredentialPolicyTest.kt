package com.velumtegra.xuimobile.inventory

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class LinkedPanelSshCredentialPolicyTest {
    @Test fun `valid exact SSH panel settings may be saved only with consent`() {
        assertNull(LinkedPanelSshCredentialPolicy.preflight("server", "installation", "ssh-1", "admin", 12, true, 443, "/secret/"))
        assertNotNull(LinkedPanelSshCredentialPolicy.preflight("server", "installation", "ssh-1", "admin", 12, false, 443, "/secret/"))
    }
    @Test fun `fail closed for missing bindings and invalid secrets`() {
        assertNotNull(LinkedPanelSshCredentialPolicy.preflight("server", "installation", "", "admin", 12, true, 443, "/secret/"))
        assertNotNull(LinkedPanelSshCredentialPolicy.preflight("server", "installation", "ssh-1", " admin", 12, true, 443, "/secret/"))
        assertNotNull(LinkedPanelSshCredentialPolicy.preflight("server", "installation", "ssh-1", "admin", 0, true, 443, "/secret/"))
        assertNotNull(LinkedPanelSshCredentialPolicy.preflight("server", "installation", "ssh-1", "admin", 4097, true, 443, "/secret/"))
    }
    @Test fun `fail closed for invalid saved panel port and path`() {
        assertNotNull(LinkedPanelSshCredentialPolicy.preflight("server", "installation", "ssh-1", "admin", 12, true, 0, "/secret/"))
        assertNotNull(LinkedPanelSshCredentialPolicy.preflight("server", "installation", "ssh-1", "admin", 12, true, 443, "relative"))
        assertNotNull(LinkedPanelSshCredentialPolicy.preflight("server", "installation", "ssh-1", "admin", 12, true, 443, "/../secret"))
    }
}
