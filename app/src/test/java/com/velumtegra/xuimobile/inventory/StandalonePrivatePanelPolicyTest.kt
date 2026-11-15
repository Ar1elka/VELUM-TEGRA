package com.velumtegra.xuimobile.inventory

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class StandalonePrivatePanelPolicyTest {
    @Test fun acceptsExactManualLoopbackPanelRegardlessOfInstallationDirectory() {
        assertNull(StandalonePrivatePanelPolicy.targetError("127.0.0.1", "2053", "/custom-secret/"))
        assertNull(StandalonePrivatePanelPolicy.targetError("localhost", "443", "/"))
    }
    @Test fun rejectsArbitraryDestinationAndInvalidPortAndPath() {
        assertNotNull(StandalonePrivatePanelPolicy.targetError("8.8.8.8", "2053", "/"))
        assertNotNull(StandalonePrivatePanelPolicy.targetError("127.0.0.1", "0", "/"))
        assertNotNull(StandalonePrivatePanelPolicy.targetError("127.0.0.1", "40916?", "/"))
        assertNotNull(StandalonePrivatePanelPolicy.targetError("127.0.0.1", "2053", "secret"))
        assertNotNull(StandalonePrivatePanelPolicy.targetError("127.0.0.1", "2053", "/../"))
    }
    @Test fun credentialsRequireExplicitSavedSshProfileAndConsent() {
        assertNull(StandalonePrivatePanelPolicy.credentialError("ssh-id", "admin", 5, true))
        assertNotNull(StandalonePrivatePanelPolicy.credentialError("", "admin", 5, true))
        assertNotNull(StandalonePrivatePanelPolicy.credentialError("ssh-id", "admin", 5, false))
        assertNotNull(StandalonePrivatePanelPolicy.credentialError("ssh-id", "admin", 0, true))
    }
}
