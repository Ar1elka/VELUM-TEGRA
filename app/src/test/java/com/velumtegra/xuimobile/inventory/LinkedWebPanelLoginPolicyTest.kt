package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.WebPanelAccess
import com.velumtegra.xuimobile.core.model.WebPanelAccessId
import com.velumtegra.xuimobile.core.model.WebPanelInstallationLink
import com.velumtegra.xuimobile.core.model.WebPanelRoute
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import com.velumtegra.xuimobile.core.webpanel.CredentialSubmissionState
import com.velumtegra.xuimobile.core.webpanel.WebPanelAuthenticationFailure
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LinkedWebPanelLoginPolicyTest {
    private fun panel(linked: Boolean = true, direct: Boolean = true) = WebPanelAccess(
        id = WebPanelAccessId("panel-1"),
        installationLink = if (linked) WebPanelInstallationLink.Linked(XuiInstallationId("install-1"))
            else WebPanelInstallationLink.Standalone,
        username = "user",
        passwordSecretId = SecretId("secret-1"),
        route = if (direct) WebPanelRoute.Direct("panel.example.com")
            else WebPanelRoute.SshTunnel(ServerAccessId("ssh-1")),
    )

    @Test fun `explicit approval is necessary and only linked direct access is allowed`() {
        assertTrue(LinkedWebPanelLoginPolicy.permitted(panel(), true))
        assertFalse(LinkedWebPanelLoginPolicy.permitted(panel(), false))
        assertFalse(LinkedWebPanelLoginPolicy.permitted(panel(linked = false), true))
        assertFalse(LinkedWebPanelLoginPolicy.permitted(panel(direct = false), true))
    }

    @Test fun `ambiguous credential submission never looks like a rejected password`() {
        val msg = LinkedWebPanelLoginPolicy.failureMessage(
            WebPanelAuthenticationFailure.NETWORK_FAILURE, CredentialSubmissionState.OUTCOME_UNKNOWN)
        assertTrue(msg.contains("неизвестен"))
        assertTrue(msg.contains("повтора"))
    }

    @Test fun `TLS and 2FA errors are safely described and not bypassed`() {
        val tls = LinkedWebPanelLoginPolicy.failureMessage(
            WebPanelAuthenticationFailure.TLS_FAILURE, CredentialSubmissionState.NOT_STARTED)
        assertTrue(tls.contains("TLS"))
        val twoFactor = LinkedWebPanelLoginPolicy.failureMessage(
            WebPanelAuthenticationFailure.SECOND_FACTOR_REQUIRED, CredentialSubmissionState.NOT_STARTED)
        assertTrue(twoFactor.contains("двухфакторная"))
    }
}
