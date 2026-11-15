package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.ssh.SshConnectFailure
import com.velumtegra.xuimobile.core.ssh.SshTimeoutPhase
import com.velumtegra.xuimobile.core.ssh.WebPanelLocalForwardFailure
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** User-facing diagnostics must distinguish failures without exposing private endpoint details. */
class PrivatePanelDiagnosticMessagesTest {
    @Test fun `authentication error indicates SSH rather than panel login`() {
        val result = privatePanelSshFailureMessage(SshConnectFailure.AuthenticationRejected)
        assertTrue(result.contains("SSH"))
        assertTrue(result.contains("авторизации"))
    }

    @Test fun `SSH timeout and forward rejection produce separate hints`() {
        val timeout = privatePanelSshFailureMessage(SshConnectFailure.Timeout(SshTimeoutPhase.TCP_CONNECT))
        val forward = privatePanelForwardFailureMessage(WebPanelLocalForwardFailure.LOCAL_FORWARD_OPEN_FAILED)
        assertTrue(timeout.contains("SSH-сервер"))
        assertTrue(forward.contains("проброс"))
    }

    @Test fun `host-key details are not shown to the user`() {
        val result = privatePanelSshFailureMessage(
            SshConnectFailure.HostIdentityMismatch("sensitive-expected-pin", "sensitive-presented-pin")
        )
        assertTrue(result.contains("ключ"))
        assertFalse(result.contains("sensitive"))
    }
}
