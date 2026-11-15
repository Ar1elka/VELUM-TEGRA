package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.model.CommandCompletion
import java.util.Arrays
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Phase4_6OPrivacySurfaceTest {
    @Test
    fun `command output and credential material stay redacted across representative result paths`() {
        val rawCommandCanary = "phase46o-command-secret-canary"
        val stdoutCanary = "phase46o-stdout-secret-canary"
        val stderrCanary = "phase46o-stderr-secret-canary"
        val passwordCanary = "phase46o-password-secret-canary"
        val privateKeyCanary = "phase46o-private-key-secret-canary"
        val passphraseCanary = "phase46o-passphrase-secret-canary"

        val command = RemoteCommand.create(
            raw = "printf '$rawCommandCanary'",
            redactedLabel = "phase46o-probe",
        )
        assertSafeRendering(
            rendered = command.toString(),
            forbidden = listOf(rawCommandCanary),
            requireRedactionMarker = true,
        )

        val stdout = CapturedOutput.of(stdoutCanary.encodeToByteArray(), truncated = false)
        val stderr = CapturedOutput.of(stderrCanary.encodeToByteArray(), truncated = false)
        val completions = listOf(
            CommandCompletion.ConfirmedSuccess,
            CommandCompletion.ConfirmedFailure(
                reason = "Remote command exited with non-zero status",
                exitCode = 7,
            ),
            CommandCompletion.Unknown("SSH command completion became indeterminate after dispatch"),
        )

        completions.forEach { completion ->
            val rendered = SshCommandResult(
                dispatchState = CommandDispatchState.DISPATCHED,
                completion = completion,
                stdout = stdout,
                stderr = stderr,
            ).toString()
            assertSafeRendering(
                rendered = rendered,
                forbidden = listOf(stdoutCanary, stderrCanary, rawCommandCanary),
                requireRedactionMarker = true,
            )
        }

        val passwordBytes = passwordCanary.encodeToByteArray()
        val passwordMaterial = SecretMaterial.fromBytes(passwordBytes)
        try {
            assertSafeRendering(
                rendered = passwordMaterial.toString(),
                forbidden = listOf(passwordCanary),
                requireRedactionMarker = true,
            )
            assertSafeRendering(
                rendered = SecretReadResult.Found(passwordMaterial).toString(),
                forbidden = listOf(passwordCanary),
                requireRedactionMarker = true,
            )
        } finally {
            passwordMaterial.close()
            Arrays.fill(passwordBytes, 0)
        }

        val keyBytes = privateKeyCanary.encodeToByteArray()
        val passphraseBytes = passphraseCanary.encodeToByteArray()
        val privateKeyMaterial = SshPrivateKeyCredentialMaterial.create(keyBytes, passphraseBytes)
        try {
            assertSafeRendering(
                rendered = privateKeyMaterial.toString(),
                forbidden = listOf(privateKeyCanary, passphraseCanary),
                requireRedactionMarker = true,
            )
        } finally {
            privateKeyMaterial.close()
            Arrays.fill(keyBytes, 0)
            Arrays.fill(passphraseBytes, 0)
        }
    }

    private fun assertSafeRendering(
        rendered: String,
        forbidden: List<String>,
        requireRedactionMarker: Boolean,
    ) {
        forbidden.forEach { secret ->
            assertFalse("Sensitive canary leaked through rendering", rendered.contains(secret))
        }
        if (requireRedactionMarker) {
            assertTrue("Expected explicit redaction marker", rendered.contains("[REDACTED]"))
        }
    }
}
