package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionObservation
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Phase 11.59 bounded SSH adapter. Callers cannot supply shell text.
 *
 * The adapter may write only two exact operation-owned non-*.conf files, verify both SHA-256 values,
 * run `nginx -t` against the isolated validation wrapper and remove both files. It never activates
 * the exact production *.conf path and never reloads nginx or mutates DNS/firewall/packages.
 */
class SiteWebServingConfigStagingSyntaxSshAdapter {
    data class ReadyBeforeWrite(
        val verifiedHostKeySha256: String,
        val remoteCommandCount: Int,
    )

    suspend fun verifyBeforeFirstWrite(
        executionPlan: SiteWebServingConfigStagingSyntaxExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ): ReadyBeforeWrite {
        validateInputs(executionPlan, publicationPlan, access, session)
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("Phase 11.59 SSH session does not expose verified host-key evidence")
        val output = executeSuccessText(
            session,
            command(preWriteGuardCommand(executionPlan, publicationPlan.port), "site-web-config-stage-prewrite-guard"),
        ).trim()
        require(output == "READY") { "Phase 11.59 remote baseline is no longer safe for first write" }
        return ReadyBeforeWrite(verified.verifiedHostKeySha256, remoteCommandCount = 1)
    }

    suspend fun stageValidateAndCleanup(
        executionPlan: SiteWebServingConfigStagingSyntaxExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
        durableBaselineCheckpointRecorded: Boolean,
        priorCommandCount: Int,
    ): SiteWebServingConfigStagingSyntaxExecutionObservation {
        validateInputs(executionPlan, publicationPlan, access, session)
        require(durableBaselineCheckpointRecorded) {
            "Phase 11.59 durable baseline checkpoint must exist before first remote write"
        }
        require(priorCommandCount == 1)
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("Phase 11.59 SSH session does not expose verified host-key evidence")

        val desiredBytes = publicationPlan.desiredConfigUtf8.encodeToByteArray()
        val validationBytes = executionPlan.validationConfigUtf8.encodeToByteArray()
        require(desiredBytes.size in 1..MAX_CONFIG_BYTES)
        require(validationBytes.size in 1..MAX_CONFIG_BYTES)
        val desiredBase64 = Base64.getEncoder().encodeToString(desiredBytes)
        val validationBase64 = Base64.getEncoder().encodeToString(validationBytes)
        var commandCount = priorCommandCount
        var stagingWrite = false
        var stagingShaVerified = false
        var validationWrite = false
        var validationShaVerified = false
        var syntaxValidated = false
        var cleanupConfirmed = false

        try {
            executeSuccessText(
                session,
                command(
                    writeExclusiveBase64Command(executionPlan.stagingConfigPath, desiredBase64),
                    "site-web-config-stage-write",
                ),
            ).also { require(it.trim() == "WRITTEN") }
            commandCount += 1
            stagingWrite = true

            val stageSha = executeSuccessText(
                session,
                command(sha256Command(executionPlan.stagingConfigPath), "site-web-config-stage-sha256"),
            ).trim().substringBefore(' ')
            commandCount += 1
            require(stageSha == executionPlan.desiredConfigSha256) { "Phase 11.59 staging SHA-256 mismatch" }
            stagingShaVerified = true

            executeSuccessText(
                session,
                command(
                    writeExclusiveBase64Command(executionPlan.validationConfigPath, validationBase64),
                    "site-web-config-validation-write",
                ),
            ).also { require(it.trim() == "WRITTEN") }
            commandCount += 1
            validationWrite = true

            val validationSha = executeSuccessText(
                session,
                command(sha256Command(executionPlan.validationConfigPath), "site-web-config-validation-sha256"),
            ).trim().substringBefore(' ')
            commandCount += 1
            require(validationSha == executionPlan.validationConfigSha256) { "Phase 11.59 validation-wrapper SHA-256 mismatch" }
            validationShaVerified = true

            executeSuccess(
                session,
                command(nginxSyntaxCommand(executionPlan.validationConfigPath), "site-web-config-nginx-syntax-test"),
            )
            commandCount += 1
            syntaxValidated = true
        } finally {
            if (session.isOpen) {
                val cleanup = runCatching {
                    executeSuccessText(
                        session,
                        command(cleanupAndFinalVerifyCommand(executionPlan, publicationPlan.port), "site-web-config-stage-cleanup-verify"),
                    )
                }
                commandCount += 1
                cleanupConfirmed = cleanup.getOrNull()?.trim() == "CLEAN"
                if (!cleanupConfirmed) {
                    throw IllegalStateException(
                        "Phase 11.59 operation-owned cleanup/final verification was not proven; read-only reconciliation required",
                        cleanup.exceptionOrNull(),
                    )
                }
            }
        }

        require(stagingWrite && stagingShaVerified)
        require(validationWrite && validationShaVerified)
        require(syntaxValidated && cleanupConfirmed)
        return SiteWebServingConfigStagingSyntaxExecutionObservation(
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            verifiedHostKeySha256 = verified.verifiedHostKeySha256,
            durableBaselineCheckpointRecorded = true,
            stagingWritePerformed = true,
            stagingSha256Verified = true,
            validationConfigWritePerformed = true,
            validationConfigSha256Verified = true,
            nginxSyntaxValidationPassed = true,
            exactConfigActivationPerformed = false,
            exactConfigPathAbsentAfterValidation = true,
            listenerStillFreeAfterValidation = true,
            stagingConfigAbsentAfterCleanup = true,
            validationConfigAbsentAfterCleanup = true,
            validationPidAbsentAfterCleanup = true,
            remoteCommandCount = commandCount,
            arbitraryCommandAccepted = false,
            webServerReloadPerformed = false,
            dnsMutationPerformed = false,
            firewallMutationPerformed = false,
            packageInstallPerformed = false,
            automaticRetryPerformed = false,
        )
    }

    private fun validateInputs(
        executionPlan: SiteWebServingConfigStagingSyntaxExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ) {
        SiteWebServingConfigStagingSyntaxExecutionBoundary.validate(executionPlan)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        require(executionPlan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(executionPlan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(executionPlan.configPath == publicationPlan.configPath)
        require(executionPlan.desiredConfigSha256 == publicationPlan.desiredConfigSha256)
        require(access.endpoint.host == executionPlan.remoteHostIdentity)
        require(session.binding.serverAccessId == access.id)
        require(session.binding.owner is SessionOwner.Operation)
        require(session.isOpen)
    }

    private fun preWriteGuardCommand(plan: SiteWebServingConfigStagingSyntaxExecutionPlan, port: Int): String {
        val config = quote(plan.configPath)
        val staging = quote(plan.stagingConfigPath)
        val validation = quote(plan.validationConfigPath)
        val pid = quote(plan.validationPidPath)
        val filter = quote("sport = :$port")
        return "if ! command -v nginx >/dev/null 2>&1; then printf 'BLOCKED\\n'; " +
            "elif [ -e $config ] || [ -L $config ] || [ -e $staging ] || [ -L $staging ] || " +
            "[ -e $validation ] || [ -L $validation ] || [ -e $pid ] || [ -L $pid ]; then printf 'BLOCKED\\n'; " +
            "elif ! command -v ss >/dev/null 2>&1; then printf 'BLOCKED\\n'; " +
            "else out=\$(ss -H -ltn $filter 2>/dev/null); code=\$?; " +
            "if [ \$code -ne 0 ] || [ -n \"\$out\" ]; then printf 'BLOCKED\\n'; else printf 'READY\\n'; fi; fi"
    }

    private fun writeExclusiveBase64Command(path: String, base64: String): String {
        require(base64.matches(Regex("^[A-Za-z0-9+/=]+$")))
        val qPath = quote(path)
        val qPayload = quote(base64)
        return "umask 077; set -C; printf '%s' $qPayload | base64 -d > $qPath; chmod 0600 -- $qPath; printf 'WRITTEN\\n'"
    }

    private fun sha256Command(path: String): String = "sha256sum -- ${quote(path)}"

    private fun nginxSyntaxCommand(validationConfigPath: String): String =
        "nginx_bin=\$(command -v nginx); test -n \"\$nginx_bin\"; \"\$nginx_bin\" -t -c ${quote(validationConfigPath)}"

    private fun cleanupAndFinalVerifyCommand(
        plan: SiteWebServingConfigStagingSyntaxExecutionPlan,
        port: Int,
    ): String {
        val staging = quote(plan.stagingConfigPath)
        val validation = quote(plan.validationConfigPath)
        val pid = quote(plan.validationPidPath)
        val config = quote(plan.configPath)
        val desiredSha = quote(plan.desiredConfigSha256)
        val validationSha = quote(plan.validationConfigSha256)
        val filter = quote("sport = :$port")
        // set -e: the trailing `test` assertions must actually fail the command (with plain `;` they were
        // ignored and CLEAN was always printed). nginx >= 1.27 creates the validation pid file even for
        // `nginx -t`; it is empty and operation-owned (unique name), so remove it instead of leaking it in /tmp.
        return "set -e; stage_ok=0; validate_ok=0; " +
            "if [ -f $pid ] && [ ! -L $pid ] && [ ! -s $pid ]; then rm -f -- $pid; fi; " +
            "if [ ! -e $staging ] && [ ! -L $staging ]; then stage_ok=1; " +
            "elif [ -f $staging ] && [ ! -L $staging ] && [ \"\$(sha256sum -- $staging | cut -d' ' -f1)\" = $desiredSha ]; then rm -- $staging; stage_ok=1; fi; " +
            "if [ ! -e $validation ] && [ ! -L $validation ]; then validate_ok=1; " +
            "elif [ -f $validation ] && [ ! -L $validation ] && [ \"\$(sha256sum -- $validation | cut -d' ' -f1)\" = $validationSha ]; then rm -- $validation; validate_ok=1; fi; " +
            "test \$stage_ok -eq 1; test \$validate_ok -eq 1; " +
            "test ! -e $staging; test ! -L $staging; test ! -e $validation; test ! -L $validation; " +
            "test ! -e $pid; test ! -L $pid; test ! -e $config; test ! -L $config; " +
            "out=\$(ss -H -ltn $filter 2>/dev/null); code=\$?; test \$code -eq 0; test -z \"\$out\"; printf 'CLEAN\\n'"
    }

    private suspend fun executeSuccessText(session: SshSessionHandle, command: RemoteCommand): String {
        val result = executeSuccess(session, command)
        return decodeUtf8(result.stdout.copyBytes())
    }

    private suspend fun executeSuccess(session: SshSessionHandle, command: RemoteCommand): SshCommandResult {
        val result = session.execute(command, EXECUTION_CONFIG)
        require(result.dispatchState == CommandDispatchState.DISPATCHED) { "Phase 11.59 command was not dispatched" }
        require(!result.stdout.truncated && !result.stderr.truncated) { "Phase 11.59 command output was truncated" }
        require(result.completion == CommandCompletion.ConfirmedSuccess) { "Phase 11.59 command failed or became uncertain" }
        return result
    }

    private fun command(raw: String, label: String): RemoteCommand = RemoteCommand.create(raw, label)

    private fun quote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' }) { "Unsafe shell token" }
        return "'$value'"
    }

    private fun decodeUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()

    companion object {
        private const val MAX_CONFIG_BYTES = 128 * 1024
        private val EXECUTION_CONFIG = SshTransportConfig(
            stdoutCaptureLimitBytes = 32 * 1024,
            stderrCaptureLimitBytes = 64 * 1024,
        )
    }
}
