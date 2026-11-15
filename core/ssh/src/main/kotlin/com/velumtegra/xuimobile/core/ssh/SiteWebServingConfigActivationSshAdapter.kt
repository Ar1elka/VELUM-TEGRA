package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionObservation
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Phase 11.60 bounded SSH adapter. Callers cannot provide shell text.
 *
 * It revalidates an exact absent baseline, recreates one operation-owned non-*.conf staging file,
 * verifies its SHA-256, promotes it to the exact reviewed *.conf path with no-clobber semantics,
 * verifies the final SHA, runs read-only nginx syntax validation and proves the target listener is
 * still free. nginx reload and all unrelated mutation classes remain forbidden.
 */
class SiteWebServingConfigActivationSshAdapter {
    data class ReadyBeforeActivation(
        val verifiedHostKeySha256: String,
        val remoteCommandCount: Int,
    )

    suspend fun verifyBeforeActivation(
        activationPlan: SiteWebServingConfigActivationExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ): ReadyBeforeActivation {
        validateInputs(activationPlan, publicationPlan, access, session)
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("Phase 11.60 SSH session does not expose verified host-key evidence")
        val output = executeSuccessText(
            session,
            command(preActivationGuardCommand(activationPlan, publicationPlan.port), "site-web-config-activation-guard"),
        ).trim()
        require(output == "READY") { "Phase 11.60 remote baseline is not safe for exact config activation" }
        return ReadyBeforeActivation(verified.verifiedHostKeySha256, remoteCommandCount = 1)
    }

    suspend fun activateOnce(
        activationPlan: SiteWebServingConfigActivationExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
        durablePreactivationCheckpointRecorded: Boolean,
        priorCommandCount: Int,
    ): SiteWebServingConfigActivationExecutionObservation {
        validateInputs(activationPlan, publicationPlan, access, session)
        require(durablePreactivationCheckpointRecorded) {
            "Phase 11.60 durable preactivation checkpoint must exist before first remote write"
        }
        require(priorCommandCount == 1)
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("Phase 11.60 SSH session does not expose verified host-key evidence")
        val desiredBytes = publicationPlan.desiredConfigUtf8.encodeToByteArray()
        require(desiredBytes.size in 1..MAX_CONFIG_BYTES)
        val desiredBase64 = Base64.getEncoder().encodeToString(desiredBytes)
        var commandCount = priorCommandCount
        var stagingWrite = false
        var stagingShaVerified = false
        var activated = false
        var exactShaVerified = false
        var syntaxValidated = false
        var finalVerified = false

        try {
            executeSuccessText(
                session,
                command(
                    writeExclusiveBase64Command(activationPlan.stagingConfigPath, desiredBase64),
                    "site-web-config-activation-stage-write",
                ),
            ).also { require(it.trim() == "WRITTEN") }
            commandCount += 1
            stagingWrite = true

            val stageSha = executeSuccessText(
                session,
                command(sha256Command(activationPlan.stagingConfigPath), "site-web-config-activation-stage-sha256"),
            ).trim().substringBefore(' ')
            commandCount += 1
            require(stageSha == activationPlan.desiredConfigSha256) { "Phase 11.60 staging SHA-256 mismatch" }
            stagingShaVerified = true

            executeSuccessText(
                session,
                command(atomicActivateCommand(activationPlan), "site-web-config-atomic-activate"),
            ).also { require(it.trim() == "ACTIVATED") }
            commandCount += 1
            activated = true

            val exactSha = executeSuccessText(
                session,
                command(sha256Command(activationPlan.configPath), "site-web-config-exact-sha256"),
            ).trim().substringBefore(' ')
            commandCount += 1
            require(exactSha == activationPlan.desiredConfigSha256) { "Phase 11.60 exact config SHA-256 mismatch" }
            exactShaVerified = true

            executeSuccess(
                session,
                command(nginxSyntaxCommand(), "site-web-config-exact-nginx-syntax-test"),
            )
            commandCount += 1
            syntaxValidated = true

            executeSuccessText(
                session,
                command(finalVerifyCommand(activationPlan, publicationPlan.port), "site-web-config-activation-final-verify"),
            ).also { require(it.trim() == "ACTIVE_NO_RELOAD") }
            commandCount += 1
            finalVerified = true
        } catch (failure: Throwable) {
            if (session.isOpen) {
                val rollback = runCatching {
                    executeSuccessText(
                        session,
                        command(rollbackToAbsentCommand(activationPlan, publicationPlan.port), "site-web-config-activation-rollback-to-absent"),
                    ).trim()
                }
                if (rollback.getOrNull() == "ABSENT") {
                    throw IllegalStateException(
                        "Phase 11.60 activation failed and exact desired artifacts were rolled back to ABSENT; no retry authorized",
                        failure,
                    )
                }
                throw IllegalStateException(
                    "Phase 11.60 activation failed and rollback-to-ABSENT was not proven; read-only reconciliation required",
                    rollback.exceptionOrNull() ?: failure,
                )
            }
            throw IllegalStateException(
                "Phase 11.60 activation became uncertain after session loss; read-only reconciliation to ABSENT required",
                failure,
            )
        }

        require(stagingWrite && stagingShaVerified && activated && exactShaVerified && syntaxValidated && finalVerified)
        return SiteWebServingConfigActivationExecutionObservation(
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            verifiedHostKeySha256 = verified.verifiedHostKeySha256,
            durablePreactivationCheckpointRecorded = true,
            stagingWritePerformed = true,
            stagingSha256Verified = true,
            exactConfigActivationPerformed = true,
            exactConfigSha256Verified = true,
            nginxSyntaxValidationPassed = true,
            exactConfigPathPresentAfterActivation = true,
            stagingConfigAbsentAfterActivation = true,
            listenerStillFreeAfterActivation = true,
            rollbackToAbsentPerformed = false,
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
        activationPlan: SiteWebServingConfigActivationExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ) {
        SiteWebServingConfigActivationExecutionBoundary.validate(activationPlan)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        require(activationPlan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(activationPlan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(activationPlan.configPath == publicationPlan.configPath)
        require(activationPlan.desiredConfigSha256 == publicationPlan.desiredConfigSha256)
        require(access.endpoint.host == activationPlan.remoteHostIdentity)
        require(session.binding.serverAccessId == access.id)
        require(session.binding.owner is SessionOwner.Operation)
        require(session.isOpen)
    }

    private fun preActivationGuardCommand(plan: SiteWebServingConfigActivationExecutionPlan, port: Int): String {
        val config = quote(plan.configPath)
        val staging = quote(plan.stagingConfigPath)
        val filter = quote("sport = :$port")
        return "if ! command -v nginx >/dev/null 2>&1; then printf 'BLOCKED\\n'; " +
            "elif [ -e $config ] || [ -L $config ] || [ -e $staging ] || [ -L $staging ]; then printf 'BLOCKED\\n'; " +
            "elif ! command -v ss >/dev/null 2>&1; then printf 'BLOCKED\\n'; " +
            "elif ! nginx -t >/dev/null 2>&1; then printf 'BLOCKED\\n'; " +
            "else out=\$(ss -H -ltn $filter 2>/dev/null); code=\$?; " +
            "if [ \$code -ne 0 ] || [ -n \"\$out\" ]; then printf 'BLOCKED\\n'; else printf 'READY\\n'; fi; fi"
    }

    private fun writeExclusiveBase64Command(path: String, base64: String): String {
        require(base64.matches(Regex("^[A-Za-z0-9+/=]+$")))
        val qPath = quote(path)
        val qPayload = quote(base64)
        return "umask 077; set -C; printf '%s' $qPayload | base64 -d > $qPath; chmod 0600 -- $qPath; printf 'WRITTEN\\n'"
    }

    private fun atomicActivateCommand(plan: SiteWebServingConfigActivationExecutionPlan): String {
        val staging = quote(plan.stagingConfigPath)
        val config = quote(plan.configPath)
        val desiredSha = quote(plan.desiredConfigSha256)
        return "test -f $staging; test ! -L $staging; " +
            "test \"\$(sha256sum -- $staging | cut -d' ' -f1)\" = $desiredSha; " +
            "test ! -e $config; test ! -L $config; mv -n -- $staging $config; " +
            "test ! -e $staging; test ! -L $staging; test -f $config; test ! -L $config; " +
            "test \"\$(sha256sum -- $config | cut -d' ' -f1)\" = $desiredSha; printf 'ACTIVATED\\n'"
    }

    private fun sha256Command(path: String): String = "sha256sum -- ${quote(path)}"

    private fun nginxSyntaxCommand(): String =
        "nginx_bin=\$(command -v nginx); test -n \"\$nginx_bin\"; \"\$nginx_bin\" -t"

    private fun finalVerifyCommand(plan: SiteWebServingConfigActivationExecutionPlan, port: Int): String {
        val staging = quote(plan.stagingConfigPath)
        val config = quote(plan.configPath)
        val desiredSha = quote(plan.desiredConfigSha256)
        val filter = quote("sport = :$port")
        return "test ! -e $staging; test ! -L $staging; test -f $config; test ! -L $config; " +
            "test \"\$(sha256sum -- $config | cut -d' ' -f1)\" = $desiredSha; " +
            "out=\$(ss -H -ltn $filter 2>/dev/null); code=\$?; test \$code -eq 0; test -z \"\$out\"; " +
            "printf 'ACTIVE_NO_RELOAD\\n'"
    }

    private fun rollbackToAbsentCommand(plan: SiteWebServingConfigActivationExecutionPlan, port: Int): String {
        val staging = quote(plan.stagingConfigPath)
        val config = quote(plan.configPath)
        val desiredSha = quote(plan.desiredConfigSha256)
        val filter = quote("sport = :$port")
        return "stage_ok=0; config_ok=0; " +
            "if [ ! -e $staging ] && [ ! -L $staging ]; then stage_ok=1; " +
            "elif [ -f $staging ] && [ ! -L $staging ] && [ \"\$(sha256sum -- $staging | cut -d' ' -f1)\" = $desiredSha ]; then rm -- $staging; stage_ok=1; fi; " +
            "if [ ! -e $config ] && [ ! -L $config ]; then config_ok=1; " +
            "elif [ -f $config ] && [ ! -L $config ] && [ \"\$(sha256sum -- $config | cut -d' ' -f1)\" = $desiredSha ]; then rm -- $config; config_ok=1; fi; " +
            "test \$stage_ok -eq 1; test \$config_ok -eq 1; test ! -e $staging; test ! -L $staging; test ! -e $config; test ! -L $config; " +
            "out=\$(ss -H -ltn $filter 2>/dev/null); code=\$?; test \$code -eq 0; test -z \"\$out\"; printf 'ABSENT\\n'"
    }

    private suspend fun executeSuccessText(session: SshSessionHandle, command: RemoteCommand): String {
        val result = executeSuccess(session, command)
        return decodeUtf8(result.stdout.copyBytes())
    }

    private suspend fun executeSuccess(session: SshSessionHandle, command: RemoteCommand): SshCommandResult {
        val result = session.execute(command, EXECUTION_CONFIG)
        require(result.dispatchState == CommandDispatchState.DISPATCHED) { "Phase 11.60 command was not dispatched" }
        require(!result.stdout.truncated && !result.stderr.truncated) { "Phase 11.60 command output was truncated" }
        require(result.completion == CommandCompletion.ConfirmedSuccess) { "Phase 11.60 command failed or became uncertain" }
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
