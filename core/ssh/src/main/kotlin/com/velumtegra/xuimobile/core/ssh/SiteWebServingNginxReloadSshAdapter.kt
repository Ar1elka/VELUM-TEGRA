package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionObservation
import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** Phase 11.61 bounded SSH adapter. Callers cannot supply shell text. */
class SiteWebServingNginxReloadSshAdapter {
    data class ReadyBeforeReload(val verifiedHostKeySha256: String, val remoteCommandCount: Int)

    suspend fun verifyBeforeReload(
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ): ReadyBeforeReload {
        validateInputs(reloadPlan, publicationPlan, access, session)
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("Phase 11.61 SSH session does not expose verified host-key evidence")
        val output = executeSuccessText(
            session,
            command(preReloadGuardCommand(reloadPlan), "site-web-nginx-reload-guard"),
        ).trim()
        require(output == "READY") { "Phase 11.61 activated config is not safe for nginx reload" }
        return ReadyBeforeReload(verified.verifiedHostKeySha256, remoteCommandCount = 1)
    }

    suspend fun reloadOnce(
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
        durablePreReloadCheckpointRecorded: Boolean,
        priorCommandCount: Int,
    ): SiteWebServingNginxReloadExecutionObservation {
        validateInputs(reloadPlan, publicationPlan, access, session)
        require(durablePreReloadCheckpointRecorded) { "Phase 11.61 durable pre-reload checkpoint is required" }
        require(priorCommandCount == 1)
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("Phase 11.61 SSH session does not expose verified host-key evidence")
        var commandCount = priorCommandCount
        try {
            executeSuccessText(session, command(reloadCommand(), "site-web-nginx-reload-once"))
                .also { require(it.trim() == "RELOADED") }
            commandCount += 1
            executeSuccessText(
                session,
                command(postReloadVerifyCommand(reloadPlan), "site-web-nginx-reload-post-verify"),
            ).also { require(it.trim() == "LIVE") }
            commandCount += 1
        } catch (failure: Throwable) {
            if (!session.isOpen) {
                throw IllegalStateException(
                    "Phase 11.61 reload dispatch became uncertain after session loss; read-only reconciliation required and retry is forbidden",
                    failure,
                )
            }
            throw IllegalStateException(
                "Phase 11.61 reload failed or became uncertain; read-only reconciliation required and retry is forbidden",
                failure,
            )
        }
        require(commandCount == 3)
        return SiteWebServingNginxReloadExecutionObservation(
            remoteHostIdentity = publicationPlan.remoteHostIdentity,
            verifiedHostKeySha256 = verified.verifiedHostKeySha256,
            exactConfigSha256VerifiedBeforeReload = true,
            nginxSyntaxValidationPassedBeforeReload = true,
            listenerFreeBeforeReload = true,
            durablePreReloadCheckpointRecorded = true,
            nginxReloadPerformed = true,
            exactConfigSha256VerifiedAfterReload = true,
            nginxMasterRunningAfterReload = true,
            expectedListenerLiveAfterReload = true,
            remoteCommandCount = commandCount,
            arbitraryCommandAccepted = false,
            configMutationPerformed = false,
            dnsMutationPerformed = false,
            firewallMutationPerformed = false,
            packageInstallPerformed = false,
            automaticRetryPerformed = false,
        )
    }

    private fun validateInputs(
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
        publicationPlan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ) {
        SiteWebServingNginxReloadExecutionBoundary.validate(reloadPlan)
        SiteWebServingPublicationPlanBoundary.validate(publicationPlan)
        require(reloadPlan.publicationPlanSha256 == publicationPlan.publicationPlanSha256)
        require(reloadPlan.remoteHostIdentity == publicationPlan.remoteHostIdentity)
        require(reloadPlan.configPath == publicationPlan.configPath)
        require(reloadPlan.desiredConfigSha256 == publicationPlan.desiredConfigSha256)
        require(reloadPlan.expectedListenerPort == publicationPlan.port)
        require(access.endpoint.host == reloadPlan.remoteHostIdentity)
        require(session.binding.serverAccessId == access.id)
        require(session.binding.owner is SessionOwner.Operation)
        require(session.isOpen)
    }

    private fun preReloadGuardCommand(plan: SiteWebServingNginxReloadExecutionPlan): String {
        val config = quote(plan.configPath)
        val desiredSha = quote(plan.desiredConfigSha256)
        val filter = quote("sport = :${plan.expectedListenerPort}")
        return "if ! command -v nginx >/dev/null 2>&1 || ! command -v ss >/dev/null 2>&1; then printf 'BLOCKED\\n'; " +
            "elif [ ! -f $config ] || [ -L $config ]; then printf 'BLOCKED\\n'; " +
            "elif [ \"\$(sha256sum -- $config | cut -d' ' -f1)\" != $desiredSha ]; then printf 'BLOCKED\\n'; " +
            "elif ! nginx -t >/dev/null 2>&1; then printf 'BLOCKED\\n'; " +
            "elif [ ! -s /run/nginx.pid ] || ! kill -0 \"\$(cat /run/nginx.pid)\" 2>/dev/null; then printf 'BLOCKED\\n'; " +
            "else out=\$(ss -H -ltn $filter 2>/dev/null); code=\$?; " +
            "if [ \$code -ne 0 ] || [ -n \"\$out\" ]; then printf 'BLOCKED\\n'; else printf 'READY\\n'; fi; fi"
    }

    private fun reloadCommand(): String =
        "nginx_bin=\$(command -v nginx); test -n \"\$nginx_bin\"; \"\$nginx_bin\" -s reload; printf 'RELOADED\\n'"

    private fun postReloadVerifyCommand(plan: SiteWebServingNginxReloadExecutionPlan): String {
        val config = quote(plan.configPath)
        val desiredSha = quote(plan.desiredConfigSha256)
        val filter = quote("sport = :${plan.expectedListenerPort}")
        return "test -f $config; test ! -L $config; " +
            "test \"\$(sha256sum -- $config | cut -d' ' -f1)\" = $desiredSha; " +
            "test -s /run/nginx.pid; kill -0 \"\$(cat /run/nginx.pid)\" 2>/dev/null; " +
            "i=0; while [ \$i -lt 40 ]; do out=\$(ss -H -ltn $filter 2>/dev/null); code=\$?; " +
            "if [ \$code -eq 0 ] && [ -n \"\$out\" ]; then printf 'LIVE\\n'; exit 0; fi; i=\$((i+1)); sleep 0.1; done; exit 1"
    }

    private suspend fun executeSuccessText(session: SshSessionHandle, command: RemoteCommand): String {
        val result = session.execute(command, EXECUTION_CONFIG)
        require(result.dispatchState == CommandDispatchState.DISPATCHED) { "Phase 11.61 command was not dispatched" }
        require(!result.stdout.truncated && !result.stderr.truncated) { "Phase 11.61 command output was truncated" }
        require(result.completion == CommandCompletion.ConfirmedSuccess) { "Phase 11.61 command failed or became uncertain" }
        return StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(result.stdout.copyBytes())).toString()
    }

    private fun command(raw: String, label: String): RemoteCommand = RemoteCommand.create(raw, label)
    private fun quote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' })
        return "'$value'"
    }

    companion object {
        private val EXECUTION_CONFIG = SshTransportConfig(
            commandExecutionTimeout = java.time.Duration.ofSeconds(12),
            stdoutCaptureLimitBytes = 32 * 1024,
            stderrCaptureLimitBytes = 64 * 1024,
        )
    }
}
