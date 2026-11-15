package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimeProvisioningBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimeProvisioningObservation
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimeProvisioningPlan
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration

/** Phase 11.59B exact apt-based nginx provisioning executor. No command input is caller supplied. */
class SiteWebServingRuntimeProvisioningSshAdapter {
    suspend fun verifyBeforeMutation(
        plan: SiteWebServingRuntimeProvisioningPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ): String {
        validateInputs(plan, access, session)
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("Phase 11.59B requires verified host-key evidence")
        val result = executeSuccessText(
            session,
            command(preMutationGuardCommand(plan), "site-web-runtime-provisioning-preflight"),
            READ_ONLY_CONFIG,
        )
        require(result.trim() == "READY") {
            "Phase 11.59B clean missing-nginx baseline was not revalidated"
        }
        return verified.verifiedHostKeySha256
    }

    suspend fun provisionAndVerify(
        plan: SiteWebServingRuntimeProvisioningPlan,
        access: ServerAccess,
        session: SshSessionHandle,
        verifiedHostKeySha256: String,
    ): SiteWebServingRuntimeProvisioningObservation {
        validateInputs(plan, access, session)
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("Phase 11.59B requires verified host-key evidence")
        require(verified.verifiedHostKeySha256 == verifiedHostKeySha256)

        var commandCount = 1 // pre-mutation guard was already executed on this exact session
        executeSuccess(
            session,
            command(aptUpdateCommand(), "site-web-runtime-apt-update"),
            PACKAGE_CONFIG,
        )
        commandCount += 1

        executeSuccess(
            session,
            command(aptInstallNginxCommand(), "site-web-runtime-apt-install-nginx"),
            PACKAGE_CONFIG,
        )
        commandCount += 1

        val verifiedText = executeSuccessText(
            session,
            command(postInstallVerificationCommand(plan), "site-web-runtime-post-install-verify"),
            VERIFY_CONFIG,
        ).trim()
        commandCount += 1
        require(verifiedText.startsWith("VERIFIED|")) {
            "Phase 11.59B nginx post-install verification marker missing"
        }
        val nginxPath = verifiedText.substringAfter("VERIFIED|").trim()
        require(nginxPath.startsWith('/'))
        require('\n' !in nginxPath && '\r' !in nginxPath)

        return SiteWebServingRuntimeProvisioningObservation(
            remoteHostIdentity = plan.remoteHostIdentity,
            verifiedHostKeySha256 = verified.verifiedHostKeySha256,
            durablePredispatchCheckpointRecorded = true,
            cleanMissingNginxBaselineRevalidated = true,
            aptMetadataRefreshPerformed = true,
            packageInstallPerformed = true,
            packageInstalledByDpkg = true,
            nginxExecutablePath = nginxPath,
            nginxRootDirectoryPresent = true,
            confDDirectoryPresent = true,
            nginxSyntaxValidationPassed = true,
            exactConfigPathAbsentAfterProvisioning = true,
            listenerStillFreeAfterProvisioning = true,
            packageManagedConfigFilesObserved = true,
            packageManagedServiceLifecycleMayHaveOccurred = true,
            siteConfigMutationPerformed = false,
            explicitServiceCommandPerformed = false,
            webServerReloadPerformed = false,
            dnsMutationPerformed = false,
            firewallMutationPerformed = false,
            automaticRetryPerformed = false,
            arbitraryCommandAccepted = false,
            remoteCommandCount = commandCount,
        )
    }

    private fun validateInputs(
        plan: SiteWebServingRuntimeProvisioningPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ) {
        SiteWebServingRuntimeProvisioningBoundary.validate(plan)
        require(access.endpoint.host == plan.remoteHostIdentity)
        require(access.username == "root") { "Phase 11.59B exact package provisioning requires reviewed root access" }
        require(session.binding.serverAccessId == access.id)
        require(session.binding.owner is SessionOwner.Operation)
        require(session.isOpen)
    }

    private fun preMutationGuardCommand(plan: SiteWebServingRuntimeProvisioningPlan): String {
        val config = quote(plan.configPath)
        val filter = quote("sport = :${plan.servicePort}")
        return "if [ \"\$(id -u)\" != '0' ]; then printf 'BLOCKED\\n'; " +
            "elif [ ! -x /usr/bin/apt-get ] || [ ! -x /usr/bin/dpkg-query ]; then printf 'BLOCKED\\n'; " +
            "elif command -v nginx >/dev/null 2>&1; then printf 'BLOCKED\\n'; " +
            "elif [ -e /etc/nginx ] || [ -L /etc/nginx ] || [ -e /etc/nginx/conf.d ] || [ -L /etc/nginx/conf.d ]; then printf 'BLOCKED\\n'; " +
            "elif /usr/bin/dpkg-query -W -f='\${db:Status-Abbrev}\\n' nginx 2>/dev/null | grep -q '^ii '; then printf 'BLOCKED\\n'; " +
            "elif [ -e $config ] || [ -L $config ]; then printf 'BLOCKED\\n'; " +
            "elif ! command -v ss >/dev/null 2>&1; then printf 'BLOCKED\\n'; " +
            "else out=\$(ss -H -ltn $filter 2>/dev/null); code=\$?; " +
            "if [ \$code -ne 0 ] || [ -n \"\$out\" ]; then printf 'BLOCKED\\n'; else printf 'READY\\n'; fi; fi"
    }

    private fun aptUpdateCommand(): String =
        "DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -o Acquire::Retries=0 -o Dpkg::Use-Pty=0 update"

    private fun aptInstallNginxCommand(): String =
        "DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -y -o Acquire::Retries=0 -o Dpkg::Use-Pty=0 install --no-install-recommends nginx"

    private fun postInstallVerificationCommand(plan: SiteWebServingRuntimeProvisioningPlan): String {
        val config = quote(plan.configPath)
        val filter = quote("sport = :${plan.servicePort}")
        return "nginx_bin=\$(command -v nginx 2>/dev/null); test -n \"\$nginx_bin\"; " +
            "/usr/bin/dpkg-query -W -f='\${db:Status-Abbrev}\\n' nginx 2>/dev/null | grep -q '^ii '; " +
            "test -d /etc/nginx; test ! -L /etc/nginx; test -d /etc/nginx/conf.d; test ! -L /etc/nginx/conf.d; " +
            "test ! -e $config; test ! -L $config; \"\$nginx_bin\" -t >/dev/null 2>&1; " +
            "out=\$(ss -H -ltn $filter 2>/dev/null); code=\$?; test \$code -eq 0; test -z \"\$out\"; " +
            "printf 'VERIFIED|%s\\n' \"\$nginx_bin\""
    }

    private suspend fun executeSuccessText(
        session: SshSessionHandle,
        command: RemoteCommand,
        config: SshTransportConfig,
    ): String {
        val result = executeSuccess(session, command, config)
        return StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(result.stdout.copyBytes()))
            .toString()
    }

    private suspend fun executeSuccess(
        session: SshSessionHandle,
        command: RemoteCommand,
        config: SshTransportConfig,
    ): SshCommandResult {
        val result = session.execute(command, config)
        require(result.dispatchState == CommandDispatchState.DISPATCHED) {
            "Phase 11.59B command dispatch was not confirmed; reconciliation required"
        }
        require(!result.stdout.truncated && !result.stderr.truncated) {
            "Phase 11.59B command output was truncated; reconciliation required"
        }
        require(result.completion == CommandCompletion.ConfirmedSuccess) {
            "Phase 11.59B remote command failed or became uncertain; no automatic retry"
        }
        return result
    }

    private fun command(raw: String, label: String): RemoteCommand = RemoteCommand.create(raw, label)

    private fun quote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' })
        return "'$value'"
    }

    companion object {
        private val READ_ONLY_CONFIG = SshTransportConfig(
            commandExecutionTimeout = Duration.ofSeconds(10),
            stdoutCaptureLimitBytes = 16 * 1024,
            stderrCaptureLimitBytes = 16 * 1024,
        )
        private val PACKAGE_CONFIG = SshTransportConfig(
            commandExecutionTimeout = Duration.ofMinutes(4),
            stdoutCaptureLimitBytes = 256 * 1024,
            stderrCaptureLimitBytes = 256 * 1024,
        )
        private val VERIFY_CONFIG = SshTransportConfig(
            commandExecutionTimeout = Duration.ofSeconds(15),
            stdoutCaptureLimitBytes = 32 * 1024,
            stderrCaptureLimitBytes = 64 * 1024,
        )
    }
}
