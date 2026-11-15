package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.DiscoveryProbeParseResult
import com.velumtegra.xuimobile.core.domain.DiscoveryProbeParsers
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.DiscoveryObservation
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimePrerequisiteObservation
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Instant

/** Phase 11.59A finite read-only classifier for the missing nginx runtime prerequisite. */
class SiteWebServingRuntimePrerequisiteSshAdapter(
    private val now: () -> Instant = Instant::now,
) {
    suspend fun observe(
        plan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ): SiteWebServingRuntimePrerequisiteObservation {
        SiteWebServingPublicationPlanBoundary.validate(plan)
        require(access.endpoint.host == plan.remoteHostIdentity)
        require(session.binding.serverAccessId == access.id)
        require(session.binding.owner is SessionOwner.Operation)
        require(session.isOpen)
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("SSH session does not expose verified host-key evidence")

        var commandCount = 0
        suspend fun runText(raw: String, label: String): String {
            commandCount += 1
            return executeText(session, command(raw, label))
        }

        val platformRaw = runText("cat -- /etc/os-release", "site-web-prereq-os-release")
        val platform = when (val parsed = DiscoveryProbeParsers.parseOsRelease(platformRaw, now())) {
            is DiscoveryProbeParseResult.Parsed -> parsed.value
            DiscoveryProbeParseResult.Malformed -> error("Malformed /etc/os-release prerequisite evidence")
        }
        require(platform is DiscoveryObservation.Platform)

        val aptGet = executableOrNull(runText(executableCommand("apt-get"), "site-web-prereq-apt-get"))
        val dpkgQuery = executableOrNull(runText(executableCommand("dpkg-query"), "site-web-prereq-dpkg-query"))
        val nginx = executableOrNull(runText(executableCommand("nginx"), "site-web-prereq-nginx"))
        val nginxRootType = observePathType(
            "/etc/nginx",
            runText(pathTypeCommand("/etc/nginx"), "site-web-prereq-nginx-root"),
        )
        val confDType = observePathType(
            "/etc/nginx/conf.d",
            runText(pathTypeCommand("/etc/nginx/conf.d"), "site-web-prereq-conf-d"),
        )

        return SiteWebServingRuntimePrerequisiteObservation(
            remoteHostIdentity = plan.remoteHostIdentity,
            verifiedHostKeySha256 = verified.verifiedHostKeySha256,
            distributionId = platform.platform.distributionId,
            distributionVersionId = platform.platform.versionId,
            aptGetExecutablePath = aptGet,
            dpkgQueryExecutablePath = dpkgQuery,
            nginxExecutablePath = nginx,
            nginxRootPathType = nginxRootType,
            confDPathType = confDType,
            remoteCommandCount = commandCount,
            mutationOperationPerformed = false,
            arbitraryCommandAccepted = false,
        )
    }

    private fun executableCommand(name: String): String {
        require(name in setOf("apt-get", "dpkg-query", "nginx"))
        return "if p=\$(command -v $name 2>/dev/null); then printf '%s\\n' \"\$p\"; else printf 'ABSENT\\n'; fi"
    }

    private fun executableOrNull(text: String): String? = text.trim().let { raw ->
        if (raw == "ABSENT") null else raw.also {
            require(it.startsWith('/'))
            require('\n' !in it && '\r' !in it)
        }
    }

    private fun pathTypeCommand(path: String): String {
        val q = quote(path)
        return "if [ -L $q ]; then printf 'SYMLINK\\n'; " +
            "elif [ -d $q ]; then printf 'DIRECTORY\\n'; " +
            "elif [ -f $q ]; then printf 'FILE\\n'; " +
            "elif [ -e $q ]; then printf 'OTHER\\n'; else printf 'ABSENT\\n'; fi"
    }

    private fun observePathType(path: String, text: String): SiteWebServingObservedPathType {
        require(path.startsWith('/'))
        return SiteWebServingObservedPathType.valueOf(text.trim())
    }

    private suspend fun executeText(session: SshSessionHandle, command: RemoteCommand): String {
        val result = session.execute(command, READ_ONLY_CONFIG)
        require(result.dispatchState == CommandDispatchState.DISPATCHED)
        require(!result.stdout.truncated && !result.stderr.truncated)
        require(result.completion == CommandCompletion.ConfirmedSuccess)
        return StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(result.stdout.copyBytes()))
            .toString()
    }

    private fun command(raw: String, label: String): RemoteCommand = RemoteCommand.create(raw, label)

    private fun quote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' })
        return "'$value'"
    }

    companion object {
        private val READ_ONLY_CONFIG = SshTransportConfig(
            stdoutCaptureLimitBytes = 16 * 1024,
            stderrCaptureLimitBytes = 16 * 1024,
        )
    }
}
