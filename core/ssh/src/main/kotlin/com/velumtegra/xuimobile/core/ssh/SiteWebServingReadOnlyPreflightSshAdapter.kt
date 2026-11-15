package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteWebServingListenerState
import com.velumtegra.xuimobile.core.site.SiteWebServingObservedPathType
import com.velumtegra.xuimobile.core.site.SiteWebServingProtocol
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlanBoundary
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightObservation
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * Exact Phase 11.57 real-VPS read-only web-serving probe.
 *
 * The caller supplies only a validated publication plan and an already-open exact pinned-key SSH
 * session. No command string is accepted from callers. This adapter compiles a finite internal
 * command vocabulary that can only observe nginx discoverability, exact path types, exact config or
 * certificate SHA-256, and the exact requested TCP listener port. It never writes a config, reloads
 * a service, changes DNS/firewall/packages, reads private-key content, or dispatches arbitrary shell.
 */
class SiteWebServingReadOnlyPreflightSshAdapter {
    suspend fun observe(
        plan: SiteWebServingPublicationPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ): SiteWebServingReadOnlyPreflightObservation {
        SiteWebServingPublicationPlanBoundary.validate(plan)
        require(access.endpoint.host == plan.remoteHostIdentity) {
            "Web-serving preflight host differs from exact SSH endpoint"
        }
        require(session.binding.serverAccessId == access.id) { "SSH session is not bound to requested ServerAccess" }
        require(session.binding.owner is SessionOwner.Operation) { "Web-serving preflight requires operation-owned SSH session" }
        require(session.isOpen) { "SSH session is closed" }
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("SSH session does not expose verified host-key evidence")

        var commandCount = 0
        suspend fun runText(raw: String, label: String): String {
            commandCount += 1
            return executeText(session, command(raw, label))
        }

        val nginxExecutable = runText(
            "if p=\$(command -v nginx 2>/dev/null); then printf '%s\\n' \"\$p\"; else printf 'ABSENT\\n'; fi",
            "site-web-nginx-executable",
        ).trim().let { raw ->
            if (raw == "ABSENT") null else raw.also {
                require(it.startsWith('/')) { "Observed nginx executable is not an absolute path" }
                require('\n' !in it && '\r' !in it) { "Malformed nginx executable observation" }
            }
        }

        val confDType = observePathType(
            path = "/etc/nginx/conf.d",
            text = runText(pathTypeCommand("/etc/nginx/conf.d"), "site-web-conf-d-type"),
        )
        val configType = observePathType(
            path = plan.configPath,
            text = runText(pathTypeCommand(plan.configPath), "site-web-config-type"),
        )
        val existingConfigSha = if (configType == SiteWebServingObservedPathType.FILE) {
            parseSha256(runText(sha256Command(plan.configPath), "site-web-config-sha256"))
        } else null

        val listenerState = runText(listenerCommand(plan.port), "site-web-listener-port")
            .trim()
            .let(SiteWebServingListenerState::valueOf)

        var certificatePathType: SiteWebServingObservedPathType? = null
        var observedCertificateSha256: String? = null
        var privateKeyPathType: SiteWebServingObservedPathType? = null
        if (plan.protocol == SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE) {
            val certificatePath = requireNotNull(plan.certificatePath)
            val privateKeyPath = requireNotNull(plan.privateKeyPath)
            certificatePathType = observePathType(
                path = certificatePath,
                text = runText(pathTypeCommand(certificatePath), "site-web-certificate-type"),
            )
            if (certificatePathType == SiteWebServingObservedPathType.FILE) {
                observedCertificateSha256 = parseSha256(
                    runText(sha256Command(certificatePath), "site-web-certificate-sha256"),
                )
            }
            privateKeyPathType = observePathType(
                path = privateKeyPath,
                text = runText(pathTypeCommand(privateKeyPath), "site-web-private-key-type"),
            )
        }

        return SiteWebServingReadOnlyPreflightObservation(
            remoteHostIdentity = plan.remoteHostIdentity,
            verifiedHostKeySha256 = verified.verifiedHostKeySha256,
            nginxExecutablePath = nginxExecutable,
            confDPathType = confDType,
            configPath = plan.configPath,
            configPathType = configType,
            existingConfigSha256 = existingConfigSha,
            listenerState = listenerState,
            certificatePathType = certificatePathType,
            observedCertificateSha256 = observedCertificateSha256,
            privateKeyPathType = privateKeyPathType,
            remoteCommandCount = commandCount,
            mutationOperationPerformed = false,
            arbitraryCommandAccepted = false,
            privateKeyContentReadPerformed = false,
        )
    }

    private fun pathTypeCommand(path: String): String {
        val q = quote(path)
        return "if [ -L $q ]; then printf 'SYMLINK\\n'; " +
            "elif [ -d $q ]; then printf 'DIRECTORY\\n'; " +
            "elif [ -f $q ]; then printf 'FILE\\n'; " +
            "elif [ -e $q ]; then printf 'OTHER\\n'; " +
            "else printf 'ABSENT\\n'; fi"
    }

    private fun sha256Command(path: String): String = "sha256sum -- ${quote(path)}"

    private fun listenerCommand(port: Int): String {
        require(port in 1..65535)
        val filter = quote("sport = :$port")
        return "if ! command -v ss >/dev/null 2>&1; then printf 'OBSERVER_UNAVAILABLE\\n'; " +
            "else out=\$(ss -H -ltn $filter 2>/dev/null); code=\$?; " +
            "if [ \$code -ne 0 ]; then printf 'OBSERVER_UNAVAILABLE\\n'; " +
            "elif [ -n \"\$out\" ]; then printf 'OCCUPIED\\n'; else printf 'FREE\\n'; fi; fi"
    }

    private fun observePathType(path: String, text: String): SiteWebServingObservedPathType {
        require(path.startsWith('/'))
        return SiteWebServingObservedPathType.valueOf(text.trim())
    }

    private fun parseSha256(text: String): String {
        val value = text.trim().substringBefore(' ')
        require(value.matches(Regex("^[0-9a-f]{64}$"))) { "Malformed remote SHA-256 observation" }
        return value
    }

    private suspend fun executeText(session: SshSessionHandle, command: RemoteCommand): String {
        val result = session.execute(command, READ_ONLY_CONFIG)
        require(result.dispatchState == CommandDispatchState.DISPATCHED) { "Read-only web-serving command was not dispatched" }
        require(!result.stdout.truncated && !result.stderr.truncated) { "Read-only web-serving output was truncated" }
        require(result.completion == CommandCompletion.ConfirmedSuccess) { "Read-only web-serving command failed" }
        return decodeUtf8(result.stdout.copyBytes())
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
        private val READ_ONLY_CONFIG = SshTransportConfig(
            stdoutCaptureLimitBytes = 16 * 1024,
            stderrCaptureLimitBytes = 16 * 1024,
        )
    }
}
