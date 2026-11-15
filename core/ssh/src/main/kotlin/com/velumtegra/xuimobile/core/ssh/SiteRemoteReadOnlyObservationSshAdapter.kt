package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteRemoteReadOnlyDigest
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPlan
import com.velumtegra.xuimobile.core.site.SiteCertificateReuseMode
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPolicy
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPath
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import com.velumtegra.xuimobile.core.site.SiteRemoteOwnershipObservation
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteServerObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportTreeEntrySpec
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportTreeObservation
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * Read-only SSH evidence collector for Site Deployer.
 *
 * It accepts only a validated deployment plan plus one exact already-open pinned-key session.
 * Every remote command belongs to a finite read-only vocabulary. There is no upload, mkdir,
 * rename, delete, chmod/chown, certificate copy, shell script upload or arbitrary command input.
 */
class SiteRemoteReadOnlyObservationSshAdapter {
    suspend fun collectPreflight(
        plan: SiteRemoteDeployPlan,
        access: ServerAccess,
        session: SshSessionHandle,
    ): SiteRemotePreflightObservation {
        SiteRemoteDeployPolicy.validatePlan(plan)
        require(access.endpoint.host == plan.remoteHostIdentity) { "Remote host identity does not match exact SSH endpoint" }
        require(session.binding.serverAccessId == access.id) { "SSH session is not bound to the requested ServerAccess" }
        require(session.binding.owner is SessionOwner.Operation) { "Site observation requires an operation-owned SSH session" }
        require(plan.certificate.mode == SiteCertificateReuseMode.NONE) { "Certificate reuse evidence is not part of the Phase 11.10 read-only adapter" }
        require(session.isOpen) { "SSH session is closed" }
        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("SSH session does not expose verified host-key evidence")

        val target = observePath(plan.publish.targetRoot, session)
        val staging = observePath(plan.publish.stagingRoot, session)
        val backup = when (plan.publish.existingTargetPolicy) {
            SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> null
            SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> observePath(requireNotNull(plan.publish.backupRoot), session)
        }
        val parent = plan.publish.targetRoot.substringBeforeLast('/').ifBlank { "/" }
        val available = parseLong(executeText(session, command(
            "df -Pk -- ${quote(parent)} | awk 'NR==2 {print \$4}'",
            "site-observe-capacity",
        )), "available capacity")

        val ownerExists = executePresence(session, "getent passwd ${quote(plan.publish.owner)} >/dev/null 2>&1", "site-observe-owner")
        val groupExists = executePresence(session, "getent group ${quote(plan.publish.group)} >/dev/null 2>&1", "site-observe-group")
        val identity = executeText(session, command("id -u; id -un; id -Gn", "site-observe-identity"))
            .lineSequence().map(String::trim).filter(String::isNotEmpty).toList()
        require(identity.size == 3) { "Malformed remote identity observation" }
        val uid = identity[0].toLongOrNull() ?: error("Malformed remote uid")
        val username = identity[1]
        val groups = identity[2].split(Regex("\\s+")).filter(String::isNotBlank).toSet()
        val ownerMatches = username == plan.publish.owner
        val groupUsable = plan.publish.group in groups

        return SiteRemotePreflightObservation(
            server = SiteRemoteServerObservation(plan.remoteHostIdentity, verified.verifiedHostKeySha256),
            target = target,
            staging = staging,
            backup = backup,
            availableBytes = Math.multiplyExact(available, 1024L),
            ownership = SiteRemoteOwnershipObservation(
                ownerExists = ownerExists,
                groupExists = groupExists,
                ownershipChangeApplicable = uid == 0L || (ownerMatches && groupUsable),
                modeChangeApplicable = uid == 0L || ownerMatches,
            ),
            certificate = null,
        )
    }

    suspend fun observeFileSha256(remotePath: String, session: SshSessionHandle): String {
        val path = SiteRemoteDeployPolicy.prepareTargetRoot(remotePath)
        val line = executeText(session, command("sha256sum -- ${quote(path)}", "site-observe-file-sha256"))
        val hash = line.trim().substringBefore(' ')
        require(hash.matches(Regex("^[0-9a-f]{64}$"))) { "Malformed remote SHA-256 observation" }
        return hash
    }

    suspend fun observeTree(
        rootPath: String,
        entries: List<SiteRemoteTransportTreeEntrySpec>,
        session: SshSessionHandle,
    ): SiteRemoteTransportTreeObservation {
        val root = SiteRemoteDeployPolicy.prepareTargetRoot(rootPath)
        require(entries.isNotEmpty()) { "Tree observation requires at least one entry" }
        val contents = entries.associate { entry ->
            val remotePath = "$root/${entry.relativePath}"
            entry.relativePath to executeBytes(session, command("cat -- ${quote(remotePath)}", "site-observe-tree-file"))
        }
        return SiteRemoteTransportTreeObservation(
            rootPath = root,
            treeSha256 = SiteRemoteReadOnlyDigest.treeSha256(entries, contents),
            fileCount = entries.size,
            totalBytes = contents.values.sumOf { it.size.toLong() },
        )
    }

    private suspend fun observePath(path: String, session: SshSessionHandle): SiteRemoteObservedPath {
        val safe = SiteRemoteDeployPolicy.prepareTargetRoot(path)
        val raw = executeText(session, command(
            "if [ -L ${quote(safe)} ]; then printf 'SYMLINK\\t0\\n'; " +
                "elif [ -d ${quote(safe)} ]; then printf 'DIRECTORY\\t0\\n'; " +
                "elif [ -f ${quote(safe)} ]; then printf 'FILE\\t'; wc -c < ${quote(safe)}; " +
                "elif [ -e ${quote(safe)} ]; then printf 'OTHER\\t0\\n'; " +
                "else printf 'ABSENT\\t0\\n'; fi",
            "site-observe-path",
        )).trim()
        val parts = raw.split('\t')
        require(parts.size == 2) { "Malformed remote path observation" }
        val type = SiteRemoteObservedPathType.valueOf(parts[0])
        val bytes = parseLong(parts[1], "remote path size")
        require(bytes >= 0) { "Remote path size must not be negative" }
        return SiteRemoteObservedPath(safe, type, bytes)
    }

    private suspend fun executePresence(session: SshSessionHandle, raw: String, label: String): Boolean {
        val result = session.execute(command(raw, label), READ_ONLY_CONFIG)
        require(result.dispatchState == CommandDispatchState.DISPATCHED) { "Read-only observation command was not dispatched" }
        require(!result.stdout.truncated && !result.stderr.truncated) { "Read-only observation output was truncated" }
        return when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> true
            is CommandCompletion.ConfirmedFailure -> when (completion.exitCode) {
                1, 2 -> false
                else -> error("Read-only presence observation failed")
            }
            is CommandCompletion.Unknown -> error("Read-only presence observation completion is unknown")
        }
    }

    private suspend fun executeText(session: SshSessionHandle, command: RemoteCommand): String =
        decodeUtf8(executeBytes(session, command))

    private suspend fun executeBytes(session: SshSessionHandle, command: RemoteCommand): ByteArray {
        val result = session.execute(command, READ_ONLY_CONFIG)
        require(result.dispatchState == CommandDispatchState.DISPATCHED) { "Read-only observation command was not dispatched" }
        require(!result.stdout.truncated && !result.stderr.truncated) { "Read-only observation output was truncated" }
        require(result.completion == CommandCompletion.ConfirmedSuccess) { "Read-only observation command failed" }
        return result.stdout.copyBytes()
    }

    private fun command(raw: String, label: String): RemoteCommand = RemoteCommand.create(raw, label)

    private fun quote(value: String): String {
        require(value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' }) { "Unsafe shell token" }
        return "'$value'"
    }

    private fun parseLong(value: String, label: String): Long =
        value.trim().toLongOrNull() ?: error("Malformed $label observation")

    private fun decodeUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(java.nio.ByteBuffer.wrap(bytes))
        .toString()

    companion object {
        private val READ_ONLY_CONFIG = SshTransportConfig(
            stdoutCaptureLimitBytes = SshTransportConfig.MAX_CAPTURE_BYTES,
            stderrCaptureLimitBytes = 64 * 1024,
        )
    }
}
