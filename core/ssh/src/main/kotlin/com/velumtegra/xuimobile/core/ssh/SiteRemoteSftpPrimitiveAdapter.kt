package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteBuildPolicy
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import com.velumtegra.xuimobile.core.site.SiteRemoteReadOnlyDigest
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportAuthorization
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportCapabilities
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportCapability
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportOperation
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportPrimitivePort
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportRenamePurpose
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportTreeEntrySpec
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportTreeObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportPolicy
import java.security.MessageDigest
import java.util.ArrayDeque

/**
 * Opens one authorization-bound SFTP primitive lease behind SiteRemoteTransportExecutor.
 *
 * The returned port cannot address arbitrary remote paths: every mutation/read is checked against
 * the exact typed operations already present in [authorization]. No VPS/UI integration is provided
 * here; Phase 11.11 is the bounded transport primitive only.
 */
class SiteRemoteSftpPrimitiveFactory {
    suspend fun open(
        authorization: SiteRemoteTransportAuthorization,
        access: ServerAccess,
        session: SshSessionHandle,
    ): SiteRemoteSftpPrimitivePort {
        SiteRemoteTransportPolicy.validateAuthorization(authorization)
        require(authorization.implementationId == CAPABILITIES.implementationId) {
            "Transport authorization was prepared for a different implementation"
        }
        require(authorization.capabilityProfileSha256 == SiteRemoteTransportPolicy.capabilityProfileSha256(CAPABILITIES)) {
            "Transport authorization capability profile mismatch"
        }
        require(access.endpoint.host == authorization.remoteHostIdentity) { "Authorization host does not match exact SSH endpoint" }
        require(session.binding.serverAccessId == access.id) { "SSH session is bound to a different ServerAccess" }
        require(session.binding.owner is SessionOwner.Operation) { "SFTP deployment requires an operation-owned SSH session" }
        require(session.isOpen) { "SSH session is closed" }

        val verified = session as? VerifiedHostKeySshSessionHandle
            ?: error("SSH session does not expose verified host-key evidence")
        val expectedPin = when (val parsed = CanonicalHostKeyFingerprint.parse(access.pinnedHostKey)) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
            is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
        }
        require(MessageDigest.isEqual(expectedPin.encodeToByteArray(), verified.verifiedHostKeySha256.encodeToByteArray())) {
            "Exact SSH session host-key evidence no longer matches ServerAccess pin"
        }

        val sftpSession = session as? SiteRemoteSftpCapableSessionHandle
            ?: error("SSH session does not expose the bounded Site SFTP channel")
        val identity = resolveIdentity(authorization, session)
        val channel = sftpSession.openSiteRemoteSftpChannel()
        return try {
            SiteRemoteSftpPrimitivePort(
                authorization = authorization,
                channel = channel,
                desiredUid = identity.uid,
                desiredGid = identity.gid,
            )
        } catch (failure: Throwable) {
            runCatching { channel.close() }
            throw failure
        }
    }

    private suspend fun resolveIdentity(
        authorization: SiteRemoteTransportAuthorization,
        session: SshSessionHandle,
    ): ResolvedIdentity {
        val metadata = authorization.forwardOperations.mapNotNull { operation ->
            when (operation) {
                is SiteRemoteTransportOperation.CreateDirectory -> operation.owner to operation.group
                is SiteRemoteTransportOperation.ApplyFileMetadata -> operation.owner to operation.group
                is SiteRemoteTransportOperation.ApplyDirectoryMetadata -> operation.owner to operation.group
                else -> null
            }
        }.distinct()
        require(metadata.size == 1) { "Authorization must use one exact owner/group pair" }
        val (owner, group) = metadata.single()
        val passwd = executeReadOnly(session, "getent passwd ${quote(owner)}", "site-sftp-resolve-owner")
        val groupLine = executeReadOnly(session, "getent group ${quote(group)}", "site-sftp-resolve-group")
        val passwdParts = passwd.trim().split(':')
        val groupParts = groupLine.trim().split(':')
        require(passwdParts.size >= 4 && passwdParts[0] == owner) { "Malformed owner account evidence" }
        require(groupParts.size >= 3 && groupParts[0] == group) { "Malformed group account evidence" }
        val uid = passwdParts[2].toIntOrNull() ?: error("Malformed owner uid evidence")
        val gid = groupParts[2].toIntOrNull() ?: error("Malformed group gid evidence")
        require(uid >= 0 && gid >= 0) { "Remote uid/gid evidence must be non-negative" }
        return ResolvedIdentity(uid, gid)
    }

    private suspend fun executeReadOnly(session: SshSessionHandle, raw: String, label: String): String {
        val result = session.execute(RemoteCommand.create(raw, label), IDENTITY_CONFIG)
        require(result.dispatchState == CommandDispatchState.DISPATCHED) { "Identity observation command was not dispatched" }
        require(result.completion == CommandCompletion.ConfirmedSuccess) { "Identity observation command failed" }
        require(!result.stdout.truncated && !result.stderr.truncated) { "Identity observation output was truncated" }
        return result.stdout.copyBytes().decodeToString()
    }

    private fun quote(value: String): String {
        require(value.isNotBlank() && value.none { it == '\'' || it == '\n' || it == '\r' || it == '\u0000' }) {
            "Unsafe identity token"
        }
        return "'$value'"
    }

    private data class ResolvedIdentity(val uid: Int, val gid: Int)

    companion object {
        val CAPABILITIES = SiteRemoteTransportCapabilities(
            implementationId = "jsch-sftp-bounded-v1",
            capabilities = SiteRemoteTransportCapability.entries.sortedBy { it.name },
            maxFiles = SiteBuildPolicy.MAX_DOCUMENTS,
            maxTotalBytes = SiteBuildPolicy.MAX_TOTAL_BYTES,
            maxSingleFileBytes = SiteBuildPolicy.MAX_DOCUMENT_BYTES,
            maxRemotePathLength = 1024,
        ).also(SiteRemoteTransportPolicy::validateCapabilities)

        private val IDENTITY_CONFIG = SshTransportConfig(
            stdoutCaptureLimitBytes = 8 * 1024,
            stderrCaptureLimitBytes = 8 * 1024,
        )
    }
}

class SiteRemoteSftpPrimitivePort internal constructor(
    private val authorization: SiteRemoteTransportAuthorization,
    private val channel: SiteRemoteSftpChannelHandle,
    private val desiredUid: Int,
    private val desiredGid: Int,
) : SiteRemoteTransportPrimitivePort, AutoCloseable {
    override val capabilities: SiteRemoteTransportCapabilities = SiteRemoteSftpPrimitiveFactory.CAPABILITIES

    private val asserts = authorization.forwardOperations.filterIsInstance<SiteRemoteTransportOperation.AssertPathState>()
    private val createDirectories = authorization.forwardOperations.filterIsInstance<SiteRemoteTransportOperation.CreateDirectory>()
        .associateBy { it.path }
    private val uploads = authorization.forwardOperations.filterIsInstance<SiteRemoteTransportOperation.UploadFile>()
        .associateBy { it.remotePath }
    private val verifyFiles = authorization.forwardOperations.filterIsInstance<SiteRemoteTransportOperation.VerifyFileSha256>()
        .associateBy { it.remotePath }
    private val metadata = (authorization.forwardOperations.mapNotNull { operation ->
        when (operation) {
            is SiteRemoteTransportOperation.ApplyFileMetadata -> Metadata(operation.remotePath, operation.owner, operation.group, operation.mode, SiteRemoteObservedPathType.FILE)
            is SiteRemoteTransportOperation.ApplyDirectoryMetadata -> Metadata(operation.remotePath, operation.owner, operation.group, operation.mode, SiteRemoteObservedPathType.DIRECTORY)
            else -> null
        }
    }).associateBy { it.path }
    private val treeChecks = authorization.forwardOperations.filterIsInstance<SiteRemoteTransportOperation.VerifyTree>()
        .associateBy { it.rootPath }
    private val renames = (authorization.forwardOperations + authorization.rollbackOperations)
        .filterIsInstance<SiteRemoteTransportOperation.AtomicRename>()
        .associateBy { RenameKey(it.fromPath, it.toPath) }
    private val cleanupRoots = authorization.rollbackOperations.filterIsInstance<SiteRemoteTransportOperation.RemoveTransactionTree>()
        .associateBy { it.path }
    private val treeSpecs = uploads.values.sortedBy { it.relativePath }
        .map { SiteRemoteTransportTreeEntrySpec(it.relativePath, it.mediaType) }
    private val stagingRoot = renames.values.single { it.purpose == SiteRemoteTransportRenamePurpose.STAGING_TO_TARGET }.fromPath
    private val targetRoot = renames.values.single { it.purpose == SiteRemoteTransportRenamePurpose.STAGING_TO_TARGET }.toPath
    private val backupRoot = renames.values.singleOrNull { it.purpose == SiteRemoteTransportRenamePurpose.TARGET_TO_BACKUP }?.toPath
    private val allowedStatPaths = buildSet {
        asserts.forEach { add(it.path) }
        createDirectories.keys.forEach(::add)
        uploads.keys.forEach(::add)
        verifyFiles.keys.forEach(::add)
        metadata.keys.forEach(::add)
        treeChecks.keys.forEach(::add)
        renames.keys.forEach { add(it.from); add(it.to) }
        cleanupRoots.keys.forEach(::add)
    }

    private var stagingOwned = false
    private var publishedTargetOwned = false
    private var ownershipAmbiguous = false
    private var closed = false

    init {
        SiteRemoteTransportPolicy.validateAuthorization(authorization)
        require(authorization.implementationId == capabilities.implementationId)
        require(authorization.capabilityProfileSha256 == SiteRemoteTransportPolicy.capabilityProfileSha256(capabilities))
        require(channel.isOpen) { "SFTP channel is not open" }
        verifyMutableRootAncestors(stagingRoot)
        verifyMutableRootAncestors(targetRoot)
        backupRoot?.let(::verifyMutableRootAncestors)
    }

    override fun statPath(path: String): SiteRemoteObservedPathType {
        ensureOpen()
        require(path in allowedStatPaths) { "Path is outside authorization-bound SFTP stat surface" }
        return channel.lstat(path).type
    }

    override fun createDirectory(path: String, owner: String, group: String, mode: String) {
        ensureOpen()
        val operation = requireNotNull(createDirectories[path]) { "Directory creation is not authorized" }
        require(operation.owner == owner && operation.group == group && operation.mode == mode) { "Directory metadata intent differs from authorization" }
        require(channel.lstat(path).type == SiteRemoteObservedPathType.ABSENT) { "Authorized directory path is no longer absent" }
        if (path != stagingRoot) {
            require(stagingOwned) { "Nested staging directory cannot be created before owned staging root" }
            require(isStrictDescendant(stagingRoot, path)) { "Nested directory escaped staging root" }
            require(channel.lstat(parent(path)).type == SiteRemoteObservedPathType.DIRECTORY) { "Nested staging parent is not a directory" }
        }
        channel.mkdir(path)
        val created = channel.lstat(path)
        require(created.type == SiteRemoteObservedPathType.DIRECTORY) { "SFTP mkdir did not create a directory" }
        // Keep the transaction tree private until explicit ApplyDirectoryMetadata operations run.
        channel.chmod(path, PRIVATE_DIRECTORY_MODE)
        if (path == stagingRoot) stagingOwned = true
    }

    override fun uploadFile(remotePath: String, payload: ByteArray) {
        ensureOpen()
        require(stagingOwned && !ownershipAmbiguous) { "Upload requires an unambiguous owned staging tree" }
        val operation = requireNotNull(uploads[remotePath]) { "File upload is not authorized" }
        require(isStrictDescendant(stagingRoot, remotePath)) { "Upload escaped staging root" }
        require(payload.size == operation.byteSize) { "Upload byte size differs from authorization" }
        require(payload.size <= capabilities.maxSingleFileBytes) { "Upload exceeds SFTP single-file bound" }
        require(sha256(payload) == operation.sha256) { "Upload SHA-256 differs from authorization" }
        require(channel.lstat(parent(remotePath)).type == SiteRemoteObservedPathType.DIRECTORY) { "Upload parent is not a directory" }
        require(channel.lstat(remotePath).type == SiteRemoteObservedPathType.ABSENT) { "Authorized upload path is no longer absent" }
        channel.writeFile(remotePath, payload.copyOf())
        val written = channel.lstat(remotePath)
        require(written.type == SiteRemoteObservedPathType.FILE && written.sizeBytes == payload.size.toLong()) {
            "SFTP upload postcondition failed"
        }
    }

    override fun fileSha256(remotePath: String): String {
        ensureOpen()
        val operation = requireNotNull(verifyFiles[remotePath]) { "File hash verification is not authorized" }
        val upload = requireNotNull(uploads[remotePath]) { "File hash path has no authorized upload" }
        val observation = channel.lstat(remotePath)
        require(observation.type == SiteRemoteObservedPathType.FILE) { "Remote hash target is not a regular file" }
        require(observation.sizeBytes == upload.byteSize.toLong()) { "Remote hash target size mismatch" }
        val bytes = channel.readFile(remotePath, upload.byteSize + 1)
        require(bytes.size == upload.byteSize) { "Remote file read size mismatch" }
        return sha256(bytes).also { require(it == operation.expectedSha256) { "Remote file SHA-256 mismatch" } }
    }

    override fun applyMetadata(path: String, owner: String, group: String, mode: String) {
        ensureOpen()
        require(!ownershipAmbiguous) { "Metadata mutation is forbidden after ambiguous ownership state" }
        val expected = requireNotNull(metadata[path]) { "Metadata mutation is not authorized" }
        require(expected.owner == owner && expected.group == group && expected.mode == mode) { "Metadata differs from authorization" }
        require(path == stagingRoot || isStrictDescendant(stagingRoot, path)) { "Metadata mutation escaped staging tree" }
        require(stagingOwned) { "Metadata mutation requires owned staging tree" }
        val observed = channel.lstat(path)
        require(observed.type == expected.type) { "Metadata target type changed" }
        channel.chown(path, desiredUid)
        channel.chgrp(path, desiredGid)
        channel.chmod(path, parseMode(mode))
        val after = channel.lstat(path)
        require(after.type == expected.type && after.uid == desiredUid && after.gid == desiredGid) { "Owner/group metadata postcondition failed" }
        require(after.permissions and PERMISSION_MASK == parseMode(mode)) { "Mode metadata postcondition failed" }
    }

    override fun inspectTree(
        rootPath: String,
        entries: List<SiteRemoteTransportTreeEntrySpec>,
    ): SiteRemoteTransportTreeObservation {
        ensureOpen()
        val operation = requireNotNull(treeChecks[rootPath]) { "Tree verification is not authorized" }
        require(entries == treeSpecs) { "Tree entry specification differs from authorization" }
        val root = channel.lstat(rootPath)
        require(root.type == SiteRemoteObservedPathType.DIRECTORY) { "Tree root is not a directory" }

        val actualFiles = linkedSetOf<String>()
        val actualDirectories = linkedSetOf<String>()
        enumerateTree(rootPath, "", actualFiles, actualDirectories)
        val expectedFiles = treeSpecs.map { it.relativePath }.toSortedSet()
        val expectedDirectories = expectedDirectoryPaths(expectedFiles)
        require(actualFiles.toSortedSet() == expectedFiles) { "Remote tree contains missing or unexpected files" }
        require(actualDirectories.toSortedSet() == expectedDirectories) { "Remote tree contains unexpected directories" }

        val contents = LinkedHashMap<String, ByteArray>(treeSpecs.size)
        var total = 0L
        treeSpecs.forEach { spec ->
            val upload = uploads.values.single { it.relativePath == spec.relativePath }
            val remotePath = "$rootPath/${spec.relativePath}"
            val observed = channel.lstat(remotePath)
            require(observed.type == SiteRemoteObservedPathType.FILE && observed.sizeBytes == upload.byteSize.toLong()) {
                "Remote tree file type/size mismatch"
            }
            val bytes = channel.readFile(remotePath, upload.byteSize + 1)
            require(bytes.size == upload.byteSize) { "Remote tree file read size mismatch" }
            require(sha256(bytes) == upload.sha256) { "Remote tree file SHA-256 mismatch" }
            contents[spec.relativePath] = bytes
            total += bytes.size
        }
        val treeSha = SiteRemoteReadOnlyDigest.treeSha256(treeSpecs, contents)
        require(treeSha == operation.expectedTreeSha256) { "Remote tree SHA-256 mismatch" }
        require(total == operation.totalBytes && actualFiles.size == operation.fileCount) { "Remote tree bounds mismatch" }
        return SiteRemoteTransportTreeObservation(rootPath, treeSha, actualFiles.size, total)
    }

    override fun atomicRename(fromPath: String, toPath: String) {
        ensureOpen()
        require(!ownershipAmbiguous) { "Rename is forbidden after ambiguous ownership state" }
        val operation = requireNotNull(renames[RenameKey(fromPath, toPath)]) { "Rename is not authorized" }
        val sourceBefore = channel.lstat(fromPath)
        val targetBefore = channel.lstat(toPath)
        require(sourceBefore.type == SiteRemoteObservedPathType.DIRECTORY) { "Rename source is not a directory" }
        require(targetBefore.type == SiteRemoteObservedPathType.ABSENT) { "Rename destination is no longer absent" }
        when (operation.purpose) {
            SiteRemoteTransportRenamePurpose.STAGING_TO_TARGET -> require(stagingOwned) { "Publish rename requires owned staging tree" }
            SiteRemoteTransportRenamePurpose.TARGET_TO_BACKUP -> require(!publishedTargetOwned) { "Pre-existing target backup state is inconsistent" }
            SiteRemoteTransportRenamePurpose.BACKUP_TO_TARGET_ROLLBACK -> require(!publishedTargetOwned) { "Rollback restore requires target to be transaction-clean" }
        }
        try {
            channel.rename(fromPath, toPath)
            applyRenameOwnership(operation)
        } catch (failure: Throwable) {
            reconcileRenameOwnership(operation)
            throw failure
        }
    }

    override fun removeTransactionTree(path: String) {
        ensureOpen()
        require(!ownershipAmbiguous) { "Cleanup is forbidden after ambiguous ownership state" }
        val operation = requireNotNull(cleanupRoots[path]) { "Transaction cleanup path is not authorized" }
        require(operation.transactionOwnedOnly) { "Cleanup authorization is not transaction-owned-only" }
        when (path) {
            stagingRoot -> require(stagingOwned) { "Staging cleanup denied because ownership is not proven" }
            targetRoot -> require(publishedTargetOwned) { "Published-target cleanup denied because ownership is not proven" }
            else -> error("Cleanup root is not transaction-owned")
        }
        removeTree(path)
        when (path) {
            stagingRoot -> stagingOwned = false
            targetRoot -> publishedTargetOwned = false
        }
    }

    override fun close() {
        if (!closed) {
            closed = true
            channel.close()
        }
    }

    private fun applyRenameOwnership(operation: SiteRemoteTransportOperation.AtomicRename) {
        when (operation.purpose) {
            SiteRemoteTransportRenamePurpose.TARGET_TO_BACKUP -> Unit
            SiteRemoteTransportRenamePurpose.STAGING_TO_TARGET -> {
                stagingOwned = false
                publishedTargetOwned = true
            }
            SiteRemoteTransportRenamePurpose.BACKUP_TO_TARGET_ROLLBACK -> Unit
        }
    }

    private fun reconcileRenameOwnership(operation: SiteRemoteTransportOperation.AtomicRename) {
        val from = runCatching { channel.lstat(operation.fromPath).type }.getOrNull()
        val to = runCatching { channel.lstat(operation.toPath).type }.getOrNull()
        when (operation.purpose) {
            SiteRemoteTransportRenamePurpose.STAGING_TO_TARGET -> when {
                from == SiteRemoteObservedPathType.ABSENT && to == SiteRemoteObservedPathType.DIRECTORY -> {
                    stagingOwned = false
                    publishedTargetOwned = true
                }
                from == SiteRemoteObservedPathType.DIRECTORY && to == SiteRemoteObservedPathType.ABSENT -> Unit
                else -> ownershipAmbiguous = true
            }
            SiteRemoteTransportRenamePurpose.TARGET_TO_BACKUP,
            SiteRemoteTransportRenamePurpose.BACKUP_TO_TARGET_ROLLBACK,
            -> if (!(
                (from == SiteRemoteObservedPathType.ABSENT && to == SiteRemoteObservedPathType.DIRECTORY) ||
                    (from == SiteRemoteObservedPathType.DIRECTORY && to == SiteRemoteObservedPathType.ABSENT)
                )) ownershipAmbiguous = true
        }
    }

    private fun enumerateTree(
        rootPath: String,
        relativeDirectory: String,
        files: MutableSet<String>,
        directories: MutableSet<String>,
    ) {
        require(files.size + directories.size <= MAX_ENUMERATED_ENTRIES) { "Remote tree exceeds enumeration bound" }
        val absolute = if (relativeDirectory.isEmpty()) rootPath else "$rootPath/$relativeDirectory"
        channel.listDirectory(absolute, MAX_ENUMERATED_ENTRIES - files.size - directories.size + 1)
            .filter { it.name != "." && it.name != ".." }
            .sortedBy { it.name }
            .forEach { entry ->
            require(entry.name.isNotBlank()) { "Unsafe SFTP directory entry" }
            require('/' !in entry.name && '\\' !in entry.name && '\u0000' !in entry.name) { "Unsafe SFTP directory entry name" }
            val relative = if (relativeDirectory.isEmpty()) entry.name else "$relativeDirectory/${entry.name}"
            when (entry.observation.type) {
                SiteRemoteObservedPathType.FILE -> files += relative
                SiteRemoteObservedPathType.DIRECTORY -> {
                    directories += relative
                    enumerateTree(rootPath, relative, files, directories)
                }
                SiteRemoteObservedPathType.SYMLINK -> error("Symlink is forbidden inside deployment tree")
                SiteRemoteObservedPathType.OTHER -> error("Unsupported remote filesystem entry inside deployment tree")
                SiteRemoteObservedPathType.ABSENT -> error("Directory listing returned an absent entry")
            }
        }
    }

    private fun removeTree(rootPath: String) {
        val root = channel.lstat(rootPath)
        if (root.type == SiteRemoteObservedPathType.ABSENT) return
        require(root.type == SiteRemoteObservedPathType.DIRECTORY) { "Transaction cleanup root changed type" }
        var visited = 0
        val stack = ArrayDeque<Pair<String, Boolean>>()
        stack.addLast(rootPath to false)
        while (stack.isNotEmpty()) {
            val (path, expanded) = stack.removeLast()
            visited += 1
            require(visited <= MAX_ENUMERATED_ENTRIES * 2) { "Transaction cleanup tree exceeds bound" }
            if (expanded) {
                channel.removeDirectory(path)
                continue
            }
            stack.addLast(path to true)
            val entries = channel.listDirectory(path, MAX_ENUMERATED_ENTRIES + 1).filter { it.name != "." && it.name != ".." }.sortedByDescending { it.name }
            entries.forEach { entry ->
                require(entry.name.isNotBlank() && '/' !in entry.name && '\\' !in entry.name && '\u0000' !in entry.name) {
                    "Unsafe cleanup directory entry"
                }
                val child = "$path/${entry.name}"
                when (entry.observation.type) {
                    SiteRemoteObservedPathType.DIRECTORY -> stack.addLast(child to false)
                    SiteRemoteObservedPathType.FILE,
                    SiteRemoteObservedPathType.SYMLINK,
                    -> channel.removeFile(child)
                    SiteRemoteObservedPathType.OTHER -> error("Unsupported entry blocks safe transaction cleanup")
                    SiteRemoteObservedPathType.ABSENT -> Unit
                }
            }
        }
    }

    private fun verifyMutableRootAncestors(root: String) {
        var current = parent(root)
        val ancestors = mutableListOf<String>()
        while (current != "/") {
            ancestors += current
            current = parent(current)
        }
        ancestors.asReversed().forEach { ancestor ->
            val type = channel.lstat(ancestor).type
            require(type == SiteRemoteObservedPathType.DIRECTORY) { "Mutable remote-root ancestor is not a real directory: $ancestor" }
        }
    }

    private fun expectedDirectoryPaths(files: Set<String>): java.util.SortedSet<String> = buildSet {
        files.forEach { file ->
            val segments = file.split('/')
            for (index in 1 until segments.size) add(segments.take(index).joinToString("/"))
        }
    }.toSortedSet()

    private fun parseMode(value: String): Int = value.toInt(8).also {
        require(it in 0..PERMISSION_MASK) { "Remote mode is outside permission mask" }
    }

    private fun ensureOpen() {
        require(!closed && channel.isOpen) { "SFTP primitive lease is closed" }
    }

    private fun parent(path: String): String = path.substringBeforeLast('/').ifBlank { "/" }

    private fun isStrictDescendant(root: String, path: String): Boolean = path.startsWith("$root/")

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private data class Metadata(
        val path: String,
        val owner: String,
        val group: String,
        val mode: String,
        val type: SiteRemoteObservedPathType,
    )

    private data class RenameKey(val from: String, val to: String)

    private companion object {
        const val PRIVATE_DIRECTORY_MODE = 448 // 0700
        const val PERMISSION_MASK = 4095 // 07777
        const val MAX_ENUMERATED_ENTRIES = SiteBuildPolicy.MAX_DOCUMENTS * 4
    }
}
