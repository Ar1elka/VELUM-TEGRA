package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.site.SiteDeployerCommitTransactionBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerPostTransactionCleanupBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerPostTransactionCleanupPlan
import com.velumtegra.xuimobile.core.site.SiteDeployerRemoteTreeExpectation
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import com.velumtegra.xuimobile.core.site.SiteRemoteReadOnlyDigest
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportTreeEntrySpec
import java.security.MessageDigest
import java.time.Duration

data class SiteRemoteSftpPostTransactionCleanupEvidence(
    val cleanupRoot: String,
    val cleanupTreeSha256: String,
    val preservedTargetTreeSha256: String?,
    val cleanupRootVerifiedBeforeDelete: Boolean,
    val preservedTargetVerifiedBeforeDelete: Boolean,
    val cleanupRootAbsentAfterDelete: Boolean,
    val preservedTargetVerifiedAfterDelete: Boolean,
    val siblingAbsentBeforeAndAfter: Boolean,
    val removedFileCount: Int,
    val removedDirectoryCount: Int,
    val lstatOperationCount: Int,
    val listOperationCount: Int,
    val readFileOperationCount: Int,
    val channelOpened: Boolean,
    val channelClosed: Boolean,
    val writeFileOperationCount: Int,
    val mkdirOperationCount: Int,
    val renameOperationCount: Int,
    val chmodOperationCount: Int,
    val chownOrChgrpOperationCount: Int,
    val remoteCommandDispatchCount: Int,
)

/**
 * Phase 11.54 exact residual cleanup primitive. It can remove only the cleanup root already bound
 * into [SiteDeployerPostTransactionCleanupPlan]. The target root is verification-only and can never
 * be removed or renamed by this primitive.
 */
class SiteRemoteSftpPostTransactionCleanup {
    fun execute(
        session: SshSessionHandle,
        plan: SiteDeployerPostTransactionCleanupPlan,
        channelOpenTimeout: Duration = SshTransportConfig().channelOpenTimeout,
    ): SiteRemoteSftpPostTransactionCleanupEvidence {
        SiteDeployerPostTransactionCleanupBoundary.validate(plan)
        require(session.isOpen) { "SSH session is closed" }
        require(session is VerifiedHostKeySshSessionHandle) { "Cleanup requires verified host-key evidence" }
        val capable = session as? SiteRemoteSftpCapableSessionHandle
            ?: error("SSH session does not expose the bounded Site SFTP channel")
        val channel = capable.openSiteRemoteSftpChannel(channelOpenTimeout)
        val counts = Counts()
        try {
            require(channel.isOpen) { "SFTP channel did not reach open state" }
            verifyTree(channel, plan.cleanupRoot, plan.cleanupTree, counts)
            verifyPreservedTarget(channel, plan, counts)
            plan.siblingRootThatMustRemainAbsent?.let {
                requireType(channel, it, SiteRemoteObservedPathType.ABSENT, counts)
            }

            removeExactTree(channel, plan.cleanupRoot, plan.cleanupTree, counts)

            requireType(channel, plan.cleanupRoot, SiteRemoteObservedPathType.ABSENT, counts)
            verifyPreservedTarget(channel, plan, counts)
            plan.siblingRootThatMustRemainAbsent?.let {
                requireType(channel, it, SiteRemoteObservedPathType.ABSENT, counts)
            }

            channel.close()
            require(!channel.isOpen)
            return SiteRemoteSftpPostTransactionCleanupEvidence(
                cleanupRoot = plan.cleanupRoot,
                cleanupTreeSha256 = plan.cleanupTree.treeSha256,
                preservedTargetTreeSha256 = plan.preservedTargetTree?.treeSha256,
                cleanupRootVerifiedBeforeDelete = true,
                preservedTargetVerifiedBeforeDelete = true,
                cleanupRootAbsentAfterDelete = true,
                preservedTargetVerifiedAfterDelete = true,
                siblingAbsentBeforeAndAfter = true,
                removedFileCount = counts.removeFile,
                removedDirectoryCount = counts.removeDirectory,
                lstatOperationCount = counts.lstat,
                listOperationCount = counts.list,
                readFileOperationCount = counts.read,
                channelOpened = true,
                channelClosed = true,
                writeFileOperationCount = 0,
                mkdirOperationCount = 0,
                renameOperationCount = 0,
                chmodOperationCount = 0,
                chownOrChgrpOperationCount = 0,
                remoteCommandDispatchCount = 0,
            )
        } finally {
            if (channel.isOpen) channel.close()
        }
    }

    private fun verifyPreservedTarget(
        channel: SiteRemoteSftpChannelHandle,
        plan: SiteDeployerPostTransactionCleanupPlan,
        counts: Counts,
    ) {
        if (plan.preservedTargetMustBeAbsent) {
            requireType(channel, plan.targetRoot, SiteRemoteObservedPathType.ABSENT, counts)
        } else {
            verifyTree(channel, plan.targetRoot, requireNotNull(plan.preservedTargetTree), counts)
        }
    }

    private fun removeExactTree(
        channel: SiteRemoteSftpChannelHandle,
        root: String,
        expectation: SiteDeployerRemoteTreeExpectation,
        counts: Counts,
    ) {
        // Delete only the exact manifest paths. No discovered/extra entry is ever traversed.
        expectation.files.sortedByDescending { it.relativePath.count { c -> c == '/' } }.forEach { file ->
            val path = "$root/${file.relativePath}"
            val observed = lstat(channel, path, counts)
            require(observed.type == SiteRemoteObservedPathType.FILE && observed.sizeBytes == file.byteSize.toLong()) {
                "Cleanup file changed after verification: $path"
            }
            channel.removeFile(path)
            counts.removeFile++
            requireType(channel, path, SiteRemoteObservedPathType.ABSENT, counts)
        }

        val expectedDirectories = expectation.files.flatMap { file ->
            val parent = file.relativePath.substringBeforeLast('/', missingDelimiterValue = "")
            if (parent.isBlank()) emptyList() else {
                val segments = parent.split('/')
                segments.indices.map { index -> segments.take(index + 1).joinToString("/") }
            }
        }.toSet()
        val directories = expectedDirectories
            .sortedWith(compareByDescending<String> { it.count { c -> c == '/' } }.thenByDescending { it })
            .map { "$root/$it" } + root

        directories.forEach { directory ->
            requireType(channel, directory, SiteRemoteObservedPathType.DIRECTORY, counts)
            val remaining = channel.listDirectory(directory, 2).also { counts.list++ }
                .filter { it.name != "." && it.name != ".." }
            require(remaining.isEmpty()) { "Cleanup directory is not empty after exact child removal: $directory" }
            channel.removeDirectory(directory)
            counts.removeDirectory++
            requireType(channel, directory, SiteRemoteObservedPathType.ABSENT, counts)
        }
    }

    private fun verifyTree(
        channel: SiteRemoteSftpChannelHandle,
        root: String,
        expectation: SiteDeployerRemoteTreeExpectation,
        counts: Counts,
    ) {
        SiteDeployerCommitTransactionBoundary.validateExpectation(expectation)
        requireType(channel, root, SiteRemoteObservedPathType.DIRECTORY, counts)
        val expectedFiles = expectation.files.map { it.relativePath }.toSet()
        val expectedDirs = expectedFiles.flatMap { relative ->
            val parent = relative.substringBeforeLast('/', missingDelimiterValue = "")
            if (parent.isBlank()) emptyList() else {
                val segments = parent.split('/')
                segments.indices.map { index -> segments.take(index + 1).joinToString("/") }
            }
        }.toSet()
        val dirs = listOf("") + expectedDirs.sortedWith(compareBy<String> { it.count { c -> c == '/' } }.thenBy { it })
        dirs.forEach { relativeDir ->
            val expectedDirect = linkedMapOf<String, SiteRemoteObservedPathType>()
            expectedDirs.filter { parentRelative(it) == relativeDir }.forEach { rel ->
                expectedDirect[rel.substringAfterLast('/')] = SiteRemoteObservedPathType.DIRECTORY
            }
            expectedFiles.filter { parentRelative(it) == relativeDir }.forEach { rel ->
                expectedDirect[rel.substringAfterLast('/')] = SiteRemoteObservedPathType.FILE
            }
            val remoteDir = if (relativeDir.isEmpty()) root else "$root/$relativeDir"
            val observed = channel.listDirectory(remoteDir, expectedDirect.size + 2).also { counts.list++ }
                .filter { it.name != "." && it.name != ".." }
            require(observed.size == expectedDirect.size) { "Remote tree contains unexpected entries under $remoteDir" }
            observed.forEach { entry -> require(expectedDirect[entry.name] == entry.observation.type) }
        }

        val content = LinkedHashMap<String, ByteArray>(expectation.fileCount)
        try {
            var total = 0L
            expectation.files.forEach { file ->
                val path = "$root/${file.relativePath}"
                val obs = lstat(channel, path, counts)
                require(obs.type == SiteRemoteObservedPathType.FILE && obs.sizeBytes == file.byteSize.toLong())
                val bytes = channel.readFile(path, file.byteSize + 1).also { counts.read++ }
                require(bytes.size == file.byteSize)
                require(sha256(bytes) == file.sha256)
                content[file.relativePath] = bytes
                total += bytes.size
            }
            val specs = expectation.files.map { SiteRemoteTransportTreeEntrySpec(it.relativePath, it.mediaType) }
            require(SiteRemoteReadOnlyDigest.treeSha256(specs, content) == expectation.treeSha256)
            require(total == expectation.totalBytes)
        } finally {
            content.values.forEach { it.fill(0) }
        }
    }

    private fun lstat(channel: SiteRemoteSftpChannelHandle, path: String, counts: Counts): SiteRemoteSftpPathObservation =
        channel.lstat(path).also { counts.lstat++ }

    private fun requireType(
        channel: SiteRemoteSftpChannelHandle,
        path: String,
        expected: SiteRemoteObservedPathType,
        counts: Counts,
    ) {
        require(lstat(channel, path, counts).type == expected) { "Unexpected remote path state: $path" }
    }

    private fun parentRelative(path: String): String = path.substringBeforeLast('/', missingDelimiterValue = "")
    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { b -> "%02x".format(b.toInt() and 0xff) }

    private data class Counts(
        var lstat: Int = 0,
        var list: Int = 0,
        var read: Int = 0,
        var removeFile: Int = 0,
        var removeDirectory: Int = 0,
    )
}
