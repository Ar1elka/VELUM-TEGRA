package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.site.SiteBuildPolicy
import com.velumtegra.xuimobile.core.site.SiteBundle
import com.velumtegra.xuimobile.core.site.SiteDeployerStagingWriteBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerStagingWritePlan
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import com.velumtegra.xuimobile.core.site.SiteRemoteReadOnlyDigest
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportTreeEntrySpec
import java.security.MessageDigest
import java.time.Duration

data class SiteRemoteSftpStagingWriteEvidence(
    val stagingRoot: String,
    val sourceTreeSha256: String,
    val createdDirectoryCount: Int,
    val uploadedFileCount: Int,
    val uploadedBytes: Long,
    val verifiedFileCount: Int,
    val lstatOperationCount: Int,
    val listOperationCount: Int,
    val readFileOperationCount: Int,
    val writeFileOperationCount: Int,
    val mkdirOperationCount: Int,
    val channelOpened: Boolean,
    val channelClosed: Boolean,
    val targetRootMutationPerformed: Boolean,
    val renamePerformed: Boolean,
    val deletePerformed: Boolean,
    val chmodPerformed: Boolean,
    val chownOrChgrpPerformed: Boolean,
    val remoteCommandDispatched: Boolean,
)

/**
 * Staging-only SFTP primitive for Phase 11.52. It intentionally exposes no rename/delete/chmod/
 * chown/chgrp or SSH-command path. A failure after staging creation is fail-closed: no cleanup is
 * attempted here and the durable execution fence prevents an automatic retry over uncertain state.
 */
class SiteRemoteSftpStagingWriter {
    fun stage(
        session: SshSessionHandle,
        plan: SiteDeployerStagingWritePlan,
        bundle: SiteBundle,
        channelOpenTimeout: Duration = SshTransportConfig().channelOpenTimeout,
    ): SiteRemoteSftpStagingWriteEvidence {
        SiteDeployerStagingWriteBoundary.validate(plan, bundle)
        require(session.isOpen) { "SSH session is closed" }
        require(session is VerifiedHostKeySshSessionHandle) { "Staging write requires verified host-key evidence" }
        val capable = session as? SiteRemoteSftpCapableSessionHandle
            ?: error("SSH session does not expose the bounded Site SFTP channel")
        val channel = capable.openSiteRemoteSftpChannel(channelOpenTimeout)

        var lstats = 0
        var lists = 0
        var reads = 0
        var writes = 0
        var mkdirs = 0
        val verifiedContent = LinkedHashMap<String, ByteArray>(plan.fileCount)
        val bundleByPath = bundle.documents.associateBy { it.path }
        try {
            require(channel.isOpen) { "SFTP channel did not reach open state" }
            val stagingBefore = channel.lstat(plan.stagingRoot).also { lstats++ }
            require(stagingBefore.type == SiteRemoteObservedPathType.ABSENT) { "Exact staging root is no longer absent" }
            val stagingParent = parent(plan.stagingRoot)
            val parentObs = channel.lstat(stagingParent).also { lstats++ }
            require(parentObs.type == SiteRemoteObservedPathType.DIRECTORY) { "Staging parent is not a real directory" }

            plan.directories.forEachIndexed { index, directory ->
                if (index > 0) {
                    val expectedParent = parent(directory.remotePath)
                    val parent = channel.lstat(expectedParent).also { lstats++ }
                    require(parent.type == SiteRemoteObservedPathType.DIRECTORY) { "Staging child parent is not a directory" }
                    val before = channel.lstat(directory.remotePath).also { lstats++ }
                    require(before.type == SiteRemoteObservedPathType.ABSENT) { "Planned staging directory already exists" }
                }
                channel.mkdir(directory.remotePath)
                mkdirs++
                val after = channel.lstat(directory.remotePath).also { lstats++ }
                require(after.type == SiteRemoteObservedPathType.DIRECTORY) { "Staging mkdir postcondition failed" }
            }

            var uploadedBytes = 0L
            plan.files.forEach { file ->
                val doc = requireNotNull(bundleByPath[file.relativePath])
                val payload = doc.content.encodeToByteArray()
                require(payload.size == file.byteSize)
                require(sha256(payload) == file.sha256)
                val parent = channel.lstat(parent(file.remotePath)).also { lstats++ }
                require(parent.type == SiteRemoteObservedPathType.DIRECTORY) { "Upload parent is not a directory" }
                val before = channel.lstat(file.remotePath).also { lstats++ }
                require(before.type == SiteRemoteObservedPathType.ABSENT) { "Authorized staging file is no longer absent" }
                channel.writeFile(file.remotePath, payload.copyOf())
                writes++
                uploadedBytes += payload.size
                val after = channel.lstat(file.remotePath).also { lstats++ }
                require(after.type == SiteRemoteObservedPathType.FILE && after.sizeBytes == payload.size.toLong()) {
                    "Staging upload postcondition failed"
                }
                val remoteBytes = channel.readFile(file.remotePath, file.byteSize + 1)
                reads++
                require(remoteBytes.size == file.byteSize) { "Staged file read-back size mismatch" }
                require(sha256(remoteBytes) == file.sha256) { "Staged file read-back SHA-256 mismatch" }
                verifiedContent[file.relativePath] = remoteBytes
            }
            require(uploadedBytes == plan.totalBytes)

            val expectedFiles = plan.files.map { it.relativePath }.toSet()
            val expectedDirs = plan.directories.drop(1).map { it.relativePath }.toSet()
            plan.directories.forEach { directory ->
                val expectedDirect = linkedMapOf<String, SiteRemoteObservedPathType>()
                expectedDirs.filter { parentRelative(it) == directory.relativePath }.forEach { rel ->
                    expectedDirect[rel.substringAfterLast('/')] = SiteRemoteObservedPathType.DIRECTORY
                }
                expectedFiles.filter { parentRelative(it) == directory.relativePath }.forEach { rel ->
                    expectedDirect[rel.substringAfterLast('/')] = SiteRemoteObservedPathType.FILE
                }
                val observed = channel.listDirectory(directory.remotePath, expectedDirect.size + 2)
                    .also { lists++ }
                    .filter { it.name != "." && it.name != ".." }
                require(observed.size == expectedDirect.size) { "Staging directory contains unexpected entries" }
                observed.forEach { entry ->
                    require(expectedDirect[entry.name] == entry.observation.type) {
                        "Staging directory entry/type mismatch"
                    }
                }
            }

            val specs = plan.files.map { SiteRemoteTransportTreeEntrySpec(it.relativePath, it.mediaType) }
            val treeSha = SiteRemoteReadOnlyDigest.treeSha256(specs, verifiedContent)
            require(treeSha == plan.sourceTreeSha256) { "Staged tree SHA-256 mismatch" }
            require(writes == plan.fileCount && reads == plan.fileCount)
            channel.close()
            require(!channel.isOpen) { "SFTP channel remained open after staging write" }
            return SiteRemoteSftpStagingWriteEvidence(
                stagingRoot = plan.stagingRoot,
                sourceTreeSha256 = treeSha,
                createdDirectoryCount = mkdirs,
                uploadedFileCount = writes,
                uploadedBytes = uploadedBytes,
                verifiedFileCount = reads,
                lstatOperationCount = lstats,
                listOperationCount = lists,
                readFileOperationCount = reads,
                writeFileOperationCount = writes,
                mkdirOperationCount = mkdirs,
                channelOpened = true,
                channelClosed = true,
                targetRootMutationPerformed = false,
                renamePerformed = false,
                deletePerformed = false,
                chmodPerformed = false,
                chownOrChgrpPerformed = false,
                remoteCommandDispatched = false,
            )
        } finally {
            if (channel.isOpen) channel.close()
            verifiedContent.values.forEach { bytes -> bytes.fill(0) }
        }
    }

    private fun parent(path: String): String = path.substringBeforeLast('/').ifBlank { "/" }
    private fun parentRelative(path: String): String = path.substringBeforeLast('/', missingDelimiterValue = "")
    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}
