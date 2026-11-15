package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPolicy
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import java.time.Duration

data class SiteRemoteSftpReadOnlyPathEvidence(
    val path: String,
    val type: SiteRemoteObservedPathType,
    val sizeBytes: Long,
    val uid: Int,
    val gid: Int,
    val permissions: Int,
)

data class SiteRemoteSftpReadOnlyPreflightEvidence(
    val target: SiteRemoteSftpReadOnlyPathEvidence,
    val staging: SiteRemoteSftpReadOnlyPathEvidence,
    val backup: SiteRemoteSftpReadOnlyPathEvidence,
    val targetEntryNames: List<String>,
    val lstatOperationCount: Int,
    val listOperationCount: Int,
    val channelOpened: Boolean,
    val channelClosed: Boolean,
    val mutationOperationPerformed: Boolean,
    val remoteCommandDispatched: Boolean,
)

/**
 * Narrow Phase 11.35 production primitive. It can only lstat the three exact deployment roots and
 * list the exact target root with a hard bound. It exposes no read-file or mutation API and never
 * dispatches an SSH exec command.
 */
class SiteRemoteSftpReadOnlyPreflightProbe {
    fun observe(
        session: SshSessionHandle,
        targetRoot: String,
        stagingRoot: String,
        backupRoot: String,
        expectedTargetEntryNames: List<String>,
        channelOpenTimeout: Duration = SshTransportConfig().channelOpenTimeout,
    ): SiteRemoteSftpReadOnlyPreflightEvidence {
        require(session.isOpen) { "SSH session is closed" }
        require(session is VerifiedHostKeySshSessionHandle) { "Read-only SFTP preflight requires verified host-key evidence" }
        val target = SiteRemoteDeployPolicy.prepareTargetRoot(targetRoot)
        val staging = SiteRemoteDeployPolicy.prepareTargetRoot(stagingRoot)
        val backup = SiteRemoteDeployPolicy.prepareTargetRoot(backupRoot)
        require(setOf(target, staging, backup).size == 3) { "Read-only SFTP preflight roots must be distinct" }
        require(parent(target) == parent(staging) && parent(target) == parent(backup)) {
            "Read-only SFTP preflight roots must be siblings"
        }
        val expected = expectedTargetEntryNames.sorted()
        require(expected.isNotEmpty() && expected.size <= MAX_TARGET_ENTRIES) { "Expected target entry set is outside bounds" }
        require(expected.distinct().size == expected.size) { "Expected target entry set contains duplicates" }
        require(expected.all(::safeEntryName)) { "Expected target entry name is unsafe" }

        val capable = session as? SiteRemoteSftpCapableSessionHandle
            ?: error("SSH session does not expose the bounded Site SFTP channel")
        val channel = capable.openSiteRemoteSftpChannel(channelOpenTimeout)
        try {
            require(channel.isOpen) { "SFTP channel did not reach open state" }
            val targetObservation = channel.lstat(target).toEvidence(target)
            val stagingObservation = channel.lstat(staging).toEvidence(staging)
            val backupObservation = channel.lstat(backup).toEvidence(backup)
            require(targetObservation.type == SiteRemoteObservedPathType.DIRECTORY) {
                "Read-only SFTP target root must be a real directory"
            }
            require(stagingObservation.type == SiteRemoteObservedPathType.ABSENT) {
                "Read-only SFTP staging root must be absent"
            }
            require(backupObservation.type == SiteRemoteObservedPathType.ABSENT) {
                "Read-only SFTP backup root must be absent"
            }
            val entries = channel.listDirectory(target, MAX_TARGET_ENTRIES + 2)
                .filter { it.name != "." && it.name != ".." }
                .also { observed -> require(observed.size <= MAX_TARGET_ENTRIES) { "Target directory exceeds preflight bound" } }
            require(entries.all { safeEntryName(it.name) }) { "Target directory contains unsafe entry name" }
            require(entries.all {
                it.observation.type == SiteRemoteObservedPathType.FILE ||
                    it.observation.type == SiteRemoteObservedPathType.DIRECTORY
            }) { "Target directory contains symlink or unsupported entry" }
            val names = entries.map { it.name }.sorted()
            require(names == expected) { "Target directory identity does not match the approved entry set" }
            val evidence = SiteRemoteSftpReadOnlyPreflightEvidence(
                target = targetObservation,
                staging = stagingObservation,
                backup = backupObservation,
                targetEntryNames = names,
                lstatOperationCount = 3,
                listOperationCount = 1,
                channelOpened = true,
                channelClosed = false,
                mutationOperationPerformed = false,
                remoteCommandDispatched = false,
            )
            channel.close()
            require(!channel.isOpen) { "SFTP channel remained open after read-only preflight" }
            return evidence.copy(channelClosed = true)
        } finally {
            if (channel.isOpen) channel.close()
        }
    }

    private fun SiteRemoteSftpPathObservation.toEvidence(path: String) = SiteRemoteSftpReadOnlyPathEvidence(
        path = path,
        type = type,
        sizeBytes = sizeBytes,
        uid = uid,
        gid = gid,
        permissions = permissions,
    )

    private fun parent(path: String): String = path.substringBeforeLast('/').ifBlank { "/" }
    private fun safeEntryName(value: String): Boolean = value.isNotBlank() && value != "." && value != ".." &&
        '/' !in value && '\\' !in value && '\u0000' !in value && value.length <= 128

    companion object { const val MAX_TARGET_ENTRIES: Int = 16 }
}
