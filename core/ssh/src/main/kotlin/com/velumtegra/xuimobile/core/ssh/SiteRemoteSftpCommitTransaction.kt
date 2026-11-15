package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.site.SiteDeployerCommitTransactionBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerCommitTransactionPlan
import com.velumtegra.xuimobile.core.site.SiteDeployerRemoteTreeExpectation
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import com.velumtegra.xuimobile.core.site.SiteRemoteReadOnlyDigest
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportTreeEntrySpec
import java.security.MessageDigest
import java.time.Duration

enum class SiteRemoteSftpCommitFailureInjection { NONE, AFTER_TARGET_TO_BACKUP, AFTER_STAGING_TO_TARGET }
enum class SiteRemoteSftpCommitOutcome { COMMITTED, ROLLED_BACK }

data class SiteRemoteSftpCommitEvidence(
    val outcome: SiteRemoteSftpCommitOutcome,
    val targetRoot: String,
    val stagingRoot: String,
    val backupRoot: String?,
    val sourceTreeSha256: String,
    val previousTargetTreeSha256: String?,
    val lstatOperationCount: Int,
    val listOperationCount: Int,
    val readFileOperationCount: Int,
    val renameOperationCount: Int,
    val targetToBackupRenamePerformed: Boolean,
    val stagingToTargetRenamePerformed: Boolean,
    val targetToStagingRollbackRenamePerformed: Boolean,
    val backupToTargetRollbackRenamePerformed: Boolean,
    val rollbackPerformed: Boolean,
    val finalTargetVerified: Boolean,
    val finalStagingVerified: Boolean,
    val finalBackupVerified: Boolean,
    val backupRetainedAfterCommit: Boolean,
    val channelOpened: Boolean,
    val channelClosed: Boolean,
    val writeFileOperationCount: Int,
    val mkdirOperationCount: Int,
    val deleteOperationCount: Int,
    val chmodOperationCount: Int,
    val chownOrChgrpOperationCount: Int,
    val remoteCommandDispatchCount: Int,
)

/** Rename-only commit/rollback primitive. No upload/mkdir/delete/metadata/shell path exists here. */
class SiteRemoteSftpCommitTransaction {
    fun execute(
        session: SshSessionHandle,
        plan: SiteDeployerCommitTransactionPlan,
        failureInjection: SiteRemoteSftpCommitFailureInjection = SiteRemoteSftpCommitFailureInjection.NONE,
        channelOpenTimeout: Duration = SshTransportConfig().channelOpenTimeout,
    ): SiteRemoteSftpCommitEvidence {
        SiteDeployerCommitTransactionBoundary.validate(plan)
        require(session.isOpen) { "SSH session is closed" }
        require(session is VerifiedHostKeySshSessionHandle) { "Commit requires verified host-key evidence" }
        val capable = session as? SiteRemoteSftpCapableSessionHandle
            ?: error("SSH session does not expose the bounded Site SFTP channel")
        val channel = capable.openSiteRemoteSftpChannel(channelOpenTimeout)
        val counts = Counts()
        var targetToBackup = false
        var stagingToTarget = false
        var targetToStagingRollback = false
        var backupToTargetRollback = false

        try {
            require(channel.isOpen) { "SFTP channel did not reach open state" }
            requireType(channel, plan.stagingRoot, SiteRemoteObservedPathType.DIRECTORY, counts)
            verifyTree(channel, plan.stagingRoot, plan.sourceTree, counts)

            when (plan.existingTargetPolicy) {
                SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT ->
                    requireType(channel, plan.targetRoot, SiteRemoteObservedPathType.ABSENT, counts)
                SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> {
                    requireType(channel, plan.targetRoot, SiteRemoteObservedPathType.DIRECTORY, counts)
                    verifyTree(channel, plan.targetRoot, requireNotNull(plan.previousTargetTree), counts)
                    requireType(channel, requireNotNull(plan.backupRoot), SiteRemoteObservedPathType.ABSENT, counts)
                }
            }

            try {
                if (plan.existingTargetPolicy == SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE) {
                    renameExact(channel, plan.targetRoot, requireNotNull(plan.backupRoot), counts)
                    targetToBackup = true
                    if (failureInjection == SiteRemoteSftpCommitFailureInjection.AFTER_TARGET_TO_BACKUP) {
                        throw InjectedCommitFailure("Injected after target->backup rename")
                    }
                } else {
                    require(failureInjection != SiteRemoteSftpCommitFailureInjection.AFTER_TARGET_TO_BACKUP)
                }

                renameExact(channel, plan.stagingRoot, plan.targetRoot, counts)
                stagingToTarget = true
                if (failureInjection == SiteRemoteSftpCommitFailureInjection.AFTER_STAGING_TO_TARGET) {
                    throw InjectedCommitFailure("Injected after staging->target rename")
                }

                verifyTree(channel, plan.targetRoot, plan.sourceTree, counts)
                requireType(channel, plan.stagingRoot, SiteRemoteObservedPathType.ABSENT, counts)
                if (plan.existingTargetPolicy == SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE) {
                    verifyTree(channel, requireNotNull(plan.backupRoot), requireNotNull(plan.previousTargetTree), counts)
                }
                channel.close()
                require(!channel.isOpen)
                return evidence(
                    plan, counts, SiteRemoteSftpCommitOutcome.COMMITTED,
                    targetToBackup, stagingToTarget, false, false,
                    rollback = false, targetVerified = true, stagingVerified = false,
                    backupVerified = true, backupRetained = plan.backupRoot != null,
                )
            } catch (failure: Throwable) {
                var state = reconcile(channel, plan, counts)
                if (state.ambiguous) throw IllegalStateException("Commit rename state is ambiguous; automatic rollback denied", failure)
                if (state.backupHasPreviousTarget) targetToBackup = true
                if (state.targetHasSourceTree) stagingToTarget = true

                if (state.targetHasSourceTree) {
                    requireType(channel, plan.stagingRoot, SiteRemoteObservedPathType.ABSENT, counts)
                    renameExact(channel, plan.targetRoot, plan.stagingRoot, counts)
                    targetToStagingRollback = true
                }
                state = reconcile(channel, plan, counts)
                if (state.ambiguous) throw IllegalStateException("Rollback state became ambiguous after target->staging", failure)

                if (plan.existingTargetPolicy == SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE && state.backupHasPreviousTarget) {
                    requireType(channel, plan.targetRoot, SiteRemoteObservedPathType.ABSENT, counts)
                    renameExact(channel, requireNotNull(plan.backupRoot), plan.targetRoot, counts)
                    backupToTargetRollback = true
                }

                state = reconcile(channel, plan, counts)
                require(!state.ambiguous)
                verifyTree(channel, plan.stagingRoot, plan.sourceTree, counts)
                when (plan.existingTargetPolicy) {
                    SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT ->
                        requireType(channel, plan.targetRoot, SiteRemoteObservedPathType.ABSENT, counts)
                    SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> {
                        verifyTree(channel, plan.targetRoot, requireNotNull(plan.previousTargetTree), counts)
                        requireType(channel, requireNotNull(plan.backupRoot), SiteRemoteObservedPathType.ABSENT, counts)
                    }
                }
                channel.close()
                require(!channel.isOpen)
                return evidence(
                    plan, counts, SiteRemoteSftpCommitOutcome.ROLLED_BACK,
                    targetToBackup,
                    stagingToTarget,
                    targetToStagingRollback, backupToTargetRollback,
                    rollback = true, targetVerified = true, stagingVerified = true,
                    backupVerified = true, backupRetained = false,
                )
            }
        } finally {
            if (channel.isOpen) channel.close()
        }
    }

    private fun evidence(
        plan: SiteDeployerCommitTransactionPlan,
        counts: Counts,
        outcome: SiteRemoteSftpCommitOutcome,
        targetToBackup: Boolean,
        stagingToTarget: Boolean,
        targetToStagingRollback: Boolean,
        backupToTargetRollback: Boolean,
        rollback: Boolean,
        targetVerified: Boolean,
        stagingVerified: Boolean,
        backupVerified: Boolean,
        backupRetained: Boolean,
    ) = SiteRemoteSftpCommitEvidence(
        outcome = outcome,
        targetRoot = plan.targetRoot,
        stagingRoot = plan.stagingRoot,
        backupRoot = plan.backupRoot,
        sourceTreeSha256 = plan.sourceTree.treeSha256,
        previousTargetTreeSha256 = plan.previousTargetTree?.treeSha256,
        lstatOperationCount = counts.lstat,
        listOperationCount = counts.list,
        readFileOperationCount = counts.read,
        renameOperationCount = counts.rename,
        targetToBackupRenamePerformed = targetToBackup,
        stagingToTargetRenamePerformed = stagingToTarget,
        targetToStagingRollbackRenamePerformed = targetToStagingRollback,
        backupToTargetRollbackRenamePerformed = backupToTargetRollback,
        rollbackPerformed = rollback,
        finalTargetVerified = targetVerified,
        finalStagingVerified = stagingVerified,
        finalBackupVerified = backupVerified,
        backupRetainedAfterCommit = backupRetained,
        channelOpened = true,
        channelClosed = true,
        writeFileOperationCount = 0,
        mkdirOperationCount = 0,
        deleteOperationCount = 0,
        chmodOperationCount = 0,
        chownOrChgrpOperationCount = 0,
        remoteCommandDispatchCount = 0,
    )

    private fun reconcile(channel: SiteRemoteSftpChannelHandle, plan: SiteDeployerCommitTransactionPlan, counts: Counts): State {
        val staging = lstat(channel, plan.stagingRoot, counts).type
        val target = lstat(channel, plan.targetRoot, counts).type
        val backup = plan.backupRoot?.let { lstat(channel, it, counts).type } ?: SiteRemoteObservedPathType.ABSENT
        val allKnown = listOf(staging, target, backup).all {
            it == SiteRemoteObservedPathType.ABSENT || it == SiteRemoteObservedPathType.DIRECTORY
        }
        if (!allKnown) return State(ambiguous = true)
        return State(
            targetHasSourceTree = target == SiteRemoteObservedPathType.DIRECTORY && staging == SiteRemoteObservedPathType.ABSENT,
            backupHasPreviousTarget = plan.backupRoot != null && backup == SiteRemoteObservedPathType.DIRECTORY,
            ambiguous = plan.existingTargetPolicy == SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT && backup != SiteRemoteObservedPathType.ABSENT,
        )
    }

    private fun renameExact(channel: SiteRemoteSftpChannelHandle, from: String, to: String, counts: Counts) {
        requireType(channel, from, SiteRemoteObservedPathType.DIRECTORY, counts)
        requireType(channel, to, SiteRemoteObservedPathType.ABSENT, counts)
        try {
            channel.rename(from, to)
            counts.rename++
        } catch (failure: Throwable) {
            val fromAfter = lstat(channel, from, counts).type
            val toAfter = lstat(channel, to, counts).type
            when {
                fromAfter == SiteRemoteObservedPathType.ABSENT && toAfter == SiteRemoteObservedPathType.DIRECTORY -> {
                    counts.rename++
                    return
                }
                fromAfter == SiteRemoteObservedPathType.DIRECTORY && toAfter == SiteRemoteObservedPathType.ABSENT -> throw failure
                else -> throw IllegalStateException("SFTP rename outcome is ambiguous: $from -> $to", failure)
            }
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

    private fun requireType(channel: SiteRemoteSftpChannelHandle, path: String, expected: SiteRemoteObservedPathType, counts: Counts) {
        require(lstat(channel, path, counts).type == expected) { "Unexpected remote path state: $path" }
    }

    private fun parentRelative(path: String): String = path.substringBeforeLast('/', missingDelimiterValue = "")
    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { b -> "%02x".format(b.toInt() and 0xff) }

    private data class State(
        val targetHasSourceTree: Boolean = false,
        val backupHasPreviousTarget: Boolean = false,
        val ambiguous: Boolean = false,
    )
    private data class Counts(var lstat: Int = 0, var list: Int = 0, var read: Int = 0, var rename: Int = 0)
    private class InjectedCommitFailure(message: String) : RuntimeException(message)
}
