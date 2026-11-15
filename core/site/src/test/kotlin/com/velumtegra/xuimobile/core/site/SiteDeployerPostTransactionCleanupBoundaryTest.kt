package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteDeployerPostTransactionCleanupBoundaryTest {
    @Test
    fun replacementCommitDerivesOnlyExactRetainedBackupCleanup() {
        val oldRoot = Files.createTempDirectory("site-cleanup-old-")
        val newRoot = Files.createTempDirectory("site-cleanup-new-")
        try {
            val target = "/tmp/velum-p1154-replace-unit"
            val oldPreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11540L), domain = "phase1154.example.com", servicePort = 8443,
                    remoteHostIdentity = "192.0.2.169", targetRoot = target, owner = "root", group = "root",
                ), oldRoot,
            )
            val replacement = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11541L), domain = "phase1154.example.com", servicePort = 8443,
                    remoteHostIdentity = "192.0.2.169", targetRoot = target, owner = "root", group = "root",
                    existingTargetPolicy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                ), newRoot,
            )
            val staging = SiteDeployerStagingWriteBoundary.prepare(replacement)
            val commit = SiteDeployerCommitTransactionBoundary.prepare(
                replacement,
                staging,
                SiteDeployerCommitTransactionBoundary.expectation(oldPreparation),
            )
            val cleanup = SiteDeployerPostTransactionCleanupBoundary.prepareRetainedBackupAfterCommit(commit)
            assertEquals(SiteDeployerPostTransactionCleanupKind.RETAINED_BACKUP_AFTER_COMMIT, cleanup.cleanupKind)
            assertEquals(commit.backupRoot, cleanup.cleanupRoot)
            assertNotEquals(commit.targetRoot, cleanup.cleanupRoot)
            assertEquals(commit.previousTargetTree, cleanup.cleanupTree)
            assertEquals(commit.sourceTree, cleanup.preservedTargetTree)
            assertEquals(commit.stagingRoot, cleanup.siblingRootThatMustRemainAbsent)
            assertTrue(cleanup.verifyBeforeCleanup && cleanup.verifyAfterCleanup)
            SiteDeployerPostTransactionCleanupBoundary.validateAgainstCommit(cleanup, commit)
        } finally {
            listOf(oldRoot, newRoot).forEach { root ->
                Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
            }
        }
    }

    @Test
    fun rollbackCleanupTargetsOnlyStagingAndPreservesPriorTargetExpectation() {
        val oldRoot = Files.createTempDirectory("site-cleanup-rollback-old-")
        val newRoot = Files.createTempDirectory("site-cleanup-rollback-new-")
        try {
            val target = "/tmp/velum-p1154-rollback-unit"
            val oldPreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11542L), domain = "phase1154.example.com", servicePort = 8443,
                    remoteHostIdentity = "192.0.2.169", targetRoot = target, owner = "root", group = "root",
                ), oldRoot,
            )
            val replacement = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11543L), domain = "phase1154.example.com", servicePort = 8443,
                    remoteHostIdentity = "192.0.2.169", targetRoot = target, owner = "root", group = "root",
                    existingTargetPolicy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                ), newRoot,
            )
            val staging = SiteDeployerStagingWriteBoundary.prepare(replacement)
            val commit = SiteDeployerCommitTransactionBoundary.prepare(
                replacement,
                staging,
                SiteDeployerCommitTransactionBoundary.expectation(oldPreparation),
            )
            val cleanup = SiteDeployerPostTransactionCleanupBoundary.prepareStagingAfterRollback(commit)
            assertEquals(SiteDeployerPostTransactionCleanupKind.STAGING_AFTER_ROLLBACK, cleanup.cleanupKind)
            assertEquals(commit.stagingRoot, cleanup.cleanupRoot)
            assertNotEquals(commit.targetRoot, cleanup.cleanupRoot)
            assertEquals(commit.sourceTree, cleanup.cleanupTree)
            assertEquals(commit.previousTargetTree, cleanup.preservedTargetTree)
            assertEquals(commit.backupRoot, cleanup.siblingRootThatMustRemainAbsent)
            SiteDeployerPostTransactionCleanupBoundary.validateAgainstCommit(cleanup, commit)
        } finally {
            listOf(oldRoot, newRoot).forEach { root ->
                Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
            }
        }
    }

    @Test
    fun absentTargetRollbackCleanupPreservesAbsentTargetAndHasNoBackupSibling() {
        val root = Files.createTempDirectory("site-cleanup-absent-")
        try {
            val preparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11544L), domain = "phase1154.example.com", servicePort = 8443,
                    remoteHostIdentity = "192.0.2.169", targetRoot = "/tmp/velum-p1154-absent-unit",
                    owner = "root", group = "root",
                ), root,
            )
            val staging = SiteDeployerStagingWriteBoundary.prepare(preparation)
            val commit = SiteDeployerCommitTransactionBoundary.prepare(preparation, staging)
            val cleanup = SiteDeployerPostTransactionCleanupBoundary.prepareStagingAfterRollback(commit)
            assertTrue(cleanup.preservedTargetMustBeAbsent)
            assertNull(cleanup.preservedTargetTree)
            assertNull(cleanup.backupRoot)
            assertNull(cleanup.siblingRootThatMustRemainAbsent)
            SiteDeployerPostTransactionCleanupBoundary.validateAgainstCommit(cleanup, commit)
        } finally {
            Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }
}
