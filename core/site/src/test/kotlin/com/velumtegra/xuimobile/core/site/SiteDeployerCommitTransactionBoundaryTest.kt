package com.velumtegra.xuimobile.core.site

import java.nio.file.Files
import java.util.Comparator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteDeployerCommitTransactionBoundaryTest {
    @Test
    fun absentTargetPlanBindsExactVerifiedStagingTreeAndNoBackup() {
        val root = Files.createTempDirectory("site-commit-plan-absent-")
        try {
            val preparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(1153L),
                    domain = "phase1153.example.com",
                    servicePort = 8443,
                    remoteHostIdentity = "192.0.2.169",
                    targetRoot = "/tmp/velum-p1153-unit",
                    owner = "root",
                    group = "root",
                ),
                root,
            )
            val staging = SiteDeployerStagingWriteBoundary.prepare(preparation)
            val plan = SiteDeployerCommitTransactionBoundary.prepare(preparation, staging)
            assertEquals(SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT, plan.existingTargetPolicy)
            assertEquals(staging.stagingWritePlanSha256, plan.stagingWritePlanSha256)
            assertEquals(staging.sourceTreeSha256, plan.sourceTree.treeSha256)
            assertNull(plan.backupRoot)
            assertNull(plan.previousTargetTree)
            assertTrue(plan.verifyBeforeCommit && plan.verifyAfterCommit && plan.rollbackByRenameOnly)
            SiteDeployerCommitTransactionBoundary.validate(plan)
        } finally {
            Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun replacePlanBindsPreviousTreeAndGetsDifferentTransactionDigest() {
        val oldRoot = Files.createTempDirectory("site-commit-old-")
        val newRoot = Files.createTempDirectory("site-commit-new-")
        try {
            val target = "/tmp/velum-p1153-replace-unit"
            val oldPreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11530L), domain = "phase1153.example.com", servicePort = 8443,
                    remoteHostIdentity = "192.0.2.169", targetRoot = target, owner = "root", group = "root",
                ), oldRoot,
            )
            val newPreparation = SiteDeployerLocalPreparationBoundary.prepare(
                SiteDeployerLocalPreparationRequest(
                    rootSeed = DesignSeed(11531L), domain = "phase1153.example.com", servicePort = 8443,
                    remoteHostIdentity = "192.0.2.169", targetRoot = target, owner = "root", group = "root",
                    existingTargetPolicy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
                ), newRoot,
            )
            val previous = SiteDeployerCommitTransactionBoundary.expectation(oldPreparation)
            val staging = SiteDeployerStagingWriteBoundary.prepare(newPreparation)
            val plan = SiteDeployerCommitTransactionBoundary.prepare(newPreparation, staging, previous)
            assertEquals(SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE, plan.existingTargetPolicy)
            assertEquals(previous.treeSha256, plan.previousTargetTree?.treeSha256)
            assertNotEquals(plan.targetRoot, plan.backupRoot)
            assertNotEquals(plan.stagingRoot, plan.backupRoot)
            assertTrue(plan.retainBackupAfterSuccessfulReplacement)
            SiteDeployerCommitTransactionBoundary.validate(plan)
        } finally {
            listOf(oldRoot, newRoot).forEach { root ->
                Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
            }
        }
    }
}
