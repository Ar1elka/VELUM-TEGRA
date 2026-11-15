package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteRemoteTransportExecutorAmbiguousRenameTest {
    @Test
    fun `post apply rename failure is reconciled and rolled back safely`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(
            seed = 8195L,
            policy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
        )
        val probe = InMemoryRemotePrimitive(
            capabilities = SiteRemoteTransportTestFixtures.fullCapabilities(),
            initialTargetRoot = fixture.plan.publish.targetRoot,
        )
        val probeAuthorization = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, probe.capabilities)
        SiteRemoteTransportExecutor(probe).execute(probeAuthorization, fixture.source())
        val renameCalls = probe.operationLog.withIndex().filter { it.value.startsWith("RENAME:") }
        assertEquals(2, renameCalls.size)

        renameCalls.forEach { indexed ->
            val primitive = InMemoryRemotePrimitive(
                capabilities = SiteRemoteTransportTestFixtures.fullCapabilities(),
                initialTargetRoot = fixture.plan.publish.targetRoot,
                failAtCall = indexed.index + 1,
                failAfterApply = true,
            )
            val authorization = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, primitive.capabilities)
            val result = SiteRemoteTransportExecutor(primitive).execute(authorization, fixture.source())

            assertEquals(SiteRemoteTransportOutcome.ROLLED_BACK, result.outcome)
            assertEquals(SiteRemoteObservedPathType.DIRECTORY, primitive.statPath(fixture.plan.publish.targetRoot))
            assertEquals(SiteRemoteObservedPathType.ABSENT, primitive.statPath(fixture.plan.publish.stagingRoot))
            assertEquals(SiteRemoteObservedPathType.ABSENT, primitive.statPath(requireNotNull(fixture.plan.publish.backupRoot)))
            assertTrue(primitive.hasFile("${fixture.plan.publish.targetRoot}/legacy.txt"))
        }
    }

    @Test
    fun `ambiguous staging create is never deleted without proven transaction ownership`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(8197L, SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT)
        val probe = InMemoryRemotePrimitive(SiteRemoteTransportTestFixtures.fullCapabilities())
        val authorization = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, probe.capabilities)
        val stagingCreateCall = authorization.forwardOperations
            .takeWhile { it is SiteRemoteTransportOperation.AssertPathState }
            .size + 1
        val primitive = InMemoryRemotePrimitive(
            capabilities = SiteRemoteTransportTestFixtures.fullCapabilities(),
            failAtCall = stagingCreateCall,
            failAfterApply = true,
        )
        val failedAuthorization = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, primitive.capabilities)

        val failure = runCatching { SiteRemoteTransportExecutor(primitive).execute(failedAuthorization, fixture.source()) }.exceptionOrNull()

        assertTrue(failure != null)
        assertEquals(SiteRemoteObservedPathType.DIRECTORY, primitive.statPath(fixture.plan.publish.stagingRoot))
        assertTrue(primitive.operationLog.none { it == "REMOVE:${fixture.plan.publish.stagingRoot}" })
    }

    @Test
    fun `rollback failure is surfaced instead of reporting a false rollback`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(8196L, SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT)
        val probe = InMemoryRemotePrimitive(SiteRemoteTransportTestFixtures.fullCapabilities())
        val probeAuthorization = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, probe.capabilities)
        SiteRemoteTransportExecutor(probe).execute(probeAuthorization, fixture.source())
        val targetInspectIndex = probe.operationLog.indexOfLast { it.startsWith("INSPECT_TREE:${fixture.plan.publish.targetRoot}:") }
        assertTrue(targetInspectIndex >= 0)

        val primitive = InMemoryRemotePrimitive(
            capabilities = SiteRemoteTransportTestFixtures.fullCapabilities(),
            failAtCall = targetInspectIndex + 1,
            failAfterApply = false,
            failRemoveTransactionTreeOnce = true,
        )
        val authorization = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, primitive.capabilities)
        val failure = runCatching { SiteRemoteTransportExecutor(primitive).execute(authorization, fixture.source()) }.exceptionOrNull()

        assertTrue(failure is SiteRemoteTransportRollbackException)
        val rollbackFailure = failure as SiteRemoteTransportRollbackException
        assertTrue(rollbackFailure.rollbackErrors.any { it.startsWith("published-target-cleanup:") })
        assertEquals(SiteRemoteObservedPathType.DIRECTORY, primitive.statPath(fixture.plan.publish.targetRoot))
    }
}
