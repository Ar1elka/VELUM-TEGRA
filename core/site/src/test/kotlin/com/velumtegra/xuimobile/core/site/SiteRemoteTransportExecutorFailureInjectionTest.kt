package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteRemoteTransportExecutorFailureInjectionTest {
    @Test
    fun `every forward primitive failure after first mutation rolls back to original target`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(
            seed = 8193L,
            policy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
        )
        val baseline = InMemoryRemotePrimitive(
            capabilities = SiteRemoteTransportTestFixtures.fullCapabilities(),
            initialTargetRoot = fixture.plan.publish.targetRoot,
        )
        val baselineAuthorization = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, baseline.capabilities)
        val committed = SiteRemoteTransportExecutor(baseline).execute(baselineAuthorization, fixture.source())
        assertEquals(SiteRemoteTransportOutcome.COMMITTED, committed.outcome)

        val firstMutationIndex = baseline.operationLog.indexOfFirst { it.startsWith("MKDIR:") }
        assertTrue(firstMutationIndex >= 0)
        val forwardCallCount = baseline.operationLog.size

        for (zeroBasedIndex in 0 until forwardCallCount) {
            val primitive = InMemoryRemotePrimitive(
                capabilities = SiteRemoteTransportTestFixtures.fullCapabilities(),
                initialTargetRoot = fixture.plan.publish.targetRoot,
                failAtCall = zeroBasedIndex + 1,
                failAfterApply = false,
            )
            val authorization = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, primitive.capabilities)
            if (zeroBasedIndex <= firstMutationIndex) {
                val failure = runCatching { SiteRemoteTransportExecutor(primitive).execute(authorization, fixture.source()) }.exceptionOrNull()
                assertTrue("Expected pre-mutation failure at call ${zeroBasedIndex + 1}", failure != null)
                assertEquals(SiteRemoteObservedPathType.DIRECTORY, primitive.statPath(fixture.plan.publish.targetRoot))
                assertEquals(SiteRemoteObservedPathType.ABSENT, primitive.statPath(fixture.plan.publish.stagingRoot))
            } else {
                val result = SiteRemoteTransportExecutor(primitive).execute(authorization, fixture.source())
                assertEquals("Failure at call ${zeroBasedIndex + 1}", SiteRemoteTransportOutcome.ROLLED_BACK, result.outcome)
                assertTrue(result.rollbackPerformed)
                assertEquals(SiteRemoteObservedPathType.DIRECTORY, primitive.statPath(fixture.plan.publish.targetRoot))
                assertEquals(SiteRemoteObservedPathType.ABSENT, primitive.statPath(fixture.plan.publish.stagingRoot))
                assertEquals(SiteRemoteObservedPathType.ABSENT, primitive.statPath(requireNotNull(fixture.plan.publish.backupRoot)))
                assertTrue(primitive.hasFile("${fixture.plan.publish.targetRoot}/legacy.txt"))
            }
        }
    }

    @Test
    fun `bad local source is rejected before the first remote primitive call`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(8194L, SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT)
        val primitive = InMemoryRemotePrimitive(SiteRemoteTransportTestFixtures.fullCapabilities())
        val authorization = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, primitive.capabilities)
        val firstPath = fixture.exportPlan.entries.first().path
        val good = fixture.exportPlan.entries.associate { it.path to it.content.encodeToByteArray() }
        val badSource = SiteRemoteTransportSource { path ->
            if (path == firstPath) "tampered".encodeToByteArray() else requireNotNull(good[path])
        }

        val failure = runCatching { SiteRemoteTransportExecutor(primitive).execute(authorization, badSource) }.exceptionOrNull()
        assertTrue(failure != null)
        assertTrue(primitive.operationLog.isEmpty())
    }
}
