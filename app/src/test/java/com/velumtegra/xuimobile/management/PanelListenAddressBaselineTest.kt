package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.XuiPanelAccessState
import com.velumtegra.xuimobile.core.ssh.XuiPanelExposure
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class PanelListenAddressBaselineTest {
    private val original = RecoveryRegressionFixture.installation
    private fun state(address: String = "0.0.0.0", port: Int = 2053) =
        XuiPanelAccessState(address, XuiPanelExposure.PUBLIC, port, "/panel/", false, false, emptyList())
    private class Repository(var current: XuiInstallation) : XuiInstallationRepository {
        var writes = 0
        var result: RepositoryResult<RecordRevision> = RepositoryResult.Success(RecordRevision(8))
        var failure: Exception? = null
        override suspend fun get(installationId: XuiInstallationId): RepositoryResult<VersionedRecord<XuiInstallation>> {
            failure?.let { throw it }
            return RepositoryResult.Success(VersionedRecord(current, RecordRevision(7)))
        }
        override suspend fun update(installation: XuiInstallation, expectedRevision: RecordRevision): RepositoryResult<RecordRevision> {
            assertEquals(RecordRevision(7), expectedRevision)
            writes++
            if (result is RepositoryResult.Success) current = installation
            return result
        }
        override suspend fun create(installation: XuiInstallation): RepositoryResult<RecordRevision> = error("create")
        override suspend fun listForServer(serverId: ServerId): RepositoryResult<List<VersionedRecord<XuiInstallation>>> = error("list")
        override suspend fun delete(installationId: XuiInstallationId, expectedRevision: RecordRevision): RepositoryResult<Unit> = error("delete")
    }

    @Test fun changesOnlyTheVerifiedListenAddressUsingTheCurrentRevision() = runBlocking {
        val repo = Repository(original)
        assertTrue(rememberPanelListenAddress(repo, original, state(" 0.0.0.0 ")))
        assertEquals(original.copy(baseline = original.baseline.copy(listenAddress = "0.0.0.0")), repo.current)
        assertEquals(1, repo.writes)
    }
    @Test fun emptyListenAddressIsCanonicalNullAndNoChangeDoesNotWrite() = runBlocking {
        val repo = Repository(original)
        assertTrue(rememberPanelListenAddress(repo, original, state(" ")))
        assertNull(repo.current.baseline.listenAddress)
        assertTrue(rememberPanelListenAddress(repo, repo.current, state("")))
        assertEquals(1, repo.writes)
    }
    @Test fun changedRecordOrPortCannotBeSilentlyRebased() = runBlocking {
        val repo = Repository(original.copy(baseline = original.baseline.copy(webBasePath = "/changed/")))
        assertFalse(rememberPanelListenAddress(repo, original, state()))
        repo.current = original
        assertFalse(rememberPanelListenAddress(repo, original, state(port = 9999)))
        assertEquals(0, repo.writes)
    }
    @Test fun failedCasDoesNotReportTheBaselineAsSaved() = runBlocking {
        val repo = Repository(original)
        repo.result = RepositoryResult.NotFound
        assertFalse(rememberPanelListenAddress(repo, original, state()))
        assertEquals(original, repo.current)
    }
    @Test fun readFailureIsReportedButCancellationPropagates() = runBlocking {
        val repo = Repository(original)
        repo.failure = IllegalStateException("fixture")
        assertFalse(rememberPanelListenAddress(repo, original, state()))
        repo.failure = CancellationException("fixture")
        try {
            rememberPanelListenAddress(repo, original, state())
            fail("Cancellation must propagate")
        } catch (_: CancellationException) { }
        assertEquals(0, repo.writes)
    }
}
