package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteRemoteTransportFakePortTest {
    @Test
    fun `deterministic in memory fake consumes only authorization and bounded source`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(8131L, SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT)
        val fake = RecordingFakeTransport(SiteRemoteTransportTestFixtures.fullCapabilities())
        val authorization = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, fake.capabilities)
        val sourceBytes = fixture.exportPlan.entries.associate { it.path to it.content.encodeToByteArray() }
        val source = SiteRemoteTransportSource { path -> requireNotNull(sourceBytes[path]) }

        val first = fake.execute(authorization, source)
        val firstLog = fake.operationLog.toList()
        fake.operationLog.clear()
        val second = fake.execute(authorization, source)

        assertEquals(first, second)
        assertEquals(firstLog, fake.operationLog)
        assertEquals(SiteRemoteTransportOutcome.COMMITTED, first.outcome)
        assertEquals(fixture.plan.fileCount, first.uploadedFileCount)
        assertEquals(fixture.plan.totalBytes, first.uploadedBytes)
        assertEquals(fixture.plan.sourceTreeSha256, first.publishedTreeSha256)
        assertTrue(fake.operationLog.first().startsWith("ASSERT:"))
        SiteRemoteTransportPolicy.validateResult(authorization, first)
    }

    private class RecordingFakeTransport(
        override val capabilities: SiteRemoteTransportCapabilities,
    ) : SiteRemoteTransportPort {
        val operationLog = mutableListOf<String>()

        override fun execute(
            authorization: SiteRemoteTransportAuthorization,
            source: SiteRemoteTransportSource,
        ): SiteRemoteTransportResult {
            SiteRemoteTransportPolicy.validateCapabilities(capabilities)
            SiteRemoteTransportPolicy.validateAuthorization(authorization)
            require(authorization.implementationId == capabilities.implementationId)
            require(authorization.capabilityProfileSha256 == SiteRemoteTransportPolicy.capabilityProfileSha256(capabilities))

            var files = 0
            var bytes = 0L
            authorization.forwardOperations.forEach { operation ->
                operationLog += operation.logValue()
                if (operation is SiteRemoteTransportOperation.UploadFile) {
                    val payload = source.read(operation.relativePath)
                    require(payload.size == operation.byteSize)
                    require(SiteBundleDigest.sha256(payload) == operation.sha256)
                    files += 1
                    bytes += payload.size
                }
            }
            return SiteRemoteTransportResult(
                authorizationSha256 = authorization.authorizationSha256,
                outcome = SiteRemoteTransportOutcome.COMMITTED,
                uploadedFileCount = files,
                uploadedBytes = bytes,
                publishedTreeSha256 = authorization.sourceTreeSha256,
                rollbackPerformed = false,
            ).also { SiteRemoteTransportPolicy.validateResult(authorization, it) }
        }

        private fun SiteRemoteTransportOperation.logValue(): String = when (this) {
            is SiteRemoteTransportOperation.AssertPathState -> "ASSERT:$path:${expectedType.name}"
            is SiteRemoteTransportOperation.CreateDirectory -> "MKDIR:$path"
            is SiteRemoteTransportOperation.UploadFile -> "UPLOAD:$relativePath:$sha256"
            is SiteRemoteTransportOperation.VerifyFileSha256 -> "VERIFY_FILE:$remotePath:$expectedSha256"
            is SiteRemoteTransportOperation.ApplyFileMetadata -> "FILE_META:$remotePath:$mode"
            is SiteRemoteTransportOperation.ApplyDirectoryMetadata -> "DIR_META:$remotePath:$mode"
            is SiteRemoteTransportOperation.VerifyTree -> "VERIFY_TREE:$rootPath:$expectedTreeSha256"
            is SiteRemoteTransportOperation.AtomicRename -> "RENAME:$fromPath:$toPath:${purpose.name}"
            is SiteRemoteTransportOperation.RemoveTransactionTree -> "REMOVE:$path:$transactionOwnedOnly"
        }
    }
}
