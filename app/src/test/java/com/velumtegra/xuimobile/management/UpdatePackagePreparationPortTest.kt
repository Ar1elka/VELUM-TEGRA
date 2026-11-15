package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.model.*
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.net.URI
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class UpdatePackagePreparationPortTest {
    @get:Rule val temporary = TemporaryFolder()
    private val time = Instant.parse("2026-10-16T20:00:00Z")
    private val report = UpdatePreflightSnapshot(ManagementScope(OperationId("operation"), ServerId("server"),
        ServerAccessId("ssh"), XuiInstallationId("installation")), UpdateRootStatus.DIRECT_ROOT,
        UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD, DeepDiagnosticServiceDefinitionStatus.CONSISTENT,
        "3.10.0", ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, time,
        UpdateServerArchitecture.AMD64)
    private val release = ReviewedXuiUpdatePackage.V3_10_2_AMD64
    private val request = UpdatePackageRequest(report, release)
    private val statuses = UpdatePreflightStatusPort { server, installation, pointer ->
        assertEquals("server", server); assertEquals("installation", installation)
        assertEquals(UpdatePreflightPointer("operation", "ssh"), pointer)
        UpdatePreflightStatus("completed", true, report)
    }
    private fun response(status: Int = 200, location: String? = null, length: Long? = null,
        body: InputStream = ByteArrayInputStream("fixture does not match a real release".toByteArray())) =
        UpdatePackageHttpResponse(status, location, length, body)

    @Test fun expiredReportCannotCauseANetworkRequest() = runBlocking {
        val opens = AtomicInteger()
        val port = OfficialUpdatePackagePreparationPort(temporary.newFolder(), statuses,
            UpdatePackageHttpTransport { opens.incrementAndGet(); response() }, now = { time.plusSeconds(601) })
        assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.REPORT_CHANGED), port.prepare(request))
        assertEquals(0, opens.get())
    }
    @Test fun missingExactDurableResultBlocksBeforeAnyDownload() = runBlocking {
        val opens = AtomicInteger()
        val port = OfficialUpdatePackagePreparationPort(temporary.newFolder(),
            UpdatePreflightStatusPort { _, _, _ -> UpdatePreflightStatus("completion only", true) },
            UpdatePackageHttpTransport { opens.incrementAndGet(); response() }, now = { time })
        assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.REPORT_CHANGED), port.prepare(request))
        assertEquals(0, opens.get())
    }
    @Test fun architectureMismatchIsBlockedBeforeNetwork() = runBlocking {
        val opens = AtomicInteger()
        val port = OfficialUpdatePackagePreparationPort(temporary.newFolder(), statuses,
            UpdatePackageHttpTransport { opens.incrementAndGet(); response() }, now = { time })
        assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.REPORT_CHANGED),
            port.prepare(request.copy(release = ReviewedXuiUpdatePackage.V3_10_2_ARM64)))
        assertEquals(0, opens.get())
    }
    @Test fun foreignRedirectNeverGetsOpenedAndLeavesNoPartialFile() = runBlocking {
        val dir = temporary.newFolder(); val opened = mutableListOf<URI>()
        val port = OfficialUpdatePackagePreparationPort(dir, statuses,
            UpdatePackageHttpTransport { opened += it; response(302, "https://private.invalid/secret") }, now = { time })
        assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.DOWNLOAD_REJECTED), port.prepare(request))
        assertEquals(listOf(URI(release.downloadUrl)), opened)
        assertTrue(dir.listFiles().orEmpty().isEmpty())
    }
    @Test fun redirectLoopHasAFiniteRequestBound() = runBlocking {
        val dir = temporary.newFolder(); val opens = AtomicInteger()
        val port = OfficialUpdatePackagePreparationPort(dir, statuses,
            UpdatePackageHttpTransport { opens.incrementAndGet(); response(302, release.downloadUrl) }, now = { time })
        assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.DOWNLOAD_REJECTED), port.prepare(request))
        assertEquals(5, opens.get()); assertTrue(dir.listFiles().orEmpty().isEmpty())
    }
    @Test fun declaredOversizeIsRejectedBeforeReadingAnyPayload() = runBlocking {
        val reads = AtomicInteger(); val dir = temporary.newFolder()
        val body = object : InputStream() {
            override fun read(): Int { reads.incrementAndGet(); return 1 }
        }
        val port = OfficialUpdatePackagePreparationPort(dir, statuses,
            UpdatePackageHttpTransport { response(length = UpdatePackageReceipt.MAX_BYTES + 1, body = body) }, now = { time })
        assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.TOO_LARGE), port.prepare(request))
        assertEquals(0, reads.get()); assertTrue(dir.listFiles().orEmpty().isEmpty())
    }
    @Test fun wrongDigestIsRejectedAndTheUnverifiedFileIsDeleted() = runBlocking {
        val dir = temporary.newFolder()
        val port = OfficialUpdatePackagePreparationPort(dir, statuses, UpdatePackageHttpTransport { response() }, now = { time })
        assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.INTEGRITY), port.prepare(request))
        assertTrue(dir.listFiles().orEmpty().isEmpty())
    }
    @Test fun emptyReleaseResponseIsNotAValidPackage() = runBlocking {
        val dir = temporary.newFolder()
        val port = OfficialUpdatePackagePreparationPort(dir, statuses,
            UpdatePackageHttpTransport { response(body = ByteArrayInputStream(byteArrayOf())) }, now = { time })
        assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.INTEGRITY), port.prepare(request))
        assertTrue(dir.listFiles().orEmpty().isEmpty())
    }
    @Test fun interruptedReadCannotLeakRawExceptionTextOrRetainAReceipt() = runBlocking {
        val dir = temporary.newFolder()
        val body = object : InputStream() {
            override fun read(): Int = throw IOException("PrivateToken=NeverShow")
        }
        val port = OfficialUpdatePackagePreparationPort(dir, statuses,
            UpdatePackageHttpTransport { response(body = body) }, now = { time })
        val result = port.prepare(request)
        assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.UNAVAILABLE), result)
        assertFalse(result.toString().contains("NeverShow")); assertTrue(dir.listFiles().orEmpty().isEmpty())
    }
    @Test fun cancellationDeletesThePartialFileAndPropagates() = runBlocking {
        val dir = temporary.newFolder()
        val body = object : InputStream() {
            override fun read(): Int = throw CancellationException("fixture")
        }
        val port = OfficialUpdatePackagePreparationPort(dir, statuses,
            UpdatePackageHttpTransport { response(body = body) }, now = { time })
        try { port.prepare(request); fail("Cancellation ignored") } catch (_: CancellationException) { }
        assertTrue(dir.listFiles().orEmpty().isEmpty())
    }
    @Test fun parallelConfirmationCannotStartAnotherDownload() = runBlocking {
        val entered = CompletableDeferred<Unit>(); val releaseRead = CountDownLatch(1)
        val opens = AtomicInteger(); val dir = temporary.newFolder()
        val port = OfficialUpdatePackagePreparationPort(dir, statuses, UpdatePackageHttpTransport {
            opens.incrementAndGet(); entered.complete(Unit)
            check(releaseRead.await(5, TimeUnit.SECONDS)); response()
        }, now = { time })
        val first = async { port.prepare(request) }
        try {
            entered.await()
            assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.BUSY), port.prepare(request))
            assertEquals(1, opens.get())
        } finally { releaseRead.countDown() }
        assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.INTEGRITY), first.await())
    }
    @Test fun cleanupDoesNotDeleteUnrelatedCacheFiles() = runBlocking {
        val dir = temporary.newFolder(); val unrelated = java.io.File(dir, "other-feature.txt").apply { writeText("keep") }
        val port = OfficialUpdatePackagePreparationPort(dir, statuses, UpdatePackageHttpTransport { response(404) }, now = { time })
        assertEquals(UpdatePackagePreparationResult.Failed(UpdatePackagePreparationFailure.DOWNLOAD_REJECTED), port.prepare(request))
        assertEquals("keep", unrelated.readText())
    }
    @Test fun downloadAuthorityAllowsOnlyTheFixedAssetAndBoundedGithubCdnRedirects() {
        assertTrue(UpdatePackageDownloadUrlPolicy.allowed(release, URI(release.downloadUrl)))
        assertTrue(UpdatePackageDownloadUrlPolicy.allowed(release, URI("https://release-assets.githubusercontent.com/github-production-release-asset/123/file?token=fixture")))
        listOf("http://github.com/MHSanaei/3x-ui/releases/download/v3.10.2/x-ui-linux-amd64.tar.gz",
            "https://github.com/foreign/project/file", "https://github.com/MHSanaei/3x-ui/releases/latest/download/x-ui-linux-amd64.tar.gz",
            release.downloadUrl + "?token=other", release.downloadUrl + "#fragment",
            "https://release-assets.githubusercontent.com.evil.invalid/github-production-release-asset/file",
            "https://user@release-assets.githubusercontent.com/github-production-release-asset/file",
            "https://release-assets.githubusercontent.com:8443/github-production-release-asset/file",
            "https://release-assets.githubusercontent.com/github-production-release-asset/../file",
            "https://127.0.0.1/github-production-release-asset/file").forEach {
                assertFalse(it, UpdatePackageDownloadUrlPolicy.allowed(release, URI(it)))
            }
    }
}
