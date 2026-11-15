package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteBuildRequest
import com.velumtegra.xuimobile.core.site.SiteBuilder
import com.velumtegra.xuimobile.core.site.SiteDesignGenerator
import com.velumtegra.xuimobile.core.site.SiteDesignRequest
import com.velumtegra.xuimobile.core.site.SiteDesignSeeds
import com.velumtegra.xuimobile.core.site.SiteExistingSitePolicy
import com.velumtegra.xuimobile.core.site.SiteReplaceBlocker
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Runs the exact read-only probe commands through a local bash (standing in for the VPS shell) so
 * the shell syntax and the parser are verified together.
 */
class SiteExistingSiteReadOnlyProbeTest {
    private val adapter = SiteFirstPublicationReadOnlyObservationSshAdapter()

    @Test
    fun `absent folder is reported as absent`() = runBlocking<Unit> {
        assumeBash()
        val root = Files.createTempDirectory("velum-probe").toFile()
        val observed = adapter.observeExistingTarget("${root.absolutePath}/site", LocalBashSession())
        assertFalse(observed.present)
        root.deleteRecursively()
    }

    @Test
    fun `previously published site is inventoried and can be replaced`() = runBlocking<Unit> {
        assumeBash()
        val root = Files.createTempDirectory("velum-probe").toFile()
        val site = File(root, "site")
        val bundle = SiteBuilder.build(
            SiteBuildRequest(
                SiteDesignGenerator.generate(SiteDesignRequest(SiteDesignSeeds.fromRoot(DesignSeed(7L)))),
            ),
        )
        bundle.documents.forEach { File(site, it.path).apply { parentFile.mkdirs() }.writeText(it.content) }

        val session = LocalBashSession()
        val observed = adapter.observeExistingTarget(site.absolutePath, session)
        assertTrue(observed.present && observed.isDirectory)
        assertEquals(bundle.documents.size, observed.totalFileCount)
        assertEquals(bundle.documents.map { it.path }, observed.files.map { it.relativePath })
        assertEquals(bundle.documents.map { it.sha256 }, observed.files.map { it.sha256 })
        assertNull(SiteExistingSitePolicy.replaceBlocker(observed, portUsedByOtherService = false))

        val tree = SiteRemoteReadOnlyObservationSshAdapter().observeTree(
            site.absolutePath,
            SiteExistingSitePolicy.treeEntries(observed),
            session,
        )
        val expectation = SiteExistingSitePolicy.previousTreeExpectation(observed, tree.treeSha256)
        assertNotNull(expectation)
        assertEquals(bundle.documents.size, expectation!!.fileCount)
        root.deleteRecursively()
    }

    @Test
    fun `foreign content with images or symlinks is not replaceable`() = runBlocking<Unit> {
        assumeBash()
        val root = Files.createTempDirectory("velum-probe").toFile()
        val site = File(root, "site").apply { mkdirs() }
        File(site, "index.html").writeText("<h1>hi</h1>")
        File(site, "logo.png").writeBytes(byteArrayOf(1, 2, 3))
        val observed = adapter.observeExistingTarget(site.absolutePath, LocalBashSession())
        assertEquals(2, observed.totalFileCount)
        assertEquals(SiteReplaceBlocker.UNSUPPORTED_FILE, SiteExistingSitePolicy.replaceBlocker(observed, false))

        Files.createSymbolicLink(File(site, "link.html").toPath(), File(site, "index.html").toPath())
        val withLink = adapter.observeExistingTarget(site.absolutePath, LocalBashSession())
        assertTrue(withLink.hasSymlinksOrSpecialEntries)
        assertEquals(SiteReplaceBlocker.UNSUPPORTED_ENTRIES, SiteExistingSitePolicy.replaceBlocker(withLink, false))
        root.deleteRecursively()
    }

    @Test
    fun `endpoint probe parses config presence and listening ports`() = runBlocking<Unit> {
        assumeBash()
        val configPath = adapter.exactFutureConfigPath("server-1.example", "/srv/www/site", "site.example.com", 8443)
        val session = LocalBashSession(
            fakeSs = "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 511 [::]:8443 [::]:*\nLISTEN 0 128 127.0.0.1:2053 0.0.0.0:*\n",
        )
        val observed = adapter.observeEndpoint(configPath, 8443, session)
        assertFalse(observed.configPresent)
        assertTrue(observed.portInUse)
        assertEquals(setOf(443, 2053, 8443), observed.listeningPorts)
        assertEquals(2083, SiteExistingSitePolicy.suggestPort(8443, observed.listeningPorts))
    }

    @Test
    fun `endpoint probe fails closed without ss`() {
        assumeBash()
        val configPath = adapter.exactFutureConfigPath("server-1.example", "/srv/www/site", "site.example.com", 8443)
        assertThrows(IllegalStateException::class.java) {
            runBlocking { adapter.observeEndpoint(configPath, 8443, LocalBashSession(fakeSs = null)) }
        }
    }

    private fun assumeBash() = assumeTrue(File("/bin/bash").canExecute())

    /** Executes commands with a local bash; optionally shadows `ss` with a fixed listing. */
    private class LocalBashSession(private val fakeSs: String? = "") : VerifiedHostKeySshSessionHandle {
        override val binding = SessionBinding(
            SessionId("probe-session"),
            ServerAccessId("access-1"),
            SessionOwner.Operation(OperationId("probe-op")),
        )
        override val verifiedHostKeySha256: String = "7".repeat(64)
        override val isOpen: Boolean = true

        private val binDir: File = Files.createTempDirectory("velum-bin").toFile().also { dir ->
            if (fakeSs != null) {
                val listing = File(dir, "listing.txt").apply { writeText(fakeSs) }
                File(dir, "ss").apply {
                    writeText("#!/bin/sh\ncat '${listing.absolutePath}'\n")
                    setExecutable(true)
                }
            }
        }

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            val path = if (fakeSs != null) "${binDir.absolutePath}:/usr/bin:/bin" else hideSs("/usr/bin:/bin")
            val process = ProcessBuilder("/bin/bash", "-c", command.rawForTransport())
                .apply { environment()["PATH"] = path }
                .start()
            val stdout = process.inputStream.readBytes()
            val stderr = process.errorStream.readBytes()
            check(process.waitFor(20, TimeUnit.SECONDS))
            return SshCommandResult(
                dispatchState = CommandDispatchState.DISPATCHED,
                completion = if (process.exitValue() == 0) {
                    CommandCompletion.ConfirmedSuccess
                } else {
                    CommandCompletion.ConfirmedFailure("exit", process.exitValue())
                },
                stdout = CapturedOutput.of(stdout, false),
                stderr = CapturedOutput.of(stderr, false),
            )
        }

        /** Builds a PATH with the usual tools but without any `ss` binary. */
        private fun hideSs(base: String): String {
            val dir = File(binDir, "no-ss").apply { mkdirs() }
            base.split(':').map(::File).flatMap { it.listFiles()?.toList().orEmpty() }
                .filter { it.name != "ss" && it.canExecute() && !File(dir, it.name).exists() }
                .forEach { runCatching { Files.createSymbolicLink(File(dir, it.name).toPath(), it.toPath()) } }
            return dir.absolutePath
        }

        override fun close() = Unit
    }
}
