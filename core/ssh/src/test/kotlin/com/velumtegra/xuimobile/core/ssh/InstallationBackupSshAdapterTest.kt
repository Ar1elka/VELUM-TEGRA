package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class InstallationBackupSshAdapterTest {
    private val at = Instant.parse("2026-10-17T06:00:00Z")
    private val scope = ManagementScope(OperationId("archive"), ServerId("server"), ServerAccessId("ssh"), XuiInstallationId("install"))
    private val binding = InstallationBackupBinding("3.10.0", UpdateServerArchitecture.AMD64, "a".repeat(64))
    private val adapter = InstallationBackupSshAdapter { at }
    private fun proof() = "FORMAT=VELUM_KNOWN_INSTALLATION_V1\nSCOPE=${binding.digest}\nVERSION=3.10.0\nARCH=AMD64\nBYTES=20480\nSHA256=${"b".repeat(64)}\nDATABASE_SHA256=${"c".repeat(64)}\nFILES=3\nINVENTORY_SHA256=${"d".repeat(64)}\n"
    private fun ok(raw: String) = SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess,
        CapturedOutput.of(raw.toByteArray(), false), CapturedOutput.EMPTY)
    private inner class Handle : SshSessionHandle {
        override var binding = SessionBinding(SessionId("session"), scope.serverAccessId, SessionOwner.Operation(scope.operationId))
        override var isOpen = true
        val labels = mutableListOf<String>()
        var respond: (String) -> SshCommandResult = { label -> ok(if (label == "installation-backup-storage") "0\n4096000000\n" else proof()) }
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            assertTrue(config.stdoutCaptureLimitBytes <= 1024); assertTrue(config.stderrCaptureLimitBytes <= 512)
            labels += command.redactedLabel
            return respond(command.redactedLabel)
        }
        override fun close() { isOpen = false }
    }
    @Test fun closedManifestReturnsOnlyTypedExactProof() = runBlocking {
        val h = Handle(); val r = requireNotNull(adapter.verify(scope, binding, h))
        assertEquals(scope, r.scope); assertEquals(binding, r.binding); assertEquals(3, r.fileCount)
        assertEquals("b".repeat(64), r.sha256); assertEquals("c".repeat(64), r.databaseSha256)
        assertEquals(listOf("installation-backup-verify-existing"), h.labels)
    }
    @Test fun foreignOwnerAccessOrClosedSessionCannotRead() = runBlocking {
        for (which in 0..2) {
            val h = Handle()
            when(which) { 0 -> h.binding = h.binding.copy(owner = SessionOwner.Operation(OperationId("foreign")))
                1 -> h.binding = h.binding.copy(serverAccessId = ServerAccessId("foreign")); else -> h.isOpen = false }
            assertNull(adapter.verify(scope, binding, h)); assertNull(adapter.storage(scope, h)); assertTrue(h.labels.isEmpty())
        }
    }
    @Test fun wrongScopeVersionArchitectureOrFormatCannotPublishReceipt() = runBlocking {
        for (raw in listOf(proof().replace(binding.digest, "e".repeat(64)), proof().replace("3.10.0", "3.10.1"),
            proof().replace("AMD64", "ARM64"), proof().replace("VELUM_KNOWN_INSTALLATION_V1", "VELUM_DB_BACKUP_V1"))) {
            val h = Handle(); h.respond = { ok(raw) }; assertNull(adapter.verify(scope, binding, h))
        }
    }
    @Test fun missingExtraDuplicateOrUnterminatedFieldsAreRejected() = runBlocking {
        for (raw in listOf(proof().replace("FILES=3\n", ""), proof() + "PRIVATE=hidden\n", proof().replace("FILES=3", "ARCH=AMD64"), proof().dropLast(1))) {
            val h = Handle(); h.respond = { ok(raw) }; assertNull(adapter.verify(scope, binding, h))
        }
    }
    @Test fun invalidMemberCountArchiveSizeOrHashAreRejected() = runBlocking {
        for (raw in listOf(proof().replace("FILES=3", "FILES=97"), proof().replace("FILES=3", "FILES=0"),
            proof().replace("BYTES=20480", "BYTES=738197505"), proof().replace("BYTES=20480", "BYTES=0"),
            proof().replace("c".repeat(64), "invalid"), proof().replace("d".repeat(64), "e".repeat(63)))) {
            val h = Handle(); h.respond = { ok(raw) }; assertNull(adapter.verify(scope, binding, h))
        }
    }
    @Test fun unknownTransportTruncationStderrOrInvalidUtf8NeverBecomeProof() = runBlocking {
        val bad = listOf(ok(proof()).copy(completion = CommandCompletion.Unknown("private")),
            ok(proof()).copy(stderr = CapturedOutput.of("private".toByteArray(), false)),
            ok(proof()).copy(stdout = CapturedOutput.of(proof().toByteArray(), true)),
            ok(proof()).copy(stdout = CapturedOutput.of(byteArrayOf(0xc3.toByte(), 0x28), false)))
        for (value in bad) { val h = Handle(); h.respond = { value }; assertNull(adapter.verify(scope, binding, h)) }
    }
    @Test fun sessionReplacementDuringReadCannotPublishLateReceipt() = runBlocking {
        val h = Handle(); h.respond = { h.binding = h.binding.copy(sessionId = SessionId("other")); ok(proof()) }
        assertNull(adapter.verify(scope, binding, h))
    }
    @Test fun storageRejectsMalformedOverflowAndFifthSlot() = runBlocking {
        for (raw in listOf("5\n100\n", "0\n9999999999999999999\n", "0\n-1\n", "0\n100\nextra\n")) {
            val h = Handle(); h.respond = { ok(raw) }; assertNull(adapter.storage(scope, h))
        }
        assertEquals(4096000000L, requireNotNull(adapter.storage(scope, Handle())).availableBytes)
    }
    @Test fun storageAlsoDiscardsReplacedSession() = runBlocking {
        val h = Handle(); h.respond = { h.binding = h.binding.copy(sessionId = SessionId("other")); ok("0\n4096000000\n") }
        assertNull(adapter.storage(scope, h))
    }
    @Test fun commandArgumentsAreClosedAndWorkerNeverLoadsExternalCode() {
        val command = InstallationBackupCommands.copy(binding, "e".repeat(64))
        assertTrue(command.startsWith("timeout --kill-after=2s 90s python3 -I -c "))
        assertTrue(command.endsWith(" create ${binding.digest} 3.10.0 AMD64 ${"e".repeat(64)}"))
        assertTrue(InstallationBackupCommands.verify(binding).endsWith(" verify ${binding.digest} 3.10.0 AMD64 ${"0".repeat(64)}"))
        assertTrue(InstallationBackupWorker.source.contains("source.backup(target"))
        assertFalse(InstallationBackupWorker.source.contains("extractall("))
    }
}
