package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class DatabaseBackupSshAdapterTest {
    private val at = Instant.parse("2026-10-17T01:00:00Z")
    private val scope = ManagementScope(OperationId("copy"), ServerId("server"), ServerAccessId("ssh"), XuiInstallationId("install"))
    private val b = DatabaseBackupBinding("3.10.0", UpdateServerArchitecture.AMD64, "a".repeat(64))
    private val sum = "b".repeat(64)
    private val adapter = DatabaseBackupSshAdapter { at }
    private fun meta() = "8|10|0|600|4096|1792180000|1792180000|1\n8|11|0|600|${manifest().toByteArray().size}|1792180000|1792180000|1\n"
    private fun manifest() = "FORMAT=VELUM_DB_BACKUP_V1\nSCOPE=${b.digest}\nVERSION=3.10.0\nARCH=AMD64\nBYTES=4096\nSHA256=$sum\n"
    private fun ok(raw: String) = SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess,
        CapturedOutput.of(raw.toByteArray(), false), CapturedOutput.EMPTY)
    private inner class Handle : SshSessionHandle {
        override var binding = SessionBinding(SessionId("session"), scope.serverAccessId, SessionOwner.Operation(scope.operationId))
        override var isOpen = true
        val labels = mutableListOf<String>()
        val commands = mutableListOf<String>()
        var respond: (String, Int) -> SshCommandResult = { label, _ -> ok(when (label) {
            "database-backup-storage" -> "0\n1000000|4096\n"
            "database-backup-artifact-metadata" -> meta()
            "database-backup-manifest" -> manifest()
            "database-backup-sha256" -> "$sum  ${b.remoteDirectory}/database.sqlite\n"
            "database-backup-integrity" -> "ok\n"
            "database-backup-create-once" -> "CREATED\n"
            else -> error("Unexpected fixture command")
        }) }
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            assertTrue(config.stdoutCaptureLimitBytes <= 512); assertTrue(config.stderrCaptureLimitBytes <= 512)
            labels += command.redactedLabel; commands += command.rawForTransport()
            return respond(command.redactedLabel, labels.size)
        }
        override fun close() { isOpen = false }
    }
    @Test fun completeProofRequiresMetadataManifestHashIntegrityAndStableReadback() = runBlocking {
        val h = Handle(); val receipt = requireNotNull(adapter.verify(scope, b, h))
        assertEquals(4096, receipt.sizeBytes.toInt()); assertEquals(sum, receipt.sha256)
        assertEquals(listOf("database-backup-artifact-metadata", "database-backup-manifest", "database-backup-sha256",
            "database-backup-integrity", "database-backup-artifact-metadata"), h.labels)
        h.commands.forEach { assertFalse(it.contains(".backup")); assertFalse(it.contains("mkdir")); assertFalse(it.contains("rm ")) }
    }
    @Test fun foreignSessionOrClosedHandleCannotReadArtifact() = runBlocking {
        val h = Handle(); h.binding = h.binding.copy(serverAccessId = ServerAccessId("foreign"))
        assertNull(adapter.verify(scope, b, h)); assertNull(adapter.storage(scope, h)); assertTrue(h.labels.isEmpty())
        h.isOpen = false; assertNull(adapter.verify(scope, b, h))
    }
    @Test fun unsafeModesOwnershipLinksAndSizeNeverProduceReceipt() = runBlocking {
        listOf(meta().replace("|600|4096|", "|644|4096|"), meta().replace("8|10|0|", "8|10|1000|"),
            meta().replace("|1\n", "|2\n"), meta().replace("|4096|", "|134217729|")).forEach { bad ->
            val h = Handle(); h.respond = { _, _ -> ok(bad) }
            assertNull(adapter.verify(scope, b, h)); assertEquals(1, h.labels.size)
        }
    }
    @Test fun metadataChangingAfterHashCannotCreateCompletion() = runBlocking {
        val h = Handle(); val base = h.respond
        h.respond = { label, index -> if (index == 5) ok(meta().replace("|10|", "|20|")) else base(label, index) }
        assertNull(adapter.verify(scope, b, h))
    }
    @Test fun wrongManifestScopeVersionArchitectureOrSizeCannotBeAccepted() = runBlocking {
        listOf(manifest().replace(b.digest, "c".repeat(64)), manifest().replace("3.10.0", "3.10.1"),
            manifest().replace("AMD64", "ARM64"), manifest().replace("4096", "8192")).forEach { bad ->
            val h = Handle(); val base = h.respond
            h.respond = { label, index -> if (label == "database-backup-manifest") ok(bad) else base(label, index) }
            assertNull(adapter.verify(scope, b, h))
        }
    }
    @Test fun duplicateExtraOrUnterminatedManifestIsRejected() = runBlocking {
        listOf(manifest() + "SECRET=private\n", manifest().replace("ARCH=AMD64", "VERSION=3.10.0"), manifest().dropLast(1)).forEach { bad ->
            val h = Handle(); val base = h.respond
            h.respond = { label, index -> if (label == "database-backup-manifest") ok(bad) else base(label, index) }
            assertNull(adapter.verify(scope, b, h))
        }
    }
    @Test fun actualHashMismatchAndFailedQuickCheckAreIndependent() = runBlocking {
        listOf("database-backup-sha256" to "c".repeat(64) + "  ${b.remoteDirectory}/database.sqlite\n",
            "database-backup-integrity" to "database corrupt\n").forEach { (which, bad) ->
            val h = Handle(); val base = h.respond
            h.respond = { label, index -> if (label == which) ok(bad) else base(label, index) }
            assertNull(adapter.verify(scope, b, h))
        }
    }
    @Test fun transportUnknownStderrAndTruncatedDataAreNotFacts() = runBlocking {
        listOf(ok(meta()).copy(completion = CommandCompletion.Unknown("private detail")),
            ok(meta()).copy(stderr = CapturedOutput.of("private detail".toByteArray(), false)),
            ok(meta()).copy(stdout = CapturedOutput.of(meta().toByteArray(), true))).forEach { bad ->
            val h = Handle(); h.respond = { _, _ -> bad }; assertNull(adapter.verify(scope, b, h))
        }
    }
    @Test fun sessionReplacementAfterSuspensionDiscardsProof() = runBlocking {
        val h = Handle(); val base = h.respond
        h.respond = { label, index -> val r = base(label, index); h.binding = h.binding.copy(sessionId = SessionId("replacement")); r }
        assertNull(adapter.verify(scope, b, h)); assertEquals(1, h.labels.size)
    }
    @Test fun boundedStorageRejectsOverflowExtraLinesAndMalformedCounts() = runBlocking {
        listOf("6\n100|4096\n", "0\n999999999999999999|999999999999999999\n", "0\n1|4096\nsecret\n").forEach { raw ->
            val h = Handle(); h.respond = { _, _ -> ok(raw) }; assertNull(adapter.storage(scope, h))
        }
        assertEquals(4096000000L, requireNotNull(adapter.storage(scope, Handle())).availableBytes)
    }
    @Test fun closedCommandUsesSqliteBackupLimitsPrivateStorageAndAtomicQuotaLock() {
        val raw = DatabaseBackupCommands.copy(b)
        listOf("-readonly", ".backup", "umask 077", "mkdir -m 700", "prlimit --fsize=134217728:134217728",
            "flock -n 9", "manifest.pending", "mv -T", "sync -f").forEach { assertTrue(raw.contains(it)) }
        listOf("rm ", "curl", "wget", "systemctl stop", "systemctl restart", "chmod", "chown").forEach { assertFalse(raw.contains(it)) }
    }
}
