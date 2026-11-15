package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class UpdateRecoveryReadinessSshReaderTest {
    private val time = Instant.parse("2026-10-17T00:00:00Z")
    private val installation = XuiInstallation(XuiInstallationId("install"), ServerId("server"), InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", null, time))
    private val scope = ManagementScope(OperationId("check"), installation.serverId, ServerAccessId("ssh"), installation.id)
    private suspend fun read(handle: Handle = Handle(), request: ManagementScope = scope, target: XuiInstallation = installation) =
        UpdateRecoveryReadinessSshReader { time }.read(request, target, handle)
    private suspend fun source(handle: Handle = Handle()) = (read(handle) as UpdateRecoveryReadinessSshResult.Completed).snapshot
    private val metadata = "META=8|1|0|0|600|4096|1792180000|1792180000\n"
    private fun success(raw: String) = SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess,
        CapturedOutput.of(raw.toByteArray(), false), CapturedOutput.EMPTY)

    @Test fun finiteReadOnlyCommandsShareOneSessionAndDoNotCopyAnyData() = runBlocking {
        val h = Handle(); val result = source(h)
        assertEquals(scope, result.scope); assertEquals(UpdateRecoveryDatabaseState.PRIVATE_REGULAR, result.database)
        assertEquals(4096L, result.databaseBytes); assertEquals(DeepDiagnosticDatabaseIntegrityStatus.OK, result.integrity)
        assertEquals(7, h.labels.size); assertEquals(2, h.labels.count { it == "update-recovery-database-metadata" })
        assertEquals(UpdateRecoveryPanelTlsState.NOT_CONFIGURED, result.panelTls)
        h.commands.forEach { raw ->
            listOf("mkdir", "chmod", "chown", "curl", "wget", ".backup", "restore", " restart", " stop", "rm ", "cp ", "tar -", "VACUUM").forEach {
                assertFalse("Unexpected mutation: $it", raw.contains(it))
            }
        }
    }
    @Test fun foreignOperationOrAccessRunsNoProbe() = runBlocking {
        val h = Handle(); assertTrue(read(h, request = scope.copy(operationId = OperationId("foreign"))) is UpdateRecoveryReadinessSshResult.Failed)
        assertTrue(h.labels.isEmpty())
    }
    @Test fun nonstandardInstallationCannotReadStandardPaths() = runBlocking {
        val h = Handle()
        assertTrue(read(h, target = installation.copy(identity = installation.identity.copy(databasePath = "/opt/custom.db"))) is UpdateRecoveryReadinessSshResult.Failed)
        assertTrue(h.labels.isEmpty())
    }
    @Test fun missingSqliteIsTypedAndNeverTriggersAnInstallOrDatabaseQuery() = runBlocking {
        val h = Handle(); h.tools = h.tools.replace("SQLITE3=AVAILABLE", "SQLITE3=MISSING")
        val result = source(h)
        assertEquals(UpdateRecoveryToolState.MISSING, result.tools[UpdateRecoveryTool.SQLITE3])
        assertEquals(DeepDiagnosticDatabaseIntegrityStatus.UNREADABLE, result.integrity)
        assertFalse(h.labels.any { it.startsWith("deep-database") || it == "deep-certificate-references" })
    }
    @Test fun truncatedRequiredReadbackFailsWithoutPublishingAPartialSource() = runBlocking {
        val h = Handle(); h.rewrite = { label, result -> if (label == "update-recovery-tools") result.copy(stdout = CapturedOutput.of("SQLITE3=AVAILABLE\n".toByteArray(), true)) else result }
        assertEquals(UpdateRecoveryReadinessSshResult.Failed(UpdatePreflightFailure.READBACK_UNAVAILABLE), read(h))
        assertEquals(1, h.labels.size)
    }
    @Test fun uncertainTransportCannotBeDowngradedToAnOrdinaryMissingFile() = runBlocking {
        val h = Handle(); h.rewrite = { label, result -> if (label == "deep-database-quick-check") result.copy(completion = CommandCompletion.Unknown("PrivateValue")) else result }
        val result = read(h)
        assertEquals(UpdateRecoveryReadinessSshResult.Failed(UpdatePreflightFailure.TRANSPORT_UNCERTAIN), result)
        assertFalse(result.toString().contains("PrivateValue")); assertEquals(4, h.labels.size)
    }
    @Test fun changedSessionBindingSuppressesEvenSuccessfulReadback() = runBlocking {
        val h = Handle(); h.after = { h.binding = h.binding.copy(sessionId = SessionId("replacement")) }
        assertEquals(UpdateRecoveryReadinessSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT), read(h))
        assertEquals(1, h.labels.size)
    }
    @Test fun successfulCommandWithUnexpectedStderrIsRejectedAndRedacted() = runBlocking {
        val h = Handle(); h.rewrite = { _, result -> result.copy(stderr = CapturedOutput.of("password=PrivateValue".toByteArray(), false)) }
        val result = read(h); assertTrue(result is UpdateRecoveryReadinessSshResult.Failed)
        assertFalse(result.toString().contains("PrivateValue"))
    }
    @Test fun duplicateMissingOrArbitraryToolKeysCannotFormASourceReport() = runBlocking {
        listOf("SQLITE3=AVAILABLE\n".repeat(4), "SQLITE3=AVAILABLE\nTAR=AVAILABLE\nSHA256SUM=AVAILABLE\nSECRET=AVAILABLE\n", "PrivateValue").forEach { raw ->
            val h = Handle(); h.tools = raw
            assertEquals(UpdateRecoveryReadinessSshResult.Failed(UpdatePreflightFailure.READBACK_UNAVAILABLE), read(h))
        }
    }
    @Test fun databaseSymlinkIsReportedAndNeverOpenedBySqlite() = runBlocking {
        val h = Handle(); h.metadataBefore = "UNSAFE_LINK\n"; h.metadataAfter = h.metadataBefore
        assertEquals(UpdateRecoveryDatabaseState.UNSAFE_LINK, source(h).database)
        assertFalse(h.labels.contains("deep-database-quick-check"))
    }
    @Test fun unsafeOwnerPermissionsAndSpecialModeBitsPreventDatabaseQueries() = runBlocking {
        listOf("8|1|1000|0|600|4096|1|1", "8|1|0|0|644|4096|1|1", "8|1|0|0|4600|4096|1|1").forEach { fields ->
            val h = Handle(); h.metadataBefore = "META=$fields\n"; h.metadataAfter = h.metadataBefore
            assertEquals(UpdateRecoveryDatabaseState.UNSAFE_PERMISSIONS, source(h).database)
            assertFalse(h.labels.contains("deep-database-quick-check"))
        }
    }
    @Test fun oversizedDatabaseIsNotSubjectedToUnboundedIntegrityReads() = runBlocking {
        val h = Handle(); h.metadataBefore = metadata.replace("|4096|", "|${UpdateRecoverySourceSnapshot.MAX_DATABASE_BYTES + 1}|"); h.metadataAfter = h.metadataBefore
        assertEquals(UpdateRecoveryDatabaseState.TOO_LARGE, source(h).database)
        assertFalse(h.labels.contains("deep-database-quick-check"))
    }
    @Test fun absentAndZeroLengthFilesDoNotBecomeValidSources() = runBlocking {
        listOf("UNAVAILABLE\n", metadata.replace("|4096|", "|0|")).forEach { raw ->
            val h = Handle(); h.metadataBefore = raw; h.metadataAfter = raw
            assertEquals(UpdateRecoveryDatabaseState.UNAVAILABLE, source(h).database)
            assertFalse(h.labels.contains("deep-database-quick-check"))
        }
    }
    @Test fun changedFileIdentityBetweenReadsBlocksTheSourceWithoutInventingConsistency() = runBlocking {
        val h = Handle(); h.metadataAfter = metadata.replace("META=8|1|", "META=8|2|")
        val result = source(h); assertEquals(UpdateRecoveryDatabaseState.CHANGED_DURING_READ, result.database); assertNull(result.databaseBytes)
    }
    @Test fun integrityFailurePublishesOnlyTheFiniteFindingWithoutRawDatabaseText() = runBlocking {
        val h = Handle(); h.integrity = "corrupt row password=PrivateValue\n"
        val result = source(h); assertEquals(DeepDiagnosticDatabaseIntegrityStatus.FAILED, result.integrity)
        assertFalse(result.toString().contains("PrivateValue"))
    }
    @Test fun incompleteSchemaDoesNotQueryPrivateCertificateReferences() = runBlocking {
        val h = Handle(); h.schema = "INCOMPLETE\n"
        val result = source(h); assertEquals(DeepDiagnosticDatabaseSchemaStatus.INCOMPLETE, result.schema)
        assertEquals(UpdateRecoveryPanelTlsState.UNOBSERVED, result.panelTls)
        assertFalse(h.labels.contains("deep-certificate-references"))
    }
    @Test fun configuredTlsPairUsesOnlyExactPresenceProbesAndNeverPublishesPaths() = runBlocking {
        val h = Handle(); h.references = "CERT=/private/SecretCertificate.pem\nKEY=/private/SecretKey.pem\n"
        val result = source(h); assertEquals(UpdateRecoveryPanelTlsState.PAIR_PRESENT, result.panelTls)
        assertEquals(2, h.labels.count { it == "deep-private-key-presence" })
        assertFalse(result.toString().contains("/private")); assertFalse(result.toString().contains("SecretKey"))
        h.commands.filter { it.contains("SecretKey") }.forEach { assertFalse(it.contains("cat ")); assertFalse(it.contains("openssl")) }
    }
    @Test fun incompleteAndMissingTlsFilesRemainBlockingFacts() = runBlocking {
        val partial = Handle(); partial.references = "CERT=/private/cert.pem\nKEY=\n"
        assertEquals(UpdateRecoveryPanelTlsState.INCOMPLETE, source(partial).panelTls)
        assertFalse(partial.labels.contains("deep-private-key-presence"))
        val absent = Handle(); absent.references = "CERT=/private/cert.pem\nKEY=/private/key.pem\n"; absent.presence = "ABSENT\n"
        assertEquals(UpdateRecoveryPanelTlsState.UNAVAILABLE, source(absent).panelTls)
    }
    @Test fun malformedDatabaseMetadataAndUnsafeReferencesFailClosed() = runBlocking {
        listOf("META=8|1|0|0|600|4096|-1|1\n", "META=8|1|0|0|888|4096|1|1\n", "META=8|1|0|0|600|4096|1|1\npassword=PrivateValue").forEach { raw ->
            val h = Handle(); h.metadataBefore = raw
            assertTrue(read(h) is UpdateRecoveryReadinessSshResult.Failed)
        }
        val h = Handle(); h.references = "CERT=/../private.pem\nKEY=/private/key.pem\n"
        assertTrue(read(h) is UpdateRecoveryReadinessSshResult.Failed)
        assertFalse(h.labels.contains("deep-private-key-presence"))
    }
    @Test fun cancellationEscapesWithoutFollowingProbesOrAutomaticRetry() = runBlocking {
        val h = Handle(); h.after = { throw CancellationException("fixture cancellation") }
        try { read(h); fail("Cancellation suppressed") } catch (_: CancellationException) { }
        assertEquals(1, h.labels.size)
    }
    @Test fun confirmedDatabaseCommandFailureDoesNotLeakErrorsOrPretendAnIntegrityPass() = runBlocking {
        val h = Handle(); h.rewrite = { label, result -> if (label == "deep-database-quick-check") result.copy(
            completion = CommandCompletion.ConfirmedFailure("PrivateValue", 2), stderr = CapturedOutput.of("PrivateValue".toByteArray(), false)) else result }
        val result = source(h); assertEquals(DeepDiagnosticDatabaseIntegrityStatus.UNREADABLE, result.integrity)
        assertFalse(result.toString().contains("PrivateValue"))
    }

    private inner class Handle : SshSessionHandle {
        override var binding = SessionBinding(SessionId("session"), scope.serverAccessId, SessionOwner.Operation(scope.operationId))
        override var isOpen = true
        var tools = "SQLITE3=AVAILABLE\nTAR=AVAILABLE\nSHA256SUM=AVAILABLE\nSTAT=AVAILABLE\n"
        var metadataBefore = metadata; var metadataAfter = metadata
        var integrity = "ok\n"; var schema = "SUPPORTED\n"; var references = "CERT=\nKEY=\n"; var presence = "PRESENT\n"
        var after: () -> Unit = {}
        var rewrite: (String, SshCommandResult) -> SshCommandResult = { _, result -> result }
        val labels = mutableListOf<String>(); val commands = mutableListOf<String>()
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            assertTrue(config.stdoutCaptureLimitBytes <= 4096); assertEquals(512, config.stderrCaptureLimitBytes)
            assertEquals(10, config.commandExecutionTimeout.seconds.toInt())
            labels += command.redactedLabel; commands += command.rawForTransport()
            val raw = when (command.redactedLabel) {
                "update-recovery-tools" -> tools
                "update-recovery-database-metadata" -> if (labels.count { it == command.redactedLabel } == 1) metadataBefore else metadataAfter
                "update-recovery-runtime-files" -> "PRESENT\n"
                "deep-database-quick-check" -> integrity
                "deep-database-schema" -> schema
                "deep-certificate-references" -> references
                "deep-private-key-presence" -> presence
                else -> error("Unexpected probe")
            }
            after(); return rewrite(command.redactedLabel, success(raw))
        }
        override fun close() { isOpen = false }
    }
}
