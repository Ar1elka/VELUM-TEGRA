package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

/** Scripted exact session; never contacts a server or reads actual keys. */
class RecoveryFileInventorySshReaderTest {
    private val at = Instant.parse("2026-10-17T04:00:00Z")
    private val installation = XuiInstallation(XuiInstallationId("install"), ServerId("server"), InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", null, at))
    private val scope = ManagementScope(OperationId("inventory"), installation.serverId, ServerAccessId("ssh"), installation.id)
    private fun source() = UpdateRecoverySourceSnapshot(scope, UpdateRecoveryTool.values().associateWith { UpdateRecoveryToolState.AVAILABLE },
        UpdateRecoveryDatabaseState.PRIVATE_REGULAR, 4096, UpdateRecoveryRuntimeState.STANDARD_FILES_PRESENT,
        DeepDiagnosticDatabaseIntegrityStatus.OK, DeepDiagnosticDatabaseSchemaStatus.SUPPORTED, UpdateRecoveryPanelTlsState.NOT_CONFIGURED, at)
    private suspend fun read(h: Handle = Handle(), request: ManagementScope = scope, target: XuiInstallation = installation,
        source: UpdateRecoverySourceSnapshot = source()) = RecoveryFileInventorySshReader { at }.read(request, target, h, source)
    private fun hex(value: String) = value.toByteArray().joinToString("") { "%02X".format(it.toInt() and 255) }
    private fun success(value: String) = SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess,
        CapturedOutput.of(value.toByteArray(), false), CapturedOutput.EMPTY)

    @Test fun knownSetHasExactScopeBoundedCountsAndNoPrivatePathsInPublishedReport() = runBlocking {
        val h = Handle(); val result = read(h)
        assertEquals(scope, result.scope); assertEquals(3, result.fileCount); assertEquals(300200L, result.totalBytes)
        assertEquals(2, result.groups.getValue(RecoveryFileGroup.RUNTIME).files)
        assertEquals(1, result.groups.getValue(RecoveryFileGroup.SERVICE).files)
        assertTrue(result.issues.isEmpty()); assertTrue(Regex("[0-9a-f]{64}").matches(result.knownSetDigest!!))
        assertEquals(9, h.labels.size); assertEquals(2, h.labels.count { it == "recovery-files-references" })
        assertFalse(result.toString().contains("/usr/local")); assertFalse(result.toString().contains("x-ui.service"))
    }
    @Test fun commandsAreReadOnlyAndUseTheExactExistingSession() = runBlocking {
        val h = Handle(); read(h)
        h.commands.forEach { raw ->
            listOf(".backup", "chmod ", "chown ", "mkdir ", "cp ", "tar -", "curl ", "wget ", " restart", " stop", "rm ").forEach {
                assertFalse("Unexpected command $it", raw.contains(it))
            }
        }
        assertTrue(h.commands.any { "sqlite3 -readonly" in it }); assertTrue(h.commands.any { "json_tree(" in it })
    }
    @Test fun foreignOperationAccessAndInstallationCannotRunAnyCommand() = runBlocking {
        for (request in listOf(scope.copy(operationId = OperationId("other")), scope.copy(serverAccessId = ServerAccessId("other")),
            scope.copy(installationId = XuiInstallationId("other")))) {
            val h = Handle(); assertEquals(setOf(RecoveryFileIssue.TARGET_UNVERIFIED), read(h, request).issues); assertTrue(h.labels.isEmpty())
        }
    }
    @Test fun nonstandardIdentityOrUnverifiedDatabaseSchemaNeverExpandsPaths() = runBlocking {
        val h = Handle(); assertTrue(read(h, target = installation.copy(identity = installation.identity.copy(rootPath = "/opt/custom"))).issues.isNotEmpty())
        assertTrue(read(h, source = source().copy(schema = DeepDiagnosticDatabaseSchemaStatus.INCOMPLETE)).issues.isNotEmpty())
        assertTrue(h.labels.isEmpty())
    }
    @Test fun missingToolsOrNonRootIsNotRepairedOrRetried() = runBlocking {
        val h = Handle(); h.rewrite = { label, r -> if (label == "recovery-files-tools") r.copy(completion = CommandCompletion.ConfirmedFailure("private", 81)) else r }
        val result = read(h); assertEquals(setOf(RecoveryFileIssue.READ_UNAVAILABLE), result.issues)
        assertEquals(1, h.labels.size); assertFalse(result.toString().contains("private"))
    }
    @Test fun runtimeSymlinkCannotBecomeACompleteKnownSet() = runBlocking {
        val h = Handle(); h.runtime += "l|/usr/local/x-ui/bin/linked.dat\n"
        val result = read(h); assertTrue(RecoveryFileIssue.UNSAFE_FILE in result.issues); assertNull(result.knownSetDigest)
    }
    @Test fun traversalWhitespaceAndShellSyntaxInRuntimePathsAreRejectedBeforeMetadata() = runBlocking {
        for (path in listOf("/usr/local/x-ui/../key", "/usr/local/x-ui/bad name", "/usr/local/x-ui/$(touch_bad)", "/usr/local/x-ui/a'quoted")) {
            val h = Handle(); h.runtime += "f|$path\n"
            assertTrue(RecoveryFileIssue.UNSAFE_PATH in read(h).issues); assertFalse(h.labels.contains("recovery-files-metadata"))
        }
    }
    @Test fun tooManyRuntimeFilesStopBeforePerFileReads() = runBlocking {
        val h = Handle(); h.runtime += (1..97).joinToString("") { "f|/usr/local/x-ui/bin/extra$it.dat\n" }
        assertTrue(RecoveryFileIssue.LIMIT_EXCEEDED in read(h).issues); assertFalse(h.labels.contains("recovery-files-metadata"))
    }
    @Test fun serviceEnvironmentAndExternalEnvironmentFilesAreFiniteFindings() = runBlocking {
        val h = Handle(); h.service = h.service.replace("ENVIRONMENT=NONE", "ENVIRONMENT=PRESENT").replace("ENVFILES=NONE", "ENVFILES=PRESENT")
        val result = read(h); assertEquals(setOf(RecoveryFileIssue.SERVICE_ENVIRONMENT), result.issues); assertNull(result.knownSetDigest)
        assertFalse(result.toString().contains("Environment="))
    }
    @Test fun stockInlineFlagAndAbsentOptionalEnvironmentAreAClosedKnownSet() = runBlocking {
        val h = Handle()
        h.service = h.service.replace("ENVIRONMENT=NONE", "ENVIRONMENT=STOCK_VMESS_FALSE")
            .replace("ENVFILES=NONE", "ENVFILES=STOCK_OPTIONAL_DEFAULT_ABSENT")
        val result = read(h)
        assertTrue(result.issues.isEmpty()); assertNotNull(result.knownSetDigest); assertNotNull(result.sourceSetDigest)
        assertEquals(3, result.fileCount)
    }
    @Test fun existingNodeKeyringAndUnsafeDependencyPathCannotProduceKnownSet() = runBlocking {
        for ((value, issue) in listOf("PRESENT" to RecoveryFileIssue.UNKNOWN_REFERENCE, "UNSAFE" to RecoveryFileIssue.UNSAFE_PATH)) {
            val h = Handle(); h.service = h.service.replace("NODEKEY=ABSENT", "NODEKEY=$value")
            val result = read(h)
            assertTrue(issue in result.issues); assertNull(result.knownSetDigest); assertNull(result.sourceSetDigest)
        }
    }
    @Test fun malformedStockDependencyAttestationIsNeverAccepted() = runBlocking {
        for (line in listOf("ENVIRONMENT=STOCK_VMESS_TRUE", "ENVFILES=STOCK_PRESENT", "NODEKEY=UNKNOWN")) {
            val h = Handle(); val key = line.substringBefore('=')
            h.service = h.service.replace(Regex("(?m)^$key=.*$"), line)
            assertEquals(setOf(RecoveryFileIssue.READ_UNAVAILABLE), read(h).issues)
        }
    }
    @Test fun changedServiceEnvironmentDuringInventoryInvalidatesTheReport() = runBlocking {
        val h = Handle()
        h.rewrite = { label, result ->
            if (label == "recovery-files-service" && h.labels.count { it == label } == 2)
                success(h.service.replace("ENVIRONMENT=NONE", "ENVIRONMENT=PRESENT")) else result
        }
        val result = read(h)
        assertTrue(RecoveryFileIssue.FILES_CHANGED in result.issues); assertNull(result.knownSetDigest)
    }
    @Test fun malformedServiceFieldsAndForeignFragmentsFailClosed() = runBlocking {
        for (service in listOf("SECRET=hidden\n", Handle().service + "FRAGMENT=/etc/systemd/system/other.service\n",
            Handle().service.replace("/etc/systemd/system/x-ui.service", "/root/private.service"))) {
            val h = Handle(); h.service = service
            val result = read(h); assertNull(result.knownSetDigest); assertFalse(result.toString().contains("hidden"))
        }
    }
    @Test fun panelAndXraySharingOnePrivateKeyAreDeduplicatedAndStillRequirePrivateMode() = runBlocking {
        val h = Handle()
        h.references += "PANEL_KEY|${hex("/root/cert/key.pem")}\nXRAY_KEY|${hex("/root/cert/key.pem")}\nXRAY_DATA|${hex("ext:custom.dat:tag")}\n"
        h.runtime += "f|/usr/local/x-ui/bin/custom.dat\n"
        // Sorted exact paths: service, shared key, custom DAT, Xray binary, panel binary.
        h.metadata = "F|0|8|1|0|644|200|1|1|1\nF|1|8|4|0|600|100|1|1|1\nF|2|8|5|0|644|500|1|1|1\nF|3|8|2|0|755|200000|1|1|1\nF|4|8|3|0|755|100000|1|1|1\n"
        val result = read(h); assertEquals(5, result.fileCount); assertTrue(result.issues.isEmpty())
        assertEquals(1, result.groups.getValue(RecoveryFileGroup.PANEL_TLS).files)
        assertEquals(1, result.groups.getValue(RecoveryFileGroup.XRAY_TLS).files)
        assertEquals(1, result.groups.getValue(RecoveryFileGroup.XRAY_DATA).files)
        assertFalse(result.toString().contains("key.pem"))
        h.metadata = h.metadata.replace("|600|100|", "|644|100|")
        assertTrue(RecoveryFileIssue.UNSAFE_FILE in read(h).issues)
    }
    @Test fun unsafeHexDecodedReferencesNeverBecomeShellInput() = runBlocking {
        for (path in listOf("/root/../secret", "../key", "/root/a;id", "/dev/random", "/root/a\nsecret", "/root//key")) {
            val h = Handle(); h.references += "PANEL_KEY|${hex(path)}\n"
            assertTrue(RecoveryFileIssue.UNSAFE_PATH in read(h).issues); assertFalse(h.labels.contains("recovery-files-metadata"))
        }
    }
    @Test fun malformedJsonDuplicateSettingsOrExcessiveReferencesAreNotZeroDependencies() = runBlocking {
        for (raw in listOf("DOCS|1|2|1|0\n", "DOCS|1|2|0|1\n", "DOCS|1|2097153|0|0\n",
            "DOCS|1|2|0|0\n" + (1..33).joinToString("") { "PANEL_KEY|${hex("/root/cert/k$it.pem")}\n" })) {
            val h = Handle(); h.references = raw
            assertTrue(RecoveryFileIssue.REFERENCES_UNAVAILABLE in read(h).issues); assertFalse(h.labels.contains("recovery-files-metadata"))
        }
    }
    @Test fun unknownAbsoluteReferencesStayUnresolvedWithoutReadingTheirContents() = runBlocking {
        val h = Handle(); h.references += "UNKNOWN|${hex("/root/PrivateUnknownResource")}\n"
        val result = read(h); assertTrue(RecoveryFileIssue.UNKNOWN_REFERENCE in result.issues)
        assertNull(result.knownSetDigest); assertFalse(result.toString().contains("PrivateUnknownResource"))
        assertFalse(h.commands.filter { "stat -c" in it }.any { "PrivateUnknownResource" in it })
    }
    @Test fun changedReferenceSetAfterMetadataNeverPublishesAPass() = runBlocking {
        val h = Handle(); h.secondReferences = h.references + "UNKNOWN|${hex("/root/changed")}\n"
        assertTrue(RecoveryFileIssue.REFERENCES_CHANGED in read(h).issues)
    }
    @Test fun changedFileMetadataAndRuntimeSetNeverPublishADigest() = runBlocking {
        val h = Handle(); h.secondMetadata = h.metadata.replace("|100000|", "|100001|")
        assertTrue(RecoveryFileIssue.FILES_CHANGED in read(h).issues)
        val other = Handle(); other.secondRuntime = other.runtime + "f|/usr/local/x-ui/bin/new.dat\n"
        assertTrue(RecoveryFileIssue.FILES_CHANGED in read(other).issues)
    }
    @Test fun missingUnsafeAndOversizedFilesProduceIndependentFiniteFindings() = runBlocking {
        for ((line, issue) in listOf("M|1" to RecoveryFileIssue.FILE_MISSING, "U|1" to RecoveryFileIssue.UNSAFE_FILE,
            "F|1|8|2|0|644|200000|1|1|1" to RecoveryFileIssue.UNSAFE_FILE,
            "F|1|8|2|0|755|0|1|1|1" to RecoveryFileIssue.UNSAFE_FILE,
            "F|1|8|2|0|755|268435457|1|1|1" to RecoveryFileIssue.LIMIT_EXCEEDED)) {
            val h = Handle(); h.metadata = h.metadata.replace("F|1|8|2|0|755|200000|1|1|1", line)
            val result = read(h); assertTrue(issue in result.issues); assertNull(result.knownSetDigest)
        }
    }
    @Test fun truncatedUncertainStderrAndMalformedUtf8AreRedactedReadFailures() = runBlocking {
        for (change in listOf<(SshCommandResult) -> SshCommandResult>(
            { it.copy(stdout = CapturedOutput.of("PrivateValue".toByteArray(), true)) },
            { it.copy(completion = CommandCompletion.Unknown("PrivateValue")) },
            { it.copy(stderr = CapturedOutput.of("PrivateValue".toByteArray(), false)) },
            { it.copy(stdout = CapturedOutput.of(byteArrayOf(0xC3.toByte(), 0x28), false)) })) {
            val h = Handle(); h.rewrite = { _, r -> change(r) }
            val result = read(h); assertEquals(setOf(RecoveryFileIssue.READ_UNAVAILABLE), result.issues)
            assertFalse(result.toString().contains("PrivateValue")); assertEquals(1, h.labels.size)
        }
    }
    @Test fun replacedSessionCannotPublishLateFileFacts() = runBlocking {
        val h = Handle(); h.after = { if (h.labels.last() == "recovery-files-metadata") h.binding = h.binding.copy(sessionId = SessionId("replacement")) }
        val result = read(h); assertEquals(setOf(RecoveryFileIssue.TARGET_UNVERIFIED), result.issues); assertNull(result.knownSetDigest)
    }
    @Test fun cancellationPropagatesWithoutAnotherCommandOrReplay() = runBlocking {
        val h = Handle(); h.after = { throw CancellationException("fixture cancel") }
        try { read(h); fail("Cancellation suppressed") } catch (_: CancellationException) { }
        assertEquals(1, h.labels.size)
    }
    @Test fun fixedCommandsRejectUnvalidatedPathArguments() {
        for (path in listOf("/root/../key", "/root/key';id", "/proc/self/fd/0", "/root//key")) {
            assertFalse(RecoveryFileInventoryCommands.safePath(path))
            try { RecoveryFileInventoryCommands.metadata(listOf(path)); fail("Unsafe path accepted") } catch (_: IllegalArgumentException) { }
        }
    }

    private inner class Handle : SshSessionHandle {
        override var binding = SessionBinding(SessionId("session"), scope.serverAccessId, SessionOwner.Operation(scope.operationId))
        override var isOpen = true
        var runtime = "d|/usr/local/x-ui/bin\nf|/usr/local/x-ui/x-ui\nf|/usr/local/x-ui/bin/xray-linux-amd64\n"
        var service = "FRAGMENT=/etc/systemd/system/x-ui.service\nDROPINS=\nENVIRONMENT=NONE\nENVFILES=NONE\nDIRECTORY=/usr/local/x-ui\nNODEKEY=ABSENT\n"
        var references = "DOCS|1|2|0|0\n"
        var metadata = "F|0|8|1|0|644|200|1|1|1\nF|1|8|2|0|755|200000|1|1|1\nF|2|8|3|0|755|100000|1|1|1\n"
        var secondRuntime: String? = null; var secondReferences: String? = null; var secondMetadata: String? = null
        val labels = mutableListOf<String>(); val commands = mutableListOf<String>()
        var after: () -> Unit = {}
        var rewrite: (String, SshCommandResult) -> SshCommandResult = { _, r -> r }
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            labels += command.redactedLabel; commands += command.rawForTransport()
            assertTrue(config.stdoutCaptureLimitBytes <= 24_576); assertEquals(512, config.stderrCaptureLimitBytes)
            assertEquals(12L, config.commandExecutionTimeout.seconds)
            val count = labels.count { it == command.redactedLabel }
            val raw = when (command.redactedLabel) {
                "recovery-files-tools" -> "READY\n"
                "recovery-files-runtime" -> if (count == 1) runtime else secondRuntime ?: runtime
                "recovery-files-service" -> service
                "recovery-files-references" -> if (count == 1) references else secondReferences ?: references
                "recovery-files-metadata" -> if (count == 1) metadata else secondMetadata ?: metadata
                else -> error("Unexpected command")
            }
            after(); return rewrite(command.redactedLabel, success(raw))
        }
        override fun close() { isOpen = false }
    }
}
