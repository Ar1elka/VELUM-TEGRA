package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class ServiceLogSshReaderTest {
    private val time = Instant.parse("2026-10-15T18:00:00Z")
    private val installation = XuiInstallation(XuiInstallationId("install"), ServerId("server"), InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", null, time))
    private val scope = ManagementScope(OperationId("logs"), installation.serverId, ServerAccessId("ssh"), installation.id)

    @Test fun commandIsFiniteReadOnlyExactUnitWithoutFollowOrUserQuery() {
        val command = requireNotNull(ServiceLogCommandCompiler.compile("x-ui.service")).rawForTransport()
        assertTrue(command.contains("--lines=101"))
        assertTrue(command.contains("'_SYSTEMD_UNIT=x-ui.service'"))
        listOf("--quiet", "--follow", " -f", "sudo", "systemctl", "--vacuum", "--rotate", "--flush", "curl", "wget").forEach {
            assertFalse(command.contains(it))
        }
    }
    @Test fun unsafeUnitNamesCannotBecomeShellSyntax() {
        listOf("--help", "x-ui.service;id", "x-ui.service'", "x-ui.service\n", "$(id).service", "/etc/x.service").forEach {
            assertNull(ServiceLogCommandCompiler.compile(it))
        }
    }
    @Test fun foreignSessionAndTargetNeverDispatch() = runBlocking {
        val handle = Handle()
        val result = reader().read(scope.copy(serverAccessId = ServerAccessId("foreign")), installation, handle)
        assertEquals(ServiceLogSshResult.Failed(ServiceLogFailure.INTERNAL_CONTRACT), result)
        assertEquals(0, handle.calls)
    }
    @Test fun outputLimitCannotBeMisrepresentedAsCompleteOrEmptyLogs() = runBlocking {
        val handle = Handle(result = success(record(), truncated = true))
        assertEquals(ServiceLogSshResult.Failed(ServiceLogFailure.OUTPUT_LIMIT), reader().read(scope, installation, handle))
    }
    @Test fun stderrWarningPreventsAnEmptySuccessEvenWithExitZero() = runBlocking {
        val handle = Handle(result = success("").copy(stderr = CapturedOutput.of("partial access".toByteArray(), false)))
        assertEquals(ServiceLogSshResult.Failed(ServiceLogFailure.INCOMPLETE_ACCESS), reader().read(scope, installation, handle))
    }
    @Test fun validEmptyJournalIsAZeroEntrySnapshotWithoutInventedHealth() = runBlocking {
        val result = reader().read(scope, installation, Handle(result = success(""))) as ServiceLogSshResult.Completed
        assertTrue(result.snapshot.entries.isEmpty())
        assertFalse(result.snapshot.hasOlder)
        assertEquals(time, result.snapshot.observedAt)
    }
    @Test fun secretsAddressesEscapesAndMultilineTextNeverCrossTheProjection() = runBlocking {
        val raw = record("connection refused password=SuperSecret https://user:pass@example.invalid/?token=abc \\n -----BEGIN PRIVATE KEY-----")
        val result = reader().read(scope, installation, Handle(result = success(raw))) as ServiceLogSshResult.Completed
        assertEquals(ServiceLogCategory.CONNECTION_REFUSED, result.snapshot.entries.single().category)
        listOf("SuperSecret", "example.invalid", "abc", "PRIVATE KEY", "user:pass").forEach { assertFalse(result.toString().contains(it)) }
    }
    @Test fun unknownOrBinaryMessageIsSuppressedWhileSafeMetadataRemains() {
        val unknown = requireNotNull(ServiceLogJsonProjection.parse(record("arbitrary secret"), "x-ui.service"))
        assertEquals(ServiceLogCategory.OTHER_REDACTED, unknown.first.single().category)
        val binary = record().replace("\"connection refused\"", "[112,97,115,115]")
        assertEquals(ServiceLogCategory.OTHER_REDACTED, requireNotNull(ServiceLogJsonProjection.parse(binary, "x-ui.service")).first.single().category)
    }
    @Test fun duplicateKeysAndForeignUnitOrBadTimestampFailClosed() {
        val valid = record()
        listOf(valid.replace("\"PRIORITY\":\"3\"", "\"PRIORITY\":\"3\",\"PRIORITY\":\"6\""),
            valid.replace("x-ui.service", "ssh.service"), valid.replace("1800000000000000", "not-a-number"),
            valid + "trailing", "{\"MESSAGE\":\"unterminated}").forEach { assertNull(ServiceLogJsonProjection.parse(it, "x-ui.service")) }
    }
    @Test fun oneExtraRowProvesOlderRowsAndOnlyLatestHundredAreProjected() {
        val raw = (0..100).joinToString("\n") { record(stamp = (1_800_000_000_000_000L + it).toString()) }
        val projected = requireNotNull(ServiceLogJsonProjection.parse(raw, "x-ui.service"))
        assertEquals(100, projected.first.size)
        assertTrue(projected.second)
        assertEquals(1000, projected.first.first().recordedAt.nano)
        assertNull(ServiceLogJsonProjection.parse(raw + "\n" + record(), "x-ui.service"))
    }
    @Test fun malformedUtf8IsNotReplacedWithPlausibleEvents() = runBlocking {
        val result = success("").copy(stdout = CapturedOutput.of(byteArrayOf(0xc3.toByte(), 0x28), false))
        assertEquals(ServiceLogSshResult.Failed(ServiceLogFailure.MALFORMED_OUTPUT), reader().read(scope, installation, Handle(result = result)))
    }
    @Test fun unavailableAndUncertainCommandsRemainFailures() = runBlocking {
        val unavailable = success("").copy(completion = CommandCompletion.ConfirmedFailure("fixture command unavailable", exitCode = 127))
        assertEquals(ServiceLogSshResult.Failed(ServiceLogFailure.COMMAND_UNAVAILABLE), reader().read(scope, installation, Handle(result = unavailable)))
        val uncertain = success(record()).copy(completion = CommandCompletion.Unknown("lost"))
        assertEquals(ServiceLogSshResult.Failed(ServiceLogFailure.TRANSPORT_UNCERTAIN), reader().read(scope, installation, Handle(result = uncertain)))
    }
    @Test fun differentSystemdExecutableIsNotAcceptedEvenWhenSavedPathsExist() = runBlocking {
        val handle = Handle(definition = "LOAD=loaded\nEXEC={ path=/usr/bin/foreign ; }\n")
        assertEquals(ServiceLogSshResult.Failed(ServiceLogFailure.TARGET_NOT_VERIFIED), reader().read(scope, installation, handle))
        assertEquals(1, handle.calls)
    }
    private fun reader() = ServiceLogSshReader { time }
    private fun record(message: String = "connection refused", stamp: String = "1800000000000000") =
        "{\"__REALTIME_TIMESTAMP\":\"$stamp\",\"PRIORITY\":\"3\",\"MESSAGE\":\"$message\",\"_SYSTEMD_UNIT\":\"x-ui.service\"}"
    private fun success(raw: String, truncated: Boolean = false) = SshCommandResult(CommandDispatchState.DISPATCHED,
        CommandCompletion.ConfirmedSuccess, CapturedOutput.of(raw.toByteArray(), truncated), CapturedOutput.EMPTY)
    private inner class Handle(override val binding: SessionBinding = SessionBinding(SessionId("session"), scope.serverAccessId,
        SessionOwner.Operation(scope.operationId)), val result: SshCommandResult = success(record()),
        val definition: String = "LOAD=loaded\nEXEC={ path=/usr/local/x-ui/x-ui ; }\n") : SshSessionHandle {
        override val isOpen = true
        var calls = 0
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            calls++
            assertEquals(15, config.commandExecutionTimeout.seconds.toInt())
            if (command.redactedLabel == "deep-service-definition") {
                assertEquals(4096, config.stdoutCaptureLimitBytes)
                return success(definition)
            }
            assertEquals(128 * 1024, config.stdoutCaptureLimitBytes)
            return result
        }
        override fun close() = Unit
    }
}
