package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class UpdatePreflightSshReaderTest {
    private val time = Instant.parse("2026-10-16T18:00:00Z")
    private val installation = XuiInstallation(XuiInstallationId("install"), ServerId("server"), InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", null, time))
    private val scope = ManagementScope(OperationId("preflight"), installation.serverId, ServerAccessId("ssh"), installation.id)
    private fun management() = ManagementLiveSnapshot(scope, ManagementIdentityStatus.Matched,
        ManagementServiceState.ACTIVE, ManagementBaselineStatus.Matched, null, time)
    private suspend fun read(handle: Handle = Handle(), target: XuiInstallation = installation,
        request: ManagementScope = scope, live: ManagementLiveSnapshot = management()) =
        UpdatePreflightSshReader { time }.read(request, target, handle, live)

    @Test fun exactReadCommandsProduceVersionArchitectureAndRecoverySourceWithoutMutation() = runBlocking {
        val h = Handle(); val result = read(h) as UpdatePreflightSshResult.Completed
        assertEquals("3.0.0", result.snapshot.currentVersion)
        assertEquals(UpdateRootStatus.DIRECT_ROOT, result.snapshot.root)
        assertEquals(UpdateServerArchitecture.AMD64, result.snapshot.architecture)
        assertEquals(listOf("update-preflight-effective-uid", "deep-service-definition", "xui-readonly-binary-version", "update-preflight-architecture",
            "update-recovery-tools", "update-recovery-database-metadata", "update-recovery-runtime-files",
            "deep-database-quick-check", "deep-database-schema", "deep-certificate-references", "update-recovery-database-metadata"), h.labels)
        assertEquals(UpdateRecoveryDatabaseState.PRIVATE_REGULAR, result.snapshot.recovery!!.database)
        h.commands.forEach { raw -> listOf("curl", "wget", "install.sh", "restart", "rm ", "sudo", "apt", "chmod", "chown").forEach { assertFalse(raw.contains(it)) } }
        assertEquals("id -u", h.commands.first())
        assertEquals("'/usr/local/x-ui/x-ui' -v", h.commands[2])
        assertEquals("uname -m", h.commands[3])
    }
    @Test fun differentAccessOrOwnerNeverDispatches() = runBlocking {
        val h = Handle(); assertTrue(read(h, request = scope.copy(serverAccessId = ServerAccessId("foreign"))) is UpdatePreflightSshResult.Failed)
        assertTrue(h.labels.isEmpty())
    }
    @Test fun unverifiedPreludeIsRejectedBeforeAnyExtraRead() = runBlocking {
        val h = Handle(); val live = management().copy(identityStatus = ManagementIdentityStatus.Insufficient(setOf(ManagementEvidenceGap.BINARY_PATH_UNOBSERVED)))
        assertEquals(UpdatePreflightSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT), read(h, live = live)); assertTrue(h.labels.isEmpty())
    }
    @Test fun nonstandardLayoutIsReportedWithoutRunningAnUnapprovedBinary() = runBlocking {
        val h = Handle(); val target = installation.copy(identity = installation.identity.copy(binaryPath = "/opt/custom/x-ui"))
        val result = read(h, target) as UpdatePreflightSshResult.Completed
        assertEquals(UpdateLayoutStatus.UNSUPPORTED, result.snapshot.layout); assertNull(result.snapshot.currentVersion)
        assertEquals(UpdateRootStatus.UNOBSERVED, result.snapshot.root); assertTrue(h.labels.isEmpty())
    }
    @Test fun nonRootIsARealBlockingObservationWithoutSudoFallback() = runBlocking {
        val h = Handle(uid = "1000\n")
        val result = read(h) as UpdatePreflightSshResult.Completed
        assertEquals(UpdateRootStatus.NOT_ROOT, result.snapshot.root)
        assertNull(result.snapshot.recovery); assertFalse(h.labels.any { it.startsWith("update-recovery") })
    }
    @Test fun malformedOrTruncatedUidCannotBeAcceptedAsRoot() = runBlocking {
        listOf("00\n", "0\npassword=secret", "-1", "4294967296").forEach { raw ->
            assertEquals(UpdatePreflightSshResult.Failed(UpdatePreflightFailure.READBACK_UNAVAILABLE), read(Handle(uid = raw)))
        }
        assertTrue(read(Handle(uidOutput = success("0\n").copy(stdout = CapturedOutput.of("0\n".toByteArray(), true)))) is UpdatePreflightSshResult.Failed)
    }
    @Test fun stderrOrUnknownTransportCannotBecomeACompleteReport() = runBlocking {
        val warning = success("0\n").copy(stderr = CapturedOutput.of("secret warning".toByteArray(), false))
        assertTrue(read(Handle(uidOutput = warning)) is UpdatePreflightSshResult.Failed)
        val uncertain = success("0\n").copy(completion = CommandCompletion.Unknown("transport interrupted"))
        assertEquals(UpdatePreflightSshResult.Failed(UpdatePreflightFailure.TRANSPORT_UNCERTAIN), read(Handle(uidOutput = uncertain)))
    }
    @Test fun foreignServiceExecutableNeverRunsTheSavedVersionCommand() = runBlocking {
        val h = Handle(definition = "LOAD=loaded\nEXEC={ path=/usr/bin/foreign ; }\n")
        val result = read(h) as UpdatePreflightSshResult.Completed
        assertEquals(DeepDiagnosticServiceDefinitionStatus.EXEC_START_MISMATCH, result.snapshot.serviceDefinition)
        assertNull(result.snapshot.currentVersion); assertEquals(2, h.labels.size)
    }
    @Test fun malformedServiceDefinitionNeverPublishesFactsOrExecutesVersion() = runBlocking {
        listOf("", "password=SuperSecret\n", "LOAD=loaded\nLOAD=loaded\nEXEC={ path=/usr/local/x-ui/x-ui ; }\n").forEach { raw ->
            val h = Handle(definition = raw)
            val result = read(h)
            assertEquals(UpdatePreflightSshResult.Failed(UpdatePreflightFailure.READBACK_UNAVAILABLE), result)
            assertEquals(listOf("update-preflight-effective-uid", "deep-service-definition"), h.labels)
            assertFalse(result.toString().contains("SuperSecret"))
        }
    }
    @Test fun arbitraryVersionTextIsSuppressedWithoutPretendingAVersionWasFound() = runBlocking {
        val result = read(Handle(version = "password=SuperSecret https://private.invalid\n")) as UpdatePreflightSshResult.Completed
        assertNull(result.snapshot.currentVersion); assertFalse(result.toString().contains("SuperSecret"))
    }
    @Test fun sessionLossDuringReadCannotPublishAPartialReport() = runBlocking {
        val h = Handle();h.closeAfterUid = true
        assertEquals(UpdatePreflightSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT), read(h)); assertEquals(1, h.labels.size)
    }

    @Test fun architectureComesFromTheExactServerAndAcceptsArm64() = runBlocking {
        val result = read(Handle(architecture = "aarch64\n")) as UpdatePreflightSshResult.Completed
        assertEquals(UpdateServerArchitecture.ARM64, result.snapshot.architecture)
    }
    @Test fun unsupportedOrInjectedArchitectureCannotBecomeAPackageSelection() = runBlocking {
        listOf("armv7l\n", "amd64\n", "x86_64\nsecret=PrivateValue", " x86_64 ").forEach { raw ->
            val result = read(Handle(architecture = raw)) as UpdatePreflightSshResult.Completed
            assertNull(result.snapshot.architecture)
            assertFalse(result.toString().contains("PrivateValue"))
        }
    }
    @Test fun truncatedOrUnknownArchitectureReadCannotPublishACompleteReport() = runBlocking {
        val truncated = success("x86_64\n").copy(stdout = CapturedOutput.of("x86_64\n".toByteArray(), true))
        assertEquals(UpdatePreflightSshResult.Failed(UpdatePreflightFailure.READBACK_UNAVAILABLE), read(Handle(architectureOutput = truncated)))
        val uncertain = success("x86_64\n").copy(completion = CommandCompletion.Unknown("private detail"))
        assertEquals(UpdatePreflightSshResult.Failed(UpdatePreflightFailure.TRANSPORT_UNCERTAIN), read(Handle(architectureOutput = uncertain)))
    }
    @Test fun sessionLossDuringArchitectureReadCannotPublishFacts() = runBlocking {
        val h = Handle(); h.closeAfterArchitecture = true
        assertEquals(UpdatePreflightSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT), read(h))
    }

    private fun success(raw: String) = SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess,
        CapturedOutput.of(raw.toByteArray(), false), CapturedOutput.EMPTY)
    private inner class Handle(val uid: String = "0\n", val definition: String = "LOAD=loaded\nEXEC={ path=/usr/local/x-ui/x-ui ; }\n",
        val version: String = "3.0.0\n", val uidOutput: SshCommandResult? = null,
        val architecture: String = "x86_64\n", val architectureOutput: SshCommandResult? = null) : SshSessionHandle {
        override val binding = SessionBinding(SessionId("session"), scope.serverAccessId, SessionOwner.Operation(scope.operationId))
        override var isOpen = true
        var closeAfterUid = false
        var closeAfterArchitecture = false
        val labels = mutableListOf<String>(); val commands = mutableListOf<String>()
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            labels += command.redactedLabel; commands += command.rawForTransport()
            assertTrue(config.stdoutCaptureLimitBytes <= 4096); assertTrue(config.stderrCaptureLimitBytes <= 512)
            return when (command.redactedLabel) {
                "update-preflight-effective-uid" -> { if (closeAfterUid) isOpen = false; uidOutput ?: success(uid) }
                "deep-service-definition" -> success(definition)
                "xui-readonly-binary-version" -> success(version)
                "update-preflight-architecture" -> { if (closeAfterArchitecture) isOpen = false; architectureOutput ?: success(architecture) }
                "update-recovery-tools" -> success("SQLITE3=AVAILABLE\nTAR=AVAILABLE\nSHA256SUM=AVAILABLE\nSTAT=AVAILABLE\n")
                "update-recovery-database-metadata" -> success("META=8|1|0|0|600|4096|1792180000|1792180000\n")
                "update-recovery-runtime-files" -> success("PRESENT\n")
                "deep-database-quick-check" -> success("ok\n")
                "deep-database-schema" -> success("SUPPORTED\n")
                "deep-certificate-references" -> success("CERT=\nKEY=\n")
                else -> error("Unexpected remote command")
            }
        }
        override fun close() { isOpen = false }
    }
}
