package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Scripted SSH boundary only: fixed read-only commands, no real connection or credentials. */
class ExistingInstallationRestartPreflightSshAdapterTest {
    @Test fun `real uid and exact executable settings and paths produce short lived typed proof`() = runSuspend {
        val f = Fixture()
        val result = f.verify() as ExistingInstallationRestartPreflightResult.Verified
        assertEquals(f.current.snapshot.operationId, result.preflight.authorization.operationId)
        assertEquals(f.current.revision, result.preflight.authorization.operationRevision)
        assertEquals(f.installation.identity, result.preflight.evidence.installationProof.observedIdentity)
        assertEquals(f.now.plusSeconds(15), result.preflight.evidence.validUntil)
        assertEquals("operator", f.access.username)
        assertEquals(7, f.session.commands.size)
        assertTrue(f.session.commands.none { it.rawForTransport().contains("restart") || it.rawForTransport().contains("sudo") })
    }

    @Test fun `root username never substitutes for observed uid zero`() = runSuspend {
        val f = Fixture(); f.access = f.access.copy(username = "root"); f.session.uid = "1000\n"
        assertEquals(ExistingInstallationRestartPreflightResult.Rejected(ExistingInstallationRestartPreflightRejection.DIRECT_ROOT_REQUIRED), f.verify())
        assertEquals(listOf("id -u"), f.session.commands.map { it.rawForTransport() })
    }

    @Test fun `foreign owner or profile is rejected before any command`() = runSuspend {
        for (binding in listOf(SessionBinding(SessionId("foreign"), ServerAccessId("fixture-access"), SessionOwner.Operation(OperationId("foreign-operation"))),
            SessionBinding(SessionId("foreign"), ServerAccessId("other-access"), SessionOwner.Operation(OperationId("fixture-operation"))))) {
            val f = Fixture(); f.session = FakeSession(binding)
            assertEquals(ExistingInstallationRestartPreflightResult.Rejected(ExistingInstallationRestartPreflightRejection.EXACT_SCOPE_REQUIRED), f.verify())
            assertEquals(0, f.session.commands.size)
        }
    }

    @Test fun `unsafe operation never starts preflight`() = runSuspend {
        val f = Fixture(); f.current = f.current.copy(snapshot = f.current.snapshot.copy(checkpoint =
            OperationCheckpoint("RESTART_DISPATCHED", CheckpointSemantics.RESTART_IN_FLIGHT, f.now)))
        assertEquals(ExistingInstallationRestartPreflightResult.Rejected(ExistingInstallationRestartPreflightRejection.EXACT_SCOPE_REQUIRED), f.verify())
        assertEquals(0, f.session.commands.size)
    }

    @Test fun `unproven mutation barrier rejects before any command`() = runSuspend {
        val f = Fixture()
        val blocked = ExistingInstallationRestartPreflightSshAdapter { f.now }.verify(f.current, f.installation,
            f.access, f.session, ExistingInstallationMutationBarrierState.UNKNOWN)
        assertEquals(ExistingInstallationRestartPreflightResult.Rejected(ExistingInstallationRestartPreflightRejection.MUTATION_BARRIER_BLOCKED), blocked)
        assertEquals(0, f.session.commands.size)
    }

    @Test fun `nonstandard installation never reaches ssh`() = runSuspend {
        val f = Fixture(); f.installation = f.installation.copy(identity = f.installation.identity.copy(binaryPath = "/opt/x-ui/x-ui"))
        assertEquals(ExistingInstallationRestartPreflightResult.Rejected(ExistingInstallationRestartPreflightRejection.STANDARD_LAYOUT_REQUIRED), f.verify())
        assertEquals(0, f.session.commands.size)
    }

    @Test fun `other systemd executable fails before path or database probes`() = runSuspend {
        val f = Fixture(); f.session.execStart = "{ path=/opt/other/x-ui ; argv[]=/opt/other/x-ui ; ignore_errors=no ; }\n"
        assertEquals(ExistingInstallationRestartPreflightResult.Rejected(ExistingInstallationRestartPreflightRejection.IDENTITY_MISMATCH), f.verify())
        assertEquals(2, f.session.commands.size)
    }

    @Test fun `changed panel baseline never produces preflight authority`() = runSuspend {
        val f = Fixture(); f.session.settings = "PORT=2443\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=127.0.0.1\n"
        assertEquals(ExistingInstallationRestartPreflightResult.Rejected(ExistingInstallationRestartPreflightRejection.PANEL_SETTINGS_CHANGED), f.verify())
        assertTrue(f.session.commands.none { it.rawForTransport().contains("restart") })
    }

    @Test fun `managed installation requires exact durable marker`() = runSuspend {
        val f = Fixture(); val managed = ManagedInstallId("v1-0123456789abcdef0123456789abcdef")
        f.installation = f.installation.copy(ownership = InstallationOwnership.MANAGED,
            identity = f.installation.identity.copy(managedInstallId = managed))
        f.session.marker = ManagedInstallMarkerProtocol.encode(managed)
        assertTrue(f.verify() is ExistingInstallationRestartPreflightResult.Verified)
        f.session.marker = ManagedInstallMarkerProtocol.encode(ManagedInstallId("v1-fedcba9876543210fedcba9876543210"))
        assertEquals(ExistingInstallationRestartPreflightResult.Rejected(ExistingInstallationRestartPreflightRejection.MANAGED_MARKER_UNCONFIRMED), f.verify())
    }

    @Test fun `unknown truncated or malformed output cannot become permission`() = runSuspend {
        for (mode in listOf("unknown", "truncated", "malformed")) {
            val f = Fixture(); f.session.uidMode = mode
            assertEquals(ExistingInstallationRestartPreflightResult.Rejected(ExistingInstallationRestartPreflightRejection.READ_ONLY_CHECK_INCOMPLETE), f.verify())
            assertEquals(1, f.session.commands.size)
        }
    }

    private class Fixture {
        val now = Instant.parse("2026-10-14T10:00:00Z")
        val server = ServerId("fixture-server")
        var access = ServerAccess(ServerAccessId("fixture-access"), server, SshEndpoint("fixture.invalid", 22), "operator",
            SshAuthRef.Password(SecretId("fixture-reference")), HostKeyFingerprint("SHA256:fixture"))
        var installation = XuiInstallation(XuiInstallationId("fixture-installation"), server, InstallationOwnership.ADOPTED,
            InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
            InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db",
                2053, "/panel/", "127.0.0.1", now.minusSeconds(60)))
        var current = VersionedOperationSnapshot(OperationSnapshot(OperationId("fixture-operation"), OperationType.RESTART,
            OperationTarget.InstallationTarget(server, access.id, installation.id), OperationStatus.RUNNING,
            OperationCheckpoint("RESTART_USER_CONFIRMED", CheckpointSemantics.MUTATION_NOT_STARTED, now), now, now), OperationRevision(7))
        var session = FakeSession(SessionBinding(SessionId("fixture-session"), access.id, SessionOwner.Operation(current.snapshot.operationId)))
        suspend fun verify() = ExistingInstallationRestartPreflightSshAdapter { now }.verify(current, installation, access, session,
            ExistingInstallationMutationBarrierState.PROVEN_CLEAR)
    }
    private class FakeSession(override val binding: SessionBinding) : SshSessionHandle {
        override val isOpen = true
        val commands = mutableListOf<RemoteCommand>()
        var uid = "0\n"
        var uidMode = "valid"
        var execStart = "{ path=/usr/local/x-ui/x-ui ; argv[]=/usr/local/x-ui/x-ui ; ignore_errors=no ; }\n"
        var settings = "PORT=2053\nWEB_BASE_PATH=/panel/\nLISTEN_ADDRESS=127.0.0.1\n"
        var marker = ""
        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            commands += command
            if (command.redactedLabel == "restart-preflight-effective-uid") {
                if (uidMode == "unknown") return SshCommandResult(CommandDispatchState.DISPATCHED,
                    CommandCompletion.Unknown("fixture transport lost"), CapturedOutput.EMPTY, CapturedOutput.EMPTY)
                if (uidMode == "truncated") return success(uid, truncated = true)
                if (uidMode == "malformed") return SshCommandResult(CommandDispatchState.DISPATCHED, CommandCompletion.ConfirmedSuccess,
                    CapturedOutput.of(byteArrayOf(0xC3.toByte(), 0x28), truncated = false), CapturedOutput.EMPTY)
                return success(uid)
            }
            return success(when {
                command.redactedLabel == "restart-preflight-exact-systemd-executable" -> execStart
                command.redactedLabel == "restart-preflight-managed-marker" -> marker
                command.rawForTransport().contains("sqlite3") -> settings
                else -> ""
            })
        }
        override fun close() = Unit
    }
    companion object {
        private fun success(text: String, truncated: Boolean = false) = SshCommandResult(CommandDispatchState.DISPATCHED,
            CommandCompletion.ConfirmedSuccess, CapturedOutput.of(text.encodeToByteArray(), truncated), CapturedOutput.EMPTY)
    }
}
private fun <T> runSuspend(block: suspend () -> T): T {
    var outcome: Result<T>? = null
    block.startCoroutine(object : Continuation<T> {
        override val context = EmptyCoroutineContext
        override fun resumeWith(result: Result<T>) { outcome = result }
    })
    return checkNotNull(outcome).getOrThrow()
}
