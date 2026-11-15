package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.DeepDiagnosticProbeSpec
import com.velumtegra.xuimobile.core.model.*
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

sealed interface UpdatePreflightSshResult {
    data class Completed(val snapshot: UpdatePreflightSnapshot) : UpdatePreflightSshResult
    data class Failed(val kind: UpdatePreflightFailure) : UpdatePreflightSshResult
}

/** No installer, download, backup or mutation command. Uses the already-open exact operation session. */
class UpdatePreflightSshReader(private val now: () -> Instant = Instant::now) {
    suspend fun read(scope: ManagementScope, installation: XuiInstallation, handle: SshSessionHandle,
        management: ManagementLiveSnapshot, includeRecoveryFiles: Boolean = false): UpdatePreflightSshResult {
        if (scope.serverId != installation.serverId || scope.installationId != installation.id ||
            handle.binding.owner != SessionOwner.Operation(scope.operationId) ||
            handle.binding.serverAccessId != scope.serverAccessId || !handle.isOpen ||
            management.scope != scope || management.identityStatus != ManagementIdentityStatus.Matched)
            return UpdatePreflightSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT)
        val binding = handle.binding
        fun exact() = handle.isOpen && handle.binding == binding
        val identity = installation.identity
        val standard = identity.serviceUnit == "x-ui.service" && identity.binaryPath == "/usr/local/x-ui/x-ui" &&
            identity.rootPath == "/usr/local/x-ui" && identity.databasePath == "/etc/x-ui/x-ui.db"
        if (!standard) return UpdatePreflightSshResult.Completed(UpdatePreflightSnapshot(scope,
            UpdateRootStatus.UNOBSERVED, UpdateLayoutStatus.UNSUPPORTED, DeepDiagnosticServiceDefinitionStatus.UNREADABLE,
            null, management.serviceState, management.baselineStatus, now()))

        currentCoroutineContext().ensureActive()
        val uidResult = handle.execute(RemoteCommand.create("id -u", "update-preflight-effective-uid"), config(32))
        currentCoroutineContext().ensureActive()
        if (!exact()) return UpdatePreflightSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT)
        val uidText = safeText(uidResult, 32)
            ?: return UpdatePreflightSshResult.Failed(failure(uidResult))
        val uid = uidText.removeSuffix("\n").removeSuffix("\r")
        val numericUid = uid.toLongOrNull()
        if (!Regex("0|[1-9][0-9]{0,9}").matches(uid) || numericUid == null || numericUid > 4294967295L)
            return UpdatePreflightSshResult.Failed(UpdatePreflightFailure.READBACK_UNAVAILABLE)

        val probe = DeepDiagnosticProbeSpec.ServiceDefinitionReadback(identity.serviceUnit, identity.binaryPath)
        val command = DeepDiagnosticReadOnlyCommandCompiler.compile(probe)
            ?: return UpdatePreflightSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT)
        val definitionResult = handle.execute(command, config(4096))
        currentCoroutineContext().ensureActive()
        if (!exact()) return UpdatePreflightSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT)
        val definitionText = safeText(definitionResult, 4096)
            ?: return UpdatePreflightSshResult.Failed(failure(definitionResult))
        val definition = DeepDiagnosticProbeParsers.parseServiceDefinition(definitionText, identity.binaryPath)
            ?: return UpdatePreflightSshResult.Failed(UpdatePreflightFailure.READBACK_UNAVAILABLE)
        // A different executable must never be run merely to obtain its purported version.
        val version = if (definition == DeepDiagnosticServiceDefinitionStatus.CONSISTENT) {
            when (val observed = XuiReadOnlyVersionProbe.inspect(handle, identity.binaryPath)) {
                is XuiVersionProbeOutcome.Observed -> observed.version
                XuiVersionProbeOutcome.Unavailable -> null
            }
        } else null
        currentCoroutineContext().ensureActive()
        if (!exact()) return UpdatePreflightSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT)
        val architecture = if (definition == DeepDiagnosticServiceDefinitionStatus.CONSISTENT) {
            val architectureResult = handle.execute(RemoteCommand.create("uname -m", "update-preflight-architecture"), config(64))
            currentCoroutineContext().ensureActive()
            if (!exact()) return UpdatePreflightSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT)
            val raw = safeText(architectureResult, 64)
                ?: return UpdatePreflightSshResult.Failed(failure(architectureResult))
            when (raw.removeSuffix("\n").removeSuffix("\r")) {
                "x86_64" -> UpdateServerArchitecture.AMD64
                "aarch64" -> UpdateServerArchitecture.ARM64
                else -> null
            }
        } else null
        val recovery = if (uid == "0" && definition == DeepDiagnosticServiceDefinitionStatus.CONSISTENT) {
            when (val result = UpdateRecoveryReadinessSshReader(now).read(scope, installation, handle)) {
                is UpdateRecoveryReadinessSshResult.Completed -> result.snapshot
                is UpdateRecoveryReadinessSshResult.Failed -> return UpdatePreflightSshResult.Failed(result.kind)
            }
        } else null
        val recoveryFiles = if (includeRecoveryFiles && recovery != null) {
            RecoveryFileInventorySshReader(now).read(scope, installation, handle, recovery)
        } else null
        currentCoroutineContext().ensureActive()
        if (!exact()) return UpdatePreflightSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT)
        return UpdatePreflightSshResult.Completed(UpdatePreflightSnapshot(scope,
            if (uid == "0") UpdateRootStatus.DIRECT_ROOT else UpdateRootStatus.NOT_ROOT,
            UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD, definition, version,
            management.serviceState, management.baselineStatus, now(), architecture, recovery, recoveryFiles))
    }

    private fun config(limit: Int) = SshTransportConfig(channelOpenTimeout = Duration.ofSeconds(5),
        commandExecutionTimeout = Duration.ofSeconds(15), stdoutCaptureLimitBytes = limit, stderrCaptureLimitBytes = 512)

    private fun failure(result: SshCommandResult) = if (result.completion is CommandCompletion.Unknown)
        UpdatePreflightFailure.TRANSPORT_UNCERTAIN else UpdatePreflightFailure.READBACK_UNAVAILABLE

    private fun safeText(result: SshCommandResult, limit: Int): String? {
        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.completion != CommandCompletion.ConfirmedSuccess ||
            result.stdout.truncated || result.stdout.sizeBytes > limit || result.stderr.truncated || result.stderr.sizeBytes != 0) return null
        val bytes = result.stdout.copyBytes()
        return try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: Exception) { null } finally { Arrays.fill(bytes, 0) }
    }
}
