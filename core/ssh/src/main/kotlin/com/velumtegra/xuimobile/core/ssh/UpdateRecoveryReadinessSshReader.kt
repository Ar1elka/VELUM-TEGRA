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

sealed interface UpdateRecoveryReadinessSshResult {
    data class Completed(val snapshot: UpdateRecoverySourceSnapshot) : UpdateRecoveryReadinessSshResult
    data class Failed(val kind: UpdatePreflightFailure) : UpdateRecoveryReadinessSshResult
}

/** Bounded metadata and existing read-only database probes. Owns no connection or mutation. */
class UpdateRecoveryReadinessSshReader(private val now: () -> Instant = Instant::now) {
    suspend fun read(scope: ManagementScope, installation: XuiInstallation,
        handle: SshSessionHandle): UpdateRecoveryReadinessSshResult {
        val identity = installation.identity
        if (scope.serverId != installation.serverId || scope.installationId != installation.id ||
            identity.serviceUnit != "x-ui.service" || identity.binaryPath != "/usr/local/x-ui/x-ui" ||
            identity.rootPath != "/usr/local/x-ui" || identity.databasePath != "/etc/x-ui/x-ui.db" ||
            handle.binding.owner != SessionOwner.Operation(scope.operationId) ||
            handle.binding.serverAccessId != scope.serverAccessId || !handle.isOpen)
            return UpdateRecoveryReadinessSshResult.Failed(UpdatePreflightFailure.INTERNAL_CONTRACT)
        val binding = handle.binding
        suspend fun query(command: RemoteCommand, limit: Int = 512, allowFailure: Boolean = false): String? {
            currentCoroutineContext().ensureActive()
            if (!handle.isOpen || handle.binding != binding) throw Rejected(UpdatePreflightFailure.INTERNAL_CONTRACT)
            val result = handle.execute(command, SshTransportConfig(channelOpenTimeout = Duration.ofSeconds(5),
                commandExecutionTimeout = Duration.ofSeconds(10), stdoutCaptureLimitBytes = limit, stderrCaptureLimitBytes = 512))
            currentCoroutineContext().ensureActive()
            if (!handle.isOpen || handle.binding != binding) throw Rejected(UpdatePreflightFailure.INTERNAL_CONTRACT)
            if (result.completion is CommandCompletion.Unknown) throw Rejected(UpdatePreflightFailure.TRANSPORT_UNCERTAIN)
            if (result.dispatchState != CommandDispatchState.DISPATCHED || result.stdout.truncated ||
                result.stderr.truncated || result.stdout.sizeBytes > limit) throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
            if (result.completion is CommandCompletion.ConfirmedFailure && allowFailure) return null
            if (result.completion != CommandCompletion.ConfirmedSuccess || result.stderr.sizeBytes != 0)
                throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
            val bytes = result.stdout.copyBytes()
            return try {
                StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            } catch (_: Exception) { throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
            } finally { Arrays.fill(bytes, 0) }
        }
        suspend fun probe(spec: DeepDiagnosticProbeSpec, limit: Int = 4096): String? {
            val command = DeepDiagnosticReadOnlyCommandCompiler.compile(spec)
                ?: throw Rejected(UpdatePreflightFailure.INTERNAL_CONTRACT)
            return query(command, limit, allowFailure = true)
        }
        return try {
            val toolsRaw = requireNotNull(query(RemoteCommand.create(TOOLS_COMMAND, "update-recovery-tools")))
            val tools = parseTools(toolsRaw) ?: throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
            val before = parseDatabase(requireNotNull(query(RemoteCommand.create(DATABASE_COMMAND, "update-recovery-database-metadata"))))
                ?: throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
            val runtime = when (line(requireNotNull(query(RemoteCommand.create(RUNTIME_COMMAND, "update-recovery-runtime-files"))))) {
                "PRESENT" -> UpdateRecoveryRuntimeState.STANDARD_FILES_PRESENT
                "UNSAFE_LINK" -> UpdateRecoveryRuntimeState.UNSAFE_LINK
                "UNAVAILABLE" -> UpdateRecoveryRuntimeState.UNAVAILABLE
                else -> throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
            }
            var integrity = DeepDiagnosticDatabaseIntegrityStatus.UNREADABLE
            var schema = DeepDiagnosticDatabaseSchemaStatus.UNREADABLE
            var panelTls = UpdateRecoveryPanelTlsState.UNOBSERVED
            if (tools[UpdateRecoveryTool.SQLITE3] == UpdateRecoveryToolState.AVAILABLE &&
                before.state == UpdateRecoveryDatabaseState.PRIVATE_REGULAR) {
                val check = probe(DeepDiagnosticProbeSpec.DatabaseQuickCheck(identity.databasePath))
                integrity = if (check == null) DeepDiagnosticDatabaseIntegrityStatus.UNREADABLE
                    else when (DeepDiagnosticProbeParsers.parseDatabaseQuickCheck(check)) {
                        true -> DeepDiagnosticDatabaseIntegrityStatus.OK
                        false -> DeepDiagnosticDatabaseIntegrityStatus.FAILED
                        null -> throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
                    }
                val schemaRaw = probe(DeepDiagnosticProbeSpec.DatabaseSchemaReadback(identity.databasePath))
                schema = if (schemaRaw == null) DeepDiagnosticDatabaseSchemaStatus.UNREADABLE
                    else DeepDiagnosticProbeParsers.parseDatabaseSchema(schemaRaw)
                        ?: throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
                if (schema == DeepDiagnosticDatabaseSchemaStatus.SUPPORTED) {
                    val refsRaw = probe(DeepDiagnosticProbeSpec.CertificateReferencesReadback(identity.databasePath))
                    if (refsRaw != null) {
                        val refs = DeepDiagnosticProbeParsers.parseCertificateReferences(refsRaw)
                            ?: throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
                        val certificatePath = refs.certificatePath
                        val privateKeyPath = refs.privateKeyPath
                        panelTls = when {
                            certificatePath == null && privateKeyPath == null -> UpdateRecoveryPanelTlsState.NOT_CONFIGURED
                            certificatePath == null || privateKeyPath == null -> UpdateRecoveryPanelTlsState.INCOMPLETE
                            else -> {
                                // Presence only for both exact configured paths; never read a private key's bytes.
                                val cert = probe(DeepDiagnosticProbeSpec.ExactPrivateKeyPresence(certificatePath), 64)
                                val key = probe(DeepDiagnosticProbeSpec.ExactPrivateKeyPresence(privateKeyPath), 64)
                                if (cert == null || key == null) UpdateRecoveryPanelTlsState.UNAVAILABLE
                                else {
                                    val certPresence = DeepDiagnosticProbeParsers.parseFilePresence(cert)
                                        ?: throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
                                    val keyPresence = DeepDiagnosticProbeParsers.parseFilePresence(key)
                                        ?: throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
                                    if (certPresence == DeepDiagnosticFilePresence.PRESENT && keyPresence == DeepDiagnosticFilePresence.PRESENT)
                                        UpdateRecoveryPanelTlsState.PAIR_PRESENT else UpdateRecoveryPanelTlsState.UNAVAILABLE
                                }
                            }
                        }
                    }
                }
            }
            val after = parseDatabase(requireNotNull(query(RemoteCommand.create(DATABASE_COMMAND, "update-recovery-database-metadata"))))
                ?: throw Rejected(UpdatePreflightFailure.READBACK_UNAVAILABLE)
            val database = if (before != after) UpdateRecoveryDatabaseState.CHANGED_DURING_READ else before.state
            UpdateRecoveryReadinessSshResult.Completed(UpdateRecoverySourceSnapshot(scope, tools, database,
                if (before == after) before.bytes else null, runtime, integrity, schema, panelTls, now()))
        } catch (failure: Rejected) { UpdateRecoveryReadinessSshResult.Failed(failure.kind) }
    }

    private data class DatabaseMetadata(val state: UpdateRecoveryDatabaseState, val bytes: Long? = null,
        val fingerprint: String? = null)
    private class Rejected(val kind: UpdatePreflightFailure) : RuntimeException()
    private fun line(raw: String) = raw.removeSuffix("\n").removeSuffix("\r")

    private fun parseTools(raw: String): Map<UpdateRecoveryTool, UpdateRecoveryToolState>? {
        val lines = line(raw).split('\n').map { it.removeSuffix("\r") }
        if (lines.size != 4) return null
        val values = linkedMapOf<UpdateRecoveryTool, UpdateRecoveryToolState>()
        for (entry in lines) {
            val parts = entry.split('=')
            if (parts.size != 2) return null
            val tool = UpdateRecoveryTool.values().singleOrNull { it.name == parts[0] } ?: return null
            val state = UpdateRecoveryToolState.values().singleOrNull { it.name == parts[1] } ?: return null
            if (values.put(tool, state) != null) return null
        }
        return values.takeIf { it.keys == UpdateRecoveryTool.values().toSet() }
    }

    private fun parseDatabase(raw: String): DatabaseMetadata? {
        val value = line(raw)
        when (value) {
            "UNSAFE_LINK" -> return DatabaseMetadata(UpdateRecoveryDatabaseState.UNSAFE_LINK)
            "UNAVAILABLE" -> return DatabaseMetadata(UpdateRecoveryDatabaseState.UNAVAILABLE)
            "UNOBSERVED" -> return DatabaseMetadata(UpdateRecoveryDatabaseState.UNOBSERVED)
        }
        if (!value.startsWith("META=")) return null
        val fields = value.removePrefix("META=").split('|')
        if (fields.size != 8 || fields.any { !Regex("0|[1-9][0-9]{0,18}").matches(it) }) return null
        val numbers = fields.map { it.toLongOrNull() ?: return null }
        if (numbers[2] > 4294967295L || numbers[3] > 4294967295L || !Regex("[0-7]{1,4}").matches(fields[4])) return null
        val mode = fields[4].toIntOrNull(8) ?: return null
        val bytes = numbers[5]
        val state = when {
            numbers[2] != 0L || (mode and 63) != 0 || (mode and 3584) != 0 || (mode and 256) == 0 -> UpdateRecoveryDatabaseState.UNSAFE_PERMISSIONS
            bytes == 0L -> UpdateRecoveryDatabaseState.UNAVAILABLE
            bytes > UpdateRecoverySourceSnapshot.MAX_DATABASE_BYTES -> UpdateRecoveryDatabaseState.TOO_LARGE
            else -> UpdateRecoveryDatabaseState.PRIVATE_REGULAR
        }
        return DatabaseMetadata(state, bytes, fields.joinToString("|"))
    }

    companion object {
        private val TOOLS_COMMAND = listOf("SQLITE3" to "sqlite3", "TAR" to "tar", "SHA256SUM" to "sha256sum", "STAT" to "stat")
            .joinToString("; ") { (key, tool) ->
                "if command -v $tool >/dev/null 2>&1; then printf '$key=AVAILABLE\\n'; else printf '$key=MISSING\\n'; fi"
            }
        private val DATABASE_COMMAND = "if [ -L '/etc' ] || [ -L '/etc/x-ui' ] || [ -L '/etc/x-ui/x-ui.db' ]; then printf 'UNSAFE_LINK\\n'; " +
            "elif [ ! -f '/etc/x-ui/x-ui.db' ] || [ ! -r '/etc/x-ui/x-ui.db' ]; then printf 'UNAVAILABLE\\n'; " +
            "elif ! command -v stat >/dev/null 2>&1; then printf 'UNOBSERVED\\n'; " +
            "else printf 'META='; stat -c '%d|%i|%u|%g|%a|%s|%Y|%Z' -- '/etc/x-ui/x-ui.db'; fi"
        private val RUNTIME_COMMAND = "if [ -L '/usr/local' ] || [ -L '/usr/local/x-ui' ] || [ -L '/usr/local/x-ui/x-ui' ] || [ -L '/usr/local/x-ui/bin' ]; then printf 'UNSAFE_LINK\\n'; " +
            "elif [ -f '/usr/local/x-ui/x-ui' ] && [ -r '/usr/local/x-ui/x-ui' ] && [ -x '/usr/local/x-ui/x-ui' ] && " +
            "[ -d '/usr/local/x-ui/bin' ] && [ -r '/usr/local/x-ui/bin' ] && [ -x '/usr/local/x-ui/bin' ]; then printf 'PRESENT\\n'; else printf 'UNAVAILABLE\\n'; fi"
    }
}
