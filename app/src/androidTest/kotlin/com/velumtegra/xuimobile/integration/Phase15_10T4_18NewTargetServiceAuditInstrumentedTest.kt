package com.velumtegra.xuimobile.integration

import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import com.velumtegra.xuimobile.readiness.*
import java.security.MessageDigest
import java.time.Duration
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** User rebound the dedicated test server on 2026-10-31. Fixed read-only metadata only. */
class Phase15_10T4_18NewTargetServiceAuditInstrumentedTest {
    private fun emit(key: String, value: Any) {
        val line = "NEW_TARGET_AUDIT_$key=$value"
        require(line.length <= 256 && '\n' !in line && '\r' !in line)
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply { putString("stream", "$line\n") })
    }
    private fun <T> RepositoryResult<T>.required(): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("AUDIT_LOCAL_REPOSITORY_UNAVAILABLE")
    }
    private fun digest(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun quote(value: String) = "'" + value.replace("'", "'\"'\"'") + "'"

    @Test fun exactAuthorizedReadOnlyServiceMetadata() = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("live_authorization") == "READ_ONLY_TEST_SERVER_SERVICE_AUDIT")
        val nonce = args.getString("audit_nonce").orEmpty()
        assertTrue(Regex("[0-9a-f]{32}").matches(nonce))
        emit("NONCE", nonce)
        var gate = "TARGET"
        try {
            val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as VelumTegraApplication
            val deps = app.debugMaintenanceDependencies()
            suspend fun exact(): Triple<VersionedRecord<Server>, ServerAccess, VersionedRecord<XuiInstallation>> {
                val servers = app.inventoryServerRepository.list().required()
                assertTrue(servers.size <= 128 && servers.map { it.value.id }.distinct().size == servers.size)
                val matches = mutableListOf<Pair<VersionedRecord<Server>, ServerAccess>>()
                for (server in servers) {
                    val accesses = app.inventoryServerAccessRepository.listForServer(server.value.id).required()
                    assertTrue(accesses.size <= 64 && accesses.all { it.serverId == server.value.id })
                    assertEquals(accesses.size, accesses.map { it.id }.distinct().size)
                    matches += accesses.filter { it.endpoint.host == "192.0.2.139" && it.endpoint.port == 21578 }.map { server to it }
                }
                assertEquals(1, matches.size)
                val (server, access) = matches.single()
                assertEquals("d497bfe2-781a-4fff-bac9-16816bdc1d6b", server.value.id.value)
                assertEquals("root", access.username)
                assertEquals(HostKeyFingerprint("SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"), access.pinnedHostKey)
                assertEquals(server, app.inventoryServerRepository.get(server.value.id).required())
                assertEquals(access, app.inventoryServerAccessRepository.get(access.id).required())
                val installations = app.inventoryInstallationRepository.listForServer(server.value.id).required()
                assertTrue(installations.size <= 96 && installations.all { it.value.serverId == server.value.id })
                assertEquals(installations.size, installations.map { it.value.id }.distinct().size)
                val installation = installations.single { it.value.identity.let { identity ->
                    identity.serviceUnit == "x-ui.service" && identity.binaryPath == "/usr/local/x-ui/x-ui" &&
                        identity.rootPath == "/usr/local/x-ui" && identity.databasePath == "/etc/x-ui/x-ui.db"
                } }
                assertEquals(installation, app.inventoryInstallationRepository.get(installation.value.id).required())
                assertEquals(ManagementAccess(installation.value.id, access.id),
                    app.inventoryManagementRepository.get(installation.value.id, access.id).required())
                return Triple(server, access, installation)
            }
            val selected = exact()
            val server = selected.first.value
            val access = selected.second
            suspend fun stable() { assertEquals(selected, exact()) }
            suspend fun idle() {
                val entries = (deps.journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: throw AssertionError("AUDIT_JOURNAL_UNAVAILABLE")
                assertTrue(entries.size <= 512 && entries.map { it.snapshot.operationId }.distinct().size == entries.size)
                assertTrue(entries.all { OperationJournalContractPolicy.validateInitial(it.snapshot) == OperationSnapshotValidation.Valid })
                assertTrue(entries.none { it.snapshot.target.serverId == server.id })
            }
            val reviewed = (LocalSshReadinessPolicy.inspect(server.id.value, access.id.value, access)
                as? LocalSshReadinessResult.MetadataPresent)?.summary ?: error("INVALID_SAVED_TARGET")
            emit("TARGET_SHA256", digest(listOf(server.id.value, selected.first.revision.value.toString(), access.id.value,
                reviewed.host, reviewed.port.toString(), reviewed.username, reviewed.savedFingerprint,
                reviewed.credentialRefDigest).joinToString("") { "${it.length}:$it" }))
            emit("INSTALLATION_SHA256", digest(selected.third.value.id.value))
            gate = "JOURNAL"; idle(); stable()
            val operation = OperationId("service-audit-$nonce")
            val owner = SessionOwner.Operation(operation)
            val outcome = deps.coordinator.withExclusiveServerMaintenanceLease(server.id, operation) {
                idle(); stable(); gate = "SESSION"
                val pin = (CanonicalHostKeyFingerprint.parse(access.pinnedHostKey) as? HostKeyFingerprintParseResult.Valid)
                    ?.fingerprint ?: error("INVALID_PIN")
                val handle = (deps.connections.connect(access, owner) as? SshConnectResult.Connected)?.handle ?: error("SSH_REJECTED")
                try {
                    assertTrue(handle.isOpen)
                    assertEquals(access.id, handle.binding.serverAccessId); assertEquals(owner, handle.binding.owner)
                    assertEquals(pin.asHexSha256(), (handle as? VerifiedHostKeySshSessionHandle)?.verifiedHostKeySha256)
                    emit("PINNED_SESSION", "VERIFIED")
                    suspend fun read(command: String, tag: String): String {
                        idle(); stable()
                        val result = handle.execute(RemoteCommand.create(command, tag), SshTransportConfig(
                            channelOpenTimeout = Duration.ofSeconds(5), commandExecutionTimeout = Duration.ofSeconds(15),
                            stdoutCaptureLimitBytes = 8192, stderrCaptureLimitBytes = 128))
                        emit("QUERY", tag)
                        emit("DISPATCH", result.dispatchState.name)
                        emit("COMPLETION", result.completion.javaClass.simpleName)
                        emit("STDOUT_BYTES", result.stdout.sizeBytes)
                        emit("STDERR_BYTES", result.stderr.sizeBytes)
                        assertEquals(CommandDispatchState.DISPATCHED, result.dispatchState)
                        assertEquals(CommandCompletion.ConfirmedSuccess, result.completion)
                        assertFalse(result.stdout.truncated)
                        assertFalse(result.stderr.truncated); assertEquals(0, result.stderr.sizeBytes)
                        val bytes = result.stdout.copyBytes()
                        return try { bytes.toString(Charsets.UTF_8) } finally { bytes.fill(0) }
                    }
                    gate = "SERVICE"
                    val extras = listOf("RootDirectory", "RootImage", "BindPaths", "BindReadOnlyPaths", "LoadCredential",
                        "LoadCredentialEncrypted", "RuntimeDirectory", "StateDirectory", "ConfigurationDirectory", "ExecStartPre",
                        "ExecStartPost", "ExecStop", "ExecReload")
                    val properties = listOf("WorkingDirectory", "Environment", "EnvironmentFiles") + extras
                    val lines = read("systemctl show --all " + properties.joinToString(" ") { "--property=$it" } + " -- x-ui.service",
                        "dedicated-test-service-metadata").trimEnd().lines()
                    emit("PROPERTY_COUNT", lines.size)
                    val received = lines.map { it.substringBefore('=') }.toSet()
                    val missing = properties.filter { it !in received }
                    emit("MISSING_PROPERTIES", if (missing.isEmpty()) "NONE" else missing.joinToString(","))
                    emit("UNEXPECTED_PROPERTY_COUNT", received.count { it !in properties })
                    assertEquals(lines.size, received.size)
                    val fields = lines.associate { line -> val parts = line.split('=', limit = 2); assertEquals(2, parts.size); parts[0] to parts[1] }.toMutableMap()
                    assertTrue(received.all { it in properties })
                    assertTrue(missing.all { it in setOf("ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload") })
                    for (property in missing) {
                        val typed = read("/usr/bin/busctl --system --no-pager get-property org.freedesktop.systemd1 " +
                            "/org/freedesktop/systemd1/unit/x_2dui_2eservice org.freedesktop.systemd1.Service $property",
                            "dedicated-test-empty-exec-array")
                        assertTrue(typed in setOf("a(sasbttttuii) 0", "a(sasbttttuii) 0\n"))
                        fields[property] = ""
                        emit("EMPTY_EXEC_ARRAY_$property", "VERIFIED")
                    }
                    assertEquals(properties.toSet(), fields.keys)
                    for (property in listOf("LoadCredential", "LoadCredentialEncrypted")) {
                        val value = fields.getValue(property)
                        emit("CREDENTIAL_RENDERING_$property", when (value) { "" -> "EMPTY"; "[unprintable]" -> "UNPRINTABLE"; else -> "OTHER" })
                        if (value == "[unprintable]") {
                            val typed = read("/usr/bin/busctl --system --no-pager get-property org.freedesktop.systemd1 " +
                                "/org/freedesktop/systemd1/unit/x_2dui_2eservice org.freedesktop.systemd1.Service $property",
                                "dedicated-test-empty-credential-array")
                            assertTrue(typed in setOf("a(ss) 0", "a(ss) 0\n"))
                            fields[property] = ""
                            emit("EMPTY_CREDENTIAL_ARRAY_$property", "VERIFIED")
                        }
                    }
                    val other = extras.filter { it != "ExecReload" && fields.getValue(it).isNotEmpty() }
                    emit("OTHER_SERVICE_DEPENDENCIES", if (other.isEmpty()) "NONE" else other.joinToString(","))
                    assertTrue(other.isEmpty())
                    val reload = fields.getValue("ExecReload")
                    val arguments = Regex("argv\\[\\]=([^;]+)").findAll(reload).map { it.groupValues[1].trim() }.toList()
                    val executables = Regex("path=([^ ;]+)").findAll(reload).map { it.groupValues[1] }.toList()
                    val knownReload = reload.isEmpty() || (executables.size == 1 && arguments.size == 1 &&
                        executables.single() in setOf("/bin/kill", "/usr/bin/kill") &&
                        arguments.single() == executables.single() + " -USR1 " + 36.toChar() + "MAINPID")
                    emit("RELOAD_KNOWN", knownReload); assertTrue(knownReload)
                    emit("DIRECTORY", if (fields.getValue("WorkingDirectory").trimEnd('/') == "/usr/local/x-ui") "STANDARD" else "OTHER")
                    emit("ENVIRONMENT", when (fields.getValue("Environment")) {
                        "" -> "EMPTY"
                        "XRAY_VMESS_AEAD_FORCED=false" -> "STOCK_VMESS_FALSE"
                        else -> "OTHER"
                    })
                    emit("ENVFILES", when (fields.getValue("EnvironmentFiles")) {
                        "" -> "NONE"
                        "/etc/default/x-ui (ignore_errors=yes)" -> "STOCK_OPTIONAL_DEBIAN"
                        else -> "OTHER"
                    })
                    gate = "DEPENDENCIES"
                    val script = """set -eu
                        if [ -L /etc/default/x-ui ]; then printf 'ENV_PATH=UNSAFE\n'; elif [ -f /etc/default/x-ui ]; then if [ -s /etc/default/x-ui ]; then printf 'ENV_PATH=NONEMPTY_FILE\n'; else printf 'ENV_PATH=EMPTY_FILE\n'; fi; elif [ -e /etc/default/x-ui ]; then printf 'ENV_PATH=UNSAFE\n'; else printf 'ENV_PATH=ABSENT\n'; fi
                        if [ -e /etc/x-ui/node_token_key.json ] || [ -L /etc/x-ui/node_token_key.json ]; then printf 'NODE_KEY_PATH=PRESENT\n'; else printf 'NODE_KEY_PATH=ABSENT\n'; fi
                    """.trimIndent()
                    val facts = read("sh -c " + quote(script), "dedicated-test-service-dependencies").trimEnd().lines()
                    assertEquals(2, facts.size)
                    assertTrue(facts[0] in setOf("ENV_PATH=UNSAFE", "ENV_PATH=NONEMPTY_FILE", "ENV_PATH=EMPTY_FILE", "ENV_PATH=ABSENT"))
                    assertTrue(facts[1] in setOf("NODE_KEY_PATH=PRESENT", "NODE_KEY_PATH=ABSENT"))
                    facts.forEach { emit(it.substringBefore('='), it.substringAfter('=')) }
                    idle(); stable(); true
                } finally { handle.close() }
            }
            assertEquals(true, outcome); idle(); stable()
            emit("MUTATIONS", "NONE_REQUESTED"); emit("RESULT", "COMPLETE")
        } catch (_: Exception) { throw AssertionError("NEW_TARGET_AUDIT_BLOCKED_GATE=$gate") }
          catch (_: AssertionError) { throw AssertionError("NEW_TARGET_AUDIT_BLOCKED_GATE=$gate") }
    }
}
