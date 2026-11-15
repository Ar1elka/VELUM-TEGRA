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

/** Explicit dedicated-server environment setup, not a product UI or recovery operation. */
class Phase15_10T4_17Live03SqliteSetupInstrumentedTest {
    private enum class Stage { TARGET, JOURNAL, SESSION, PREFLIGHT, INSTALL, READBACK }
    private fun emit(line: String) {
        require(line.length <= 512 && '\n' !in line && '\r' !in line)
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply { putString("stream", line + "\n") })
    }
    private fun <T> RepositoryResult<T>.required(): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("LOCAL_INVENTORY_UNAVAILABLE")
    }
    private fun digest(v: ByteArray) = MessageDigest.getInstance("SHA-256").digest(v)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun quote(v: String) = "'" + v.replace("'", "'\"'\"'") + "'"

    @Test fun exactAuthorizedSqlitePrerequisiteSetup() = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("SETUP_OPT_IN_REQUIRED", args.getString("live_authorization") == "REAL_TEST_SERVER_INSTALL_SQLITE3")
        assertEquals("192.0.2.169", args.getString("live_host")); assertEquals("22", args.getString("live_port"))
        val nonce = args.getString("live_run_nonce").orEmpty(); assertTrue(Regex("[0-9a-f]{32}").matches(nonce))
        var stage = Stage.TARGET
        try {
            val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as VelumTegraApplication
            val dependencies = app.debugMaintenanceDependencies()
            val scriptBytes = InstrumentationRegistry.getInstrumentation().context.assets.open("t4_17_sqlite_setup.sh").use { it.readBytes() }
            assertTrue(scriptBytes.size <= 8192)
            assertEquals("74e20915f5b474c198ae4316cfe7b728a53a626d6a06070495b1d31f5f6e4181", digest(scriptBytes))
            val script = scriptBytes.toString(Charsets.UTF_8)
            suspend fun exact(): Pair<VersionedRecord<Server>, ServerAccess> {
                val servers = app.inventoryServerRepository.list().required()
                assertTrue(servers.size <= 128 && servers.map { it.value.id }.distinct().size == servers.size)
                val matches = mutableListOf<Pair<VersionedRecord<Server>, ServerAccess>>()
                for (server in servers) {
                    val accesses = app.inventoryServerAccessRepository.listForServer(server.value.id).required()
                    assertTrue(accesses.size <= 64 && accesses.all { it.serverId == server.value.id })
                    assertEquals(accesses.size, accesses.map { it.id }.distinct().size)
                    matches += accesses.filter { it.endpoint.host == "192.0.2.169" && it.endpoint.port == 22 }.map { server to it }
                }
                assertEquals(1, matches.size)
                val selected = matches.single()
                assertEquals(selected.first, app.inventoryServerRepository.get(selected.first.value.id).required())
                assertEquals(selected.second, app.inventoryServerAccessRepository.get(selected.second.id).required())
                return selected
            }
            val selected = exact(); val server = selected.first.value; val access = selected.second
            val reviewed = (LocalSshReadinessPolicy.inspect(server.id.value, access.id.value, access) as? LocalSshReadinessResult.MetadataPresent)?.summary
                ?: throw AssertionError("SAVED_TARGET_INVALID")
            val targetDigest = digest(listOf(server.id.value, selected.first.revision.value.toString(), access.id.value,
                reviewed.host, reviewed.port.toString(), reviewed.username, reviewed.savedFingerprint,
                reviewed.credentialRefDigest).joinToString("") { "${it.length}:$it" }.toByteArray(Charsets.UTF_8))
            assertEquals("7ccc0deb6eed9b30cd596fd46282b16f71bd7b60ee7d05fdb4600d9b8337b7ad", targetDigest)
            suspend fun stable() { assertEquals(selected, exact()) }
            suspend fun clearJournal() {
                val records = (dependencies.journal.listNonTerminal() as? OperationJournalResult.Success)?.value
                    ?: throw AssertionError("JOURNAL_UNAVAILABLE")
                assertTrue(records.size <= 512 && records.map { it.snapshot.operationId }.distinct().size == records.size)
                assertTrue(records.all { OperationJournalContractPolicy.validateInitial(it.snapshot) == OperationSnapshotValidation.Valid })
                assertTrue(records.none { it.snapshot.target.serverId == server.id })
            }
            emit("SQLITE_SETUP_BEGIN=192.0.2.169:22"); emit("LIVE_RUN_NONCE=$nonce")
            emit("LIVE_SAVED_TARGET_SHA256=$targetDigest")
            val operationId = OperationId("sqlite-setup-$nonce"); val owner = SessionOwner.Operation(operationId)
            val outcome = dependencies.coordinator.withExclusiveServerMaintenanceLease(server.id, operationId) {
                stage = Stage.JOURNAL; clearJournal(); stable()
                stage = Stage.SESSION
                val fingerprint = (CanonicalHostKeyFingerprint.parse(access.pinnedHostKey) as? HostKeyFingerprintParseResult.Valid)?.fingerprint
                    ?: throw AssertionError("PIN_INVALID")
                val handle = (dependencies.connections.connect(access, owner) as? SshConnectResult.Connected)?.handle
                    ?: throw AssertionError("SSH_REJECTED")
                try {
                    val pinned = handle as? VerifiedHostKeySshSessionHandle
                    assertTrue(handle.isOpen && handle.binding.serverAccessId == access.id && handle.binding.owner == owner)
                    assertEquals(fingerprint.asHexSha256(), pinned?.verifiedHostKeySha256)
                    emit("SQLITE_SETUP_PINNED_SESSION=VERIFIED")
                    suspend fun run(mode: String, seconds: Long): String {
                        require(mode in setOf("preflight", "install", "readback"))
                        stable(); clearJournal()
                        val result = handle.execute(RemoteCommand.create("sh -c " + quote(script) + " -- " + mode,
                            "dedicated-test-sqlite-$mode"), SshTransportConfig(channelOpenTimeout = Duration.ofSeconds(5),
                            commandExecutionTimeout = Duration.ofSeconds(seconds), stdoutCaptureLimitBytes = 128, stderrCaptureLimitBytes = 256))
                        if (result.dispatchState != CommandDispatchState.DISPATCHED || result.completion is CommandCompletion.Unknown) {
                            emit("SQLITE_SETUP_OUTCOME=UNCONFIRMED_NO_RETRY"); throw AssertionError("OUTCOME_UNCONFIRMED")
                        }
                        assertFalse(result.stdout.truncated)
                        val bytes = result.stdout.copyBytes()
                        val code = try { bytes.toString(Charsets.UTF_8) } finally { bytes.fill(0) }
                        val allowed = setOf("SETUP_ALREADY_READY\n", "SETUP_SQLITE_MISSING\n", "SETUP_INSTALLED\n", "SETUP_READY\n",
                            "SETUP_BLOCKED\n", "SETUP_PRIOR_INTENT\n", "SETUP_INSTALL_UNVERIFIED\n")
                        assertTrue(code in allowed)
                        emit("SQLITE_SETUP_RESULT=" + code.trim())
                        assertEquals(CommandCompletion.ConfirmedSuccess, result.completion)
                        stable(); clearJournal()
                        return code.trim()
                    }
                    stage = Stage.PREFLIGHT
                    when (run("preflight", 20)) {
                        "SETUP_SQLITE_MISSING" -> {
                            stage = Stage.INSTALL
                            emit("SQLITE_SETUP_MUTATION=APT_SQLITE3_REQUESTED")
                            assertEquals("SETUP_INSTALLED", run("install", 280))
                        }
                        "SETUP_ALREADY_READY" -> emit("SQLITE_SETUP_MUTATION=NONE_NEEDED")
                        else -> throw AssertionError("PREFLIGHT_BLOCKED")
                    }
                    stage = Stage.READBACK
                    assertEquals("SETUP_READY", run("readback", 20))
                    emit("SQLITE_SETUP_CLI_AND_ACTIVE_SERVICE=VERIFIED")
                    true
                } finally { handle.close() }
            }
            assertEquals(true, outcome)
            stable(); emit("SQLITE_SETUP_PASS=192.0.2.169:22")
        } catch (_: Exception) {
            throw AssertionError("SQLITE_SETUP_BLOCKED_STAGE=${stage.name};NO_AUTOMATIC_RETRY")
        } catch (_: AssertionError) {
            throw AssertionError("SQLITE_SETUP_BLOCKED_STAGE=${stage.name};NO_AUTOMATIC_RETRY")
        }
    }
}
