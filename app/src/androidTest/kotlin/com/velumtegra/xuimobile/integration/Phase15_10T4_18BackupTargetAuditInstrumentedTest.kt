package com.velumtegra.xuimobile.integration

import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.readiness.*
import java.io.File
import java.security.MessageDigest
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Local repository reads only. No action port, SSH session, journal write or backup dispatch. */
class Phase15_10T4_18BackupTargetAuditInstrumentedTest {
    private fun emit(key: String, value: Any) {
        val line = "BACKUP_TARGET_AUDIT_$key=$value"
        require(line.length <= 256 && '\n' !in line && '\r' !in line)
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply { putString("stream", "$line\n") })
    }
    private fun digest(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun <T> RepositoryResult<T>.required(): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("AUDIT_LOCAL_REPOSITORY_UNAVAILABLE")
    }
    private fun complete() { emit("REMOTE_ACTIONS", "NONE"); emit("RESULT", "COMPLETE") }

    @Test fun readOnlySavedBackupTarget() = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("live_authorization") == "LOCAL_SAVED_BACKUP_TARGET_AUDIT")
        val nonce = args.getString("audit_nonce").orEmpty()
        assertTrue(Regex("[0-9a-f]{32}").matches(nonce))
        emit("NONCE", nonce)
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as VelumTegraApplication
        val servers = app.inventoryServerRepository.list().required()
        emit("SERVER_COUNT", servers.size)
        assertTrue(servers.size <= 128 && servers.map { it.value.id }.distinct().size == servers.size)
        val matches = mutableListOf<Pair<VersionedRecord<Server>, ServerAccess>>()
        for (server in servers) {
            val accesses = app.inventoryServerAccessRepository.listForServer(server.value.id).required()
            assertTrue(accesses.size <= 64 && accesses.all { it.serverId == server.value.id })
            assertTrue(accesses.map { it.id }.distinct().size == accesses.size)
            matches += accesses.filter { it.endpoint.host == "192.0.2.169" && it.endpoint.port == 22 }.map { server to it }
        }
        emit("ENDPOINT_MATCHES", matches.size)
        if (matches.size != 1) { complete(); return@runBlocking }
        val (server, access) = matches.single()
        emit("SERVER_READBACK_MATCH", server == app.inventoryServerRepository.get(server.value.id).required())
        emit("ACCESS_READBACK_MATCH", access == app.inventoryServerAccessRepository.get(access.id).required())
        val installations = app.inventoryInstallationRepository.listForServer(server.value.id).required()
        emit("INSTALLATION_COUNT", installations.size)
        assertTrue(installations.size <= 96 && installations.all { it.value.serverId == server.value.id })
        assertTrue(installations.map { it.value.id }.distinct().size == installations.size)
        val selected = installations.filter { it.value.identity.let { identity ->
            identity.serviceUnit == "x-ui.service" && identity.binaryPath == "/usr/local/x-ui/x-ui" &&
                identity.rootPath == "/usr/local/x-ui" && identity.databasePath == "/etc/x-ui/x-ui.db"
        } }
        emit("INSTALLATION_MATCHES", selected.size)
        if (selected.size != 1) { complete(); return@runBlocking }
        val installation = selected.single()
        emit("INSTALLATION_READBACK_MATCH", installation == app.inventoryInstallationRepository.get(installation.value.id).required())
        emit("INSTALLATION_ID_MATCH", digest(installation.value.id.value) == "3754b80441879c665f343d3ac39f3558077dd540f016d4338d725070c3c3cb3f")
        emit("MANAGEMENT_BINDING_MATCH", ManagementAccess(installation.value.id, access.id) ==
            app.inventoryManagementRepository.get(installation.value.id, access.id).required())
        val reviewed = (LocalSshReadinessPolicy.inspect(server.value.id.value, access.id.value, access)
            as? LocalSshReadinessResult.MetadataPresent)?.summary
        emit("SSH_METADATA_PRESENT", reviewed != null)
        val expected = "7ccc0deb6eed9b30cd596fd46282b16f71bd7b60ee7d05fdb4600d9b8337b7ad"
        emit("EXPECTED_INTENT_EXISTS", File(app.noBackupFilesDir, "t4_18-backup-${expected.take(32)}.intent").exists())
        if (reviewed != null) {
            val actual = digest(listOf(server.value.id.value, server.revision.value.toString(), access.id.value,
                reviewed.host, reviewed.port.toString(), reviewed.username, reviewed.savedFingerprint,
                reviewed.credentialRefDigest).joinToString("") { "${it.length}:$it" })
            emit("TARGET_DIGEST_MATCH", actual == expected)
            emit("CURRENT_INTENT_EXISTS", File(app.noBackupFilesDir, "t4_18-backup-${actual.take(32)}.intent").exists())
        }
        val entries = (app.debugMaintenanceDependencies().journal.listNonTerminal() as? OperationJournalResult.Success)?.value
            ?: throw AssertionError("AUDIT_JOURNAL_UNAVAILABLE")
        assertTrue(entries.size <= 512 && entries.map { it.snapshot.operationId }.distinct().size == entries.size)
        emit("JOURNAL_VALID", entries.all { OperationJournalContractPolicy.validateInitial(it.snapshot) == OperationSnapshotValidation.Valid })
        emit("TARGET_NONTERMINAL_COUNT", entries.count { it.snapshot.target.serverId == server.value.id })
        complete()
    }
}
