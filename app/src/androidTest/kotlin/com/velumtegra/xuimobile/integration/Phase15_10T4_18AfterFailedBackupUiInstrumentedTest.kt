package com.velumtegra.xuimobile.integration

import android.os.Bundle
import android.system.Os
import android.system.OsConstants
import androidx.activity.ComponentActivity
import androidx.compose.runtime.*
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.SavedStateHandle
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.management.*
import com.velumtegra.xuimobile.readiness.*
import com.velumtegra.xuimobile.ui.theme.VelumTegraTheme
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/** Real production screens, ports, journal and SSH. Never supplies observations or operation pointers. */
class Phase15_10T4_18AfterFailedBackupUiInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private enum class Stage { TARGET, RECONCILE, OPEN, PREFLIGHT, SOURCE, REVIEW, INTENT, CREATE, CHECK, READBACK, AFTER }
    private fun emit(line: String) {
        require(line.length <= 512 && '\n' !in line && '\r' !in line)
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply { putString("stream", "$line\n") })
    }
    private fun digest(v: String) = MessageDigest.getInstance("SHA-256").digest(v.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun <T> RepositoryResult<T>.required(): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("LOCAL_INVENTORY_UNAVAILABLE")
    }
    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
    private fun click(tag: String) {
        val node = compose.onNodeWithTag(tag)
        if (tag !in setOf("update_preparation_confirm", "installation_backup_confirm")) node.performScrollTo()
        node.performClick()
    }
    private fun await(tag: String) = compose.waitUntil(15_000) { present(tag) }
    private fun reportFacts(report: UpdatePreflightSnapshot) {
        emit("LIVE_BACKUP_ROOT=" + report.root.name)
        emit("LIVE_BACKUP_DEFINITION=" + report.serviceDefinition.name)
        emit("LIVE_BACKUP_SERVICE=" + report.serviceState.name)
        emit("LIVE_BACKUP_BASELINE_MATCHED=" + (report.baselineStatus == ManagementBaselineStatus.Matched))
        val recovery = UpdateRecoveryReadinessPolicy.review(report, Instant.now())
        emit("LIVE_BACKUP_SOURCE_BLOCKERS=" + if (recovery is UpdateRecoveryPlanReview.Blocked)
            recovery.reasons.sortedBy { it.ordinal }.joinToString(",") { it.name } else "NONE")
        val files = report.recoveryFiles
        emit("LIVE_BACKUP_FILE_ISSUES=" + (files?.issues?.sortedBy { it.ordinal }?.joinToString(",") { it.name }?.ifEmpty { "NONE" } ?: "UNOBSERVED"))
        emit("LIVE_BACKUP_SOURCE_FINGERPRINT=" + if (files?.sourceSetDigest != null) "PRESENT" else "ABSENT")
        files?.let { emit("LIVE_BACKUP_SOURCE_FILES=" + it.fileCount); emit("LIVE_BACKUP_SOURCE_BYTES=" + it.totalBytes) }
    }

    @Test fun exactAuthorizedNativeBackupAndIndependentCheck() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("LIVE_BACKUP_OPT_IN_REQUIRED", args.getString("live_authorization") == "REAL_NEW_TEST_SERVER_BACKUP_AFTER_CONFIRMED_FAILURE_UI")
        assertEquals("192.0.2.139", args.getString("live_host")); assertEquals("21578", args.getString("live_port"))
        val nonce = args.getString("live_run_nonce").orEmpty()
        assertTrue(Regex("[0-9a-f]{32}").matches(nonce))
        var stage = Stage.TARGET
        val backupRef = AtomicReference<ManagementInstallationBackupViewModel?>()
        var preflight: ManagementUpdatePreparationViewModel? = null
        try {
            val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as VelumTegraApplication
            val journal = app.debugMaintenanceDependencies().journal
            fun exact(): Triple<VersionedRecord<Server>, ServerAccess, VersionedRecord<XuiInstallation>> = runBlocking {
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
                assertEquals(server, app.inventoryServerRepository.get(server.value.id).required())
                assertEquals(access, app.inventoryServerAccessRepository.get(access.id).required())
                val installations = app.inventoryInstallationRepository.listForServer(server.value.id).required()
                assertTrue(installations.size <= 96 && installations.all { it.value.serverId == server.value.id })
                assertEquals(installations.size, installations.map { it.value.id }.distinct().size)
                val installation = installations.single { record -> record.value.identity.let {
                    it.serviceUnit == "x-ui.service" && it.binaryPath == "/usr/local/x-ui/x-ui" &&
                        it.rootPath == "/usr/local/x-ui" && it.databasePath == "/etc/x-ui/x-ui.db"
                } }
                assertEquals(installation, app.inventoryInstallationRepository.get(installation.value.id).required())
                assertEquals(ManagementAccess(installation.value.id, access.id), app.inventoryManagementRepository.get(installation.value.id, access.id).required())
                assertEquals("88712ec46623201e0b25403f82c5a44a459222dd10316b50fd732d87c4ee392d", digest(installation.value.id.value))
                Triple(server, access, installation)
            }
            val selected = exact(); val server = selected.first.value; val access = selected.second; val installation = selected.third.value
            fun stable() { assertEquals(selected, exact()) }
            val reviewed = (LocalSshReadinessPolicy.inspect(server.id.value, access.id.value, access) as? LocalSshReadinessResult.MetadataPresent)?.summary
                ?: throw AssertionError("SAVED_TARGET_INVALID")
            val targetDigest = digest(listOf(server.id.value, selected.first.revision.value.toString(), access.id.value,
                reviewed.host, reviewed.port.toString(), reviewed.username, reviewed.savedFingerprint,
                reviewed.credentialRefDigest).joinToString("") { "${it.length}:$it" })
            assertEquals("698cb8a2b1726c1c4dbc2028c29b989d2e4ce59709865ed0b2e735d3b798f08f", targetDigest)
            fun clearJournal() = runBlocking {
                val entries = (journal.listNonTerminal() as? OperationJournalResult.Success)?.value ?: error("JOURNAL_UNAVAILABLE")
                assertTrue(entries.size <= 512 && entries.map { it.snapshot.operationId }.distinct().size == entries.size)
                assertTrue(entries.all { OperationJournalContractPolicy.validateInitial(it.snapshot) == OperationSnapshotValidation.Valid })
                assertTrue(entries.none { it.snapshot.target.serverId == server.id })
            }
            // Test harness anti-replay intent only. Never grants runtime authority or clears a journal barrier.
            val priorId = OperationId("49c230f1-4dad-4cb6-8b19-1affc369b64d")
            val prior = runBlocking { (journal.get(priorId) as? OperationJournalResult.Success)?.value } ?: error("PRIOR_RECORD_MISSING")
            assertEquals(OperationStatus.RECONCILIATION_REQUIRED, prior.snapshot.status)
            assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, prior.snapshot.checkpoint.semantics)
            assertEquals(InstallationBackupPhase.COMMAND_FAILED, InstallationBackupBinding.parse(prior.snapshot.checkpoint.phaseName)?.first)
            assertTrue(InstallationBackupBindingPolicy.matches(prior, installation, access))
            val priorIntent = File(app.noBackupFilesDir, "t4_18-backup-${targetDigest.take(32)}.intent")
            assertTrue(priorIntent.isFile && priorIntent.length() in 1..512)
            val priorIntentBytes = priorIntent.readBytes()
            assertEquals(targetDigest, priorIntentBytes.toString(Charsets.UTF_8).lines().getOrNull(1))
            // Read an actual preflight ID; never synthesize a pointer or supply a report.
            val sourceId = android.database.sqlite.SQLiteDatabase.openDatabase(
                app.getDatabasePath(com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory.DEFAULT_DATABASE_NAME).absolutePath,
                null, android.database.sqlite.SQLiteDatabase.OPEN_READONLY).use { db ->
                db.rawQuery("SELECT operation_id FROM operation_snapshots WHERE server_id=? AND installation_id=? AND server_access_id=? " +
                    "AND operation_type='UPDATE_PREFLIGHT' AND status='SUCCEEDED' " +
                    "AND (started_at_epoch_second<? OR (started_at_epoch_second=? AND started_at_nano<=?)) " +
                    "ORDER BY started_at_epoch_second DESC,started_at_nano DESC,operation_id LIMIT 2",
                    arrayOf(server.id.value,installation.id.value,access.id.value,prior.snapshot.startedAt.epochSecond.toString(),
                        prior.snapshot.startedAt.epochSecond.toString(),prior.snapshot.startedAt.nano.toString())).use { cursor ->
                    assertTrue(cursor.count in 1..2 && cursor.moveToFirst()); cursor.getString(0)
                }
            }
            val actualSource = runBlocking { (journal.get(OperationId(sourceId)) as? OperationJournalResult.Success)?.value } ?: error("SOURCE_RECORD_MISSING")
            assertEquals(OperationType.UPDATE_PREFLIGHT, actualSource.snapshot.type)
            assertEquals(OperationStatus.SUCCEEDED, actualSource.snapshot.status)
            assertEquals(prior.snapshot.target, actualSource.snapshot.target)
            assertTrue(!actualSource.snapshot.startedAt.isAfter(prior.snapshot.startedAt))
            val priorSource = UpdatePreflightPointer(sourceId, access.id.value)
            val intent = File(app.noBackupFilesDir, "t4_18-after-failure-49c230f1-${targetDigest.take(32)}.intent")
            assertFalse("PREVIOUS_BACKUP_ATTEMPT_REQUIRES_REVIEW_NO_REPLAY", intent.exists())
            stable()
            emit("LIVE_BACKUP_PRIOR_OPERATION=" + priorId.value)
            emit("LIVE_BACKUP_BEGIN=192.0.2.139:21578"); emit("LIVE_RUN_NONCE=$nonce")
            emit("LIVE_SAVED_TARGET_SHA256=$targetDigest")
            val statuses = app.updatePreflightStatusPort()
            val backupStatuses = app.installationBackupStatusPort()
            val local = RepositoryManagementLocalReviewPort(app.inventoryServerRepository, app.inventoryInstallationRepository,
                app.inventoryManagementRepository, app.inventoryServerAccessRepository)
            val model = ManagementUpdatePreparationViewModel(SavedStateHandle(), server.id.value, installation.id.value, access.id.value,
                local, statuses, RepositorySshReadinessPort(app.inventoryServerRepository, app.inventoryServerAccessRepository))
            preflight = model
            var backupSource by mutableStateOf<UpdatePreflightPointer?>(priorSource)
            val preflightActions = app.visibleUpdatePreflightActionPort(compose.activity, local)
            val backupActions = app.visibleInstallationBackupActionPort(compose.activity)
            stage = Stage.OPEN
            compose.setContent { VelumTegraTheme {
                val pointer = backupSource
                if (pointer == null) ManagementUpdatePreparationScreen(model, preflightActions, {},
                    onInstallationBackup = { backupSource = it })
                else {
                    val backup = remember(pointer) { ManagementInstallationBackupViewModel(SavedStateHandle(), server.id.value,
                        installation.id.value, access.id.value, pointer, app.managementRestartLocalPort, statuses, backupStatuses) }
                    DisposableEffect(backup) { backupRef.set(backup); onDispose { backupRef.compareAndSet(backup, null) } }
                    ManagementInstallationBackupScreen(backup, backupActions, { backupSource = null })
                }
            } }
            stage = Stage.RECONCILE
            await("installation_backup_check")
            compose.waitUntil(15_000) { backupRef.get()?.state?.value?.let { !it.loading && it.observation?.mayCheck == true } == true }
            val existing = requireNotNull(backupRef.get())
            assertEquals(priorId.value, existing.state.value.operationId)
            compose.onNodeWithTag("installation_backup_create").assertIsNotEnabled()
            click("installation_backup_check"); await("installation_backup_confirm"); stable(); click("installation_backup_confirm")
            compose.waitUntil(120_000) { existing.state.value.let { !it.busy && it.observation?.terminal == true } }
            compose.waitUntil(15_000) { app.operationHostLifecycleRegistry.latest()?.let { it.operationId == priorId && it.state.isTerminal } == true }
            val closedPrior = runBlocking { (journal.get(priorId) as? OperationJournalResult.Success)?.value } ?: error("PRIOR_RECORD_MISSING")
            assertEquals(OperationStatus.FAILED, closedPrior.snapshot.status)
            assertEquals(CheckpointSemantics.TERMINAL, closedPrior.snapshot.checkpoint.semantics)
            assertEquals(InstallationBackupPhase.FAILED, InstallationBackupBinding.parse(closedPrior.snapshot.checkpoint.phaseName)?.first)
            assertNull(existing.state.value.observation?.receipt)
            val priorHistory = runBlocking { (journal.history(priorId) as? OperationJournalResult.Success)?.value } ?: error("PRIOR_HISTORY_MISSING")
            assertEquals(1, priorHistory.count { it.checkpoint.semantics == CheckpointSemantics.MUTATION_IN_FLIGHT })
            assertEquals(1, priorHistory.count { it.checkpoint.semantics == CheckpointSemantics.POST_VERIFY_REQUIRED })
            assertArrayEquals(priorIntentBytes, priorIntent.readBytes()); clearJournal(); stable()
            emit("LIVE_BACKUP_PRIOR=CONFIRMED_FAILURE_CLOSED_BY_NATIVE_READ_ONLY_CHECK")
            click("installation_backup_back")
            stage = Stage.OPEN
            await("update_preparation_request"); stable(); clearJournal()
            assertNull(model.state.value.pointer); emit("LIVE_BACKUP_OPEN=LOCAL_ONLY")
            fun readFromUi(): UpdatePreflightSnapshot {
                click("update_preparation_request"); await("update_preparation_confirm")
                stable(); emit("LIVE_BACKUP_PREFLIGHT_REVIEW=VISIBLE")
                click("update_preparation_confirm"); emit("LIVE_BACKUP_PREFLIGHT_CONFIRM=CLICKED")
                compose.waitUntil(180_000) {
                    model.state.value.result?.let { it.terminal || it.attemptEnded } == true || model.state.value.notice != null
                }
                stable()
                val result = model.state.value.result ?: error("PREFLIGHT_NO_RESULT")
                val report = result.snapshot ?: error("PREFLIGHT_NO_CURRENT_FACTS")
                assertTrue(result.terminal)
                val pointer = requireNotNull(model.state.value.pointer)
                assertEquals(ManagementScope(OperationId(pointer.operationId), server.id, access.id, installation.id), report.scope)
                compose.waitUntil(15_000) {
                    app.operationHostLifecycleRegistry.latest()?.let { it.operationId == report.scope.operationId && it.state.isTerminal } == true
                }
                reportFacts(report)
                return report
            }
            stage = Stage.PREFLIGHT
            val report = readFromUi()
            assertTrue(UpdateRecoveryReadinessPolicy.review(report, Instant.now()) is UpdateRecoveryPlanReview.Draft)
            assertTrue(RecoveryFileInventoryPolicy.review(report, Instant.now()) is RecoveryFileInventoryReview.KnownSet)
            assertNotNull(report.recoveryFiles?.sourceSetDigest)
            emit("LIVE_BACKUP_PREFLIGHT=ACTUAL_SOURCE_VERIFIED")
            clearJournal()
            stage = Stage.SOURCE
            click("installation_backup_open"); await("installation_backup_create")
            compose.waitUntil(15_000) { backupRef.get()?.state?.value?.loading == false }
            val backup = requireNotNull(backupRef.get())
            assertEquals(report, backup.state.value.source); assertTrue(backup.state.value.sourceReady)
            assertNull(backup.state.value.operationId); stable(); clearJournal()
            compose.onNodeWithTag("installation_backup_create").assertIsEnabled()
            stage = Stage.REVIEW
            click("installation_backup_create"); await("installation_backup_confirm")
            assertNull(backup.state.value.operationId); stable(); clearJournal()
            emit("LIVE_BACKUP_REVIEW=EXPLICIT_CREATE_NOT_DISPATCHED")
            stage = Stage.INTENT
            assertTrue(intent.createNewFile())
            FileOutputStream(intent).use { it.write("T4.18\n$targetDigest\n$nonce\n".toByteArray(Charsets.UTF_8)); it.fd.sync() }
            val directory = Os.open(app.noBackupFilesDir.absolutePath, OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW, 0)
            try {
                assertTrue(OsConstants.S_ISDIR(Os.fstat(directory).st_mode))
                Os.fsync(directory)
            } finally { Os.close(directory) }
            // All later failures retain this intent, including a crash before pointer publication.
            stage = Stage.CREATE
            stable(); click("installation_backup_confirm")
            compose.waitUntil(180_000) {
                val state = backup.state.value
                val id = state.operationId
                (!state.busy && state.notice != null) ||
                    (!state.busy && id != null && state.observation?.let { it.terminal || it.mayCheck } == true &&
                        app.operationHostLifecycleRegistry.latest()?.let { it.operationId.value == id && it.state.isTerminal } == true)
            }
            stable()
            val id = requireNotNull(backup.state.value.operationId)
            assertTrue(Regex("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}").matches(id))
            assertNotEquals(priorId.value, id)
            emit("LIVE_BACKUP_OPERATION_ID=$id")
            val created = runBlocking { (journal.get(OperationId(id)) as? OperationJournalResult.Success)?.value } ?: error("JOURNAL_UNAVAILABLE")
            assertEquals(InstallationBackupPhase.FINISHED, InstallationBackupBinding.parse(created.snapshot.checkpoint.phaseName)?.first)
            assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, created.snapshot.checkpoint.semantics)
            assertTrue(backup.state.value.observation?.mayCheck == true)
            assertNull(backup.state.value.observation?.receipt)
            emit("LIVE_BACKUP_CREATE=FINISHED_SEPARATE_CHECK_REQUIRED")
            stage = Stage.CHECK
            click("installation_backup_check"); await("installation_backup_confirm")
            stable(); click("installation_backup_confirm")
            compose.waitUntil(120_000) {
                !backup.state.value.busy && (backup.state.value.observation?.terminal == true || backup.state.value.notice != null)
            }
            compose.waitUntil(15_000) {
                app.operationHostLifecycleRegistry.latest()?.let { it.operationId.value == id && it.state.isTerminal } == true
            }
            // Journal commit can precede process receipt publication. Refresh local status, never rerun verification.
            click("installation_backup_refresh")
            compose.waitUntil(15_000) { !backup.state.value.loading && backup.state.value.observation?.receipt != null }
            stable()
            stage = Stage.READBACK
            val observation = requireNotNull(backup.state.value.observation)
            val receipt = requireNotNull(observation.receipt)
            assertEquals(ManagementScope(OperationId(id), server.id, access.id, installation.id), receipt.scope)
            assertTrue(observation.terminal && observation.mayReviewRestore && !observation.mayCheck)
            val current = runBlocking { (journal.get(OperationId(id)) as? OperationJournalResult.Success)?.value } ?: error("JOURNAL_UNAVAILABLE")
            assertTrue(InstallationBackupBindingPolicy.matches(current, installation, access))
            assertEquals(OperationStatus.SUCCEEDED, current.snapshot.status)
            assertEquals(InstallationBackupPhase.VERIFIED, InstallationBackupBinding.parse(current.snapshot.checkpoint.phaseName)?.first)
            val history = runBlocking { (journal.history(OperationId(id)) as? OperationJournalResult.Success)?.value } ?: error("JOURNAL_HISTORY_UNAVAILABLE")
            assertEquals(1, history.count { it.checkpoint.semantics == CheckpointSemantics.MUTATION_IN_FLIGHT })
            assertEquals(1, history.count { it.checkpoint.semantics == CheckpointSemantics.POST_VERIFY_REQUIRED })
            assertEquals(current.revision, history.last().revision)
            val independent = runBlocking { backupStatuses.read(server.id.value, installation.id.value, access.id.value, id) }
            assertEquals(observation, independent)
            await("installation_backup_hash")
            compose.onNodeWithTag("installation_backup_hash").assertTextContains(receipt.sha256, substring = true)
            compose.onNodeWithTag("installation_backup_database_hash").assertTextContains(receipt.databaseSha256, substring = true)
            emit("LIVE_BACKUP_ARCHIVE_SHA256=" + receipt.sha256)
            emit("LIVE_BACKUP_DATABASE_SHA256=" + receipt.databaseSha256)
            emit("LIVE_BACKUP_INVENTORY_SHA256=" + receipt.inventorySha256)
            emit("LIVE_BACKUP_BYTES=" + receipt.sizeBytes); emit("LIVE_BACKUP_FILES=" + receipt.fileCount)
            emit("LIVE_BACKUP_MANIFEST_AND_SQLITE=INDEPENDENT_CHECK_VERIFIED")
            compose.waitUntil(15_000) { app.operationHostLifecycleRegistry.latest()?.let { it.operationId.value == id && it.state.isTerminal } == true }
            clearJournal()
            stage = Stage.AFTER
            click("installation_backup_back"); await("update_preparation_request")
            compose.waitUntil(15_000) { model.state.value.local is LocalManagementReview.Ready && model.state.value.profile != null }
            val after = readFromUi()
            assertNotEquals(report.scope.operationId, after.scope.operationId)
            assertTrue(!after.observedAt.isBefore(receipt.verifiedAt))
            assertEquals(ManagementServiceState.ACTIVE, after.serviceState)
            assertEquals(ManagementBaselineStatus.Matched, after.baselineStatus)
            assertEquals(report.currentVersion, after.currentVersion); assertEquals(report.architecture, after.architecture)
            assertTrue(UpdateRecoveryReadinessPolicy.review(after, Instant.now()) is UpdateRecoveryPlanReview.Draft)
            assertTrue(RecoveryFileInventoryPolicy.review(after, Instant.now()) is RecoveryFileInventoryReview.KnownSet)
            stable(); clearJournal()
            FileOutputStream(intent, true).use { it.write("VERIFIED\n$id\n${receipt.sha256}\n".toByteArray(Charsets.UTF_8)); it.fd.sync() }
            assertArrayEquals(priorIntentBytes, priorIntent.readBytes())
            assertEquals(closedPrior, runBlocking { (journal.get(priorId) as? OperationJournalResult.Success)?.value })
            emit("LIVE_BACKUP_PRIOR_GUARD_AND_FAILED_HISTORY=PRESERVED")
            emit("LIVE_BACKUP_AFTER=FRESH_ACTIVE_SERVICE_BASELINE_SOURCE_VERIFIED")
            emit("LIVE_BACKUP_RESTORE=NOT_REQUESTED")
            emit("LIVE_BACKUP_PASS=192.0.2.139:21578")
        } catch (_: Exception) {
            emitFailure(stage, preflight, backupRef.get())
        } catch (_: AssertionError) {
            emitFailure(stage, preflight, backupRef.get())
        }
    }

    private fun emitFailure(stage: Stage, preflight: ManagementUpdatePreparationViewModel?, backup: ManagementInstallationBackupViewModel?): Nothing {
        // Finite typed diagnostics only: no Compose trees, SQL, private names, settings, keys or transport output.
        preflight?.state?.value?.let { state ->
            emit("LIVE_BACKUP_PREFLIGHT_POINTER_PRESENT=" + (state.pointer != null))
            emit("LIVE_BACKUP_PREFLIGHT_REVIEW_VISIBLE=" + state.reviewing)
            emit("LIVE_BACKUP_PREFLIGHT_NOTICE_PRESENT=" + (state.notice != null))
            state.result?.snapshot?.let(::reportFacts)
        }
        backup?.state?.value?.let { state ->
            emit("LIVE_BACKUP_LOCAL_BUSY=" + state.busy)
            emit("LIVE_BACKUP_LOCAL_CAN_CHECK=" + (state.observation?.mayCheck == true))
        }
        runCatching {
            val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as VelumTegraApplication
            val sourceId = preflight?.state?.value?.pointer?.operationId
            sourceId?.let {
                val failure = app.updatePreflightResultRegistry.latest(OperationId(it)) as? UpdatePreflightProcessResult.Failed
                failure?.let { failed -> emit("LIVE_BACKUP_PREFLIGHT_FAILURE=" + failed.kind.name) }
            }
            backup?.state?.value?.operationId?.let { id ->
                if (Regex("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}").matches(id)) emit("LIVE_BACKUP_OPERATION_ID=$id")
                val current = runBlocking { (app.debugMaintenanceDependencies().journal.get(OperationId(id)) as? OperationJournalResult.Success)?.value }
                current?.snapshot?.let {
                    emit("LIVE_BACKUP_JOURNAL_STATUS=" + it.status.name)
                    emit("LIVE_BACKUP_JOURNAL_SEMANTICS=" + it.checkpoint.semantics.name)
                    InstallationBackupBinding.parse(it.checkpoint.phaseName)?.let { parsed -> emit("LIVE_BACKUP_PHASE=" + parsed.first.name) }
                }
                val rejected = app.installationBackupResultRegistry.latest(OperationId(id)) as? com.velumtegra.xuimobile.core.runtime.InstallationBackupRuntimeResult.Rejected
                rejected?.let { emit("LIVE_BACKUP_RUNTIME_REJECTION=" + it.failure.name) }
            }
        }
        throw AssertionError("LIVE_BACKUP_BLOCKED_STAGE=${stage.name};NO_CREATE_REPLAY")
    }
}
