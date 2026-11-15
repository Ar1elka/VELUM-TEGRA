package com.velumtegra.xuimobile.integration

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.SavedStateHandle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.management.*
import com.velumtegra.xuimobile.ui.theme.VelumTegraTheme
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Memory-only UI. Ports never read archives, extract files, contact SSH or modify any server. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_7RestoreCheckAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val time = Instant.parse("2026-10-18T06:00:00Z")
    private val installation = XuiInstallation(XuiInstallationId("install"),ServerId("server"),InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",null),
        InstallationBaseline("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",2053,"/panel/",null,time))
    private val access = ServerAccess(ServerAccessId("ssh"),installation.serverId,SshEndpoint("fixture.invalid",22),"root",
        SshAuthRef.Password(SecretId("fixture-reference")),HostKeyFingerprint("SHA256:fixture"))
    private val review=ManagementRestartReview("Fixture VPS",installation,access)
    private val local=AtomicReference<ManagementRestartLocalReview>(ManagementRestartLocalReview.Ready(review))
    private val sourceBinding=InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64))
    private val sourceRow=RestoreCheckSourceReview("backup",sourceBinding,time)
    private var sourceRead: suspend () -> RestoreCheckSourceReview? = {sourceRow}
    private val binding=RestoreCheckBinding(OperationId("backup"),2,sourceBinding,"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val scope=ManagementScope(OperationId("restore"),installation.serverId,access.id,installation.id)
    private val inspections=AtomicInteger();private val copies=AtomicInteger();private val checks=AtomicInteger();private val cancels=AtomicInteger();private val reads=AtomicInteger()
    private val observation=AtomicReference(RestoreCheckObservation("restore","backup","Запрос проверки зарегистрирован.",false,mayInspect=true,mayCancel=true))
    private var read: suspend () -> RestoreCheckObservation? = {observation.get()}
    private var inspect: suspend () -> RestoreCheckStart = {RestoreCheckStart.Recorded("restore")}
    private var copy: suspend () -> String? = {observation.set(RestoreCheckObservation("restore","backup","Нужна отдельная проверка результата.",false,mayCheck=true,sourceProof=binding));null}
    private val statuses=object:RestoreCheckStatusPort {
        override suspend fun source(server:String,installation:String,access:String,source:String):RestoreCheckSourceReview? {
            assertEquals(listOf("server","install","ssh","backup"),listOf(server,installation,access,source));return sourceRead()
        }
        override suspend fun read(server:String,installation:String,access:String,operation:String):RestoreCheckObservation? {
            assertEquals(listOf("server","install","ssh","restore"),listOf(server,installation,access,operation));reads.incrementAndGet();return read()
        }
        override suspend fun unfinished(server:String,installation:String,access:String,source:String)=emptyList<String>()
    }
    private val actions=object:RestoreCheckActionPort {
        override suspend fun inspectConfirmed(review:ManagementRestartReview,source:String):RestoreCheckStart {
            assertEquals(this@Phase15_10T4_7RestoreCheckAcceptanceInstrumentedTest.review,review);assertEquals("backup",source);inspections.incrementAndGet();return inspect()
        }
        override suspend fun inspectCurrentConfirmed(review:ManagementRestartReview,operation:String):String? {assertEquals("restore",operation);inspections.incrementAndGet();return null}
        override suspend fun restoreConfirmed(review:ManagementRestartReview,operation:String,reviewedSource:RestoreCheckBinding):String? {
            assertEquals("restore",operation);assertEquals(binding,reviewedSource);copies.incrementAndGet();return copy()
        }
        override suspend fun checkConfirmed(review:ManagementRestartReview,operation:String):String? {
            assertEquals("restore",operation);checks.incrementAndGet();observation.set(RestoreCheckObservation("restore","backup","Пробные файлы проверены.",true,sourceProof=binding,receipt=RestoreCheckReceipt(scope,binding,12288,time)));return null
        }
        override suspend fun cancelPending(review:ManagementRestartReview,operation:String):String? {
            cancels.incrementAndGet();observation.set(RestoreCheckObservation("restore","backup","Ожидающий запрос отменён.",true,sourceProof=binding));return null
        }
    }
    private fun model(saved:SavedStateHandle)=ManagementRestoreCheckViewModel(saved,"server","install","ssh","backup",ManagementRestartLocalPort{_,_,_->local.get()},statuses)
    private fun show(saved:SavedStateHandle=SavedStateHandle()):ManagementRestoreCheckViewModel {
        val m=model(saved);compose.setContent{VelumTegraTheme{ManagementRestoreCheckScreen(m,actions,{})}}
        compose.waitUntil(10_000){!m.state.value.loading};return m
    }
    private fun restored(extra:Map<String,Any?> = emptyMap())=SavedStateHandle(mapOf("rc_server" to "server","rc_installation" to "install","rc_access" to "ssh","rc_source" to "backup","rc_operation" to "restore")+extra)
    private fun reviewed(){observation.set(RestoreCheckObservation("restore","backup","Источник проверен.",false,mayRestore=true,mayCancel=true,sourceProof=binding))}
    private fun click(tag:String)=compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag:String){compose.waitUntil(10_000){compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()}}
    private fun absent(tag:String)=assertEquals(0,compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)

    @Test fun backupLinkPassesExactCompletedOperationWithoutLaunchingAnyAction(){
        val selected=AtomicReference<String?>(null)
        val oldStatuses=object:InstallationBackupStatusPort {
            override suspend fun read(server:String,installation:String,access:String,operation:String)=InstallationBackupObservation("backup","Копия проверена.",true,mayReviewRestore=true)
            override suspend fun unfinished(server:String,installation:String,access:String)=emptyList<String>()
        }
        val oldActions=object:InstallationBackupActionPort {
            override suspend fun createConfirmed(review:ManagementRestartReview,source:UpdatePreflightPointer):InstallationBackupStart=error("Navigation only")
            override suspend fun checkConfirmed(review:ManagementRestartReview,operation:String):String?=error("Navigation only")
            override suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?=error("Navigation only")
        }
        val saved=SavedStateHandle(mapOf("ibb_server" to "server","ibb_installation" to "install","ibb_access" to "ssh","ibb_operation" to "backup"))
        val m=ManagementInstallationBackupViewModel(saved,"server","install","ssh",UpdatePreflightPointer("preflight","ssh"),ManagementRestartLocalPort{_,_,_->local.get()},
            UpdatePreflightStatusPort{_,_,_->UpdatePreflightStatus("fixture",true,null)},oldStatuses)
        compose.setContent{VelumTegraTheme{ManagementInstallationBackupScreen(m,oldActions,{},onRestoreCheck={selected.set(it)})}}
        await("installation_backup_restore_check");click("installation_backup_restore_check");assertEquals("backup",selected.get());assertEquals(0,inspections.get());assertEquals(0,copies.get())
    }
    @Test fun openingAndRefreshingOnlyReadLocalStatus(){show();click("restore_check_refresh");assertEquals(0,inspections.get());assertEquals(0,copies.get());assertEquals(0,checks.get())}
    @Test fun scopeExplainsPrivateIsolatedFolderAndRemainingCompatibility(){show();compose.onNodeWithTag("restore_check_scope").assertTextContains("Рабочие файлы и база панели не заменяются",substring=true);compose.onNodeWithTag("restore_check_scope").assertTextContains("совместимость разных версий",substring=true)}
    @Test fun sourceInspectionNeedsSeparateNativeConfirmation(){show();click("restore_check_source");await("restore_check_confirm");assertEquals(0,inspections.get());compose.onNodeWithTag("restore_check_confirm").performClick();compose.waitUntil(10_000){inspections.get()==1};assertEquals(0,copies.get())}
    @Test fun sourceReviewCopyAndExplicitReadbackRemainUsableInOneForegroundSession(){
        inspect={reviewed();RestoreCheckStart.Recorded("restore")};show();click("restore_check_source")
        compose.onNodeWithTag("restore_check_confirm").performClick();await("restore_check_restore")
        click("restore_check_restore");compose.onNodeWithTag("restore_check_confirm").performClick();await("restore_check_verify")
        click("restore_check_verify");compose.onNodeWithTag("restore_check_confirm").performClick();await("restore_check_receipt_size")
        assertEquals(1,inspections.get());assertEquals(1,copies.get());assertEquals(1,checks.get())
    }
    @Test fun dismissingSourceReviewDoesNothing(){show();click("restore_check_source");compose.onNodeWithTag("restore_check_dismiss").performClick();assertEquals(0,inspections.get());absent("restore_check_confirm")}
    @Test fun missingSourceLeavesNoRemoteAction(){sourceRead={null};show();absent("restore_check_source");assertEquals(0,inspections.get());assertEquals(0,copies.get())}
    @Test fun foreignSourcePointerCannotPopulateSelectedCopy(){sourceRead={sourceRow.copy(operationId="foreign")};val m=show();assertNull(m.state.value.source);absent("restore_check_source");assertEquals(0,inspections.get())}
    @Test fun changedLocalTargetClearsButtons(){local.set(ManagementRestartLocalReview.Ready(review.copy(access=access.copy(id=ServerAccessId("other")))));val m=show();assertNull(m.state.value.review);absent("restore_check_source");assertEquals(0,copies.get())}
    @Test fun exactSshIdentityIsVisibleBeforeAnyAction(){show();compose.onNodeWithTag("restore_check_ssh").assertTextContains("root@fixture.invalid:22",substring=true);assertEquals(0,inspections.get())}
    @Test fun durableReviewedSourceNeverAutomaticallyCopies(){reviewed();show(restored());await("restore_check_restore");assertEquals(0,copies.get());assertEquals(0,checks.get());assertEquals(0,inspections.get())}
    @Test fun copyReviewFreezesActualSourceHashAndDispatchesOnce(){reviewed();show(restored());click("restore_check_restore");compose.onNodeWithTag("restore_check_review_hash").assertTextContains("b".repeat(64),substring=true);assertEquals(0,copies.get());compose.onNodeWithTag("restore_check_confirm").performClick();compose.waitUntil(10_000){copies.get()==1};assertEquals(0,checks.get())}
    @Test fun dismissingCopyReviewDoesNotCopy(){reviewed();show(restored());click("restore_check_restore");compose.onNodeWithTag("restore_check_dismiss").performClick();assertEquals(0,copies.get())}
    @Test fun duplicateConfirmationDuringPendingHandoffDoesNotCopyTwice(){
        reviewed();val gate=CompletableDeferred<String?>();copy={gate.await()};val m=show(restored());click("restore_check_restore")
        compose.runOnIdle{m.confirm(actions);m.confirm(actions)};compose.waitUntil(10_000){copies.get()==1};assertEquals(1,copies.get());gate.complete(null)
    }
    @Test fun resultCheckIsSeparateAndShowsOnlyActualReceipt(){
        observation.set(RestoreCheckObservation("restore","backup","Нужна проверка результата.",false,mayCheck=true,sourceProof=binding));show(restored());click("restore_check_verify")
        assertEquals(0,checks.get());compose.onNodeWithTag("restore_check_confirm").performClick();compose.waitUntil(10_000){checks.get()==1};await("restore_check_receipt_size")
        compose.onNodeWithTag("restore_check_receipt_size").assertTextContains("12288",substring=true);assertEquals(0,copies.get())
    }
    @Test fun pendingCancellationIsLocal(){reviewed();show(restored());click("restore_check_cancel");compose.waitUntil(10_000){cancels.get()==1};assertEquals(0,copies.get());assertEquals(0,checks.get());assertEquals(0,inspections.get())}
    @Test fun pendingProcessPointerShowsUncertainHandoffWithoutReplay(){show(restored(mapOf("rc_launch_pending" to true)));await("restore_check_notice");compose.onNodeWithTag("restore_check_notice").assertTextContains("Автоматического повтора не будет",substring=true);assertEquals(0,copies.get());assertEquals(0,inspections.get())}
    @Test fun foreignSavedSourceCannotReuseOperationPointer(){val m=show(restored(mapOf("rc_source" to "other")));assertNull(m.state.value.operationId);assertEquals(0,reads.get());assertEquals(0,copies.get())}
    @Test fun foreignOperationObservationCannotRenderSourceProof(){reviewed();read={observation.get().copy(operationId="foreign")};show(restored());absent("restore_check_source_hash");absent("restore_check_restore");assertEquals(0,copies.get())}
    @Test fun receiptForAnotherTargetCannotRenderRestoredBytes(){
        observation.set(RestoreCheckObservation("restore","backup","Foreign",true,sourceProof=binding,receipt=RestoreCheckReceipt(scope.copy(serverId=ServerId("other")),binding,12288,time)))
        show(restored());absent("restore_check_receipt_size");absent("restore_check_source_hash")
    }
    @Test fun leavingForegroundDiscardsReviewAndDoesNotResumeConfirmation(){reviewed();val m=show(restored());click("restore_check_restore");compose.runOnIdle{m.leaveForeground();m.confirm(actions);m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};absent("restore_check_confirm");assertEquals(0,copies.get())}
    @Test fun lateOldSourceReadCannotOverwriteNewForegroundUnavailableState(){
        val m=show();val gate=CompletableDeferred<RestoreCheckSourceReview?>();sourceRead={withContext(NonCancellable){gate.await()}}
        compose.runOnIdle{m.refresh()};compose.runOnIdle{m.leaveForeground();sourceRead={null};m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};gate.complete(sourceRow)
        compose.waitForIdle();assertNull(m.state.value.source);assertNull(m.state.value.review);assertEquals(0,copies.get())
    }
}
