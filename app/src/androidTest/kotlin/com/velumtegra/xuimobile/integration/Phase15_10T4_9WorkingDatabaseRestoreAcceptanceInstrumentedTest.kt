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

/** Memory UI only. No database replacement, service command, keys, files, download or SSH/VPS. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_9WorkingDatabaseRestoreAcceptanceInstrumentedTest{
    @get:Rule val compose=createAndroidComposeRule<ComponentActivity>()
    private val at=Instant.parse("2026-10-18T18:00:00Z")
    private val i=XuiInstallation(XuiInstallationId("install"),ServerId("server"),InstallationOwnership.ADOPTED,InstallationIdentity("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",null),InstallationBaseline("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",2053,"/panel/",null,at))
    private val a=ServerAccess(ServerAccessId("ssh"),i.serverId,SshEndpoint("fixture.invalid",22),"root",SshAuthRef.Password(SecretId("fixture")),HostKeyFingerprint("SHA256:fixture"))
    private val review=ManagementRestartReview("Fixture VPS",i,a)
    private val local=AtomicReference<ManagementRestartLocalReview>(ManagementRestartLocalReview.Ready(review))
    private val backup=InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64))
    private val checked=RestoreCheckBinding(OperationId("backup"),2,backup,"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val compared=RestoreCompatibilityBinding(OperationId("check"),3,checked,"f".repeat(64))
    private val report=RestoreCompatibilityReport(ManagementScope(OperationId("compare"),i.serverId,a.id,i.id),compared,"3.10.0",UpdateServerArchitecture.AMD64,"1".repeat(64),"1".repeat(64),RestoreFileSetComparison.MATCH,0,1,2,ManagementServiceState.ACTIVE,ManagementBaselineStatus.Matched,at)
    private val sourceRow=WorkingDatabaseRestoreSourceReview("compare",4,compared,report,true)
    private var sourceRead:suspend()->WorkingDatabaseRestoreSourceReview?={sourceRow}
    private val binding=WorkingDatabaseRestoreBinding(OperationId("compare"),4,compared,"9".repeat(64),"8".repeat(64))
    private val receipt=WorkingDatabaseRestoreReceipt(ManagementScope(OperationId("restore"),i.serverId,a.id,i.id),binding,"1".repeat(64),"2".repeat(64),"3".repeat(64),8192,at)
    private val starts=AtomicInteger();private val checks=AtomicInteger();private val cancels=AtomicInteger()
    private val observation=AtomicReference(WorkingDatabaseRestoreObservation("restore","compare","Запрос зарегистрирован.",false,mayCancel=true))
    private var read:suspend()->WorkingDatabaseRestoreObservation?={observation.get()}
    private var start:suspend()->WorkingDatabaseRestoreStart={WorkingDatabaseRestoreStart.Recorded("restore")}
    private fun checking(){observation.set(WorkingDatabaseRestoreObservation("restore","compare","Изменение могло выполниться. Повторной записи не будет.",false,mayCheck=true))}
    private fun complete(r:WorkingDatabaseRestoreReceipt=receipt){observation.set(WorkingDatabaseRestoreObservation("restore","compare","База проверена; служба была остановлена.",true,receipt=r))}
    private val statuses=object:WorkingDatabaseRestoreStatusPort{
        override suspend fun source(server:String,installation:String,access:String,source:String):WorkingDatabaseRestoreSourceReview?{assertEquals(listOf("server","install","ssh","compare"),listOf(server,installation,access,source));return sourceRead()}
        override suspend fun read(server:String,installation:String,access:String,operation:String):WorkingDatabaseRestoreObservation?{assertEquals("restore",operation);return read()}
        override suspend fun unfinished(server:String,installation:String,access:String,source:String)=emptyList<String>()
    }
    private val actions=object:WorkingDatabaseRestoreActionPort{
        override suspend fun startConfirmed(review:ManagementRestartReview,source:WorkingDatabaseRestoreSourceReview):WorkingDatabaseRestoreStart{assertEquals(this@Phase15_10T4_9WorkingDatabaseRestoreAcceptanceInstrumentedTest.review,review);assertEquals(sourceRow,source);starts.incrementAndGet();return start()}
        override suspend fun checkConfirmed(review:ManagementRestartReview,source:WorkingDatabaseRestoreSourceReview,operation:String):String?{assertEquals("restore",operation);checks.incrementAndGet();complete();return null}
        override suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?{cancels.incrementAndGet();observation.set(WorkingDatabaseRestoreObservation("restore","compare","Отменено.",true));return null}
    }
    private fun saved(extra:Map<String,Any?> = emptyMap())=SavedStateHandle(mapOf("wdb_server" to "server","wdb_installation" to "install","wdb_access" to "ssh","wdb_source" to "compare","wdb_operation" to "restore")+extra)
    private fun show(saved:SavedStateHandle=SavedStateHandle()):ManagementWorkingDatabaseRestoreViewModel{val m=ManagementWorkingDatabaseRestoreViewModel(saved,"server","install","ssh","compare",ManagementRestartLocalPort{_,_,_->local.get()},statuses);compose.setContent{VelumTegraTheme{ManagementWorkingDatabaseRestoreScreen(m,actions,{})}};compose.waitUntil(10_000){!m.state.value.loading};return m}
    private fun click(tag:String)=compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag:String){compose.waitUntil(10_000){compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()}}
    private fun absent(tag:String)=assertEquals(0,compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    @Test fun exactComparisonNavigationDoesNotWrite(){val selected=AtomicReference<String?>(null);val s=object:RestoreCompatibilityStatusPort{override suspend fun source(server:String,installation:String,access:String,source:String)=RestoreCompatibilitySourceReview("check",3,checked,at)
            override suspend fun read(server:String,installation:String,access:String,operation:String)=RestoreCompatibilityObservation("compare","check","Observed",true,report=report,fresh=true)
            override suspend fun unfinished(server:String,installation:String,access:String,source:String)=emptyList<String>()
        };val acts=object:RestoreCompatibilityActionPort{override suspend fun startConfirmed(review:ManagementRestartReview,source:RestoreCompatibilitySourceReview):RestoreCompatibilityStart=error("Navigation only")
            override suspend fun retryConfirmed(review:ManagementRestartReview,source:RestoreCompatibilitySourceReview,operation:String):String?=error("Navigation only")
            override suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?=error("Navigation only")
        };val m=ManagementRestoreCompatibilityViewModel(SavedStateHandle(mapOf("rcp_server" to "server","rcp_installation" to "install","rcp_access" to "ssh","rcp_source" to "check","rcp_operation" to "compare")),"server","install","ssh","check",ManagementRestartLocalPort{_,_,_->local.get()},s);compose.setContent{VelumTegraTheme{ManagementRestoreCompatibilityScreen(m,acts,{},onRestore={selected.set(it)})}};await("restore_comparison_working_db");click("restore_comparison_working_db");assertEquals("compare",selected.get());assertEquals(0,starts.get())}
    @Test fun openingAndRefreshNeverStopsOrRestores(){show();click("working_db_refresh");assertEquals(0,starts.get());assertEquals(0,checks.get())}
    @Test fun consequenceIncludesStoppedPanelAndOlderData(){show();compose.onNodeWithTag("working_db_consequence").assertTextContains("Панель будет остановлена",substring=true);compose.onNodeWithTag("working_db_consequence").assertTextContains("настройки и клиенты",substring=true)}
    @Test fun serviceRemainsStoppedIsExplained(){show();compose.onNodeWithTag("working_db_stopped").assertTextContains("служба останется остановленной",substring=true)}
    @Test fun exactSshIsVisible(){show();compose.onNodeWithTag("working_db_ssh").assertTextContains("root@fixture.invalid:22",substring=true)}
    @Test fun uncheckedAcknowledgementDisablesWriteConfirmation(){show();click("working_db_restore");compose.onNodeWithTag("working_db_confirm").assertIsNotEnabled();assertEquals(0,starts.get())}
    @Test fun exactHashAndAcknowledgedConfirmationStartsOneRequest(){start={checking();WorkingDatabaseRestoreStart.Recorded("restore")};show();click("working_db_restore");compose.onNodeWithTag("working_db_review_hash").assertTextContains("b".repeat(64),substring=true);click("working_db_ack");compose.onNodeWithTag("working_db_confirm").performClick();await("working_db_check");assertEquals(1,starts.get());assertEquals(0,checks.get())}
    @Test fun dismissedReviewHasNoMutation(){show();click("working_db_restore");compose.onNodeWithTag("working_db_dismiss").performClick();assertEquals(0,starts.get());absent("working_db_confirm")}
    @Test fun missingSourceHidesMutation(){sourceRead={null};show();absent("working_db_restore");assertEquals(0,starts.get())}
    @Test fun missingFreshComparisonDisablesNewMutation(){sourceRead={sourceRow.copy(report=null,mayRestore=false)};show();compose.onNodeWithTag("working_db_restore").assertIsNotEnabled();await("working_db_needs_comparison")}
    @Test fun foreignSourcePointerClearsControls(){sourceRead={sourceRow.copy(operationId="other")};val m=show();assertNull(m.state.value.source);absent("working_db_restore")}
    @Test fun targetChangeClearsMutationControls(){local.set(ManagementRestartLocalReview.Ready(review.copy(access=a.copy(id=ServerAccessId("other")))));show();absent("working_db_restore")}
    @Test fun savedPendingPointerDoesNotReconstructWriteConsent(){show(saved(mapOf("wdb_launch_pending" to true)));await("working_db_cancel");assertEquals(0,starts.get());assertEquals(0,checks.get())}
    @Test fun savedUncertainPointerAllowsOnlyReadback(){checking();show(saved());await("working_db_check");absent("working_db_cancel");compose.onNodeWithTag("working_db_restore").assertIsNotEnabled();assertEquals(0,starts.get())}
    @Test fun resultCheckRequiresSeparateReadOnlyConsentEvenWithoutFreshReport(){checking();sourceRead={sourceRow.copy(report=null,mayRestore=false)};show(saved());click("working_db_check");compose.onNodeWithTag("working_db_review_readonly").assertTextContains("Повторной",substring=true);assertEquals(0,checks.get());compose.onNodeWithTag("working_db_confirm").performClick();await("working_db_verified");assertEquals(1,checks.get());assertEquals(0,starts.get())}
    @Test fun pendingCancelUsesOnlyLocalPort(){show(saved());click("working_db_cancel");compose.waitUntil(10_000){cancels.get()==1};assertEquals(0,starts.get());assertEquals(0,checks.get())}
    @Test fun duplicateConfirmDuringHandoffDoesNotWriteTwice(){val gate=CompletableDeferred<WorkingDatabaseRestoreStart>();start={gate.await()};val m=show();click("working_db_restore");click("working_db_ack");compose.runOnIdle{m.confirm(actions);m.confirm(actions)};compose.waitUntil(10_000){starts.get()==1};gate.complete(WorkingDatabaseRestoreStart.Recorded("restore"));assertEquals(1,starts.get())}
    @Test fun leavingForegroundDropsWriteConfirmation(){val m=show();click("working_db_restore");click("working_db_ack");compose.runOnIdle{m.leaveForeground();m.confirm(actions);m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};absent("working_db_confirm");assertEquals(0,starts.get())}
    @Test fun changedSourceDuringDialogBlocksWrite(){val m=show();click("working_db_restore");click("working_db_ack");sourceRead={sourceRow.copy(revision=5)};compose.runOnIdle{m.confirm(actions)};compose.waitUntil(10_000){!m.state.value.busy};assertEquals(0,starts.get())}
    @Test fun foreignReceiptCannotDisplayPreviousBytes(){complete(receipt.copy(scope=receipt.scope.copy(serverId=ServerId("other"))));show(saved());absent("working_db_previous_size");absent("working_db_verified")}
    @Test fun actualReceiptShowsOnlyActualPreviousCopyBytes(){complete();show(saved());compose.onNodeWithTag("working_db_previous_size").assertTextContains("8192",substring=true);await("working_db_verified");assertEquals(0,checks.get())}
    @Test fun durableCompletionDoesNotInventReceiptOrCurrentServiceState(){observation.set(WorkingDatabaseRestoreObservation("restore","compare","Журнал подтверждает завершение. Текущее состояние неизвестно.",true));show(saved());await("working_db_status");absent("working_db_previous_size");absent("working_db_verified")}
    @Test fun lateOldSourceCannotOverwriteNewUnavailableForeground(){val m=show();val gate=CompletableDeferred<WorkingDatabaseRestoreSourceReview?>();sourceRead={withContext(NonCancellable){gate.await()}};compose.runOnIdle{m.refresh()};compose.runOnIdle{m.leaveForeground();sourceRead={null};m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};gate.complete(sourceRow);compose.waitForIdle();assertNull(m.state.value.source);assertEquals(0,starts.get())}
    @Test fun unknownOutcomeHasNoReplayControl(){checking();show(saved());compose.onNodeWithTag("working_db_status").assertTextContains("Повторной записи не будет",substring=true);absent("working_db_cancel");assertEquals(0,starts.get())}
}
