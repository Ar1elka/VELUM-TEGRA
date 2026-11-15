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
class Phase15_10T4_10RestoredPanelStartAcceptanceInstrumentedTest{
    @get:Rule val compose=createAndroidComposeRule<ComponentActivity>()
    private val at=Instant.parse("2026-10-18T18:00:00Z")
    private val i=XuiInstallation(XuiInstallationId("install"),ServerId("server"),InstallationOwnership.ADOPTED,InstallationIdentity("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",null),InstallationBaseline("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",2053,"/panel/",null,at))
    private val a=ServerAccess(ServerAccessId("ssh"),i.serverId,SshEndpoint("fixture.invalid",22),"root",SshAuthRef.Password(SecretId("fixture")),HostKeyFingerprint("SHA256:fixture"))
    private val review=ManagementRestartReview("Fixture VPS",i,a)
    private val local=AtomicReference<ManagementRestartLocalReview>(ManagementRestartLocalReview.Ready(review))
    private val backup=InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64))
    private val checked=RestoreCheckBinding(OperationId("backup"),2,backup,"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val compared=RestoreCompatibilityBinding(OperationId("check"),3,checked,"f".repeat(64))
    private val restoredBinding=WorkingDatabaseRestoreBinding(OperationId("source-comparison"),4,compared,"9".repeat(64),"8".repeat(64))
    private val sourceRow=RestoredPanelStartSourceReview("restore-db",5,restoredBinding,true)
    private var sourceRead:suspend()->RestoredPanelStartSourceReview?={sourceRow}
    private val binding=RestoredPanelStartBinding(OperationId("restore-db"),5,restoredBinding,"7".repeat(64))
    private val receipt=RestoredPanelStartReceipt(ManagementScope(OperationId("restore"),i.serverId,a.id,i.id),binding,"3.10.0",UpdateServerArchitecture.AMD64,"1".repeat(64),2,at)
    private val starts=AtomicInteger();private val checks=AtomicInteger();private val cancels=AtomicInteger();private val panels=AtomicInteger()
    private val observation=AtomicReference(RestoredPanelStartObservation("restore","restore-db","Запрос зарегистрирован.",false,mayCancel=true))
    private var read:suspend()->RestoredPanelStartObservation?={observation.get()}
    private var start:suspend()->RestoredPanelStartRequest={RestoredPanelStartRequest.Recorded("restore")}
    private fun checking(){observation.set(RestoredPanelStartObservation("restore","restore-db","Запуск мог выполниться. Повторного запуска не будет.",false,mayCheck=true))}
    private fun complete(r:RestoredPanelStartReceipt=receipt){observation.set(RestoredPanelStartObservation("restore","restore-db","Активная служба проверена. Вход не подтверждён.",true,receipt=r))}
    private val statuses=object:RestoredPanelStartStatusPort{
        override suspend fun source(server:String,installation:String,access:String,source:String):RestoredPanelStartSourceReview?{assertEquals(listOf("server","install","ssh","restore-db"),listOf(server,installation,access,source));return sourceRead()}
        override suspend fun read(server:String,installation:String,access:String,operation:String):RestoredPanelStartObservation?{assertEquals("restore",operation);return read()}
        override suspend fun unfinished(server:String,installation:String,access:String,source:String)=emptyList<String>()
    }
    private val actions=object:RestoredPanelStartActionPort{
        override suspend fun startConfirmed(review:ManagementRestartReview,source:RestoredPanelStartSourceReview):RestoredPanelStartRequest{assertEquals(this@Phase15_10T4_10RestoredPanelStartAcceptanceInstrumentedTest.review,review);assertEquals(sourceRow,source);starts.incrementAndGet();return start()}
        override suspend fun checkConfirmed(review:ManagementRestartReview,source:RestoredPanelStartSourceReview,operation:String):String?{assertEquals("restore",operation);checks.incrementAndGet();complete();return null}
        override suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?{cancels.incrementAndGet();observation.set(RestoredPanelStartObservation("restore","restore-db","Отменено.",true));return null}
    }
    private fun saved(extra:Map<String,Any?> = emptyMap())=SavedStateHandle(mapOf("rps_server" to "server","rps_installation" to "install","rps_access" to "ssh","rps_source" to "restore-db","rps_operation" to "restore")+extra)
    private fun show(saved:SavedStateHandle=SavedStateHandle()):ManagementRestoredPanelStartViewModel{val m=ManagementRestoredPanelStartViewModel(saved,"server","install","ssh","restore-db",ManagementRestartLocalPort{_,_,_->local.get()},statuses);compose.setContent{VelumTegraTheme{ManagementRestoredPanelStartScreen(m,actions,{},onWebPanels={panels.incrementAndGet()})}};compose.waitUntil(10_000){!m.state.value.loading};return m}
    private fun click(tag:String)=compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag:String){compose.waitUntil(10_000){compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()}}
    private fun absent(tag:String)=assertEquals(0,compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    @Test fun exactVerifiedRestoreNavigationDoesNotStart(){val selected=AtomicReference<String?>(null)
        val source=WorkingDatabaseRestoreSourceReview("source-comparison",4,compared,null,false)
        val statuses=object:WorkingDatabaseRestoreStatusPort{
            override suspend fun source(server:String,installation:String,access:String,source:String)=this@Phase15_10T4_10RestoredPanelStartAcceptanceInstrumentedTest.run{WorkingDatabaseRestoreSourceReview("source-comparison",4,compared,null,false)}
            override suspend fun read(server:String,installation:String,access:String,operation:String)=WorkingDatabaseRestoreObservation("restore-db","source-comparison","Verified",true,mayStartService=true)
            override suspend fun unfinished(server:String,installation:String,access:String,source:String)=emptyList<String>()
        }
        val actions=object:WorkingDatabaseRestoreActionPort{
            override suspend fun startConfirmed(review:ManagementRestartReview,source:WorkingDatabaseRestoreSourceReview):WorkingDatabaseRestoreStart=error("navigation only")
            override suspend fun checkConfirmed(review:ManagementRestartReview,source:WorkingDatabaseRestoreSourceReview,operation:String):String?=error("navigation only")
            override suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?=error("navigation only")
        }
        val saved=SavedStateHandle(mapOf("wdb_server" to "server","wdb_installation" to "install","wdb_access" to "ssh","wdb_source" to "source-comparison","wdb_operation" to "restore-db"))
        val m=ManagementWorkingDatabaseRestoreViewModel(saved,"server","install","ssh","source-comparison",ManagementRestartLocalPort{_,_,_->local.get()},statuses)
        compose.setContent{VelumTegraTheme{ManagementWorkingDatabaseRestoreScreen(m,actions,{},onStartService={selected.set(it)})}}
        await("working_db_start_service");click("working_db_start_service");assertEquals("restore-db",selected.get());assertEquals(0,starts.get())
    }
    @Test fun openingAndRefreshNeverStopsOrRestores(){show();click("restored_start_refresh");assertEquals(0,starts.get());assertEquals(0,checks.get())}
    @Test fun consequenceExplainsExposedPortsAndRestoredClients(){show();compose.onNodeWithTag("restored_start_consequence").assertTextContains("Могут открыться настроенные порты",substring=true);compose.onNodeWithTag("restored_start_consequence").assertTextContains("клиентов",substring=true)}
    @Test fun activeServiceIsNotClaimedAuthenticatedRecovery(){show();compose.onNodeWithTag("restored_start_not_login").assertTextContains("ещё не подтверждает вход",substring=true)}
    @Test fun exactSshIsVisible(){show();compose.onNodeWithTag("restored_start_ssh").assertTextContains("root@fixture.invalid:22",substring=true)}
    @Test fun uncheckedAcknowledgementDisablesWriteConfirmation(){show();click("restored_start_start");compose.onNodeWithTag("restored_start_confirm").assertIsNotEnabled();assertEquals(0,starts.get())}
    @Test fun exactHashAndAcknowledgedConfirmationStartsOneRequest(){start={checking();RestoredPanelStartRequest.Recorded("restore")};show();click("restored_start_start");compose.onNodeWithTag("restored_start_review_hash").assertTextContains("b".repeat(64),substring=true);click("restored_start_ack");compose.onNodeWithTag("restored_start_confirm").performClick();await("restored_start_check");assertEquals(1,starts.get());assertEquals(0,checks.get())}
    @Test fun dismissedReviewHasNoMutation(){show();click("restored_start_start");compose.onNodeWithTag("restored_start_dismiss").performClick();assertEquals(0,starts.get());absent("restored_start_confirm")}
    @Test fun missingSourceHidesMutation(){sourceRead={null};show();absent("restored_start_start");assertEquals(0,starts.get())}
    @Test fun unavailableSourceAuthorityDisablesStart(){sourceRead={sourceRow.copy(mayStart=false)};show();compose.onNodeWithTag("restored_start_start").assertIsNotEnabled()}
    @Test fun foreignSourcePointerClearsControls(){sourceRead={sourceRow.copy(operationId="other")};val m=show();assertNull(m.state.value.source);absent("restored_start_start")}
    @Test fun targetChangeClearsMutationControls(){local.set(ManagementRestartLocalReview.Ready(review.copy(access=a.copy(id=ServerAccessId("other")))));show();absent("restored_start_start")}
    @Test fun savedPendingPointerDoesNotReconstructWriteConsent(){show(saved(mapOf("rps_launch_pending" to true)));await("restored_start_cancel");assertEquals(0,starts.get());assertEquals(0,checks.get())}
    @Test fun savedUncertainPointerAllowsOnlyReadback(){checking();show(saved());await("restored_start_check");absent("restored_start_cancel");compose.onNodeWithTag("restored_start_start").assertIsNotEnabled();assertEquals(0,starts.get())}
    @Test fun explicitResultReadDoesNotNeedAnotherStartConsent(){checking();sourceRead={sourceRow.copy(mayStart=false)};show(saved());click("restored_start_check");compose.onNodeWithTag("restored_start_review_readonly").assertTextContains("Повторного запуска",substring=true);assertEquals(0,checks.get());compose.onNodeWithTag("restored_start_confirm").performClick();await("restored_start_verified");assertEquals(1,checks.get());assertEquals(0,starts.get())}
    @Test fun pendingCancelUsesOnlyLocalPort(){show(saved());click("restored_start_cancel");compose.waitUntil(10_000){cancels.get()==1};assertEquals(0,starts.get());assertEquals(0,checks.get())}
    @Test fun duplicateConfirmDuringHandoffDoesNotWriteTwice(){val gate=CompletableDeferred<RestoredPanelStartRequest>();start={gate.await()};val m=show();click("restored_start_start");click("restored_start_ack");compose.runOnIdle{m.confirm(actions);m.confirm(actions)};compose.waitUntil(10_000){starts.get()==1};gate.complete(RestoredPanelStartRequest.Recorded("restore"));assertEquals(1,starts.get())}
    @Test fun leavingForegroundDropsWriteConfirmation(){val m=show();click("restored_start_start");click("restored_start_ack");compose.runOnIdle{m.leaveForeground();m.confirm(actions);m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};absent("restored_start_confirm");assertEquals(0,starts.get())}
    @Test fun changedSourceDuringDialogBlocksWrite(){val m=show();click("restored_start_start");click("restored_start_ack");sourceRead={sourceRow.copy(revision=6)};compose.runOnIdle{m.confirm(actions)};compose.waitUntil(10_000){!m.state.value.busy};assertEquals(0,starts.get())}
    @Test fun foreignReceiptCannotDisplayActiveServiceFacts(){complete(receipt.copy(scope=receipt.scope.copy(serverId=ServerId("other"))));show(saved());absent("restored_start_verified");absent("restored_start_inbounds")}
    @Test fun verifiedReceiptShowsFactsAndWebPanelNavigationDoesNotLogin(){complete();show(saved());compose.onNodeWithTag("restored_start_inbounds").assertTextContains("2",substring=true);click("restored_start_webpanels");assertEquals(1,panels.get());assertEquals(0,starts.get());assertEquals(0,checks.get())}
    @Test fun durableCompletionDoesNotInventCurrentServiceOrLogin(){observation.set(RestoredPanelStartObservation("restore","restore-db","Журнал подтверждает завершение. Текущее состояние неизвестно.",true));show(saved());await("restored_start_status");absent("restored_start_inbounds");absent("restored_start_verified");absent("restored_start_webpanels")}
    @Test fun lateOldSourceCannotOverwriteNewUnavailableForeground(){val m=show();val gate=CompletableDeferred<RestoredPanelStartSourceReview?>();sourceRead={withContext(NonCancellable){gate.await()}};compose.runOnIdle{m.refresh()};compose.runOnIdle{m.leaveForeground();sourceRead={null};m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};gate.complete(sourceRow);compose.waitForIdle();assertNull(m.state.value.source);assertEquals(0,starts.get())}
    @Test fun unknownOutcomeHasNoReplayOrStopControl(){checking();show(saved());compose.onNodeWithTag("restored_start_status").assertTextContains("Повторного запуска не будет",substring=true);absent("restored_start_cancel");assertEquals(0,starts.get())}
}
