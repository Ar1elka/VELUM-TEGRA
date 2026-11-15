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

/** Memory-only UI; no archive/key reads, schema execution, files, downloads or SSH/VPS. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_8RestoreCompatibilityAcceptanceInstrumentedTest {
    @get:Rule val compose=createAndroidComposeRule<ComponentActivity>()
    private val time=Instant.parse("2026-10-18T06:00:00Z")
    private val installation=XuiInstallation(XuiInstallationId("install"),ServerId("server"),InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",null),
        InstallationBaseline("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",2053,"/panel/",null,time))
    private val access=ServerAccess(ServerAccessId("ssh"),installation.serverId,SshEndpoint("fixture.invalid",22),"root",SshAuthRef.Password(SecretId("fixture-reference")),HostKeyFingerprint("SHA256:fixture"))
    private val review=ManagementRestartReview("Fixture VPS",installation,access)
    private val local=AtomicReference<ManagementRestartLocalReview>(ManagementRestartLocalReview.Ready(review))
    private val backup=InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64))
    private val restored=RestoreCheckBinding(OperationId("backup"),2,backup,"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val sourceRow=RestoreCompatibilitySourceReview("check",3,restored,time)
    private var sourceRead:suspend()->RestoreCompatibilitySourceReview?={sourceRow}
    private val binding=RestoreCompatibilityBinding(OperationId("check"),3,restored,"f".repeat(64))
    private val scope=ManagementScope(OperationId("compare"),installation.serverId,access.id,installation.id)
    private val reads=AtomicInteger();private val starts=AtomicInteger();private val retries=AtomicInteger();private val cancels=AtomicInteger()
    private val observation=AtomicReference(RestoreCompatibilityObservation("compare","check","Запрос сверки зарегистрирован.",false,mayRetry=true,mayCancel=true))
    private var read:suspend()->RestoreCompatibilityObservation?={observation.get()}
    private var start:suspend()->RestoreCompatibilityStart={RestoreCompatibilityStart.Recorded("compare")}
    private fun report()=RestoreCompatibilityReport(scope,binding,"3.10.0",UpdateServerArchitecture.AMD64,"1".repeat(64),"1".repeat(64),RestoreFileSetComparison.MATCH,0,1,2,ManagementServiceState.ACTIVE,ManagementBaselineStatus.Matched,time)
    private fun complete(r:RestoreCompatibilityReport=report(),fresh:Boolean=true){observation.set(RestoreCompatibilityObservation("compare","check","Сверка завершена.",true,report=r,fresh=fresh))}
    private val statuses=object:RestoreCompatibilityStatusPort{
        override suspend fun source(server:String,installation:String,access:String,source:String):RestoreCompatibilitySourceReview?{assertEquals(listOf("server","install","ssh","check"),listOf(server,installation,access,source));return sourceRead()}
        override suspend fun read(server:String,installation:String,access:String,operation:String):RestoreCompatibilityObservation?{assertEquals(listOf("server","install","ssh","compare"),listOf(server,installation,access,operation));reads.incrementAndGet();return read()}
        override suspend fun unfinished(server:String,installation:String,access:String,source:String)=emptyList<String>()
    }
    private val actions=object:RestoreCompatibilityActionPort{
        override suspend fun startConfirmed(review:ManagementRestartReview,source:RestoreCompatibilitySourceReview):RestoreCompatibilityStart{assertEquals(this@Phase15_10T4_8RestoreCompatibilityAcceptanceInstrumentedTest.review,review);assertEquals(sourceRow,source);starts.incrementAndGet();return start()}
        override suspend fun retryConfirmed(review:ManagementRestartReview,source:RestoreCompatibilitySourceReview,operation:String):String?{assertEquals("compare",operation);retries.incrementAndGet();return null}
        override suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?{assertEquals("compare",operation);cancels.incrementAndGet();observation.set(RestoreCompatibilityObservation("compare","check","Запрос отменён.",true));return null}
    }
    private fun model(saved:SavedStateHandle)=ManagementRestoreCompatibilityViewModel(saved,"server","install","ssh","check",ManagementRestartLocalPort{_,_,_->local.get()},statuses)
    private fun show(saved:SavedStateHandle=SavedStateHandle()):ManagementRestoreCompatibilityViewModel{val m=model(saved);compose.setContent{VelumTegraTheme{ManagementRestoreCompatibilityScreen(m,actions,{})}};compose.waitUntil(10_000){!m.state.value.loading};return m}
    private fun saved(extra:Map<String,Any?> = emptyMap())=SavedStateHandle(mapOf("rcp_server" to "server","rcp_installation" to "install","rcp_access" to "ssh","rcp_source" to "check","rcp_operation" to "compare")+extra)
    private fun click(tag:String)=compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag:String){compose.waitUntil(10_000){compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()}}
    private fun absent(tag:String)=assertEquals(0,compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    @Test fun navigationUsesVerifiedRestoreOperationWithoutRemoteAction(){
        val selected=AtomicReference<String?>(null)
        val oldStatuses=object:RestoreCheckStatusPort{
            override suspend fun source(server:String,installation:String,access:String,source:String)=RestoreCheckSourceReview("backup",backup,time)
            override suspend fun read(server:String,installation:String,access:String,operation:String)=RestoreCheckObservation("check","backup","Проверено.",true,sourceProof=restored,mayCompare=true)
            override suspend fun unfinished(server:String,installation:String,access:String,source:String)=emptyList<String>()
        }
        val oldActions=object:RestoreCheckActionPort{
            override suspend fun inspectConfirmed(review:ManagementRestartReview,source:String):RestoreCheckStart=error("Navigation only")
            override suspend fun inspectCurrentConfirmed(review:ManagementRestartReview,operation:String):String?=error("Navigation only")
            override suspend fun restoreConfirmed(review:ManagementRestartReview,operation:String,reviewedSource:RestoreCheckBinding):String?=error("Navigation only")
            override suspend fun checkConfirmed(review:ManagementRestartReview,operation:String):String?=error("Navigation only")
            override suspend fun cancelPending(review:ManagementRestartReview,operation:String):String?=error("Navigation only")
        }
        val m=ManagementRestoreCheckViewModel(SavedStateHandle(mapOf("rc_server" to "server","rc_installation" to "install","rc_access" to "ssh","rc_source" to "backup","rc_operation" to "check")),"server","install","ssh","backup",ManagementRestartLocalPort{_,_,_->local.get()},oldStatuses)
        compose.setContent{VelumTegraTheme{ManagementRestoreCheckScreen(m,oldActions,{},onCompare={selected.set(it)})}}
        await("restore_check_compare");click("restore_check_compare");assertEquals("check",selected.get());assertEquals(0,starts.get())
    }
    @Test fun openingAndRefreshingDoesNotRequestRemoteReading(){show();click("restore_comparison_refresh");assertEquals(0,starts.get());assertEquals(0,retries.get())}
    @Test fun scopeExplainsReadOnlyAndNoWorkingRecoveryClaim(){show();compose.onNodeWithTag("restore_comparison_scope").assertTextContains("Это только чтение",substring=true);compose.onNodeWithTag("restore_comparison_scope").assertTextContains("ещё не подтверждает восстановление",substring=true)}
    @Test fun readRequiresNativeConfirmationAndShowsExactHash(){start={complete();RestoreCompatibilityStart.Recorded("compare")};show();click("restore_comparison_read");compose.onNodeWithTag("restore_comparison_review_hash").assertTextContains("b".repeat(64),substring=true);assertEquals(0,starts.get());compose.onNodeWithTag("restore_comparison_confirm").performClick();await("restore_comparison_schema");assertEquals(1,starts.get())}
    @Test fun dismissingReviewDoesNothing(){show();click("restore_comparison_read");compose.onNodeWithTag("restore_comparison_dismiss").performClick();assertEquals(0,starts.get());absent("restore_comparison_confirm")}
    @Test fun missingSourceDisablesRemoteAction(){sourceRead={null};show();absent("restore_comparison_read");assertEquals(0,starts.get())}
    @Test fun foreignSourcePointerCannotSelectAnotherCopy(){sourceRead={sourceRow.copy(operationId="foreign")};val m=show();assertNull(m.state.value.source);absent("restore_comparison_read")}
    @Test fun changedTargetDiscardsControls(){local.set(ManagementRestartLocalReview.Ready(review.copy(access=access.copy(id=ServerAccessId("other")))));val m=show();assertNull(m.state.value.review);absent("restore_comparison_read")}
    @Test fun exactSshProfileIsShownBeforeReading(){show();compose.onNodeWithTag("restore_comparison_ssh").assertTextContains("root@fixture.invalid:22",substring=true);assertEquals(0,starts.get())}
    @Test fun pendingSavedPointerDoesNotReplayReading(){show(saved(mapOf("rcp_launch_pending" to true)));await("restore_comparison_notice");assertEquals(0,starts.get());assertEquals(0,retries.get())}
    @Test fun duplicateConfirmDuringHandoffDoesNotLaunchTwice(){val gate=CompletableDeferred<RestoreCompatibilityStart>();start={gate.await()};val m=show();click("restore_comparison_read");compose.runOnIdle{m.confirm(actions);m.confirm(actions)};compose.waitUntil(10_000){starts.get()==1};assertEquals(1,starts.get());gate.complete(RestoreCompatibilityStart.Recorded("compare"))}
    @Test fun foregroundExitDiscardsConfirmation(){val m=show();click("restore_comparison_read");compose.runOnIdle{m.leaveForeground();m.confirm(actions);m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};absent("restore_comparison_confirm");assertEquals(0,starts.get())}
    @Test fun changedSourceWhileReviewOpenCannotUseOldConfirmation(){val m=show();click("restore_comparison_read");sourceRead={sourceRow.copy(revision=4)};compose.runOnIdle{m.confirm(actions)};compose.waitUntil(10_000){!m.state.value.busy};assertEquals(0,starts.get());assertNull(m.state.value.source)}
    @Test fun foreignOperationCannotDisplayComparison(){complete();read={observation.get().copy(operationId="foreign")};show(saved());absent("restore_comparison_schema");absent("restore_comparison_summary")}
    @Test fun reportForAnotherServerCannotDisplayCounts(){complete(report().copy(scope=scope.copy(serverId=ServerId("other"))));show(saved());absent("restore_comparison_counts");absent("restore_comparison_schema")}
    @Test fun actualReportShowsObservedVersionsSchemaAndDistinctCounts(){complete();show(saved());compose.onNodeWithTag("restore_comparison_version").assertTextContains("3.10.0",substring=true);compose.onNodeWithTag("restore_comparison_schema").assertTextContains("совпадает",substring=true);compose.onNodeWithTag("restore_comparison_counts").assertTextContains("копия 1 · установка 2",substring=true)}
    @Test fun unknownSchemaNeverAppearsMatched(){complete(report().copy(currentSchemaSha256=null,currentInbounds=null));show(saved());compose.onNodeWithTag("restore_comparison_schema").assertTextContains("не проверена",substring=true);compose.onNodeWithTag("restore_comparison_summary").assertTextContains("непроверенные",substring=true)}
    @Test fun differentVersionIsVisibleAsDifference(){complete(report().copy(currentVersion="3.10.2"));show(saved());compose.onNodeWithTag("restore_comparison_version").assertTextContains("установка 3.10.2",substring=true);compose.onNodeWithTag("restore_comparison_summary").assertTextContains("различия",substring=true)}
    @Test fun pendingCancellationUsesOnlyLocalPort(){show(saved());click("restore_comparison_cancel");compose.waitUntil(10_000){cancels.get()==1};assertEquals(0,starts.get());assertEquals(0,retries.get())}
    @Test fun lateOldReadCannotReplaceNewUnavailableForeground(){val m=show();val gate=CompletableDeferred<RestoreCompatibilitySourceReview?>();sourceRead={withContext(NonCancellable){gate.await()}};compose.runOnIdle{m.refresh()};compose.runOnIdle{m.leaveForeground();sourceRead={null};m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};gate.complete(sourceRow);compose.waitForIdle();assertNull(m.state.value.source);assertEquals(0,starts.get())}
    @Test fun durableCompletionCannotInventSchemaOrCounters(){observation.set(RestoreCompatibilityObservation("compare","check","Подробные наблюдения не сохранились.",true));show(saved());await("restore_comparison_status");absent("restore_comparison_schema");absent("restore_comparison_counts");assertEquals(0,starts.get())}
    @Test fun staleReportIsExplicitAndDoesNotTriggerFreshReading(){complete(fresh=false);show(saved());await("restore_comparison_stale");assertEquals(0,starts.get());assertEquals(0,retries.get())}
}
