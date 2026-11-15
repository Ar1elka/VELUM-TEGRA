package com.velumtegra.xuimobile.integration
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.lifecycle.SavedStateHandle
import com.velumtegra.xuimobile.management.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.ui.theme.VelumTegraTheme
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
/** Memory-only review/confirmation UI. No real archive/key/DB/service/SSH operations. */
class Phase15_10T4_16KnownFileRestoreAcceptanceInstrumentedTest{
    @get:Rule val compose=createComposeRule()
    private val performs=AtomicInteger();private val reviews=AtomicInteger();private val discarded=AtomicInteger()
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val parent=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private val binding=KnownFileRestoreBinding(OperationId("compare"),4,parent,"2".repeat(64),2,"3".repeat(64))
    private val scope=ManagementScope(OperationId("files"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private var clock=Instant.now()
    private var localReview=KnownFileRestoreReview("token",scope,0,binding,KnownFileRestoreAction.APPLY,"Fixture VPS","operator@fixture:22",clock)
    private var available=true;private var backCount=0
    private var reviewResult:suspend(KnownFileRestoreAction)->KnownFileRestoreReview?={a->if(available)localReview.copy(action=a,reviewedAt=clock,returnManifest=if(a==KnownFileRestoreAction.RETURN)"4".repeat(64)else null)else null}
    private fun proof(desired:Int=1)=KnownFileRestoreInspection(scope,binding,"4".repeat(64),"5".repeat(64),desired,2-desired,clock)
    private var result:suspend(KnownFileRestoreReview)->KnownFileRestoreResult={r->if(r.action==KnownFileRestoreAction.READ)KnownFileRestoreResult.Checked(proof(),false,true)else KnownFileRestoreResult.Recorded(r.scope.operationId.value)}
    private val port=object:KnownFileRestorePort{
        override suspend fun review(server:String,installation:String,access:String,comparison:String,operation:String?,evidence:RecoveryReadinessEvidence?,returning:KnownFileRestoreInspection?):KnownFileRestoreReview?{
            reviews.incrementAndGet();assertEquals("server",server);assertEquals("install",installation);assertEquals("ssh",access);assertEquals("compare",comparison)
            return reviewResult(if(returning!=null)KnownFileRestoreAction.RETURN else if(operation!=null)KnownFileRestoreAction.READ else KnownFileRestoreAction.APPLY)
        }
        override suspend fun perform(review:KnownFileRestoreReview):KnownFileRestoreResult{performs.incrementAndGet();return result(review)}
        override fun discard(review:KnownFileRestoreReview){discarded.incrementAndGet()}
    }
    private fun show(saved:SavedStateHandle=SavedStateHandle()):ManagementKnownFileRestoreViewModel{
        val m=ManagementKnownFileRestoreViewModel(saved,"server","install","ssh","compare",null,port,{clock})
        compose.setContent{VelumTegraTheme{ManagementKnownFileRestoreScreen(m,onBack={backCount++})}}
        compose.waitUntil(10_000){!m.state.value.loading};return m
    }
    private fun click(tag:String)=compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag:String)=compose.waitUntil(10_000){compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()}
    private fun absent(tag:String)=assertEquals(0,compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    private fun request(){click("known_file_request");await("known_file_confirm")}
    private fun confirm(){request();compose.onNodeWithTag("known_file_ack").performClick();compose.onNodeWithTag("known_file_confirm").performClick()}
    private fun readSaved()=SavedStateHandle(mapOf("known_file_operation" to "files"))
    @Test fun openingOnlyReviewsLocalSource(){show();assertEquals(0,performs.get());assertEquals(1,reviews.get())}
    @Test fun refreshNeverDispatches(){show();click("known_file_refresh");assertEquals(0,performs.get())}
    @Test fun dialogShowsExactSourceWithoutDispatch(){show();request();compose.onNodeWithTag("known_file_review_hash").assertTextContains("b".repeat(64),substring=true);assertEquals(0,performs.get())}
    @Test fun consentStartsUnchecked(){show();request();compose.onNodeWithTag("known_file_confirm").assertIsNotEnabled();assertEquals(0,performs.get())}
    @Test fun dismissDoesNotDispatch(){show();request();compose.onNodeWithTag("known_file_dismiss").performClick();absent("known_file_confirm");assertEquals(0,performs.get())}
    @Test fun applyRecordsButNeverClaimsVerifiedFiles(){show();confirm();await("known_file_recorded");absent("known_file_checked");assertEquals(1,performs.get())}
    @Test fun recordedRequestOffersOnlySeparateReadAfterLocalRefresh(){val m=show();confirm();await("known_file_recorded");click("known_file_refresh");compose.waitUntil(10_000){!m.state.value.loading};assertEquals(KnownFileRestoreAction.READ,m.state.value.review!!.action);assertEquals(1,performs.get())}
    @Test fun partialReadShowsMixedCountsAndSeparateReturn(){show(readSaved());confirm();await("known_file_checked");compose.onNodeWithTag("known_file_counts").assertTextContains("Из копии: 1; прежних: 1",substring=true);compose.onNodeWithTag("known_file_return").assertExists()}
    @Test fun completeReadShowsEvidenceWithoutReturn(){result={KnownFileRestoreResult.Checked(proof(2),true,false)};show(readSaved());confirm();await("known_file_checked");absent("known_file_return");compose.onNodeWithTag("known_file_checked").assertTextContains("прочитаны и проверены",substring=true)}
    @Test fun returnGetsNewUncheckedDialogAndExactManifest(){show(readSaved());confirm();await("known_file_return");click("known_file_return");await("known_file_confirm");compose.onNodeWithTag("known_file_confirm").assertIsNotEnabled();compose.onNodeWithTag("known_file_return_hash").assertTextContains("4".repeat(64),substring=true);assertEquals(1,performs.get())}
    @Test fun returnDispatchRequiresNewConsent(){show(readSaved());confirm();await("known_file_return");click("known_file_return");await("known_file_confirm");compose.onNodeWithTag("known_file_ack").performClick();compose.onNodeWithTag("known_file_confirm").performClick();await("known_file_recorded");assertEquals(2,performs.get())}
    @Test fun missingSourceNeverShowsWrite(){available=false;show();absent("known_file_request");assertEquals(0,performs.get())}
    @Test fun foreignScopeReviewIsDiscarded(){localReview=localReview.copy(scope=scope.copy(serverAccessId=ServerAccessId("foreign")));show();absent("known_file_request");assertTrue(discarded.get()>0)}
    @Test fun foreignParentReviewIsDiscarded(){localReview=localReview.copy(binding=binding.copy(comparisonOperationId=OperationId("foreign")));show();absent("known_file_request")}
    @Test fun savedPointerRestoresNoConsentOrProof(){val m=show(readSaved());assertEquals(KnownFileRestoreAction.READ,m.state.value.review!!.action);absent("known_file_confirm");absent("known_file_checked");assertEquals(0,performs.get())}
    @Test fun savedPointerCannotBecomeNewApply(){reviewResult={localReview};show(readSaved());absent("known_file_request");assertEquals(0,performs.get())}
    @Test fun backgroundDropsConsentAndProof(){val m=show();request();compose.runOnIdle{m.leaveForeground();m.confirm();m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};absent("known_file_confirm");assertEquals(0,performs.get())}
    @Test fun duplicateConfirmDispatchesOnce(){val gate=CompletableDeferred<KnownFileRestoreResult>();result={gate.await()};val m=show();request();compose.runOnIdle{m.confirm();m.confirm()};compose.waitUntil(10_000){performs.get()==1};gate.complete(KnownFileRestoreResult.Recorded("files"));await("known_file_recorded");assertEquals(1,performs.get())}
    @Test fun lateRemoteProofAfterBackgroundCannotPublish(){val gate=CompletableDeferred<KnownFileRestoreResult>();result={withContext(NonCancellable){gate.await()}};val m=show(readSaved());confirm();compose.waitUntil(10_000){performs.get()==1};compose.runOnIdle{m.leaveForeground();m.enterForeground()};gate.complete(KnownFileRestoreResult.Checked(proof(),false,true));compose.waitUntil(10_000){!m.state.value.loading};absent("known_file_checked")}
    @Test fun foreignProofCannotPublish(){result={KnownFileRestoreResult.Checked(proof().copy(scope=scope.copy(serverId=ServerId("foreign"))),false,true)};show(readSaved());confirm();await("known_file_unavailable");absent("known_file_checked")}
    @Test fun expiredReviewCannotDispatch(){val m=show();request();compose.runOnIdle{clock=clock.plusSeconds(90);m.confirm()};compose.waitUntil(10_000){!m.state.value.loading};assertEquals(0,performs.get())}
    @Test fun unknownOutcomeNeverAutomaticallyReturns(){result={KnownFileRestoreResult.Unavailable("Исход неизвестен; барьер сохранён")};show();confirm();await("known_file_unavailable");absent("known_file_return");assertEquals(1,performs.get())}
    @Test fun backDoesNotDispatch(){show();click("known_file_back");assertEquals(1,backCount);assertEquals(0,performs.get())}
    @Test fun limitsKeepStoppedServiceAndDatabasePairing(){show();compose.onNodeWithTag("known_file_stopped").assertTextContains("База не заменяется",substring=true);compose.onNodeWithTag("known_file_limits").assertTextContains("Автоматического повтора или возврата нет",substring=true)}
}
