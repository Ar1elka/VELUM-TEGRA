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
/** Memory-only UI; no SSH, user database/key reads, service commands or external connections. */
class Phase15_10T4_13BeforeCopyReturnAcceptanceInstrumentedTest {
    @get:Rule val compose=createComposeRule()
    private val reads=AtomicInteger();private val reviews=AtomicInteger();private val discarded=AtomicInteger();private val backs=AtomicInteger()
    private val sourceBinding=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val comparison=RestoreCompatibilityBinding(OperationId("check"),3,sourceBinding,"f".repeat(64))
    private val binding=WorkingDatabaseRestoreBinding(OperationId("compare"),4,comparison,"9".repeat(64),"8".repeat(64))
    private val scope=ManagementScope(OperationId("restore"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val returnBinding=BeforeCopyReturnBinding(binding.phaseName(WorkingDatabaseRestorePhase.UNCERTAIN),5,"1".repeat(64),"2".repeat(64),4096,"3".repeat(64))
    private var review=BeforeCopyReturnReview("token","restore",5,returnBinding,BeforeCopyReturnAction.RETURN_ONCE,"Fixture VPS","operator@fixture:22",Instant.now())
    private var reviewRead:suspend()->BeforeCopyReturnReview? = {review}
    private var resultRead:suspend()->BeforeCopyReturnResult = {BeforeCopyReturnResult.Recorded("restore")}
    private fun receipt()=BeforeCopyReturnReceipt(scope,returnBinding,"4".repeat(64),4096,Instant.now())
    private val port=object:BeforeCopyReturnPort{
        override suspend fun review(server:String,installation:String,access:String,operation:String,evidence:BeforeCopyEvidence?):BeforeCopyReturnReview?{reviews.incrementAndGet();assertEquals("restore",operation);return reviewRead()}
        override suspend fun perform(review:BeforeCopyReturnReview):BeforeCopyReturnResult{reads.incrementAndGet();return resultRead()}
        override fun discard(review:BeforeCopyReturnReview){discarded.incrementAndGet()}
    }
    private fun show(saved:SavedStateHandle=SavedStateHandle()):ManagementBeforeCopyReturnViewModel{
        val m=ManagementBeforeCopyReturnViewModel(saved,"server","install","ssh","restore",null,port)
        compose.setContent{VelumTegraTheme{ManagementBeforeCopyReturnScreen(m,{backs.incrementAndGet()})}}
        compose.waitUntil(10_000){!m.state.value.loading};return m
    }
    private fun click(tag:String)=compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag:String)=compose.waitUntil(10_000){compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()}
    private fun absent(tag:String)=assertEquals(0,compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    private fun request(){click("before_return_action");await("before_return_confirm")}
    private fun confirm(){request();compose.onNodeWithTag("before_return_ack").performScrollTo().performClick();compose.onNodeWithTag("before_return_confirm").performClick()}
    @Test fun openingOnlyReadsLocalJournal(){show();assertEquals(0,reads.get());assertEquals(1,reviews.get())}
    @Test fun refreshNeverCopiesOrReadsRemote(){show();click("before_return_refresh");assertEquals(0,reads.get())}
    @Test fun reviewDialogDoesNotDispatch(){show();request();assertEquals(0,reads.get())}
    @Test fun uncheckedAcknowledgementBlocksReturn(){show();request();compose.onNodeWithTag("before_return_confirm").assertIsNotEnabled();assertEquals(0,reads.get())}
    @Test fun dismissDoesNotReturnDatabase(){show();request();compose.onNodeWithTag("before_return_dismiss").performClick();absent("before_return_confirm");assertEquals(0,reads.get())}
    @Test fun confirmedAttemptDoesNotClaimReadback(){show();confirm();await("before_return_recorded");absent("before_return_checked");assertEquals(1,reads.get())}
    @Test fun separatelyConfirmedReadbackShowsDisplacedHash(){review=review.copy(action=BeforeCopyReturnAction.READ_RESULT);resultRead={BeforeCopyReturnResult.Checked(receipt())};show();confirm();await("before_return_checked");compose.onNodeWithTag("before_return_displaced").assertTextContains("4".repeat(64),substring=true);absent("before_return_recorded")}
    @Test fun unavailableResultCannotClaimReturn(){resultRead={BeforeCopyReturnResult.Unavailable("Исход неизвестен")};show();confirm();await("before_return_unavailable");absent("before_return_checked")}
    @Test fun missingAuthorityHasNoDispatchButton(){reviewRead={null};show();absent("before_return_action");assertEquals(0,reads.get())}
    @Test fun foreignOperationCannotOpenConsent(){review=review.copy(operationId="other");show();absent("before_return_action");assertTrue(discarded.get()>0)}
    @Test fun exactSshProfileIsVisible(){show();compose.onNodeWithTag("before_return_ssh").assertTextContains("operator@fixture:22",substring=true)}
    @Test fun savedAttemptDoesNotRestoreConsentOrCurrentProof(){show(SavedStateHandle(mapOf("before_return_attempted" to true)));absent("before_return_confirm");absent("before_return_checked");assertEquals(0,reads.get())}
    @Test fun backgroundDropsConsent(){val m=show();request();compose.runOnIdle{m.leaveForeground();m.confirm();m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};absent("before_return_confirm");assertEquals(0,reads.get())}
    @Test fun duplicateConfirmCannotDispatchTwice(){val gate=CompletableDeferred<BeforeCopyReturnResult>();resultRead={gate.await()};val m=show();request();compose.runOnIdle{m.confirm();m.confirm()};compose.waitUntil(10_000){reads.get()==1};gate.complete(BeforeCopyReturnResult.Recorded("restore"));await("before_return_recorded");assertEquals(1,reads.get())}
    @Test fun lateLocalReviewCannotSurviveForegroundChange(){val m=show();val gate=CompletableDeferred<BeforeCopyReturnReview?>();reviewRead={withContext(NonCancellable){gate.await()}};click("before_return_refresh");compose.runOnIdle{m.leaveForeground();reviewRead={null};m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};gate.complete(review);compose.waitForIdle();absent("before_return_action")}
    @Test fun lateResultCannotPublishAfterBackground(){val gate=CompletableDeferred<BeforeCopyReturnResult>();resultRead={withContext(NonCancellable){gate.await()}};val m=show();confirm();compose.waitUntil(10_000){reads.get()==1};compose.runOnIdle{m.leaveForeground();m.enterForeground()};gate.complete(BeforeCopyReturnResult.Recorded("restore"));compose.waitUntil(10_000){!m.state.value.loading};absent("before_return_recorded")}
    @Test fun foreignReadbackCannotClaimExactReturn(){review=review.copy(action=BeforeCopyReturnAction.READ_RESULT);resultRead={BeforeCopyReturnResult.Checked(receipt().copy(scope=scope.copy(serverId=ServerId("foreign"))))};show();confirm();await("before_return_unavailable");absent("before_return_checked")}
    @Test fun staleReadbackCannotClaimCurrentReturn(){review=review.copy(action=BeforeCopyReturnAction.READ_RESULT);resultRead={BeforeCopyReturnResult.Checked(receipt().copy(verifiedAt=review.reviewedAt.minusSeconds(1)))};show();confirm();await("before_return_unavailable");absent("before_return_checked")}
    @Test fun limitsRetainStoppedStateAndBarrier(){show();compose.onNodeWithTag("before_return_limits").assertTextContains("Служба останется остановленной",substring=true);compose.onNodeWithTag("before_return_limits").assertTextContains("Барьер неопределённости сохраняется",substring=true)}
    @Test fun backDoesNotDispatchOrRestart(){show();click("before_return_back");assertEquals(1,backs.get());assertEquals(0,reads.get())}
}
