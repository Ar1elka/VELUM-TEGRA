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
class Phase15_10T4_14CompensatedPanelStartAcceptanceInstrumentedTest {
    @get:Rule val compose=createComposeRule()
    private val reads=AtomicInteger();private val reviews=AtomicInteger();private val discarded=AtomicInteger();private val backs=AtomicInteger()
    private val logins=AtomicInteger()
    private val sourceBinding=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val comparison=RestoreCompatibilityBinding(OperationId("check"),3,sourceBinding,"f".repeat(64))
    private val binding=WorkingDatabaseRestoreBinding(OperationId("compare"),4,comparison,"9".repeat(64),"8".repeat(64))
    private val scope=ManagementScope(OperationId("restore"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val returnBinding=BeforeCopyReturnBinding(binding.phaseName(WorkingDatabaseRestorePhase.UNCERTAIN),5,"1".repeat(64),"2".repeat(64),4096,"3".repeat(64))
    private val startBinding=CompensatedPanelStartBinding(returnBinding,7,"5".repeat(64))
    private var review=CompensatedPanelStartReview("token","restore",7,startBinding,CompensatedPanelStartAction.START_ONCE,"Fixture VPS","operator@fixture:22",Instant.now())
    private var reviewRead:suspend()->CompensatedPanelStartReview? = {review}
    private var resultRead:suspend()->CompensatedPanelStartResult = {CompensatedPanelStartResult.Recorded("restore")}
    private fun receipt()=CompensatedPanelStartReceipt(scope,startBinding,"4".repeat(64),2,Instant.now())
    private val port=object:CompensatedPanelStartPort{
        override suspend fun review(server:String,installation:String,access:String,operation:String):CompensatedPanelStartReview?{reviews.incrementAndGet();assertEquals("restore",operation);return reviewRead()}
        override suspend fun perform(review:CompensatedPanelStartReview):CompensatedPanelStartResult{reads.incrementAndGet();return resultRead()}
        override fun discard(review:CompensatedPanelStartReview){discarded.incrementAndGet()}
    }
    private fun show(saved:SavedStateHandle=SavedStateHandle()):ManagementCompensatedPanelStartViewModel{
        val m=ManagementCompensatedPanelStartViewModel(saved,"server","install","ssh","restore",port)
        compose.setContent{VelumTegraTheme{ManagementCompensatedPanelStartScreen(m,{backs.incrementAndGet()},{logins.incrementAndGet()})}}
        compose.waitUntil(10_000){!m.state.value.loading};return m
    }
    private fun click(tag:String)=compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag:String)=compose.waitUntil(10_000){compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()}
    private fun absent(tag:String)=assertEquals(0,compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    private fun request(){click("compensated_start_action");await("compensated_start_confirm")}
    private fun confirm(){request();compose.onNodeWithTag("compensated_start_ack").performScrollTo().performClick();compose.onNodeWithTag("compensated_start_confirm").performClick()}
    @Test fun openingOnlyReadsLocalJournal(){show();assertEquals(0,reads.get());assertEquals(1,reviews.get())}
    @Test fun refreshNeverCopiesOrReadsRemote(){show();click("compensated_start_refresh");assertEquals(0,reads.get())}
    @Test fun reviewDialogDoesNotDispatch(){show();request();assertEquals(0,reads.get())}
    @Test fun uncheckedAcknowledgementBlocksReturn(){show();request();compose.onNodeWithTag("compensated_start_confirm").assertIsNotEnabled();assertEquals(0,reads.get())}
    @Test fun dismissDoesNotReturnDatabase(){show();request();compose.onNodeWithTag("compensated_start_dismiss").performClick();absent("compensated_start_confirm");assertEquals(0,reads.get())}
    @Test fun confirmedAttemptDoesNotClaimReadback(){show();confirm();await("compensated_start_recorded");absent("compensated_start_checked");assertEquals(1,reads.get())}
    @Test fun separatelyConfirmedReadbackShowsActiveStructure(){review=review.copy(action=CompensatedPanelStartAction.READ_RESULT);resultRead={CompensatedPanelStartResult.Checked(receipt())};show();confirm();await("compensated_start_checked");compose.onNodeWithTag("compensated_start_checked").assertTextContains("Служба и структура базы проверены",substring=true);absent("compensated_start_recorded")}
    @Test fun unavailableResultCannotClaimReturn(){resultRead={CompensatedPanelStartResult.Unavailable("Исход неизвестен")};show();confirm();await("compensated_start_unavailable");absent("compensated_start_checked")}
    @Test fun missingAuthorityHasNoDispatchButton(){reviewRead={null};show();absent("compensated_start_action");assertEquals(0,reads.get())}
    @Test fun foreignOperationCannotOpenConsent(){review=review.copy(operationId="other");show();absent("compensated_start_action");assertTrue(discarded.get()>0)}
    @Test fun exactSshProfileIsVisible(){show();compose.onNodeWithTag("compensated_start_ssh").assertTextContains("operator@fixture:22",substring=true)}
    @Test fun savedAttemptDoesNotRestoreConsentOrCurrentProof(){show(SavedStateHandle(mapOf("compensated_start_attempted" to true)));absent("compensated_start_confirm");absent("compensated_start_checked");assertEquals(0,reads.get())}
    @Test fun backgroundDropsConsent(){val m=show();request();compose.runOnIdle{m.leaveForeground();m.confirm();m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};absent("compensated_start_confirm");assertEquals(0,reads.get())}
    @Test fun duplicateConfirmCannotDispatchTwice(){val gate=CompletableDeferred<CompensatedPanelStartResult>();resultRead={gate.await()};val m=show();request();compose.runOnIdle{m.confirm();m.confirm()};compose.waitUntil(10_000){reads.get()==1};gate.complete(CompensatedPanelStartResult.Recorded("restore"));await("compensated_start_recorded");assertEquals(1,reads.get())}
    @Test fun lateLocalReviewCannotSurviveForegroundChange(){val m=show();val gate=CompletableDeferred<CompensatedPanelStartReview?>();reviewRead={withContext(NonCancellable){gate.await()}};click("compensated_start_refresh");compose.runOnIdle{m.leaveForeground();reviewRead={null};m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};gate.complete(review);compose.waitForIdle();absent("compensated_start_action")}
    @Test fun lateResultCannotPublishAfterBackground(){val gate=CompletableDeferred<CompensatedPanelStartResult>();resultRead={withContext(NonCancellable){gate.await()}};val m=show();confirm();compose.waitUntil(10_000){reads.get()==1};compose.runOnIdle{m.leaveForeground();m.enterForeground()};gate.complete(CompensatedPanelStartResult.Recorded("restore"));compose.waitUntil(10_000){!m.state.value.loading};absent("compensated_start_recorded")}
    @Test fun foreignReadbackCannotClaimExactReturn(){review=review.copy(action=CompensatedPanelStartAction.READ_RESULT);resultRead={CompensatedPanelStartResult.Checked(receipt().copy(scope=scope.copy(serverId=ServerId("foreign"))))};show();confirm();await("compensated_start_unavailable");absent("compensated_start_checked")}
    @Test fun staleReadbackCannotClaimCurrentReturn(){review=review.copy(action=CompensatedPanelStartAction.READ_RESULT);resultRead={CompensatedPanelStartResult.Checked(receipt().copy(observedAt=review.reviewedAt.minusSeconds(1)))};show();confirm();await("compensated_start_unavailable");absent("compensated_start_checked")}
    @Test fun limitsRetainStoppedStateAndBarrier(){show();compose.onNodeWithTag("compensated_start_limits").assertTextContains("База и файлы этой командой не заменяются",substring=true);compose.onNodeWithTag("compensated_start_limits").assertTextContains("Барьер исходной операции сохраняется",substring=true)}
    @Test fun backDoesNotDispatchOrRestart(){show();click("compensated_start_back");assertEquals(1,backs.get());assertEquals(0,reads.get())}
    @Test fun sentStartRequestDoesNotOfferAuthenticatedRecovery(){show();confirm();await("compensated_start_recorded");absent("compensated_start_check_login");assertEquals(0,logins.get())}
    @Test fun activeReadbackOnlyOffersSeparatelyReviewedLogin(){review=review.copy(action=CompensatedPanelStartAction.READ_RESULT);resultRead={CompensatedPanelStartResult.Checked(receipt())};show();confirm();await("compensated_start_check_login");assertEquals(0,logins.get());click("compensated_start_check_login");assertEquals(1,logins.get())}
    @Test fun foreignBindingReadbackCannotOfferLogin(){review=review.copy(action=CompensatedPanelStartAction.READ_RESULT);resultRead={CompensatedPanelStartResult.Checked(receipt().copy(binding=startBinding.copy(digest="f".repeat(64))))};show();confirm();await("compensated_start_unavailable");absent("compensated_start_check_login")}
    @Test fun futureObservationCannotClaimCurrentService(){review=review.copy(action=CompensatedPanelStartAction.READ_RESULT);resultRead={CompensatedPanelStartResult.Checked(receipt().copy(observedAt=Instant.now().plusSeconds(30)))};show();confirm();await("compensated_start_unavailable");absent("compensated_start_checked")}

}
