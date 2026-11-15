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
class Phase15_10T4_12BeforeCopyEvidenceAcceptanceInstrumentedTest {
    @get:Rule val compose=createComposeRule()
    private val reads=AtomicInteger();private val reviews=AtomicInteger();private val discarded=AtomicInteger();private val backs=AtomicInteger()
    private val sourceBinding=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val comparison=RestoreCompatibilityBinding(OperationId("check"),3,sourceBinding,"f".repeat(64))
    private val binding=WorkingDatabaseRestoreBinding(OperationId("compare"),4,comparison,"9".repeat(64),"8".repeat(64))
    private val scope=ManagementScope(OperationId("restore"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private var review=BeforeCopyReview("token","restore",5,binding.digest,"Fixture VPS","operator@fixture:22",Instant.now())
    private fun evidence()=BeforeCopyEvidence(scope,binding,"1".repeat(64),"2".repeat(64),4096,BeforeCopyService.INACTIVE,BeforeCopyCurrent.DIFFERENT,BeforeCopyStructure.MATCH,BeforeCopyCompletion.PARTIAL,Instant.now())
    private var reviewRead:suspend()->BeforeCopyReview? = {review}
    private var resultRead:suspend()->BeforeCopyResult = {BeforeCopyResult.Observed(evidence())}
    private val port=object:BeforeCopyEvidencePort{
        override suspend fun review(server:String,installation:String,access:String,operation:String):BeforeCopyReview?{reviews.incrementAndGet();assertEquals("restore",operation);return reviewRead()}
        override suspend fun read(review:BeforeCopyReview):BeforeCopyResult{reads.incrementAndGet();return resultRead()}
        override fun discard(review:BeforeCopyReview){discarded.incrementAndGet()}
    }
    private fun show(saved:SavedStateHandle=SavedStateHandle()):ManagementBeforeCopyEvidenceViewModel{
        val m=ManagementBeforeCopyEvidenceViewModel(saved,"server","install","ssh","restore",port)
        compose.setContent{VelumTegraTheme{ManagementBeforeCopyEvidenceScreen(m,{backs.incrementAndGet()})}}
        compose.waitUntil(10_000){!m.state.value.loading};return m
    }
    private fun click(tag:String)=compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag:String)=compose.waitUntil(10_000){compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()}
    private fun absent(tag:String)=assertEquals(0,compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    private fun request(){click("before_copy_read");await("before_copy_confirm")}
    private fun confirm(){request();compose.onNodeWithTag("before_copy_ack").performClick();compose.onNodeWithTag("before_copy_confirm").performClick()}
    @Test fun openingOnlyReadsLocalSource(){show();assertEquals(0,reads.get());assertEquals(1,reviews.get())}
    @Test fun refreshNeverConnects(){show();click("before_copy_refresh");assertEquals(0,reads.get())}
    @Test fun reviewDialogDoesNotReadRemote(){show();request();assertEquals(0,reads.get())}
    @Test fun uncheckedConsentBlocksRead(){show();request();compose.onNodeWithTag("before_copy_confirm").assertIsNotEnabled();assertEquals(0,reads.get())}
    @Test fun dismissNeverReadsRemote(){show();request();compose.onNodeWithTag("before_copy_dismiss").performClick();absent("before_copy_confirm");assertEquals(0,reads.get())}
    @Test fun exactReadShowsPriorHashAndSize(){show();confirm();await("before_copy_observed");compose.onNodeWithTag("before_copy_hash").assertTextContains("1".repeat(64),substring=true);assertEquals(1,reads.get())}
    @Test fun unavailableResultCannotClaimCopyExists(){resultRead={BeforeCopyResult.Unavailable("Копия не подтверждена")};show();confirm();await("before_copy_unavailable");absent("before_copy_observed")}
    @Test fun missingLocalSourceHasNoReadButton(){reviewRead={null};show();absent("before_copy_read");assertEquals(0,reads.get())}
    @Test fun foreignOperationSourceCannotOpenRead(){review=review.copy(operationId="other");show();absent("before_copy_read");assertTrue(discarded.get()>0)}
    @Test fun exactSshProfileIsVisible(){show();compose.onNodeWithTag("before_copy_ssh").assertTextContains("operator@fixture:22",substring=true)}
    @Test fun savedAttemptDoesNotRestoreConsentOrResult(){show(SavedStateHandle(mapOf("before_read_attempted" to true)));absent("before_copy_confirm");absent("before_copy_observed");assertEquals(0,reads.get())}
    @Test fun backgroundDropsConsent(){val m=show();request();compose.runOnIdle{m.leaveForeground();m.confirm();m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};absent("before_copy_confirm");assertEquals(0,reads.get())}
    @Test fun duplicateConfirmDoesNotDuplicateRead(){val gate=CompletableDeferred<BeforeCopyResult>();resultRead={gate.await()};val m=show();request();compose.runOnIdle{m.confirm();m.confirm()};compose.waitUntil(10_000){reads.get()==1};gate.complete(BeforeCopyResult.Unavailable("fixture"));await("before_copy_unavailable");assertEquals(1,reads.get())}
    @Test fun lateReviewCannotSurviveForegroundChange(){val m=show();val gate=CompletableDeferred<BeforeCopyReview?>();reviewRead={withContext(NonCancellable){gate.await()}};click("before_copy_refresh");compose.runOnIdle{m.leaveForeground();reviewRead={null};m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};gate.complete(review);compose.waitForIdle();absent("before_copy_read")}
    @Test fun lateNetworkProofCannotSurviveBackground(){val gate=CompletableDeferred<BeforeCopyResult>();resultRead={withContext(NonCancellable){gate.await()}};val m=show();confirm();compose.waitUntil(10_000){reads.get()==1};compose.runOnIdle{m.leaveForeground();m.enterForeground()};gate.complete(BeforeCopyResult.Observed(evidence()));compose.waitUntil(10_000){!m.state.value.loading};absent("before_copy_observed")}
    @Test fun foreignTargetProofCannotShowSuccess(){resultRead={BeforeCopyResult.Observed(evidence().copy(scope=scope.copy(serverId=ServerId("other"))))};show();confirm();await("before_copy_unavailable");absent("before_copy_observed")}
    @Test fun staleProofCannotShowSuccess(){resultRead={BeforeCopyResult.Observed(evidence().copy(observedAt=review.reviewedAt.minusSeconds(1)))};show();confirm();await("before_copy_unavailable");absent("before_copy_observed")}
    @Test fun activeServiceEvidenceDoesNotBecomeStopped(){resultRead={BeforeCopyResult.Observed(evidence().copy(service=BeforeCopyService.ACTIVE,current=BeforeCopyCurrent.UNAVAILABLE))};show();confirm();await("before_copy_observed");compose.onNodeWithTag("before_copy_findings").assertTextContains("работает",substring=true)}
    @Test fun limitsSayNoWriteAndBarrierRemains(){show();compose.onNodeWithTag("before_copy_limits").assertTextContains("Барьер неопределённого исхода сохраняется",substring=true)}
    @Test fun backDoesNotReadOrRestore(){show();click("before_copy_back");assertEquals(1,backs.get());assertEquals(0,reads.get())}
}
