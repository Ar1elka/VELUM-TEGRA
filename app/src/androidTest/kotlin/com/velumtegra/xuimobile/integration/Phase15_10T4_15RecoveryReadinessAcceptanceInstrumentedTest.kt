package com.velumtegra.xuimobile.integration
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
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
/** Memory-only UI. No actual file/SQLite/key reads, service commands, downloads or SSH/VPS. */
class Phase15_10T4_15RecoveryReadinessAcceptanceInstrumentedTest {
    @get:Rule val compose=createComposeRule()
    private val reads=AtomicInteger();private val reviews=AtomicInteger();private val discarded=AtomicInteger()
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val binding=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private val scope=ManagementScope(OperationId("compare"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private var review=RecoveryReadinessReview("token",scope,4,binding,"Fixture VPS","operator@fixture:22",Instant.now())
    private fun evidence():RecoveryReadinessEvidence{
        val groups=RecoveryFileGroup.values().associateWith{when(it){RecoveryFileGroup.RUNTIME->RecoveryGroupDifference(2,2,1,0,0);RecoveryFileGroup.SERVICE->RecoveryGroupDifference(1,1,0,0,0);else->RecoveryGroupDifference(0,0,0,0,0)}}
        return RecoveryReadinessEvidence(scope,binding,4,"3.10.0",UpdateServerArchitecture.AMD64,"1".repeat(64),"1".repeat(64),groups,3,3,1,0,0,1024,1024,true,true,RecoveryJournalMode.WAL,RecoveryWalPresence.PRESENT,RecoveryQuiescence.REQUIRED,"2".repeat(64),Instant.now())
    }
    private var reviewRead:suspend()->RecoveryReadinessReview? = {review}
    private var resultRead:suspend()->RecoveryReadinessResult = {RecoveryReadinessResult.Observed(evidence())}
    private val port=object:RecoveryReadinessPort{
        override suspend fun review(scope:ManagementScope):RecoveryReadinessReview?{reviews.incrementAndGet();assertEquals(this@Phase15_10T4_15RecoveryReadinessAcceptanceInstrumentedTest.scope,scope);return reviewRead()}
        override suspend fun read(review:RecoveryReadinessReview):RecoveryReadinessResult{reads.incrementAndGet();return resultRead()}
        override fun discard(review:RecoveryReadinessReview){discarded.incrementAndGet()}
    }
    private fun show(saved:SavedStateHandle=SavedStateHandle()):ManagementRecoveryReadinessViewModel{
        val m=ManagementRecoveryReadinessViewModel(saved,scope,port)
        compose.setContent{VelumTegraTheme{Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())){ManagementRecoveryReadinessSection(m)}}}
        compose.waitUntil(10_000){!m.state.value.loading};return m
    }
    private fun click(tag:String)=compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag:String)=compose.waitUntil(10_000){compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()}
    private fun absent(tag:String)=assertEquals(0,compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    private fun request(){click("recovery_readiness_read");await("recovery_readiness_confirm")}
    private fun confirm(){request();compose.onNodeWithTag("recovery_readiness_ack").performClick();compose.onNodeWithTag("recovery_readiness_confirm").performClick()}
    @Test fun openingOnlyReviewsLocalSource(){show();assertEquals(0,reads.get());assertEquals(1,reviews.get())}
    @Test fun refreshNeverConnects(){show();click("recovery_readiness_refresh");assertEquals(0,reads.get())}
    @Test fun dialogDoesNotReadRemote(){show();request();assertEquals(0,reads.get());compose.onNodeWithTag("recovery_readiness_review_hash").assertTextContains("b".repeat(64),substring=true)}
    @Test fun uncheckedConsentBlocks(){show();request();compose.onNodeWithTag("recovery_readiness_confirm").assertIsNotEnabled();assertEquals(0,reads.get())}
    @Test fun dismissNeverReads(){show();request();compose.onNodeWithTag("recovery_readiness_dismiss").performClick();absent("recovery_readiness_confirm");assertEquals(0,reads.get())}
    @Test fun exactReadShowsGroupedCounts(){show();confirm();await("recovery_readiness_observed");compose.onNodeWithTag("recovery_readiness_group_RUNTIME").assertTextContains("изменено 1",substring=true);assertEquals(1,reads.get())}
    @Test fun unavailableCannotClaimReadiness(){resultRead={RecoveryReadinessResult.Unavailable("Условия не подтверждены")};show();confirm();await("recovery_readiness_unavailable");absent("recovery_readiness_observed")}
    @Test fun missingLocalSourceHidesRead(){reviewRead={null};show();absent("recovery_readiness_read");assertEquals(0,reads.get())}
    @Test fun foreignScopeReviewCannotRead(){review=review.copy(scope=scope.copy(operationId=OperationId("foreign")));show();absent("recovery_readiness_read");assertTrue(discarded.get()>0)}
    @Test fun sshProfileIsExact(){show();compose.onNodeWithTag("recovery_readiness_ssh").assertTextContains("operator@fixture:22",substring=true)}
    @Test fun savedAttemptRestoresNoConsentOrEvidence(){show(SavedStateHandle(mapOf("recovery_read_attempted" to true)));absent("recovery_readiness_confirm");absent("recovery_readiness_observed");assertEquals(0,reads.get())}
    @Test fun backgroundDropsReview(){val m=show();request();compose.runOnIdle{m.leaveForeground();m.confirm();m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};absent("recovery_readiness_confirm");assertEquals(0,reads.get())}
    @Test fun duplicateConfirmDoesNotDuplicateRead(){val gate=CompletableDeferred<RecoveryReadinessResult>();resultRead={gate.await()};val m=show();request();compose.runOnIdle{m.confirm();m.confirm()};compose.waitUntil(10_000){reads.get()==1};gate.complete(RecoveryReadinessResult.Unavailable("fixture"));await("recovery_readiness_unavailable");assertEquals(1,reads.get())}
    @Test fun lateLocalReviewCannotSurviveForegroundChange(){val m=show();val gate=CompletableDeferred<RecoveryReadinessReview?>();reviewRead={withContext(NonCancellable){gate.await()}};click("recovery_readiness_refresh");compose.runOnIdle{m.leaveForeground();reviewRead={null};m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};gate.complete(review);compose.waitForIdle();absent("recovery_readiness_read")}
    @Test fun lateRemoteProofCannotSurviveBackground(){val gate=CompletableDeferred<RecoveryReadinessResult>();resultRead={withContext(NonCancellable){gate.await()}};val m=show();confirm();compose.waitUntil(10_000){reads.get()==1};compose.runOnIdle{m.leaveForeground();m.enterForeground()};gate.complete(RecoveryReadinessResult.Observed(evidence()));compose.waitUntil(10_000){!m.state.value.loading};absent("recovery_readiness_observed")}
    @Test fun foreignProofCannotPublish(){resultRead={RecoveryReadinessResult.Observed(evidence().copy(scope=scope.copy(serverId=ServerId("foreign"))))};show();confirm();await("recovery_readiness_unavailable");absent("recovery_readiness_observed")}
    @Test fun staleProofCannotPublish(){resultRead={RecoveryReadinessResult.Observed(evidence().copy(observedAt=review.reviewedAt.minusSeconds(1)))};show();confirm();await("recovery_readiness_unavailable");absent("recovery_readiness_observed")}
    @Test fun sameVersionAndSchemaStillShowMigrationAndWriterBlockers(){show();confirm();await("recovery_readiness_observed");compose.onNodeWithTag("recovery_readiness_block_MIGRATION_UNVERIFIED").assertExists();compose.onNodeWithTag("recovery_readiness_block_FILE_WRITE_PROTOCOL_UNVERIFIED").assertExists()}
    @Test fun liveWalAndServiceRequireSeparateActions(){show();confirm();await("recovery_readiness_observed");compose.onNodeWithTag("recovery_readiness_wal").assertTextContains("WAL: есть данные",substring=true);compose.onNodeWithTag("recovery_readiness_block_SERVICE_RUNNING").assertExists()}
    @Test fun limitsPreserveNoWriteAndUncertainty(){show();compose.onNodeWithTag("recovery_readiness_limits").assertTextContains("не снимает барьер",substring=true);compose.onNodeWithTag("recovery_readiness_scope").assertTextContains("прокси, ACME",substring=true)}
}
