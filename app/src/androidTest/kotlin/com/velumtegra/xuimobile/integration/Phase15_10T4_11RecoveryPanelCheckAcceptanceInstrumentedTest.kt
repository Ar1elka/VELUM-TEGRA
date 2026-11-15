package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.lifecycle.SavedStateHandle
import com.velumtegra.xuimobile.management.*
import com.velumtegra.xuimobile.ui.theme.VelumTegraTheme
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** Memory-only native UI. No credentials, certificate reads, SSH, network or real user stores. */
class Phase15_10T4_11RecoveryPanelCheckAcceptanceInstrumentedTest {
    @get:Rule val compose=createComposeRule()
    private val checks=AtomicInteger();private val reviews=AtomicInteger();private val discarded=AtomicInteger();private val inventories=AtomicInteger();private val backs=AtomicInteger()
    private var rows=listOf(RecoveryPanelChoice("panel","fixture-admin","Прямой HTTPS"))
    private var sourceReview=RecoveryPanelReview("token","source-start","panel","fixture-admin","Прямой HTTPS","https://fixture.invalid:2053/panel/",null,Instant.now())
    private var choicesRead:suspend()->List<RecoveryPanelChoice> = { rows }
    private var reviewRead:suspend()->RecoveryPanelReview?={sourceReview}
    private var checkRead:suspend()->RecoveryPanelCheckResult={RecoveryPanelCheckResult.Verified("panel",Instant.now())}
    private val port=object:RecoveryPanelCheckPort{
        override suspend fun choices(server:String,installation:String,ssh:String,operation:String):List<RecoveryPanelChoice>{assertEquals("source-start",operation);return choicesRead()}
        override suspend fun review(server:String,installation:String,ssh:String,operation:String,panel:String):RecoveryPanelReview?{reviews.incrementAndGet();return reviewRead()}
        override suspend fun check(review:RecoveryPanelReview):RecoveryPanelCheckResult{checks.incrementAndGet();return checkRead()}
        override fun discard(review:RecoveryPanelReview){discarded.incrementAndGet()}
    }
    private fun show(saved:SavedStateHandle=SavedStateHandle()):ManagementRecoveryPanelCheckViewModel{
        val m=ManagementRecoveryPanelCheckViewModel(saved,"server","installation","ssh","source-start",port)
        compose.setContent{VelumTegraTheme{ManagementRecoveryPanelCheckScreen(m,{backs.incrementAndGet()},{inventories.incrementAndGet()})}}
        compose.waitUntil(10_000){!m.state.value.loading};return m
    }
    private fun click(tag:String)=compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun await(tag:String)=compose.waitUntil(10_000){compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()}
    private fun absent(tag:String)=assertEquals(0,compose.onAllNodesWithTag(tag).fetchSemanticsNodes().size)
    private fun select(){click("recovery_panel_choice_panel");await("recovery_panel_confirm")}
    private fun confirm(){select();compose.onNodeWithTag("recovery_panel_ack").performClick();compose.onNodeWithTag("recovery_panel_confirm").performClick()}
    @Test fun openingOnlyListsLocalChoices(){show();assertEquals(0,reviews.get());assertEquals(0,checks.get())}
    @Test fun refreshNeverAuthenticates(){show();click("recovery_panel_refresh");assertEquals(0,checks.get())}
    @Test fun selectingAccessOnlyOpensReview(){show();select();assertEquals(1,reviews.get());assertEquals(0,checks.get())}
    @Test fun uncheckedAcknowledgementBlocksConfirmation(){show();select();compose.onNodeWithTag("recovery_panel_confirm").assertIsNotEnabled();assertEquals(0,checks.get())}
    @Test fun reviewShowsExactLoginAndHttpsRoute(){show();select();compose.onNodeWithTag("recovery_panel_username").assertTextContains("fixture-admin",substring=true);compose.onNodeWithTag("recovery_panel_route").assertTextContains("fixture.invalid:2053/panel/",substring=true)}
    @Test fun privateReviewShowsAcceptedCertificate(){sourceReview=sourceReview.copy(route="Приватный HTTPS через SSH",certificate="A".repeat(64));show();select();compose.onNodeWithTag("recovery_panel_pin").assertTextContains("A".repeat(64),substring=true);assertEquals(0,checks.get())}
    @Test fun dismissDoesNotSendCredentials(){show();select();compose.onNodeWithTag("recovery_panel_dismiss").performClick();assertEquals(0,checks.get());assertTrue(discarded.get()>0)}
    @Test fun explicitCheckShowsMomentaryApiReceipt(){show();confirm();await("recovery_panel_verified");assertEquals(1,checks.get())}
    @Test fun authFailureCannotShowSuccess(){checkRead={RecoveryPanelCheckResult.Unverified("Авторизация отклонена")};show();confirm();await("recovery_panel_unverified");absent("recovery_panel_verified")}
    @Test fun uncertainOutcomeDoesNotReplay(){checkRead={RecoveryPanelCheckResult.Unverified("Итог неизвестен; повтора нет")};show();confirm();await("recovery_panel_unverified");click("recovery_panel_refresh");assertEquals(1,checks.get());absent("recovery_panel_verified")}
    @Test fun noExactAccessHasNoCredentialAction(){rows=emptyList();show();absent("recovery_panel_choice_panel");assertEquals(0,checks.get())}
    @Test fun unavailablePinOrSourceCannotOpenConsent(){reviewRead={null};show();click("recovery_panel_choice_panel");await("recovery_panel_notice");absent("recovery_panel_confirm");assertEquals(0,checks.get())}
    @Test fun foreignSourceReviewIsRejected(){sourceReview=sourceReview.copy(operationId="other");show();click("recovery_panel_choice_panel");await("recovery_panel_notice");absent("recovery_panel_confirm")}
    @Test fun foreignAccessReviewIsRejected(){sourceReview=sourceReview.copy(accessId="other");show();click("recovery_panel_choice_panel");await("recovery_panel_notice");absent("recovery_panel_confirm")}
    @Test fun savedAttemptNeverRestoresConsentOrSuccess(){show(SavedStateHandle(mapOf("rpc_attempted" to true)));absent("recovery_panel_confirm");absent("recovery_panel_verified");assertEquals(0,checks.get())}
    @Test fun leavingForegroundDropsConsent(){val m=show();select();compose.runOnIdle{m.leaveForeground();m.confirm();m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};absent("recovery_panel_confirm");assertEquals(0,checks.get())}
    @Test fun duplicateConfirmCannotSendTwice(){val gate=CompletableDeferred<RecoveryPanelCheckResult>();checkRead={gate.await()};val m=show();select();compose.runOnIdle{m.confirm();m.confirm()};compose.waitUntil(10_000){checks.get()==1};gate.complete(RecoveryPanelCheckResult.Unverified("fixture"));await("recovery_panel_unverified");assertEquals(1,checks.get())}
    @Test fun lateReviewCannotReplaceNewForegroundSource(){val m=show();val gate=CompletableDeferred<RecoveryPanelReview?>();reviewRead={withContext(NonCancellable){gate.await()}};click("recovery_panel_choice_panel");compose.runOnIdle{m.leaveForeground();rows=emptyList();m.enterForeground()};compose.waitUntil(10_000){!m.state.value.loading};gate.complete(sourceReview);compose.waitForIdle();absent("recovery_panel_confirm");assertEquals(0,checks.get())}
    @Test fun lateNetworkSuccessCannotSurviveBackground(){val gate=CompletableDeferred<RecoveryPanelCheckResult>();checkRead={withContext(NonCancellable){gate.await()}};val m=show();confirm();compose.waitUntil(10_000){checks.get()==1};compose.runOnIdle{m.leaveForeground();m.enterForeground()};gate.complete(RecoveryPanelCheckResult.Verified("panel",Instant.now()));compose.waitUntil(10_000){!m.state.value.loading};absent("recovery_panel_verified")}
    @Test fun foreignNetworkReceiptCannotClaimAccess(){checkRead={RecoveryPanelCheckResult.Verified("other",Instant.now())};show();confirm();await("recovery_panel_unverified");absent("recovery_panel_verified")}
    @Test fun staleNetworkReceiptCannotClaimAccess(){checkRead={RecoveryPanelCheckResult.Verified("panel",sourceReview.reviewedAt.minusSeconds(1))};show();confirm();await("recovery_panel_unverified");absent("recovery_panel_verified")}
    @Test fun scopeDoesNotClaimVpnOrRollback(){show();compose.onNodeWithTag("recovery_panel_limits").assertTextContains("не доказывает работу VPN",substring=true)}
    @Test fun inventoryNavigationDoesNotAuthenticate(){show();click("recovery_panel_inventory");assertEquals(1,inventories.get());assertEquals(0,checks.get())}
    @Test fun backNavigationDoesNotAuthenticate(){show();click("recovery_panel_back");assertEquals(1,backs.get());assertEquals(0,checks.get())}
}
