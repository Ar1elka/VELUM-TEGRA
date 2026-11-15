package com.velumtegra.xuimobile.management

import androidx.activity.ComponentActivity
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.lifecycle.SavedStateHandle
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real [ManagementRestoreCheckScreen] + real [ManagementRestoreCheckViewModel] + the production
 * [JournalRestoreCheckStatusPort] over a fake journal / fake verified-results inventory / fake local review.
 * A "reopen" here means the composable leaves and re-enters composition with a NEW ViewModel and empty
 * SavedStateHandle; it is NOT an Activity restart or a real navigation. No SSH, network, secrets or database.
 */
@RunWith(AndroidJUnit4::class)
class RestoreCheckVerifiedResultInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val at = Instant.parse("2026-10-18T06:00:00Z")
    private val server = ServerId("server")
    private val access = ServerAccess(ServerAccessId("ssh"), server, SshEndpoint("fixture.invalid", 22), "root",
        SshAuthRef.Password(SecretId("fixture-ref")), HostKeyFingerprint("SHA256:fixture"))
    private val installation = XuiInstallation(XuiInstallationId("install"), server, InstallationOwnership.ADOPTED,
        InstallationIdentity("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", null),
        InstallationBaseline("x-ui.service", "/usr/local/x-ui/x-ui", "/usr/local/x-ui", "/etc/x-ui/x-ui.db", 2053, "/panel/", null, at.minusSeconds(60)))
    private val review = ManagementRestartReview("VPS", installation, access)
    private val target = OperationTarget.InstallationTarget(server, access.id, installation.id)

    private val parent: VersionedOperationSnapshot = run {
        val b = InstallationBackupBindingPolicy.bind(OperationId("archive"), installation, access, "3.10.0", UpdateServerArchitecture.AMD64)
        VersionedOperationSnapshot(OperationSnapshot(OperationId("archive"), OperationType.INSTALLATION_BACKUP, target, OperationStatus.SUCCEEDED,
            OperationCheckpoint(b.phaseName(InstallationBackupPhase.VERIFIED), CheckpointSemantics.TERMINAL, at), at, at), OperationRevision(2))
    }
    private val verified: VersionedOperationSnapshot = run {
        val binding = RestoreCheckBindingPolicy.bind(OperationId("good"), installation, access, parent, "b".repeat(64), "c".repeat(64), "d".repeat(64), 4096, 3)
        val t = at.plusSeconds(60)
        VersionedOperationSnapshot(OperationSnapshot(OperationId("good"), OperationType.INSTALLATION_RESTORE_CHECK, target, OperationStatus.SUCCEEDED,
            OperationCheckpoint(binding.phaseName(RestoreCheckPhase.VERIFIED), CheckpointSemantics.TERMINAL, t), t, t), OperationRevision(3))
    }

    /** Read-only journal: any write fails the test loudly. */
    private class Journal(val rows: Map<String, VersionedOperationSnapshot>) : OperationJournal {
        override suspend fun create(initial: OperationSnapshot) = throw AssertionError("write")
        override suspend fun get(operationId: OperationId) = rows[operationId.value]?.let { OperationJournalResult.Success(it) } ?: OperationJournalResult.NotFound
        override suspend fun listNonTerminal() = OperationJournalResult.Success(emptyList<VersionedOperationSnapshot>())
        override suspend fun advance(operationId: OperationId, expectedRevision: OperationRevision, next: OperationSnapshot) = throw AssertionError("write")
        override suspend fun history(operationId: OperationId) = throw AssertionError("history")
    }

    /** Records every call; none is expected before an explicit confirmation. */
    private val actionCalls = mutableListOf<String>()
    private val actions = object : RestoreCheckActionPort {
        override suspend fun inspectConfirmed(review: ManagementRestartReview, source: String): RestoreCheckStart { actionCalls += "inspect"; return RestoreCheckStart.Blocked("fixture") }
        override suspend fun inspectCurrentConfirmed(review: ManagementRestartReview, operation: String): String? { actionCalls += "inspectCurrent"; return null }
        override suspend fun restoreConfirmed(review: ManagementRestartReview, operation: String, reviewedSource: RestoreCheckBinding): String? { actionCalls += "restore"; return null }
        override suspend fun checkConfirmed(review: ManagementRestartReview, operation: String): String? { actionCalls += "check"; return null }
        override suspend fun cancelPending(review: ManagementRestartReview, operation: String): String? { actionCalls += "cancel"; return null }
    }

    private val compared = mutableListOf<String>()
    private var inventoryReads = 0

    private fun statuses(withVerifiedResult: Boolean) = JournalRestoreCheckStatusPort(
        Journal(if (withVerifiedResult) mapOf("archive" to parent, "good" to verified) else mapOf("archive" to parent)),
        { _, _, _ -> ManagementRestartLocalReview.Ready(review) }, RestoreCheckResultRegistry(),
        verified = RestoreCheckResultInventory { _, _, _, _ ->
            inventoryReads++
            OperationJournalResult.Success(if (withVerifiedResult) listOf(verified) else emptyList())
        },
    )

    private fun host(withVerifiedResult: Boolean, shown: MutableState<Boolean>) = compose.setContent {
        if (shown.value) {
            val vm = remember {
                ManagementRestoreCheckViewModel(SavedStateHandle(), "server", "install", "ssh", "archive",
                    { _, _, _ -> ManagementRestartLocalReview.Ready(review) }, statuses(withVerifiedResult))
            }
            ManagementRestoreCheckScreen(vm, actions, onBack = {}, onCompare = { compared += it })
        }
    }

    private fun AndroidComposeTestRule<*, *>.awaitTag(tag: String) =
        waitUntil(10_000) { onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }
    private fun AndroidComposeTestRule<*, *>.count(tag: String) = onAllNodesWithTag(tag).fetchSemanticsNodes().size

    @Test fun verifiedResultFromJournalReturnsCompareButtonAfterReopenWithoutAnyActionCall() {
        val shown = mutableStateOf(true)
        host(true, shown)
        compose.awaitTag("restore_check_compare")
        compose.onNodeWithTag("restore_check_status").assertTextContains("завершённую проверку", substring = true)
        compose.runOnIdle { assertEquals(emptyList<String>(), actionCalls) }

        // The compare button only reports the exact verified check id to the callback.
        compose.onNodeWithTag("restore_check_compare").performScrollTo().performClick()
        compose.runOnIdle { assertEquals(listOf("good"), compared) }

        // Opening the confirmation dialog for the source check sends nothing; dismissing keeps it that way.
        compose.onNodeWithTag("restore_check_source").performScrollTo().performClick()
        compose.awaitTag("restore_check_confirm")
        compose.onNodeWithTag("restore_check_review_scope").assertTextContains("Разрешить чтение выбранной", substring = true)
        compose.runOnIdle { assertEquals(emptyList<String>(), actionCalls) }
        compose.onNodeWithTag("restore_check_dismiss").performClick()
        compose.waitUntil(10_000) { compose.count("restore_check_confirm") == 0 }
        compose.runOnIdle { assertEquals(emptyList<String>(), actionCalls) }

        // Leave and re-enter composition: a new ViewModel with an empty SavedStateHandle finds the same result.
        val readsBefore = inventoryReads
        compose.runOnIdle { shown.value = false }
        compose.waitUntil(10_000) { compose.count("restore_check_root") == 0 }
        compose.runOnIdle { shown.value = true }
        compose.awaitTag("restore_check_compare")
        compose.onNodeWithTag("restore_check_status").assertTextContains("завершённую проверку", substring = true)
        compose.runOnIdle {
            assertEquals(emptyList<String>(), actionCalls)
            assertEquals(listOf("good"), compared) // reopening never triggers compare by itself
            org.junit.Assert.assertTrue(inventoryReads > readsBefore)
        }
    }

    @Test fun noVerifiedResultShowsNoCompareButtonAndCallsNothing() {
        host(false, mutableStateOf(true))
        compose.awaitTag("restore_check_source") // review + source loaded
        assertEquals(0, compose.count("restore_check_compare"))
        assertEquals(0, compose.count("restore_check_status"))
        compose.runOnIdle {
            assertEquals(emptyList<String>(), actionCalls)
            assertEquals(emptyList<String>(), compared)
        }
    }
}
