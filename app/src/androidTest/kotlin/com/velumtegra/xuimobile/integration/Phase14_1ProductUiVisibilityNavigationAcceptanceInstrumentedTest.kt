package com.velumtegra.xuimobile.integration

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.semantics.SemanticsNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.velumtegra.xuimobile.MainActivity
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase14_1ProductUiVisibilityNavigationAcceptanceInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun realSectionsAreVisibleDistinctAndBackSafe() {
        compose.onNodeWithTag("home_root").fetchSemanticsNode()
        compose.onNodeWithTag("dashboard_navigation").fetchSemanticsNode()

        compose.onNodeWithTag("nav_servers").performClick()
        compose.onNodeWithTag("inventory_servers").fetchSemanticsNode()
        compose.onNodeWithText("Мои серверы").fetchSemanticsNode()
        compose.onNodeWithTag("inventory_refresh").performClick()
        compose.runOnIdle { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithTag("home_root").fetchSemanticsNode()

        compose.onNodeWithTag("nav_management").performClick()
        compose.onNodeWithTag("inventory_management").fetchSemanticsNode()
        compose.onNodeWithText("Управление X-UI").fetchSemanticsNode()
        compose.onNodeWithTag("nav_web_panel").performClick()
        compose.onNodeWithTag("inventory_web_panel").fetchSemanticsNode()
        compose.onNodeWithText("Веб-панели").fetchSemanticsNode()
        compose.onNodeWithTag("nav_home").performClick()
        compose.onNodeWithTag("home_root").fetchSemanticsNode()

        // Home is vertically scrollable: the button can be below the viewport.
        // Scroll and assert actual visibility before injecting the touch gesture.
        compose.onNodeWithTag("home_reality_scanner").performScrollTo().assertIsDisplayed().performClick()
        // The scanner is a subcomposed responsive screen. Wait for the actual
        // scanner subtree instead of assuming that the next semantics frame is ready.
        // Keep the original scanner-root assertion; do not mask a broken route.
        try {
            compose.waitUntil(timeoutMillis = 10_000) {
                compose.onAllNodesWithTag(
                    "reality_scanner_root",
                    useUnmergedTree = true,
                ).fetchSemanticsNodes().isNotEmpty()
            }
        } catch (cause: Throwable) {
            // The prior FIX02 emitted only SemanticsNode@<identity>, which cannot
            // distinguish failed navigation from a missing scanner testTag.
            // Capture bounded, readable evidence WITHOUT changing the assertion.
            throw AssertionError(
                "Reality Scanner did not appear after home_reality_scanner click.\n" +
                    scannerNavigationEvidence(),
                cause,
            )
        }
        compose.onNodeWithTag("reality_scanner_root", useUnmergedTree = true).fetchSemanticsNode()
        compose.onNodeWithTag("reality_scanner_back", useUnmergedTree = true).fetchSemanticsNode()
        compose.runOnIdle { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithTag("home_root").fetchSemanticsNode()

        compose.onNodeWithTag("home_site_deployer_review").performScrollTo().assertIsDisplayed().performClick()
        compose.onNodeWithTag("site_deployer_review_root").fetchSemanticsNode()
        compose.runOnIdle { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithTag("home_root").fetchSemanticsNode()
    }

    private fun scannerNavigationEvidence(): String {
        val expectedTags = listOf(
            "home_root", "dashboard_navigation", "home_reality_scanner",
            "reality_scanner_root", "reality_scanner_back", "inventory_servers",
            "inventory_management", "inventory_web_panel", "site_deployer_review_root",
        )
        val counts = expectedTags.joinToString(", ") { tag ->
            val count = runCatching {
                compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().size
            }.getOrElse { -1 }
            "$tag=$count"
        }
        val tree = runCatching {
            val root = compose.onRoot(useUnmergedTree = true).fetchSemanticsNode()
            buildString {
                var nodes = 0
                fun visit(node: SemanticsNode, depth: Int) {
                    if (nodes >= 48 || depth > 6) return
                    nodes++
                    append("  ".repeat(depth))
                    append("node#").append(node.id).append(' ')
                    append(node.config.toString().replace('\n', ' ').take(180))
                    append('\n')
                    node.children.forEach { visit(it, depth + 1) }
                }
                visit(root, 0)
                if (nodes >= 48) append("... node listing capped at 48\n")
            }.take(3800)
        }.getOrElse { error ->
            "Unable to read unmerged semantics tree: ${error.javaClass.simpleName}: ${error.message}"
        }
        return "Active tag counts: $counts\nUnmerged semantics tree (bounded):\n$tree"
    }
}
