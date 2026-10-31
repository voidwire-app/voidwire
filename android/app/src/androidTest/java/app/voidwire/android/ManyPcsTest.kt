package app.voidwire.android

import android.content.Context
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasScrollAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.ComposeTestRule
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performScrollToNode
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.voidwire.android.ui.theme.ThemeMode
import org.junit.After
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.voidwire_core.PcInfo

/**
 * QA spec S1b (760bad2 FAIL item 2): 7 paired PCs (seeded through the
 * debug-only DebugSeams), the list scrolls, and the wire strip stays pinned
 * below it. Shots: s1b-many-top, s1b-many-scrolled.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class ManyPcsTest {
    @get:Rule val compose: ComposeTestRule = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()
    private val ctx: Context get() = ApplicationProvider.getApplicationContext()

    @After fun reset() { DebugSeams.fakePhone = null; ThemePref.set(ctx, ThemeMode.Default) }

    @Test fun s1bListScrolls() {
        Qa.osNight(true)
        ThemePref.set(ctx, ThemeMode.Dark)
        val pcs = (1..7).map { i -> PcInfo("%02x".format(i).repeat(32), "QA PC $i Primary Workstation Studio Upstairs") }
        DebugSeams.fakePhone = FakePhone(pcs)
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, pcs.first().name)
            Thread.sleep(1_000)
            Qa.shot("s1b-many-top")
            // F4 / designer blocker check: long card names (>= 30 chars) wrap to 2 lines, not 1 + ellipsis.
            val firstLines = Qa.lineCounts(compose, pcs.first().name)
            org.junit.Assert.assertTrue("long PC name should wrap to 2 lines, got $firstLines", firstLines.isNotEmpty() && firstLines.all { it == 2 })
            val h = ctx.resources.displayMetrics.heightPixels
            val last = pcs.last().name
            // The last card starts off screen (or under the strip): the list must scroll.
            val lastNodes = compose.onAllNodesWithText(last, useUnmergedTree = true).fetchSemanticsNodes()
            val stripTop = compose.onAllNodesWithText("THIS PHONE", useUnmergedTree = true).fetchSemanticsNodes().minOf { it.boundsInWindow.top }
            org.junit.Assert.assertTrue(
                "7 PCs fit without scrolling; S1b needs an overflowing list",
                lastNodes.isEmpty() || lastNodes.all { it.boundsInWindow.top >= stripTop || it.boundsInWindow.bottom > h },
            )
            compose.onAllNodes(hasScrollAction())[0].performScrollToNode(hasText(last))
            compose.waitForIdle()
            compose.onNodeWithText(last).assertIsDisplayed()
            Qa.shot("s1b-many-scrolled")
            // REVIEW-m11 #3: the strip is pinned to the bottom when the content is
            // short and scrolls with a long list, so with 7 PCs it sits below the
            // last card at the end of the scroll. (d446e01: the old check read the
            // strip while it was scrolled out of view; clipped bounds are 0.0.)
            compose.onAllNodes(hasScrollAction())[0].performScrollToNode(hasText("THIS PHONE"))
            compose.waitForIdle()
            Qa.shot("s1b-many-end")
            val strip = compose.onAllNodesWithText("THIS PHONE", useUnmergedTree = true).fetchSemanticsNodes()
                .maxBy { it.boundsInWindow.top }.boundsInWindow
            val lastBottom = compose.onAllNodesWithText(last, useUnmergedTree = true).fetchSemanticsNodes()
                .maxOf { it.boundsInWindow.bottom }
            org.junit.Assert.assertTrue("strip not visible at the end of the list ($strip)", strip.height > 0f && strip.bottom <= h + 4f) // 4 px: gesture-bar rounding (QA 8ee9a16, 2 px seen)
            org.junit.Assert.assertTrue("strip top ${strip.top} not >= 50% of $h at the end of the list", strip.top >= 0.5f * h)
            org.junit.Assert.assertTrue("last card ($lastBottom) overlaps the strip (${strip.top})", lastBottom <= strip.top + 1)
        }
    }
}
