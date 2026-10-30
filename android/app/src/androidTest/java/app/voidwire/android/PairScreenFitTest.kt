package app.voidwire.android

import android.content.Context
import androidx.compose.ui.test.isRoot
import androidx.compose.ui.test.junit4.ComposeTestRule
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.voidwire_core.PcInfo

/**
 * v0.7.1 hardware test: on the "Pair a device" screen, "Show a code" and
 * "Type a code" sat below the camera, off the screen. They must be fully on
 * screen without scrolling on a 360x640 dp phone, at normal and large text.
 * Shots: pair-screen-360x640-font1.0, pair-screen-360x640-font1.3,
 * pair-screen-360x640-font2.0.
 */
@RunWith(AndroidJUnit4::class)
class PairScreenFitTest {
    @get:Rule val compose: ComposeTestRule = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()
    private val ctx: Context get() = ApplicationProvider.getApplicationContext()

    @After fun reset() {
        DebugSeams.fakePhone = null
        Qa.shell("wm size reset")
        Qa.shell("wm density reset")
        Qa.shell("settings put system font_scale 1.0")
        Thread.sleep(1_500)
    }

    private fun check(fontScale: String) {
        // 720x1280 px at 320 dpi = 360x640 dp.
        Qa.shell("wm size 720x1280")
        Qa.shell("wm density 320")
        Qa.shell("settings put system font_scale $fontScale")
        Thread.sleep(2_000)
        DebugSeams.fakePhone = FakePhone(listOf(PcInfo("ab".repeat(32), "QA PC", false)))
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, "Pair a device")
            compose.waitForIdle()
            // At large text the home button is below the fold: scroll to it first.
            compose.onAllNodesWithText("Pair a device").let { it[it.fetchSemanticsNodes().size - 1] }.performScrollTo().performClick()
            Qa.waitText(compose, "Show a code")
            compose.waitForIdle()
            Qa.shot("pair-screen-360x640-font$fontScale")
            val root = compose.onAllNodes(isRoot()).fetchSemanticsNodes().maxBy { it.boundsInWindow.height }.boundsInWindow
            for (label in listOf("Show a code", "Type a code")) {
                val b = compose.onAllNodesWithText(label, useUnmergedTree = true).fetchSemanticsNodes().single().boundsInWindow
                assertTrue(
                    "font $fontScale: \"$label\" must be on screen without scrolling: $b in $root",
                    b.top >= root.top && b.bottom <= root.bottom && b.height > 0f,
                )
            }
        }
    }

    @Test fun buttonsOnScreenAtNormalText() = check("1.0")
    @Test fun buttonsOnScreenAtLargeText() = check("1.3")
    @Test fun buttonsOnScreenAtLargestText() = check("2.0")
}
