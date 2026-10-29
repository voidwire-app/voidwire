package app.voidwire.android

import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.voidwire_core.PcInfo

/** android-qa spec A: shots S9, S11, S12, S13 with their content checks (fake phone, debug-only seam). */
@RunWith(AndroidJUnit4::class)
class MoreShotsTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()
    private val pc = PcInfo("ab".repeat(32), "Workstation", false)

    @Before fun fresh() { resetAppPrefs(); Qa.osNight(true) }
    @After fun reset() { DebugSeams.fakePhone = null; ShareActivity.resetForTests(); resetAppPrefs() }

    /** S9: a 40-character phone name set through Settings; the main screen keeps the full name in content-desc. */
    @Test fun s9LongPhoneName() {
        val long = "Android Studio Tab S9 FE Plus 5G Ultra X" // 40 chars
        check(long.length == 40)
        DebugSeams.fakePhone = FakePhone(listOf(pc))
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, pc.name)
            compose.onNodeWithContentDescription("Settings").performClick()
            Qa.waitText(compose, "Name shown on your PCs")
            compose.onNode(hasSetTextAction()).performScrollTo().performTextReplacement(long)
            Espresso.closeSoftKeyboard()
            compose.onNodeWithText("Save").performScrollTo().performClick()
            compose.onNodeWithContentDescription("Back").performClick()
            Qa.waitText(compose, pc.name)
            compose.onNodeWithContentDescription(long, useUnmergedTree = true).assertExists()
            Qa.shot("S9-long-phone-name")
        }
    }

    /** S11: Settings with both opt-ins off shows the note; it goes once Keep recent sends is on. */
    @Test fun s11NothingStoredNote() {
        DebugSeams.fakePhone = FakePhone(listOf(pc))
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, pc.name)
            compose.onNodeWithContentDescription("Settings").performClick()
            Qa.waitText(compose, "NOTHING ABOUT YOUR SENDS IS STORED")
            Qa.shot("S11-settings-optins-off")
            compose.onAllNodes(isToggleable())[0].performClick() // Keep recent sends
            compose.waitUntil(10_000) { !Qa.has(compose, "NOTHING ABOUT YOUR SENDS IS STORED") }
            Qa.shot("S11b-settings-recent-on")
            assertTrue(RecentSends.enabled(Qa.ctx))
        }
    }

    /** S12: a share on a fresh install (no PC paired). */
    @Test fun s12ShareWithoutPc() {
        ShareActivity.backendFactory = { FakeShare(emptyList()) }
        ActivityScenario.launch<ShareActivity>(shareIntent("https://example.com/s12")).use {
            Qa.waitText(compose, "No PC paired yet")
            assertTrue(Qa.has(compose, "Pair with a PC"))
            Qa.shot("S12-share-no-pc")
        }
    }

    /** S13: a share of plain text with no link. */
    @Test fun s13ShareTextWithoutLink() {
        ShareActivity.backendFactory = { FakeShare(listOf(ShareTarget(pc.id, pc.name))) }
        ActivityScenario.launch<ShareActivity>(shareIntent("just some words, no link here")).use {
            Qa.waitText(compose, "NOTHING WAS SENT OR SAVED")
            assertFalse(Qa.has(compose, "Send to ${pc.name}"))
            Qa.shot("S13-share-no-link")
        }
    }

    /** F2: failed Forget keeps the card, shows "Couldn't forget <PC>. Try again." with Retry, and Retry succeeds. */
    @Test fun f2ForgetRetry() {
        DebugSeams.fakePhone = FakePhone(listOf(pc)).apply { failNextForget = true }
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, pc.name)
            compose.onAllNodesWithText("Forget")[0].performClick()
            Qa.waitText(compose, "Forget ${pc.name}?")
            compose.onNode(
                hasText("Forget") and androidx.compose.ui.test.hasClickAction() and
                    androidx.compose.ui.test.hasAnyAncestor(androidx.compose.ui.test.isDialog()),
            ).performClick()
            // Fail at the step that broke (QA 40833274587 only saw the end state).
            Qa.shotOnTimeout { compose.waitUntil(10_000) { !Qa.has(compose, "Forget ${pc.name}?") } }
            Qa.waitText(compose, "Couldn't forget ${pc.name}. Try again.")
            assertTrue(Qa.has(compose, pc.name))
            compose.onNodeWithText("Retry").performClick()
            Qa.waitText(compose, "Forgot ${pc.name}.")
        }
    }
}

/**
 * S10 (spec A #5): the scanner with the camera permission denied. android-qa.sh
 * revokes CAMERA with the user-fixed flag first (no system dialog) and runs
 * this class on its own, before any class that grants the camera.
 */
@RunWith(AndroidJUnit4::class)
class ScannerNoCameraTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()

    @After fun reset() { DebugSeams.fakePhone = null }

    @Test fun s10PasteFieldWithoutCamera() {
        DebugSeams.fakePhone = FakePhone(emptyList())
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, "None yet")
            compose.onAllNodesWithText("Pair with a PC").let { it[it.fetchSemanticsNodes().size - 1] }.performClick()
            // Camera not granted: the system permission dialog (not Compose) takes
            // focus, which gave "No compose hierarchies" (QA 8ee9a16). Deny it via UiAutomator.
            denyCameraDialogIfShown()
            Qa.waitText(compose, "Starts with voidwire:pair?")
            compose.onNode(hasText("Use link")).assertExists()
            compose.onNode(hasText("Use link")).assertIsNotEnabled()
            assertTrue("'Pair a phone…' missing from the pair instructions", Qa.has(compose, "Pair a phone…"))
            Qa.shot("S10-scanner-no-camera")
        }
    }
}

/** Taps "Don't allow" on the runtime permission dialog if it appears within [ms]. */
internal fun denyCameraDialogIfShown(ms: Long = 8_000) {
    val dev = androidx.test.uiautomator.UiDevice.getInstance(androidx.test.platform.app.InstrumentationRegistry.getInstrumentation())
    val deny = androidx.test.uiautomator.By.res(java.util.regex.Pattern.compile(".*permission_deny(_and_dont_ask_again)?_button"))
    dev.wait(androidx.test.uiautomator.Until.findObject(deny), ms)?.click()
    dev.waitForIdle()
}
