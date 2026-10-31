package app.voidwire.android

import android.Manifest
import android.content.Context
import android.content.Intent
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasScrollAction
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.ComposeTestRule
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import app.voidwire.android.ui.theme.ThemeMode
import org.junit.After
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.voidwire_core.PcInfo

/**
 * Design sign-off screenshots for .github/workflows/android-qa.yml (KVM
 * emulator on a GitHub runner; never on the build box).
 *
 * No live PC: the main app gets a fake phone through the DEBUG-ONLY
 * [DebugSeams] (src/debug; the release variant is a constant null), and the
 * share sheet uses its existing [ShareActivity.backendFactory]. App prefs
 * (theme, recent sends, last PC) are seeded through the app's own objects.
 *
 * PNGs go to <external files>/vw-shots/ (the workflow pulls them with adb).
 * Not part of the normal connected run: the workflow runs DeviceSmokeTest via
 * Gradle and this class via `am instrument`, so the app isn't uninstalled
 * before the pull.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class ScreenshotFlowTest {
    @get:Rule val compose: ComposeTestRule = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()
    @get:Rule val camera: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.CAMERA)

    private val ctx: Context get() = ApplicationProvider.getApplicationContext()

    private val desk = PcInfo("ab".repeat(32), "Workstation", false)
    private val laptop = PcInfo("cd".repeat(32), "Work Laptop", false)

    @After fun reset() {
        DebugSeams.fakePhone = null
        ShareActivity.resetForTests()
        ThemePref.set(ctx, ThemeMode.Default)
    }

    private fun osNight(dark: Boolean) = Qa.osNight(dark)
    private fun shot(name: String) = Qa.shot(name)
    private fun waitText(text: String, timeoutMs: Long = 30_000) = Qa.waitText(compose, text, timeoutMs)

    private fun seedPrefs(theme: ThemeMode, history: Boolean) {
        ThemePref.set(ctx, theme)
        RecentSends.setEnabled(ctx, history)
        LastPc.setEnabled(ctx, history)
        if (history) {
            RecentSends.add(ctx, "github.com → ${desk.name}: opened 12 ms")
            RecentSends.add(ctx, "news.ycombinator.com → ${laptop.name}: opened 9 ms")
            LastPc.set(ctx, desk.id)
        }
    }

    // ---- flows ----
    @Test fun shotsDark() = flow(dark = true)

    @Test fun shotsLight() = flow(dark = false)

    /** System theme on a light OS, a fresh install, past the splash. */
    @Test fun mainEmptyLight() {
        osNight(false)
        seedPrefs(ThemeMode.Default, history = false)
        DebugSeams.fakePhone = FakePhone(emptyList())
        ActivityScenario.launch(MainActivity::class.java).use {
            waitText("None yet")
            Thread.sleep(3_000)
            shot("main-empty-light")
        }
        osNight(true)
    }

    private fun flow(dark: Boolean) {
        val th = if (dark) "dark" else "light"
        osNight(dark)
        seedPrefs(if (dark) ThemeMode.Dark else ThemeMode.Light, history = true)
        val phone = FakePhone(listOf(desk, laptop))
        DebugSeams.fakePhone = phone

        ActivityScenario.launch(MainActivity::class.java).use {
            // 1. main with paired PCs and HISTORY ON
            waitText(desk.name); waitText("History on")
            shot("main-history-on-$th")
            // c5fe0a7 #1: the wire strip is pinned to the bottom (spec A).
            val h = ctx.resources.displayMetrics.heightPixels
            for (t in listOf("THIS PHONE", "YOUR PC")) {
                val bottom = compose.onAllNodesWithText(t, useUnmergedTree = true).fetchSemanticsNodes().maxOf { it.boundsInWindow.bottom }
                org.junit.Assert.assertTrue("$t bottom $bottom < 85% of $h", bottom >= 0.85f * h)
            }

            // 2. Settings: recent sends ON with the red outlined Clear; Appearance
            compose.onNodeWithContentDescription("Settings").performClick()
            waitText("Keep recent sends")
            compose.onNodeWithText("Clear").performScrollTo()
            shot("settings-recents-clear-$th")
            compose.onNodeWithText("Theme").performScrollTo()
            shot("settings-appearance-$th")
            Espresso.pressBack()

            // 3. scanner + the 6-digit code to type on the other device
            // (a v=2 link pasted, fake pairing)
            pairVia(shotScanAs = "scan-qr-$th")
            waitText("Type this on QA device", 60_000)
            shot("pair-code-$th")
            Espresso.pressBack() // cancels the fake pairing, back to Home

            // 4. Forget snackbar
            waitText(laptop.name)
            compose.onAllNodesWithText("Forget")[1].performClick() // second card: Work Laptop
            waitText("Forget ${laptop.name}?")
            compose.onNode(hasText("Forget") and hasClickAction() and hasAnyAncestor(isDialog())).performClick()
            waitText("Forgot ${laptop.name}")
            shot("forget-snackbar-$th")

            // >>> QA EXTRA ANDROID CHECKS (main app) GO HERE <<<
            // r3 design / theme splash / items 6-8: add steps + shot("qa-...-$th").
        }

        // 6. share sheet with LINK OK and LAST USED
        ShareActivity.backendFactory = { FakeShare(listOf(ShareTarget(laptop.id, laptop.name), ShareTarget(desk.id, desk.name))) }
        val share = Intent(ctx, ShareActivity::class.java)
            .setAction(Intent.ACTION_SEND).setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, "https://github.com/voidwire-app/voidwire/pull/1")
        ActivityScenario.launch<ShareActivity>(share).use {
            waitText("Link OK"); waitText("Last used")
            compose.waitUntil(15_000) {
                compose.onAllNodes(hasClickAction() and androidx.compose.ui.test.isEnabled() and
                    androidx.compose.ui.test.hasContentDescription("Send to ", substring = true)).fetchSemanticsNodes().size == 2
            }
            shot("share-last-used-short-$th")
        }
        osNight(true)
    }

    private fun pairVia(shotScanAs: String? = null) {
        // Right after Back from the pair-code screen the Home button can be
        // tapped while the transition is still running and the tap is lost
        // (QA 40925072953 / 40930478697, dark run only): tap again, at most 3 times.
        var open = false
        for (attempt in 0 until 3) {
            waitText("Pair a device")
            compose.waitForIdle()
            compose.onAllNodesWithText("Pair a device").let { it[it.fetchSemanticsNodes().size - 1] }.performClick()
            open = runCatching {
                compose.waitUntil(10_000) { compose.onAllNodes(hasSetTextAction()).fetchSemanticsNodes().isNotEmpty() }
            }.isSuccess
            if (open) break
        }
        org.junit.Assert.assertTrue("the scanner did not open after 3 taps on Pair a device", open)
        if (shotScanAs != null) shot(shotScanAs)
        Qa.usePairLink(compose, "voidwire:pair?v=2&qa=fake")
    }
}

