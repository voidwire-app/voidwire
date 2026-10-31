package app.voidwire.android

import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.voidwire_core.PcInfo
import java.io.File

/** android-qa spec B4/B5: live theme switch; prefs file only for Dark/Light; no stacked MainActivity. */
@RunWith(AndroidJUnit4::class)
class ThemeSwitchTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()
    private val ui get() = File(Qa.ctx.applicationInfo.dataDir, "shared_prefs/ui.xml")

    @Before fun fresh() { resetAppPrefs(); Qa.osNight(true); DebugSeams.fakePhone = FakePhone(listOf(PcInfo("ab".repeat(32), "QA PC", false))) }
    @After fun reset() { DebugSeams.fakePhone = null; resetAppPrefs() }

    /**
     * Distinct live MainActivity records. d446e01 counted every dumpsys line
     * naming the record (Hist, mResumedActivity, topResumedActivity,
     * mFocusedApp, ...), so one activity read as 8. The app itself never
     * starts MainActivity on a theme change: Settings sets Compose state, and
     * on API 31+ setApplicationNightMode makes the system *relaunch* the same
     * record (same id), not stack a new one.
     */
    private fun mainActivities(): Int {
        val dump = Qa.shell("dumpsys activity activities")
        java.io.File(Qa.outDir, "B4-dumpsys-activities.txt").writeText(dump)
        val re = Regex("""ActivityRecord\{(\w+) u\d+ ${Regex.escape(Qa.ctx.packageName)}/\.MainActivity""")
        return re.findAll(dump).map { it.groupValues[1] }.toSet().size
    }

    private fun tap(mode: String, i: Int) {
        compose.onNodeWithText(mode).performScrollTo().performClick()
        Thread.sleep(2_000) // recreation / recomposition
        compose.waitForIdle()
        Qa.waitText(compose, "Keep recent sends")
        assertTrue("Settings screen must stay open after theme switch to $mode", Qa.has(compose, "Appearance"))
        assertFalse("must not reset to Home after $mode", Qa.has(compose, "Paired PCs"))
        Qa.shot("B4-theme-$i-$mode")
        assertEquals("MainActivity copies after $mode", 1, mainActivities())
    }

    private fun openSettings() {
        Qa.waitText(compose, "QA PC")
        compose.onNodeWithContentDescription("Settings").performClick()
        Qa.waitText(compose, "Keep recent sends")
    }

    @Test fun systemStoresNothing() {
        ActivityScenario.launch(MainActivity::class.java).use {
            openSettings()
            tap("Dark", 1); tap("System", 2)
            assertFalse("ui.xml kept for System", ui.exists())
        }
    }

    @Test fun darkLightStoreKey() {
        ActivityScenario.launch(MainActivity::class.java).use {
            openSettings()
            tap("System", 0)
            assertFalse(ui.exists())
            tap("Dark", 1)
            assertTrue(ui.readText().contains("dark"))
            tap("Light", 2)
            assertTrue(ui.readText().contains("light"))
            tap("System", 3)
            assertFalse(ui.exists())
        }
    }
}
