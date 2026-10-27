package app.voidwire.android

import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
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

/** android-qa spec D5: A–Z without "Remember last PC"; last PC first with LAST USED when on. */
@RunWith(AndroidJUnit4::class)
class ShareOrderUiTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()
    private val zeta = ShareTarget("ee".repeat(32), "zeta")
    private val alpha = ShareTarget("aa".repeat(32), "Alpha")

    @Before fun fresh() { resetAppPrefs(); ShareActivity.backendFactory = { FakeShare(listOf(zeta, alpha)) } }
    @After fun reset() { ShareActivity.resetForTests(); resetAppPrefs() }

    @Test fun azWithoutRemember() {
        var pcs = emptyList<String>()
        ActivityScenario.launch<ShareActivity>(shareIntent("https://example.com/order")).use { s ->
            Qa.waitText(compose, "Send to Alpha")
            s.onActivity { pcs = (it.ui as ShareUi.Ready).pcs.map { p -> p.name } }
            assertFalse(Qa.has(compose, "Last used"))
        }
        assertEquals(listOf("Alpha", "zeta"), pcs)
    }

    @Test fun lastUsedFirstWhenOn() {
        LastPc.setEnabled(Qa.ctx, true); LastPc.set(Qa.ctx, zeta.id)
        ActivityScenario.launch<ShareActivity>(shareIntent("https://example.com/order")).use { s ->
            Qa.waitText(compose, "Last used")
            var pcs = emptyList<String>()
            s.onActivity { pcs = (it.ui as ShareUi.Ready).pcs.map { p -> p.name } }
            assertEquals(listOf("zeta", "Alpha"), pcs)
            Qa.shot("D5-last-used-first")
        }
        assertTrue(LastPc.enabled(Qa.ctx))
    }

    /** Designer blocker 1 re-shoot: long names, LAST USED overline inside the gold button, both themes. */
    @Test fun longNamesLight() = longNames(app.voidwire.android.ui.theme.ThemeMode.Light, "light", osNight = false)
    @Test fun longNamesDark() = longNames(app.voidwire.android.ui.theme.ThemeMode.Dark, "dark", osNight = true)

    private fun longNames(mode: app.voidwire.android.ui.theme.ThemeMode, th: String, osNight: Boolean) {
        val desk = ShareTarget("dd".repeat(32), "Primary Workstation Studio Upstairs Office Rack 2")
        val lap = ShareTarget("cc".repeat(32), "Engineering Work Laptop Docking Station")
        ShareActivity.backendFactory = { FakeShare(listOf(lap, desk)) }
        Qa.osNight(osNight); ThemePref.set(Qa.ctx, mode)
        LastPc.setEnabled(Qa.ctx, true); LastPc.set(Qa.ctx, desk.id)
        try {
            ActivityScenario.launch<ShareActivity>(shareIntent("https://github.com/voidwire-app/voidwire/pull/1")).use {
                Qa.waitText(compose, "Link OK", 60_000); Qa.waitText(compose, "Last used")
                // The light shot on bc00c59 fired while the S1 tap gate still drew the buttons disabled.
                compose.waitUntil(15_000) {
                    compose.onAllNodes(androidx.compose.ui.test.hasClickAction() and androidx.compose.ui.test.isEnabled() and
                        androidx.compose.ui.test.hasContentDescription("Send to ", substring = true)).fetchSemanticsNodes().size == 2
                }
                Thread.sleep(500)
                Qa.shot("share-last-used-$th")
                val label = "Send to ${desk.name}"
                // Too long for 2 lines: start and end kept, "…" in the middle (Designer blocker 1).
                val shown = compose.onAllNodesWithText("Send to Primary Workstation", substring = true, useUnmergedTree = true)
                    .fetchSemanticsNodes().single().config[androidx.compose.ui.semantics.SemanticsProperties.Text].joinToString("") { it.text }
                assertTrue("primary label should be middle-ellipsized, got '$shown'",
                    shown.contains("…") && shown.endsWith("Rack 2") && !shown.endsWith("…"))
                val lines = Qa.lineCounts(compose, shown)
                assertTrue("primary label should take 2 lines, got $lines", lines == listOf(2))
                assertTrue("other PC label should show its full name, got ${Qa.lineCounts(compose, "Send to ${lap.name}")}",
                    Qa.lineCounts(compose, "Send to ${lap.name}").let { it.size == 1 && it[0] <= 2 })
                val over = compose.onAllNodesWithText("LAST USED", useUnmergedTree = true).fetchSemanticsNodes().single().boundsInWindow
                val lbl = compose.onAllNodesWithText(shown, useUnmergedTree = true).fetchSemanticsNodes().single().boundsInWindow
                assertTrue("LAST USED ($over) must sit above the label ($lbl)", over.bottom <= lbl.top + 1)
                compose.onNode(androidx.compose.ui.test.hasContentDescription("$label, last used")).assertExists()
            }
        } finally { Qa.osNight(true) }
    }
}
