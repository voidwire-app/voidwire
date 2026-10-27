package app.voidwire.android

import androidx.compose.ui.test.junit4.createEmptyComposeRule
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

/** android-qa spec D1-D4 and E (opt-in files): the HISTORY chip and what the opt-ins keep on disk. */
@RunWith(AndroidJUnit4::class)
class HistoryChipTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()
    private val pc = PcInfo("ab".repeat(32), "QA PC", false)

    @Before fun fresh() { resetAppPrefs(); DebugSeams.fakePhone = FakePhone(listOf(pc)) }
    @After fun reset() { DebugSeams.fakePhone = null; ShareActivity.resetForTests(); resetAppPrefs() }

    private fun chip(): Boolean {
        var on = false
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, pc.name)
            on = Qa.has(compose, "HISTORY ON")
            if (!on) assertTrue(Qa.has(compose, "NO HISTORY"))
        }
        return on
    }

    private fun prefsXml(name: String) = File(Qa.ctx.applicationInfo.dataDir, "shared_prefs/$name.xml")

    @Test fun noHistoryByDefault() {
        assertEquals("prefs on a fresh state", emptyList<String>(), Qa.prefsFiles())
        assertFalse(chip())
    }

    @Test fun historyOnWhenAnyOptIn() {
        LastPc.setEnabled(Qa.ctx, true)
        assertTrue(chip())
        // A real send through the share sheet (fake backend) records last_pc.
        ShareActivity.backendFactory = { FakeShare(listOf(ShareTarget(pc.id, pc.name))) }
        androidx.test.core.app.ActivityScenario.launch<ShareActivity>(shareIntent("https://example.org/p?q=private#x")).use { s ->
            Qa.waitText(compose, "Link OK")
            tapSendWhenArmed(s); Qa.waitText(compose, "Sent to")
        }
        val share = Qa.prefsFiles().filter { it.startsWith("share") }
        assertTrue("share prefs: ${Qa.prefsFiles()}", share.isNotEmpty())
        val xml = share.joinToString("\n") { File(Qa.ctx.applicationInfo.dataDir, "shared_prefs/$it").readText() }
        assertTrue(xml, xml.contains(pc.id))
        resetAppPrefs()
        RecentSends.setEnabled(Qa.ctx, true)
        assertTrue(chip())
    }

    /** Recent sends keep the host only (no path, no query); turning everything off deletes the files. */
    @Test fun optInsOffDeleteFiles() {
        RecentSends.setEnabled(Qa.ctx, true); LastPc.setEnabled(Qa.ctx, true)
        ThemePref.set(Qa.ctx, app.voidwire.android.ui.theme.ThemeMode.Dark)
        RecentSends.add(Qa.ctx, "${SendText.host("https://example.org/p?q=private#x")} → ${pc.name}: opened 9 ms")
        val lines = RecentSends.list(Qa.ctx)
        assertTrue(lines.toString(), lines.single().contains("example.org → QA PC"))
        assertFalse(lines.toString(), lines.single().contains("private") || lines.single().contains("/p"))
        assertTrue(Qa.prefsFiles().isNotEmpty())
        resetAppPrefs() // the same calls the Settings switches and Theme=System make
        assertEquals(emptyList<String>(), Qa.prefsFiles())
        assertFalse(prefsXml("ui").exists())
        assertFalse(chip())
    }
}
