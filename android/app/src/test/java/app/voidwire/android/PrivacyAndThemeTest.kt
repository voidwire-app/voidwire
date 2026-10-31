package app.voidwire.android

import android.content.Context
import android.content.res.Configuration
import org.robolectric.RuntimeEnvironment
import java.io.File
import app.voidwire.android.ui.theme.ThemeMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** M1.1: dark-by-default rule and the opt-in "Recent sends" list. */
@RunWith(RobolectricTestRunner::class)
class PrivacyAndThemeTest {
    private val context: Context = RuntimeEnvironment.getApplication()
    private fun prefsFile(name: String) = File(context.applicationInfo.dataDir, "shared_prefs/$name.xml")

    @Test
    fun darkUnlessTheOsExplicitlySaysLight() {
        assertTrue("undefined -> dark", ThemeRule.isDark(Configuration.UI_MODE_NIGHT_UNDEFINED))
        assertTrue(ThemeRule.isDark(Configuration.UI_MODE_NIGHT_YES))
        assertFalse(ThemeRule.isDark(Configuration.UI_MODE_NIGHT_NO))
        // Other uiMode bits (type) don't matter.
        assertTrue(ThemeRule.isDark(Configuration.UI_MODE_TYPE_NORMAL or Configuration.UI_MODE_NIGHT_UNDEFINED))
        assertFalse(ThemeRule.isDark(Configuration.UI_MODE_TYPE_NORMAL or Configuration.UI_MODE_NIGHT_NO))
    }

    @Test
    fun recentSendsStoreNothingByDefault() {
        RecentSends.wipe(context)
        assertFalse(RecentSends.enabled(context))
        RecentSends.add(context, "x.com -> PC: opened 4 ms")
        assertEquals(emptyList<String>(), RecentSends.list(context))
        assertFalse("no prefs file while off", prefsFile("recent_sends").exists())
    }

    @Test
    fun turningRecentSendsOffDeletesThem() {
        RecentSends.setEnabled(context, true)
        RecentSends.add(context, "x.com -> PC: opened 4 ms")
        assertEquals(1, RecentSends.list(context).size)
        RecentSends.setEnabled(context, false)
        assertFalse(RecentSends.enabled(context))
        assertEquals(emptyList<String>(), RecentSends.list(context))
        assertFalse(prefsFile("recent_sends").exists())
    }

    @Test
    fun startupWipesAnM1ListAndTheLastPcFile() {
        // An M1 install: list stored, no "enabled" flag; last PC on disk.
        context.getSharedPreferences("recent_sends", Context.MODE_PRIVATE).edit()
            .putString("lines", "12:00:00  x.com -> PC: opened").commit()
        context.getSharedPreferences("share", Context.MODE_PRIVATE).edit()
            .putString("last_pc", "abc").commit()
        RecentSends.enforce(context)
        LastPc.enforce(context) // what Privacy.enforce runs at startup
        assertFalse(prefsFile("recent_sends").exists())
        assertFalse(prefsFile("share").exists())
        assertEquals(emptyList<String>(), RecentSends.list(context))
    }

    private val pcs = listOf(
        ShareTarget("id-3", "zeta"),
        ShareTarget("id-2", "Alpha"),
        ShareTarget("id-1", "alpha"),
        ShareTarget("id-4", "Basement"),
    )

    @Test
    fun rememberLastPcIsOffByDefaultStoresNothingAndSortsAToZ() {
        LastPc.wipe(context)
        assertFalse(LastPc.enabled(context))
        LastPc.set(context, "id-3")
        assertNull(LastPc.last(context))
        assertFalse("no share prefs file while off", prefsFile("share").exists())
        // A–Z, case-insensitive, id as tie-breaker; no LAST USED (nothing first).
        assertEquals(listOf("id-1", "id-2", "id-4", "id-3"), LastPc.order(context, pcs).map { it.id })
        assertFalse(History.anyOn(context))
    }

    @Test
    fun rememberLastPcOnPutsItFirstAndTurningItOffDeletesIt() {
        LastPc.setEnabled(context, true)
        LastPc.set(context, "id-3")
        assertEquals("id-3", LastPc.last(context))
        assertTrue(LastPc.isLast(context, "id-3"))
        assertEquals(listOf("id-3", "id-1", "id-2", "id-4"), LastPc.order(context, pcs).map { it.id })
        assertTrue("HISTORY ON while it is on", History.anyOn(context))
        LastPc.setEnabled(context, false)
        assertFalse(prefsFile("share").exists())
        assertNull(LastPc.last(context))
        assertEquals(listOf("id-1", "id-2", "id-4", "id-3"), LastPc.order(context, pcs).map { it.id })
        assertFalse(History.anyOn(context))
    }

    @Test
    fun startupKeepsTheLastPcOnlyWhileRememberIsOn() {
        LastPc.setEnabled(context, true)
        LastPc.set(context, "id-2")
        LastPc.enforce(context)
        assertEquals("id-2", LastPc.last(context))
        LastPc.wipe(context)
    }

    @Test
    fun themeSettingDefaultsToDarkAndDarkStoresNothing() {
        ThemePref.set(context, ThemeMode.Dark)
        assertEquals(ThemeMode.Dark, ThemePref.get(context))
        assertFalse("no ui prefs file for the default", prefsFile("ui").exists())
        ThemePref.set(context, ThemeMode.Light)
        assertEquals(ThemeMode.Light, ThemePref.get(context))
        ThemePref.set(context, ThemeMode.System)
        assertEquals(ThemeMode.System, ThemePref.get(context))
        ThemePref.set(context, ThemeMode.Dark)
        assertFalse(prefsFile("ui").exists())
    }

    @Test
    fun themeModeResolution() {
        val undef = Configuration.UI_MODE_NIGHT_UNDEFINED
        val no = Configuration.UI_MODE_NIGHT_NO
        val yes = Configuration.UI_MODE_NIGHT_YES
        assertTrue("System, OS silent: dark", ThemeRule.isDark(ThemeMode.System, undef))
        assertFalse("System, OS light: light", ThemeRule.isDark(ThemeMode.System, no))
        assertTrue(ThemeRule.isDark(ThemeMode.System, yes))
        assertTrue("Dark beats a light OS", ThemeRule.isDark(ThemeMode.Dark, no))
        assertFalse("Light beats a dark OS", ThemeRule.isDark(ThemeMode.Light, yes))
        assertEquals(ThemeMode.Dark, ThemeMode.fromKey(null))
        assertEquals(ThemeMode.Dark, ThemeMode.fromKey("purple"))
        assertEquals(ThemeMode.System, ThemeMode.fromKey("system"))
        assertEquals(ThemeMode.Light, ThemeMode.fromKey("light"))
    }
}
