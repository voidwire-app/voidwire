package app.voidwire.android

import android.app.UiModeManager
import android.content.Context
import android.os.Build
import app.voidwire.android.ui.theme.ThemeMode
import java.text.Collator
import java.util.Locale

/**
 * In-app Theme setting (SPEC 3.1 / 3.7, round 2): `ui` prefs, key
 * `theme_mode`. The default, System, stores nothing (no file); Dark and Light
 * store their key. System = dark unless the OS explicitly says light.
 */
object ThemePref {
    private const val PREFS = "ui"
    private const val KEY = "theme_mode"

    fun get(context: Context): ThemeMode {
        if (!prefsFile(context, PREFS).exists()) return ThemeMode.Default
        return ThemeMode.fromKey(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, null))
    }

    fun set(context: Context, mode: ThemeMode) {
        if (mode == ThemeMode.Default) {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit()
            context.deleteSharedPreferences(PREFS)
        } else {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, mode.key).commit()
        }
        syncWindowNightMode(context, mode)
    }

    /**
     * Keeps the per-app night mode (API 31+) in line with the in-app theme so
     * configuration-dependent system UI matches it. The cold-start splash no
     * longer depends on this: it is theme-neutral (one dark #070B14 background
     * with the icon in values/ and values-v31/, no notnight override), because
     * QA 8ee9a16 B2 showed the API 34 starting window resolving the light
     * values-notnight-v31 splash despite MODE_NIGHT_YES. Compose then paints
     * the chosen theme. android-qa.sh logs `cmd uimode night`, `dumpsys uimode`
     * and getApplicationNightMode (QaStateTest#nightMode) around B2/B3.
     */
    fun syncWindowNightMode(context: Context, mode: ThemeMode = get(context)) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
        val ui = context.getSystemService(UiModeManager::class.java) ?: return
        val want = when (mode) {
            ThemeMode.Dark -> UiModeManager.MODE_NIGHT_YES
            ThemeMode.Light -> UiModeManager.MODE_NIGHT_NO
            ThemeMode.System -> UiModeManager.MODE_NIGHT_AUTO
        }
        runCatching { ui.setApplicationNightMode(want) }
    }
}

/**
 * "Remember last PC" (SPEC 3.6 / 3.7, R4b, round 2): a privacy opt-in, OFF by
 * default. Off: nothing is stored (no `share` prefs file), the share sheet
 * lists PCs A–Z and there is no LAST USED tag. On: `share` prefs hold the
 * flag and `last_pc` (a PC id), and that PC goes first. Turning it off
 * deletes the file.
 */
object LastPc {
    private const val PREFS = "share"
    private const val ON = "remember"
    private const val KEY = "last_pc"

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun enabled(context: Context): Boolean =
        prefsFile(context, PREFS).exists() && prefs(context).getBoolean(ON, false)

    fun setEnabled(context: Context, on: Boolean) {
        if (on) prefs(context).edit().putBoolean(ON, true).commit() else wipe(context)
    }

    fun wipe(context: Context) {
        if (prefsFile(context, PREFS).exists()) prefs(context).edit().clear().commit()
        context.deleteSharedPreferences(PREFS)
    }

    /** Startup: off (or an M1 file without the flag) keeps nothing. */
    fun enforce(context: Context) {
        if (!enabled(context)) wipe(context)
    }

    /** Remember the PC just sent to. Off: writes nothing. */
    fun set(context: Context, id: String) {
        if (enabled(context)) prefs(context).edit().putString(KEY, id).apply()
    }

    fun last(context: Context): String? =
        if (enabled(context)) prefs(context).getString(KEY, null) else null

    fun isLast(context: Context, id: String): Boolean = last(context) == id

    fun order(context: Context, pcs: List<ShareTarget>): List<ShareTarget> = order(pcs, last(context))

    /** A–Z (case-insensitive Collator, PC id as tie-breaker); `last` first if given. */
    fun order(pcs: List<ShareTarget>, last: String?): List<ShareTarget> {
        val c = Collator.getInstance(Locale.getDefault()).apply { strength = Collator.SECONDARY }
        val az = pcs.sortedWith { a, b -> c.compare(a.name, b.name).takeIf { it != 0 } ?: a.id.compareTo(b.id) }
        return if (last == null) az else az.sortedByDescending { it.id == last } // stable
    }
}

/** History-type opt-ins (SPEC 3.2 NO HISTORY rule): add any future one here. */
object History {
    fun anyOn(context: Context): Boolean = RecentSends.enabled(context) || LastPc.enabled(context)
}

internal fun prefsFile(context: Context, name: String) =
    java.io.File(context.applicationInfo.dataDir, "shared_prefs/$name.xml")
