package app.voidwire.android

import android.content.res.Configuration
import app.voidwire.android.ui.theme.ThemeMode

/**
 * Dark unless the OS explicitly says light (M1.1 design rule). The same
 * rule as the generated ui/theme/Theme.kt `voidwireUseDarkTheme()` (which is
 * @Composable); this pure copy is used outside composition (system bar icon
 * style) and by the JVM tests. Compose's isSystemInDarkTheme() is NOT used:
 * it treats UI_MODE_NIGHT_UNDEFINED as light.
 */
object ThemeRule {
    fun isDark(uiMode: Int): Boolean =
        (uiMode and Configuration.UI_MODE_NIGHT_MASK) != Configuration.UI_MODE_NIGHT_NO

    /** With the in-app Theme setting (round 2): System follows [isDark]. */
    fun isDark(mode: ThemeMode, uiMode: Int): Boolean = when (mode) {
        ThemeMode.System -> isDark(uiMode)
        ThemeMode.Dark -> true
        ThemeMode.Light -> false
    }
}
