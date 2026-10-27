package app.voidwire.android

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The optional "Recent sends" list (host only, never the full link).
 *
 * M1.1 privacy rule: OFF by default. While off nothing is stored and the
 * preferences file doesn't exist; turning it off (or an older install that
 * never turned it on) deletes the file. The on/off flag lives in the same
 * file, so "off" is simply "no file".
 */
object RecentSends {
    private const val PREFS = "recent_sends"
    private const val KEY = "lines"
    private const val ENABLED = "enabled"
    private const val MAX = 20

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun prefsFile(context: Context) =
        java.io.File(context.applicationInfo.dataDir, "shared_prefs/$PREFS.xml")

    fun enabled(context: Context): Boolean =
        prefsFile(context).exists() && prefs(context).getBoolean(ENABLED, false)

    fun setEnabled(context: Context, on: Boolean) {
        if (on) {
            prefs(context).edit().putBoolean(ENABLED, true).commit()
        } else {
            wipe(context)
        }
    }

    /** Remove everything (list, flag, file). */
    fun wipe(context: Context) {
        if (prefsFile(context).exists()) prefs(context).edit().clear().commit()
        context.deleteSharedPreferences(PREFS)
    }

    /** Startup: an install without the setting on keeps nothing (M1 lists included). */
    fun enforce(context: Context) {
        if (!enabled(context)) wipe(context)
    }

    fun add(context: Context, line: String) {
        if (!enabled(context)) return
        val stamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val lines = listOf("$stamp  $line") + list(context)
        prefs(context).edit().putString(KEY, lines.take(MAX).joinToString("\n")).apply()
    }

    fun list(context: Context): List<String> {
        if (!enabled(context)) return emptyList()
        return prefs(context).getString(KEY, null)
            ?.split("\n")?.filter { it.isNotBlank() } ?: emptyList()
    }

    fun clear(context: Context) {
        if (enabled(context)) prefs(context).edit().remove(KEY).apply()
    }
}

/** Formatting shared by the UI and its JVM tests. */
object SendText {
    fun host(url: String): String = try {
        java.net.URI(url).host ?: url.take(40)
    } catch (e: Exception) {
        url.take(40)
    }

    fun latency(us: ULong): String {
        val ms = us.toDouble() / 1000.0
        return if (ms < 10) String.format(Locale.US, "%.1f ms", ms) else "${ms.toLong()} ms"
    }

    /** F3 (REVIEW-m11-android): two-line recent row (`host · result` over `time → PC`). */
    fun splitRecent(raw: String): Pair<String, String?> {
        val m = Regex("""^(\d\d:\d\d:\d\d)\s+(.+?)\s+→\s+(.+?):\s+(.+)$""").matchEntire(raw.trim())
            ?: return raw to null
        val (time, host, pc, res) = m.destructured
        return "$host · $res" to "$time → $pc"
    }
}
