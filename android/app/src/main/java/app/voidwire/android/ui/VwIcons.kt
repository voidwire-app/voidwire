package app.voidwire.android.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.unit.dp

/**
 * The design kit's 24-grid line icons (design/m1-polish/src/icons.js), as
 * Compose ImageVectors. Stroke 1.75, round caps; tint them with Icon(tint=).
 * No icon library dependency.
 */
object VwIcons {
    private fun rect(x: Float, y: Float, w: Float, h: Float, r: Float) =
        "M${x + r} ${y}h${w - 2 * r}a$r $r 0 0 1 $r ${r}v${h - 2 * r}a$r $r 0 0 1 -$r ${r}h${-(w - 2 * r)}a$r $r 0 0 1 -$r -${r}v${-(h - 2 * r)}a$r $r 0 0 1 $r -${r}z"

    private fun circle(cx: Float, cy: Float, r: Float) =
        "M${cx - r} ${cy}a$r $r 0 1 0 ${2 * r} 0a$r $r 0 1 0 ${-2 * r} 0z"

    private fun icon(name: String, vararg paths: String): ImageVector {
        val b = ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f)
        for (d in paths) {
            b.addPath(
                pathData = PathParser().parsePathString(d).toNodes(),
                fill = null,
                stroke = SolidColor(Color.Black),
                strokeLineWidth = 1.75f,
                strokeLineCap = StrokeCap.Round,
                strokeLineJoin = StrokeJoin.Round,
            )
        }
        return b.build()
    }

    val Phone by lazy { icon("phone", rect(7f, 2.5f, 10f, 19f, 2.2f), "M10.5 18.5h3") }
    val Monitor by lazy { icon("monitor", rect(2.5f, 4f, 19f, 12.5f, 1.8f), "M8.5 20.5h7M12 16.5v4") }
    val Gear by lazy {
        icon(
            "gear",
            circle(12f, 12f, 3f),
            "M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
        )
    }
    val Clock by lazy { icon("clock", circle(12f, 12f, 9f), "M12 7v5l3 2") }
    val Back by lazy { icon("back", "M19 12H5M11 6l-6 6 6 6") }
    val Check by lazy { icon("check", "M4.5 12.5l5 5 10-11") }
    val Close by lazy { icon("x", "M6 6l12 12M18 6L6 18") }
    val Warn by lazy { icon("warn", "M12 3.5l9.5 16.5h-19z", "M12 10v4.5M12 17.6v.1") }
    val Qr by lazy {
        icon(
            "qr",
            rect(3.5f, 3.5f, 6.5f, 6.5f, 1f),
            rect(14f, 3.5f, 6.5f, 6.5f, 1f),
            rect(3.5f, 14f, 6.5f, 6.5f, 1f),
            "M14 14h2.5v2.5H14zM18 18h2.5v2.5H18zM14 18.5v2M18.5 14h2",
        )
    }
    val Info by lazy { icon("info", circle(12f, 12f, 9f), "M12 11v5.5M12 7.6v.1") }
    val Link by lazy {
        icon(
            "link",
            "M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1",
            "M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1",
        )
    }
    val Unlink by lazy {
        icon(
            "unlink",
            "M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1",
            "M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1",
            "M3 3l18 18",
        )
    }
    val Refresh by lazy {
        icon("refresh", "M20 11a8 8 0 0 0-14.6-4.5L4 8M4 4v4h4M4 13a8 8 0 0 0 14.6 4.5L20 16M20 20v-4h-4")
    }
    val Lock by lazy { icon("lock", rect(5f, 10.5f, 14f, 10f, 2f), "M8 10.5V7.5a4 4 0 0 1 8 0v3") }
    val Shield by lazy {
        icon("shield", "M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6z", "M8.8 12.2l2.3 2.3 4.3-4.6")
    }
    val Send by lazy { icon("send", "M4 12l16-8-6 16-2.5-6.5z", "M11.5 13.5L20 4") }
    val File by lazy { icon("file", "M14 2.5H6.5a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V8z", "M14 2.5V8h5.5") }
    val EyeOff by lazy {
        icon(
            "eyeoff",
            "M3 3l18 18M10.6 5.1A9.7 9.7 0 0 1 12 5c5 0 8.5 4.5 9.5 7a13 13 0 0 1-2.6 3.8M6.4 6.4C4.3 7.8 3 9.9 2.5 12c1 2.5 4.5 7 9.5 7 1.7 0 3.2-.5 4.5-1.3",
            "M9.9 9.9a3 3 0 0 0 4.2 4.2",
        )
    }
    val Eye by lazy {
        icon(
            "eye",
            "M2.5 12c1-2.5 4.5-7 9.5-7s8.5 4.5 9.5 7c-1 2.5-4.5 7-9.5 7s-8.5-4.5-9.5-7z",
            circle(12f, 12f, 3f),
        )
    }
    val Clipboard by lazy {
        icon(
            "clipboard",
            "M9 4.5H6.5a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-13a2 2 0 0 0-2-2H15",
            rect(9f, 2.5f, 6f, 4f, 1.2f),
        )
    }
}
