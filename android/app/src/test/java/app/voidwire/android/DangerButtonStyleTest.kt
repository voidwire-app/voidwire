package app.voidwire.android

import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.graphics.Color
import app.voidwire.android.ui.theme.VoidwireTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.GraphicsMode

/** Designer r3: Settings 'Clear' (recent sends) is an error-role OUTLINED button, never gold, never filled. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class DangerButtonStyleTest {
    @Test
    fun clearIsRedOutlineRedLabelNoFill() {
        for (dark in listOf(true, false)) {
            var label = Color.Unspecified
            var fill = Color.Unspecified
            var stroke: androidx.compose.ui.graphics.Brush? = null
            var error = Color.Unspecified
            var primary = Color.Unspecified
            val activity = Robolectric.buildActivity(ComponentActivity::class.java).setup().get()
            activity.setContent {
                VoidwireTheme(darkTheme = dark) {
                    val c = dangerOutlinedButtonColors()
                    label = c.contentColor
                    fill = c.containerColor
                    stroke = dangerOutlinedBorder().brush
                    error = MaterialTheme.colorScheme.error
                    primary = MaterialTheme.colorScheme.primary
                }
            }
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals("label = error ($dark)", error, label)
            assertNotEquals("never gold ($dark)", primary, label)
            assertEquals("not filled ($dark)", Color.Transparent, fill)
            assertEquals("outline = error @ 55% ($dark)", androidx.compose.ui.graphics.SolidColor(error.copy(alpha = 0.55f)), stroke)
        }
    }
}
