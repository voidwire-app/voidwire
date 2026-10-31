package app.voidwire.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** The re-pair notice (owner decision, 10-31): exact text, no dismiss button, shown only
 *  while the core says old pairings were dropped (cleared by the next pairing). */
class RepairNoticeTest {
    @Test
    fun textIsExact() {
        assertEquals("The app was upgraded, and to improve security, your devices will need to be re-paired.", REPAIR_NOTICE)
    }

    @Test
    fun theLineHasNoDismissAndFollowsTheCoreFlag() {
        val src = File("src/main/java/app/voidwire/android/MainActivity.kt").readText()
        val start = src.indexOf("if (oldPairingsDropped) {")
        assertTrue("the notice is gated on the core flag", start >= 0)
        val block = src.substring(start, src.indexOf("old_pairings_line", start))
        assertTrue(block.contains("REPAIR_NOTICE"))
        for (dismiss in listOf("onClick", "Button", "oldPairingsDropped = false", "clickable")) {
            assertFalse("no dismiss ($dismiss)", block.contains(dismiss))
        }
        assertFalse("nothing in the app clears it by hand", src.contains("oldPairingsDropped = false"))
    }
}
