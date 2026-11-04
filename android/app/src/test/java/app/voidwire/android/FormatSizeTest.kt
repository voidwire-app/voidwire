package app.voidwire.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Sizes on the incoming card, the relay prompt and the relay-limit dialog, up to 1 TiB. */
class FormatSizeTest {
    private val kib = 1024L
    private val mib = kib * 1024L
    private val gib = mib * 1024L
    private val tib = gib * 1024L

    @Test
    fun smallUnitsKeepTheirFormat() {
        assertEquals("0 B", FileShareStaging.formatSize(0))
        assertEquals("1023 B", FileShareStaging.formatSize(1023))
        assertEquals("1 KB", FileShareStaging.formatSize(kib))
        assertEquals("1.5 KB", FileShareStaging.formatSize(kib + 512))
        assertEquals("25.0 MB", FileShareStaging.formatSize(25 * mib))
        assertEquals("0 B", FileShareStaging.formatSize(-5))
    }

    @Test
    fun gigabytesAndTerabytesUpToOneTib() {
        assertEquals("1.00 GB", FileShareStaging.formatSize(gib))
        assertEquals("2.00 GB", FileShareStaging.formatSize(2 * gib))
        assertEquals("2.50 GB", FileShareStaging.formatSize(2 * gib + 512 * mib))
        assertEquals("4.00 GB", FileShareStaging.formatSize(4 * gib + 1))
        assertEquals("1.00 TB", FileShareStaging.formatSize(tib))
        assertEquals("1.00 TB", FileShareStaging.formatSize(tib - 1))
        assertEquals("1.00 GB", FileShareStaging.formatSize(gib - 1))
        assertEquals("1.50 TB", FileShareStaging.formatSize(tib + tib / 2))
    }

    @Test
    fun relayLimitDialogNamesALargeCapInTerabytes() {
        val dlg = PhoneErrors.dialogForDetail("exceeds_relay_cap size=1 cap=$tib", "Desk")
        assertTrue(dlg.message, dlg.message.contains("(1.00 TB)"))
        val small = PhoneErrors.dialogForDetail("exceeds_relay_cap size=1 cap=${25 * mib}", "Desk")
        assertTrue(small.message, small.message.contains("(25 MB)"))
    }
}
