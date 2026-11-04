package app.voidwire.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Sizes and offsets near 1 TiB never pass through Int: core hands the phone u64
 * (Kotlin ULong) counts and the app keeps them in Long.
 */
class LargeSizeMathTest {
    private val gib = 1024UL * 1024UL * 1024UL
    private val tib = gib * 1024UL

    @Test
    fun progressIsExactPastIntAndUpToOneTib() {
        for (total in listOf(Int.MAX_VALUE.toULong(), 2UL * gib, 4UL * gib + 1UL, tib - 1UL, tib)) {
            assertEquals(total.toLong(), TransferProgress.total(total))
            assertEquals(0, TransferProgress.percent(0UL, total))
            assertEquals(50, TransferProgress.percent((total + 1UL) / 2UL, total))
            assertEquals(99, TransferProgress.percent(total - 1UL, total))
            assertEquals(100, TransferProgress.percent(total, total))
            assertEquals(total.toLong() - 1L, TransferProgress.done(total - 1UL, total))
            assertEquals(0.5f, TransferProgress.fraction(total / 2UL, total), 1e-6f)
        }
        // One chunk (256 KiB) into a 1 TiB file is above 0 bytes but rounds to 0 %.
        assertEquals(262_144L, TransferProgress.done(262_144UL, tib))
        assertEquals(0, TransferProgress.percent(262_144UL, tib))
    }

    @Test
    fun progressClampsOddCounts() {
        assertEquals(1L, TransferProgress.total(0UL))
        assertEquals(0, TransferProgress.percent(0UL, 0UL))
        assertEquals(100, TransferProgress.percent(5UL * tib, tib))
        assertEquals(tib.toLong(), TransferProgress.done(5UL * tib, tib))
        // A count past Long.MAX_VALUE never turns negative.
        assertEquals(100, TransferProgress.percent(ULong.MAX_VALUE, ULong.MAX_VALUE))
        assertTrue(TransferProgress.total(ULong.MAX_VALUE) > 0L)
    }

    @Test
    fun sizeLimitsAreLongNotInt() {
        assertEquals(tib.toLong(), FileShareStaging.MAX_FILE_BYTES)
        assertTrue(FileShareStaging.MAX_FILE_BYTES > Int.MAX_VALUE.toLong())
        assertEquals("1.00 TB", FileShareStaging.formatSize(tib.toLong()))
        assertEquals("4.00 GB", FileShareStaging.formatSize((4UL * gib + 1UL).toLong()))
    }
}
