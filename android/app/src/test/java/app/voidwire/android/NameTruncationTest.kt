package app.voidwire.android

import org.junit.Assert.assertEquals
import org.junit.Test

/** SPEC §4 / REVIEW-m11 #8: identifiers keep their tail (head(n-7) + "…" + tail(6)). */
class NameTruncationTest {
    @Test
    fun shortNamesAreUntouched() {
        assertEquals("Pixel 6 Pro", middleEllipsis("Pixel 6 Pro", 18))
        assertEquals("exactly-18-chars!!", middleEllipsis("exactly-18-chars!!", 18))
    }

    @Test
    fun longNamesKeepHeadAndLastSix() {
        val out = middleEllipsis("Android SDK built for x86_64", 18)
        assertEquals("Android SDK…x86_64", out)
        assertEquals(18, out.codePointCount(0, out.length))
    }

    @Test
    fun countsCodePointsNotUtf16Units() {
        val name = "😀".repeat(20)
        val out = middleEllipsis(name, 18)
        assertEquals(18, out.codePointCount(0, out.length))
        assertEquals("😀".repeat(11) + "…" + "😀".repeat(6), out)
    }
}
