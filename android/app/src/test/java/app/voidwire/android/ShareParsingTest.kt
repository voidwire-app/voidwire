package app.voidwire.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.voidwire_core.maxPushUrlBytes
import uniffi.voidwire_core.maxUrlBytes

/** Runs the real UniFFI bindings against the host build of voidwire-core. */
class ShareParsingTest {
    @Test fun extractsUrlFromShareText() {
        val r = ShareParsing.describe("Look: https://Example.com/a?b=1 via app")
        assertTrue(r.ok)
        assertEquals("https://example.com/a?b=1", r.body)
    }

    @Test fun rejectsNonHttpSchemes() {
        for (s in listOf("javascript:alert(1)", "file:///etc/passwd", "intent://x#Intent;end", "data:text/html,x")) {
            assertFalse(s, ShareParsing.describe(s).ok)
        }
    }

    @Test fun rejectsEmptyAndPlainText() {
        assertFalse(ShareParsing.describe(null).ok)
        assertFalse(ShareParsing.describe("just words").ok)
    }

    @Test fun rejectsOversize() {
        val r = ShareParsing.describe("https://example.com/" + "a".repeat(9000))
        assertFalse(r.ok)
        assertEquals("Link too long", r.title)
    }

    @Test fun limitsExported() {
        assertEquals(8192u, maxUrlBytes())
        assertEquals(2048u, maxPushUrlBytes())
    }

    @Test fun splitsRecentSendIntoTwoLines() {
        val (top, sub) = SendText.splitRecent("18:36:25  example.com → WORKSTATION: opened 12 ms")
        assertEquals("example.com · opened 12 ms", top)
        assertEquals("18:36:25 → WORKSTATION", sub)
    }
}
