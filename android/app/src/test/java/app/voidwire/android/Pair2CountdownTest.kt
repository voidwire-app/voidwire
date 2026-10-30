package app.voidwire.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** M4.3: a shown pairing code lives 5 minutes; the countdown and the expired state. */
class Pair2CountdownTest {
    private val ttl = 300_000L
    private val t0 = 1_000_000L
    private val showing = ShowState.Showing("voidwire:pair?v=2", "VW-CODE", t0 + ttl, ttl)

    @Test fun countsDownFromFiveMinutes() {
        assertEquals("5:00", codeTimeLeft(t0 + ttl, t0))
        assertEquals("4:59", codeTimeLeft(t0 + ttl, t0 + 1_000))
        assertEquals("2:50", codeTimeLeft(t0 + ttl, t0 + 130_000))
        assertEquals("0:01", codeTimeLeft(t0 + ttl, t0 + ttl - 1))
        assertEquals("0:00", codeTimeLeft(t0 + ttl, t0 + ttl + 5_000))
    }

    @Test fun barEmptiesOverTheLifetime() {
        assertEquals(1f, codeProgress(t0 + ttl, t0, ttl), 0.0001f)
        assertEquals(0.5f, codeProgress(t0 + ttl, t0 + ttl / 2, ttl), 0.0001f)
        assertEquals(0f, codeProgress(t0 + ttl, t0 + ttl + 1, ttl), 0.0001f)
        assertEquals(0f, codeProgress(t0, t0, 0), 0.0001f)
    }

    @Test fun expiredCodeOffersNewCodeOtherFailuresDoNot() {
        assertEquals(ShowState.Expired, afterShowFailed(showing, t0 + ttl, "That code expired."))
        val early = afterShowFailed(showing, t0 + 10_000, "The relay refused it.")
        assertTrue(early is ShowState.Failed)
        assertEquals("The relay refused it.", (early as ShowState.Failed).message)
        assertTrue(afterShowFailed(ShowState.Starting, t0 + ttl, null) is ShowState.Failed)
    }

    @Test fun expiredCodeRenewsFiveTimesThenStops() {
        for (n in 0 until MAX_AUTO_RENEW) assertEquals(ShowState.Starting to true, onExpired(n))
        assertEquals(ShowState.Expired to false, onExpired(MAX_AUTO_RENEW))
        assertEquals(5, MAX_AUTO_RENEW)
    }
}
