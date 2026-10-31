package app.voidwire.android

import java.lang.reflect.Proxy
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import uniffi.voidwire_core.IncomingLinkItem
import uniffi.voidwire_core.IncomingListener
import uniffi.voidwire_core.IncomingSnapshot
import uniffi.voidwire_core.PhoneInterface

/**
 * No polling: an incoming item reaches the notification path only because
 * the core fired its change listener, and nothing reads the phone between
 * events.
 */
class IncomingMonitorTest {
    private fun link(id: ULong) = IncomingLinkItem(id, "00", "PC", "https://example.com/", "example.com", 0uL)

    private class FakeCore {
        @Volatile var snap = IncomingSnapshot(emptyList(), emptyList(), emptyList())
        val reads = AtomicInteger(0)
        var listener: IncomingListener? = null
        val phone: PhoneInterface = Proxy.newProxyInstance(
            PhoneInterface::class.java.classLoader,
            arrayOf(PhoneInterface::class.java),
        ) { _, m, args ->
            when (m.name) {
                "pollIncoming" -> { reads.incrementAndGet(); snap }
                "setIncomingListener" -> { listener = args[0] as IncomingListener; Unit }
                "toString" -> "FakeCore"
                "hashCode" -> 0
                "equals" -> false
                else -> throw UnsupportedOperationException(m.name)
            }
        } as PhoneInterface
    }

    private val direct = Executor { it.run() }

    @Test fun newItemNotifiesOnlyWhenTheCoreSaysSo() {
        val core = FakeCore()
        val notified = AtomicInteger(0)
        IncomingMonitor(core.phone, { notified.incrementAndGet() }, direct).start()
        assertNotNull("listener registered", core.listener)
        val listener = core.listener!!
        assertEquals("one initial read, then nothing until an event", 1, core.reads.get())

        // An item lands in the core, but no event yet: nothing reads it.
        core.snap = IncomingSnapshot(listOf(link(1uL)), emptyList(), emptyList())
        assertEquals(1, core.reads.get())
        assertEquals(0, notified.get())

        val v0 = IncomingEvents.version.value
        listener.onChanged()
        assertEquals("the event bumps the UI refresh signal", v0 + 1, IncomingEvents.version.value)
        assertEquals(2, core.reads.get())
        assertEquals("a new item notifies", 1, notified.get())

        listener.onChanged()
        assertEquals("nothing new: no second notification", 1, notified.get())

        core.snap = IncomingSnapshot(listOf(link(1uL), link(2uL)), emptyList(), emptyList())
        listener.onChanged()
        assertEquals(2, notified.get())
    }
}
