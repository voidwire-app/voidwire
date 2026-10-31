package app.voidwire.android

import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import uniffi.voidwire_core.IncomingListener
import uniffi.voidwire_core.IncomingSnapshot
import uniffi.voidwire_core.PhoneInterface

/**
 * Change events from the core (no polling, no timers). The core calls the
 * registered [IncomingListener] when an item, prompt or file offer arrives or
 * changes; the screens collect [version] and refresh only then.
 */
object IncomingEvents {
    private val _version = MutableStateFlow(0L)

    /** Bumped on every core change event; collectors refresh on each value. */
    val version: StateFlow<Long> = _version

    fun changed() {
        _version.update { it + 1 }
    }
}

/** Which incoming ids were already seen, so only new arrivals notify. */
internal class IncomingTracker(initial: IncomingSnapshot?) {
    private var links: Set<ULong> = initial?.links?.map { it.id }?.toSet() ?: emptySet()
    private var clips: Set<ULong> = initial?.clipboards?.map { it.id }?.toSet() ?: emptySet()
    private var files: Set<String> = initial?.files?.map { it.transferId }?.toSet() ?: emptySet()

    /** Record [snap]; true if it holds anything not seen before. */
    fun update(snap: IncomingSnapshot): Boolean {
        val hasNew = snap.links.any { it.id !in links } ||
            snap.clipboards.any { it.id !in clips } ||
            snap.files.any { it.transferId !in files }
        links = snap.links.map { it.id }.toSet()
        clips = snap.clipboards.map { it.id }.toSet()
        files = snap.files.map { it.transferId }.toSet()
        return hasNew
    }
}

/**
 * Registers the core change listener on [client]. On each event: bump
 * [IncomingEvents.version], then (coalesced, on [worker]) read the snapshot
 * once and call [onNewItem] if something new arrived. Nothing runs between
 * events.
 */
internal class IncomingMonitor(
    private val client: PhoneInterface,
    private val onNewItem: () -> Unit,
    private val worker: Executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "voidwire-incoming").apply { isDaemon = true }
    },
) {
    private val tracker = IncomingTracker(runCatching { client.pollIncoming() }.getOrNull())
    private val queued = AtomicBoolean(false)

    fun start() {
        client.setIncomingListener(object : IncomingListener {
            override fun onChanged() {
                IncomingEvents.changed()
                if (!queued.compareAndSet(false, true)) return
                worker.execute {
                    queued.set(false)
                    val snap = runCatching { client.pollIncoming() }.getOrNull() ?: return@execute
                    if (tracker.update(snap)) onNewItem()
                }
            }
        })
    }
}
