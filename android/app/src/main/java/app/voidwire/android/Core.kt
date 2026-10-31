package app.voidwire.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import java.util.concurrent.atomic.AtomicBoolean
import uniffi.voidwire_core.Phone

/**
 * M1.1 privacy rule: nothing beyond the sealed state file is kept unless the
 * user turned it on. Runs once per process before the phone starts.
 */
object Privacy {
    @Volatile private var done = false

    fun enforce(context: Context) {
        if (done) return
        RecentSends.enforce(context)
        // M1 kept the last-picked PC on disk without asking; now only while
        // "Remember last PC" is on (round 2, off by default).
        LastPc.enforce(context)
        BackgroundReceivePref.enforce(context)
        ThemePref.syncWindowNightMode(context)
        done = true
    }
}

/** Process-wide phone client (one identity per install). */
object Core {
    @Volatile private var phone: Phone? = null
    private val monitorStarted = AtomicBoolean(false)
    private val pullingInbox = AtomicBoolean(false)

    /**
     * Blocking (loads state, binds the QUIC socket): call off the main thread.
     * Installs the JNI context first (C1); if that failed, `Phone()` throws
     * `PhoneException.NotInitialized` instead of the process aborting.
     */
    fun phone(context: Context): Phone = phone ?: synchronized(this) {
        val appContext = context.applicationContext
        NativeInit.init(appContext)
        Privacy.enforce(appContext)
        phone ?: Phone(
            KeystoreStateStorage(appContext),
            KeystoreStateStorage(appContext, SETTINGS_FILE),
            defaultName(appContext),
        ).also {
            it.setDataDir(appContext.noBackupFilesDir.absolutePath)
            phone = it
            startIncomingMonitor(appContext, it)
        }
    }

    /**
     * Triggers a single non-blocking pull from the blind device inbox on a
     * background thread (coalescing concurrent calls).
     */
    fun triggerOneShotInboxPull(context: Context, force: Boolean = true) {
        if (!pullingInbox.compareAndSet(false, true)) return
        val appContext = context.applicationContext
        Thread({
            try {
                // force = app open; unlock / network events pull each relay
                // at most every 5 minutes (enforced in the core).
                phone(appContext).pullDeviceInboxOnEvent(force)
            } catch (_: Exception) {
            } finally {
                pullingInbox.set(false)
            }
        }, "voidwire-inbox-pull").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Tells the core whether the app UI is open (relay supervisor: phones keep
     * only their home relay while closed). Off the main thread, never throws.
     */
    fun setAppForeground(context: Context, foreground: Boolean) {
        val appContext = context.applicationContext
        Thread({
            try {
                phone(appContext).setAppForeground(foreground)
            } catch (_: Exception) {
            }
        }, "voidwire-fg").apply {
            isDaemon = true
            start()
        }
    }

    /** The OS reported a new default network: parked relays retry now. */
    fun notifyNetworkChanged(context: Context) {
        val appContext = context.applicationContext
        Thread({
            try {
                phone(appContext).networkChanged()
            } catch (_: Exception) {
            }
        }, "voidwire-net").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Event-driven incoming monitor (no polling, no timers): the core calls
     * back when an item, prompt or file offer arrives or changes. Screens
     * refresh on [IncomingEvents.version]; while [MainActivity] isn't in the
     * foreground a new item posts the generic notification if enabled.
     */
    private fun startIncomingMonitor(appContext: Context, client: Phone) {
        if (!monitorStarted.compareAndSet(false, true)) return
        IncomingMonitor(client, onNewItem = {
            if (!VoidwireReceiveService.foregroundVisible.get()) {
                VoidwireNotifications.notifyIncomingIfEnabled(appContext)
            }
        }).start()
    }

    private fun defaultName(context: Context): String {
        val user = Settings.Global.getString(context.contentResolver, Settings.Global.DEVICE_NAME)
        val name = user?.takeIf { it.isNotBlank() } ?: "${Build.MANUFACTURER} ${Build.MODEL}"
        return name.filter { !it.isISOControl() }.take(64).ifBlank { "Android phone" }
    }

    /** False when the phone has no Wi-Fi/Ethernet network (the PC can't be on it). */
    fun onLocalNetwork(context: Context): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
    }

    /**
     * mDNS answers are multicast; many phones drop them unless an app holds a
     * MulticastLock. Held only for the duration of [block] (no background
     * work, no foreground service).
     */
    fun <T> withMulticast(context: Context, block: () -> T): T {
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val lock = wifi.createMulticastLock("voidwire-mdns").apply { setReferenceCounted(true) }
        lock.acquire()
        try {
            return block()
        } finally {
            lock.release()
        }
    }
}
