package app.voidwire.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
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
        ThemePref.syncWindowNightMode(context)
        done = true
    }
}

/** Process-wide phone client (one identity per install). */
object Core {
    @Volatile private var phone: Phone? = null

    /**
     * Blocking (loads state, binds the QUIC socket): call off the main thread.
     * Installs the JNI context first (C1); if that failed, `Phone()` throws
     * `PhoneException.NotInitialized` instead of the process aborting.
     */
    fun phone(context: Context): Phone = phone ?: synchronized(this) {
        NativeInit.init(context.applicationContext)
        Privacy.enforce(context.applicationContext)
        phone ?: Phone(KeystoreStateStorage(context.applicationContext), defaultName(context)).also { phone = it }
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
