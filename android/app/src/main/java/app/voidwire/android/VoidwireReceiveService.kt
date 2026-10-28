package app.voidwire.android

import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Event-driven opt-in foreground service for "Receive in background"
 * (M3.1.1, default OFF).
 *
 * Keeps the persistent `iroh` QUIC endpoint alive in the background so paired
 * PCs reach the phone directly without periodic relay polling, and pulls the
 * blind RAM device inbox once on service start and on network reconnection.
 */
class VoidwireReceiveService : Service() {
    private val running = AtomicBoolean(false)
    @Volatile private var netCallback: ConnectivityManager.NetworkCallback? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP || !BackgroundReceivePref.enabled(this)) {
            BackgroundReceivePref.setEnabled(this, false)
            stopBackgroundLoop()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        VoidwireNotifications.ensureChannels(this)
        val openPending = PendingIntent.getActivity(
            this,
            1,
            VoidwireNotifications.buildLaunchIntent(this),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = Intent(this, VoidwireReceiveService::class.java).apply { action = ACTION_STOP }
        val stopPending = PendingIntent.getService(
            this,
            2,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(this, VoidwireNotifications.CHANNEL_BACKGROUND)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle("Voidwire")
            .setContentText("Voidwire — Listening for your PC")
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setOngoing(true)
            .setContentIntent(openPending)
            .addAction(0, "Turn off", stopPending)
            .build()

        try {
            startForeground(VoidwireNotifications.NOTIFICATION_ID_BACKGROUND, notification)
        } catch (_: Exception) {
            stopSelf()
            return START_NOT_STICKY
        }

        startBackgroundLoop()
        return START_STICKY
    }

    override fun onDestroy() {
        stopBackgroundLoop()
        super.onDestroy()
    }

    private fun startBackgroundLoop() {
        if (!running.compareAndSet(false, true)) return
        val appContext = applicationContext
        Thread({
            try {
                val phone = Core.phone(appContext)
                phone.setBackgroundListening(true)
                Core.triggerOneShotInboxPull(appContext)
            } catch (_: Exception) {
            }
        }, "voidwire-bg-start").apply {
            isDaemon = true
            start()
        }

        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        if (cm != null && netCallback == null) {
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    if (running.get() && BackgroundReceivePref.enabled(appContext)) {
                        Core.triggerOneShotInboxPull(appContext)
                    }
                }
            }
            try {
                cm.registerDefaultNetworkCallback(cb)
                netCallback = cb
            } catch (_: Exception) {
            }
        }
    }

    private fun stopBackgroundLoop() {
        if (!running.compareAndSet(true, false)) return
        val appContext = applicationContext
        val cb = netCallback
        netCallback = null
        if (cb != null) {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            try {
                cm?.unregisterNetworkCallback(cb)
            } catch (_: Exception) {
            }
        }
        Thread({
            try {
                Core.phone(appContext).setBackgroundListening(false)
            } catch (_: Exception) {
            }
        }, "voidwire-bg-stop").apply {
            isDaemon = true
            start()
        }
    }

    companion object {
        const val ACTION_STOP = "app.voidwire.android.action.STOP_BG_RECEIVE"
        internal val foregroundVisible = AtomicBoolean(false)

        fun setMainActivityVisible(visible: Boolean) {
            foregroundVisible.set(visible)
        }

        fun syncWithPreference(context: Context) {
            val app = context.applicationContext
            if (BackgroundReceivePref.enabled(app)) {
                try {
                    ContextCompat.startForegroundService(app, Intent(app, VoidwireReceiveService::class.java))
                } catch (_: Exception) {
                }
            } else {
                try {
                    app.stopService(Intent(app, VoidwireReceiveService::class.java))
                } catch (_: Exception) {
                }
            }
        }
    }
}
