package app.voidwire.android

import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Lightweight opt-in foreground service for "Receive in background"
 * (M3.1 §1.2 Tier 3, default OFF).
 *
 * Keeps the QUIC endpoint warm and periodically checks for incoming items from
 * paired PCs. When a new item arrives while [MainActivity] is not visible,
 * posts the privacy-safe generic notification via [VoidwireNotifications].
 */
class VoidwireReceiveService : Service() {
    private val running = AtomicBoolean(false)
    @Volatile private var worker: Thread? = null

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
        worker = Thread({
            var lastCount = 0
            try {
                val phone = Core.phone(applicationContext)
                phone.setBackgroundListening(true)
                while (running.get() && BackgroundReceivePref.enabled(applicationContext)) {
                    try {
                        phone.pullDeviceInboxNow()
                    } catch (_: Exception) {
                    }
                    val snap = try {
                        phone.pollIncoming()
                    } catch (_: Exception) {
                        null
                    }
                    val total = (snap?.links?.size ?: 0) +
                        (snap?.clipboards?.size ?: 0) +
                        (snap?.files?.size ?: 0)
                    if (total > lastCount && ! foregroundVisible.get()) {
                        VoidwireNotifications.notifyIncomingIfEnabled(applicationContext)
                    }
                    lastCount = total
                    Thread.sleep(4_000L)
                }
            } catch (_: InterruptedException) {
            } catch (_: Exception) {
            } finally {
                try {
                    Core.phone(applicationContext).setBackgroundListening(false)
                } catch (_: Exception) {
                }
            }
        }, "voidwire-bg-receive").apply {
            isDaemon = true
            start()
        }
    }

    private fun stopBackgroundLoop() {
        running.set(false)
        worker?.interrupt()
        worker = null
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
