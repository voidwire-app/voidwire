package app.voidwire.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat

/**
 * Privacy-safe notifications for incoming items from paired PCs (M3.1 §4.1).
 *
 * Hard privacy invariant:
 * - Mobile notifications NEVER contain URLs, hosts/domains, clipboard text,
 *   filenames, file sizes, or sender device names/IDs.
 * - Both the notification and its public lock-screen version always use the
 *   exact generic copy [GENERIC_TITLE] / [GENERIC_BODY] with
 *   [NotificationCompat.VISIBILITY_PRIVATE].
 * - The tap [PendingIntent] opens [MainActivity] with zero extras.
 */
object VoidwireNotifications {
    const val CHANNEL_INCOMING = "voidwire_incoming"
    const val CHANNEL_BACKGROUND = "voidwire_background"
    const val NOTIFICATION_ID_INCOMING = 1001
    const val NOTIFICATION_ID_BACKGROUND = 1002

    const val GENERIC_TITLE = "Voidwire"
    const val GENERIC_BODY = "Voidwire — New item waiting (tap to view)"

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        val incoming = NotificationChannel(
            CHANNEL_INCOMING,
            "Incoming items",
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "Generic alert when a paired PC sends a link, clipboard text, or file"
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        }
        val bg = NotificationChannel(
            CHANNEL_BACKGROUND,
            "Background receive",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Silent status indicator while background receive is turned on"
            lockscreenVisibility = Notification.VISIBILITY_SECRET
            setShowBadge(false)
        }
        nm.createNotificationChannel(incoming)
        nm.createNotificationChannel(bg)
    }

    /**
     * Build the launch intent for tapping an incoming notification.
     * Deliberately carries NO extras so no metadata ever crosses Android's
     * system notification manager.
     */
    fun buildLaunchIntent(context: Context): Intent =
        Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }

    /**
     * Build the privacy-safe generic notification for an incoming item.
     * Takes no item parameters by design so callers cannot pass private data.
     */
    fun buildIncomingNotification(context: Context): Notification {
        ensureChannels(context)
        val launchIntent = buildLaunchIntent(context)
        val pendingFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val pendingIntent = PendingIntent.getActivity(context, 0, launchIntent, pendingFlags)

        val publicVersion = NotificationCompat.Builder(context, CHANNEL_INCOMING)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle(GENERIC_TITLE)
            .setContentText(GENERIC_BODY)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .build()

        return NotificationCompat.Builder(context, CHANNEL_INCOMING)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle(GENERIC_TITLE)
            .setContentText(GENERIC_BODY)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(pendingIntent)
            .build()
    }

    /**
     * Post the generic incoming-item notification if and only if
     * [IncomingNotificationPref.enabled] is true. Returns true if posted.
     */
    fun notifyIncomingIfEnabled(context: Context): Boolean {
        if (!IncomingNotificationPref.enabled(context)) return false
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return false
        return try {
            nm.notify(NOTIFICATION_ID_INCOMING, buildIncomingNotification(context))
            true
        } catch (_: SecurityException) {
            false
        }
    }

    fun cancelIncoming(context: Context) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        nm.cancel(NOTIFICATION_ID_INCOMING)
    }
}
