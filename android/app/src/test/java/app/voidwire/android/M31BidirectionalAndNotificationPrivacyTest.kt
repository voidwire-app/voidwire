package app.voidwire.android

import android.app.Notification
import android.app.NotificationManager
import android.content.ClipDescription
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.view.MotionEvent
import java.io.File
import kotlinx.coroutines.Dispatchers
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * M3.1c unit tests covering:
 * 1. Hard privacy rule on mobile notifications (generic text, VISIBILITY_PRIVATE,
 *    zero extras, no URL/host/clipboard/filename/PC name, opt-out preference).
 * 2. IncomingReceive URL re-verification, sensitive clipboard marking, and file export.
 * 3. First-class Phone -> PC plain-text clipboard sharing in ShareActivity (<= 7,500 B
 *    via sendText, > 7,500 B via staged shared-text.txt).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class M31BidirectionalAndNotificationPrivacyTest {
    private val context: Context = RuntimeEnvironment.getApplication()
    private fun prefsFile(name: String) = File(context.applicationInfo.dataDir, "shared_prefs/$name.xml")

    @Before
    fun setUp() {
        ShareActivity.resetForTests()
        ShareActivity.io = Dispatchers.Main.immediate
        IncomingNotificationPref.wipe(context)
        BackgroundReceivePref.wipe(context)
        VoidwireNotifications.cancelIncoming(context)
    }

    @After
    fun tearDown() {
        ShareActivity.resetForTests()
        IncomingNotificationPref.wipe(context)
        BackgroundReceivePref.wipe(context)
        VoidwireNotifications.cancelIncoming(context)
    }

    @Test
    fun incomingNotificationUsesExactGenericCopyAndPrivateVisibilityWithZeroExtras() {
        val notification = VoidwireNotifications.buildIncomingNotification(context)
        val title = notification.extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()
        val text = notification.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()

        assertEquals("Voidwire", title)
        assertEquals("You have items waiting in Voidwire", text)
        assertEquals(Notification.VISIBILITY_PRIVATE, notification.visibility)
        assertNotNull(notification.publicVersion)
        assertEquals(
            "You have items waiting in Voidwire",
            notification.publicVersion.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString(),
        )
        assertTrue((notification.flags and Notification.FLAG_AUTO_CANCEL) != 0)

        val launch = VoidwireNotifications.buildLaunchIntent(context)
        assertNull("launch intent must carry no extras", launch.extras)
    }

    @Test
    fun manyItemsPostOneGenericNotificationWithNoCountAndOpeningRemovesIt() {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val shadow = shadowOf(nm)
        repeat(3) { assertTrue(VoidwireNotifications.notifyIncomingIfEnabled(context)) }
        val all = shadow.allNotifications
        assertEquals("one notification, never one per item", 1, all.size)
        assertNotNull(shadow.getNotification(VoidwireNotifications.NOTIFICATION_ID_INCOMING))
        val n = all.single()
        val text = n.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
        assertEquals("You have items waiting in Voidwire", text)
        assertEquals("no count", 0, n.number)
        assertFalse("no count in the text", text!!.any { it.isDigit() })
        assertNull("no expanded content", n.extras.getCharSequence(Notification.EXTRA_BIG_TEXT))
        assertTrue("updates stay quiet", (n.flags and Notification.FLAG_ONLY_ALERT_ONCE) != 0)
        // Opening the app (MainActivity.onStart/onResume) clears it.
        VoidwireNotifications.cancelIncoming(context)
        assertEquals(0, shadow.allNotifications.size)
    }

    @Test
    fun incomingNotificationPreferenceDefaultsOnStoresNoFileAndSuppressesWhenOff() {
        assertTrue(IncomingNotificationPref.enabled(context))
        assertFalse("default ON must not create a prefs file", prefsFile("incoming_notif").exists())

        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val shadowNm = shadowOf(nm)
        nm.cancelAll()

        assertTrue(VoidwireNotifications.notifyIncomingIfEnabled(context))
        assertEquals(1, shadowNm.allNotifications.size)

        // Turning notifications OFF persists false and blocks posting.
        IncomingNotificationPref.setEnabled(context, false)
        assertFalse(IncomingNotificationPref.enabled(context))
        VoidwireNotifications.cancelIncoming(context)
        assertFalse(VoidwireNotifications.notifyIncomingIfEnabled(context))
        assertEquals(0, shadowNm.allNotifications.size)

        // Turning notifications back ON deletes the prefs file (zero-footprint default).
        IncomingNotificationPref.setEnabled(context, true)
        assertTrue(IncomingNotificationPref.enabled(context))
        assertFalse(prefsFile("incoming_notif").exists())
    }

    @Test
    fun backgroundReceivePreferenceDefaultsOffAndStoresNoFileWhileOff() {
        assertFalse(BackgroundReceivePref.enabled(context))
        assertFalse("default OFF must not create a prefs file", prefsFile("bg_receive").exists())

        BackgroundReceivePref.setEnabled(context, true)
        assertTrue(BackgroundReceivePref.enabled(context))
        assertTrue(prefsFile("bg_receive").exists())

        BackgroundReceivePref.setEnabled(context, false)
        assertFalse(BackgroundReceivePref.enabled(context))
        assertFalse(prefsFile("bg_receive").exists())
    }

    @Test
    fun verifyBrowserUrlAllowsHttpAndHttpsAndRejectsDangerousOrLocalUrls() {
        assertEquals(
            "https://example.com/path?a=1",
            IncomingReceive.verifyBrowserUrl("https://example.com/path?a=1").getOrThrow(),
        )
        assertTrue(IncomingReceive.verifyBrowserUrl("javascript:alert(1)").isFailure)
        assertTrue(IncomingReceive.verifyBrowserUrl("file:///etc/hosts").isFailure)
        assertTrue(IncomingReceive.verifyBrowserUrl("http://127.0.0.1:8080/admin").isFailure)
        assertTrue(IncomingReceive.verifyBrowserUrl("https://user:pass@example.com/").isFailure)
    }

    @Test
    fun sensitiveClipboardSetsExtraIsSensitiveFlag() {
        val plainClip = IncomingReceive.buildClipData("hello world", sensitive = false)
        assertNull(plainClip.description.extras)

        val secretClip = IncomingReceive.buildClipData("ghp_1234567890abcdefghijklmnopqrstuv", sensitive = true)
        assertNotNull(secretClip.description.extras)
        assertTrue(
            secretClip.description.extras!!.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE, false),
        )
    }

    @Test
    fun shareActivitySendsInlineClipboardTextThroughTapGateAndStagesLargeTextAsFile() {
        var now = 1_000L
        ShareActivity.clock = { now }
        val sentTexts = mutableListOf<Pair<String, String>>()
        val pcs = listOf(ShareTarget("pc-1", "Workstation"))

        ShareActivity.backendFactory = {
            object : ShareBackend {
                override fun parse(shared: String?) = ShareParsing.describe(shared)
                override fun classifyText(shared: String?) = ShareParsing.classifyPlainText(shared)
                override fun pairedPcs() = pcs
                override fun send(pc: ShareTarget, url: String) =
                    ShareSendResult.Failed("unexpected URL send")
                override fun sendText(pc: ShareTarget, text: String): ShareSendResult {
                    sentTexts += pc.id to text
                    return ShareSendResult.Sent("Sent clipboard text to ${pc.name}.")
                }
            }
        }

        for (note in listOf(
            "Note: call Bob at 3pm",
            "TODO: buy milk",
            "Meeting notes:\nhttps://example.com/agenda\nBring laptop",
        )) {
            sentTexts.clear()
            val intent = Intent(context, ShareActivity::class.java).apply {
                action = Intent.ACTION_SEND
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, note)
            }
            val controller = Robolectric.buildActivity(ShareActivity::class.java, intent).setup()
            try {
                val a = controller.get()
                a.onWindowFocusChanged(true)
                assertTrue("expected TextReady for '$note', got ${a.ui}", a.ui is ShareUi.TextReady)
                val ready = a.ui as ShareUi.TextReady
                assertEquals(note, ready.text)
                assertFalse(ready.sensitive)

                // Before arm delay: tap is blocked.
                assertFalse(a.onSendTapped("pc-1"))
                assertTrue(sentTexts.isEmpty())

                // Advance clock past ARM_DELAY_MS and deliver finger-down.
                now += ShareActivity.ARM_DELAY_MS + 50L
                val down = MotionEvent.obtain(
                    SystemClock.uptimeMillis(),
                    SystemClock.uptimeMillis(),
                    MotionEvent.ACTION_DOWN,
                    10f,
                    10f,
                    0,
                )
                a.dispatchTouchEvent(down)
                down.recycle()

                assertTrue(a.onSendTapped("pc-1"))
                assertEquals(listOf("pc-1" to note), sentTexts)
            } finally {
                controller.pause().stop().destroy()
            }
        }

        // Large text (> 7,680 B) stages as shared-text.txt and enters FileReady.
        val largeText = "A".repeat(8_000)
        val largeIntent = Intent(context, ShareActivity::class.java).apply {
            action = Intent.ACTION_SEND
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, largeText)
        }
        val largeCtrl = Robolectric.buildActivity(ShareActivity::class.java, largeIntent).setup()
        try {
            val a = largeCtrl.get()
            assertTrue("expected FileReady for >7680B text, got ${a.ui}", a.ui is ShareUi.FileReady)
            val fileReady = a.ui as ShareUi.FileReady
            assertEquals("shared-text.txt", fileReady.file.displayName)
            assertEquals(8_000L, fileReady.file.sizeBytes)
        } finally {
            largeCtrl.pause().stop().destroy()
        }
    }

    @Test
    fun exportVerifiedFileToDownloadsStreamsAndDeletesStagedSource() {
        assertEquals(7680, IncomingReceive.MAX_INLINE_CLIPBOARD_BYTES)
        val staged = File(context.cacheDir, "staged-incoming-test.bin")
        val payload = ByteArray(150_000) { (it % 251).toByte() }
        java.nio.file.Files.write(staged.toPath(), payload)
        assertTrue(staged.exists())

        val label = IncomingReceive.exportVerifiedFileToDownloads(
            context,
            staged.absolutePath,
            "report.bin",
        )
        assertTrue("unexpected export label: $label", label.startsWith("Downloads/Voidwire/report"))
        assertFalse("staged source file must be deleted after streaming export", staged.exists())
    }
}
