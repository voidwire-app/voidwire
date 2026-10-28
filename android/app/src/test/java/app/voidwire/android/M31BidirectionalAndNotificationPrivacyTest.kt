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
        assertEquals("Voidwire — New item waiting (tap to view)", text)
        assertEquals(Notification.VISIBILITY_PRIVATE, notification.visibility)
        assertNotNull(notification.publicVersion)
        assertEquals(
            "Voidwire — New item waiting (tap to view)",
            notification.publicVersion.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString(),
        )
        assertTrue((notification.flags and Notification.FLAG_AUTO_CANCEL) != 0)

        val launch = VoidwireNotifications.buildLaunchIntent(context)
        assertNull("launch intent must carry no extras", launch.extras)
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
                override fun parse(shared: String?) =
                    if (shared != null && (shared.startsWith("https://") || shared.startsWith("http://"))) {
                        ShareParsing.Result(true, "Link received", shared)
                    } else {
                        ShareParsing.Result(false, "No link found", "no link")
                    }

                override fun classifyText(shared: String?): ShareTextCandidate? {
                    if (shared.isNullOrBlank()) return null
                    return ShareTextCandidate(shared, sensitive = shared.startsWith("ghp_"))
                }

                override fun pairedPcs() = pcs
                override fun send(pc: ShareTarget, url: String) =
                    ShareSendResult.Failed("unexpected URL send")
                override fun sendText(pc: ShareTarget, text: String): ShareSendResult {
                    sentTexts += pc.id to text
                    return ShareSendResult.Sent("Sent clipboard text to ${pc.name}.")
                }
            }
        }

        val intent = Intent(context, ShareActivity::class.java).apply {
            action = Intent.ACTION_SEND
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, "Deploy checklist: verify TLS certs")
        }
        val controller = Robolectric.buildActivity(ShareActivity::class.java, intent).setup()
        try {
            val a = controller.get()
            a.onWindowFocusChanged(true)
            assertTrue("expected TextReady, got ${a.ui}", a.ui is ShareUi.TextReady)
            val ready = a.ui as ShareUi.TextReady
            assertEquals("Deploy checklist: verify TLS certs", ready.text)
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
            assertEquals(listOf("pc-1" to "Deploy checklist: verify TLS certs"), sentTexts)
        } finally {
            controller.pause().stop().destroy()
        }

        // Large text (> 7,500 B) stages as shared-text.txt and enters FileReady.
        val largeText = "A".repeat(8_000)
        val largeIntent = Intent(context, ShareActivity::class.java).apply {
            action = Intent.ACTION_SEND
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, largeText)
        }
        val largeCtrl = Robolectric.buildActivity(ShareActivity::class.java, largeIntent).setup()
        try {
            val a = largeCtrl.get()
            assertTrue("expected FileReady for >7500B text, got ${a.ui}", a.ui is ShareUi.FileReady)
            val fileReady = a.ui as ShareUi.FileReady
            assertEquals("shared-text.txt", fileReady.file.displayName)
            assertEquals(8_000L, fileReady.file.sizeBytes)
        } finally {
            largeCtrl.pause().stop().destroy()
        }
    }
}
