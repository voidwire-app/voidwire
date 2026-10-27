package app.voidwire.android

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.os.Looper
import android.view.MotionEvent
import kotlinx.coroutines.Dispatchers
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.time.Duration
import java.util.Collections

/**
 * QA M1 High: ShareActivity is exported, so any app can start it. Starting
 * it (any number of times, with any intents, in any lifecycle state) must
 * never send; only an explicit tap that passes the TapGate does, once.
 *
 * QA M1 final S1: every "tap" here is a real finger press (ACTION_DOWN then
 * ACTION_UP at the centre of the actual "Send to <PC>" button) dispatched
 * through Activity.dispatchTouchEvent, so it goes through the obscured-touch
 * filter, the Compose button (which ignores it while disabled) and its
 * onClick. No test calls onSendTapped() to stand in for a click.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
// Round 2: the gold Send button is chamfered (CutCornerShape); Compose hit-
// tests a clipped generic outline with real Path math, which Robolectric
// only has in native graphics mode (legacy mode misses every tap).
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class ShareActivityTest {
    private class FakeBackend(private val pcs: List<ShareTarget>) : ShareBackend {
        val sends: MutableList<Pair<String, String>> = Collections.synchronizedList(mutableListOf())
        val fileCalls: MutableList<Triple<String, String, String?>> = Collections.synchronizedList(mutableListOf())
        var stagedToReturn: StagedShareFile? = null
        var requireRelayPrompt: Boolean = false

        override fun parse(shared: String?): ShareParsing.Result =
            if (shared != null && (shared.startsWith("https://") || shared.startsWith("http://"))) {
                ShareParsing.Result(true, "Link received", shared)
            } else {
                ShareParsing.Result(false, "No link found", "no link")
            }
        override fun pairedPcs() = pcs
        override fun send(pc: ShareTarget, url: String): ShareSendResult {
            sends += pc.id to url
            return ShareSendResult.Sent("Sent to ${pc.name}.")
        }
        override fun stageFile(context: android.content.Context, uri: android.net.Uri, mime: String?): StagedShareFile =
            stagedToReturn ?: super.stageFile(context, uri, mime)
        override fun sendFile(
            pc: ShareTarget,
            filePath: String,
            displayName: String,
            sizeBytes: Long,
            mime: String,
            relayDecision: String?,
        ): FileShareOutcome {
            fileCalls += Triple(pc.id, filePath, relayDecision)
            return when {
                relayDecision == "cancel" -> FileShareOutcome.Failed("Transfer cancelled.")
                requireRelayPrompt && relayDecision == null -> FileShareOutcome.RelayPromptNeeded(
                    sizeBytes = sizeBytes,
                    promptText = "Not on the same network — send ${FileShareStaging.formatSize(sizeBytes)} via relay?",
                )
                else -> FileShareOutcome.Sent("Sent $displayName to ${pc.name}.")
            }
        }
    }

    private val onePc = listOf(ShareTarget("aa".repeat(32), "Desk PC"))
    private val twoPcs = onePc + ShareTarget("bb".repeat(32), "Laptop")
    private var now = 1_000_000L
    private lateinit var backend: FakeBackend

    private fun use(pcs: List<ShareTarget>) {
        backend = FakeBackend(pcs)
        ShareActivity.backendFactory = { backend }
    }

    @Before fun setUp() {
        // Install-time (normal) permission; Robolectric doesn't auto-grant it.
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(android.Manifest.permission.HIDE_OVERLAY_WINDOWS)
        ShareActivity.clock = { now }
        ShareActivity.io = Dispatchers.Unconfined
        use(onePc)
    }

    @After fun tearDown() = ShareActivity.resetForTests()

    private fun shareIntent(text: String) = Intent(Intent.ACTION_SEND).apply {
        component = ComponentName(RuntimeEnvironment.getApplication(), ShareActivity::class.java)
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }

    private fun idle() = shadowOf(Looper.getMainLooper()).idle()

    /** Move both the fake gate clock and the main looper (UI re-checks, frames). */
    private fun advance(ms: Long) {
        now += ms
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(ms))
    }

    private fun motion(action: Int, flags: Int = 0, x: Float = 10f, y: Float = 10f, downTime: Long = now): MotionEvent {
        val p = arrayOf(MotionEvent.PointerProperties().apply { id = 0; toolType = MotionEvent.TOOL_TYPE_FINGER })
        val c = arrayOf(MotionEvent.PointerCoords().apply { this.x = x; this.y = y; pressure = 1f; size = 1f })
        return MotionEvent.obtain(downTime, now, action, 1, p, c, 0, 0, 1f, 1f, 0, 0, 0x1002, flags)
    }

    /** Centre of the real "Send to <PC>" button, in window coordinates. */
    private fun centre(a: ShareActivity, pcId: String): Pair<Float, Float>? =
        a.sendButtonBounds[pcId]?.let { it.exactCenterX() to it.exactCenterY() }

    private fun started(a: ShareActivity) =
        a.ui is ShareUi.Sending || a.ui is ShareUi.Done || a.ui is ShareUi.FileSending || a.ui is ShareUi.RelayPrompt

    /**
     * A real finger tap on the PC's Send button: DOWN, 50 ms, UP at the
     * button's centre, through Activity.dispatchTouchEvent. Returns whether
     * this tap started a send (the screen moved on, or the backend got one).
     */
    private fun tap(a: ShareActivity, pcId: String, flags: Int = 0): Boolean {
        val before = backend.sends.size + backend.fileCalls.size
        val wasStarted = started(a)
        val (x, y) = centre(a, pcId) ?: return false // no such button on screen
        val down = now
        a.dispatchTouchEvent(motion(MotionEvent.ACTION_DOWN, flags, x, y, down))
        advance(50)
        a.dispatchTouchEvent(motion(MotionEvent.ACTION_UP, flags, x, y, down))
        idle()
        return (backend.sends.size + backend.fileCalls.size) > before || (!wasStarted && started(a))
    }

    /** Launch like the share sheet (or a hostile app) would, fully on screen. */
    private fun launch(text: String, state: Bundle? = null): ActivityController<ShareActivity> {
        val c = Robolectric.buildActivity(ShareActivity::class.java, shareIntent(text))
        c.create(state).start().postCreate(state).resume().visible().windowFocusChanged(true)
        idle()
        advance(0)
        return c
    }

    @Test fun programmaticLaunchNeverSends() {
        val c = launch("https://example.com/a")
        advance(10_000)
        idle()
        assertTrue(c.get().ui is ShareUi.Ready)
        assertEquals(0, backend.sends.size)
        // Even with two PCs, or a full lifecycle round, nothing goes out.
        c.pause().stop().destroy()
        use(twoPcs)
        val c2 = launch("https://example.com/b")
        advance(10_000)
        c2.pause().stop().start().resume().windowFocusChanged(true)
        idle()
        assertEquals(0, backend.sends.size)
    }

    @Test fun repeatedAndNewIntentsNeverSend() {
        val c = launch("https://example.com/first")
        repeat(5) { i ->
            advance(1_000)
            c.newIntent(shareIntent("https://evil.example/$i"))
            idle()
        }
        // Several fresh launches too (each share is a new instance).
        repeat(3) { launch("https://evil.example/fresh$it") }
        advance(10_000)
        idle()
        assertEquals(0, backend.sends.size)
        // A re-delivered intent never replaces what the user is looking at.
        assertEquals("https://example.com/first", (c.get().ui as ShareUi.Ready).url)
        assertTrue(c.get().ignoredIntents >= 1)
    }

    @Test fun backgroundedIntentNeverSendsOrShows() {
        val c = launch("https://example.com/shown")
        c.pause().stop()
        c.newIntent(shareIntent("https://evil.example/background"))
        assertEquals(1, c.get().ignoredIntents)
        // A tap attempt while backgrounded does nothing.
        advance(10_000)
        assertFalse(tap(c.get(), onePc[0].id))
        c.start().resume().windowFocusChanged(true)
        idle()
        assertEquals("https://example.com/shown", (c.get().ui as ShareUi.Ready).url)
        assertEquals(0, backend.sends.size)
    }

    @Test fun restoredStateNeverSends() {
        val c = launch("https://example.com/r")
        val saved = Bundle()
        c.saveInstanceState(saved).pause().stop().destroy()
        launch("https://example.com/r", saved)
        advance(10_000)
        idle()
        assertEquals(0, backend.sends.size)
    }

    @Test fun tapsBeforeDelayWithoutFocusOrResumeDoNotCount() {
        val c = launch("https://example.com/t")
        val a = c.get()
        // Too early: < 500 ms after the content appeared.
        advance(ShareActivity.ARM_DELAY_MS - 1)
        assertFalse(tap(a, onePc[0].id))
        // Window lost focus (e.g. a dialog/overlay took it): no.
        advance(10_000)
        c.windowFocusChanged(false)
        assertFalse(tap(a, onePc[0].id))
        // Focus back: the delay starts again.
        c.windowFocusChanged(true)
        assertFalse(tap(a, onePc[0].id))
        advance(ShareActivity.ARM_DELAY_MS)
        // Paused: no.
        c.pause()
        assertFalse(tap(a, onePc[0].id))
        assertEquals(0, backend.sends.size)
    }

    @Test fun explicitTapAfterDelaySendsExactlyOnce() {
        use(twoPcs)
        val c = launch("https://example.com/go")
        val a = c.get()
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(tap(a, twoPcs[1].id))
        // Double tap / second button: still one send.
        assertFalse(tap(a, twoPcs[1].id))
        assertFalse(tap(a, twoPcs[0].id))
        idle()
        assertEquals(listOf(twoPcs[1].id to "https://example.com/go"), backend.sends.toList())
        assertTrue(a.ui is ShareUi.Done)
    }

    @Test fun onePcIsOneTapAway() {
        val c = launch("https://example.com/one")
        val ready = c.get().ui as ShareUi.Ready
        assertEquals(onePc, ready.pcs)
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(tap(c.get(), onePc[0].id))
        idle()
        assertEquals(1, backend.sends.size)
    }

    @Test fun unknownPcOrInvalidLinkNeverSends() {
        val c = launch("https://example.com/x")
        advance(10_000)
        assertFalse(tap(c.get(), "cc".repeat(32)))
        val bad = launch("javascript:alert(1)")
        advance(10_000)
        assertTrue(bad.get().ui is ShareUi.Invalid)
        assertFalse(tap(bad.get(), onePc[0].id))
        assertEquals(0, backend.sends.size)
    }

    // ---- QA M1 final S1: real clicks on the real button ---------------------

    @Test fun s1SendButtonEnablesAfterTheDelayWithoutAnyTouch() {
        val c = launch("https://example.com/s1")
        val a = c.get()
        assertTrue(a.ui is ShareUi.Ready)
        assertTrue("the Send button is on screen", a.sendButtonBounds.containsKey(onePc[0].id))
        assertFalse(a.buttonsArmed)
        advance(ShareActivity.ARM_DELAY_MS - 1)
        assertFalse(a.buttonsArmed)
        advance(1)
        assertTrue("enabled by the delay alone, no finger needed", a.buttonsArmed)
        // Focus lost: disabled; regained: enabled again once the delay passes.
        c.windowFocusChanged(false)
        idle()
        assertFalse(a.buttonsArmed)
        c.windowFocusChanged(true)
        idle()
        assertFalse(a.buttonsArmed)
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(a.buttonsArmed)
        // Pause / resume: same.
        c.pause()
        idle()
        assertFalse(a.buttonsArmed)
        c.resume()
        idle()
        assertFalse(a.buttonsArmed)
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(a.buttonsArmed)
        // An overlay re-arm disables it, and it comes back by itself.
        a.dispatchTouchEvent(motion(MotionEvent.ACTION_DOWN, MotionEvent.FLAG_WINDOW_IS_OBSCURED))
        idle()
        assertFalse(a.buttonsArmed)
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(a.buttonsArmed)
        assertEquals(0, backend.sends.size)
    }

    @Test fun s1RealClickOnEnabledButtonSendsExactlyOnce() {
        val c = launch("https://example.com/real")
        val a = c.get()
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(a.buttonsArmed)
        assertTrue(tap(a, onePc[0].id))
        // More taps on the same spot (double tap, impatient user): nothing more.
        assertFalse(tap(a, onePc[0].id))
        assertFalse(tap(a, onePc[0].id))
        advance(2_000)
        assertEquals(listOf(onePc[0].id to "https://example.com/real"), backend.sends.toList())
    }

    @Test fun s1RealClickBeforeArmingDoesNotSend() {
        val c = launch("https://example.com/early-click")
        val a = c.get()
        // Taps all through the delay: the button is disabled and swallows them.
        repeat(4) {
            assertFalse(a.buttonsArmed)
            assertFalse(tap(a, onePc[0].id))
            advance(50)
        }
        assertEquals(0, backend.sends.size)
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(tap(a, onePc[0].id))
        idle()
        assertEquals(1, backend.sends.size)
    }

    @Test fun s1ObscuredRealClickDoesNotSend() {
        val c = launch("https://example.com/obscured-click")
        val a = c.get()
        advance(10_000)
        assertTrue(a.buttonsArmed)
        for (f in listOf(MotionEvent.FLAG_WINDOW_IS_OBSCURED, MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)) {
            assertFalse(tap(a, onePc[0].id, flags = f))
            assertEquals(0, backend.sends.size)
            advance(10_000) // even long after the overlay has gone, that tap is not replayed
            assertEquals(0, backend.sends.size)
        }
        assertTrue(tap(a, onePc[0].id))
        idle()
        assertEquals(1, backend.sends.size)
    }

    @Test fun s1ProgrammaticLaunchLeavesButtonEnabledButNeverSends() {
        use(twoPcs)
        val c = launch("https://example.com/idle")
        advance(60_000)
        assertTrue(c.get().buttonsArmed)
        assertEquals(0, backend.sends.size)
    }

    @Test fun tapGateRules() {
        val g = TapGate(500)
        assertFalse(g.allows(0))
        g.onResumed(0)
        assertFalse(g.allows(1_000)) // no focus
        g.onFocus(true, 1_000)
        g.onDown(1_499)
        assertFalse(g.allows(1_499))
        assertFalse("finger went down before arming", g.allows(1_500))
        g.onDown(1_500)
        assertTrue(g.allows(1_500))
        g.rearm(2_000)
        assertFalse(g.allows(2_400))
        g.onDown(2_500)
        assertTrue(g.allows(2_500))
        g.onPaused()
        assertFalse(g.allows(9_999))
        // S1: the look depends on time + lifecycle only, never on a finger.
        val t = TapGate(500)
        t.onResumed(0); t.onFocus(true, 0)
        assertFalse(t.timeArmed(499))
        assertTrue(t.timeArmed(500))
        assertFalse("no finger yet: a click wouldn't count", t.allows(500))
        t.onFocus(false, 600)
        assertFalse(t.timeArmed(10_000))
    }

    // ---- QA M1 re-check L1 -------------------------------------------------

    @Test fun obscuredTouchRestartsTheDelay() {
        val c = launch("https://example.com/ov")
        val a = c.get()
        advance(10_000)
        // An overlay sits over us: Android flags the touch; it's dropped and
        // the delay starts again.
        for (f in listOf(MotionEvent.FLAG_WINDOW_IS_OBSCURED, MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)) {
            assertFalse(a.dispatchTouchEvent(motion(MotionEvent.ACTION_DOWN, f)))
            // Overlay gone, the very next tap lands on Send: refused.
            advance(50)
            assertFalse(tap(a, onePc[0].id))
            advance(ShareActivity.ARM_DELAY_MS - 160) // the tap above took 50 ms
            assertFalse(tap(a, onePc[0].id))
        }
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(tap(a, onePc[0].id))
        idle()
        assertEquals(1, backend.sends.size)
    }

    @Test fun pressStartedBeforeArmingDoesNotCount() {
        val c = launch("https://example.com/early")
        val a = c.get()
        advance(100)
        val (x, y) = centre(a, onePc[0].id)!!
        val down = now
        a.dispatchTouchEvent(motion(MotionEvent.ACTION_DOWN, x = x, y = y, downTime = down)) // "tap fast" game
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(a.buttonsArmed)
        // Lifting that finger on the now-enabled button doesn't click...
        a.dispatchTouchEvent(motion(MotionEvent.ACTION_UP, x = x, y = y, downTime = down))
        idle()
        assertEquals(0, backend.sends.size)
        // ...and the gate itself refuses it too (defence in depth).
        assertFalse("finger went down before the button armed", a.onSendTapped(onePc[0].id))
        assertTrue(tap(a, onePc[0].id))
        idle()
        assertEquals(1, backend.sends.size)
    }

    @Test fun focusRegainedAfterOverlayRestartsTheDelay() {
        val c = launch("https://example.com/focus")
        val a = c.get()
        advance(10_000)
        c.windowFocusChanged(false) // a focusable overlay/dialog took focus
        advance(5_000)
        c.windowFocusChanged(true) // ...and went away
        advance(50)
        assertFalse(tap(a, onePc[0].id))
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(tap(a, onePc[0].id))
    }

    @Test fun hidesOtherAppsOverlaysOnApi31Plus() {
        val a = launch("https://example.com/h").get()
        assertTrue(a.hidesOverlayWindows)
    }

    @Test fun fileShareRelayPromptSendAndCancelDeleteStagingFile() {
        val stagingDir = java.io.File(RuntimeEnvironment.getApplication().cacheDir, "share-staging").apply { mkdirs() }
        val tempFile1 = java.io.File(stagingDir, "photo.png").apply { writeBytes(ByteArray(600_000) { 0x42 }) }
        backend.stagedToReturn = StagedShareFile(tempFile1.absolutePath, "photo.png", 600_000L, "image/png")
        backend.requireRelayPrompt = true

        val intent = Intent(Intent.ACTION_SEND).apply {
            component = ComponentName(RuntimeEnvironment.getApplication(), ShareActivity::class.java)
            type = "image/png"
            putExtra(Intent.EXTRA_STREAM, android.net.Uri.parse("content://app.voidwire.test/photo.png"))
        }
        val c = Robolectric.buildActivity(ShareActivity::class.java, intent)
        c.create(null).start().postCreate(null).resume().visible().windowFocusChanged(true)
        idle()
        advance(0)
        val a = c.get()
        assertTrue("expected FileReady, got ${a.ui}", a.ui is ShareUi.FileReady)
        assertEquals(0, backend.fileCalls.size)

        // Tap Send after arming -> transitions to RelayPrompt ("Not on the same network — send 585.9 KB via relay?")
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(tap(a, onePc[0].id))
        idle()
        val prompt = a.ui as ShareUi.RelayPrompt
        assertTrue(prompt.promptText.contains("Not on the same network — send"))
        assertTrue("staging file kept while awaiting relay prompt decision", tempFile1.exists())

        // Choose "Send via relay" -> sends with relayDecision="send_via_relay" and deletes staging file!
        assertTrue(a.onRelayDecisionTapped(true))
        idle()
        assertEquals(2, backend.fileCalls.size)
        assertEquals("send_via_relay", backend.fileCalls[1].third)
        assertTrue(a.ui is ShareUi.Done)
        assertFalse("staging file must be deleted on completion", tempFile1.exists())

        // Also verify Cancel on RelayPrompt deletes the staging file immediately
        val tempFile2 = java.io.File(stagingDir, "archive.zip").apply { writeBytes(ByteArray(700_000) { 0x24 }) }
        backend.stagedToReturn = StagedShareFile(tempFile2.absolutePath, "archive.zip", 700_000L, "application/zip")
        val c2 = Robolectric.buildActivity(ShareActivity::class.java, intent)
        c2.create(null).start().postCreate(null).resume().visible().windowFocusChanged(true)
        idle()
        advance(ShareActivity.ARM_DELAY_MS)
        assertTrue(tap(c2.get(), onePc[0].id))
        idle()
        assertTrue(c2.get().ui is ShareUi.RelayPrompt)
        assertTrue(c2.get().onRelayDecisionTapped(false))
        idle()
        assertEquals("cancel", backend.fileCalls.last().third)
        assertFalse("staging file must be deleted on cancel", tempFile2.exists())
    }

    @Test fun m27H2RejectsFileSchemePrivateAppDirsAndSelfOwnedFds() {
        val app = RuntimeEnvironment.getApplication()
        val secretFile = java.io.File(app.noBackupFilesDir, "state.bin").apply {
            parentFile?.mkdirs()
            writeBytes(ByteArray(64) { 0x7f })
        }

        // 1. file:// URI pointing to private storage is rejected immediately
        val fileUri = android.net.Uri.fromFile(secretFile)
        val errScheme = org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            FileShareStaging.stage(app, fileUri)
        }
        assertTrue(errScheme.message!!.contains("content://"))

        // 2. content:// URI whose path points inside filesDir / noBackupFilesDir / dataDir is rejected
        val forgedContentUri = android.net.Uri.parse("content://app.voidwire.forged${secretFile.absolutePath}")
        val errPrivatePath = org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            FileShareStaging.stage(app, forgedContentUri)
        }
        assertTrue(errPrivatePath.message!!.contains("internal app files"))

        // 3. Real ParcelFileDescriptor pointing inside app-private directory is rejected via /proc/self/fd
        android.os.ParcelFileDescriptor.open(secretFile, android.os.ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
            val errFdPrivate = org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
                FileShareStaging.verifyDescriptorNotSelfOwnedOrPrivate(app, pfd, disallowOwnUid = false)
            }
            assertTrue(errFdPrivate.message!!.contains("internal app files"))
        }

        // 4. Real ParcelFileDescriptor owned by currentAppUid() is rejected even outside app-private dirs
        val extTemp = java.io.File.createTempFile("vw-uid-check-", ".bin").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val realUid = android.system.Os.getuid()
        val prevUidFn = FileShareStaging.currentAppUid
        try {
            if (realUid > 0) {
                FileShareStaging.currentAppUid = { realUid }
                android.os.ParcelFileDescriptor.open(extTemp, android.os.ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
                    val errUid = org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
                        FileShareStaging.verifyDescriptorNotSelfOwnedOrPrivate(app, pfd, disallowOwnUid = true)
                    }
                    assertTrue(errUid.message!!.contains("internal app files"))
                }
            }
        } finally {
            FileShareStaging.currentAppUid = prevUidFn
            extTemp.delete()
            secretFile.delete()
        }
    }

    @Test fun m27M2SanitizeNameRejectsDotSegmentsAndBoundedStreamDeletesOnOverflow() {
        assertEquals("shared-file", FileShareStaging.sanitizeName("."))
        assertEquals("shared-file", FileShareStaging.sanitizeName(".."))
        assertEquals("shared-file", FileShareStaging.sanitizeName("foo/bar/.."))
        assertEquals("shared-file", FileShareStaging.sanitizeName("\\.."))
        assertEquals("report.pdf", FileShareStaging.sanitizeName("../report.pdf"))

        val app = RuntimeEnvironment.getApplication()
        val uri = android.net.Uri.parse("content://external.provider/stream/oversized.bin")
        // Register a 200 KiB stream with no OpenableColumns.SIZE metadata, and enforce maxBytes = 100 KiB
        shadowOf(app.contentResolver).registerInputStream(
            uri,
            java.io.ByteArrayInputStream(ByteArray(200 * 1024) { 0x33 }),
        )
        val err = org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            FileShareStaging.stage(app, uri, fallbackMime = "application/octet-stream", maxBytes = 100 * 1024L, disallowOwnUid = false)
        }
        assertTrue(err.message!!.contains("2 GB limit"))
        val abortedFile = java.io.File(java.io.File(app.cacheDir, "share-staging"), "oversized.bin")
        assertFalse("aborted stream must delete partial dst file", abortedFile.exists())
    }

    @Test fun m29ModalErrorDialogShownOnRelayDisabledCapExceededAndCanceledOnPc() {
        val dlgNever = PhoneErrors.dialogForDetail(
            "exceeds_relay_cap: never_send_files_over_relay: size=1048576 cap=0",
            "Desk PC",
            neverSendOverRelay = true,
        )
        assertEquals("Relay file transfers disabled", dlgNever.title)
        assertTrue(dlgNever.message.contains("Never send files over relay"))

        val dlgCap = PhoneErrors.dialogForDetail(
            "exceeds_relay_cap: size=43000000 cap=26214400",
            "Desk PC",
            neverSendOverRelay = false,
        )
        assertEquals("File exceeds relay limit", dlgCap.title)
        assertTrue(dlgCap.message.contains("25 MB"))

        val dlgCanceled = PhoneErrors.dialogForDetail(
            "file_chunk_failed: canceled_by_recipient",
            "Desk PC",
        )
        assertEquals("Transfer canceled", dlgCanceled.title)
        assertEquals("Transfer canceled on Desk PC.", dlgCanceled.message)
    }
}
