package app.voidwire.android

import androidx.compose.ui.semantics.getOrNull
import android.content.Context
import android.graphics.Bitmap
import android.os.ParcelFileDescriptor
import androidx.compose.ui.test.junit4.ComposeTestRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isEnabled
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import uniffi.voidwire_core.NoPointer
import uniffi.voidwire_core.Pairing
import uniffi.voidwire_core.PairingPreview
import uniffi.voidwire_core.ConnectionStatRecord
import uniffi.voidwire_core.FileSendResult
import uniffi.voidwire_core.IncomingSnapshot
import uniffi.voidwire_core.PcInfo
import uniffi.voidwire_core.PhoneInterface
import uniffi.voidwire_core.Pair2Done
import uniffi.voidwire_core.Pair2Opened
import uniffi.voidwire_core.Pair2Show
import uniffi.voidwire_core.Pair2Status
import uniffi.voidwire_core.RelayChoice
import uniffi.voidwire_core.SendResult
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Shared helpers for the android-qa.yml instrumented checks (screenshots,
 * fakes, waits). androidTest only: none of this is in the app APK.
 */
object Qa {
    val ctx: Context get() = ApplicationProvider.getApplicationContext()
    private val inst get() = InstrumentationRegistry.getInstrumentation()

    /** Instrumentation arg (`am instrument -e key value`). */
    fun arg(key: String): String? = InstrumentationRegistry.getArguments().getString(key)

    /** Where shots and hand-off files go; android-qa.sh pulls this folder. */
    val outDir: File get() = File(ctx.getExternalFilesDir(null), "vw-shots").apply { mkdirs() }

    fun shell(cmd: String): String {
        val pfd: ParcelFileDescriptor = inst.uiAutomation.executeShellCommand(cmd)
        return ParcelFileDescriptor.AutoCloseInputStream(pfd).use { String(it.readBytes()) }
    }

    fun osNight(dark: Boolean) {
        shell("cmd uimode night ${if (dark) "yes" else "no"}")
        Thread.sleep(1_500)
    }

    /** The slow CI emulator pops "Process system isn't responding" over the app (7ae8d4e shots). Tap Wait. */
    fun dismissSystemAnr() {
        val dev = androidx.test.uiautomator.UiDevice.getInstance(inst)
        repeat(3) {
            if (!dev.hasObject(androidx.test.uiautomator.By.textContains("isn't responding"))) return
            dev.findObject(androidx.test.uiautomator.By.text("Wait"))?.click()
            Thread.sleep(700)
        }
    }

    fun shot(name: String, settleMs: Long = 1_200) {
        inst.waitForIdleSync()
        Thread.sleep(settleMs)
        dismissSystemAnr()
        val bmp: Bitmap = inst.uiAutomation.takeScreenshot() ?: error("takeScreenshot returned null for $name")
        File(outDir, "$name.png").outputStream().use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
        println("VW-SHOT $name")
    }

    fun has(compose: ComposeTestRule, text: String): Boolean =
        runCatching {
            compose.onAllNodesWithText(text, substring = true, ignoreCase = true, useUnmergedTree = true)
                .fetchSemanticsNodes(atLeastOneRootRequired = false).isNotEmpty()
        }.getOrDefault(false)

    /** Laid-out line counts of the Text nodes whose text is exactly [text]. */
    fun lineCounts(compose: ComposeTestRule, text: String): List<Int> =
        compose.onAllNodesWithText(text, useUnmergedTree = true).fetchSemanticsNodes().mapNotNull { n ->
            val out = mutableListOf<androidx.compose.ui.text.TextLayoutResult>()
            n.config.getOrNull(androidx.compose.ui.semantics.SemanticsActions.GetTextLayoutResult)?.action?.invoke(out)
            out.firstOrNull()?.lineCount
        }

    private val timeoutShots = java.util.concurrent.atomic.AtomicInteger()

    /**
     * Saves the live screen as vw-shots/WAIT-TIMEOUT-<pid>-<n>.png (pid: one file per instrumentation run), then rethrows.
     * FailShotRule runs after ActivityScenario.use has closed the activity,
     * so its shot only shows the launcher (QA 40833274587).
     */
    fun <T> shotOnTimeout(block: () -> T): T = try {
        block()
    } catch (e: Throwable) {
        runCatching { shot("WAIT-TIMEOUT-${android.os.Process.myPid()}-${timeoutShots.incrementAndGet()}", settleMs = 0) }
        throw e
    }

    fun waitText(compose: ComposeTestRule, text: String, timeoutMs: Long = 30_000) =
        shotOnTimeout { compose.waitUntil(timeoutMs) { has(compose, text) } }

    /** The soft keyboard is showing over the resumed activity. */
    fun imeVisible(): Boolean {
        var shown = false
        inst.runOnMainSync {
            val act = androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry.getInstance()
                .getActivitiesInStage(androidx.test.runner.lifecycle.Stage.RESUMED).firstOrNull()
            val root = act?.window?.decorView
            shown = root != null && androidx.core.view.ViewCompat.getRootWindowInsets(root)
                ?.isVisible(androidx.core.view.WindowInsetsCompat.Type.ime()) == true
        }
        return shown
    }

    /**
     * Scanner screen: paste [link] into "Can't scan? Paste the pairing link"
     * and tap "Use link", the way a user does. Each step waits for its
     * precondition (the field holds the link, the keyboard is gone, the button
     * is enabled) and the tap must leave the scanner. QA 40833274587 lost
     * this tap on a slow emulator and then waited 120 s on the next screen.
     */
    fun usePairLink(compose: ComposeTestRule, link: String) {
        compose.waitUntil(30_000) { compose.onAllNodes(hasSetTextAction()).fetchSemanticsNodes().isNotEmpty() }
        compose.onNode(hasSetTextAction()).performScrollTo().performTextInput(link)
        shotOnTimeout {
            compose.waitUntil(10_000) {
                compose.onAllNodes(hasText("Use link") and isEnabled()).fetchSemanticsNodes().isNotEmpty()
            }
        }
        // The tap on "Use link" can be lost while the keyboard or the camera
        // preview is still settling (tag QA 40939711077: the scanner stayed up
        // with the link typed). Tap again, at most 3 times, and only count the
        // scanner as left when it stays gone for a second.
        fun onScanner() = has(compose, "Starts with voidwire:pair?") &&
            !has(compose, "Join a different device group?")
        var left = false
        for (attempt in 0 until 3) {
            androidx.test.espresso.Espresso.closeSoftKeyboard()
            shotOnTimeout { compose.waitUntil(10_000) { !imeVisible() } }
            compose.waitForIdle()
            compose.onNode(hasText("Use link")).performScrollTo().performClick()
            left = runCatching {
                compose.waitUntil(15_000) { !onScanner() }
                Thread.sleep(1_000)
                compose.waitForIdle()
                check(!onScanner())
            }.isSuccess
            if (left || !onScanner()) { left = true; break }
        }
        if (!left) {
            runCatching { shot("WAIT-TIMEOUT-${android.os.Process.myPid()}-${timeoutShots.incrementAndGet()}", settleMs = 0) }
            throw AssertionError("\"Use link\" did not leave the scanner after 3 taps")
        }
    }

    fun prefsFiles(): List<String> =
        File(ctx.applicationInfo.dataDir, "shared_prefs").list()?.sorted() ?: emptyList()
}

/** In-memory phone for UI-only checks: paired PCs; pairing shows a fixed code and waits. */
class FakePhone(pcs: List<PcInfo>, @Volatile var name: String = "Pixel 8 (QA emulator)") : PhoneInterface {
    @Volatile var pcs: List<PcInfo> = pcs
    @Volatile var differentGroup = false
    @Volatile var failNextForget = false
    override fun beginPairing(qr: String, confirmGroupChange: Boolean): Pairing = FakePairing()
    // M4.3 v2 pairing: a fixed code, nothing on the network.
    override fun savedRelays(): List<RelayChoice> = listOf(RelayChoice("relay.voidwire.app", "https://relay.voidwire.app", true, true, true))
    override fun pair2Show(relayUrl: String?) = Pair2Show(
        "voidwire:pair?v=2&id=qa", "VW-QAQA-QAQA-QAQA-QAQA-QAQA-QAQA-QAQA",
        (System.currentTimeMillis() + 300_000).toULong(), relayUrl ?: "https://relay.voidwire.app", 300_000uL,
    )
    override fun pair2Status() = Pair2Status("showing", null, null, null, null)
    override fun pair2SubmitCode(sas: String) = Pair2Done("00", "QA device")
    override fun pair2Cancel() {}
    override fun pair2OpenCode(code: String, relayUrl: String?) = Pair2Opened("QA device", relayUrl ?: "https://relay.voidwire.app", "saved", null)
    override fun pair2OpenQr(qr: String) = Pair2Opened("QA device", "https://relay.voidwire.app", "saved", null)
    override fun pair2AddRelay() {}
    override fun pair2Join() = "123456"
    override fun pair2JoinWait(): Pair2Done {
        Thread.sleep(Long.MAX_VALUE)
        throw IllegalStateException()
    }
    override fun deviceName() = name
    override fun forgetPc(pcIdHex: String) {
        if (failNextForget) {
            failNextForget = false
            throw IllegalStateException("couldn't save")
        }
        pcs = pcs.filter { it.id != pcIdHex }
    }
    override fun inspectPairing(qr: String) = PairingPreview(
        "Office PC", differentGroup, false, if (differentGroup) pcs.map { it.name } else emptyList(),
    )
    override fun pairedPcs() = pcs
    override fun refresh(pcIdHex: String) = true
    override fun sendUrl(pcIdHex: String, url: String) = SendResult(true, false, 12_000uL)
    override fun setDeviceName(name: String) { this.name = name }
    override fun removalCheckWarning(): String? = null
    override fun setMailboxPeer(peerHex: String?) {}
    override fun cancelFileTransfer(pcIdHex: String, transferIdHex: String) {}
    override fun connectionStats(): List<ConnectionStatRecord> = emptyList()
    override fun connectionStatsEnabled(): Boolean = false
    override fun relayFileCapBytes(): ULong = 25uL * 1024uL * 1024uL
    override fun sendFile(
        pcIdHex: String,
        filePath: String,
        mime: String,
        relayDecision: String?,
    ): FileSendResult = FileSendResult("0".repeat(64), "test.txt", 0uL, 0uL, 0uL, false, 0uL)
    @Volatile var neverRelay = false
    @Volatile var customRelayUrl: String? = "https://relay.voidwire.app"
    @Volatile var customMailboxId: String? = "b080fe7101c968a6c827bad4e99d225343faa3bee18ee2a82b799c7a9d2f6840"
    override fun setConnectionStatsEnabled(enabled: Boolean) {}
    override fun setUserRelayCapBytes(capBytes: ULong) { neverRelay = (capBytes == 0uL) }
    override fun neverSendFilesOverRelay(): Boolean = neverRelay
    override fun setNeverSendFilesOverRelay(never: Boolean) { neverRelay = never }
    override fun relayUrl(): String? = customRelayUrl
    override fun setRelayUrl(relayUrl: String?) {
        customRelayUrl = if (relayUrl.isNullOrBlank()) "https://relay.voidwire.app" else relayUrl.trim()
    }
    override fun mailboxId(): String? = customMailboxId
    override fun setMailboxId(peerHex: String?) {
        customMailboxId = if (peerHex.isNullOrBlank()) "b080fe7101c968a6c827bad4e99d225343faa3bee18ee2a82b799c7a9d2f6840" else peerHex.trim()
    }
    @Volatile var incomingSnapshot = IncomingSnapshot(emptyList(), emptyList(), emptyList())
    @Volatile var bgListening = false
    override fun sendClipboardText(pcIdHex: String, text: String) = SendResult(true, false, 12_000uL)
    override fun sendTextOrUrl(pcIdHex: String, rawText: String) = SendResult(true, false, 12_000uL)
    override fun pollIncoming(): IncomingSnapshot = incomingSnapshot
    override fun pullDeviceInboxNow(): UInt = 0u
    override fun dismissIncomingItem(id: ULong) {
        incomingSnapshot = incomingSnapshot.copy(
            links = incomingSnapshot.links.filter { it.id != id },
            clipboards = incomingSnapshot.clipboards.filter { it.id != id },
        )
    }
    override fun acceptIncomingFile(transferId: String, destDir: String): String = "$destDir/received.bin"
    override fun cancelIncomingFile(transferId: String) {
        incomingSnapshot = incomingSnapshot.copy(
            files = incomingSnapshot.files.filter { it.transferId != transferId },
        )
    }
    override fun setDataDir(dataDir: String) {}
    override fun setBackgroundListening(enabled: Boolean) { bgListening = enabled }
    override fun setAppForeground(foreground: Boolean) {}
    override fun networkChanged() {}
    override fun pullDeviceInboxOnEvent(force: Boolean): UInt = 0u
}

class FakePairing : Pairing(NoPointer) {
    private val cancelled = CountDownLatch(1)
    override fun code() = "482913"
    override fun pcName() = "Office PC"
    override fun cancel() = cancelled.countDown()
    override fun wait(timeoutSecs: UInt): PcInfo {
        cancelled.await(timeoutSecs.toLong(), TimeUnit.SECONDS)
        throw IllegalStateException("cancelled")
    }
}

/** Share backend with fixed PCs; records sends, never touches the network. */
class FakeShare(private val pcs: List<ShareTarget>) : ShareBackend {
    val sends = java.util.Collections.synchronizedList(mutableListOf<String>())
    override fun parse(shared: String?) = ShareParsing.describe(shared)
    override fun pairedPcs() = pcs
    override fun send(pc: ShareTarget, url: String): ShareSendResult {
        sends += url
        return ShareSendResult.Sent("Sent to ${pc.name}.")
    }
}

/** Wait for a Send button to arm by itself, then tap its centre like a finger (as DeviceSmokeTest S1). */
fun tapSendWhenArmed(s: androidx.test.core.app.ActivityScenario<ShareActivity>, pcId: String? = null): String {
    var target: String? = null
    var why = ""
    for (n in 0 until 240) {
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
        s.onActivity { a ->
            val id = pcId ?: a.sendButtonBounds.keys.firstOrNull()
            if (a.buttonsArmed && id != null && a.sendButtonBounds.containsKey(id)) target = id
            why = "ui=${a.ui::class.simpleName} focus=${a.hasWindowFocus()} buttons=${a.sendButtonBounds.keys}"
        }
        if (target != null) break
        Thread.sleep(250)
    }
    val id = target ?: error("Send button never armed: $why")
    var centre = floatArrayOf(0f, 0f)
    s.onActivity { a ->
        val b = a.sendButtonBounds.getValue(id)
        val loc = IntArray(2)
        a.window.decorView.getLocationOnScreen(loc)
        centre = floatArrayOf(loc[0] + b.exactCenterX(), loc[1] + b.exactCenterY())
    }
    androidx.test.espresso.Espresso.onView(androidx.test.espresso.matcher.ViewMatchers.isRoot()).perform(
        androidx.test.espresso.action.GeneralClickAction(
            androidx.test.espresso.action.Tap.SINGLE, { centre }, androidx.test.espresso.action.Press.FINGER,
            android.view.InputDevice.SOURCE_TOUCHSCREEN, android.view.MotionEvent.BUTTON_PRIMARY,
        ),
    )
    return id
}

fun shareIntent(text: String): android.content.Intent =
    android.content.Intent(Qa.ctx, ShareActivity::class.java)
        .setAction(android.content.Intent.ACTION_SEND).setType("text/plain")
        .putExtra(android.content.Intent.EXTRA_TEXT, text)

/** Clear every app pref file (theme, recent sends, last PC) to a fresh-install state. */
fun resetAppPrefs() {
    RecentSends.setEnabled(Qa.ctx, false); RecentSends.wipe(Qa.ctx)
    LastPc.setEnabled(Qa.ctx, false); LastPc.wipe(Qa.ctx)
    ThemePref.set(Qa.ctx, app.voidwire.android.ui.theme.ThemeMode.Default)
    IncomingNotificationPref.wipe(Qa.ctx)
    BackgroundReceivePref.wipe(Qa.ctx)
}

/**
 * Failure evidence (d446e01): on a failed test, a screenshot to
 * vw-shots/FAIL-<Class>-<method>.png (android-qa.sh also screencaps).
 */
class FailShotRule : org.junit.rules.TestWatcher() {
    override fun failed(e: Throwable?, d: org.junit.runner.Description) {
        runCatching { Qa.shot("FAIL-${d.testClass?.simpleName}-${d.methodName}", settleMs = 0) }
    }
}
