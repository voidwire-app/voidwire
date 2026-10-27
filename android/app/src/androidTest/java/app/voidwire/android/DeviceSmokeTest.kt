package app.voidwire.android

import android.content.Context
import android.content.Intent
import android.view.InputDevice
import android.view.MotionEvent
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.CoordinatesProvider
import androidx.test.espresso.action.GeneralClickAction
import androidx.test.espresso.action.Press
import androidx.test.espresso.action.Tap
import androidx.test.espresso.matcher.ViewMatchers.isRoot
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Collections

/**
 * QA M1 re-check C1: on a real Android runtime (device or emulator), building
 * the phone client and opening both activities must not crash the process.
 * Before the fix, `Phone()` aborted in iroh's DNS resolver ("android context
 * was not initialized"); an abort kills the instrumentation process, so any
 * crash fails this run as "Process crashed".
 *
 * Run: scripts/android-smoke.sh (emulator, no KVM) or, on a phone,
 * `cd android && ./gradlew connectedDebugAndroidTest`.
 */
@RunWith(AndroidJUnit4::class)
class DeviceSmokeTest {
    private val ctx: Context get() = ApplicationProvider.getApplicationContext()

    @Test fun phoneBuildsOnTheRealRuntime() {
        assertTrue("NativeInit failed", NativeInit.init(ctx))
        val phone = Core.phone(ctx) // the call that used to abort
        assertFalse(phone.deviceName().isBlank())
        phone.pairedPcs() // state loads; nothing paired on a fresh install is fine
    }

    private fun <A : android.app.Activity> assertActivityAlive(s: ActivityScenario<A>) {
        if (!s.state.isAtLeast(Lifecycle.State.RESUMED)) {
            // Under software-emulated CI load, com.android.systemui can briefly ANR and steal
            // window focus with a system dialog, dropping the foreground activity to STARTED.
            try {
                InstrumentationRegistry.getInstrumentation().uiAutomation
                    .executeShellCommand("am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS")
                    .close()
            } catch (_: Exception) {}
            Thread.sleep(1_000)
        }
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
        assertTrue("unexpected lifecycle state: ${s.state}", s.state.isAtLeast(Lifecycle.State.STARTED))
        s.onActivity { a ->
            assertFalse("activity is finishing", a.isFinishing)
            assertFalse("activity is destroyed", a.isDestroyed)
        }
    }

    @Test fun mainActivityStartsAndStaysUp() {
        ActivityScenario.launch(MainActivity::class.java).use { s ->
            // Core.phone() runs on Dispatchers.IO from the first composition;
            // give a slow (software-emulated) runtime time to get there.
            Thread.sleep(8_000)
            assertActivityAlive(s)
        }
    }

    @Test fun shareActivityStartsLoadsPcsAndNeverSends() {
        val i = Intent(ctx, ShareActivity::class.java)
            .setAction(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, "smoke test https://example.com/smoke")
        ActivityScenario.launch<ShareActivity>(i).use { s ->
            Thread.sleep(8_000) // loadTargets() → Core.phone().pairedPcs()
            assertActivityAlive(s)
        }
    }

    @After fun restore() = ShareActivity.resetForTests()

    /** Records sends instead of talking to a PC; one paired PC. */
    private class RecordingBackend : ShareBackend {
        val pc = ShareTarget("ab".repeat(32), "Smoke PC")
        val sends: MutableList<String> = Collections.synchronizedList(mutableListOf())
        override fun parse(shared: String?) = ShareParsing.describe(shared)
        override fun pairedPcs() = listOf(pc)
        override fun send(pc: ShareTarget, url: String): ShareSendResult {
            sends += url
            return ShareSendResult.Sent("Sent to ${pc.name}.")
        }
    }

    /**
     * QA M1 final S1: the "Send to <PC>" button must become enabled on its own
     * and a real tap on it (injected through the system input pipeline by
     * Espresso, so it passes the obscured-touch filter and the tap gate
     * exactly like a finger) sends exactly once.
     */
    @Test fun shareSendButtonEnablesAndARealTapSendsOnce() {
        val backend = RecordingBackend()
        ShareActivity.backendFactory = { backend }
        val i = Intent(ctx, ShareActivity::class.java)
            .setAction(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, "tap test https://example.com/s1-tap")
        ActivityScenario.launch<ShareActivity>(i).use { s ->
            // Wait (software emulation is slow) for the button to arm by itself.
            // The button is (correctly) disabled while another window has
            // focus, e.g. a system "isn't responding" dialog on a slow emulator.
            var armed = false
            var why = ""
            for (n in 0 until 240) {
                s.onActivity {
                    armed = it.buttonsArmed && it.sendButtonBounds.containsKey(backend.pc.id)
                    why = "ui=${it.ui::class.simpleName} focus=${it.hasWindowFocus()} button=${it.sendButtonBounds.keys}"
                }
                if (armed) break
                Thread.sleep(250)
            }
            assertTrue("Send button never enabled (S1): $why", armed)
            assertEquals(0, backend.sends.size)
            var centre = floatArrayOf(0f, 0f)
            s.onActivity { a ->
                val b = a.sendButtonBounds.getValue(backend.pc.id)
                val loc = IntArray(2)
                a.window.decorView.getLocationOnScreen(loc)
                centre = floatArrayOf(loc[0] + b.exactCenterX(), loc[1] + b.exactCenterY())
            }
            val atButton = CoordinatesProvider { centre }
            onView(isRoot()).perform(
                GeneralClickAction(Tap.SINGLE, atButton, Press.FINGER, InputDevice.SOURCE_TOUCHSCREEN, MotionEvent.BUTTON_PRIMARY),
            )
            for (n in 0 until 40) {
                if (backend.sends.isNotEmpty()) break
                Thread.sleep(250)
            }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            assertEquals(listOf("https://example.com/s1-tap"), backend.sends.toList())
        }
    }
}
