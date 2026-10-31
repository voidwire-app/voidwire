package app.voidwire.android

import android.os.Looper
import androidx.activity.compose.setContent
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Collections
import java.util.concurrent.CountDownLatch

/**
 * android-qa 41192066579: under the Compose test rule a composition's effect
 * context is an unconfined test dispatcher, so code after
 * `withContext(Dispatchers.IO)` in a plain `rememberCoroutineScope` /
 * `LaunchedEffect` kept running on the IO thread and wrote state (and ran a
 * layout pass) there while the main thread drew: FATAL "performMeasureAndLayout
 * called during measure layout". `rememberUiScope` and `UiEffect` must come
 * back to the main thread after IO, in this exact setup.
 */
@RunWith(AndroidJUnit4::class)
class UiThreadTest {
    @get:Rule val compose = createEmptyComposeRule()

    @Test fun uiScopeAndUiEffectResumeOnMainAfterIo() {
        val onMain = Collections.synchronizedList(mutableListOf<String>())
        val done = CountDownLatch(2)
        fun mark(tag: String) {
            if (Looper.myLooper() == Looper.getMainLooper()) onMain.add(tag)
            done.countDown()
        }
        ActivityScenario.launch(MainActivity::class.java).use { s ->
            s.onActivity { a ->
                a.setContent {
                    val scope = rememberUiScope()
                    DisposableEffect(Unit) {
                        scope.launch {
                            withContext(Dispatchers.IO) { Thread.sleep(50) }
                            mark("scope")
                        }
                        onDispose {}
                    }
                    UiEffect(Unit) {
                        withContext(Dispatchers.IO) { Thread.sleep(50) }
                        mark("effect")
                    }
                }
            }
            // The rule's frame clock only advances while the test waits through
            // it; a bare latch await never let the composition apply.
            compose.waitUntil(timeoutMillis = 20_000) { done.count == 0L }
            assertEquals(setOf("scope", "effect"), onMain.toSet())
        }
    }
}
