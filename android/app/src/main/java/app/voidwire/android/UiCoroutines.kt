package app.voidwire.android

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.plus
import kotlinx.coroutines.withContext

/*
 * UI coroutines always run on the main thread, whatever dispatcher the
 * composition was given. Screens do `withContext(Dispatchers.IO) { core call }`
 * and then write Compose state; that state write (and the frame it schedules)
 * must happen on the main thread. A composition's own effect context isn't
 * always main: under the Compose test rule it is an unconfined test
 * dispatcher, so the code after `withContext(IO)` kept running on the IO
 * thread and drove a layout pass there while the main thread drew
 * ("performMeasureAndLayout called during measure layout", android-qa
 * 41192066579). Use these instead of `rememberCoroutineScope` and
 * `LaunchedEffect` (gate `android-ui-coroutines-on-main`).
 */

/** [rememberCoroutineScope], pinned to the main thread. Cancelled with the composition. */
@Composable
fun rememberUiScope(): CoroutineScope {
    val scope = rememberCoroutineScope()
    return remember(scope) { scope + Dispatchers.Main.immediate }
}

/** [LaunchedEffect], with the body on the main thread. */
@Composable
fun UiEffect(vararg keys: Any?, block: suspend CoroutineScope.() -> Unit) {
    LaunchedEffect(*keys) { withContext(Dispatchers.Main.immediate, block) }
}
