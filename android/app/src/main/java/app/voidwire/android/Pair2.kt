package app.voidwire.android

import android.app.Activity
import android.app.KeyguardManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import app.voidwire.android.ui.Eyebrow
import app.voidwire.android.ui.HintCard
import app.voidwire.android.ui.VwIcons
import app.voidwire.android.ui.VwTopBar
import app.voidwire.android.ui.theme.VoidwireComponentShapes
import app.voidwire.android.ui.theme.VoidwireTheme
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.voidwire_core.PhoneInterface
import uniffi.voidwire_core.RelayChoice

/** M4.3 pairing QR versions (no native call, so UI tests can use it). */
internal object PairQr {
    const val UPDATE_TEXT = "This pairing code needs a newer Voidwire. Update Voidwire on this phone to use it."

    /** "1", "2", … from `voidwire:pair?…&v=N`, or null. */
    fun version(text: String): String? {
        val t = text.trim()
        if (!t.startsWith("voidwire:pair?")) return null
        return t.removePrefix("voidwire:pair?").split('&').firstNotNullOfOrNull { kv ->
            val p = kv.split('=', limit = 2)
            if (p.size == 2 && p[0] == "v") p[1] else null
        }
    }
}

/**
 * Asks for the screen lock (PIN, pattern, password or fingerprint) before
 * `onPass`. A phone with no screen lock set passes straight through.
 */
@Composable
internal fun rememberLockGate(): (String, () -> Unit) -> Unit {
    val context = LocalContext.current
    val pending = remember { mutableStateOf<(() -> Unit)?>(null) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        val p = pending.value
        pending.value = null
        if (r.resultCode == Activity.RESULT_OK) p?.invoke()
    }
    return remember(launcher) {
        { title: String, onPass: () -> Unit ->
            val km = context.getSystemService(KeyguardManager::class.java)
            @Suppress("DEPRECATION")
            val intent = if (km != null && km.isDeviceSecure) km.createConfirmDeviceCredentialIntent(title, null) else null
            if (intent == null) {
                onPass()
            } else {
                pending.value = onPass
                launcher.launch(intent)
            }
        }
    }
}

/** Dark modules on a light plate in both themes, for scanners. */
@Composable
private fun QrImage(text: String, modifier: Modifier = Modifier) {
    val matrix = remember(text) {
        QRCodeWriter().encode(
            text,
            BarcodeFormat.QR_CODE,
            0,
            0,
            mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 2),
        )
    }
    Canvas(modifier.background(Color(0xFFF4F6F9))) {
        val n = matrix.width
        val cell = size.minDimension / n
        for (y in 0 until matrix.height) {
            for (x in 0 until n) {
                if (matrix.get(x, y)) drawRect(Color(0xFF070B14), Offset(x * cell, y * cell), Size(cell + 0.5f, cell + 0.5f))
            }
        }
    }
}

@Composable
private fun RelayPicker(relays: List<RelayChoice>, chosen: String?, onChoose: (String) -> Unit) {
    if (relays.size < 2) return
    Text("Relay (both devices must use the same one)", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        relays.forEach { r ->
            FilterChip(selected = r.url == chosen, onClick = { onChoose(r.url) }, label = { Text(r.nickname) })
        }
    }
}

@Composable
private fun Big(code: String) {
    Text(
        code,
        style = VoidwireTheme.code.codeLarge.copy(fontSize = VoidwireTheme.code.codeMedium.fontSize * 1.6f),
        color = VoidwireTheme.extended.relay,
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun DoneOrFailed(ok: Boolean, title: String, body: String, onDone: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val ext = VoidwireTheme.extended
    Box(
        Modifier.padding(top = 24.dp).size(56.dp).clip(CircleShape).background(if (ok) ext.success.copy(alpha = 0.14f) else cs.errorContainer),
        contentAlignment = Alignment.Center,
    ) {
        Icon(if (ok) VwIcons.Check else VwIcons.Close, contentDescription = null, tint = if (ok) ext.success else cs.error, modifier = Modifier.size(28.dp))
    }
    Text(title, style = MaterialTheme.typography.headlineSmall)
    if (body.isNotEmpty()) Text(body, color = cs.onSurfaceVariant)
    Button(onClick = onDone, modifier = Modifier.fillMaxWidth().height(48.dp), shape = VoidwireComponentShapes.primaryButton, border = primaryButtonBorder()) {
        Text(if (ok) "Done" else "Back")
    }
}

@Composable
private fun CancelButton(onClick: () -> Unit) {
    OutlinedButton(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().height(48.dp),
        shape = VoidwireComponentShapes.secondaryButton,
        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.onSurfaceVariant),
    ) { Text("Cancel") }
}

private sealed interface ShowState {
    data object Locked : ShowState
    data object Starting : ShowState
    data class Showing(val qr: String, val code: String?, val expiresAtMs: Long) : ShowState
    data class TypeSas(val deviceName: String) : ShowState
    data class Paired(val name: String) : ShowState
    data class Failed(val message: String) : ShowState
}

/** This phone shows a code (and a v=2 QR) for another phone or PC. */
@Composable
internal fun Pair2ShowScreen(phone: PhoneInterface, onDone: () -> Unit) {
    val gate = rememberLockGate()
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<ShowState>(ShowState.Locked) }
    val relays = remember { runCatching { phone.savedRelays() }.getOrDefault(emptyList()) }
    var relay by remember { mutableStateOf(relays.firstOrNull { it.home }?.url ?: relays.firstOrNull()?.url) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    var sas by remember { mutableStateOf("") }
    // Leaving the screen any way stops the code (and deletes its relay card).
    DisposableEffect(Unit) { onDispose { runCatching { phone.pair2Cancel() } } }
    val cancel = {
        runCatching { phone.pair2Cancel() }
        onDone()
    }
    BackHandler { cancel() }

    fun start() {
        state = ShowState.Starting
        scope.launch {
            state = try {
                val s = withContext(Dispatchers.IO) { phone.pair2Show(relay) }
                ShowState.Showing(s.qr, s.code, s.expiresAtMs.toLong())
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                ShowState.Failed(PhoneErrors.text(e))
            }
        }
    }
    val unlock = { gate("Show a pairing code") { start() } }
    LaunchedEffect(Unit) { unlock() }
    // While the code shows: read this phone's own pairing state (memory
    // only, no network) and the countdown, until it's used or gone.
    LaunchedEffect(state is ShowState.Showing) {
        while (state is ShowState.Showing) {
            now = System.currentTimeMillis()
            val st = withContext(Dispatchers.IO) { phone.pair2Status() }
            when (st.state) {
                "awaiting_code" -> state = ShowState.TypeSas(st.deviceName ?: "the other device")
                "paired" -> state = ShowState.Paired(st.deviceName ?: "")
                "failed" -> state = ShowState.Failed(st.detail ?: "Pairing stopped.")
            }
            delay(500)
        }
    }
    val cs = MaterialTheme.colorScheme
    Column(Modifier.fillMaxSize()) {
        VwTopBar("Show a pairing code", onBack = cancel)
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp).padding(bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            when (val s = state) {
                ShowState.Locked -> {
                    Text("Unlock to show a code another device can use to pair with this phone.", color = cs.onSurfaceVariant)
                    RelayPicker(relays, relay) { relay = it }
                    Button(onClick = unlock, modifier = Modifier.fillMaxWidth().height(48.dp), shape = VoidwireComponentShapes.primaryButton, border = primaryButtonBorder()) { Text("Show a code") }
                    CancelButton(cancel)
                }
                ShowState.Starting -> Box(Modifier.fillMaxWidth().padding(top = 48.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = cs.secondary)
                }
                is ShowState.Showing -> {
                    Eyebrow("Type this code on the other device")
                    if (s.code != null) Big(s.code) else Text("The relay couldn't be reached, so only the QR code works.", color = cs.onSurfaceVariant)
                    Text("Or scan this from another phone:", style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant)
                    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        QrImage(s.qr, Modifier.size(220.dp).clip(VoidwireComponentShapes.card).border(1.dp, cs.outlineVariant, VoidwireComponentShapes.card))
                    }
                    val left = ((s.expiresAtMs - now).coerceAtLeast(0) + 999) / 1000
                    Text("SINGLE USE · EXPIRES IN ${left / 60}:${(left % 60).toString().padStart(2, '0')}", style = MaterialTheme.typography.labelSmall, color = cs.onSurfaceVariant)
                    LinearProgressIndicator(
                        progress = { ((s.expiresAtMs - now).coerceAtLeast(0) / 120_000f).coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth(),
                        color = cs.secondary,
                        trackColor = cs.surfaceContainerHighest,
                    )
                    HintCard(VwIcons.Shield) {
                        Text("Only pair a device you are holding. A paired device can send links and files to this phone.", style = MaterialTheme.typography.bodySmall)
                    }
                    CancelButton(cancel)
                }
                is ShowState.TypeSas -> {
                    Eyebrow("Step 2 of 2")
                    Text("Type the 6-digit code shown on ${s.deviceName}", style = MaterialTheme.typography.headlineSmall)
                    OutlinedTextField(
                        value = sas,
                        onValueChange = { v -> sas = v.filter { it.isDigit() }.take(6) },
                        singleLine = true,
                        textStyle = VoidwireTheme.code.codeLarge,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(
                        enabled = sas.length == 6,
                        onClick = {
                            val typed = sas
                            scope.launch {
                                state = try {
                                    ShowState.Paired(withContext(Dispatchers.IO) { phone.pair2SubmitCode(typed) }.name)
                                } catch (e: kotlinx.coroutines.CancellationException) {
                                    throw e
                                } catch (e: Exception) {
                                    ShowState.Failed(PhoneErrors.text(e))
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        shape = VoidwireComponentShapes.primaryButton,
                        border = primaryButtonBorder(),
                    ) { Text("Pair") }
                    CancelButton(cancel)
                }
                is ShowState.Paired -> DoneOrFailed(true, "Paired with ${s.name}", "It's in your list. Share a link from any app to send to it.", onDone)
                is ShowState.Failed -> DoneOrFailed(false, "Pairing didn't finish", s.message, onDone)
            }
        }
    }
}

private sealed interface JoinState {
    data object EnterCode : JoinState
    data object Locked : JoinState
    data object Opening : JoinState
    data class AskRelay(val host: String) : JoinState
    data object Connecting : JoinState
    data class ShowSas(val sas: String, val inviter: String) : JoinState
    data class Paired(val name: String) : JoinState
    data class Failed(val message: String) : JoinState
}

/**
 * Join another device's invite: a scanned `v=2` QR ([qr]) or a typed
 * `VW-…` code ([qr] null). A wrong check code is refused before any network.
 */
@Composable
internal fun Pair2JoinScreen(phone: PhoneInterface, qr: String?, onDone: () -> Unit) {
    val gate = rememberLockGate()
    val scope = rememberCoroutineScope()
    val relays = remember { runCatching { phone.savedRelays() }.getOrDefault(emptyList()) }
    var relay by remember { mutableStateOf(relays.firstOrNull { it.home }?.url ?: relays.firstOrNull()?.url) }
    var code by remember { mutableStateOf("") }
    var inviter by remember { mutableStateOf("the other device") }
    var state by remember {
        mutableStateOf<JoinState>(
            when {
                qr == null -> JoinState.EnterCode
                PairQr.version(qr) == "2" -> JoinState.Locked
                else -> JoinState.Failed(PairQr.UPDATE_TEXT)
            },
        )
    }
    var codeError by remember { mutableStateOf<String?>(null) }
    DisposableEffect(Unit) { onDispose { runCatching { phone.pair2Cancel() } } }
    val cancel = {
        runCatching { phone.pair2Cancel() }
        onDone()
    }
    BackHandler { cancel() }

    fun connect() {
        state = JoinState.Connecting
        scope.launch {
            try {
                val sas = withContext(Dispatchers.IO) { phone.pair2Join() }
                state = JoinState.ShowSas(sas, inviter)
                val done = withContext(Dispatchers.IO) { phone.pair2JoinWait() }
                state = JoinState.Paired(done.name)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                state = JoinState.Failed(PhoneErrors.text(e))
            }
        }
    }

    fun open() {
        state = JoinState.Opening
        scope.launch {
            try {
                val o = withContext(Dispatchers.IO) {
                    if (qr != null) phone.pair2OpenQr(qr) else phone.pair2OpenCode(code, relay)
                }
                o.inviterName?.let { inviter = it }
                when (o.relayState) {
                    "ask" -> state = JoinState.AskRelay(o.relayHost ?: o.relayUrl)
                    "full" -> state = JoinState.Failed(
                        "This pairing uses ${o.relayHost ?: o.relayUrl}, but this phone already uses the most relays it can. Remove one first.",
                    )
                    else -> connect()
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                if (qr == null) {
                    // A typo or an unknown code: let them fix it here.
                    codeError = PhoneErrors.text(e)
                    state = JoinState.EnterCode
                } else {
                    state = JoinState.Failed(PhoneErrors.text(e))
                }
            }
        }
    }
    val unlockAndOpen = { gate("Pair with another device") { open() } }
    LaunchedEffect(Unit) { if (state == JoinState.Locked) unlockAndOpen() }

    val cs = MaterialTheme.colorScheme
    Column(Modifier.fillMaxSize()) {
        VwTopBar(if (qr == null) "Type a pairing code" else "Pair with another device", onBack = cancel)
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp).padding(bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            when (val s = state) {
                JoinState.EnterCode -> {
                    Text("Type the code shown on the other phone or PC. Spaces, dashes and upper/lower case don't matter.", color = cs.onSurfaceVariant)
                    OutlinedTextField(
                        value = code,
                        onValueChange = {
                            code = it
                            codeError = null
                        },
                        singleLine = true,
                        isError = codeError != null,
                        supportingText = { codeError?.let { Text(it) } },
                        placeholder = { Text("VW-XXXX-XXXX-…", style = VoidwireTheme.code.codeMedium) },
                        textStyle = VoidwireTheme.code.codeMedium,
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, keyboardType = KeyboardType.Ascii),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    RelayPicker(relays, relay) { relay = it }
                    Button(
                        enabled = code.isNotBlank(),
                        onClick = unlockAndOpen,
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        shape = VoidwireComponentShapes.primaryButton,
                        border = primaryButtonBorder(),
                    ) { Text("Next") }
                    CancelButton(cancel)
                }
                JoinState.Locked -> {
                    Text("Unlock to pair with another device.", color = cs.onSurfaceVariant)
                    Button(onClick = unlockAndOpen, modifier = Modifier.fillMaxWidth().height(48.dp), shape = VoidwireComponentShapes.primaryButton, border = primaryButtonBorder()) { Text("Unlock") }
                    CancelButton(cancel)
                }
                JoinState.Opening, JoinState.Connecting, is JoinState.AskRelay -> {
                    Box(Modifier.fillMaxWidth().padding(top = 48.dp), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = cs.secondary)
                    }
                    Text(if (s == JoinState.Connecting) "Connecting to $inviter…" else "Checking the code…", color = cs.onSurfaceVariant)
                    CancelButton(cancel)
                }
                is JoinState.ShowSas -> {
                    Eyebrow("Step 2 of 2")
                    Text("Type this on ${s.inviter}", style = MaterialTheme.typography.headlineSmall)
                    Big(s.sas.take(3) + " " + s.sas.drop(3))
                    LinearProgressIndicator(Modifier.fillMaxWidth(), color = cs.secondary, trackColor = cs.surfaceContainerHighest)
                    Text("WAITING FOR THE OTHER DEVICE…", style = MaterialTheme.typography.labelSmall, color = cs.onSurfaceVariant)
                    CancelButton(cancel)
                }
                is JoinState.Paired -> DoneOrFailed(true, "Paired with ${s.name}", "It's in your list. Share a link from any app to send to it.", onDone)
                is JoinState.Failed -> DoneOrFailed(false, "Pairing didn't finish", s.message, onDone)
            }
            Spacer(Modifier.height(4.dp))
        }
    }
    (state as? JoinState.AskRelay)?.let { s ->
        // Spec §5.3: the invite's relay isn't saved here yet.
        AlertDialog(
            onDismissRequest = cancel,
            containerColor = cs.surfaceContainerHigh,
            title = { Text("This pairing uses ${s.host}. Add it?") },
            text = { Text("Both devices pass sealed data through this relay. It can't read it.") },
            confirmButton = {
                Button(
                    onClick = {
                        scope.launch {
                            try {
                                withContext(Dispatchers.IO) { phone.pair2AddRelay() }
                                connect()
                            } catch (e: kotlinx.coroutines.CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                state = JoinState.Failed(PhoneErrors.text(e))
                            }
                        }
                    },
                    shape = VoidwireComponentShapes.primaryButton,
                    border = primaryButtonBorder(),
                ) { Text("Add and pair") }
            },
            dismissButton = { TextButton(onClick = cancel) { Text("Cancel") } },
        )
    }
}
