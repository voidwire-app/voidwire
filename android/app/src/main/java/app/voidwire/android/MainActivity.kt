package app.voidwire.android

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Color as AColor
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import app.voidwire.android.ui.ChipTone
import app.voidwire.android.ui.Eyebrow
import app.voidwire.android.ui.HintCard
import app.voidwire.android.ui.IconWell
import app.voidwire.android.ui.KeyValue
import app.voidwire.android.ui.Placeholder
import app.voidwire.android.ui.VwCard
import app.voidwire.android.ui.VwChip
import app.voidwire.android.ui.VwIcons
import app.voidwire.android.ui.VwTopBar
import app.voidwire.android.ui.theme.VoidwireTheme
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.HorizontalDivider
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.graphics.luminance
import android.graphics.drawable.ColorDrawable
import app.voidwire.android.ui.theme.ThemeMode
import app.voidwire.android.ui.theme.VoidwireComponentShapes
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.PlainTooltip
import androidx.compose.material3.TooltipBox
import androidx.compose.material3.TooltipDefaults
import androidx.compose.material3.rememberTooltipState
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.em
import app.voidwire.android.ui.DashedNote
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import android.content.ClipboardManager
import android.content.Context
import uniffi.voidwire_core.IncomingClipboardItem
import uniffi.voidwire_core.IncomingFileOfferItem
import uniffi.voidwire_core.IncomingLinkItem
import uniffi.voidwire_core.IncomingSnapshot
import uniffi.voidwire_core.Pairing
import uniffi.voidwire_core.PcInfo
import uniffi.voidwire_core.PhoneInterface
import uniffi.voidwire_core.coreVersion

/** REVIEW-m11 #8 / SPEC §4: identifiers keep their tail: head(n-7) + "…" + tail(6). */
internal fun middleEllipsis(name: String, n: Int): String {
    val cps = name.codePoints().toArray()
    if (cps.size <= n) return name
    fun str(a: IntArray) = String(a, 0, a.size)
    return str(cps.copyOfRange(0, n - 7)) + "…" + str(cps.copyOfRange(cps.size - 6, cps.size))
}

/** Dismissive actions (Cancel, Close) are never gold (SPEC §4, REVIEW-m11 #4). */
@Composable
internal fun mutedTextButton() = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onSurfaceVariant)

// Destructive secondary actions (designer r3, 'Clear' recent sends): outlined in the error role,
// red outline + red label, never gold and never filled. Same recipe as desktop .btn-danger
// (error at 55% for the outline, full error for the label).
@Composable
internal fun dangerOutlinedButtonColors() = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)

@Composable
internal fun dangerOutlinedBorder() = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.55f))

/** F7 (REVIEW-m11-android): light-theme gold buttons (#F2C94C) get a 1dp #8C6A00 (`inversePrimary`) outline. */
@Composable
internal fun primaryButtonBorder(): BorderStroke? =
    if (MaterialTheme.colorScheme.background.luminance() < 0.5f) null
    else BorderStroke(1.dp, MaterialTheme.colorScheme.inversePrimary)

/** Long-press shows the full (untruncated) name. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun FullNameTooltip(full: String, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Box(modifier) {
        TooltipBox(
            positionProvider = TooltipDefaults.rememberPlainTooltipPositionProvider(),
            tooltip = { PlainTooltip { Text(full) } },
            state = rememberTooltipState(),
        ) { content() }
    }
}

class MainActivity : ComponentActivity() {
    /** SPEC 3.1 (round 2): the Theme setting, Compose state so Settings recomposes at once. */
    private var themeMode by mutableStateOf(ThemeMode.Default)

    override fun onCreate(savedInstanceState: Bundle?) {
        themeMode = ThemePref.get(this)
        applyWindowTheme()
        super.onCreate(savedInstanceState)
        VoidwireReceiveService.syncWithPreference(this)
        val startScan = intent?.getBooleanExtra(EXTRA_PAIR, false) == true
        setContent {
            VoidwireTheme(themeMode) {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Box(Modifier.safeDrawingPadding()) {
                        App(startScan, themeMode, onThemeMode = { m ->
                            ThemePref.set(this@MainActivity, m)
                            themeMode = m
                            applyWindowTheme()
                        })
                    }
                }
            }
        }
    }

    /**
     * Edge to edge with bar icons and the pre-Compose window background
     * matching the resolved theme: the setting, or System = dark unless the
     * OS explicitly says light (ThemeRule).
     */
    override fun onStart() {
        super.onStart()
        VoidwireReceiveService.setMainActivityVisible(true)
        VoidwireNotifications.cancelIncoming(this)
        if (DebugSeams.phone() == null) {
            Core.setAppForeground(this, true)
            Core.triggerOneShotInboxPull(this)
        }
    }

    override fun onResume() {
        super.onResume()
        VoidwireReceiveService.setMainActivityVisible(true)
        VoidwireNotifications.cancelIncoming(this)
    }

    override fun onPause() {
        VoidwireReceiveService.setMainActivityVisible(false)
        super.onPause()
    }

    override fun onStop() {
        VoidwireReceiveService.setMainActivityVisible(false)
        if (DebugSeams.phone() == null) {
            Core.setAppForeground(this, false)
        }
        super.onStop()
    }

    private fun applyWindowTheme() {
        val dark = ThemeRule.isDark(themeMode, resources.configuration.uiMode)
        val bars = if (dark) {
            SystemBarStyle.dark(AColor.TRANSPARENT)
        } else {
            SystemBarStyle.light(AColor.TRANSPARENT, AColor.TRANSPARENT)
        }
        enableEdgeToEdge(statusBarStyle = bars, navigationBarStyle = bars)
        window.setBackgroundDrawable(ColorDrawable(if (dark) 0xFF070B14.toInt() else 0xFFF4F6F9.toInt()))
    }

    companion object {
        const val EXTRA_PAIR = "app.voidwire.android.PAIR"
    }
}

private sealed interface Screen {
    data object Home : Screen
    data object Scan : Screen
    data object Settings : Screen
    data class Pairing(val qr: String) : Screen
    // M4.3: pair with any device by code.
    data object Pair2Show : Screen
    data object Pair2Enter : Screen
    data class Pair2Qr(val qr: String) : Screen
}

private val ScreenSaver: Saver<Screen, String> = Saver(
    save = { s ->
        when (s) {
            Screen.Home -> "home"
            Screen.Scan -> "scan"
            Screen.Settings -> "settings"
            is Screen.Pairing -> "pair:${s.qr}"
            // A live code isn't restored: it was cancelled when the screen went.
            Screen.Pair2Show, Screen.Pair2Enter, is Screen.Pair2Qr -> "home"
        }
    },
    restore = { raw ->
        when {
            raw == "scan" -> Screen.Scan
            raw == "settings" -> Screen.Settings
            raw.startsWith("pair:") -> Screen.Pairing(raw.removePrefix("pair:"))
            else -> Screen.Home
        }
    },
)

@Composable
private fun App(startScan: Boolean, themeMode: ThemeMode, onThemeMode: (ThemeMode) -> Unit) {
    val context = LocalContext.current
    var phone by remember { mutableStateOf<PhoneInterface?>(null) }
    var loadError by remember { mutableStateOf<String?>(null) }
    var screen by rememberSaveable(stateSaver = ScreenSaver) { mutableStateOf<Screen>(if (startScan) Screen.Scan else Screen.Home) }

    LaunchedEffect(Unit) {
        try {
            // DebugSeams: the debug build lets instrumented tests (android-qa shots)
            // supply a fake phone; the release variant's DebugSeams.phone() is a constant null.
            phone = DebugSeams.phone() ?: withContext(Dispatchers.IO) { Core.phone(context) }
        } catch (e: Exception) {
            loadError = PhoneErrors.text(e)
        }
    }
    val p = phone
    when {
        loadError != null -> Centered { Text("Couldn't start: $loadError") }
        p == null -> Centered { CircularProgressIndicator(color = MaterialTheme.colorScheme.secondary) }
        else -> when (val s = screen) {
            Screen.Home -> HomeScreen(p, onPair = { screen = Screen.Scan }, onSettings = { screen = Screen.Settings })
            Screen.Settings -> {
                BackHandler { screen = Screen.Home }
                SettingsScreen(p, themeMode, onThemeMode, onBack = { screen = Screen.Home })
            }
            Screen.Scan -> {
                BackHandler { screen = Screen.Home }
                // One link per visit: a second result (camera and paste, or a
                // double tap) before the screen switches must not start a
                // second pairing with the same one-time QR.
                ScanScreen(
                    onQr = {
                        if (screen == Screen.Scan) {
                            // v=1 (a PC's QR) keeps the M3 flow; anything newer goes to v2,
                            // which explains when this app is too old for it.
                            screen = when (PairQr.version(it)) {
                                null, "1" -> Screen.Pairing(it)
                                else -> Screen.Pair2Qr(it)
                            }
                        }
                    },
                    onBack = { screen = Screen.Home },
                    onShowCode = { screen = Screen.Pair2Show },
                    onTypeCode = { screen = Screen.Pair2Enter },
                )
            }
            // A new link starts a fresh pairing screen (no state carried over).
            is Screen.Pairing -> key(s.qr) { PairingScreen(p, s.qr, onDone = { screen = Screen.Home }) }
            Screen.Pair2Show -> Pair2ShowScreen(p, onDone = { screen = Screen.Home })
            Screen.Pair2Enter -> Pair2JoinScreen(p, null, onDone = { screen = Screen.Home })
            is Screen.Pair2Qr -> key(s.qr) { Pair2JoinScreen(p, s.qr, onDone = { screen = Screen.Home }) }
        }
    }
}

@Composable
private fun Centered(content: @Composable () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) { content() }
}

/** SPEC 3.2 (screens/08). */
@Composable
private fun HomeScreen(phone: PhoneInterface, onPair: () -> Unit, onSettings: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snack = remember { SnackbarHostState() }
    var pcs by remember { mutableStateOf(phone.pairedPcs()) }
    var removalWarning by remember { mutableStateOf(phone.removalCheckWarning()) }
    // In-memory only (SPEC R5): which PCs answered a Check this session.
    var checked by remember { mutableStateOf(mapOf<String, Boolean>()) }
    var checking by remember { mutableStateOf(setOf<String>()) }
    var gone by remember { mutableStateOf(setOf<String>()) }
    var confirmForget by remember { mutableStateOf<PcInfo?>(null) }
    // M4.3: unpairing asks for the screen lock first (none set: no prompt).
    val lockGate = rememberLockGate()
    var sendingFile by remember { mutableStateOf<Pair<StagedShareFile, ShareTarget>?>(null) }
    var sendingJob by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    var pendingRelayPrompt by remember { mutableStateOf<Triple<StagedShareFile, ShareTarget, String>?>(null) }
    var errorDialog by remember { mutableStateOf<PhoneErrors.ErrorDialogInfo?>(null) }
    var incomingSnapshot by remember {
        mutableStateOf(
            runCatching { phone.pollIncoming() }.getOrElse {
                IncomingSnapshot(emptyList(), emptyList(), emptyList())
            },
        )
    }
    var acceptingFileIds by remember { mutableStateOf(setOf<String>()) }
    var sendingClipboardTargetId by remember { mutableStateOf<String?>(null) }
    var filePickTarget by remember { mutableStateOf<ShareTarget?>(null) }
    // M4.4: each pairing's relay, this phone's move requests, and the other
    // device's requests (local reads on the loop below; app open only).
    var relayOf by remember { mutableStateOf(mapOf<String, uniffi.voidwire_core.PairingRelay>()) }
    var relayMoves by remember { mutableStateOf(mapOf<String, uniffi.voidwire_core.RelayChangeInfo>()) }
    var relayAsk by remember { mutableStateOf<uniffi.voidwire_core.RelayChangeAsk?>(null) }
    var relayPick by remember { mutableStateOf<PcInfo?>(null) }
    var relayAnswering by remember { mutableStateOf(setOf<String>()) }
    val homeNotifPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { _ -> }
    LaunchedEffect(pcs.size) {
        if (
            android.os.Build.VERSION.SDK_INT >= 33 &&
            DebugSeams.phone() == null &&
            pcs.any { !it.removed } &&
            IncomingNotificationPref.enabled(context) &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            runCatching { homeNotifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) }
        }
    }
    LaunchedEffect(phone) {
        withContext(Dispatchers.IO) {
            FileShareStaging.sweepStale(context.cacheDir)
            runCatching { phone.pullDeviceInboxNow() }
        }
        while (true) {
            val snap = runCatching { phone.pollIncoming() }.getOrNull()
            if (snap != null) {
                incomingSnapshot = snap
            }
            runCatching {
                relayOf = phone.pairingRelays().associateBy { it.peerId }
                relayMoves = phone.relayChangeStatuses().associateBy { it.peerId }
                val asks = phone.relayChangeRequests().filter { it.peerId !in relayAnswering }
                if (relayAsk == null || asks.none { it.peerId == relayAsk?.peerId }) relayAsk = asks.firstOrNull()
            }
            val fastPoll = acceptingFileIds.isNotEmpty() || (snap?.files?.any { it.accepted } == true)
            delay(if (fastPoll) 350L else 1_200L)
        }
    }
    DisposableEffect(Unit) {
        onDispose {
            pendingRelayPrompt?.first?.filePath?.let { FileShareStaging.cleanup(it) }
            sendingFile?.first?.filePath?.let { FileShareStaging.cleanup(it) }
        }
    }
    // SPEC 3.2 NO HISTORY rule: any history-type opt-in on -> HISTORY ON.
    val keepsHistory = remember { History.anyOn(context) || phone.connectionStatsEnabled() }

    fun executeHomeFileSend(staged: StagedShareFile, target: ShareTarget, relayDecision: String?) {
        sendingFile = staged to target
        sendingJob = scope.launch {
            try {
                val r = withContext(Dispatchers.IO) {
                    Core.withMulticast(context) {
                        phone.sendFile(target.id, staged.filePath, staged.mime, relayDecision)
                    }
                }
                FileShareStaging.cleanup(staged.filePath)
                sendingFile = null
                sendingJob = null
                val how = if (r.relayed) "via relay" else "direct"
                snack.showSnackbar("Sent ${r.filename} to ${target.name} ($how).")
            } catch (e: kotlinx.coroutines.CancellationException) {
                FileShareStaging.cleanup(staged.filePath)
                sendingFile = null
                sendingJob = null
            } catch (e: uniffi.voidwire_core.PhoneException.Other) {
                sendingFile = null
                sendingJob = null
                if (e.detail.contains("relay_prompt_required")) {
                    val sizeLabel = FileShareStaging.formatSize(staged.sizeBytes)
                    val largeWarn = if (staged.sizeBytes > 25L * 1024L * 1024L) {
                        " Large file ($sizeLabel) — sending over the relay may use mobile data."
                    } else {
                        ""
                    }
                    pendingRelayPrompt = Triple(
                        staged,
                        target,
                        "Not on the same network — send $sizeLabel via relay?$largeWarn",
                    )
                } else {
                    FileShareStaging.cleanup(staged.filePath)
                    val neverRelay = runCatching { phone.neverSendFilesOverRelay() }.getOrDefault(false)
                    errorDialog = PhoneErrors.dialogForPc(e, target.name, neverRelay)
                }
            } catch (e: Exception) {
                FileShareStaging.cleanup(staged.filePath)
                sendingFile = null
                sendingJob = null
                val neverRelay = runCatching { phone.neverSendFilesOverRelay() }.getOrDefault(false)
                errorDialog = PhoneErrors.dialogForPc(e, target.name, neverRelay)
            }
        }
    }

    val pickDocument = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val pickedTarget = filePickTarget
        filePickTarget = null
        if (uri == null) return@rememberLauncherForActivityResult
        val activeTargets = LastPc.order(
            context,
            pcs.filter { !it.removed && it.id !in gone }.map { ShareTarget(it.id, it.name) },
        )
        val target = pickedTarget ?: activeTargets.firstOrNull() ?: return@rememberLauncherForActivityResult
        scope.launch {
            val staged = try {
                withContext(Dispatchers.IO) { FileShareStaging.stage(context, uri) }
            } catch (e: Exception) {
                errorDialog = PhoneErrors.ErrorDialogInfo(
                    title = "Transfer failed",
                    message = e.message ?: "Couldn't read the selected file.",
                )
                return@launch
            }
            executeHomeFileSend(staged, target, relayDecision = null)
        }
    }

    fun runForget(pc: PcInfo) {
        // SPEC R3: the card goes at once, then the core call.
        gone = gone + pc.id
        scope.launch {
            val ok = try {
                withContext(Dispatchers.IO) { phone.forgetPc(pc.id) }
                true
            } catch (e: Exception) {
                false
            }
            if (ok) {
                delay(220)
                pcs = phone.pairedPcs()
                gone = gone.filter { id -> pcs.any { it.id == id } }.toSet()
                snack.showSnackbar("Forgot ${pc.name}. This phone stops sending to it.")
            } else {
                // F2 (REVIEW-m11-android): the core rolled the removal back; card returns with Retry.
                gone = gone - pc.id
                pcs = phone.pairedPcs()
                val res = snack.showSnackbar(
                    message = "Couldn't forget ${pc.name}. Try again.",
                    actionLabel = "Retry",
                )
                if (res == SnackbarResult.ActionPerformed) runForget(pc)
            }
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = {
            // F6 (REVIEW-m11-android): lift snackbar above the bottom wire strip + CORE line.
            SnackbarHost(snack, modifier = Modifier.padding(bottom = 116.dp)) { data ->
                val cs = MaterialTheme.colorScheme
                Snackbar(
                    snackbarData = data,
                    containerColor = cs.inverseSurface,
                    contentColor = cs.inverseOnSurface,
                    actionColor = cs.secondary,
                )
            }
        },
        topBar = {
            VwTopBar(
                title = null,
                leading = {
                    Image(
                        painterResource(if (MaterialTheme.colorScheme.background.luminance() < 0.5f) R.drawable.vw_lockup_for_dark else R.drawable.vw_lockup_for_light),
                        contentDescription = stringResource(R.string.app_name),
                        modifier = Modifier.height(22.dp),
                    )
                },
                actions = {
                    IconButton(onClick = onSettings) {
                        Icon(VwIcons.Gear, contentDescription = "Settings", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                },
            )
        },
    ) { inner ->
        // REVIEW-m11 #3: the strip and CORE line are pinned to the bottom when
        // the content is short, and still scroll with a long list.
        BoxWithConstraints(Modifier.fillMaxSize().padding(inner)) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).heightIn(min = maxHeight).padding(horizontal = 20.dp)
                .padding(top = 4.dp, bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            HintCard(VwIcons.Send) {
                Text(
                    buildAnnotatedString {
                        append("Share a link or file from any app and pick ")
                        withStyle(SpanStyle(fontWeight = FontWeight.SemiBold)) { append(stringResource(R.string.share_label)) }
                        append(". Links open right away; files save on your PC.")
                    },
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            // REVIEW-m11 #8 + B4: one line, middle ellipsis keeping the tail,
            // full name in contentDescription + long-press tooltip; baseline-aligned.
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("THIS PHONE ", style = VoidwireTheme.code.codeSmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.alignByBaseline())
                val fullName = phone.deviceName()
                FullNameTooltip(fullName, Modifier.weight(1f).alignByBaseline()) {
                    Text(
                        middleEllipsis(fullName, 18),
                        style = VoidwireTheme.code.codeMedium,
                        color = MaterialTheme.colorScheme.tertiary,
                        maxLines = 1,
                        modifier = Modifier.semantics { contentDescription = fullName },
                    )
                }
                // REVIEW-m11 #2: blue secondary text button (one gold per screen).
                TextButton(
                    onClick = onSettings,
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.secondary),
                    modifier = Modifier.alignByBaseline(),
                ) { Text("Rename in Settings", style = MaterialTheme.typography.bodySmall) }
            }
            val totalIncoming = incomingSnapshot.links.size + incomingSnapshot.clipboards.size + incomingSnapshot.files.size
            if (totalIncoming > 0) {
                Eyebrow("Incoming", count = totalIncoming)
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    for (linkItem in incomingSnapshot.links) {
                        key("link-${linkItem.id}") {
                            IncomingLinkCard(
                                item = linkItem,
                                onOpen = {
                                    val opened = IncomingReceive.openVerifiedBrowserUrl(context, linkItem.url)
                                    if (opened.isSuccess) {
                                        scope.launch {
                                            withContext(Dispatchers.IO) {
                                                runCatching { phone.dismissIncomingItem(linkItem.id) }
                                                runCatching { phone.pollIncoming() }.getOrNull()
                                            }?.let { incomingSnapshot = it }
                                        }
                                    } else {
                                        scope.launch {
                                            snack.showSnackbar(opened.exceptionOrNull()?.message ?: "Couldn't open link.")
                                        }
                                    }
                                },
                                onCopy = {
                                    IncomingReceive.copyToSystemClipboard(context, linkItem.url, sensitive = false)
                                    scope.launch {
                                        withContext(Dispatchers.IO) {
                                            runCatching { phone.dismissIncomingItem(linkItem.id) }
                                            runCatching { phone.pollIncoming() }.getOrNull()
                                        }?.let { incomingSnapshot = it }
                                        snack.showSnackbar("Copied link to clipboard.")
                                    }
                                },
                                onDismiss = {
                                    scope.launch {
                                        withContext(Dispatchers.IO) {
                                            runCatching { phone.dismissIncomingItem(linkItem.id) }
                                            runCatching { phone.pollIncoming() }.getOrNull()
                                        }?.let { incomingSnapshot = it }
                                    }
                                },
                            )
                        }
                    }
                    for (clipItem in incomingSnapshot.clipboards) {
                        key("clip-${clipItem.id}") {
                            IncomingClipboardCard(
                                item = clipItem,
                                onCopy = {
                                    IncomingReceive.copyToSystemClipboard(context, clipItem.text, sensitive = clipItem.sensitive)
                                    scope.launch {
                                        withContext(Dispatchers.IO) {
                                            runCatching { phone.dismissIncomingItem(clipItem.id) }
                                            runCatching { phone.pollIncoming() }.getOrNull()
                                        }?.let { incomingSnapshot = it }
                                        snack.showSnackbar("Copied to clipboard.")
                                    }
                                },
                                onSaveTxt = {
                                    scope.launch {
                                        val saved = runCatching {
                                            withContext(Dispatchers.IO) {
                                                val label = IncomingReceive.saveClipboardAsTxt(context, clipItem.text)
                                                runCatching { phone.dismissIncomingItem(clipItem.id) }
                                                label to runCatching { phone.pollIncoming() }.getOrNull()
                                            }
                                        }
                                        saved.onSuccess { (label, snap) ->
                                            if (snap != null) incomingSnapshot = snap
                                            snack.showSnackbar("Saved to $label.")
                                        }.onFailure {
                                            snack.showSnackbar("Couldn't save text file.")
                                        }
                                    }
                                },
                                onDismiss = {
                                    scope.launch {
                                        withContext(Dispatchers.IO) {
                                            runCatching { phone.dismissIncomingItem(clipItem.id) }
                                            runCatching { phone.pollIncoming() }.getOrNull()
                                        }?.let { incomingSnapshot = it }
                                    }
                                },
                            )
                        }
                    }
                    for (fileItem in incomingSnapshot.files) {
                        key("file-${fileItem.transferId}") {
                            IncomingFileCard(
                                item = fileItem,
                                busy = fileItem.transferId in acceptingFileIds,
                                onAccept = {
                                    acceptingFileIds = acceptingFileIds + fileItem.transferId
                                    scope.launch {
                                        val res = runCatching {
                                            withContext(Dispatchers.IO) {
                                                val stageDir = java.io.File(context.cacheDir, "incoming-files").apply { mkdirs() }
                                                val stagedPath = Core.withMulticast(context) {
                                                    phone.acceptIncomingFile(fileItem.transferId, stageDir.absolutePath)
                                                }
                                                val outLabel = IncomingReceive.exportVerifiedFileToDownloads(
                                                    context,
                                                    stagedPath,
                                                    fileItem.filename,
                                                )
                                                outLabel to runCatching { phone.pollIncoming() }.getOrNull()
                                            }
                                        }
                                        acceptingFileIds = acceptingFileIds - fileItem.transferId
                                        res.onSuccess { (outLabel, snap) ->
                                            if (snap != null) incomingSnapshot = snap
                                            snack.showSnackbar("Saved to $outLabel.")
                                        }.onFailure { e ->
                                            runCatching { phone.pollIncoming() }.getOrNull()?.let { incomingSnapshot = it }
                                            val errText = PhoneErrors.text(e as? Exception ?: Exception(e))
                                            errorDialog = PhoneErrors.ErrorDialogInfo(
                                                title = "Transfer failed",
                                                message = errText,
                                            )
                                        }
                                    }
                                },
                                onCancelOrDecline = {
                                    acceptingFileIds = acceptingFileIds - fileItem.transferId
                                    scope.launch {
                                        withContext(Dispatchers.IO) {
                                            runCatching { phone.cancelIncomingFile(fileItem.transferId) }
                                            runCatching { phone.pollIncoming() }.getOrNull()
                                        }?.let { incomingSnapshot = it }
                                    }
                                },
                            )
                        }
                    }
                }
            }
            Eyebrow("Paired PCs", count = pcs.count { it.id !in gone })
            removalWarning?.let { warn ->
                HintCard(VwIcons.Warn) {
                    Text(warn, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (pcs.none { it.id !in gone }) {
                // REVIEW-m11 B5: bodyMedium, muted.
                Text("None yet. Pair a device to send links and files to it.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                for (pc in pcs) {
                    key(pc.id) {
                        AnimatedVisibility(
                            visible = pc.id !in gone,
                            exit = shrinkVertically(tween(200)) + fadeOut(tween(200)),
                        ) {
                            PcCard(
                                pc,
                                relayLine = relayLine(relayOf[pc.id]?.host, relayMoves[pc.id]?.state, relayMoves[pc.id]?.host),
                                onChangeRelay = { relayPick = pc },
                                reachable = checked[pc.id],
                                busy = pc.id in checking,
                                sendingClipboard = sendingClipboardTargetId == pc.id,
                                sendingFile = sendingFile?.second?.id == pc.id,
                                actionsEnabled = sendingClipboardTargetId == null && sendingFile == null,
                                onSendClipboard = {
                                    val target = ShareTarget(pc.id, pc.name)
                                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                                    val rawClip = cm?.primaryClip?.takeIf { it.itemCount > 0 }
                                        ?.getItemAt(0)?.coerceToText(context)?.toString()
                                    if (rawClip.isNullOrBlank()) {
                                        scope.launch { snack.showSnackbar("Clipboard is empty.") }
                                        return@PcCard
                                    }
                                    val utf8Bytes = rawClip.toByteArray(Charsets.UTF_8).size
                                    if (utf8Bytes > IncomingReceive.MAX_INLINE_CLIPBOARD_BYTES) {
                                        scope.launch {
                                            val staged = runCatching {
                                                withContext(Dispatchers.IO) { FileShareStaging.stageTextAsFile(context, rawClip) }
                                            }.getOrNull()
                                            if (staged != null) {
                                                executeHomeFileSend(staged, target, relayDecision = null)
                                            } else {
                                                snack.showSnackbar("Couldn't stage large clipboard text.")
                                            }
                                        }
                                    } else {
                                        sendingClipboardTargetId = pc.id
                                        scope.launch {
                                            val msg = try {
                                                val r = withContext(Dispatchers.IO) {
                                                    Core.withMulticast(context) { phone.sendTextOrUrl(target.id, rawClip) }
                                                }
                                                "Sent clipboard to ${target.name} (${SendText.latency(r.latencyUs)})."
                                            } catch (e: Exception) {
                                                PhoneErrors.textForPc(e, target.name)
                                            } finally {
                                                sendingClipboardTargetId = null
                                            }
                                            snack.showSnackbar(msg)
                                        }
                                    }
                                },
                                onSendFile = {
                                    filePickTarget = ShareTarget(pc.id, pc.name)
                                    pickDocument.launch(arrayOf("*/*"))
                                },
                                onCheck = {
                                    checking = checking + pc.id
                                    scope.launch {
                                        val msg = try {
                                            val ok = withContext(Dispatchers.IO) {
                                                Core.withMulticast(context) {
                                                    runCatching { phone.pullDeviceInboxNow() }
                                                    phone.refresh(pc.id)
                                                }
                                            }
                                            checked = checked + (pc.id to ok)
                                            val warn = phone.removalCheckWarning()
                                            if (!ok) "${pc.name} removed this phone."
                                            else if (warn != null) warn
                                            else "${pc.name} is reachable and still paired."
                                        } catch (e: Exception) {
                                            phone.removalCheckWarning() ?: PhoneErrors.textForPc(e, pc.name)
                                        }
                                        checking = checking - pc.id
                                        pcs = phone.pairedPcs()
                                        removalWarning = phone.removalCheckWarning()
                                        runCatching { phone.pollIncoming() }.getOrNull()?.let { incomingSnapshot = it }
                                        snack.showSnackbar(msg)
                                    }
                                },
                                onForget = { confirmForget = pc },
                            )
                        }
                    }
                }
            }
            Button(
                onClick = onPair,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                shape = VoidwireComponentShapes.primaryButton,
                border = primaryButtonBorder(),
            ) {
                Icon(VwIcons.Qr, contentDescription = null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(10.dp))
                Text("Pair a device", style = MaterialTheme.typography.labelLarge)
            }
            if (pcs.any { !it.removed && it.id !in gone }) {
                sendingFile?.let { (staged, target) ->
                    VwCard(container = MaterialTheme.colorScheme.surfaceContainerLow) {
                        Column(
                            Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(
                                        staged.displayName,
                                        style = MaterialTheme.typography.bodyMedium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    Text(
                                        "${FileShareStaging.formatSize(staged.sizeBytes)} → ${target.name}",
                                        style = VoidwireTheme.code.codeSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                                TextButton(
                                    onClick = {
                                        sendingJob?.cancel()
                                        sendingJob = null
                                        sendingFile = null
                                        scope.launch {
                                            runCatching {
                                                withContext(Dispatchers.IO) {
                                                    phone.sendFile(target.id, staged.filePath, staged.mime, "cancel")
                                                }
                                            }
                                            FileShareStaging.cleanup(staged.filePath)
                                        }
                                    },
                                    modifier = Modifier.testTag("cancel_home_file_btn"),
                                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                                ) { Text("Cancel") }
                            }
                            LinearProgressIndicator(
                                modifier = Modifier.fillMaxWidth(),
                                color = MaterialTheme.colorScheme.secondary,
                            )
                        }
                    }
                }
            }
            Spacer(Modifier.weight(1f))
            WireStrip(keepsHistory, onHistory = onSettings)
            Text(
                "CORE ${coreVersion()}",
                style = VoidwireTheme.code.codeSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        }
    }

    confirmForget?.let { pc ->
        AlertDialog(
            onDismissRequest = { confirmForget = null },
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            title = { Text("Forget ${pc.name}?") },
            text = { Text("This phone stops sending to it. To send again you'll need to pair again.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmForget = null
                        lockGate("Forget ${pc.name}") { runForget(pc) }
                    },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) { Text("Forget") }
            },
            dismissButton = { TextButton(onClick = { confirmForget = null }, colors = mutedTextButton()) { Text("Cancel") } },
        )
    }
    pendingRelayPrompt?.let { (staged, target, promptText) ->
        AlertDialog(
            onDismissRequest = {
                pendingRelayPrompt = null
                scope.launch {
                    runCatching {
                        withContext(Dispatchers.IO) {
                            phone.sendFile(target.id, staged.filePath, staged.mime, "cancel")
                        }
                    }
                    FileShareStaging.cleanup(staged.filePath)
                }
            },
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            title = { Text(promptText) },
            text = { Text("${staged.displayName} (${FileShareStaging.formatSize(staged.sizeBytes)}) → ${target.name}") },
            confirmButton = {
                TextButton(
                    onClick = {
                        pendingRelayPrompt = null
                        executeHomeFileSend(staged, target, relayDecision = "send_via_relay")
                    },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.primary),
                ) { Text("Send via relay") }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        pendingRelayPrompt = null
                        scope.launch {
                            runCatching {
                                withContext(Dispatchers.IO) {
                                    phone.sendFile(target.id, staged.filePath, staged.mime, "cancel")
                                }
                            }
                            FileShareStaging.cleanup(staged.filePath)
                        }
                    },
                    colors = mutedTextButton(),
                ) { Text("Cancel") }
            },
        )
    }
    relayAsk?.let { ask ->
        RelayChangeAskDialog(ask) { allow ->
            relayAsk = null
            relayAnswering = relayAnswering + ask.peerId
            scope.launch {
                val msg = try {
                    withContext(Dispatchers.IO) { phone.answerRelayChange(ask.peerId, allow) }
                    if (allow) "Moved the pairing with ${ask.peerName} to ${ask.host}." else "Declined. The pairing keeps its relay."
                } catch (e: Exception) {
                    PhoneErrors.text(e)
                } finally {
                    relayAnswering = relayAnswering - ask.peerId
                }
                snack.showSnackbar(msg)
            }
        }
    }
    relayPick?.let { pc ->
        RelayPickDialog(phone, pc, relayOf[pc.id]?.url) { msg ->
            relayPick = null
            if (msg != null) scope.launch { snack.showSnackbar(msg) }
        }
    }
    errorDialog?.let { dlg ->
        AlertDialog(
            onDismissRequest = { errorDialog = null },
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            title = { Text(dlg.title) },
            text = { Text(dlg.message) },
            confirmButton = {
                TextButton(
                    onClick = { errorDialog = null },
                    modifier = Modifier.testTag("error_dialog_ok"),
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.primary),
                ) { Text("OK") }
            },
        )
    }
}

@Composable
private fun IncomingLinkCard(
    item: IncomingLinkItem,
    onOpen: () -> Unit,
    onCopy: () -> Unit,
    onDismiss: () -> Unit,
) {
    val cs = MaterialTheme.colorScheme
    VwCard(container = cs.surfaceContainer) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                IconWell(VwIcons.Link, cs.secondary, cs.surfaceContainerHighest)
                Column(Modifier.weight(1f)) {
                    Text("Link from ${item.pcName}", style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        item.host.ifBlank { SendText.host(item.url) },
                        style = MaterialTheme.typography.bodySmall,
                        color = cs.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                VwChip("Link", ChipTone.Info)
                IconButton(
                    onClick = onDismiss,
                    modifier = Modifier.size(40.dp).testTag("incoming_close_link_${item.id}"),
                ) {
                    Icon(VwIcons.Close, contentDescription = "Dismiss", tint = cs.onSurfaceVariant, modifier = Modifier.size(20.dp))
                }
            }
            Text(
                item.url,
                style = VoidwireTheme.code.codeSmall,
                color = cs.onSurface,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                FilledTonalButton(
                    onClick = onOpen,
                    shape = VoidwireComponentShapes.secondaryButton,
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                    modifier = Modifier.height(36.dp).testTag("incoming_open_link_${item.id}"),
                ) { Text("Open in browser", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) }
                OutlinedButton(
                    onClick = onCopy,
                    shape = VoidwireComponentShapes.secondaryButton,
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                    modifier = Modifier.height(36.dp).testTag("incoming_copy_link_${item.id}"),
                ) { Text("Copy link", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) }
            }
        }
    }
}

@Composable
private fun IncomingClipboardCard(
    item: IncomingClipboardItem,
    onCopy: () -> Unit,
    onSaveTxt: () -> Unit,
    onDismiss: () -> Unit,
) {
    val cs = MaterialTheme.colorScheme
    var revealed by remember(item.id, item.sensitive) { mutableStateOf(!item.sensitive) }
    VwCard(container = cs.surfaceContainer) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                IconWell(VwIcons.Clipboard, cs.secondary, cs.surfaceContainerHighest)
                Column(Modifier.weight(1f)) {
                    Text("Clipboard from ${item.pcName}", style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        if (item.sensitive) "Sensitive text · masked by default" else "Plain text",
                        style = MaterialTheme.typography.bodySmall,
                        color = cs.onSurfaceVariant,
                    )
                }
                if (item.sensitive) {
                    TextButton(
                        onClick = { revealed = !revealed },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                        modifier = Modifier.height(32.dp).testTag("incoming_reveal_clip_${item.id}"),
                    ) { Text(if (revealed) "Hide" else "Reveal", maxLines = 1, softWrap = false) }
                }
                IconButton(
                    onClick = onDismiss,
                    modifier = Modifier.size(40.dp).testTag("incoming_close_clip_${item.id}"),
                ) {
                    Icon(VwIcons.Close, contentDescription = "Dismiss", tint = cs.onSurfaceVariant, modifier = Modifier.size(20.dp))
                }
            }
            Text(
                if (revealed) item.text else "••••••••••••",
                style = VoidwireTheme.code.codeSmall,
                color = cs.onSurface,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                FilledTonalButton(
                    onClick = onCopy,
                    shape = VoidwireComponentShapes.secondaryButton,
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                    modifier = Modifier.height(36.dp).testTag("incoming_copy_clip_${item.id}"),
                ) { Text("Copy to clipboard", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) }
                OutlinedButton(
                    onClick = onSaveTxt,
                    shape = VoidwireComponentShapes.secondaryButton,
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                    modifier = Modifier.height(36.dp).testTag("incoming_save_clip_${item.id}"),
                ) { Text("Save as .txt", maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) }
            }
        }
    }
}

@Composable
private fun IncomingFileCard(
    item: IncomingFileOfferItem,
    busy: Boolean,
    onAccept: () -> Unit,
    onCancelOrDecline: () -> Unit,
) {
    val cs = MaterialTheme.colorScheme
    VwCard(container = cs.surfaceContainer) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                IconWell(VwIcons.File, cs.secondary, cs.surfaceContainerHighest)
                Column(Modifier.weight(1f)) {
                    Text("File from ${item.pcName}", style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        "${item.filename} · ${FileShareStaging.formatSize(item.sizeBytes.toLong())}" +
                            (if (item.relayed) " · via relay" else ""),
                        style = VoidwireTheme.code.codeSmall,
                        color = cs.onSurfaceVariant,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                if (item.isExecutable) {
                    VwChip("Executable", ChipTone.Error)
                } else {
                    VwChip("File", ChipTone.Info)
                }
            }
            if (item.isExecutable) {
                Text(
                    "Executable or installable file — saves to Downloads/Voidwire only and never opens automatically.",
                    style = MaterialTheme.typography.bodySmall,
                    color = VoidwireTheme.extended.warning,
                )
            }
            if (busy || item.accepted) {
                val totalBytes = item.sizeBytes.toLong().coerceAtLeast(1L)
                val doneBytes = item.bytesReceived.toLong().coerceIn(0L, totalBytes)
                val pct = ((doneBytes * 100L) / totalBytes).toInt().coerceIn(0, 100)
                if (doneBytes > 0L) {
                    LinearProgressIndicator(
                        progress = { doneBytes.toFloat() / totalBytes.toFloat() },
                        modifier = Modifier.fillMaxWidth(),
                        color = cs.secondary,
                    )
                } else {
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth(),
                        color = cs.secondary,
                    )
                }
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        if (doneBytes > 0L) {
                            "Receiving… $pct% (${FileShareStaging.formatSize(doneBytes)} / ${FileShareStaging.formatSize(totalBytes)})"
                        } else {
                            "Connecting to ${item.pcName}…"
                        },
                        style = VoidwireTheme.code.codeSmall,
                        color = cs.onSurfaceVariant,
                    )
                    TextButton(
                        onClick = onCancelOrDecline,
                        colors = ButtonDefaults.textButtonColors(contentColor = cs.error),
                        modifier = Modifier.testTag("incoming_cancel_file_${item.transferId}"),
                    ) { Text("Cancel", maxLines = 1, softWrap = false) }
                }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    FilledTonalButton(
                        onClick = onAccept,
                        shape = VoidwireComponentShapes.secondaryButton,
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                        modifier = Modifier.height(36.dp).testTag("incoming_accept_file_${item.transferId}"),
                    ) { Text("Accept & Save", maxLines = 1, softWrap = false) }
                    TextButton(
                        onClick = onCancelOrDecline,
                        colors = ButtonDefaults.textButtonColors(contentColor = cs.error),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                        modifier = Modifier.height(36.dp).testTag("incoming_decline_file_${item.transferId}"),
                    ) { Text("Decline", maxLines = 1, softWrap = false) }
                }
            }
        }
    }
}

@Composable
private fun PcCard(
    pc: PcInfo,
    relayLine: String?,
    onChangeRelay: () -> Unit,
    reachable: Boolean?,
    busy: Boolean,
    sendingClipboard: Boolean,
    sendingFile: Boolean,
    actionsEnabled: Boolean,
    onSendClipboard: () -> Unit,
    onSendFile: () -> Unit,
    onCheck: () -> Unit,
    onForget: () -> Unit,
) {
    val cs = MaterialTheme.colorScheme
    val removed = pc.removed
    VwCard(container = if (removed) androidx.compose.ui.graphics.lerp(cs.surfaceContainer, cs.errorContainer, 0.55f) else cs.surfaceContainer) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                if (removed) IconWell(VwIcons.Unlink, cs.error, cs.surfaceContainerHighest)
                else IconWell(VwIcons.Monitor, cs.tertiary, cs.surfaceContainerHighest)
                Column(Modifier.weight(1f)) {
                    // SPEC §4: card names wrap to 2 lines, then end ellipsis; long-press shows the full name.
                    FullNameTooltip(pc.name) {
                        Text(pc.name, style = MaterialTheme.typography.titleMedium, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    }
                    Text(
                        when {
                            removed -> "This PC removed this phone."
                            reachable == true -> "Paired · checked just now"
                            else -> "Paired"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = cs.onSurfaceVariant,
                    )
                    if (!removed && relayLine != null) {
                        Text(
                            relayLine,
                            style = VoidwireTheme.code.codeSmall,
                            color = cs.onSurfaceVariant,
                            modifier = Modifier.testTag("pc_relay_line"),
                        )
                    }
                }
                when {
                    removed -> VwChip("Removed", ChipTone.Error)
                    reachable == true -> VwChip("Reachable", ChipTone.Ok)
                }
            }
            if (!removed) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedButton(
                        onClick = onSendClipboard,
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f).height(38.dp).testTag("send_clipboard_btn"),
                        shape = VoidwireComponentShapes.secondaryButton,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = cs.onSurface),
                        border = BorderStroke(1.dp, cs.outline),
                    ) {
                        Icon(VwIcons.Clipboard, contentDescription = null, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(
                            if (sendingClipboard) "Sending…" else "Send Clipboard",
                            style = MaterialTheme.typography.labelMedium,
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    OutlinedButton(
                        onClick = onSendFile,
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f).height(38.dp).testTag("send_file_btn"),
                        shape = VoidwireComponentShapes.secondaryButton,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = cs.onSurface),
                        border = BorderStroke(1.dp, cs.outline),
                    ) {
                        Icon(VwIcons.File, contentDescription = null, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(
                            if (sendingFile) "Sending…" else "Send File",
                            style = MaterialTheme.typography.labelMedium,
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                if (!removed) {
                    // Rarely used actions live in a row menu (M4.4.2).
                    var menuOpen by remember { mutableStateOf(false) }
                    Box {
                        TextButton(
                            onClick = { menuOpen = true },
                            enabled = !busy,
                            modifier = Modifier.height(36.dp).testTag("pc_more_btn")
                                .semantics { contentDescription = "More for this device" },
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                            colors = ButtonDefaults.textButtonColors(contentColor = cs.onSurface),
                        ) {
                            if (busy) {
                                // Check connection is running (from this menu).
                                CircularProgressIndicator(Modifier.size(15.dp), strokeWidth = 2.dp, color = cs.secondary)
                            } else {
                                Text("⋯", maxLines = 1, softWrap = false)
                            }
                        }
                        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                            DropdownMenuItem(
                                text = { Text("Check connection") },
                                onClick = { menuOpen = false; onCheck() },
                                modifier = Modifier.testTag("check_pc_btn"),
                            )
                            DropdownMenuItem(
                                text = { Text("Change relay…") },
                                onClick = { menuOpen = false; onChangeRelay() },
                                modifier = Modifier.testTag("change_relay_btn"),
                            )
                        }
                    }
                }
                TextButton(
                    onClick = onForget,
                    modifier = Modifier.height(36.dp),
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    colors = ButtonDefaults.textButtonColors(contentColor = cs.error),
                ) { Text("Forget", maxLines = 1, softWrap = false) }
            }
        }
    }
}

/** THIS PHONE ─ relay ─ YOUR PC (SPEC 1.4, REVIEW-m11 #1), the only illustration. */
@Composable
private fun WireStrip(keepsHistory: Boolean, onHistory: () -> Unit) {
    val ext = VoidwireTheme.extended
    val cs = MaterialTheme.colorScheme
    VwCard(container = cs.surfaceContainerLow) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                NodeBox("THIS PHONE")
                Canvas(Modifier.weight(1f).height(14.dp)) {
                    val y = size.height / 2
                    val w = 26.dp.toPx()
                    val gap = 5.dp.toPx()
                    val cx = size.width / 2
                    drawLine(cs.secondary, Offset(0f, y), Offset(cx - w / 2 - gap, y), strokeWidth = 2.dp.toPx())
                    drawLine(cs.secondary, Offset(cx + w / 2 + gap, y), Offset(size.width, y), strokeWidth = 2.dp.toPx())
                    drawRect(cs.primary, topLeft = Offset(cx - w / 2, y - 4.dp.toPx()), size = androidx.compose.ui.geometry.Size(w, 8.dp.toPx()))
                }
                NodeBox("YOUR PC")
            }
            // Claims kept only while true (SPEC 3.2): NO HISTORY only while
            // every history-type opt-in is off; otherwise HISTORY ON (warning,
            // clock icon, opens Settings) so the user sees something is kept.
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Fact(VwIcons.Lock, "ENCRYPTED")
                Fact(VwIcons.Shield, "NO ACCOUNT")
                if (keepsHistory) {
                    // F1 (REVIEW-m11-android): 48dp minimum touch target, compact warning pill.
                    Box(
                        Modifier.minimumInteractiveComponentSize()
                            .clip(VoidwireComponentShapes.chip)
                            .clickable(onClickLabel = "Open Settings", onClick = onHistory),
                        contentAlignment = Alignment.Center,
                    ) {
                        Row(
                            Modifier.background(ext.warning.copy(alpha = 0.12f), VoidwireComponentShapes.chip)
                                .padding(horizontal = 8.dp, vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Icon(VwIcons.Clock, contentDescription = null, tint = ext.warning, modifier = Modifier.size(14.dp))
                            Text("HISTORY ON", style = VoidwireTheme.code.codeSmall, color = ext.warning)
                        }
                    }
                } else {
                    Fact(VwIcons.EyeOff, "NO HISTORY")
                }
            }
        }
    }
}

@Composable
private fun NodeBox(text: String) {
    Box(Modifier.border(1.dp, MaterialTheme.colorScheme.tertiary, RectangleShape).padding(horizontal = 7.dp, vertical = 4.dp)) {
        Text(text, style = MaterialTheme.typography.labelSmall.copy(letterSpacing = 0.08.em), color = MaterialTheme.colorScheme.tertiary)
    }
}

@Composable
private fun Fact(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Icon(icon, contentDescription = null, tint = VoidwireTheme.extended.success, modifier = Modifier.size(14.dp))
        Text(text, style = VoidwireTheme.code.codeSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** SPEC 3.7 (screens/13): privacy, this phone, about. */
@Composable
private fun SettingsScreen(phone: PhoneInterface, themeMode: ThemeMode, onThemeMode: (ThemeMode) -> Unit, onBack: () -> Unit) {
    val context = LocalContext.current
    var keepRecent by remember { mutableStateOf(RecentSends.enabled(context)) }
    var rememberPc by remember { mutableStateOf(LastPc.enabled(context)) }
    var recent by remember { mutableStateOf(RecentSends.list(context)) }
    var name by remember { mutableStateOf(phone.deviceName()) }
    var nameNote by remember { mutableStateOf<String?>(null) }
    var neverRelayFiles by remember { mutableStateOf(phone.neverSendFilesOverRelay()) }
    val scope = rememberCoroutineScope()
    var showIncomingNotif by remember { mutableStateOf(IncomingNotificationPref.enabled(context)) }
    var bgReceiveEnabled by remember { mutableStateOf(BackgroundReceivePref.enabled(context)) }
    val settingsNotifPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (!granted && android.os.Build.VERSION.SDK_INT >= 33) {
            IncomingNotificationPref.setEnabled(context, false)
            showIncomingNotif = false
        }
    }
    var connStatsEnabled by remember { mutableStateOf(phone.connectionStatsEnabled()) }
    var connStats by remember { mutableStateOf(if (connStatsEnabled) phone.connectionStats() else emptyList()) }
    val cs = MaterialTheme.colorScheme
    Column(Modifier.fillMaxSize()) {
        VwTopBar("Settings", onBack = onBack)
        BoxWithConstraints(Modifier.fillMaxSize()) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).heightIn(min = maxHeight).padding(horizontal = 20.dp).padding(bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Eyebrow("Privacy")
            VwCard {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Keep recent sends", style = MaterialTheme.typography.titleMedium)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "Off: nothing is stored about the links you send. On: keeps the time, site (host only) and result of your last 20 sends on this phone. Turning it off deletes them.",
                                style = MaterialTheme.typography.bodySmall,
                                color = cs.onSurfaceVariant,
                            )
                        }
                        Spacer(Modifier.width(12.dp))
                        Switch(
                            checked = keepRecent,
                            onCheckedChange = { on ->
                                RecentSends.setEnabled(context, on)
                                keepRecent = RecentSends.enabled(context)
                                recent = RecentSends.list(context)
                            },
                        )
                    }
                    if (keepRecent) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("Recent sends", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                            OutlinedButton(
                                onClick = { RecentSends.clear(context); recent = emptyList() },
                                shape = VoidwireComponentShapes.secondaryButton,
                                colors = dangerOutlinedButtonColors(),
                                border = dangerOutlinedBorder(),
                            ) { Text("Clear") }
                        }
                        if (recent.isEmpty()) DashedNote(VwIcons.EyeOff, "NOTHING SENT YET")
                        for (line in recent) {
                            val (top, sub) = SendText.splitRecent(line)
                            Column(Modifier.semantics(mergeDescendants = true) {}, verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(top, style = VoidwireTheme.code.codeSmall, color = cs.onSurface, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                if (sub != null) {
                                    Text(sub, style = VoidwireTheme.code.codeSmall, color = cs.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                }
                            }
                        }
                    }
                    HorizontalDivider(color = cs.outlineVariant)
                    // Round 2 (SPEC 3.6/3.7, R4b): off by default; off = A–Z, nothing stored.
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Remember last PC", style = MaterialTheme.typography.titleMedium)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "Puts the PC you last sent to first in the share sheet. Off: PCs in A–Z order, nothing stored.",
                                style = MaterialTheme.typography.bodySmall,
                                color = cs.onSurfaceVariant,
                            )
                        }
                        Spacer(Modifier.width(12.dp))
                        Switch(
                            checked = rememberPc,
                            onCheckedChange = { on ->
                                LastPc.setEnabled(context, on)
                                rememberPc = LastPc.enabled(context)
                            },
                        )
                    }
                    // REVIEW-m11 #6: one dashed box, only while both switches are off.
                    if (!keepRecent && !rememberPc) DashedNote(VwIcons.EyeOff, "NOTHING ABOUT YOUR SENDS IS STORED")
                }
            }
            Eyebrow("This phone")
            VwCard {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it.take(64); nameNote = null },
                        singleLine = true,
                        label = { Text("Name shown on your PCs") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            nameNote ?: "PCs you pair from now on will show this name.",
                            style = MaterialTheme.typography.bodySmall,
                            color = cs.onSurfaceVariant,
                            modifier = Modifier.weight(1f),
                        )
                        Spacer(Modifier.width(8.dp))
                        FilledTonalButton(shape = VoidwireComponentShapes.secondaryButton, onClick = {
                            nameNote = try {
                                phone.setDeviceName(name.trim())
                                "Saved. PCs you pair from now on will show this name."
                            } catch (e: Exception) {
                                PhoneErrors.text(e)
                            }
                        }) { Text("Save") }
                    }
                }
            }
            Eyebrow("Appearance")
            VwCard {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("Theme", style = MaterialTheme.typography.titleMedium)
                    ThemeSegments(themeMode, onThemeMode)
                    Text(
                        "System follows Android; dark if it doesn't say.",
                        style = MaterialTheme.typography.bodySmall,
                        color = cs.onSurfaceVariant,
                    )
                }
            }
            Eyebrow("Incoming & notifications")
            VwCard {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Show notifications for incoming items", style = MaterialTheme.typography.titleMedium)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "Posts a generic alert ('Voidwire — New item waiting (tap to view)') when a new item arrives while Voidwire isn't on screen. Never includes URLs, text, filenames, or device names. Needs Receive in background: with it off, Android pauses Voidwire soon after you leave it, so new items wait silently until you open the app.",
                                style = MaterialTheme.typography.bodySmall,
                                color = cs.onSurfaceVariant,
                            )
                        }
                        Spacer(Modifier.width(12.dp))
                        Switch(
                            checked = showIncomingNotif,
                            onCheckedChange = { on ->
                                IncomingNotificationPref.setEnabled(context, on)
                                showIncomingNotif = IncomingNotificationPref.enabled(context)
                                if (!showIncomingNotif) {
                                    VoidwireNotifications.cancelIncoming(context)
                                } else if (
                                    android.os.Build.VERSION.SDK_INT >= 33 &&
                                    ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                                ) {
                                    runCatching { settingsNotifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) }
                                }
                            },
                            modifier = Modifier.testTag("incoming_notif_switch"),
                        )
                    }
                    HorizontalDivider(color = cs.outlineVariant)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Receive in background", style = MaterialTheme.typography.titleMedium)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "Off by default. Keeps Voidwire connected (shows a silent 'Listening for your PC' notification) so items from your PC arrive and alert you even when Voidwire is closed. Also checks the blind relay inbox when the screen turns on or the network changes.",
                                style = MaterialTheme.typography.bodySmall,
                                color = cs.onSurfaceVariant,
                            )
                        }
                        Spacer(Modifier.width(12.dp))
                        Switch(
                            checked = bgReceiveEnabled,
                            onCheckedChange = { on ->
                                BackgroundReceivePref.setEnabled(context, on)
                                bgReceiveEnabled = BackgroundReceivePref.enabled(context)
                                VoidwireReceiveService.syncWithPreference(context)
                                scope.launch(Dispatchers.IO) {
                                    runCatching { phone.setBackgroundListening(bgReceiveEnabled) }
                                }
                                if (
                                    bgReceiveEnabled &&
                                    android.os.Build.VERSION.SDK_INT >= 33 &&
                                    ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                                ) {
                                    runCatching { settingsNotifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) }
                                }
                            },
                            modifier = Modifier.testTag("bg_receive_switch"),
                        )
                    }
                }
            }
            Eyebrow("File transfers & relay")
            VwCard {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Never send files over relay", style = MaterialTheme.typography.titleMedium)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "Off: when your PC isn't on the same Wi-Fi/LAN, files over 256 KB ask before using the encrypted blind relay, and files over 25 MB can't use the relay. On: files only send over a direct local network connection.",
                                style = MaterialTheme.typography.bodySmall,
                                color = cs.onSurfaceVariant,
                            )
                        }
                        Spacer(Modifier.width(12.dp))
                        Switch(
                            checked = neverRelayFiles,
                            onCheckedChange = { never ->
                                runCatching { phone.setNeverSendFilesOverRelay(never) }
                                neverRelayFiles = phone.neverSendFilesOverRelay()
                            },
                            modifier = Modifier.testTag("never_relay_switch"),
                        )
                    }
                    HorizontalDivider(color = cs.outlineVariant)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Keep on-device connection stats", style = MaterialTheme.typography.titleMedium)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "Day-granularity direct vs. relay counts. Never leaves this phone; turning off wipes saved stats.",
                                style = MaterialTheme.typography.bodySmall,
                                color = cs.onSurfaceVariant,
                            )
                        }
                        Spacer(Modifier.width(12.dp))
                        Switch(
                            checked = connStatsEnabled,
                            onCheckedChange = { on ->
                                runCatching { phone.setConnectionStatsEnabled(on) }
                                connStatsEnabled = phone.connectionStatsEnabled()
                                connStats = if (connStatsEnabled) phone.connectionStats() else emptyList()
                            },
                        )
                    }
                    if (connStatsEnabled) {
                        val directTotal = connStats.sumOf { it.directCount.toLong() }
                        val relayTotal = connStats.sumOf { it.relayCount.toLong() }
                        Text(
                            "$directTotal direct · $relayTotal relay recorded",
                            style = VoidwireTheme.code.codeSmall,
                            color = cs.onSurfaceVariant,
                            modifier = Modifier.testTag("conn_stats_summary"),
                        )
                    }
                }
            }
            Eyebrow("Relays")
            VwCard {
                Column(Modifier.padding(16.dp)) {
                    RelaysSection(phone) {}
                }
            }
            // About: a mono footer line, centred and pinned to the bottom (REVIEW-m11 #6).
            Spacer(Modifier.weight(1f))
            Text(
                "VOIDWIRE ${appVersion(context)} · CORE ${coreVersion()}",
                style = VoidwireTheme.code.codeSmall,
                color = cs.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            )
        }
        }
    }

}

/** System | Dark | Light (SPEC 3.7): segmented shape, sharp selected segment, gold underline. */

@Composable
private fun ThemeSegments(mode: ThemeMode, onMode: (ThemeMode) -> Unit) {
    val cs = MaterialTheme.colorScheme
    Row(
        Modifier.clip(VoidwireComponentShapes.segmented).background(cs.outlineVariant).padding(1.dp)
            .clip(VoidwireComponentShapes.segmented).background(cs.surfaceContainerHigh).padding(4.dp)
            .selectableGroup(),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        for (m in ThemeMode.entries) {
            val on = m == mode
            Box(
                Modifier.weight(1f).height(40.dp)
                    .background(if (on) cs.surfaceContainerHighest else Color.Transparent)
                    .selectable(selected = on, role = Role.RadioButton, onClick = { onMode(m) })
                    .drawBehind {
                        if (on) drawRect(cs.primary, topLeft = Offset(0f, size.height - 2.dp.toPx()), size = androidx.compose.ui.geometry.Size(size.width, 2.dp.toPx()))
                    },
                contentAlignment = Alignment.Center,
            ) {
                Text(m.name, style = MaterialTheme.typography.labelLarge, color = if (on) cs.onSurface else cs.onSurfaceVariant)
            }
        }
    }
}

private fun appVersion(context: android.content.Context): String = try {
    context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "?"
} catch (e: Exception) {
    "?"
}

/** SPEC 3.3 (screens/09). */
@Composable
private fun ScanScreen(onQr: (String) -> Unit, onBack: () -> Unit, onShowCode: () -> Unit = {}, onTypeCode: () -> Unit = {}) {
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED,
        )
    }
    var denied by remember { mutableStateOf(false) }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        granted = it
        denied = !it
    }
    LaunchedEffect(Unit) { if (!granted) ask.launch(Manifest.permission.CAMERA) }
    var pasted by remember { mutableStateOf("") }
    val cs = MaterialTheme.colorScheme
    val conf = androidx.compose.ui.platform.LocalConfiguration.current
    val camH = minOf((conf.screenWidthDp - 40) * 4f / 3f, conf.screenHeightDp * 0.45f).coerceAtLeast(160f).dp

    Column(Modifier.fillMaxSize()) {
        VwTopBar("Pair a device", onBack = onBack)
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp).padding(bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            // M4.3: another phone, or a PC, by code. v0.7.1: above the camera,
            // so they are on screen without scrolling at any size or font scale.
            Text("Pairing with another phone, or a PC by code?", style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onShowCode, modifier = Modifier.weight(1f).heightIn(min = 48.dp), shape = VoidwireComponentShapes.secondaryButton) { Text("Show a code") }
                OutlinedButton(onClick = onTypeCode, modifier = Modifier.weight(1f).heightIn(min = 48.dp), shape = VoidwireComponentShapes.secondaryButton) { Text("Type a code") }
            }
            Text(
                buildAnnotatedString {
                    append("On the PC: click the Voidwire tray icon → ")
                    withStyle(SpanStyle(fontWeight = FontWeight.SemiBold)) { append("Pair a phone…") }
                    append(" and point the camera at the code.")
                },
                style = MaterialTheme.typography.bodyMedium,
                color = cs.onSurfaceVariant,
            )
            Box(
                // REVIEW-m11 #5d: a visible 1 dp chamfered frame (no glow).
                // v0.7.1: 3:4, but never taller than 45% of the screen.
                Modifier.fillMaxWidth().height(camH).clip(VoidwireComponentShapes.card).background(cs.surfaceContainerLowest)
                    .border(1.dp, cs.outlineVariant, VoidwireComponentShapes.card),
                contentAlignment = Alignment.Center,
            ) {
                when {
                    granted -> QrScanner(Modifier.fillMaxSize(), onResult = onQr)
                    denied -> Icon(VwIcons.EyeOff, contentDescription = null, tint = cs.onSurfaceVariant, modifier = Modifier.size(40.dp))
                    else -> CircularProgressIndicator(color = cs.secondary)
                }
                Reticle()
                Surface(
                    Modifier.align(Alignment.BottomCenter).padding(bottom = 16.dp),
                    shape = CircleShape,
                    color = Color(0xCC070B14),
                ) {
                    Row(Modifier.padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(6.dp).clip(CircleShape).background(cs.secondary))
                        Spacer(Modifier.width(8.dp))
                        Text("LOOKING FOR A VOIDWIRE CODE", style = MaterialTheme.typography.labelSmall, color = Color(0xFFE3E8EE))
                    }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(VwIcons.EyeOff, contentDescription = null, tint = cs.onSurfaceVariant, modifier = Modifier.size(16.dp).padding(top = 1.dp))
                Text(
                    if (denied) "The camera is only used to read this code. Nothing is saved. Allow it in Settings → Apps."
                    else "The camera is only used to read this code. Nothing is saved.",
                    style = MaterialTheme.typography.bodySmall,
                    color = cs.onSurfaceVariant,
                )
            }
            OutlinedTextField(
                value = pasted,
                onValueChange = { pasted = it.trim() },
                singleLine = true,
                label = { Text("Can't scan? Paste the pairing link") },
                placeholder = { Text("voidwire:pair?…", style = VoidwireTheme.code.codeMedium) },
                supportingText = { Text("Starts with voidwire:pair?", style = VoidwireTheme.code.codeSmall) },
                modifier = Modifier.fillMaxWidth(),
            )
            // REVIEW-m11 #5a: full width, 48 dp.
            FilledTonalButton(
                shape = VoidwireComponentShapes.secondaryButton,
                enabled = QrDecode.looksLikePairing(pasted),
                onClick = { onQr(pasted) },
                modifier = Modifier.fillMaxWidth().height(48.dp),
            ) { Text("Use link") }
        }
    }
}

/** Gold corner brackets + a blue scan line over the preview (static if animations are off). */
@Composable
private fun Reticle() {
    val gold = VoidwireTheme.extended.relay
    val blue = MaterialTheme.colorScheme.secondary
    val t = rememberInfiniteTransition(label = "scan")
    val f by t.animateFloat(0f, 1f, infiniteRepeatable(tween(1600, easing = LinearEasing), RepeatMode.Reverse), label = "line")
    BoxWithConstraints(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        val side = minOf(maxWidth, maxHeight) * 0.68f
        Canvas(Modifier.size(side)) {
            val l = size.width * 0.16f
            val sw = 3.dp.toPx()
            val st = Stroke(sw, cap = StrokeCap.Round)
            val w = size.width
            val h = size.height
            for ((p, dx, dy) in listOf(Triple(Offset(0f, 0f), 1, 1), Triple(Offset(w, 0f), -1, 1), Triple(Offset(0f, h), 1, -1), Triple(Offset(w, h), -1, -1))) {
                drawLine(gold, p, Offset(p.x + dx * l, p.y), strokeWidth = st.width, cap = StrokeCap.Round)
                drawLine(gold, p, Offset(p.x, p.y + dy * l), strokeWidth = st.width, cap = StrokeCap.Round)
            }
            val y = h * (0.1f + 0.8f * f)
            drawLine(blue, Offset(w * 0.08f, y), Offset(w * 0.92f, y), strokeWidth = 2.dp.toPx(), cap = StrokeCap.Round)
        }
    }
}

private sealed interface PairState {
    data object Checking : PairState
    /**
     * OQ-9 / PAIR-11: the PC isn't in a device group this phone already
     * belongs to (decided from its authenticated identity, not the QR's group
     * id), and/or it has the same name as a different paired PC.
     */
    data class ConfirmGroupChange(
        val pcName: String,
        val current: List<String>,
        val differentGroup: Boolean,
        val duplicateName: Boolean,
    ) : PairState
    data object Connecting : PairState
    data class ShowCode(val pairing: Pairing, val code: String, val pcName: String) : PairState
    data class Paired(val pcName: String) : PairState
    data class Failed(val message: String) : PairState
}

@Composable
private fun PairingScreen(phone: PhoneInterface, qr: String, onDone: () -> Unit) {
    val context = LocalContext.current
    var state by remember { mutableStateOf<PairState>(PairState.Checking) }
    // null = not decided yet; true only after an explicit "Join" in the warning.
    var confirmGroupChange by remember { mutableStateOf<Boolean?>(null) }
    LaunchedEffect(qr) {
        // Offline check first: is this QR for a different device group?
        state = try {
            val preview = withContext(Dispatchers.IO) { phone.inspectPairing(qr) }
            if (preview.joinsDifferentGroup || preview.duplicateName) {
                PairState.ConfirmGroupChange(
                    preview.pcName ?: "an unnamed PC",
                    preview.currentGroups,
                    preview.joinsDifferentGroup,
                    preview.duplicateName,
                )
            } else {
                confirmGroupChange = false
                PairState.Connecting
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            // Left the composition or the key changed: a stale run must not
            // overwrite the live state with "Pairing didn't finish".
            throw e
        } catch (e: Exception) {
            PairState.Failed(PhoneErrors.text(e))
        }
    }
    LaunchedEffect(confirmGroupChange) {
        val confirmed = confirmGroupChange ?: return@LaunchedEffect
        state = PairState.Connecting
        var started: Pairing? = null
        try {
            val pairing = withContext(Dispatchers.IO) {
                Core.withMulticast(context) { phone.beginPairing(qr, confirmed) }
            }
            started = pairing
            state = PairState.ShowCode(pairing, pairing.code(), pairing.pcName())
            val pc = withContext(Dispatchers.IO) { pairing.wait(130u) }
            state = PairState.Paired(pc.name)
        } catch (e: kotlinx.coroutines.CancellationException) {
            runCatching { started?.cancel() }
            throw e
        } catch (e: Exception) {
            state = PairState.Failed(PhoneErrors.text(e))
        }
    }
    BackHandler {
        (state as? PairState.ShowCode)?.pairing?.cancel()
        onDone()
    }
    val cs = MaterialTheme.colorScheme
    val ext = VoidwireTheme.extended
    val cancel = {
        (state as? PairState.ShowCode)?.pairing?.cancel()
        onDone()
    }
    Column(Modifier.fillMaxSize()) {
        VwTopBar("Pair a device", onBack = cancel)
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp).padding(bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            when (val s = state) {
                PairState.Checking, is PairState.ConfirmGroupChange -> Box(Modifier.fillMaxWidth().padding(top = 48.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = cs.secondary)
                }
                PairState.Connecting -> {
                    StepRail(1)
                    Box(Modifier.fillMaxWidth().padding(top = 32.dp), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = cs.secondary)
                    }
                    Text("Connecting to the PC…", color = cs.onSurfaceVariant, modifier = Modifier.align(Alignment.CenterHorizontally))
                }
                is PairState.ShowCode -> {
                    StepRail(1)
                    Eyebrow("Type this on the PC")
                    Text(
                        buildAnnotatedString {
                            append("Enter this code on ")
                            withStyle(SpanStyle(color = cs.tertiary)) { append(s.pcName) }
                        },
                        style = MaterialTheme.typography.headlineSmall,
                    )
                    CodeCells(s.code)
                    LinearProgressIndicator(Modifier.fillMaxWidth(), color = cs.secondary, trackColor = cs.surfaceContainerHighest)
                    Text("WAITING FOR THE PC…", style = MaterialTheme.typography.labelSmall, color = cs.onSurfaceVariant)
                    HintCard(VwIcons.Shield) {
                        Text(
                            "The PC asks for this code so only the phone in your hand can pair. Never read it out to anyone.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(onClick = cancel, modifier = Modifier.fillMaxWidth().height(48.dp), shape = VoidwireComponentShapes.secondaryButton, colors = ButtonDefaults.outlinedButtonColors(contentColor = cs.onSurfaceVariant)) { Text("Cancel") }
                }
                is PairState.Paired -> {
                    StepRail(3)
                    Box(Modifier.padding(top = 24.dp).size(56.dp).clip(CircleShape).background(ext.success.copy(alpha = 0.14f)), contentAlignment = Alignment.Center) {
                        Icon(VwIcons.Check, contentDescription = null, tint = ext.success, modifier = Modifier.size(28.dp))
                    }
                    Text("Paired with ${s.pcName}", style = MaterialTheme.typography.headlineSmall)
                    Text(
                        "Share a link from any app and pick \"${stringResource(R.string.share_label)}\".",
                        color = cs.onSurfaceVariant,
                    )
                    Button(onClick = onDone, modifier = Modifier.fillMaxWidth().height(48.dp), shape = VoidwireComponentShapes.primaryButton, border = primaryButtonBorder()) { Text("Done") }
                }
                is PairState.Failed -> {
                    Box(Modifier.padding(top = 24.dp).size(56.dp).clip(CircleShape).background(cs.errorContainer), contentAlignment = Alignment.Center) {
                        Icon(VwIcons.Close, contentDescription = null, tint = cs.error, modifier = Modifier.size(28.dp))
                    }
                    Text("Pairing didn't finish", style = MaterialTheme.typography.headlineSmall)
                    Text(s.message, color = cs.onSurfaceVariant)
                    Button(onClick = onDone, modifier = Modifier.fillMaxWidth().height(48.dp), shape = VoidwireComponentShapes.primaryButton, border = primaryButtonBorder()) { Text("Back") }
                }
            }
        }
    }
    (state as? PairState.ConfirmGroupChange)?.let { s ->
        // SPEC 3.4. Cancel is the default: back, tapping outside and the
        // primary button all cancel. Joining needs the explicit "Join" text
        // button. Logic unchanged from M1.
        AlertDialog(
            onDismissRequest = onDone,
            containerColor = cs.surfaceContainerHigh,
            icon = {
                Box(Modifier.size(44.dp).clip(VoidwireComponentShapes.iconWell).background(ext.warningContainer), contentAlignment = Alignment.Center) {
                    Icon(VwIcons.Warn, contentDescription = null, tint = ext.warning)
                }
            },
            title = {
                Text(if (s.differentGroup) "Join a different device group?" else "Another PC with this name?")
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    val parts = mutableListOf<String>()
                    if (s.differentGroup) {
                        parts += "This will join a different device group (named ${s.pcName}). " +
                            "This phone is already paired in the group of: ${s.current.joinToString()}."
                    }
                    if (s.duplicateName) {
                        parts += "You already have a different PC named ${s.pcName}. " +
                            "This is a second, separate PC with the same name."
                    }
                    parts += "Only continue if you set up this PC yourself and expect this."
                    Text(parts.joinToString(" "))
                    Surface(shape = RoundedCornerShape(10.dp), color = cs.surfaceContainerLowest, modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Row {
                                Text("NEW GROUP", style = VoidwireTheme.code.codeSmall, color = ext.warning, modifier = Modifier.width(88.dp))
                                Text(s.pcName, style = VoidwireTheme.code.codeSmall, color = cs.onSurface)
                            }
                            Row {
                                Text("CURRENT", style = VoidwireTheme.code.codeSmall, color = cs.onSurfaceVariant, modifier = Modifier.width(88.dp))
                                Text(s.current.joinToString().ifEmpty { "—" }, style = VoidwireTheme.code.codeSmall, color = cs.onSurface)
                            }
                        }
                    }
                }
            },
            confirmButton = { Button(onClick = onDone, shape = VoidwireComponentShapes.primaryButton, border = primaryButtonBorder()) { Text("Cancel") } },
            dismissButton = {
                TextButton(
                    onClick = { confirmGroupChange = true },
                    colors = ButtonDefaults.textButtonColors(contentColor = ext.warning),
                ) { Text("Join") }
            },
        )
    }
}

/** SCAN ✓ — CODE — DONE (SPEC 3.5). [current]: 1 = code, 3 = done. */
@Composable
private fun StepRail(current: Int) {
    val cs = MaterialTheme.colorScheme
    val ok = VoidwireTheme.extended.success
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("SCAN ✓", style = MaterialTheme.typography.labelSmall, color = ok)
        Text("—", style = MaterialTheme.typography.labelSmall, color = cs.outline)
        Text(if (current > 1) "CODE ✓" else "CODE", style = MaterialTheme.typography.labelSmall, color = if (current > 1) ok else VoidwireTheme.extended.relay)
        Text("—", style = MaterialTheme.typography.labelSmall, color = cs.outline)
        Text(if (current > 2) "DONE ✓" else "DONE", style = MaterialTheme.typography.labelSmall, color = if (current > 2) ok else cs.onSurfaceVariant)
    }
}

/** Six cells (50×68 dp) in 3+3, codeLarge in primary. */
@Composable
private fun CodeCells(code: String) {
    val cs = MaterialTheme.colorScheme
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
        code.take(6).forEachIndexed { i, c ->
            if (i == 3) Box(Modifier.padding(horizontal = 6.dp).width(10.dp).height(2.dp).background(cs.outline))
            Box(
                Modifier.padding(horizontal = 3.dp).size(width = 50.dp, height = 68.dp).clip(VoidwireComponentShapes.codeCell).background(cs.surfaceContainerHigh)
                    .border(1.dp, cs.outlineVariant, VoidwireComponentShapes.codeCell),
                contentAlignment = Alignment.Center,
            ) { Text(c.toString(), style = VoidwireTheme.code.codeLarge, color = VoidwireTheme.extended.relay) }
        }
    }
}
