package app.voidwire.android

import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.draw.alpha
import androidx.compose.foundation.layout.PaddingValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import androidx.compose.ui.platform.testTag
import androidx.core.content.IntentCompat
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import android.graphics.Rect
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.MotionEvent
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.annotation.VisibleForTesting
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.ui.Alignment
import androidx.compose.ui.res.painterResource
import app.voidwire.android.ui.ChipTone
import app.voidwire.android.ui.VwChip
import app.voidwire.android.ui.VwIcons
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import app.voidwire.android.ui.DashedNote
import app.voidwire.android.ui.IconWell
import app.voidwire.android.ui.theme.VoidwireComponentShapes
import app.voidwire.android.ui.theme.VoidwireTheme
import androidx.compose.ui.graphics.luminance
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.boundsInWindow
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.voidwire_core.PhoneException
import uniffi.voidwire_core.ShareUrlException
import uniffi.voidwire_core.SharedContent
import uniffi.voidwire_core.classifySharedText
import uniffi.voidwire_core.extractShareableUrl

/** A paired PC the link can go to (decoupled from the UniFFI types for tests). */
data class ShareTarget(val id: String, val name: String)

/** Result of one send, already worded for the screen and the Recent list. */
sealed interface ShareSendResult {
    val message: String
    data class Sent(override val message: String) : ShareSendResult
    data class Failed(override val message: String) : ShareSendResult
}

/** Metadata for a shared stream copied to private cache storage (`cacheDir/share-staging/`). */
data class StagedShareFile(
    val filePath: String,
    val displayName: String,
    val sizeBytes: Long,
    val mime: String,
)

/** Outcome of one file transfer attempt (`M2.7`). */
sealed interface FileShareOutcome {
    data class Sent(val message: String) : FileShareOutcome
    data class RelayPromptNeeded(val sizeBytes: Long, val promptText: String) : FileShareOutcome
    data class Failed(val message: String) : FileShareOutcome
}

/**
 * Streams a shared `content://` URI into private `cacheDir/share-staging/<name>` after
 * verifying `size <= 2 GiB`, and deletes staging files immediately after completion/cancel.
 */
object FileShareStaging {
    const val MAX_FILE_BYTES: Long = 2L * 1024L * 1024L * 1024L
    private const val COPY_BUFFER_BYTES: Int = 64 * 1024

    @VisibleForTesting
    internal var currentAppUid: () -> Int = { android.os.Process.myUid() }

    fun formatSize(bytes: Long): String = when {
        bytes < 1024L -> "$bytes B"
        bytes < 1024L * 1024L -> String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0).removeSuffix(".0 KB") + (if (String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0).endsWith(".0 KB")) " KB" else "")
        bytes < 1024L * 1024L * 1024L -> String.format(java.util.Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
        else -> String.format(java.util.Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
    }

    fun sanitizeName(raw: String?): String {
        val base = (raw ?: "shared-file").substringAfterLast('/').substringAfterLast('\\').trim()
        val cleaned = base.filter { it.code >= 0x20 && it !in "<>:\"/\\|?*" }.trim().take(180)
        if (cleaned.isEmpty() || cleaned == "." || cleaned == "..") return "shared-file"
        return cleaned
    }

    internal fun privateAppDirs(context: Context): List<File> {
        val dirs = mutableListOf<File?>()
        dirs += context.applicationInfo?.dataDir?.let { File(it) }
        dirs += runCatching { context.filesDir }.getOrNull()
        dirs += runCatching { context.noBackupFilesDir }.getOrNull()
        dirs += runCatching { context.cacheDir }.getOrNull()
        dirs += runCatching { context.codeCacheDir }.getOrNull()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            dirs += runCatching { context.createDeviceProtectedStorageContext().dataDir }.getOrNull()
        }
        return dirs.filterNotNull().map { d ->
            runCatching { d.canonicalFile }.getOrElse { d.absoluteFile }
        }
    }

    internal fun isInsidePrivateAppDir(context: Context, candidate: File): Boolean {
        val resolved = runCatching { candidate.canonicalFile }.getOrElse { candidate.absoluteFile }
        val resolvedPath = resolved.path
        return privateAppDirs(context).any { priv ->
            val p = priv.path
            resolvedPath == p || resolvedPath.startsWith(p + File.separator)
        }
    }

    internal fun verifyDescriptorNotSelfOwnedOrPrivate(
        context: Context,
        pfd: android.os.ParcelFileDescriptor,
        disallowOwnUid: Boolean,
    ) {
        val fdPath = "/proc/self/fd/${pfd.fd}"
        val linkTarget = runCatching { android.system.Os.readlink(fdPath) }.getOrNull()
        if (linkTarget != null && isInsidePrivateAppDir(context, File(linkTarget))) {
            throw IllegalArgumentException("Can't share internal app files.")
        }
        val canonTarget = runCatching { File(fdPath).canonicalFile }.getOrNull()
        if (canonTarget != null && isInsidePrivateAppDir(context, canonTarget)) {
            throw IllegalArgumentException("Can't share internal app files.")
        }
        val st = runCatching { android.system.Os.fstat(pfd.fileDescriptor) }.getOrNull()
        if (st != null) {
            if (android.system.OsConstants.S_ISLNK(st.st_mode)) {
                throw IllegalArgumentException("Can't share symbolic links.")
            }
            val appUid = currentAppUid()
            if (disallowOwnUid && appUid > 0 && st.st_uid == appUid) {
                throw IllegalArgumentException("Can't share internal app files.")
            }
        }
    }

    fun stage(
        context: Context,
        uri: Uri,
        fallbackMime: String? = null,
        maxBytes: Long = MAX_FILE_BYTES,
        disallowOwnUid: Boolean = true,
    ): StagedShareFile {
        // M27-H2: Strictly require content:// scheme (reject file://, android.resource://, etc.)
        if (uri.scheme != android.content.ContentResolver.SCHEME_CONTENT) {
            throw IllegalArgumentException("Only content:// files can be shared.")
        }
        uri.path?.let { rawPath ->
            if (rawPath.isNotBlank() && isInsidePrivateAppDir(context, File(rawPath))) {
                throw IllegalArgumentException("Can't share internal app files.")
            }
        }
        val resolver = context.contentResolver
        var displayName: String? = null
        var knownSize: Long = -1L
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (nameIdx >= 0 && !c.isNull(nameIdx)) displayName = c.getString(nameIdx)
                val sizeIdx = c.getColumnIndex(OpenableColumns.SIZE)
                if (sizeIdx >= 0 && !c.isNull(sizeIdx)) knownSize = c.getLong(sizeIdx)
            }
        }
        if (knownSize > maxBytes) {
            throw IllegalArgumentException("This file is larger than the 2 GB limit.")
        }
        val safeName = sanitizeName(displayName ?: uri.lastPathSegment)
        val mime = resolver.getType(uri) ?: fallbackMime ?: "application/octet-stream"
        val dir = File(context.cacheDir, "share-staging").apply { mkdirs() }
        val dst = File(dir, safeName)
        // M27-M2: Verify canonical destination stays strictly inside share-staging/
        val canonDir = dir.canonicalFile
        val canonDst = dst.canonicalFile
        if (canonDst.parentFile != canonDir) {
            throw IllegalArgumentException("Invalid file name.")
        }
        try {
            val pfd = runCatching { resolver.openFileDescriptor(uri, "r") }.getOrNull()
            val inputStream: java.io.InputStream = if (pfd != null) {
                try {
                    verifyDescriptorNotSelfOwnedOrPrivate(context, pfd, disallowOwnUid)
                } catch (e: Exception) {
                    runCatching { pfd.close() }
                    throw e
                }
                android.os.ParcelFileDescriptor.AutoCloseInputStream(pfd)
            } else {
                resolver.openInputStream(uri)
                    ?: throw IllegalArgumentException("Couldn't read the shared file.")
            }
            var totalBytes = 0L
            inputStream.use { input ->
                Files.newOutputStream(dst.toPath()).use { out ->
                    val buf = ByteArray(COPY_BUFFER_BYTES)
                    while (true) {
                        val read = input.read(buf)
                        if (read < 0) break
                        totalBytes += read
                        if (totalBytes > maxBytes) {
                            throw IllegalArgumentException("This file is larger than the 2 GB limit.")
                        }
                        out.write(buf, 0, read)
                    }
                }
            }
            return StagedShareFile(
                filePath = dst.absolutePath,
                displayName = safeName,
                sizeBytes = totalBytes,
                mime = mime,
            )
        } catch (e: Exception) {
            dst.delete()
            throw e
        }
    }

    fun stageTextAsFile(context: Context, text: String): StagedShareFile {
        val bytes = text.toByteArray(Charsets.UTF_8)
        if (bytes.size.toLong() > MAX_FILE_BYTES) {
            throw IllegalArgumentException("This text is larger than the 2 GB limit.")
        }
        val dir = File(context.cacheDir, "share-staging").apply { mkdirs() }
        val dst = File(dir, "shared-text.txt")
        Files.write(dst.toPath(), bytes)
        return StagedShareFile(
            filePath = dst.absolutePath,
            displayName = "shared-text.txt",
            sizeBytes = bytes.size.toLong(),
            mime = "text/plain",
        )
    }

    fun cleanup(path: String?) {
        if (path.isNullOrBlank()) return
        runCatching { File(path).delete() }
    }

    fun sweepStale(cacheDir: File, maxAgeMs: Long = 5L * 60L * 1000L) {
        runCatching {
            val dir = File(cacheDir, "share-staging")
            if (dir.exists()) {
                val cutoff = System.currentTimeMillis() - maxAgeMs
                dir.listFiles()?.forEach { f ->
                    if (maxAgeMs <= 0L || f.lastModified() <= cutoff) {
                        f.delete()
                    }
                }
            }
        }
    }
}

/**
 * Everything ShareActivity needs from the outside world. The real one talks
 * to the Rust core; tests inject a recording fake through
 * [ShareActivity.backendFactory]. Called off the main thread.
 */
data class ShareTextCandidate(val text: String, val sensitive: Boolean)

interface ShareBackend {
    fun parse(shared: String?): ShareParsing.Result
    fun classifyText(shared: String?): ShareTextCandidate? = null
    fun pairedPcs(): List<ShareTarget>
    fun send(pc: ShareTarget, url: String): ShareSendResult
    fun sendText(pc: ShareTarget, text: String): ShareSendResult =
        ShareSendResult.Failed("Couldn't send clipboard text.")
    fun stageFile(context: Context, uri: Uri, mime: String? = null): StagedShareFile =
        FileShareStaging.stage(context, uri, mime)
    fun sendFile(
        pc: ShareTarget,
        filePath: String,
        displayName: String,
        sizeBytes: Long,
        mime: String,
        relayDecision: String? = null,
    ): FileShareOutcome = FileShareOutcome.Failed("Couldn't send that file.")
}

/** The production backend: the process-wide [Core] phone. */
class CoreShareBackend(private val context: Context) : ShareBackend {
    override fun parse(shared: String?) = ShareParsing.describe(shared)

    override fun classifyText(shared: String?): ShareTextCandidate? =
        ShareParsing.classifyPlainText(shared)

    override fun pairedPcs(): List<ShareTarget> =
        Core.phone(context).pairedPcs().filter { !it.removed }.map { ShareTarget(it.id, it.name) }

    override fun send(pc: ShareTarget, url: String): ShareSendResult = try {
        val r = Core.withMulticast(context) { Core.phone(context).sendUrl(pc.id, url) }
        val how = if (r.opened) "opened" else "waiting for Open on the PC"
        // R4: nothing is stored unless the user turned Recent sends on.
        if (RecentSends.enabled(context)) {
            RecentSends.add(context, "${SendText.host(url)} → ${pc.name}: ${if (r.opened) "opened" else "prompted"} ${SendText.latency(r.latencyUs)}")
        }
        ShareSendResult.Sent("Sent to ${pc.name} ($how, ${SendText.latency(r.latencyUs)}).")
    } catch (e: Exception) {
        if (RecentSends.enabled(context)) {
            RecentSends.add(context, "${SendText.host(url)} → ${pc.name}: FAILED ${PhoneErrors.code(e)}")
        }
        ShareSendResult.Failed(PhoneErrors.textForPc(e, pc.name))
    }

    override fun sendText(pc: ShareTarget, text: String): ShareSendResult = try {
        val r = Core.withMulticast(context) { Core.phone(context).sendClipboardText(pc.id, text) }
        val how = if (r.opened) "copied on PC" else "waiting for Copy on the PC"
        ShareSendResult.Sent("Sent clipboard text to ${pc.name} ($how, ${SendText.latency(r.latencyUs)}).")
    } catch (e: Exception) {
        ShareSendResult.Failed(PhoneErrors.textForPc(e, pc.name))
    }

    override fun sendFile(
        pc: ShareTarget,
        filePath: String,
        displayName: String,
        sizeBytes: Long,
        mime: String,
        relayDecision: String?,
    ): FileShareOutcome = try {
        val r = Core.withMulticast(context) {
            Core.phone(context).sendFile(pc.id, filePath, mime, relayDecision)
        }
        val how = if (r.relayed) "via relay" else "direct"
        FileShareOutcome.Sent("Sent ${r.filename} to ${pc.name} ($how, ${SendText.latency(r.latencyUs)}).")
    } catch (e: PhoneException.Other) {
        when {
            e.detail.contains("relay_prompt_required") -> {
                val sizeLabel = FileShareStaging.formatSize(sizeBytes)
                val largeWarn = if (sizeBytes > 25L * 1024L * 1024L) {
                    " Large file ($sizeLabel) — sending over the relay may use mobile data."
                } else {
                    ""
                }
                FileShareOutcome.RelayPromptNeeded(
                    sizeBytes = sizeBytes,
                    promptText = "Not on the same network — send $sizeLabel via relay?$largeWarn",
                )
            }
            e.detail.contains("exceeds_relay_cap") -> {
                val neverRelay = runCatching { Core.phone(context).neverSendFilesOverRelay() }.getOrDefault(false)
                FileShareOutcome.Failed(PhoneErrors.dialogForPc(e, pc.name, neverRelay).message)
            }
            e.detail.contains("waiting_for_direct_path") -> {
                FileShareOutcome.Failed("Waiting for a direct local network connection to ${pc.name}.")
            }
            else -> {
                val neverRelay = runCatching { Core.phone(context).neverSendFilesOverRelay() }.getOrDefault(false)
                FileShareOutcome.Failed(PhoneErrors.dialogForPc(e, pc.name, neverRelay).message)
            }
        }
    } catch (e: Exception) {
        val neverRelay = runCatching { Core.phone(context).neverSendFilesOverRelay() }.getOrDefault(false)
        FileShareOutcome.Failed(PhoneErrors.dialogForPc(e, pc.name, neverRelay).message)
    }
}

/**
 * When a tap on "Send" is allowed to count (QA M1 High). A tap counts only
 * while the activity is resumed AND its window has focus, at least
 * [armDelayMs] after the content (re)appeared, and never for a touch that
 * Android flagged as passing through/under another window (overlay).
 *
 * QA M1 re-check L1: the finger must also have gone DOWN after the gate
 * armed (a press that started before, e.g. during a "tap fast" game, doesn't
 * count), and any touch Android marks as obscured re-arms the delay, so a tap
 * right after an overlay goes away waits [armDelayMs] again. On API 31+ the
 * activity also hides other apps' overlays (setHideOverlayWindows).
 *
 * QA M1 final S1: [timeArmed] (time + lifecycle only) decides whether the
 * buttons LOOK enabled; [allows] (that plus the finger-down rule) decides
 * whether a click counts. Using [allows] for the look left the button
 * disabled forever: a disabled button swallows the very press that would
 * have satisfied the finger-down rule.
 */
class TapGate(private val armDelayMs: Long) {
    var resumed = false
        private set
    var focused = false
        private set
    private var shownAt: Long = NOT_SHOWN
    private var downAt: Long = NOT_SHOWN

    fun onResumed(now: Long) { resumed = true; rearm(now) }

    /** A finger went down on our window (not obscured). */
    fun onDown(now: Long) { downAt = now }
    fun onPaused() { resumed = false; shownAt = NOT_SHOWN }
    fun onFocus(has: Boolean, now: Long) {
        focused = has
        if (has) rearm(now) else shownAt = NOT_SHOWN
    }

    /** The content on screen appeared or changed: start the delay again. */
    fun rearm(now: Long) { shownAt = now }

    fun armedAt(): Long = if (shownAt == NOT_SHOWN) NOT_SHOWN else shownAt + armDelayMs

    /** The delay has run out while resumed + focused: show the buttons enabled. */
    fun timeArmed(now: Long): Boolean =
        resumed && focused && shownAt != NOT_SHOWN && now - shownAt >= armDelayMs

    /** A click counts: [timeArmed] AND the finger went down after arming. */
    fun allows(now: Long): Boolean =
        timeArmed(now) && downAt != NOT_SHOWN && downAt - shownAt >= armDelayMs && downAt <= now

    companion object { const val NOT_SHOWN = Long.MIN_VALUE }
}

/** What the share screen shows. */
sealed interface ShareUi {
    data object Loading : ShareUi
    data class Invalid(val title: String, val body: String) : ShareUi
    data class NoPcs(val url: String) : ShareUi
    data class Ready(val url: String, val pcs: List<ShareTarget>) : ShareUi
    data class Sending(val url: String, val pc: ShareTarget) : ShareUi
    data class Done(val pc: ShareTarget, val text: String) : ShareUi
    data class Failed(val url: String, val pcs: List<ShareTarget>, val text: String) : ShareUi
    data class TextNoPcs(val text: String, val sensitive: Boolean) : ShareUi
    data class TextReady(val text: String, val sensitive: Boolean, val pcs: List<ShareTarget>) : ShareUi
    data class TextSending(val text: String, val sensitive: Boolean, val pc: ShareTarget) : ShareUi
    data class TextFailed(
        val text: String,
        val sensitive: Boolean,
        val pcs: List<ShareTarget>,
        val errorText: String,
    ) : ShareUi
    data class FileNoPcs(val file: StagedShareFile) : ShareUi
    data class FileReady(val file: StagedShareFile, val pcs: List<ShareTarget>) : ShareUi
    data class FileSending(val file: StagedShareFile, val pc: ShareTarget) : ShareUi
    data class RelayPrompt(
        val file: StagedShareFile,
        val pc: ShareTarget,
        val pcs: List<ShareTarget>,
        val promptText: String,
    ) : ShareUi
    data class FileFailed(
        val file: StagedShareFile,
        val pcs: List<ShareTarget>,
        val text: String,
    ) : ShareUi
    /** Recreated after a send: nothing more to do here. */
    data object AlreadySent : ShareUi
}

/**
 * Share target (ACTION_SEND, text/plain). QA M1 High: this activity is
 * exported, so ANY app can start it with any text. Starting it must never
 * send anything by itself:
 *
 *  - nothing sends in onCreate, onNewIntent, on state restore, or because an
 *    intent was delivered; the only path to [ShareBackend.send] is
 *    [onSendTapped], wired to the "Send to <PC>" buttons;
 *  - a tap counts only per [TapGate] (resumed + window focus + 500 ms since
 *    the content appeared + finger down after that + not obscured); obscured
 *    touches are dropped in [dispatchTouchEvent] and by
 *    filterTouchesWhenObscured, and they restart the delay;
 *  - the buttons are drawn enabled only once [TapGate.timeArmed] holds; every
 *    event that changes it calls [refreshArmed], which also schedules a
 *    re-check for the moment the delay runs out (S1);
 *  - a re-delivered intent (onNewIntent: Android delivers it only while
 *    the activity is paused or backgrounded) is ignored, never shown;
 *  - one tap sends at most once.
 *
 * One tap after choosing Voidwire in the share sheet: the only (or last
 * used) PC is the big primary button. Runs only while visible: no service.
 */
class ShareActivity : ComponentActivity() {
    companion object {
        const val ARM_DELAY_MS = 500L
        private const val KEY_SENT = "voidwire.share.sent"
        private const val KEY_STAGED_PATH = "voidwire.share.staged.path"
        private const val KEY_STAGED_NAME = "voidwire.share.staged.name"
        private const val KEY_STAGED_SIZE = "voidwire.share.staged.size"
        private const val KEY_STAGED_MIME = "voidwire.share.staged.mime"

        @VisibleForTesting @JvmStatic
        var backendFactory: (Context) -> ShareBackend = { CoreShareBackend(it.applicationContext) }

        @VisibleForTesting @JvmStatic
        var clock: () -> Long = { SystemClock.uptimeMillis() }

        @VisibleForTesting @JvmStatic
        var io: CoroutineDispatcher = Dispatchers.IO

        /** Restore production defaults (tests call this in @After). */
        @VisibleForTesting @JvmStatic
        fun resetForTests() {
            backendFactory = { CoreShareBackend(it.applicationContext) }
            clock = { SystemClock.uptimeMillis() }
            io = Dispatchers.IO
        }
    }

    private lateinit var backend: ShareBackend
    private val gate = TapGate(ARM_DELAY_MS)
    @VisibleForTesting internal var ui by mutableStateOf<ShareUi>(ShareUi.Loading)
        private set
    @VisibleForTesting internal var errorDialog by mutableStateOf<PhoneErrors.ErrorDialogInfo?>(null)
        internal set
    /**
     * Whether the Send buttons are drawn enabled (S1): [TapGate.timeArmed],
     * re-evaluated by [refreshArmed] on resume, focus change, an overlay
     * re-arm, new content, and when the delay runs out. Only the look:
     * [onSendTapped] still checks [TapGate.allows] itself.
     */
    @VisibleForTesting internal var buttonsArmed by mutableStateOf(false)
        private set
    private val handler = Handler(Looper.getMainLooper())
    private val refreshTask = Runnable { refreshArmed() }

    /** Window coordinates of each Send button, for tests that tap the real button. */
    @VisibleForTesting internal val sendButtonBounds: MutableMap<String, Rect> = mutableMapOf()
    private var sendStarted = false
    @VisibleForTesting internal var ignoredIntents = 0
        private set

    /** L1: setHideOverlayWindows(true) was applied (API 31+). */
    @VisibleForTesting internal var hidesOverlayWindows = false
        private set

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Drop touches delivered while another window covers us (tapjacking).
        window.decorView.filterTouchesWhenObscured = true
        // L1: on Android 12+ hide other apps' overlay windows while we're on
        // screen (needs HIDE_OVERLAY_WINDOWS, a normal install-time permission).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            hidesOverlayWindows = try {
                window.setHideOverlayWindows(true)
                true
            } catch (e: SecurityException) {
                false // permission missing: the obscured-touch filter still applies
            }
        }
        backend = backendFactory(this)
        if (savedInstanceState == null) {
            FileShareStaging.sweepStale(cacheDir)
        } else {
            val savedPath = savedInstanceState.getString(KEY_STAGED_PATH)
            val savedName = savedInstanceState.getString(KEY_STAGED_NAME)
            val savedSize = savedInstanceState.getLong(KEY_STAGED_SIZE, -1L)
            val savedMime = savedInstanceState.getString(KEY_STAGED_MIME)
            if (!savedPath.isNullOrBlank() && savedName != null && savedSize >= 0L && savedMime != null && File(savedPath).exists()) {
                stagedFile = StagedShareFile(savedPath, savedName, savedSize, savedMime)
            }
        }
        if (savedInstanceState?.getBoolean(KEY_SENT) == true) {
            // Recreated after a send (rotation etc.): never offer it again.
            sendStarted = true
            cleanupStagedFile()
            ui = ShareUi.AlreadySent
        } else {
            load(intent)
        }
        val themeMode = ThemePref.get(this) // SPEC 3.1: the user's Theme setting
        setContent {
            VoidwireTheme(themeMode) {
                // SPEC 3.6: a dialog card over the source app.
                Surface(
                    Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    tonalElevation = 0.dp,
                    shadowElevation = 12.dp,
                ) {
                    Column(Modifier.padding(22.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                        ShareHeader(ui)
                        ShareScreen()
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
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_SENT, sendStarted)
        stagedFile?.let { f ->
            outState.putString(KEY_STAGED_PATH, f.filePath)
            outState.putString(KEY_STAGED_NAME, f.displayName)
            outState.putLong(KEY_STAGED_SIZE, f.sizeBytes)
            outState.putString(KEY_STAGED_MIME, f.mime)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // A re-delivered intent is always ignored: never shown, never sent,
        // and it never replaces what the user is looking at. Android pauses
        // an activity before handing it a new intent, so a re-delivery is by
        // definition "while not resumed" (backgrounded or paused). A real
        // share always gets a fresh instance (standard launch mode), so
        // only a caller forcing FLAG_ACTIVITY_SINGLE_TOP ever lands here.
        ignoredIntents++
    }

    override fun onResume() {
        super.onResume()
        gate.onResumed(clock())
        refreshArmed()
    }

    override fun onPause() {
        gate.onPaused()
        refreshArmed()
        super.onPause()
    }

    private var stagedFile: StagedShareFile? = null

    private fun cleanupStagedFile() {
        val f = stagedFile
        stagedFile = null
        if (f != null) FileShareStaging.cleanup(f.filePath)
    }

    override fun onDestroy() {
        handler.removeCallbacks(refreshTask)
        if (!isChangingConfigurations) {
            cleanupStagedFile()
        }
        super.onDestroy()
    }

    /**
     * S1: recompute whether the buttons look enabled, and if the gate is
     * waiting for its delay, check again when it runs out. Called after
     * every gate change; the pending re-check is replaced each time.
     */
    private fun refreshArmed() {
        handler.removeCallbacks(refreshTask)
        val now = clock()
        buttonsArmed = gate.timeArmed(now)
        if (buttonsArmed || !gate.resumed || !gate.focused) return
        val at = gate.armedAt()
        if (at == TapGate.NOT_SHOWN) return
        handler.postDelayed(refreshTask, (at - now).coerceAtLeast(1))
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        gate.onFocus(hasFocus, clock())
        refreshArmed()
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (isObscured(ev)) {
            // L1: an overlay is (or just was) over us. Drop the touch and
            // restart the delay, so a tap right after it disappears waits.
            gate.rearm(clock())
            refreshArmed()
            return false
        }
        if (ev.actionMasked == MotionEvent.ACTION_DOWN) gate.onDown(clock())
        return super.dispatchTouchEvent(ev)
    }

    private fun isObscured(ev: MotionEvent): Boolean {
        if (ev.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED != 0) return true
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
            ev.flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED != 0
    }

    private fun extractStreamUri(intent: Intent?): Uri? {
        if (intent?.action != Intent.ACTION_SEND) return null
        IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)?.let { return it }
        val clip = intent.clipData
        if (clip != null && clip.itemCount > 0) {
            clip.getItemAt(0)?.uri?.let { return it }
        }
        return null
    }

    /** Parse the intent and list the PCs. Shows buttons; never sends. */
    private fun load(intent: Intent?) {
        sendStarted = false
        val existingStaged = stagedFile
        ui = ShareUi.Loading
        val shared = if (intent?.action == Intent.ACTION_SEND) intent.getStringExtra(Intent.EXTRA_TEXT) else null
        val streamUri = extractStreamUri(intent)
        val intentMime = intent?.type
        lifecycleScope.launch {
            ui = try {
                val parsed = if (!shared.isNullOrBlank() || streamUri == null) {
                    withContext(io) { backend.parse(shared) }
                } else null
                if (parsed != null && parsed.ok) {
                    cleanupStagedFile()
                    val pcs = withContext(io) { LastPc.order(this@ShareActivity, backend.pairedPcs()) }
                    if (pcs.isEmpty()) ShareUi.NoPcs(parsed.body) else ShareUi.Ready(parsed.body, pcs)
                } else if (streamUri != null) {
                    val staged = if (existingStaged != null && File(existingStaged.filePath).exists()) {
                        existingStaged
                    } else {
                        withContext(io) { backend.stageFile(this@ShareActivity, streamUri, intentMime) }
                    }
                    stagedFile = staged
                    val pcs = withContext(io) { LastPc.order(this@ShareActivity, backend.pairedPcs()) }
                    if (pcs.isEmpty()) ShareUi.FileNoPcs(staged) else ShareUi.FileReady(staged, pcs)
                } else {
                    val textCand = if (!shared.isNullOrBlank()) {
                        withContext(io) { backend.classifyText(shared) }
                    } else null
                    if (textCand != null) {
                        val utf8Len = textCand.text.toByteArray(Charsets.UTF_8).size
                        val pcs = withContext(io) { LastPc.order(this@ShareActivity, backend.pairedPcs()) }
                        if (utf8Len <= IncomingReceive.MAX_INLINE_CLIPBOARD_BYTES) {
                            cleanupStagedFile()
                            if (pcs.isEmpty()) {
                                ShareUi.TextNoPcs(textCand.text, textCand.sensitive)
                            } else {
                                ShareUi.TextReady(textCand.text, textCand.sensitive, pcs)
                            }
                        } else {
                            val staged = withContext(io) {
                                FileShareStaging.stageTextAsFile(this@ShareActivity, textCand.text)
                            }
                            stagedFile = staged
                            if (pcs.isEmpty()) ShareUi.FileNoPcs(staged) else ShareUi.FileReady(staged, pcs)
                        }
                    } else {
                        val inv = parsed ?: ShareParsing.describe(shared)
                        ShareUi.Invalid(inv.title, inv.body)
                    }
                }
            } catch (e: IllegalArgumentException) {
                ShareUi.Invalid("Can't send this file", e.message ?: "This file can't be shared.")
            } catch (e: Exception) {
                ShareUi.Invalid("Not sent", PhoneErrors.text(e))
            }
            gate.rearm(clock())
            refreshArmed()
        }
    }

    /**
     * The ONLY way a link or file leaves this activity: a "Send to <PC>" tap that
     * passes [TapGate]. Returns whether a send was started.
     */
    @VisibleForTesting
    internal fun onSendTapped(pcId: String): Boolean {
        if (!gate.allows(clock())) return false
        if (sendStarted) return false
        when (val s = ui) {
            is ShareUi.FileReady -> {
                val pc = s.pcs.firstOrNull { it.id == pcId } ?: return false
                startFileSend(s.file, pc, s.pcs, relayDecision = null)
                return true
            }
            is ShareUi.FileFailed -> {
                val pc = s.pcs.firstOrNull { it.id == pcId } ?: return false
                startFileSend(s.file, pc, s.pcs, relayDecision = null)
                return true
            }
            is ShareUi.TextReady -> {
                val pc = s.pcs.firstOrNull { it.id == pcId } ?: return false
                startTextSend(s.text, s.sensitive, pc, s.pcs)
                return true
            }
            is ShareUi.TextFailed -> {
                val pc = s.pcs.firstOrNull { it.id == pcId } ?: return false
                startTextSend(s.text, s.sensitive, pc, s.pcs)
                return true
            }
            else -> {}
        }
        val (url, pcs) = when (val s = ui) {
            is ShareUi.Ready -> s.url to s.pcs
            is ShareUi.Failed -> s.url to s.pcs
            else -> return false
        }
        val pc = pcs.firstOrNull { it.id == pcId } ?: return false
        sendStarted = true
        ui = ShareUi.Sending(url, pc)
        LastPc.set(this, pc.id)
        lifecycleScope.launch {
            val r = try {
                withContext(io) { backend.send(pc, url) }
            } catch (e: Exception) {
                ShareSendResult.Failed(PhoneErrors.text(e))
            }
            when (r) {
                is ShareSendResult.Sent -> {
                    ui = ShareUi.Done(pc, r.message)
                    delay(1500)
                    finish()
                }
                is ShareSendResult.Failed -> {
                    // "Try again" is another explicit tap through the gate.
                    ui = ShareUi.Failed(url, pcs, r.message)
                    errorDialog = PhoneErrors.dialogForMessage(r.message, pc.name)
                    sendStarted = false
                    gate.rearm(clock())
                    refreshArmed()
                }
            }
        }
        return true
    }

    private fun startTextSend(
        text: String,
        sensitive: Boolean,
        pc: ShareTarget,
        pcs: List<ShareTarget>,
    ) {
        sendStarted = true
        ui = ShareUi.TextSending(text, sensitive, pc)
        LastPc.set(this, pc.id)
        lifecycleScope.launch {
            val r = try {
                withContext(io) { backend.sendText(pc, text) }
            } catch (e: Exception) {
                ShareSendResult.Failed(PhoneErrors.text(e))
            }
            when (r) {
                is ShareSendResult.Sent -> {
                    ui = ShareUi.Done(pc, r.message)
                    delay(1500)
                    finish()
                }
                is ShareSendResult.Failed -> {
                    ui = ShareUi.TextFailed(text, sensitive, pcs, r.message)
                    errorDialog = PhoneErrors.dialogForMessage(r.message, pc.name)
                    sendStarted = false
                    gate.rearm(clock())
                    refreshArmed()
                }
            }
        }
    }

    private fun startFileSend(
        file: StagedShareFile,
        pc: ShareTarget,
        pcs: List<ShareTarget>,
        relayDecision: String?,
    ) {
        sendStarted = true
        ui = ShareUi.FileSending(file, pc)
        LastPc.set(this, pc.id)
        lifecycleScope.launch {
            val outcome = try {
                withContext(io) {
                    backend.sendFile(pc, file.filePath, file.displayName, file.sizeBytes, file.mime, relayDecision)
                }
            } catch (e: Exception) {
                FileShareOutcome.Failed(PhoneErrors.text(e))
            }
            when (outcome) {
                is FileShareOutcome.Sent -> {
                    cleanupStagedFile()
                    ui = ShareUi.Done(pc, outcome.message)
                    delay(1500)
                    finish()
                }
                is FileShareOutcome.RelayPromptNeeded -> {
                    sendStarted = false
                    ui = ShareUi.RelayPrompt(file, pc, pcs, outcome.promptText)
                    gate.rearm(clock())
                    refreshArmed()
                }
                is FileShareOutcome.Failed -> {
                    sendStarted = false
                    ui = ShareUi.FileFailed(file, pcs, outcome.message)
                    errorDialog = PhoneErrors.dialogForMessage(outcome.message, pc.name)
                    gate.rearm(clock())
                    refreshArmed()
                }
            }
        }
    }

    /**
     * Handles the user's choice on the relay confirmation sheet (`M2.7` §6a.1):
     * `sendViaRelay = true` re-invokes `sendFile` with `"send_via_relay"`, while
     * `sendViaRelay = false` invokes `"cancel"`, deletes the staging file, and closes.
     */
    @VisibleForTesting
    internal fun onRelayDecisionTapped(sendViaRelay: Boolean): Boolean {
        val s = ui as? ShareUi.RelayPrompt ?: return false
        if (sendViaRelay) {
            startFileSend(s.file, s.pc, s.pcs, relayDecision = "send_via_relay")
        } else {
            lifecycleScope.launch {
                runCatching {
                    withContext(io) {
                        backend.sendFile(s.pc, s.file.filePath, s.file.displayName, s.file.sizeBytes, s.file.mime, "cancel")
                    }
                }
                cleanupStagedFile()
                finish()
            }
        }
        return true
    }

    @Composable
    private fun ShareHeader(s: ShareUi) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Image(
                painterResource(if (MaterialTheme.colorScheme.background.luminance() < 0.5f) R.drawable.vw_mark_px24 else R.drawable.vw_mark_px24_on_light),
                contentDescription = null,
                modifier = Modifier.size(28.dp),
            )
            Text("Send to PC", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            when (s) {
                is ShareUi.Ready, is ShareUi.NoPcs, is ShareUi.Sending -> VwChip("Link OK", ChipTone.Info)
                is ShareUi.TextReady, is ShareUi.TextNoPcs, is ShareUi.TextSending -> VwChip("Text OK", ChipTone.Info)
                is ShareUi.FileReady, is ShareUi.FileNoPcs, is ShareUi.FileSending -> VwChip("File OK", ChipTone.Info)
                is ShareUi.RelayPrompt -> VwChip("Relay", ChipTone.Info)
                is ShareUi.Invalid -> VwChip("No link", ChipTone.Error)
                else -> {}
            }
        }
    }

    @Composable
    private fun ShareScreen() {
        // Visual arming only (time + lifecycle); onSendTapped re-checks the
        // full gate, including the finger-down rule, on every click.
        val armed = buttonsArmed
        val outlineColor = MaterialTheme.colorScheme.outline
        val cancelRow: @Composable (String) -> Unit = { label ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                // Dismissive actions are never gold (SPEC 3.6 / §4, REVIEW-m11 #4).
                TextButton(
                    onClick = {
                        cleanupStagedFile()
                        finish()
                    },
                    colors = mutedTextButton(),
                ) { Text(label) }
            }
        }
        when (val s = ui) {
            ShareUi.Loading -> CircularProgressIndicator(color = MaterialTheme.colorScheme.secondary)
            ShareUi.AlreadySent -> {
                Text("Link already sent", style = MaterialTheme.typography.titleLarge)
                cancelRow("Close")
            }
            is ShareUi.Invalid -> {
                Text(s.title, style = MaterialTheme.typography.titleLarge)
                Text(s.body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                // SPEC 3.6 no-link (screens/19): reassurance, never an echo of the shared text.
                DashedNote(VwIcons.EyeOff, "NOTHING WAS SENT OR SAVED")
                cancelRow("Close")
            }
            is ShareUi.NoPcs -> {
                UrlBlock(s.url)
                // SPEC 3.6 no-PCs (screens/18): dashed row, monitor well.
                Row(
                    Modifier.fillMaxWidth().drawBehind {
                        drawRoundRect(
                            outlineColor,
                            cornerRadius = CornerRadius(6.dp.toPx()),
                            style = Stroke(1.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(4f * density, 4f * density))),
                        )
                    }.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    IconWell(VwIcons.Monitor, MaterialTheme.colorScheme.tertiary, MaterialTheme.colorScheme.surfaceContainerHighest, size = 36)
                    Column {
                        Text("No PC paired yet", style = MaterialTheme.typography.titleSmall)
                        Text("Pair one first, then share this link again.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Button(
                    onClick = {
                        // Own task, not the sharing app's; CLEAR_TOP replaces an existing
                        // MainActivity (standard launchMode -> fresh onCreate with EXTRA_PAIR)
                        // instead of stacking a second one (QA 8ee9a16).
                        startActivity(
                            Intent(this@ShareActivity, MainActivity::class.java)
                                .putExtra(MainActivity.EXTRA_PAIR, true)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
                        )
                        finish()
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = VoidwireComponentShapes.primaryButton,
                    border = primaryButtonBorder(),
                ) {
                    Icon(VwIcons.Qr, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Pair a device")
                }
                cancelRow("Cancel")
            }
            is ShareUi.Ready -> {
                UrlBlock(s.url)
                SendButtons(s.pcs, armed)
                cancelRow("Cancel")
            }
            is ShareUi.Sending -> {
                UrlBlock(s.url)
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    CircularProgressIndicator(Modifier.size(20.dp), color = MaterialTheme.colorScheme.secondary, strokeWidth = 2.dp)
                    Text("Sending to ${s.pc.name}…")
                }
            }
            is ShareUi.Done -> Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(VwIcons.Check, contentDescription = null, tint = VoidwireTheme.extended.success)
                Text(s.text, style = MaterialTheme.typography.bodyLarge)
            }
            is ShareUi.Failed -> {
                Text("Not sent", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.error)
                Text(s.text, style = MaterialTheme.typography.bodyMedium)
                UrlBlock(s.url)
                SendButtons(s.pcs, armed, retry = true)
                cancelRow("Close")
            }
            is ShareUi.FileNoPcs -> {
                FileBlock(s.file)
                Row(
                    Modifier.fillMaxWidth().drawBehind {
                        drawRoundRect(
                            outlineColor,
                            cornerRadius = CornerRadius(6.dp.toPx()),
                            style = Stroke(1.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(4f * density, 4f * density))),
                        )
                    }.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    IconWell(VwIcons.Monitor, MaterialTheme.colorScheme.tertiary, MaterialTheme.colorScheme.surfaceContainerHighest, size = 36)
                    Column {
                        Text("No PC paired yet", style = MaterialTheme.typography.titleSmall)
                        Text("Pair one first, then share this file again.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Button(
                    onClick = {
                        cleanupStagedFile()
                        startActivity(
                            Intent(this@ShareActivity, MainActivity::class.java)
                                .putExtra(MainActivity.EXTRA_PAIR, true)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
                        )
                        finish()
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = VoidwireComponentShapes.primaryButton,
                    border = primaryButtonBorder(),
                ) {
                    Icon(VwIcons.Qr, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Pair a device")
                }
                cancelRow("Cancel")
            }
            is ShareUi.FileReady -> {
                FileBlock(s.file)
                SendButtons(s.pcs, armed)
                cancelRow("Cancel")
            }
            is ShareUi.FileSending -> {
                FileBlock(s.file)
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    CircularProgressIndicator(Modifier.size(20.dp), color = MaterialTheme.colorScheme.secondary, strokeWidth = 2.dp)
                    Text("Sending ${s.file.displayName} to ${s.pc.name}…")
                }
            }
            is ShareUi.RelayPrompt -> {
                Text(s.promptText, style = MaterialTheme.typography.titleMedium)
                FileBlock(s.file)
                Button(
                    onClick = { onRelayDecisionTapped(true) },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("relay_send_btn"),
                    shape = VoidwireComponentShapes.primaryButton,
                    border = primaryButtonBorder(),
                ) {
                    Icon(VwIcons.Send, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Send via relay")
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(
                        onClick = { onRelayDecisionTapped(false) },
                        modifier = Modifier.testTag("relay_cancel_btn"),
                        colors = mutedTextButton(),
                    ) { Text("Cancel") }
                }
            }
            is ShareUi.FileFailed -> {
                Text("Not sent", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.error)
                Text(s.text, style = MaterialTheme.typography.bodyMedium)
                FileBlock(s.file)
                SendButtons(s.pcs, armed, retry = true)
                cancelRow("Close")
            }
            is ShareUi.TextNoPcs -> {
                TextBlock(s.text, s.sensitive)
                Row(
                    Modifier.fillMaxWidth().drawBehind {
                        drawRoundRect(
                            outlineColor,
                            cornerRadius = CornerRadius(6.dp.toPx()),
                            style = Stroke(1.dp.toPx(), pathEffect = PathEffect.dashPathEffect(floatArrayOf(4f * density, 4f * density))),
                        )
                    }.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    IconWell(VwIcons.Monitor, MaterialTheme.colorScheme.tertiary, MaterialTheme.colorScheme.surfaceContainerHighest, size = 36)
                    Column {
                        Text("No PC paired yet", style = MaterialTheme.typography.titleSmall)
                        Text("Pair one first, then share this text again.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Button(
                    onClick = {
                        startActivity(
                            Intent(this@ShareActivity, MainActivity::class.java)
                                .putExtra(MainActivity.EXTRA_PAIR, true)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
                        )
                        finish()
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    shape = VoidwireComponentShapes.primaryButton,
                    border = primaryButtonBorder(),
                ) {
                    Icon(VwIcons.Qr, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Pair a device")
                }
                cancelRow("Cancel")
            }
            is ShareUi.TextReady -> {
                TextBlock(s.text, s.sensitive)
                SendButtons(s.pcs, armed)
                cancelRow("Cancel")
            }
            is ShareUi.TextSending -> {
                TextBlock(s.text, s.sensitive)
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    CircularProgressIndicator(Modifier.size(20.dp), color = MaterialTheme.colorScheme.secondary, strokeWidth = 2.dp)
                    Text("Sending clipboard text to ${s.pc.name}…")
                }
            }
            is ShareUi.TextFailed -> {
                Text("Not sent", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.error)
                Text(s.errorText, style = MaterialTheme.typography.bodyMedium)
                TextBlock(s.text, s.sensitive)
                SendButtons(s.pcs, armed, retry = true)
                cancelRow("Close")
            }
        }
    }

    @Composable
    private fun TextBlock(text: String, sensitive: Boolean) {
        var revealed by remember(text, sensitive) { mutableStateOf(!sensitive) }
        val byteLen = remember(text) { text.toByteArray(Charsets.UTF_8).size }
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerLowest,
            shape = VoidwireComponentShapes.card,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                IconWell(VwIcons.Clipboard, MaterialTheme.colorScheme.secondary, MaterialTheme.colorScheme.surfaceContainerHighest, size = 36)
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        if (sensitive) "Clipboard text (sensitive)" else "Clipboard text · ${FileShareStaging.formatSize(byteLen.toLong())}",
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(
                        if (revealed) text else "••••••••••••",
                        style = VoidwireTheme.code.codeSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 3,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                if (sensitive) {
                    TextButton(
                        onClick = { revealed = !revealed },
                        modifier = Modifier.testTag("share_text_reveal_btn"),
                    ) {
                        Text(if (revealed) "Hide" else "Show")
                    }
                }
            }
        }
    }

    @Composable
    private fun FileBlock(file: StagedShareFile) {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerLowest,
            shape = VoidwireComponentShapes.card,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(
                Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                IconWell(VwIcons.File, MaterialTheme.colorScheme.secondary, MaterialTheme.colorScheme.surfaceContainerHighest, size = 36)
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(file.displayName, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        "${FileShareStaging.formatSize(file.sizeBytes)} · ${file.mime}",
                        style = VoidwireTheme.code.codeSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }

    @Composable
    private fun UrlBlock(url: String) {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerLowest,
            shape = VoidwireComponentShapes.card,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(horizontal = 14.dp, vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(SendText.host(url), style = MaterialTheme.typography.titleLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    url,
                    style = VoidwireTheme.code.codeSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }

    @Composable
    private fun SendButtons(pcs: List<ShareTarget>, armed: Boolean, retry: Boolean = false) {
        // LAST USED only while "Remember last PC" is on (round 2, SPEC 3.6).
        val last = remember { LastPc.last(this@ShareActivity) }
        pcs.forEachIndexed { i, pc ->
            // Designer blocker 1 (REVIEW-m11-android): 2 lines, then a middle ellipsis that keeps the
            // distinguishing tail; screen readers always get the full name.
            val isLast = !retry && last == pc.id
            val prefix = if (retry) "Try again: " else "Send to "
            val fullDesc = (if (retry) "Try again: " else "Send to ") + pc.name + (if (isLast) ", last used" else "")
            val mod = Modifier.fillMaxWidth().heightIn(min = if (i == 0) 64.dp else 48.dp)
                .semantics(mergeDescendants = true) { contentDescription = fullDesc }
                .onGloballyPositioned { c ->
                    val b = c.boundsInWindow()
                    sendButtonBounds[pc.id] = Rect(b.left.toInt(), b.top.toInt(), b.right.toInt(), b.bottom.toInt())
                }
            if (i == 0) {
                Button(onClick = { onSendTapped(pc.id) }, enabled = armed, modifier = mod, shape = VoidwireComponentShapes.primaryButton,
                    border = primaryButtonBorder(),
                    contentPadding = PaddingValues(horizontal = 20.dp, vertical = 10.dp)) {
                    Icon(VwIcons.Monitor, contentDescription = null, modifier = Modifier.size(22.dp))
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        if (isLast) {
                            Text("LAST USED", style = MaterialTheme.typography.labelSmall, modifier = Modifier.alpha(0.78f))
                        }
                        MiddleEllipsisText(prefix, pc.name, MaterialTheme.typography.titleMedium)
                    }
                }
            } else {
                FilledTonalButton(onClick = { onSendTapped(pc.id) }, enabled = armed, modifier = mod, shape = VoidwireComponentShapes.secondaryButton,
                    contentPadding = PaddingValues(horizontal = 20.dp, vertical = 10.dp)) {
                    MiddleEllipsisText(prefix, pc.name, androidx.compose.material3.LocalTextStyle.current, Modifier.weight(1f))
                }
            }
        }
    }
}

/**
 * Designer blocker 1: [prefix] + [name] on at most [maxLines] lines; when it does not fit, the
 * name keeps its start and end with "…" in the middle (measured against the real width, so the
 * cut adapts to font scale). Callers put the full name in contentDescription.
 */
@Composable
internal fun MiddleEllipsisText(prefix: String, name: String, style: androidx.compose.ui.text.TextStyle,
                                modifier: Modifier = Modifier, maxLines: Int = 2) {
    val measurer = androidx.compose.ui.text.rememberTextMeasurer()
    androidx.compose.foundation.layout.BoxWithConstraints(modifier) {
        val c = androidx.compose.ui.unit.Constraints(maxWidth = constraints.maxWidth)
        fun fits(t: String) = !measurer.measure(t, style, maxLines = maxLines, constraints = c).hasVisualOverflow
        val text = remember(prefix, name, style, constraints.maxWidth) {
            if (fits(prefix + name)) prefix + name else {
                var lo = 8; var hi = name.codePointCount(0, name.length) - 1; var best = middleEllipsis(name, 8)
                while (lo <= hi) {
                    val mid = (lo + hi) / 2; val cand = middleEllipsis(name, mid)
                    if (fits(prefix + cand)) { best = cand; lo = mid + 1 } else hi = mid - 1
                }
                prefix + best
            }
        }
        Text(text, style = style, maxLines = maxLines, overflow = TextOverflow.Clip)
    }
}

/**
 * Remembers the last PC picked so it is listed first (the primary button).
 * M1.1 privacy rule: in memory only (this process), never written to disk;
 * the M1 "share" preferences file is deleted at startup.
 */
/** Pure logic, unit-tested on the JVM against the host build of the core. */
object ShareParsing {
    data class Result(val ok: Boolean, val title: String, val body: String)

    fun describe(shared: String?): Result {
        if (shared.isNullOrBlank()) return Result(false, "Nothing to send", "The app didn't share any text.")
        return try {
            Result(true, "Link received", extractShareableUrl(shared))
        } catch (e: ShareUrlException.NoUrl) {
            Result(false, "No link found", "The shared text doesn't contain an http or https link.")
        } catch (e: ShareUrlException.DisallowedScheme) {
            Result(false, "Can't send this link", "Only http and https links can be sent.")
        } catch (e: ShareUrlException.TooLong) {
            Result(false, "Link too long", "This link is longer than the size limit.")
        } catch (e: ShareUrlException.HasUserinfo) {
            Result(false, "Can't send this link", "Links with a username or password can't be sent.")
        } catch (e: ShareUrlException.LocalOnlyAddress) {
            Result(false, "Can't send this link", "Links to localhost or link-local addresses only work on this phone.")
        }
    }

    /**
     * Inspect [shared] for M3.1 plain-text / clipboard sharing.
     * Returns null when [shared] is blank, already extracts as a valid link,
     * or was rejected as a disallowed/local-only URL by [describe].
     */
    fun classifyPlainText(shared: String?): ShareTextCandidate? {
        if (shared.isNullOrBlank()) return null
        val urlResult = describe(shared)
        if (urlResult.ok || urlResult.title != "No link found") return null
        return try {
            when (val c = classifySharedText(shared)) {
                is SharedContent.ClipboardText -> ShareTextCandidate(c.text, c.sensitive)
                is SharedContent.Url -> null
            }
        } catch (_: Exception) {
            null
        }
    }
}
