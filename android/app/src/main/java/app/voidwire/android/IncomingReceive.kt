package app.voidwire.android

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.PersistableBundle
import android.provider.MediaStore
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import uniffi.voidwire_core.extractShareableUrl

/**
 * Helpers for handling incoming PC -> Phone items on Android (M3.1 §4.2):
 * - Re-verifying URLs through [extractShareableUrl] and `http`/`https` check
 *   before launching `Intent.ACTION_VIEW`.
 * - Copying clipboard text with `ClipDescription.EXTRA_IS_SENSITIVE` on API 33+
 *   when `sensitive` is true.
 * - Saving `.txt` clipboard files and verified incoming files to
 *   `Downloads/Voidwire` without using `FileOutputStream` / `openFileOutput`.
 */
object IncomingReceive {
    const val MAX_INLINE_CLIPBOARD_BYTES = 7680

    /**
     * Re-verify [rawUrl] through [extractShareableUrl] and ensure scheme is
     * strictly `http` or `https` before returning the canonical URL string.
     */
    fun verifyBrowserUrl(rawUrl: String): Result<String> = try {
        val canonical = extractShareableUrl(rawUrl)
        val uri = Uri.parse(canonical)
        val scheme = uri.scheme?.lowercase()
        if ((scheme != "http" && scheme != "https") || uri.host.isNullOrBlank()) {
            Result.failure(IllegalArgumentException("Only http and https links can be opened."))
        } else {
            Result.success(canonical)
        }
    } catch (e: Exception) {
        Result.failure(e)
    }

    /**
     * Re-verify [rawUrl] and open it in the user's browser via `ACTION_VIEW`.
     */
    fun openVerifiedBrowserUrl(context: Context, rawUrl: String): Result<String> {
        val verified = verifyBrowserUrl(rawUrl).getOrElse { return Result.failure(it) }
        return try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(verified)).apply {
                addCategory(Intent.CATEGORY_BROWSABLE)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            Result.success(verified)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Copy [text] to the Android system clipboard, marking the clip description
     * with `EXTRA_IS_SENSITIVE = true` when [sensitive] is true (Android 13+).
     */
    fun copyToSystemClipboard(context: Context, text: String, sensitive: Boolean) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val clip = buildClipData(text, sensitive)
        cm.setPrimaryClip(clip)
    }

    fun buildClipData(text: String, sensitive: Boolean): ClipData {
        val clip = ClipData.newPlainText("Voidwire", text)
        if (sensitive) {
            val extras = PersistableBundle().apply {
                val key = if (Build.VERSION.SDK_INT >= 33) {
                    ClipDescription.EXTRA_IS_SENSITIVE
                } else {
                    "android.content.extra.IS_SENSITIVE"
                }
                putBoolean(key, true)
            }
            clip.description.extras = extras
        }
        return clip
    }

    fun sanitizeFilename(raw: String, fallback: String): String {
        val cleaned = raw
            .replace('/', '_')
            .replace('\\', '_')
            .filter { !it.isISOControl() }
            .trim()
            .trimStart('.')
        return cleaned.take(160).ifEmpty { fallback }
    }

    /**
     * Save [text] as a `.txt` file under `Downloads/Voidwire`.
     * Returns the user-visible path/name.
     */
    private const val STREAM_BUFFER_BYTES = 64 * 1024

    fun saveClipboardAsTxt(context: Context, text: String): String {
        val filename = "clipboard-${System.currentTimeMillis() / 1000}.txt"
        val bytes = text.toByteArray(Charsets.UTF_8)
        return streamToDownloads(context, filename, "text/plain") { out ->
            out.write(bytes)
        }
    }

    /**
     * Export a verified received file from [stagedPath] into `Downloads/Voidwire`
     * with a collision-safe name by streaming in 64 KiB chunks (never loading the
     * full file into JVM memory), then remove the staged copy.
     * Never opens or executes the saved file (FILE-11 / M3.1 §4.2.3).
     */
    fun exportVerifiedFileToDownloads(
        context: Context,
        stagedPath: String,
        requestedName: String,
    ): String {
        val src = File(stagedPath)
        val safeName = sanitizeFilename(requestedName.ifBlank { src.name }, "received-file.bin")
        val outLabel = Files.newInputStream(src.toPath()).use { input ->
            streamToDownloads(context, safeName, "application/octet-stream") { out ->
                input.copyTo(out, STREAM_BUFFER_BYTES)
            }
        }
        try {
            Files.deleteIfExists(src.toPath())
        } catch (_: Exception) {
        }
        return outLabel
    }

    private fun streamToDownloads(
        context: Context,
        filename: String,
        mimeType: String,
        writer: (java.io.OutputStream) -> Unit,
    ): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val resolver = context.contentResolver
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, filename)
                put(MediaStore.Downloads.MIME_TYPE, mimeType)
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/Voidwire")
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            if (uri != null) {
                var written = false
                resolver.openOutputStream(uri)?.use { out ->
                    writer(out)
                    out.flush()
                    written = true
                }
                if (written) {
                    val done = ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }
                    resolver.update(uri, done, null, null)
                    return "Downloads/Voidwire/$filename"
                }
            }
        }
        val baseDir = File(context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: context.filesDir, "Voidwire")
        Files.createDirectories(baseDir.toPath())
        var candidate = File(baseDir, filename)
        var suffix = 2
        val dot = filename.lastIndexOf('.')
        val stem = if (dot > 0) filename.substring(0, dot) else filename
        val ext = if (dot > 0) filename.substring(dot) else ""
        while (candidate.exists()) {
            candidate = File(baseDir, "$stem ($suffix)$ext")
            suffix += 1
        }
        Files.newOutputStream(candidate.toPath()).use { out ->
            writer(out)
            out.flush()
        }
        return "Downloads/Voidwire/${candidate.name}"
    }
}
