package app.voidwire.android

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.core.content.IntentCompat
import app.voidwire.android.ui.Eyebrow
import app.voidwire.android.ui.VwCard
import app.voidwire.android.ui.theme.VoidwireComponentShapes
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.voidwire_core.PhoneInterface
import uniffi.voidwire_core.UpdateCheckResult
import uniffi.voidwire_core.UpdateDownloadResult
import uniffi.voidwire_core.UpdateOffer
import uniffi.voidwire_core.UpdateProgress
import uniffi.voidwire_core.UpdateTrigger

/**
 * U1 (docs/UPDATES.md): the update banner on the home screen and Settings →
 * Updates. The core checks the signed manifest, downloads and verifies the
 * APK; Android's PackageInstaller installs it and the user confirms every
 * install. The only automatic check is [onAppStart] (MainActivity.onStart,
 * at most once a UTC day); nothing runs in the background service and no
 * notification is ever shown for updates.
 */
object Updates {
    /** The verified offer, or null. */
    var offer by mutableStateOf<UpdateOffer?>(null)
        private set
    /** "", "checking", "uptodate", "failed". */
    var status by mutableStateOf("")
        private set
    /** "", "downloading", "verifying", "installing". */
    var phase by mutableStateOf("")
        private set
    var percent by mutableStateOf(0)
        private set
    var error by mutableStateOf<String?>(null)
    /** "Not now": hidden until the process ends (memory only). */
    var dismissed by mutableStateOf(false)
    /** Show the "allow Voidwire to install apps" explainer. */
    var needsPermission by mutableStateOf(false)

    private val io = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    const val ERR_SECURITY = "The download didn't pass the security check and was deleted."
    const val ERR_DOWNLOAD = "Download failed. Try again later."
    const val ERR_INSTALLER = "Couldn't start the installer."
    const val NOT_INSTALLED = "Update not installed."

    /** MainActivity.onStart: check if due (the core decides; no request otherwise). */
    fun onAppStart(context: Context) {
        val app = context.applicationContext
        // A leftover APK from an earlier install (PackageInstaller copied it).
        val clean = phase == ""
        io.launch {
            if (clean) File(app.cacheDir, "update").deleteRecursively()
            val phone = runCatching { DebugSeams.phone() ?: Core.phone(app) }.getOrNull() ?: return@launch
            check(phone, UpdateTrigger.APP_START)
        }
    }

    /** Settings → "Check now". */
    fun checkNow(phone: PhoneInterface) {
        dismissed = false
        status = "checking"
        io.launch { check(phone, UpdateTrigger.CHECK_NOW) }
    }

    private suspend fun check(phone: PhoneInterface, trigger: UpdateTrigger) {
        val r = runCatching { phone.updateCheck(trigger) }.getOrDefault(UpdateCheckResult.Failed)
        withContext(Dispatchers.Main) {
            when (r) {
                is UpdateCheckResult.Available -> {
                    if (offer?.version != r.offer.version) dismissed = false
                    offer = r.offer
                    status = ""
                }
                UpdateCheckResult.UpToDate -> { offer = null; status = "uptodate" }
                UpdateCheckResult.Failed -> status = "failed"
                UpdateCheckResult.Off -> { offer = null; status = "" }
                UpdateCheckResult.Skipped -> if (status == "checking") status = ""
            }
            Unit
        }
    }

    fun forget() {
        offer = null
        status = ""
    }

    /** "Update": download, verify, then hand the APK to PackageInstaller. */
    fun start(context: Context, phone: PhoneInterface) {
        if (phase != "") return
        val app = context.applicationContext
        if (!app.packageManager.canRequestPackageInstalls()) {
            needsPermission = true
            return
        }
        error = null
        phase = "downloading"
        percent = 0
        io.launch {
            val dir = File(app.cacheDir, "update")
            val res = runCatching { phone.updateDownload(dir.absolutePath, object : UpdateProgress {
                override fun onProgress(done: ULong, total: ULong) {
                    val p = if (total == 0UL) 0 else (done * 100UL / total).toInt().coerceIn(0, 100)
                    if (p != percent) {
                        CoroutineScope(Dispatchers.Main).launch { percent = p }
                    }
                }
            }) }.getOrDefault(UpdateDownloadResult.Failed)
            when (res) {
                is UpdateDownloadResult.Ready -> {
                    withContext(Dispatchers.Main) { phase = "verifying" }
                    val file = File(res.path)
                    // Re-read the file right before installing it.
                    val err = when {
                        !runCatching { phone.updateVerify(res.path) }.getOrDefault(false) -> { file.delete(); ERR_SECURITY }
                        runCatching { UpdateInstaller.install(app, file) }.isFailure -> ERR_INSTALLER
                        else -> null
                    }
                    withContext(Dispatchers.Main) {
                        phase = if (err == null) "installing" else ""
                        error = err
                    }
                }
                UpdateDownloadResult.SecurityFailed -> withContext(Dispatchers.Main) { phase = ""; error = ERR_SECURITY }
                UpdateDownloadResult.Failed, UpdateDownloadResult.NoOffer ->
                    withContext(Dispatchers.Main) { phase = ""; error = ERR_DOWNLOAD }
            }
        }
    }

    /** PackageInstaller reported the end of the install (not installed). */
    internal fun installEnded(installed: Boolean) {
        CoroutineScope(Dispatchers.Main).launch {
            phase = ""
            if (!installed) error = NOT_INSTALLED
        }
    }

    fun openNotes(context: Context, phone: PhoneInterface) {
        val url = runCatching { phone.updateNotesUrl() }.getOrNull() ?: return
        runCatching {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
    }

    fun openInstallSettings(context: Context) {
        needsPermission = false
        runCatching {
            context.startActivity(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }
}

/** Streams a verified APK into a PackageInstaller session; Android asks the user. */
object UpdateInstaller {
    const val ACTION = "app.voidwire.android.UPDATE_INSTALL_STATUS"

    fun install(context: Context, apk: File) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            if (Build.VERSION.SDK_INT >= 31) {
                setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
            }
        }
        val id = installer.createSession(params)
        installer.openSession(id).use { session ->
            apk.inputStream().use { input ->
                session.openWrite("voidwire.apk", 0, apk.length()).use { out ->
                    input.copyTo(out)
                    session.fsync(out)
                }
            }
            val intent = Intent(context, UpdateInstallReceiver::class.java).setAction(ACTION)
            // PackageInstaller fills in the status extras, so the intent must be mutable.
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
            session.commit(PendingIntent.getBroadcast(context, id, intent, flags).intentSender)
        }
    }
}

/** Install status from PackageInstaller (not exported; only our session's PendingIntent reaches it). */
class UpdateInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != UpdateInstaller.ACTION) return
        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val confirm = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_INTENT, Intent::class.java)
                if (confirm == null) {
                    Updates.installEnded(false)
                    return
                }
                runCatching { context.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                    .onFailure { Updates.installEnded(false) }
            }
            PackageInstaller.STATUS_SUCCESS -> Updates.installEnded(true)
            else -> Updates.installEnded(false)
        }
    }
}

private fun fmtSize(bytes: ULong): String {
    val b = bytes.toDouble()
    return if (b < 1024 * 1024) "${maxOf(1, (b / 1024).toInt())} KB" else String.format(java.util.Locale.US, "%.1f MB", b / (1024 * 1024))
}

/** The home-screen banner (design §8). */
@Composable
fun UpdateBanner(phone: PhoneInterface) {
    val context = LocalContext.current
    val cs = MaterialTheme.colorScheme
    val offer = Updates.offer
    val running = Updates.phase != ""
    if (offer != null && (running || !Updates.dismissed)) {
        VwCard(Modifier.testTag("update_banner")) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Update available", style = MaterialTheme.typography.titleMedium)
                val body = when (Updates.phase) {
                    "downloading" -> "Downloading… ${Updates.percent}%"
                    "verifying", "installing" -> "Checking the download…"
                    else -> "Voidwire ${offer.version} is ready to download (${fmtSize(offer.size)})."
                }
                Text(body, style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant)
                Updates.error?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = cs.error, modifier = Modifier.testTag("update_error"))
                }
                if (!running) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        TextButton(onClick = { Updates.openNotes(context, phone) }) { Text("What's new") }
                        Spacer(Modifier.weight(1f))
                        OutlinedButton(
                            onClick = { Updates.dismissed = true },
                            shape = VoidwireComponentShapes.secondaryButton,
                        ) { Text("Not now") }
                        Spacer(Modifier.width(8.dp))
                        Button(
                            onClick = { Updates.start(context, phone) },
                            shape = VoidwireComponentShapes.secondaryButton,
                            modifier = Modifier.testTag("update_go"),
                        ) { Text("Update") }
                    }
                }
            }
        }
    }
    if (Updates.needsPermission) {
        AlertDialog(
            onDismissRequest = { Updates.needsPermission = false },
            text = { Text("To install updates, allow Voidwire to install apps. You'll still confirm every update.") },
            confirmButton = { TextButton(onClick = { Updates.openInstallSettings(context) }) { Text("Open settings") } },
            dismissButton = { TextButton(onClick = { Updates.needsPermission = false }) { Text("Cancel") } },
        )
    }
}

/** Settings → Updates (design §8). */
@Composable
fun UpdatesSection(phone: PhoneInterface) {
    val cs = MaterialTheme.colorScheme
    var s by remember { mutableStateOf(runCatching { phone.updateSettings() }.getOrNull()) }
    val settings = s ?: return
    if (!settings.availableInBuild) return
    Eyebrow("Updates")
    VwCard {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Check for updates", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "At most once a day, when you open Voidwire. Only asks GitHub for the latest version; nothing about you or your devices is sent.",
                        style = MaterialTheme.typography.bodySmall,
                        color = cs.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.width(12.dp))
                Switch(
                    checked = settings.checksOn,
                    onCheckedChange = { on ->
                        runCatching { phone.setUpdateChecks(on) }
                        if (!on) Updates.forget()
                        s = runCatching { phone.updateSettings() }.getOrNull()
                    },
                    modifier = Modifier.testTag("update_checks_switch"),
                )
            }
            HorizontalDivider(color = cs.outlineVariant)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Test builds", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Get early versions before everyone else. They may have bugs.",
                        style = MaterialTheme.typography.bodySmall,
                        color = cs.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.width(12.dp))
                Switch(
                    checked = settings.testBuilds,
                    onCheckedChange = { on ->
                        runCatching { phone.setUpdateTestBuilds(on) }
                        Updates.forget()
                        s = runCatching { phone.updateSettings() }.getOrNull()
                    },
                    modifier = Modifier.testTag("update_test_switch"),
                )
            }
            HorizontalDivider(color = cs.outlineVariant)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Version ${settings.version}", style = MaterialTheme.typography.titleSmall)
                    val line = when {
                        Updates.status == "checking" -> "Checking…"
                        Updates.status == "uptodate" -> "You're up to date (Voidwire ${settings.version})."
                        Updates.status == "failed" -> "Couldn't check for updates. Try again later."
                        !settings.checksOn -> "Update checks are off."
                        else -> ""
                    }
                    if (line.isNotEmpty()) {
                        Text(line, style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant, modifier = Modifier.testTag("update_status"))
                    }
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                    onClick = { Updates.checkNow(phone) },
                    enabled = Updates.status != "checking",
                    shape = VoidwireComponentShapes.secondaryButton,
                ) { Text("Check now") }
            }
        }
    }
}
