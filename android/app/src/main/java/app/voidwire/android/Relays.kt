package app.voidwire.android

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.voidwire.android.ui.ChipTone
import app.voidwire.android.ui.VwChip
import app.voidwire.android.ui.theme.VoidwireComponentShapes
import app.voidwire.android.ui.theme.VoidwireTheme
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.voidwire_core.PcInfo
import uniffi.voidwire_core.PhoneInterface
import uniffi.voidwire_core.RelayChangeAsk
import uniffi.voidwire_core.RelayRow

/*
 * M4.4 relays. Settings → Relays lists the saved relays (at most 8, at most
 * 4 in use) with their status. A pairing moves to another relay only when
 * both devices agree: this phone asks, the other device's user allows it,
 * and both sign the change. Requests from the other device show while the
 * app is open (no notification). Everything read here is local state;
 * nothing polls the network.
 */

/** The text under a PC card: "via <host>" plus a move in progress. */
internal fun relayLine(host: String?, state: String?, toHost: String?): String? {
    val via = host?.takeIf { it.isNotBlank() }?.let { "via $it" }
    val note = when (state) {
        "waiting" -> "moving to $toHost: waiting for the other device to allow it"
        "declined" -> "move to $toHost was declined"
        "no_room" -> "the other device has no room for $toHost"
        "done" -> "moved"
        else -> null
    }
    return listOfNotNull(via, note).joinToString(" · ").ifBlank { null }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun RelaysSection(phone: PhoneInterface, onHomeChanged: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberUiScope()
    val cs = MaterialTheme.colorScheme
    var relays by remember { mutableStateOf(runCatching { phone.relays() }.getOrDefault(emptyList())) }
    var input by remember { mutableStateOf("") }
    var mailbox by remember { mutableStateOf("") }
    var note by remember { mutableStateOf<String?>(null) }
    var noteIsError by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf<RelayRow?>(null) }
    fun reload() {
        relays = runCatching { phone.relays() }.getOrDefault(emptyList())
    }
    fun act(done: String?, after: () -> Unit = {}, block: () -> Unit) {
        scope.launch {
            try {
                withContext(Dispatchers.IO) { block() }
                after()
                note = done
                noteIsError = false
            } catch (e: Exception) {
                note = PhoneErrors.text(e)
                noteIsError = true
            }
            reload()
        }
    }
    Column(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.testTag("relays_section")) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Saved relays", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            Text(
                "${relays.size} / 8 saved",
                style = VoidwireTheme.code.codeSmall,
                color = cs.onSurfaceVariant,
                modifier = Modifier.testTag("relays_saved"),
            )
        }
        Text(
            "New pairings use the Home relay; each paired device keeps the relay it was paired with (move one from its card's ⋯ menu). Up to 4 in use. Relays only carry encrypted traffic.",
            style = MaterialTheme.typography.bodySmall,
            color = cs.onSurfaceVariant,
        )
        for (r in relays) {
            HorizontalDivider(color = cs.outlineVariant)
            Column(verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.testTag("relay_row")) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(
                                r.nickname.ifBlank { r.host },
                                style = MaterialTheme.typography.titleSmall,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f, fill = false),
                            )
                            if (r.home) {
                                Text(
                                    "HOME",
                                    style = VoidwireTheme.code.codeSmall,
                                    color = cs.primary,
                                    modifier = Modifier.testTag("relay_home_mark"),
                                )
                            }
                        }
                        val bits = listOfNotNull(
                            r.host,
                            "public".takeIf { r.builtin },
                            if (r.usedBy == 1u) "1 device" else "${r.usedBy} devices",
                        )
                        Text(bits.joinToString(" · "), style = VoidwireTheme.code.codeSmall, color = cs.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Spacer(Modifier.width(8.dp))
                    when (r.status) {
                        "connected" -> VwChip("Connected", ChipTone.Ok)
                        "unreachable" -> VwChip("Can't reach", ChipTone.Error)
                        else -> VwChip("Idle", ChipTone.Idle)
                    }
                }
                if (r.status == "unreachable" && r.downSinceMs > 0uL) {
                    val since = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(r.downSinceMs.toLong()))
                    Text("Can't reach since $since", style = MaterialTheme.typography.bodySmall, color = cs.error)
                }
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = {
                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        cm?.setPrimaryClip(ClipData.newPlainText("Relay link", r.link))
                        note = "Copied the relay link. Add it in Settings → Relays on another device."
                        noteIsError = false
                    }) { Text("Copy link") }
                    if (r.status == "unreachable") {
                        TextButton(onClick = { act("Trying ${r.host} again.") { phone.retryRelay(r.url) } }) { Text("Retry") }
                    }
                    if (!r.home) {
                        TextButton(onClick = {
                            act("Home relay is now ${r.host}. New pairings use it; paired devices keep their relay.", onHomeChanged) {
                                phone.setRelayUrl(r.url)
                                phone.setMailboxId(r.mailboxId)
                            }
                        }) { Text("Make home") }
                    }
                    TextButton(onClick = { renaming = r }) { Text("Rename") }
                    if (!r.builtin && !r.home && r.usedBy == 0u) {
                        TextButton(onClick = { act("Removed ${r.host}.") { phone.removeRelay(r.url) } }) {
                            Text("Remove", color = cs.error)
                        }
                    }
                }
            }
        }
        HorizontalDivider(color = cs.outlineVariant)
        OutlinedTextField(
            value = input,
            onValueChange = { input = it.take(2048); note = null },
            singleLine = true,
            label = { Text("Relay link or https:// URL") },
            modifier = Modifier.fillMaxWidth().testTag("relay_add_input"),
        )
        if (input.isNotBlank() && !input.trim().startsWith("voidwire:")) {
            OutlinedTextField(
                value = mailbox,
                onValueChange = { mailbox = it.take(64); note = null },
                singleLine = true,
                label = { Text("Mailbox ID (64 hex)") },
                modifier = Modifier.fillMaxWidth(),
            )
        }
        OutlinedButton(
            onClick = {
                val t = input.trim()
                if (t.isEmpty()) return@OutlinedButton
                val mb = mailbox.trim()
                act("Saved the relay. Use ⋯ → Change relay on a device card to move it there.", { input = ""; mailbox = "" }) {
                    if (t.startsWith("voidwire:")) phone.addRelayLink(t) else phone.addRelay(t, mb, "")
                }
            },
            enabled = input.isNotBlank(),
            shape = VoidwireComponentShapes.secondaryButton,
            modifier = Modifier.testTag("relay_add_btn"),
        ) { Text("Add relay") }
        // Always two lines tall, so a message never moves the layout.
        Text(
            note.orEmpty(),
            style = MaterialTheme.typography.bodySmall,
            color = if (noteIsError) cs.error else cs.onSurfaceVariant,
            minLines = 2,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.testTag("relays_note"),
        )
    }
    renaming?.let { r ->
        var name by remember(r.url) { mutableStateOf(r.nickname.ifBlank { r.host }) }
        AlertDialog(
            onDismissRequest = { renaming = null },
            title = { Text("Rename relay") },
            text = {
                OutlinedTextField(value = name, onValueChange = { name = it.take(40) }, singleLine = true, label = { Text(r.host) })
            },
            confirmButton = {
                Button(onClick = {
                    renaming = null
                    act(null) { phone.renameRelay(r.url, name.trim()) }
                }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { renaming = null }) { Text("Cancel") } },
        )
    }
}

/** The other device asks to move this pairing. */
@Composable
internal fun RelayChangeAskDialog(ask: RelayChangeAsk, onAnswer: (Boolean) -> Unit) {
    AlertDialog(
        onDismissRequest = {},
        modifier = Modifier.testTag("relay_change_ask"),
        title = { Text("${ask.peerName} wants to move your pairing to ${ask.host}") },
        text = {
            Text(
                (if (ask.newRelay) "${ask.host} isn't in your saved relays yet; allowing saves it. " else "") +
                    "Only this pairing moves. Links and files stay end-to-end encrypted; the relay only sees encrypted traffic.",
            )
        },
        confirmButton = { Button(onClick = { onAnswer(true) }, modifier = Modifier.testTag("relay_change_allow")) { Text("Allow") } },
        dismissButton = { TextButton(onClick = { onAnswer(false) }, modifier = Modifier.testTag("relay_change_decline")) { Text("Decline") } },
    )
}

/** This phone asks [pc] to move to another saved relay. */
@Composable
internal fun RelayPickDialog(
    phone: PhoneInterface,
    pc: PcInfo,
    currentUrl: String?,
    onDone: (String?) -> Unit,
) {
    val scope = rememberUiScope()
    var choices by remember { mutableStateOf(emptyList<RelayRow>()) }
    var picked by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var loaded by remember { mutableStateOf(false) }
    UiEffect(pc.id) {
        val home = runCatching { phone.relayUrl() }.getOrNull()
        val cur = (currentUrl ?: home)?.trimEnd('/')
        choices = runCatching { phone.relays() }.getOrDefault(emptyList()).filter { it.url.trimEnd('/') != cur }
        picked = choices.firstOrNull()?.url
        loaded = true
    }
    if (!loaded) return
    if (choices.isEmpty()) {
        // Nothing to move to: say only what to do (M4.4.2).
        AlertDialog(
            onDismissRequest = { onDone(null) },
            modifier = Modifier.testTag("relay_pick_none"),
            text = { Text("Add another relay in Settings → Relays first.") },
            confirmButton = { TextButton(onClick = { onDone(null) }) { Text("Close") } },
        )
        return
    }
    AlertDialog(
        onDismissRequest = { if (!busy) onDone(null) },
        modifier = Modifier.testTag("relay_pick"),
        title = { Text("Move ${pc.name} to another relay") },
        text = {
            Column(Modifier.selectableGroup(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                for (r in choices) {
                    Row(
                        Modifier.fillMaxWidth().selectable(selected = picked == r.url, role = Role.RadioButton, onClick = { picked = r.url }).padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = picked == r.url, onClick = null)
                        Spacer(Modifier.width(8.dp))
                        Text(r.nickname.ifBlank { r.host } + if (r.nickname.isNotBlank() && r.nickname != r.host) " (${r.host})" else "")
                    }
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    error ?: "Both devices must be online. ${pc.name} has to allow it before anything moves.",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            Button(
                enabled = !busy && picked != null,
                onClick = {
                    val url = picked ?: return@Button
                    busy = true
                    error = null
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { phone.changePairingRelay(pc.id, url) }
                            onDone("Asked ${pc.name}. The pairing moves once it allows the change.")
                        } catch (e: Exception) {
                            error = PhoneErrors.text(e)
                        } finally {
                            busy = false
                        }
                    }
                },
                modifier = Modifier.testTag("relay_pick_ask"),
            ) { Text(if (busy) "Asking…" else "Ask") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = { onDone(null) }) { Text("Cancel") } },
    )
}
