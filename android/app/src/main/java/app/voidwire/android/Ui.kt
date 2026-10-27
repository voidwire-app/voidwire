package app.voidwire.android

import uniffi.voidwire_core.PhoneException

/** User-facing text and modal dialog descriptors for core errors (never includes the link). */
object PhoneErrors {
    data class ErrorDialogInfo(val title: String, val message: String)

    private fun extractCapBytes(detail: String): Long? {
        val m = Regex("cap=(\\d+)").find(detail) ?: return null
        return m.groupValues[1].toLongOrNull()
    }

    private fun formatCapLabel(capBytes: Long?): String {
        val b = if (capBytes == null || capBytes <= 0L) 25L * 1024L * 1024L else capBytes
        return if (b % (1024L * 1024L) == 0L) {
            "${b / (1024L * 1024L)} MB"
        } else {
            FileShareStaging.formatSize(b)
        }
    }

    fun dialogForDetail(
        detail: String,
        pcName: String?,
        neverSendOverRelay: Boolean = false,
    ): ErrorDialogInfo {
        val lower = detail.lowercase()
        return when {
            lower.contains("never_send_files_over_relay") ||
                (lower.contains("exceeds_relay_cap") && (neverSendOverRelay || lower.contains("cap=0"))) -> {
                ErrorDialogInfo(
                    title = "Relay file transfers disabled",
                    message = "Relay file transfers are turned off (\"Never send files over relay\" is enabled in Settings). Connect to the same Wi-Fi network or change this in Settings.",
                )
            }
            lower.contains("exceeds_relay_cap") || lower.contains("exceeds the relay") -> {
                val capLabel = formatCapLabel(extractCapBytes(detail))
                ErrorDialogInfo(
                    title = "File exceeds relay limit",
                    message = "This file exceeds the relay server's size limit ($capLabel). Connect both devices to the same Wi-Fi network to send larger files directly.",
                )
            }
            lower.contains("canceled_by_recipient") ||
                lower.contains("cancelled_by_receiver") ||
                lower.contains("declined") ||
                lower.contains("transfer canceled on ") -> {
                val msg = if (!pcName.isNullOrBlank()) {
                    "Transfer canceled on $pcName."
                } else {
                    "Transfer canceled by recipient."
                }
                ErrorDialogInfo(
                    title = "Transfer canceled",
                    message = msg,
                )
            }
            else -> {
                ErrorDialogInfo(
                    title = "Transfer failed",
                    message = detail,
                )
            }
        }
    }

    fun dialogForPc(
        e: Throwable,
        pcName: String,
        neverSendOverRelay: Boolean = false,
    ): ErrorDialogInfo = when (e) {
        is PhoneException.Other -> dialogForDetail(e.detail, pcName, neverSendOverRelay)
        is PhoneException.Refused -> dialogForDetail(e.detail, pcName, neverSendOverRelay)
        else -> ErrorDialogInfo(
            title = "Transfer failed",
            message = textForPc(e, pcName),
        )
    }

    fun dialogForMessage(
        rawMessage: String,
        pcName: String?,
        neverSendOverRelay: Boolean = false,
    ): ErrorDialogInfo {
        val lower = rawMessage.lowercase()
        return when {
            lower.contains("never send files over relay") ||
                lower.contains("relayed file transfers are disabled") ||
                lower.contains("relay file transfers are turned off") -> {
                ErrorDialogInfo(
                    title = "Relay file transfers disabled",
                    message = rawMessage,
                )
            }
            lower.contains("exceeds the relay") || lower.contains("exceeds_relay_cap") -> {
                val mapped = dialogForDetail(rawMessage, pcName, neverSendOverRelay)
                ErrorDialogInfo(
                    title = "File exceeds relay limit",
                    message = if (rawMessage.contains("exceeds_relay_cap")) mapped.message else rawMessage,
                )
            }
            lower.contains("canceled on ") ||
                lower.contains("canceled_by_recipient") ||
                lower.contains("declined") -> {
                val mapped = dialogForDetail(rawMessage, pcName, neverSendOverRelay)
                ErrorDialogInfo(
                    title = "Transfer canceled",
                    message = if (rawMessage.contains("canceled_by_recipient") || rawMessage.contains("declined by recipient")) mapped.message else rawMessage,
                )
            }
            else -> ErrorDialogInfo(
                title = "Transfer failed",
                message = rawMessage,
            )
        }
    }

    fun text(e: Throwable): String = when (e) {
        is PhoneException.Unreachable -> e.detail
        is PhoneException.Refused -> dialogForDetail(e.detail, pcName = null).message
        is PhoneException.Removed -> "This PC removed this phone. Pair again to send to it."
        is PhoneException.Timeout -> "Timed out. Check that the PC app is running and both devices have a connection."
        is PhoneException.Cancelled -> "Cancelled."
        is PhoneException.Other -> dialogForDetail(e.detail, pcName = null).message
        is PhoneException.NotInitialized -> e.message ?: "Voidwire didn't start up properly. Close it and open it again."
        else -> "Something went wrong (${e.javaClass.simpleName})."
    }

    fun textForPc(e: Throwable, pcName: String, neverSendOverRelay: Boolean = false): String = when (e) {
        is PhoneException.Unreachable, is PhoneException.Timeout ->
            "Couldn't reach $pcName. Check that the PC app is running and both devices have a connection."
        is PhoneException.Other -> dialogForDetail(e.detail, pcName, neverSendOverRelay).message
        is PhoneException.Refused -> dialogForDetail(e.detail, pcName, neverSendOverRelay).message
        else -> text(e)
    }

    /** Stable short code for "what to report" (the test sheet asks for it). */
    fun code(e: Throwable): String = when (e) {
        is PhoneException.Refused -> e.code
        is PhoneException.Unreachable -> "unreachable"
        is PhoneException.Removed -> "removed"
        is PhoneException.Timeout -> "timeout"
        is PhoneException.Cancelled -> "cancelled"
        is PhoneException.NotInitialized -> "not_initialized"
        else -> "error"
    }
}
