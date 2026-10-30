package app.voidwire.android

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import uniffi.voidwire_core.Phone
import uniffi.voidwire_core.PhoneException
import uniffi.voidwire_core.StateStorage

/** The M1 phone surface through the real UniFFI bindings (host build). */
class PhoneFfiTest {
    // C1: the app installs the JNI context before Phone(); on the host JVM
    // there's nothing to install, but the contract (init first) is the same.
    @org.junit.Before fun platformInit() {
        assertTrue("NativeInit failed (java.library.path?)", NativeInit.init(null))
    }

    private class MemStorage : StateStorage {
        var blob: ByteArray? = null
        var saves = 0
        override fun load(): ByteArray? = blob
        override fun save(data: ByteArray): Boolean { blob = data; saves++; return true }
    }

    @Test fun identityPersistsThroughForeignStorage() {
        val store = MemStorage()
        val a = Phone(store, "Pixel Test")
        assertEquals("Pixel Test", a.deviceName())
        assertTrue(a.pairedPcs().isEmpty())
        a.setDeviceName("Renamed")
        assertNotNull(store.blob)
        a.close()
        val b = Phone(store, "ignored")
        assertEquals("Renamed", b.deviceName())
        b.close()
    }

    @Test fun badNamesAndQrAreRefusedWithReadableErrors() {
        val p = Phone(MemStorage(), "Phone")
        try {
            p.setDeviceName("bad\u0007name")
            fail("control char accepted")
        } catch (e: PhoneException.Refused) {
            assertEquals("bad_device_name", e.code)
        }
        for (qr in listOf("hello", "voidwire:pair?v=9", "https://example.com/")) {
            try {
                p.pair2OpenQr(qr)
                fail("accepted $qr")
            } catch (e: PhoneException) {
                assertFalse(PhoneErrors.text(e).isBlank())
            }
        }
        p.close()
    }

    @Test fun unknownPcIsAnError() {
        val p = Phone(MemStorage(), "Phone")
        try {
            p.sendUrl("00".repeat(32), "https://example.com/")
            fail("sent to an unpaired PC")
        } catch (e: PhoneException.Other) {
            assertTrue(e.detail.isNotBlank())
        }
        p.close()
    }

    @Test fun zxingDecodesAPairingQr() {
        val uri = "voidwire:pair?v=2&g=abc&s=def&a=192.168.1.20%3A48484"
        val m = QRCodeWriter().encode(uri, BarcodeFormat.QR_CODE, 400, 400)
        val y = ByteArray(400 * 400) { i -> if (m.get(i % 400, i / 400)) 0 else -1 }
        assertEquals(uri, QrDecode.decodeLuminance(y, 400, 400))
        assertTrue(QrDecode.looksLikePairing(uri))
        assertFalse(QrDecode.looksLikePairing("https://evil.example/voidwire:pair?"))
    }

    @Test fun sendTextFormatting() {
        assertEquals("example.com", SendText.host("https://example.com/a?b=1"))
        assertEquals("0.8 ms", SendText.latency(800uL))
        assertEquals("25 ms", SendText.latency(25_400uL))
    }

    @Test fun relayCapAndConnectionStatsPersistThroughFfi() {
        val store = MemStorage()
        val p = Phone(store, "Pixel M27")
        assertEquals(2uL * 1024uL * 1024uL * 1024uL, p.relayFileCapBytes())
        assertFalse(p.neverSendFilesOverRelay())
        assertEquals("https://relay.voidwire.app", p.relayUrl())
        assertEquals(
            "b080fe7101c968a6c827bad4e99d225343faa3bee18ee2a82b799c7a9d2f6840",
            p.mailboxId(),
        )
        assertFalse(p.connectionStatsEnabled())
        assertTrue(p.connectionStats().isEmpty())

        p.setNeverSendFilesOverRelay(true)
        assertTrue(p.neverSendFilesOverRelay())
        assertEquals(0uL, p.relayFileCapBytes())
        p.setRelayUrl("https://relay.example.com")
        p.setMailboxId("aa".repeat(32))
        p.setConnectionStatsEnabled(true)
        assertTrue(p.connectionStatsEnabled())
        p.close()

        val reloaded = Phone(store, "ignored")
        assertTrue(reloaded.neverSendFilesOverRelay())
        assertEquals(0uL, reloaded.relayFileCapBytes())
        assertEquals("https://relay.example.com", reloaded.relayUrl())
        assertEquals("aa".repeat(32), reloaded.mailboxId())
        assertTrue(reloaded.connectionStatsEnabled())
        reloaded.setNeverSendFilesOverRelay(false)
        assertFalse(reloaded.neverSendFilesOverRelay())
        reloaded.setRelayUrl(null)
        reloaded.setMailboxId(null)
        assertEquals("https://relay.voidwire.app", reloaded.relayUrl())
        assertEquals(
            "b080fe7101c968a6c827bad4e99d225343faa3bee18ee2a82b799c7a9d2f6840",
            reloaded.mailboxId(),
        )
        reloaded.setConnectionStatsEnabled(false)
        assertFalse(reloaded.connectionStatsEnabled())
        assertTrue(reloaded.connectionStats().isEmpty())
        reloaded.close()
    }

    @Test fun phoneErrorsUsesUpdatedConnectionCopy() {
        val msg = PhoneErrors.textForPc(PhoneException.Unreachable("old"), "Office-Desktop")
        assertEquals(
            "Couldn't reach Office-Desktop. Check that the PC app is running and both devices have a connection.",
            msg,
        )
        assertFalse(msg.contains("Wi-Fi"))
    }

    @Test fun m31ClassifyTextAndIncomingSnapshotThroughFfi() {
        val urlKind = uniffi.voidwire_core.classifySharedText("https://example.com/docs?q=1")
        assertTrue(urlKind is uniffi.voidwire_core.SharedContent.Url)

        val textKind = uniffi.voidwire_core.classifySharedText("Meeting notes: bring adapter")
        assertTrue(textKind is uniffi.voidwire_core.SharedContent.ClipboardText)
        val clip = textKind as uniffi.voidwire_core.SharedContent.ClipboardText
        assertEquals("Meeting notes: bring adapter", clip.text)
        assertFalse(clip.sensitive)

        val secretKind = uniffi.voidwire_core.classifySharedText("ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD")
        assertTrue(secretKind is uniffi.voidwire_core.SharedContent.ClipboardText)
        assertTrue((secretKind as uniffi.voidwire_core.SharedContent.ClipboardText).sensitive)
        assertTrue(uniffi.voidwire_core.looksSensitiveClipboard("sk-proj-1234567890abcdefghijklmnop"))
        assertFalse(uniffi.voidwire_core.looksSensitiveClipboard("hello world from voidwire"))

        val p = Phone(MemStorage(), "Pixel M31")
        val snap = p.pollIncoming()
        assertTrue(snap.links.isEmpty())
        assertTrue(snap.clipboards.isEmpty())
        assertTrue(snap.files.isEmpty())
        assertEquals(0u, p.pullDeviceInboxNow())
        p.dismissIncomingItem(999uL)
        try {
            p.cancelIncomingFile("00".repeat(32))
            fail("expected PhoneException for unknown transferId")
        } catch (e: PhoneException.Other) {
            assertTrue(e.detail.isNotBlank())
        }
        p.setBackgroundListening(true)
        p.setBackgroundListening(false)
        p.close()
    }
}
