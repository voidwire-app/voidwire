package app.voidwire.android

import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** android-qa spec C1: the bad-link corpus through the real share intent; no Send button, nothing sent. */
@RunWith(AndroidJUnit4::class)
class ShareRefusalTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()
    private val backend = FakeShare(listOf(ShareTarget("ab".repeat(32), "QA PC")))

    @After fun reset() = ShareActivity.resetForTests()

    private fun refused(n: String, text: String, expect: String) {
        ShareActivity.backendFactory = { backend }
        ActivityScenario.launch<ShareActivity>(shareIntent(text)).use { s ->
            Qa.waitText(compose, "No link")
            Qa.waitText(compose, expect)
            var buttons = -1
            s.onActivity { buttons = it.sendButtonBounds.size; assertTrue("ui=${it.ui}", it.ui is ShareUi.Invalid) }
            assertEquals("a Send button is shown for $n", 0, buttons)
            Qa.shot("C1-bad-$n")
        }
        assertEquals(0, backend.sends.size)
    }

    @Test fun badLinkCorpusRefused() {
        val scheme = "Only http and https links can be sent."
        val local = "Links to localhost or link-local addresses only work on this phone."
        listOf(
            Triple("01-ftp", "ftp://example.com/x", scheme),
            Triple("02-javascript", "javascript:alert(1)", scheme),
            Triple("03-file", "file:///etc/passwd", scheme),
            Triple("04-intent", "intent://x#Intent;end", scheme),
            Triple("05-data", "data:text/html,hi", scheme),
            Triple("06-localhost", "http://localhost:8080/", local),
            Triple("07-loopback4", "http://127.0.0.1/", local),
            Triple("08-loopback6", "http://[::1]/", local),
            Triple("09-linklocal4", "http://169.254.169.254/", local),
            Triple("10-linklocal6", "http://[fe80::1]/", local),
            // userinfo: QA 10-11 saw a refusal without a fixed body; only "No link" is asserted.
            Triple("11-userinfo", "https://user:pass@example.com/", "No link"),
        ).forEach { (n, u, msg) -> refused(n, u, msg) }
    }

    @Test fun oversizeLinkRefused() =
        refused("12-oversize", "https://example.com/" + "a".repeat(9000), "This link is longer than the size limit.")

    /** Not a refusal: an IDN host is shown as punycode (spec C1, Cyrillic а). */
    @Test fun idnShownAsPunycode() {
        ShareActivity.backendFactory = { backend }
        ActivityScenario.launch<ShareActivity>(shareIntent("https://аpple.com/login")).use {
            Qa.waitText(compose, "Link OK")
            Qa.waitText(compose, "xn--pple-43d.com")
            Qa.shot("C1-idn-punycode")
        }
    }
}
