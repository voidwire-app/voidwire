package app.voidwire.android

import android.Manifest
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.isDialog
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/*
 * Real core, real network: these run against the Linux desktop app started
 * headless on the runner (android-qa.yml "host PC peer"). Driven by
 * scripts/qa/android-qa.sh with instrumentation args; never run in the plain
 * connected run (they'd fail without the peer).
 */

/** Spec 0 / C: pair through "Can't scan? Paste the pairing link". Arg pairLink. */
@RunWith(AndroidJUnit4::class)
class PairViaPasteTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()
    @get:Rule val camera: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.CAMERA)

    @Test fun pairsWithHostPeer() {
        val link = Qa.arg("pairLink") ?: error("needs -e pairLink")
        val codeFile = File(Qa.outDir, "pair-code.txt").apply { delete() }
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, "Pair with a PC", 120_000)
            compose.onAllNodesWithText("Pair with a PC").let { it[it.fetchSemanticsNodes().size - 1] }.performClick()
            Qa.usePairLink(compose, link)
            Qa.waitText(compose, "Type this on the PC", 120_000)
            // The code cells are single-digit Texts; read them from the semantics tree.
            val code = compose.onAllNodes(androidx.compose.ui.test.isRoot()).fetchSemanticsNodes()
                .flatMap { collectTexts(it) }.filter { it.matches(Regex("^\\d$")) }.take(6).joinToString("")
            assertTrue("code not readable: '$code'", code.length == 6)
            Qa.shot("C-pair-code-host")
            codeFile.writeText(code) // android-qa.sh polls this and types it into the desktop
            Qa.waitText(compose, "Paired with", 150_000)
            Qa.shot("C-paired-host")
            compose.onNodeWithText("Done").performClick()
            compose.waitForIdle()
        }
    }

    private fun collectTexts(n: androidx.compose.ui.semantics.SemanticsNode): List<String> =
        (n.config.getOrElseNullable(androidx.compose.ui.semantics.SemanticsProperties.Text) { null }
            ?.map { it.text } ?: emptyList()) + n.children.flatMap { collectTexts(it) }
}

/** Spec C2/C3: a real send to the host peer; then, after the PC forgot this phone, the refusal. Arg url. */
@RunWith(AndroidJUnit4::class)
class ShareE2eTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()

    @Test fun sendsToHostPeer() {
        val url = Qa.arg("url") ?: "https://example.com/p?q=1#frag"
        ActivityScenario.launch<ShareActivity>(shareIntent(url)).use { s ->
            Qa.waitText(compose, "Link OK", 60_000)
            tapSendWhenArmed(s)
            Qa.waitText(compose, "Sent to", 60_000)
            Qa.shot("C2-sent-to-host")
        }
    }

    @Test fun refusedAfterPcForgot() {
        val url = Qa.arg("url") ?: "https://example.net/m11/after-forget"
        ActivityScenario.launch<ShareActivity>(shareIntent(url)).use { s ->
            Qa.waitText(compose, "Link OK", 60_000)
            tapSendWhenArmed(s)
            Qa.waitText(compose, "This PC removed this phone", 60_000)
            Qa.shot("C3-refused-after-forget")
        }
    }

    /** S14: the main screen card shows REMOVED after the PC forgot this phone (either from C3 send or Check). */
    @Test fun s14RemovedCard() {
        ActivityScenario.launch(MainActivity::class.java).use {
            compose.waitUntil(120_000) { Qa.has(compose, "Removed") || Qa.has(compose, "Check") }
            if (!Qa.has(compose, "Removed")) {
                compose.onNodeWithText("Check").performClick()
            }
            Qa.waitText(compose, "Removed", 60_000)
            Qa.shot("S14-main-removed-card")
        }
    }
}

/**
 * Spec F: Forget while the state can't be saved (android-qa.sh makes
 * no_backup read-only first). Expected after the core rollback fix: an error
 * snackbar and the card stays. Shots S15a-c at 0.5 / 1.5 / 3 s.
 */
@RunWith(AndroidJUnit4::class)
class ForgetSaveFailureTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()

    @Test fun cardStaysWhenSaveFails() {
        val name = Qa.arg("pcName") ?: error("needs -e pcName")
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, name, 120_000)
            // android-qa.sh runs this right after S14, so the card may already be REMOVED (the PC
            // forgot this phone). The REMOVED state must not change; it is not caused by the failed save.
            val wasRemoved = Qa.has(compose, "Removed")
            compose.onAllNodesWithText("Forget")[0].performClick()
            Qa.waitText(compose, "Forget $name?")
            compose.onNode(hasText("Forget") and hasClickAction() and hasAnyAncestor(isDialog())).performClick()
            // S15 timed series (d446e01: one assertion per point, not one at the end).
            // 0.5 s: the card never leaves, even for a frame of optimistic removal.
            Qa.shot("S15a-forget-savefail-0.5s", 500)
            assertTrue("S15a 0.5 s: card gone", Qa.has(compose, name))
            assertFalse("S15a 0.5 s: dialog still open", Qa.has(compose, "Forget $name?"))
            // 1.5 s: the error ("Couldn't forget <PC>. Try again." + Retry, F2) is shown and the card is still there.
            Qa.waitText(compose, "Couldn't forget $name. Try again.", 5_000)
            Qa.shot("S15b-forget-savefail-1.5s", 500)
            assertTrue("S15b 1.5 s: error snackbar not shown", Qa.has(compose, "Couldn't forget $name. Try again."))
            assertTrue("S15b 1.5 s: Retry action not shown", Qa.has(compose, "Retry"))
            assertTrue("S15b 1.5 s: card gone", Qa.has(compose, name))
            assertEquals("S15b: REMOVED state changed by the failed save", wasRemoved, Qa.has(compose, "Removed"))
            // 3 s: still listed, still not marked removed.
            Qa.shot("S15c-forget-savefail-3s", 1_500)
            assertTrue("S15c 3 s: card gone", Qa.has(compose, name))
            assertEquals("S15c: REMOVED state changed by the failed save", wasRemoved, Qa.has(compose, "Removed"))
        }
    }
}

/** State helpers android-qa.sh calls between adb checks (the same app calls Settings makes). */
@RunWith(AndroidJUnit4::class)
class QaStateTest {
    /** -e theme system|dark|light */
    @Test fun setTheme() =
        ThemePref.set(Qa.ctx, app.voidwire.android.ui.theme.ThemeMode.fromKey(Qa.arg("theme") ?: "system"))

    /** B2/B3 diagnostics: the per-app night mode the system holds for us. */
    @Test fun nightMode() {
        val v = if (android.os.Build.VERSION.SDK_INT >= 31)
            Qa.ctx.getSystemService(android.app.UiModeManager::class.java)?.let { "app=${it.nightMode}/${applicationNightModeOrNull(it)}" } ?: "no UiModeManager"
        else "api<31"
        android.util.Log.i("VoidwireQa", "nightMode $v pref=${ThemePref.get(Qa.ctx)}")
        File(Qa.outDir, "night-mode.txt").appendText("$v pref=${ThemePref.get(Qa.ctx)}\n")
    }

    /** -e on true|false: both history opt-ins (off also deletes their files). */
    @Test fun optIns() {
        val on = Qa.arg("on") == "true"
        RecentSends.setEnabled(Qa.ctx, on)
        LastPc.setEnabled(Qa.ctx, on)
    }
}

/** UiModeManager.getApplicationNightMode is public API 34; reflect so compileSdk below that still builds. */
internal fun applicationNightModeOrNull(ui: android.app.UiModeManager): Any? =
    runCatching { ui.javaClass.getMethod("getApplicationNightMode").invoke(ui) }.getOrElse { "n/a" }
