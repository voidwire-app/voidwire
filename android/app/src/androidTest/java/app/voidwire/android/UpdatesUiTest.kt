package app.voidwire.android

import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.voidwire_core.PcInfo
import uniffi.voidwire_core.UpdateOffer
import uniffi.voidwire_core.UpdateTrigger

/** U1: the update banner on the home screen and Settings → Updates (FakePhone, no network). */
@RunWith(AndroidJUnit4::class)
class UpdatesUiTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()
    private val pc = PcInfo("ab".repeat(32), "QA PC")
    private lateinit var fake: FakePhone

    @Before fun fresh() {
        resetAppPrefs()
        Updates.forget()
        Updates.dismissed = false
        Updates.error = null
        fake = FakePhone(listOf(pc))
        DebugSeams.fakePhone = fake
    }

    @After fun reset() {
        DebugSeams.fakePhone = null
        Updates.forget()
        Updates.dismissed = false
        Updates.error = null
        Updates.needsPermission = false
        resetAppPrefs()
    }

    private fun appops(mode: String) {
        val pkg = InstrumentationRegistry.getInstrumentation().targetContext.packageName
        InstrumentationRegistry.getInstrumentation().uiAutomation
            .executeShellCommand("appops set $pkg REQUEST_INSTALL_PACKAGES $mode").close()
    }

    @Test fun startChecksOnceAndShowsTheBanner() {
        fake.updateOffer = UpdateOffer("0.9.8", 18_400_000uL, "2026-11-02")
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, "Update available")
            assertTrue(Qa.has(compose, "Voidwire 0.9.8 is ready to download (17.5 MB)."))
            Qa.shot("U1-01-banner")
            compose.onNodeWithTag("update_banner").assertExists()
            compose.onNodeWithTag("update_go").assertExists()
        }
        // Only onStart asks; nothing else polls.
        assertEquals(listOf(UpdateTrigger.APP_START), fake.updateChecks.toList())
    }

    @Test fun notNowHidesTheBanner() {
        fake.updateOffer = UpdateOffer("0.9.8", 18_400_000uL, "2026-11-02")
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, "Update available")
            compose.onNodeWithText("Not now").performClick()
            compose.waitUntil(10_000) { !Qa.has(compose, "Update available") }
        }
    }

    @Test fun withoutPermissionExplainsThenFailsSecurityCheck() {
        fake.updateOffer = UpdateOffer("0.9.8", 18_400_000uL, "2026-11-02")
        appops("default")
        try {
            ActivityScenario.launch(MainActivity::class.java).use {
                Qa.waitText(compose, "Update available")
                compose.onNodeWithTag("update_go").performClick()
                Qa.waitText(compose, "To install updates, allow Voidwire to install apps. You'll still confirm every update.")
                Qa.shot("U1-02-permission")
                compose.onNodeWithText("Cancel").performClick()
                appops("allow")
                compose.onNodeWithTag("update_go").performClick()
                // FakePhone's download always fails the check: no installer starts.
                Qa.waitText(compose, "The download didn't pass the security check and was deleted.")
                Qa.shot("U1-03-security")
            }
        } finally {
            appops("default")
        }
    }

    @Test fun settingsSection() {
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, pc.name)
            compose.onNodeWithContentDescription("Settings").performClick()
            compose.onNodeWithTag("update_checks_switch").performScrollTo()
            Qa.waitText(compose, "Version 0.9.7-m4.6")
            Qa.shot("U1-04-settings")
            compose.onNodeWithText("Check now").performScrollTo().performClick()
            Qa.waitText(compose, "You're up to date (Voidwire 0.9.7-m4.6).")
            compose.onNodeWithTag("update_checks_switch").performClick()
            Qa.waitText(compose, "Update checks are off.")
        }
        assertTrue(!fake.updateChecksOn)
        assertTrue(fake.updateChecks.contains(UpdateTrigger.CHECK_NOW))
    }
}
