package app.voidwire.android

import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.voidwire_core.PcInfo
import uniffi.voidwire_core.RelayChangeAsk

/** M4.4: "via <host>" on the PC card, Relay… asks the PC, a request from the PC asks the user, Settings → Relays. */
@RunWith(AndroidJUnit4::class)
class RelaysUiTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()
    private val pc = PcInfo("ab".repeat(32), "QA PC", false)
    private lateinit var fake: FakePhone

    @Before fun fresh() { resetAppPrefs(); fake = FakePhone(listOf(pc)); DebugSeams.fakePhone = fake }
    @After fun reset() { DebugSeams.fakePhone = null; resetAppPrefs() }

    @Test fun cardShowsRelayAndAsksToMove() {
        fake.addRelay("https://qa-relay.example", "c1".repeat(32), "Lab")
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, "via relay.voidwire.app")
            compose.onNodeWithTag("change_relay_btn").performClick()
            Qa.waitText(compose, "Move QA PC to another relay")
            compose.onNodeWithTag("relay_pick_ask").performClick()
            Qa.waitText(compose, "waiting for the other device")
            Qa.shot("M44-01-move-waiting")
        }
        assertEquals(listOf(pc.id to "https://qa-relay.example"), fake.relayProposals.toList())
    }

    @Test fun requestFromThePcAsksTheUser() {
        fake.relayAsk = RelayChangeAsk(pc.id, "QA PC", "qa-relay.example", "https://qa-relay.example", true)
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, "QA PC wants to move your pairing to qa-relay.example")
            Qa.shot("M44-02-request")
            compose.onNodeWithTag("relay_change_allow").performClick()
            compose.waitUntil(10_000) { fake.relayAnswers.isNotEmpty() }
        }
        assertEquals(listOf(pc.id to true), fake.relayAnswers.toList())
    }

    @Test fun settingsListsAndAddsRelays() {
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, pc.name)
            compose.onNodeWithContentDescription("Settings").performClick()
            compose.onNodeWithTag("relay_add_input").performScrollTo().performTextInput("voidwire:relay?r=x")
            compose.onNodeWithTag("relay_add_btn").performScrollTo().performClick()
            Qa.waitText(compose, "qa-relay.example")
            assertTrue(Qa.has(compose, "Connected"))
            Qa.shot("M44-03-settings-relays")
        }
        assertEquals(2, fake.relayRows.size)
    }
}
