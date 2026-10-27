package app.voidwire.android

import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * QA 8ee9a16: share sheet with no PC paired -> "Pair with a PC" -> Back must
 * not leave two MainActivity records (ShareActivity starts MainActivity with
 * NEW_TASK | CLEAR_TOP, in our own task).
 */
@RunWith(AndroidJUnit4::class)
class SharePairTaskTest {
    @get:Rule val compose = createEmptyComposeRule()
    @get:Rule val failShot = FailShotRule()

    @After fun reset() { DebugSeams.fakePhone = null; ShareActivity.resetForTests() }

    private fun mainActivities(): Int {
        val dump = Qa.shell("dumpsys activity activities")
        java.io.File(Qa.outDir, "share-pair-dumpsys-activities.txt").writeText(dump)
        val re = Regex("""ActivityRecord\{(\w+) u\d+ ${Regex.escape(Qa.ctx.packageName)}/\.MainActivity""")
        return re.findAll(dump).map { it.groupValues[1] }.toSet().size
    }

    @Test fun pairFromShareSheetThenBackHasOneMainActivity() {
        DebugSeams.fakePhone = FakePhone(emptyList())
        ShareActivity.backendFactory = { FakeShare(emptyList()) }
        ActivityScenario.launch(MainActivity::class.java).use {
            Qa.waitText(compose, "None yet")
            Qa.ctx.startActivity(shareIntent("https://example.com/x").addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
            Qa.waitText(compose, "No PC paired yet")
            compose.onAllNodesWithText("Pair with a PC").let { it[it.fetchSemanticsNodes().size - 1] }.performClick()
            denyCameraDialogIfShown()
            Thread.sleep(1_500)
            assertEquals("MainActivity copies after Pair with a PC", 1, mainActivities())
            UiDevice.getInstance(InstrumentationRegistry.getInstrumentation()).pressBack()
            Thread.sleep(1_500)
            Qa.shot("share-pair-back")
            assertEquals("MainActivity copies after Back", true, mainActivities() <= 1)
        }
    }
}
