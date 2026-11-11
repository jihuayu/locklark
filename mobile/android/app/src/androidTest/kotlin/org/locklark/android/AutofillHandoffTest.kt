package org.locklark.android

import android.os.Bundle
import android.os.SystemClock
import android.view.autofill.AutofillManager
import android.widget.TextView
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.locklark.android.autofill.AutofillAuthActivity
import org.locklark.android.autofill.AutofillSmokeTargetActivity

/**
 * Real OS handoff smoke: the framework must send a FillRequest to the service,
 * render the authentication presentation, launch the explicit auth Activity,
 * and leave both synthetic test-APK fields empty after cancel. No real target
 * app, browser, password manager or vault is involved.
 */
@RunWith(AndroidJUnit4::class)
class AutofillHandoffTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    private fun stage(value: String) {
        instrumentation.sendStatus(0, Bundle().apply {
            putString("locklark_autofill_stage", value)
        })
    }

    private fun waitUntil(deadline: Long, condition: () -> Boolean): Boolean {
        while (SystemClock.elapsedRealtime() < deadline) {
            if (condition()) return true
            SystemClock.sleep(100)
        }
        return condition()
    }

    private fun resumedActivities(): List<android.app.Activity> {
        var activities: List<android.app.Activity> = emptyList()
        instrumentation.runOnMainSync {
            activities = ActivityLifecycleMonitorRegistry.getInstance()
                .getActivitiesInStage(Stage.RESUMED)
                .toList()
        }
        return activities
    }

    @Test
    fun realOsAuthenticationChallengeCancelFillsNothing() {
        stage("preconditions")
        val context = instrumentation.targetContext
        val manager = context.getSystemService(AutofillManager::class.java)
        assertNotNull("AutofillManager unavailable", manager)
        assertTrue("Autofill is not supported", manager.isAutofillSupported)

        stage("target-launch")
        val targetPackage = instrumentation.context.packageName
        instrumentation.uiAutomation.executeShellCommand(
            "am start -W -n " + targetPackage + "/" + AutofillSmokeTargetActivity::class.java.name,
        ).close()
        val device = UiDevice.getInstance(instrumentation)
        val presentationText = context.getString(R.string.autofill_auth_presentation)
        val challengeTitle = context.getString(R.string.autofill_challenge_title)
        try {
            val usernameField = device.wait(
                Until.findObject(By.desc(AutofillSmokeTargetActivity.SMOKE_USERNAME)),
                10_000,
            )
            assertNotNull("Synthetic username field not visible", usernameField)
            stage("fill-request")

            val presentation = device.wait(Until.findObject(By.text(presentationText)), 10_000)
            assertNotNull("OS authentication presentation was not shown", presentation)
            stage("presentation-visible")
            presentation!!.click()
            stage("presentation-clicked")

            val authDeadline = SystemClock.elapsedRealtime() + 15_000
            assertTrue(
                "Explicit auth Activity did not resume",
                waitUntil(authDeadline) { resumedActivities().any { it is AutofillAuthActivity } },
            )
            val auth = resumedActivities().filterIsInstance<AutofillAuthActivity>().single()
            stage("auth-resumed")

            val title = auth.findViewById<TextView>(R.id.autofill_auth_title)?.text?.toString()
            assertEquals(challengeTitle, title)
            val body = auth.findViewById<TextView>(R.id.autofill_auth_body)?.text?.toString().orEmpty()
            assertTrue("Challenge must state that no fields were filled", body.contains("尚未填充任何字段"))

            device.pressBack()
            assertTrue(
                "Back did not close the auth Activity",
                waitUntil(SystemClock.elapsedRealtime() + 10_000) {
                    resumedActivities().none { it is AutofillAuthActivity }
                },
            )
            assertTrue(
                "Synthetic target did not resume after cancel",
                waitUntil(SystemClock.elapsedRealtime() + 10_000) {
                    device.hasObject(By.desc(AutofillSmokeTargetActivity.SMOKE_USERNAME))
                },
            )
            stage("auth-canceled")

            SystemClock.sleep(500)
            val username = device.findObject(By.desc(AutofillSmokeTargetActivity.SMOKE_USERNAME))
            val password = device.findObject(By.desc(AutofillSmokeTargetActivity.SMOKE_PASSWORD))
            assertNotNull("Username field disappeared", username)
            assertNotNull("Password field disappeared", password)
            assertTrue(
                "Username was filled after cancelled authentication",
                username!!.text.isNullOrEmpty(),
            )
            assertTrue(
                "Password was filled after cancelled authentication",
                password!!.text.isNullOrEmpty(),
            )
            stage("fields-empty")
        } finally {
            runCatching {
                repeat(3) {
                    if (device.hasObject(By.desc(AutofillSmokeTargetActivity.SMOKE_USERNAME)) ||
                        device.hasObject(By.text(challengeTitle))
                    ) {
                        device.pressBack()
                        device.waitForIdle()
                    }
                }
            }
        }
    }
}
