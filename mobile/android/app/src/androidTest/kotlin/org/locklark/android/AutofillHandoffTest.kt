package org.locklark.android

import android.os.Bundle
import android.view.View
import android.os.SystemClock
import android.view.autofill.AutofillManager
import android.widget.TextView
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import mobilecore.Mobilecore
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.locklark.android.autofill.AutofillAuthActivity
import org.locklark.android.autofill.AutofillSmokeTargetActivity
import java.io.File
import java.security.SecureRandom

/**
 * Real OS handoff flows against the real `AutofillAuthService`.
 *
 * The negative flow proves the framework sends a FillRequest, renders the
 * authentication presentation, launches the explicit auth Activity with the
 * exact target package and factor form, and leaves both synthetic test-APK
 * fields empty after cancel.
 *
 * The positive flow additionally builds a synthetic-only `personal.ll` fixture
 * under the app's target context with the real mobilecore JNI API, unlocks it
 * through the real Activity UI with fresh master-password + Secret Key factors,
 * selects the one visible row, presses the separate Approve, has Android
 * receive the RESULT_OK authentication response and selects the returned
 * Dataset, and then asserts both synthetic target fields equal the fixture.
 * Only the test APK's synthetic target and a test-only vault under the app's
 * own private storage are involved; no browser, real target app or user vault.
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

    private fun launchTarget(): String {
        val targetPackage = instrumentation.context.packageName
        instrumentation.uiAutomation.executeShellCommand(
            "am start -W -n " + targetPackage + "/" + AutofillSmokeTargetActivity::class.java.name,
        ).close()
        return targetPackage
    }

    private fun openChallenge(device: UiDevice, presentationText: String): Boolean {
        val presentation = device.wait(Until.findObject(By.text(presentationText)), 15_000) ?: return false
        presentation.click()
        return true
    }

    private fun waitForAuthActivity(deadline: Long): AutofillAuthActivity? {
        if (!waitUntil(deadline) { resumedActivities().any { it is AutofillAuthActivity } }) return null
        return resumedActivities().filterIsInstance<AutofillAuthActivity>().singleOrNull()
    }

    private fun click(device: UiDevice, text: String, timeout: Long = 15_000): Boolean {
        val target: UiObject2 = device.wait(Until.findObject(By.text(text)), timeout) ?: return false
        if (!target.isEnabled) return false
        target.click()
        device.waitForIdle()
        return true
    }

    /**
     * Types [value] into the field identified by [description]. The value is
     * delivered through the accessibility ACTION_SET_TEXT node action: the
     * UiAutomator setText/selector helpers log their argument, and no factor or
     * credential may ever reach a log line.
     */
    private fun enter(device: UiDevice, description: String, value: String, timeout: Long = 15_000): Boolean {
        val field: UiObject2 = device.wait(Until.findObject(By.desc(description)), timeout) ?: return false
        runCatching {
            field.click()
            device.waitForIdle()
        }
        val arguments = Bundle().apply {
            putCharSequence(android.view.accessibility.AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value)
        }
        val applied = runCatching {
            val root = instrumentation.uiAutomation.rootInActiveWindow ?: return@runCatching false
            root.refresh()
            val node = findEditable(root, description) ?: return@runCatching false
            node.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_SET_TEXT, arguments)
        }.getOrDefault(false)
        device.waitForIdle()
        // Re-observe the node: the pre-action UiObject2 snapshot is stale.
        // A password-variation widget can report a masked equivalent of the
        // same length, so exact text equality is not observable through the
        // accessibility tree. The action result is the interaction's proof.
        instrumentation.sendStatus(0, Bundle().apply {
            putString("locklark_input_active", applied.toString())
        })
        return applied
    }

    private fun findEditable(
        root: android.view.accessibility.AccessibilityNodeInfo?,
        description: String,
    ): android.view.accessibility.AccessibilityNodeInfo? {
        root ?: return null
        if (root.contentDescription?.toString() == description && root.isEditable) return root
        for (index in 0 until root.childCount) {
            findEditable(root.getChild(index), description)?.let { return it }
        }
        return null
    }

    /**
     * Selects the one synthetic login row by its visible title without putting
     * that title into a UiAutomator selector (which would log it).
     */
    private fun clickSyntheticRow(device: UiDevice, title: String, timeout: Long = 20_000): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeout
        while (SystemClock.elapsedRealtime() < deadline) {
            try {
                // A fixed prefix is not a fixture value, and the exact title is
                // matched in-process, so no canary can enter a selector log.
                val rows = device.findObjects(By.textStartsWith(SyntheticVaultFixture.TITLE_PREFIX))
                val match = rows.firstOrNull { runCatching { it.text?.toString() }.getOrNull() == title }
                if (match != null) {
                    match.click()
                    device.waitForIdle()
                    return true
                }
            } catch (_: androidx.test.uiautomator.StaleObjectException) {
                // The list was just replaced; observe it again.
            }
            SystemClock.sleep(100)
        }
        return false
    }

    /** Waits until the fresh unlock really produced the row-selection page. */
    private fun waitForSelectPage(device: UiDevice, timeout: Long = 20_000): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeout
        while (SystemClock.elapsedRealtime() < deadline) {
            if (device.hasObject(By.text("批准所选登录"))) return true
            SystemClock.sleep(100)
        }
        return false
    }

    /** Leaves no Autofill auth Activity from a previous test resumed. */
    private fun dismissAuthActivities(device: UiDevice) {
        repeat(6) {
            if (resumedActivities().none { it is AutofillAuthActivity }) return
            device.pressBack()
            SystemClock.sleep(300)
        }
    }

    @Test
    fun realOsAuthenticationChallengeCancelFillsNothing() {
        stage("preconditions")
        val context = instrumentation.targetContext
        val manager = context.getSystemService(AutofillManager::class.java)
        assertNotNull("AutofillManager unavailable", manager)
        assertTrue("Autofill is not supported", manager.isAutofillSupported)

        stage("fixture-create")
        val fixture = SyntheticVaultFixture(context.cacheDir)
        fixture.create(instrumentation.targetContext.noBackupFilesDir)
        stage("target-launch")
        val targetPackage = launchTarget()
        val device = UiDevice.getInstance(instrumentation)
        val presentationText = context.getString(R.string.autofill_auth_presentation)
        val challengeTitle = context.getString(R.string.autofill_auth_title)
        try {
            val usernameField = device.wait(
                Until.findObject(By.desc(AutofillSmokeTargetActivity.SMOKE_USERNAME)),
                10_000,
            )
            assertNotNull("The synthetic target username field was not visible", usernameField)
            stage("fill-request")

            assertTrue("The OS did not show the authentication presentation", openChallenge(device, presentationText))
            stage("presentation-visible")
            stage("presentation-clicked")

            val auth = waitForAuthActivity(SystemClock.elapsedRealtime() + 15_000)
            assertNotNull("The explicit Autofill auth Activity did not resume", auth)
            stage("auth-resumed")

            val title = auth!!.findViewById<TextView>(R.id.autofill_auth_title)?.text?.toString()
            assertEquals(challengeTitle, title)
            val body = auth.findViewById<TextView>(R.id.autofill_auth_body)?.text?.toString().orEmpty()
            // The fixed no-fill or fresh-unlock page; neither can claim a fill.
            assertTrue(
                "Auth page must be a fixed no-fill state",
                body.contains(context.getString(R.string.autofill_auth_no_fill)) ||
                    body.contains(context.getString(R.string.autofill_auth_unlock_guidance)),
            )

            // The dialog must name the exact OS target package.
            val target = auth.findViewById<TextView>(R.id.autofill_auth_target)?.text?.toString().orEmpty()
            assertEquals(
                "Target package must be displayed exactly",
                context.getString(R.string.autofill_auth_target, targetPackage),
                target,
            )
            val deadline = SystemClock.elapsedRealtime() + 10_000
            var masterPasswordField = auth.findViewById<View>(R.id.autofill_auth_master_password)
            var secret = auth.findViewById<View>(R.id.autofill_auth_secret_key)
            while ((masterPasswordField == null || secret == null) && SystemClock.elapsedRealtime() < deadline) {
                SystemClock.sleep(100)
                masterPasswordField = auth.findViewById(R.id.autofill_auth_master_password)
                secret = auth.findViewById(R.id.autofill_auth_secret_key)
            }
            assertNotNull("Master password field not shown", masterPasswordField)
            assertNotNull("Secret Key field not shown", secret)
            // Approve does not exist before a login is selected. The factor page
            // is shown as soon as the fresh vault opens; until then the approve
            // button may be missing, but it must never be present and enabled.
            val approve = auth.findViewById<View>(R.id.autofill_auth_approve)
            assertTrue(
                "Approve must be missing or disabled while locked, but was present and enabled",
                approve == null || !approve.isEnabled,
            )
            assertNull("No login may be silently selected", auth.findViewById(R.id.autofill_auth_row))

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
                "Cancelled authentication must leave the username field empty",
                username!!.text.isNullOrEmpty(),
            )
            assertTrue(
                "Cancelled authentication must leave the password field empty",
                password!!.text.isNullOrEmpty(),
            )
            stage("fields-empty")
        } finally {
            // Any Autofill auth Activity is dismissed before the vault fixture
            // it may still be reading is deleted.
            runCatching { dismissAuthActivities(device) }
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
            runCatching { fixture.cleanup() }
        }
    }

    @Test
    fun realOsApproveReturnsDatasetAndFillsExactlyBothBoundFields() {
        stage("preconditions")
        val context = instrumentation.targetContext
        val manager = context.getSystemService(AutofillManager::class.java)
        assertNotNull("AutofillManager unavailable", manager)
        assertTrue("Autofill is not supported", manager.isAutofillSupported)

        stage("fixture-create")
        val fixture = SyntheticVaultFixture(context.cacheDir)
        fixture.create(instrumentation.targetContext.noBackupFilesDir)
        val device = UiDevice.getInstance(instrumentation)
        val presentationText = context.getString(R.string.autofill_auth_presentation)
        val datasetText = context.getString(R.string.autofill_dataset_presentation)
        try {
            stage("target-launch")
            launchTarget()
            assertNotNull(
                "The synthetic target username field was not visible",
                device.wait(Until.findObject(By.desc(AutofillSmokeTargetActivity.SMOKE_USERNAME)), 10_000),
            )
            stage("fill-request")
            assertTrue("The OS did not show the authentication presentation", openChallenge(device, presentationText))
            stage("presentation-visible")
            stage("presentation-clicked")

            assertNotNull(
                "The explicit Autofill auth Activity did not resume",
                waitForAuthActivity(SystemClock.elapsedRealtime() + 15_000),
            )
            stage("auth-resumed")

            // Fresh full factors through the real Activity UI (UiAutomator only).
            assertTrue(
                "The master password field could not be filled",
                enter(device, "autofill-master-password", fixture.masterPassword),
            )
            assertTrue(
                "The Secret Key field could not be filled",
                enter(device, "autofill-secret-key", fixture.secretKey),
            )
            device.pressBack()
            device.waitForIdle()
            assertTrue("Unlock action unavailable", click(device, "解锁并选择登录", 20_000))
            assertTrue("The fresh unlock did not reach the approval page", waitForSelectPage(device))
            stage("unlocked")

            // One visible row, selected by its synthetic title only.
            assertTrue("The synthetic active login row was not listed", clickSyntheticRow(device, fixture.title))
            stage("row-selected")
            // No credential or factor may ever be presented by the approval UI.
            assertNoFixtureSecretInHierarchy(device)
            stage("no-ui-disclosure")
            assertTrue("The separate Approve action was unavailable", click(device, "批准所选登录", 20_000))
            stage("approved")

            // The returned authentication result must be a FillResponse with one
            // Dataset, which Android now offers; the user selects that Dataset.
            assertTrue(
                "The approved Dataset was not offered by the OS",
                device.wait(Until.findObject(By.text(datasetText)), 20_000) != null,
            )
            stage("dataset-visible")
            assertTrue("The approved Dataset could not be selected", click(device, datasetText, 20_000))
            stage("dataset-clicked")

            assertTrue(
                "The username field was not filled with the synthetic fixture value",
                waitUntil(SystemClock.elapsedRealtime() + 10_000) {
                    device.findObject(By.desc(AutofillSmokeTargetActivity.SMOKE_USERNAME))?.text == fixture.username
                },
            )
            val username = device.findObject(By.desc(AutofillSmokeTargetActivity.SMOKE_USERNAME))
            val password = device.findObject(By.desc(AutofillSmokeTargetActivity.SMOKE_PASSWORD))
            assertNotNull("Filled username field disappeared", username)
            assertNotNull("Filled password field disappeared", password)
            assertEquals("The username field does not hold the synthetic fixture value", fixture.username, username!!.text)
            assertEquals("The password field does not hold the synthetic fixture value", fixture.password, password!!.text)
            stage("fields-filled")
        } finally {
            // Any Autofill auth Activity is dismissed before the vault fixture
            // it may still be reading is deleted.
            runCatching { dismissAuthActivities(device) }
            runCatching {
                repeat(3) {
                    if (device.hasObject(By.desc(AutofillSmokeTargetActivity.SMOKE_USERNAME)) ||
                        device.hasObject(By.text(datasetText)) ||
                        device.hasObject(By.text(presentationText))
                    ) {
                        device.pressBack()
                        device.waitForIdle()
                    }
                }
            }
            runCatching { fixture.cleanup() }
        }
    }

    /**
     * Fails the test (without printing any value) if any fixture text appears
     * in the visible hierarchy. This is the in-test counterpart to the gate's
     * private log/canary scan.
     */
    private fun assertNoFixtureSecretInHierarchy(device: UiDevice) {
        val stream = java.io.ByteArrayOutputStream()
        device.dumpWindowHierarchy(stream)
        val dump = stream.toString(Charsets.UTF_8.name())
        for (value in SyntheticVaultFixture.SECRET_VALUES) {
            assertTrue("An autofill canary value was visible in a UI node", !dump.contains(value))
        }
    }

    /**
     * Test-only synthetic vault created through the real mobilecore APIs under
     * the app's own private target storage. Every factor and credential is
     * recorded privately so the runtime gate's log scan can reject disclosure.
     * The file is always removed and the native vault is always locked/closed.
     */
    private class SyntheticVaultFixture(canaryDir: File) {
        private val canaries = File(canaryDir, "instrumentation-canaries.json")
        private val random = ByteArray(16).also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
        val masterPassword = secret("Autofill-Master-$random")
        val secretKey: String
        val title = record(TITLE_PREFIX + random)
        val username = secret("Autofill-User-$random")
        val password = secret("Autofill-Pass-$random")
        private val url = record("https://autofill-$random.locklark.test/login")
        private var database: File? = null

        init {
            // The Secret Key text is generated by the real native core and only
            // exists transiently in the test process until it is entered.
            val key = Mobilecore.generateSecretKey()
            try {
                secretKey = secret(Mobilecore.formatSecretKey(key))
            } finally {
                key.fill(0)
            }
        }

        fun create(noBackupDir: File) {
            val path = File(noBackupDir, "personal.ll")
            database = path
            if (path.exists()) path.delete()
            val base = Mobilecore.open(path.absolutePath)
            var passwordBytes = ByteArray(0)
            var keyBytes = ByteArray(0)
            var userBytes = ByteArray(0)
            var valueBytes = ByteArray(0)
            try {
                val captured = arrayOfNulls<mobilecore.Vault>(1)
                instrumentation().runOnMainSync { captured[0] = base.captureOperation() }
                val operation = captured[0] ?: throw AssertionError("Native operation capture failed")
                passwordBytes = masterPassword.toByteArray()
                keyBytes = Mobilecore.parseSecretKey(secretKey)
                userBytes = username.toByteArray()
                valueBytes = password.toByteArray()
                operation.create(passwordBytes.copyOf(), keyBytes.copyOf())
                operation.unlock(passwordBytes.copyOf(), keyBytes.copyOf())
                operation.createLogin(title, url, userBytes.copyOf(), valueBytes.copyOf())
            } finally {
                passwordBytes.fill(0)
                keyBytes.fill(0)
                userBytes.fill(0)
                valueBytes.fill(0)
                runCatching { base.requestLock() }
                runCatching { base.close() }
            }
        }

        fun cleanup() {
            runCatching { database?.delete() }
            database = null
        }

        /** A factor or filled value: canary-recorded and never UI-visible. */
        private fun secret(value: String): String {
            SECRET_VALUES.add(value)
            return record(value)
        }

        private fun record(value: String): String {
            val existing = if (canaries.exists()) JSONArray(canaries.readText()) else JSONArray()
            existing.put(value)
            canaries.writeText(existing.toString())
            PRIVATE_VALUES.add(value)
            return value
        }

        private fun instrumentation() = InstrumentationRegistry.getInstrumentation()

        companion object {
            /** Fixed, non-secret row-title prefix shared with the outer test. */
            const val TITLE_PREFIX = "Autofill-Synthetic-"

            /** In-process mirror of every recorded canary (factors, values, metadata). */
            val PRIVATE_VALUES: MutableList<String> = mutableListOf()

            /** Factors and credential values only; these may never appear in the approval UI. */
            val SECRET_VALUES: MutableList<String> = mutableListOf()
        }
    }
}
