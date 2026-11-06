package org.locklark.android

import android.app.KeyguardManager
import android.content.pm.ApplicationInfo
import android.graphics.Rect
import android.os.SystemClock
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.CheckBox
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.junit.Assert.assertTrue
import org.junit.Test
import org.locklark.android.security.NativeFailureCode
import org.locklark.android.security.NativePhase
import org.junit.runner.RunWith
import java.io.File
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Only this separate test APK contains fixture material or observation code. */
@RunWith(AndroidJUnit4::class)
class OfflineVaultTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val canaries = mutableListOf<String>()
    private lateinit var scenario: ActivityScenario<MainActivity>
    private var currentControl = "unknown"
    private var controlPhase = "ready"
    private var imeHideRequested = false
    private fun stage(value: String) { instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_stage", value) }) }
    private fun record(value: String): String {
        val fixture = File(instrumentation.targetContext.cacheDir, "instrumentation-canaries.json")
        if (canaries.isEmpty() && fixture.exists()) {
            val existing = JSONArray(fixture.readText())
            for (index in 0 until existing.length()) canaries.add(existing.getString(index))
        }
        canaries.add(value)
        fixture.writeText(JSONArray(canaries).toString())
        return value
    }
    private fun all(view: View): List<View> = listOf(view) + if (view is ViewGroup) (0 until view.childCount).flatMap { all(view.getChildAt(it)) } else emptyList()
    private fun view(tag: String): View? {
        var found: View? = null
        scenario.onActivity { found = it.window.decorView.findViewWithTag<View>(tag) }
        return found
    }
    private fun text(tag: String): String {
        var value = ""
        scenario.onActivity { value = (it.window.decorView.findViewWithTag<View>(tag) as? TextView)?.text?.toString() ?: "" }
        return value
    }
    private fun windowHasFocus(): Boolean {
        var focused = false
        scenario.onActivity { focused = it.hasWindowFocus() }
        return focused
    }
    private fun ensureWindowFocus() {
        try {
            instrumentation.uiAutomation.executeShellCommand("wm dismiss-keyguard").close()
        } catch (_: Exception) {}
        try {
            instrumentation.uiAutomation.executeShellCommand("am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS").close()
        } catch (_: Exception) {}
        scenario.onActivity { activity -> activity.window.decorView.requestFocus() }
    }
    private fun waitFor(message: String, test: () -> Boolean) =
        waitUntil(message, SystemClock.elapsedRealtime() + 180_000, test)
    private fun waitUntil(message: String, deadline: Long, test: () -> Boolean) {
        val wait = when (message) {
            "Initial create unavailable" -> "initial-create"
            "Account key unavailable" -> "account-key"
            "New vault list unavailable" -> "new-vault-list"
            "Native control unavailable" -> "native-control"
            "Native control not visible" -> "native-visible"
            "Soft keyboard still visible" -> "ime-hidden"
            "Native input unavailable" -> "native-input"
            "Native input focus unavailable" -> "native-input-focus"
            "Native input delivery incomplete" -> "native-input-exact"
            "Login metadata unavailable" -> "login-metadata"
            "Detail unavailable" -> "detail"
            "Editor unavailable" -> "editor"
            "Saved list unavailable" -> "saved-list"
            "Explicit disclosure unavailable" -> "disclosure"
            "Successful empty username must be explicit" -> "empty-username"
            "Successful empty notes must be explicit" -> "empty-notes"
            "Unsupported device auth did not refuse" -> "platform-auth-refusal"
            "Background must lock" -> "background-lock"
            "Explicit lock failed" -> "explicit-lock"
            "Late unlock must not reopen backgrounded vault" -> "late-unlock"
            else -> "other"
        }
        instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_wait", wait) })
        while (SystemClock.elapsedRealtime() < deadline) {
            val satisfied = test()
            // A synchronous main-thread observation may finish after the
            // absolute deadline. Its late true result is not permission to act.
            val observedAt = SystemClock.elapsedRealtime()
            if (observedAt >= deadline) break
            if (satisfied) return
            SystemClock.sleep(minOf(100L, deadline - observedAt))
        }
        failWait(message)
    }
    private fun failWait(message: String): Nothing {
        val status = text("status")
        val phase = NativePhase.entries.firstOrNull { status.startsWith(it.userText + "未完成：") }?.name?.lowercase() ?: "unknown"
        val error = NativeFailureCode.entries.firstOrNull { status.endsWith(it.userText) }?.name?.lowercase() ?: "unknown"
        val uiStatus = when {
            phase != "unknown" && error != "unknown" -> "operation-refused"
            status.startsWith("结果未确认") -> "outcome-unknown"
            status.startsWith("请先确认备份") -> "backup-ack-required"
            status.isEmpty() -> "empty"
            else -> "other"
        }
        instrumentation.sendStatus(0, android.os.Bundle().apply {
            putString("locklark_ui_status", uiStatus)
            putString("locklark_core_phase", phase); putString("locklark_core_error", error)
        })
        reportControl()
        throw AssertionError(message)
    }
    private fun ready(tag: String): Boolean {
        val current = view(tag)
        return current?.isEnabled == true && current.isLaidOut && current.width > 0 && current.height > 0
    }
    private fun click(tag: String, dismissKeyboard: Boolean = true, deadline: Long = SystemClock.elapsedRealtime() + 180_000) {
        currentControl = tag
        controlPhase = "ready"
        imeHideRequested = false
        waitUntil("Native control unavailable", deadline) { ready(tag) }
        val bounds = Rect()
        val viewport = Rect()
        var previousBounds = Rect()
        var previousViewport = Rect()
        var previousVisible = false
        var scrolledViewport: Rect? = null
        var needsScroll = true
        // IME appearance and padding/layout can arrive after a prior idle
        // observation. React to actual visibility while waiting, not only once
        // at entry. Only the owned window receives one hide request; BACK could
        // navigate if the keyboard disappeared between observation and delivery.
        waitUntil("Native control not visible", deadline) {
            if (scenario.state == androidx.lifecycle.Lifecycle.State.RESUMED && !windowHasFocus()) ensureWindowFocus()
            var visible = false
            var ime: Boolean? = null
            var requestedNow = false
            var scrolledNow = false
            scenario.onActivity { activity ->
                if (SystemClock.elapsedRealtime() >= deadline) return@onActivity
                val target = activity.window.decorView.findViewWithTag<View>(tag)
                ime = activity.window.decorView.rootWindowInsets?.isVisible(WindowInsets.Type.ime())
                if (ime == null) {
                    needsScroll = true
                    return@onActivity
                }
                if (dismissKeyboard && ime == true) {
                    needsScroll = true
                    if (!imeHideRequested && activity.hasWindowFocus() && SystemClock.elapsedRealtime() < deadline) {
                        activity.window.insetsController?.let { controller ->
                            imeHideRequested = true
                            requestedNow = true
                            controller.hide(WindowInsets.Type.ime())
                        }
                    }
                } else if (target != null && target.isEnabled && target.isShown &&
                    (activity.hasWindowFocus() || scenario.state == androidx.lifecycle.Lifecycle.State.RESUMED) &&
                    appViewport(activity, viewport)) {
                    if ((needsScroll || scrolledViewport != viewport) && SystemClock.elapsedRealtime() < deadline) {
                        target.requestRectangleOnScreen(Rect(0,0,target.width,target.height), true)
                        scrolledViewport = Rect(viewport)
                        needsScroll = false
                        scrolledNow = true
                    } else {
                        visible = target.getGlobalVisibleRect(bounds) && bounds.width() == target.width &&
                            bounds.height() == target.height && viewport.contains(bounds)
                    }
                }
            }
            if (ime == null) {
                previousBounds.setEmpty(); previousViewport.setEmpty()
                previousVisible = false
                controlPhase = "ime-observe"
                return@waitUntil false
            }
            if (dismissKeyboard && ime == true) {
                previousBounds.setEmpty(); previousViewport.setEmpty()
                previousVisible = false
                controlPhase = if (requestedNow) "ime-dismiss" else "ime-wait-hidden"
                if (requestedNow) reportControl()
                return@waitUntil false
            }
            if (scrolledNow) {
                previousBounds.setEmpty(); previousViewport.setEmpty()
                previousVisible = false
                controlPhase = "scroll"
                return@waitUntil false
            }
            controlPhase = "visibility"
            val stable = visible && previousVisible && bounds == previousBounds && viewport == previousViewport
            previousBounds = Rect(bounds)
            previousViewport = Rect(viewport)
            previousVisible = visible
            stable
        }
        controlPhase = "press"
        reportControl()
        val now = SystemClock.uptimeMillis()
        MotionEvent.obtain(now,now,MotionEvent.ACTION_DOWN,bounds.exactCenterX(),bounds.exactCenterY(),0).also {
            try {
                if (SystemClock.elapsedRealtime() >= deadline) failWait("Native control not visible")
                instrumentation.sendPointerSync(it)
            } finally { it.recycle() }
        }
        // Once DOWN has started, always send its release even if time passes
        // during the physical press. No second business tap is attempted.
        SystemClock.sleep(50)
        MotionEvent.obtain(now,SystemClock.uptimeMillis(),MotionEvent.ACTION_UP,bounds.exactCenterX(),bounds.exactCenterY(),0).also {
            instrumentation.sendPointerSync(it); it.recycle()
        }
        controlPhase = "released"
        instrumentation.waitForIdleSync()
    }
    private fun appViewport(activity: MainActivity, viewport: Rect): Boolean {
        if (activity.window.decorView.rootWindowInsets == null) return false
        activity.window.decorView.getWindowVisibleDisplayFrame(viewport)
        val content = activity.findViewById<ViewGroup>(android.R.id.content)
        val root = content?.getChildAt(0) ?: return false
        val inner = Rect()
        if (!root.getGlobalVisibleRect(inner)) return false
        inner.set(inner.left + root.paddingLeft, inner.top + root.paddingTop,
            inner.right - root.paddingRight, inner.bottom - root.paddingBottom)
        return !inner.isEmpty && viewport.intersect(inner)
    }
    private fun reportControl() {
        val known = setOf("generate-account-key", "backup-ack", "create-vault", "new-login", "generate-password", "save-login", "show-password", "hide-secret", "edit-login", "save-field", "show-notes", "show-username", "show-otp", "back-to-list", "search", "cancel-edit", "regenerate-password", "confirm-regenerate", "enable-quick-unlock", "quick-unlock", "lock", "unlock",
            "new-master-password", "repeat-master-password", "login-title", "login-url", "login-username", "login-password", "edit-value", "query", "regenerate-length", "master-password", "secret-key")
        val tag = if (currentControl.startsWith("item-")) "login-row" else currentControl.takeIf { it in known } ?: "unknown"
        val diagnostic = android.os.Bundle().apply {
            putString("locklark_control", tag)
            putString("locklark_control_phase", controlPhase)
            putString("locklark_activity", scenario.state.name)
            putString("locklark_ime_hide_requested", imeHideRequested.toString())
        }
        scenario.onActivity { activity ->
            val target = activity.window.decorView.findViewWithTag<View>(currentControl)
            val bounds = Rect()
            val viewport = Rect()
            diagnostic.putString("locklark_ime", activity.window.decorView.rootWindowInsets?.isVisible(WindowInsets.Type.ime())?.toString() ?: "unknown")
            diagnostic.putString("locklark_window_focus", activity.hasWindowFocus().toString())
            diagnostic.putString("locklark_control_present", (target != null).toString())
            diagnostic.putString("locklark_control_enabled", (target?.isEnabled == true).toString())
            diagnostic.putString("locklark_control_visible", (target != null && appViewport(activity, viewport) && target.getGlobalVisibleRect(bounds) && bounds.width() == target.width && bounds.height() == target.height && viewport.contains(bounds)).toString())
            diagnostic.putString("locklark_control_focused", (target != null && activity.currentFocus === target && target.hasFocus()).toString())
            diagnostic.putString("locklark_input_active", (target is EditText && activity.getSystemService(InputMethodManager::class.java)?.isActive(target) == true).toString())
        }
        instrumentation.sendStatus(0, diagnostic)
    }
    private fun enter(tag: String, value: String) {
        val deadline = SystemClock.elapsedRealtime() + 180_000
        currentControl = tag
        controlPhase = "input-ready"
        waitUntil("Native input unavailable", deadline) { ready(tag) }
        // One real tap establishes native focus. Main-queue idleness alone does
        // not prove that the IME has switched its served InputConnection.
        click(tag, dismissKeyboard = false, deadline = deadline)
        controlPhase = "input-focus"
        fun focused(): Boolean {
            var focused = false
            scenario.onActivity { activity ->
                val target = activity.window.decorView.findViewWithTag<View>(tag)
                val resumed = scenario.state == androidx.lifecycle.Lifecycle.State.RESUMED
                // A headless CI window can transiently report no focus while
                // the resumed activity still owns the target editor.
                if (target is EditText && resumed && !activity.hasWindowFocus()) target.requestFocus()
                focused = target is EditText && target.isEnabled && target.isAttachedToWindow &&
                    (activity.hasWindowFocus() || resumed) &&
                    (activity.currentFocus === target || target.hasFocus())
            }
            return focused
        }
        waitUntil("Native input focus unavailable", deadline) {
            if (scenario.state == androidx.lifecycle.Lifecycle.State.RESUMED && !windowHasFocus()) ensureWindowFocus()
            focused()
        }
        scenario.onActivity { if (SystemClock.elapsedRealtime() < deadline) (it.window.decorView.findViewWithTag<View>(tag) as EditText).text.clear() }
        instrumentation.waitForIdleSync()
        waitUntil("Native input focus unavailable", deadline) {
            if (scenario.state == androidx.lifecycle.Lifecycle.State.RESUMED && !windowHasFocus()) ensureWindowFocus()
            focused()
        }
        controlPhase = "input-send"
        reportControl()
        if (SystemClock.elapsedRealtime() >= deadline) failWait("Native input delivery incomplete")
        // Full factors go through native keyboard events. Unicode note input
        // uses the native Editable in the test APK, never a product endpoint.
        if (value.isNotEmpty()) {
            if (value.all { it.code in 32..126 }) instrumentation.sendStringSync(value)
            else scenario.onActivity { if (SystemClock.elapsedRealtime() < deadline) (it.window.decorView.findViewWithTag<View>(tag) as EditText).setText(value) }
        }
        instrumentation.waitForIdleSync()
        controlPhase = "input-exact"
        waitUntil("Native input delivery incomplete", deadline) { text(tag) == value }
    }
    private fun select(title: String) {
        var tag = ""
        waitFor("Login metadata unavailable") {
            scenario.onActivity { activity ->
                tag = all(activity.window.decorView).firstOrNull { it.tag?.toString()?.startsWith("item-") == true && (it as? TextView)?.text?.toString() == "选择登录：$title" }?.tag?.toString() ?: ""
            }
            tag.isNotEmpty() && ready(tag)
        }
        click(tag); waitFor("Detail unavailable") { ready("show-password") }
    }
    private fun edit(field: Int, value: String) {
        click("edit-login"); waitFor("Editor unavailable") { ready("edit-value") }
        scenario.onActivity { (it.window.decorView.findViewWithTag<View>("edit-field") as Spinner).setSelection(field) }
        enter("edit-value",value); click("save-field"); waitFor("Saved list unavailable") { ready("new-login") }
    }
    private fun shown(tag: String): String {
        click(tag); waitFor("Explicit disclosure unavailable") { text("secret-value").isNotEmpty() }
        return text("secret-value")
    }

    private fun deviceAuthenticationUnavailable(): Boolean = text("status") ==
        NativePhase.DEVICE_READY.userText + "未完成：" + NativeFailureCode.UNAVAILABLE.userText

    private fun assertNoDeviceCapsule(root: File) {
        val files = if (root.exists()) root.listFiles() else emptyArray<File>()
        assertTrue("Device authorization state not inspectable", files != null)
        assertTrue("Refused device authentication persisted a capsule", files!!.none { it.name.contains(".capsule") })
    }
    private fun hmacCode(counter: Long): String {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec("12345678901234567890".toByteArray(),"HmacSHA1"))
        val bytes = mac.doFinal(java.nio.ByteBuffer.allocate(8).putLong(counter).array())
        val offset = bytes.last().toInt() and 15
        val number = java.nio.ByteBuffer.wrap(bytes,offset,4).int and 0x7fffffff
        return (number % 1_000_000).toString().padStart(6,'0')
    }

    @Test fun realOfflineVaultNativeFlowsAndBackgroundLock() {
        val random = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val master = record("Android-Master-$random")
        val password = record("Android-Password-$random")
        val changed = record("Android-Edited-$random")
        val username = record("Android-User-$random")
        val notes = record("合成原生备注🔐\n$random\n保留末行  \n")
        val seed = record("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            ensureWindowFocus()
            waitFor("Initial create unavailable") { ready("generate-account-key") }
            scenario.onActivity {
                assertTrue("Secure window required", it.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
                assertTrue("Backup must be disabled", it.applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP == 0)
            }
            stage("create"); click("generate-account-key")
            waitFor("Account key unavailable") { text("backup-secret-key").startsWith("LL") }
            val key = record(text("backup-secret-key"))
            enter("new-master-password",master); enter("repeat-master-password",master)
            click("backup-ack"); click("create-vault")
            waitFor("New vault list unavailable") { ready("new-login") }
            stage("add-login"); click("new-login")
            enter("login-title","Android first"); enter("login-url","https://android.locklark.test/login")
            enter("login-username",username); click("generate-password"); enter("login-password",password)
            click("save-login"); select("Android first")
            stage("show-password"); assertTrue("Exact password mismatch", shown("show-password") == password)
            click("hide-secret"); assertTrue("Explicit hide failed", text("secret-value").isEmpty())
            stage("edit-password"); edit(3,changed); select("Android first")
            assertTrue("Edited password mismatch", shown("show-password") == changed)
            stage("edit-notes"); edit(5,notes); select("Android first")
            assertTrue("Unicode notes mismatch", shown("show-notes") == notes)
            stage("empty-fields")
            edit(2,""); select("Android first"); click("show-username")
            waitFor("Successful empty username must be explicit") { text("status").startsWith("字段为空") }
            assertTrue("Empty username rendered data", text("secret-value").isEmpty())
            edit(2,username); select("Android first")
            edit(5,""); select("Android first"); click("show-notes")
            waitFor("Successful empty notes must be explicit") { text("status").startsWith("字段为空") }
            assertTrue("Empty notes rendered data", text("secret-value").isEmpty())
            edit(5,notes); select("Android first")
            stage("edit-otp"); edit(4,seed); select("Android first")
            // An explicit OTP click begins well inside one original period.
            while (System.currentTimeMillis()/1000%30 > 8) SystemClock.sleep(200)
            stage("show-otp"); val before = System.currentTimeMillis()/30_000
            val code = record(shown("show-otp"))
            val after = System.currentTimeMillis()/30_000
            assertTrue("Independent HMAC mismatch", (before..after).any { code == hmacCode(it) })
            stage("search"); click("back-to-list"); enter("query","Android first"); click("search"); select("Android first")
            stage("cancel-edit"); click("edit-login"); enter("edit-value","Uncommitted-$random"); click("cancel-edit")
            assertTrue("Cancel changed password", shown("show-password") == changed)
            stage("generate-login"); click("back-to-list"); click("new-login")
            enter("login-title","Android generated"); enter("login-username",username)
            click("save-login"); select("Android generated")
            val generated = record(shown("show-password"))
            assertTrue("Generated password shape", generated.matches(Regex("[A-Za-z0-9]{24}")))
            stage("regenerate"); click("regenerate-password"); enter("regenerate-length","22"); click("confirm-regenerate"); select("Android generated")
            val regenerated = record(shown("show-password"))
            assertTrue("Exact regeneration failed", regenerated.length == 22 && regenerated != generated)
            click("back-to-list"); select("Android first")
            stage("exact-target"); assertTrue("Regeneration changed wrong target", shown("show-password") == changed)
            click("back-to-list")
            val context = instrumentation.targetContext
            val noDeviceCredential = !context.getSystemService(KeyguardManager::class.java).isDeviceSecure
            if (noDeviceCredential) {
                stage("platform-auth-refusal"); click("enable-quick-unlock")
                waitFor("Unsupported device auth did not refuse") { deviceAuthenticationUnavailable() && ready("new-login") }
                assertNoDeviceCapsule(File(context.noBackupFilesDir,"device-unlock"))
            }
            stage("background-lock"); select("Android first"); shown("show-password")
            instrumentation.uiAutomation.executeShellCommand("input keyevent KEYCODE_HOME").close()
            SystemClock.sleep(500)
            scenario.close()
            scenario = ActivityScenario.launch(MainActivity::class.java)
            ensureWindowFocus()
            waitFor("Background must lock", { ready("unlock") })
            assertTrue("Background retained secret", text("secret-value").isEmpty())
            if (noDeviceCredential) {
                // No factors are supplied for this distinct negative action.
                // A refusal must leave the full-factor form locked and usable.
                stage("platform-auth-refusal")
                assertTrue("Locked factors unexpectedly prefilled", text("master-password").isEmpty() && text("secret-key").isEmpty())
                click("quick-unlock")
                waitFor("Unsupported device auth did not refuse") {
                    deviceAuthenticationUnavailable() && ready("master-password") && ready("secret-key") && ready("unlock")
                }
                assertTrue("Unsupported device auth reopened the vault", view("new-login") == null && text("secret-value").isEmpty())
                assertNoDeviceCapsule(File(context.noBackupFilesDir,"device-unlock"))
            }
            enter("master-password",master); enter("secret-key",key); click("unlock"); select("Android first")
            stage("reopen"); assertTrue("Disk reopen changed secret", shown("show-password") == changed)
            click("lock"); waitFor("Explicit lock failed") { ready("unlock") }
            assertTrue("Lock retained disclosure", text("secret-value").isEmpty())
            stage("late-unlock"); enter("master-password",master); enter("secret-key",key); click("unlock")
            instrumentation.uiAutomation.executeShellCommand("input keyevent KEYCODE_HOME").close()
            scenario.close()
            scenario = ActivityScenario.launch(MainActivity::class.java)
            ensureWindowFocus()
            waitFor("Late unlock must not reopen backgrounded vault") { ready("unlock") }
            assertTrue("Late callback exposed a secret", text("secret-value").isEmpty())
        } finally { scenario.close() }
    }
}
