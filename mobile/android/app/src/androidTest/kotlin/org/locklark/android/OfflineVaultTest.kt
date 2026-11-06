package org.locklark.android

import android.app.KeyguardManager
import android.content.pm.ApplicationInfo
import android.graphics.Rect
import android.os.SystemClock
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
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
    private fun record(value: String): String {
        canaries.add(value)
        File(instrumentation.targetContext.cacheDir, "instrumentation-canaries.json").writeText(JSONArray(canaries).toString())
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
    private fun waitFor(message: String, test: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 180_000
        while (SystemClock.elapsedRealtime() < deadline) {
            if (test()) return
            SystemClock.sleep(100)
        }
        assertTrue(message, false)
    }
    private fun ready(tag: String) = view(tag)?.isEnabled == true
    private fun click(tag: String) {
        waitFor("Native control unavailable", { ready(tag) })
        scenario.onActivity { activity ->
            val target = activity.window.decorView.findViewWithTag<View>(tag)
            target.requestRectangleOnScreen(Rect(0,0,target.width,target.height), true)
        }
        instrumentation.waitForIdleSync()
        val bounds = Rect()
        scenario.onActivity { activity ->
            assertTrue("Native control not visible", activity.window.decorView.findViewWithTag<View>(tag).getGlobalVisibleRect(bounds))
        }
        val now = SystemClock.uptimeMillis()
        instrumentation.sendPointerSync(MotionEvent.obtain(now,now,MotionEvent.ACTION_DOWN,bounds.exactCenterX(),bounds.exactCenterY(),0))
        SystemClock.sleep(50)
        instrumentation.sendPointerSync(MotionEvent.obtain(now,SystemClock.uptimeMillis(),MotionEvent.ACTION_UP,bounds.exactCenterX(),bounds.exactCenterY(),0))
        instrumentation.waitForIdleSync()
    }
    private fun enter(tag: String, value: String) {
        waitFor("Native input unavailable", { ready(tag) })
        scenario.onActivity { (it.window.decorView.findViewWithTag<View>(tag) as EditText).apply { requestFocus(); text.clear() } }
        // Full factors go through native keyboard events. Unicode note input
        // uses the native Editable in the test APK, never a product endpoint.
        if (value.all { it.code in 32..126 }) instrumentation.sendStringSync(value)
        else scenario.onActivity { (it.window.decorView.findViewWithTag<View>(tag) as EditText).setText(value) }
        instrumentation.waitForIdleSync()
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
            waitFor("Initial create unavailable") { ready("generate-account-key") }
            scenario.onActivity {
                assertTrue("Secure window required", it.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
                assertTrue("Backup must be disabled", it.applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP == 0)
            }
            click("generate-account-key")
            waitFor("Account key unavailable") { text("backup-secret-key").startsWith("LL") }
            val key = record(text("backup-secret-key"))
            enter("new-master-password",master); enter("repeat-master-password",master)
            click("backup-ack"); click("create-vault")
            waitFor("New vault list unavailable") { ready("new-login") }
            click("new-login")
            enter("login-title","Android first"); enter("login-url","https://android.locklark.test/login")
            enter("login-username",username); enter("login-password",password)
            click("generate-password"); click("save-login"); select("Android first")
            assertTrue("Exact password mismatch", shown("show-password") == password)
            click("hide-secret"); assertTrue("Explicit hide failed", text("secret-value").isEmpty())
            edit(3,changed); select("Android first")
            assertTrue("Edited password mismatch", shown("show-password") == changed)
            edit(5,notes); select("Android first")
            assertTrue("Unicode notes mismatch", shown("show-notes") == notes)
            edit(4,seed); select("Android first")
            // An explicit OTP click begins well inside one original period.
            while (System.currentTimeMillis()/1000%30 > 8) SystemClock.sleep(200)
            val before = System.currentTimeMillis()/30_000
            val code = record(shown("show-otp"))
            val after = System.currentTimeMillis()/30_000
            assertTrue("Independent HMAC mismatch", (before..after).any { code == hmacCode(it) })
            click("back-to-list"); enter("query","Android first"); click("search"); select("Android first")
            click("edit-login"); enter("edit-value","Uncommitted-$random"); click("cancel-edit")
            assertTrue("Cancel changed password", shown("show-password") == changed)
            click("back-to-list"); click("new-login")
            enter("login-title","Android generated"); enter("login-username",username)
            click("save-login"); select("Android generated")
            val generated = record(shown("show-password"))
            assertTrue("Generated password shape", generated.matches(Regex("[A-Za-z0-9]{24}")))
            click("regenerate-password"); enter("regenerate-length","22"); click("confirm-regenerate"); select("Android generated")
            val regenerated = record(shown("show-password"))
            assertTrue("Exact regeneration failed", regenerated.length == 22 && regenerated != generated)
            click("back-to-list"); select("Android first")
            assertTrue("Regeneration changed wrong target", shown("show-password") == changed)
            click("back-to-list")
            val context = instrumentation.targetContext
            if (!context.getSystemService(KeyguardManager::class.java).isDeviceSecure) {
                click("enable-quick-unlock")
                waitFor("Unsupported device auth did not refuse") { text("status").startsWith("操作未完成") }
                assertTrue("No plaintext fallback capsule", File(context.noBackupFilesDir,"device-unlock").listFiles()?.none { it.name.endsWith(".capsule") } != false)
            }
            select("Android first"); shown("show-password")
            instrumentation.uiAutomation.executeShellCommand("input keyevent KEYCODE_HOME").close()
            SystemClock.sleep(500)
            scenario.close()
            scenario = ActivityScenario.launch(MainActivity::class.java)
            waitFor("Background must lock", { ready("unlock") })
            assertTrue("Background retained secret", text("secret-value").isEmpty())
            enter("master-password",master); enter("secret-key",key); click("unlock"); select("Android first")
            assertTrue("Disk reopen changed secret", shown("show-password") == changed)
            click("lock"); waitFor("Explicit lock failed") { ready("unlock") }
            assertTrue("Lock retained disclosure", text("secret-value").isEmpty())
            enter("master-password",master); enter("secret-key",key); click("unlock")
            instrumentation.uiAutomation.executeShellCommand("input keyevent KEYCODE_HOME").close()
            scenario.close()
            scenario = ActivityScenario.launch(MainActivity::class.java)
            waitFor("Late unlock must not reopen backgrounded vault") { ready("unlock") }
            assertTrue("Late callback exposed a secret", text("secret-value").isEmpty())
        } finally { scenario.close() }
    }
}
