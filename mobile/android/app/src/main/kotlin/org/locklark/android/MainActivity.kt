package org.locklark.android

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.view.WindowInsets
import android.view.inputmethod.EditorInfo
import android.widget.*
import mobilecore.Mobilecore
import mobilecore.Row
import mobilecore.SecretValue
import mobilecore.SystemUnlockStore
import mobilecore.Vault
import org.locklark.android.security.ForegroundGate
import org.locklark.android.security.SecretDeadline
import org.locklark.android.security.Target
import org.locklark.android.security.WorkStamp
import java.io.File
import java.util.concurrent.Executors

/** Native widgets only. No inbound data, web content, or secret-bearing IPC. */
class MainActivity : Activity() {
    private val gate = ForegroundGate()
    private val worker = Executors.newSingleThreadExecutor()
    companion object { private val cleanup = Executors.newSingleThreadExecutor() }
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var vault: Vault? = null
    private var opening = false
    private var busy = false
    private var unlockedUi = false
    private var generatedKey: ByteArray? = null
    private var currentRow: Row? = null
    private var activePrompt: NativeCryptoPrompt? = null
    private var secretView: TextView? = null
    private var secretDeadline: SecretDeadline? = null
    private lateinit var body: LinearLayout
    private lateinit var status: TextView
    private val inputs = mutableListOf<EditText>()
    private val buttons = mutableListOf<Button>()
    private val database by lazy { File(noBackupFilesDir, "personal.ll") }
    private val securityEvents = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) { lockNow() }
    }
    private val tick = object : Runnable {
        override fun run() {
            if (secretDeadline?.validAt(SystemClock.elapsedRealtime()) == false) clearDisplay()
            if (unlockedUi && vault?.isUnlocked() != true) lockNow()
            main.postDelayed(this, 100)
        }
    }

    override fun onCreate(state: Bundle?) {
        super.onCreate(null)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        // Intents/extras and saved instance state are never unlock sources.
        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF).apply {
            addAction(Intent.ACTION_TIME_CHANGED); addAction(Intent.ACTION_TIMEZONE_CHANGED)
        }
        if (android.os.Build.VERSION.SDK_INT >= 33) registerReceiver(securityEvents, filter, Context.RECEIVER_NOT_EXPORTED)
        else registerReceiver(securityEvents, filter)
        page("Locklark")
        label("正在打开此设备的本地金库…")
    }
    override fun onStart() {
        super.onStart()
        gate.start()
        main.post(tick)
        if (vault == null) {
            opening = true
            work(task = { Mobilecore.open(database.absolutePath) }, drop = { it.close() }, dropOnWorker = true) {
                opening = false; vault = it; lockedPage()
            }
        } else if (vault != null) lockedPage()
    }
    override fun onStop() {
        gate.stop()
        vault?.requestLock()
        activePrompt?.cancel()
        clearInputs(); generatedKey?.fill(0); generatedKey = null
        clearDisplay(); currentRow = null; unlockedUi = false; busy = false
        page("Locklark 已锁定")
        worker.execute { vault?.lock() }
        main.removeCallbacks(tick)
        super.onStop()
    }
    override fun onDestroy() {
        unregisterReceiver(securityEvents)
        vault?.requestLock()
        val previous = vault
        worker.execute { previous?.close() }
        worker.shutdown()
        super.onDestroy()
    }
    override fun onSaveInstanceState(outState: Bundle) { /* Never persist native input or disclosure. */ }

    private fun clearInputs() { inputs.forEach { it.text?.clear() } }
    private fun clearDisplay() { secretView?.text = ""; secretDeadline = null }
    private fun page(title: String) {
        clearInputs(); clearDisplay(); secretView = null; inputs.clear(); buttons.clear()
        val scroll = ScrollView(this).apply {
            isSaveEnabled = false
            setOnApplyWindowInsetsListener { view, insets ->
                val safe = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                view.setPadding(safe.left, safe.top, safe.right, safe.bottom)
                insets
            }
        }
        body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(24, 24, 24, 32)
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
            isSaveEnabled = false
        }
        scroll.addView(body); setContentView(scroll)
        label(title).textSize = 24f
        status = label("").apply { tag = "status" }
        if (unlockedUi) button("立即锁定", "lock") { lockNow() }
    }
    private fun label(value: String) = TextView(this).also { it.text = value; it.isSaveEnabled = false; body.addView(it) }
    private fun input(hint: String, tag: String, secret: Boolean = false, multiline: Boolean = false): EditText =
        EditText(this).also {
            it.hint = hint; it.contentDescription = hint; it.tag = tag; it.isSaveEnabled = false
            it.inputType = if (multiline) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
                else InputType.TYPE_CLASS_TEXT or if (secret) InputType.TYPE_TEXT_VARIATION_PASSWORD else InputType.TYPE_TEXT_VARIATION_NORMAL
            it.imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_ACTION_DONE
            if (multiline) it.minLines = 4
            it.filterTouchesWhenObscured = true
            inputs.add(it); body.addView(it)
        }
    private fun button(title: String, tag: String, action: () -> Unit): Button = Button(this).also {
        it.text = title; it.tag = tag; it.contentDescription = title; it.isSaveEnabled = false
        it.filterTouchesWhenObscured = true
        it.setOnClickListener { if (!busy || tag == "lock") action() }
        buttons.add(it); body.addView(it)
    }
    private fun setBusy(value: Boolean) {
        busy = value
        buttons.forEach { it.isEnabled = !value || it.tag == "lock" }
        inputs.forEach { it.isEnabled = !value }
    }
    private fun message(unknown: Boolean = false) {
        status.text = if (unknown) "结果未确认，请重新打开金库核实，勿重复提交。"
            else "操作未完成：认证被取消、金库已锁定或目标已变化。"
    }
    private fun <T> work(target: Target? = null, task: (WorkStamp) -> T, drop: (T) -> Unit = {}, dropOnWorker: Boolean = false, done: (T) -> Unit) {
        if (busy) return
        val stamp = gate.begin(target)
        setBusy(true)
        worker.execute {
            try {
                val value = task(stamp)
                main.post {
                    if (gate.accepts(stamp, target)) { setBusy(false); done(value) }
                    else { if (dropOnWorker) cleanup.execute { drop(value) } else drop(value); if (vault == null) opening = false }
                }
            } catch (error: Exception) {
                val unknown = error.message?.contains("unknown", ignoreCase = true) == true
                main.post { if (gate.accepts(stamp, target)) { setBusy(false); opening = false; message(unknown) } }
            }
        }
    }
    private fun lockNow() {
        gate.invalidate(); vault?.requestLock(); activePrompt?.cancel()
        clearInputs(); generatedKey?.fill(0); generatedKey = null
        clearDisplay(); currentRow = null; unlockedUi = false; busy = false
        worker.execute { vault?.lock() }
        lockedPage()
    }

    private fun lockedPage() {
        unlockedUi = false; currentRow = null; page("Locklark · 本机离线金库")
        if (!database.exists()) {
            label("此设备尚无金库。先生成并离线保存新的 Secret Key；它不是设备快速解锁密钥。")
            button("生成新的 Secret Key", "generate-account-key") {
                work(task = { Mobilecore.generateSecretKey() }, drop = { it.fill(0) }) { value ->
                    generatedKey?.fill(0); generatedKey = value; createPage(value)
                }
            }
            return
        }
        val password = input("主密码", "master-password", true)
        val key = input("Secret Key", "secret-key", true)
        button("打开本地金库", "unlock") {
            val pw = password.text.toString().toByteArray()
            val encodedKey = key.text.toString()
            clearInputs()
            work(task = {
                var decoded = ByteArray(0)
                try { decoded = Mobilecore.parseSecretKey(encodedKey); vault!!.unlock(pw, decoded) }
                finally { pw.fill(0); decoded.fill(0) }
            }) { showList() }
        }
        button("使用此设备认证解锁", "quick-unlock") {
            work(task = { stamp -> vault!!.unlockWithSystem(store(stamp)) }) { showList() }
        }
    }
    private fun createPage(key: ByteArray) {
        page("创建本机金库")
        label("请在应用外安全备份这份 Secret Key。丢失两项完整因素后不能依靠设备快速解锁恢复。")
        label(Mobilecore.formatSecretKey(key)).tag = "backup-secret-key"
        val acknowledgement = CheckBox(this).apply { text = "我已离线保存 Secret Key"; tag = "backup-ack"; isSaveEnabled = false }
        body.addView(acknowledgement)
        val password = input("新的主密码", "new-master-password", true)
        val repeat = input("再次输入主密码", "repeat-master-password", true)
        button("创建并解锁", "create-vault") {
            if (!acknowledgement.isChecked || password.text.toString() != repeat.text.toString()) {
                status.text = "请先确认备份，且两次主密码一致。"; return@button
            }
            val pw = password.text.toString().toByteArray()
            val accountKey = key.copyOf()
            clearInputs(); generatedKey?.fill(0); generatedKey = null
            // Remove the displayed account key before any asynchronous work.
            body.findViewWithTag<TextView>("backup-secret-key")?.text = ""
            work(task = {
                val createPassword = pw.copyOf(); val createKey = accountKey.copyOf()
                try { vault!!.create(createPassword, createKey); vault!!.unlock(pw, accountKey) }
                finally { createPassword.fill(0); createKey.fill(0); pw.fill(0); accountKey.fill(0) }
            }) { showList() }
        }
        button("取消创建", "cancel-create") { gate.invalidate(); generatedKey?.fill(0); generatedKey = null; lockedPage() }
    }

    private fun showList(query: String? = null) {
        unlockedUi = true; currentRow = null; page("Locklark · 登录")
        val search = input("搜索标题", "query")
        if (query != null) search.setText(query)
        button("搜索", "search") { val text = search.text.toString(); gate.invalidate(); showList(text) }
        button("新建登录", "new-login") { gate.invalidate(); newLoginPage() }
        button("启用此设备认证", "enable-quick-unlock") {
            work(task = { stamp -> vault!!.enableSystemUnlock(store(stamp)) }) { status.text = "已启用；本次完整双因素解锁后的 24 小时内可用。" }
        }
        button("停用此设备认证", "disable-quick-unlock") {
            work(task = { stamp -> vault!!.disableSystemUnlock(store(stamp)) }) { status.text = "本设备授权已删除。" }
        }
        work(task = { if (query == null) vault!!.list("active") else vault!!.search(query, "active") }) { rows ->
            for (i in 0 until rows.count()) {
                val row = rows.at(i)
                label("ID: " + row.getID())
                button("选择登录：" + visibleTitle(row.getTitle()), "item-" + row.getID()) {
                    gate.invalidate(); detailPage(row)
                }
            }
            status.text = "活动登录：" + rows.count()
        }
    }
    private fun detailPage(row: Row) {
        currentRow = row; page("登录：" + visibleTitle(row.getTitle()))
        label("ID: " + row.getID()); label("修订: " + row.getRevision())
        button("显示用户名", "show-username") { reveal(row, "username") }
        button("显示密码", "show-password") { reveal(row, "password") }
        button("显示备注", "show-notes") { reveal(row, "notes") }
        button("显示验证码", "show-otp") { reveal(row, "otp") }
        button("隐藏已显示字段", "hide-secret") { clearDisplay() }
        button("编辑登录字段", "edit-login") { gate.invalidate(); editPage(row) }
        button("重新生成本地密码", "regenerate-password") { gate.invalidate(); regeneratePage(row) }
        button("返回列表", "back-to-list") { gate.invalidate(); showList() }
        secretView = label("").apply { tag = "secret-value" }
    }
    private class Delivery(val value: ByteArray, val from: Long, val until: Long) { override fun toString() = "[native secret delivery]" }
    private fun reveal(row: Row, field: String) {
        clearDisplay()
        // Recreate the output widget after clearing its previous reference.
        if (secretView == null) secretView = label("").apply { tag = "secret-value" }
        val target = Target(row.getID(), row.getRevision(), field)
        work(target, task = { stamp ->
            var secret: SecretValue? = null
            try {
                secret = if (field == "otp") vault!!.revealOTP(target.id, target.revision) else vault!!.revealField(target.id, target.revision, field)
                if (!gate.accepts(stamp, target)) throw PlatformAuthenticationFailure()
                val bytes = secret.take()
                Delivery(bytes, secret.fromUnixMilli(), secret.untilUnixMilli())
            } finally { secret?.clear() }
        }, drop = { it.value.fill(0) }) { delivery ->
            try {
                val selected = currentRow
                val deadline = SecretDeadline.create(delivery.from, delivery.until, System.currentTimeMillis(), SystemClock.elapsedRealtime())
                if (vault!!.isUnlocked() && selected != null && selected.getID() == target.id && selected.getRevision() == target.revision && deadline != null) {
                    secretDeadline = deadline; secretView?.text = String(delivery.value, Charsets.UTF_8)
                    status.text = "已明确授权显示；到期自动隐藏。"
                } else clearDisplay()
            } finally { delivery.value.fill(0) }
        }
    }
    private fun newLoginPage() {
        page("新建登录")
        val title = input("登录标题", "login-title")
        val url = input("网站 HTTPS URL（可选）", "login-url")
        val username = input("用户名", "login-username", true)
        val password = input("登录密码", "login-password", true)
        val length = input("生成密码长度（22–256）", "password-length").apply { setText("24"); inputType = InputType.TYPE_CLASS_NUMBER }
        val generate = CheckBox(this).apply { text = "生成强密码"; tag = "generate-password"; isChecked = true; isSaveEnabled = false }
        body.addView(generate)
        button("保存登录", "save-login") {
            val metadataTitle = title.text.toString(); val metadataUrl = url.text.toString()
            val user = username.text.toString().toByteArray(); val pass = password.text.toString().toByteArray()
            val size = length.text.toString().toLongOrNull() ?: 0; val generated = generate.isChecked
            clearInputs()
            work(task = {
                try { if (generated) vault!!.generateLogin(metadataTitle, metadataUrl, user, size) else vault!!.createLogin(metadataTitle, metadataUrl, user, pass) }
                finally { user.fill(0); pass.fill(0) }
            }) { showList() }
        }
        button("取消新建", "cancel-new-login") { gate.invalidate(); showList() }
    }
    private fun editPage(row: Row) {
        page("编辑登录字段")
        label("ID: " + row.getID()); label("修订: " + row.getRevision())
        label("新值从空白开始。显示旧值是独立授权；取消不会写入。")
        val fields = arrayOf("title", "url", "username", "password", "otp", "notes")
        val field = Spinner(this).apply { tag = "edit-field"; adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, fields) }
        body.addView(field)
        val value = input("新值（原生可见多行正文）", "edit-value", multiline = true)
        button("保存字段", "save-field") {
            val selectedField = fields[field.selectedItemPosition]
            val bytes = value.text.toString().toByteArray(); clearInputs()
            val target = Target(row.getID(), row.getRevision(), selectedField)
            work(target, task = { try { vault!!.editField(target.id, target.revision, target.field, bytes) } finally { bytes.fill(0) } }) { showList() }
        }
        button("取消编辑", "cancel-edit") { gate.invalidate(); detailPage(row) }
    }
    private fun regeneratePage(row: Row) {
        page("确认重新生成本地密码")
        label("只替换此金库中的本地密码，不会替您更改网站密码。")
        label("ID: " + row.getID()); label("修订: " + row.getRevision())
        val length = input("密码长度（22–256）", "regenerate-length").apply { setText("24"); inputType = InputType.TYPE_CLASS_NUMBER }
        button("确认生成并替换", "confirm-regenerate") {
            val size = length.text.toString().toLongOrNull() ?: 0
            val target = Target(row.getID(), row.getRevision(), "password")
            work(target, task = { vault!!.regeneratePassword(target.id, target.revision, size) }) { showList() }
        }
        button("取消重新生成", "cancel-regenerate") { gate.invalidate(); detailPage(row) }
    }
    private fun store(stamp: WorkStamp): SystemUnlockStore {
        val current = { gate.accepts(stamp) }
        val prompt = NativeCryptoPrompt(this, current).also { activePrompt = it }
        val native = PlatformCapsuleStore(this, prompt, current)
        return object : SystemUnlockStore {
            override fun store(id: String, value: ByteArray) = native.store(id, value)
            override fun load(id: String): ByteArray = native.load(id)
            override fun delete(id: String) = native.delete(id)
        }
    }
    private fun visibleTitle(value: String): String = buildString {
        value.codePoints().limit(120).forEach { cp ->
            if (Character.isISOControl(cp) || Character.getType(cp) == Character.FORMAT.toInt()) append("\\u{%X}".format(cp))
            else appendCodePoint(cp)
        }
    }.ifEmpty { "（空标题）" }
}
