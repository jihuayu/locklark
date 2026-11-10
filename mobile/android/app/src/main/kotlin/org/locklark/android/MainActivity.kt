package org.locklark.android

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.StateListDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.*
import mobilecore.Mobilecore
import mobilecore.Row
import mobilecore.SecretValue
import mobilecore.SystemUnlockStore
import mobilecore.Vault
import org.locklark.android.security.CancellationSlot
import org.locklark.android.security.ForegroundGate
import org.locklark.android.security.GuardedWork
import org.locklark.android.security.NativeCallFailure
import org.locklark.android.security.NativeFailureCode
import org.locklark.android.security.NativeFailures
import org.locklark.android.security.NativePhase
import org.locklark.android.security.ReturnedSecretBuffers
import org.locklark.android.security.SecretDeadline
import org.locklark.android.security.Target
import org.locklark.android.security.WorkStamp
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Native widgets only. No inbound data, web content, or secret-bearing IPC. */
class MainActivity : Activity() {
    private val gate = ForegroundGate()
    private val worker = Executors.newSingleThreadExecutor()
    companion object {
        private val cleanup = Executors.newSingleThreadExecutor()
        private val authAttempts = AtomicLong()
        private val PRIMARY_TAGS = setOf(
            "unlock", "create-vault", "generate-account-key",
            "new-login", "save-login", "save-field", "confirm-regenerate"
        )
        private val DANGER_TAGS = setOf("lock", "disable-quick-unlock", "hide-secret")
    }
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var vault: Vault? = null
    private var opening = false
    private var cleanupPending = false
    private var cleanupSerial = 0L
    private var destroyed = false
    private var busy = false
    private var unlockedUi = false
    private var generatedKey: ByteArray? = null
    private var currentRow: Row? = null
    private val promptSlot = CancellationSlot<NativeCryptoPrompt> { it.cancel() }
    private var secretView: TextView? = null
    private var backupKeyView: TextView? = null
    private var secretDeadline: SecretDeadline? = null
    private lateinit var body: LinearLayout
    private var activeContainer: LinearLayout? = null
    private lateinit var status: TextView
    private val inputs = mutableListOf<EditText>()
    private val buttons = mutableListOf<Button>()
    private val database by lazy { File(noBackupFilesDir, "personal.ll") }
    private val securityEvents = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) { lockNow() }
    }
    private val tick = object : Runnable {
        override fun run() {
            if (secretDeadline?.validAt(SystemClock.elapsedRealtime(), System.currentTimeMillis()) == false) clearDisplay()
            if (unlockedUi && vault?.isUnlocked() != true) lockNow()
            main.postDelayed(this, 100)
        }
    }

    private fun dp(value: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()

    private fun roundedBox(fillColor: Int, strokeColor: Int = Color.TRANSPARENT, radiusDp: Int = 10, strokeWidthDp: Int = 1): GradientDrawable =
        GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = dp(radiusDp).toFloat()
            setColor(fillColor)
            if (strokeColor != Color.TRANSPARENT) {
                setStroke(maxOf(1, dp(strokeWidthDp)), strokeColor)
            }
        }

    private fun currentParent(): LinearLayout = activeContainer ?: body

    private fun sectionCard(headerTitle: String? = null, block: () -> Unit) {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            isSaveEnabled = false
            background = roundedBox(Color.parseColor("#FFFFFF"), Color.parseColor("#DCE3EE"), radiusDp = 12)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(8) }
        }
        if (!headerTitle.isNullOrEmpty()) {
            val sectionHeader = TextView(this).apply {
                text = headerTitle
                isSaveEnabled = false
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTypeface(typeface, Typeface.BOLD)
                setTextColor(Color.parseColor("#475569"))
                setPadding(0, 0, 0, dp(4))
            }
            card.addView(sectionHeader)
        }
        body.addView(card)
        val previous = activeContainer
        activeContainer = card
        try {
            block()
        } finally {
            activeContainer = previous
        }
    }

    override fun onCreate(state: Bundle?) {
        super.onCreate(null)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        window.statusBarColor = Color.parseColor("#0F172A")
        // Intents/extras and saved instance state are never unlock sources.
        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF).apply {
            addAction(Intent.ACTION_TIME_CHANGED); addAction(Intent.ACTION_TIMEZONE_CHANGED)
        }
        if (android.os.Build.VERSION.SDK_INT >= 33) registerReceiver(securityEvents, filter, Context.RECEIVER_NOT_EXPORTED)
        else registerReceiver(securityEvents, filter)
        page("Locklark")
        sectionCard("安全初始化") {
            label("正在打开此设备的本地金库…")
        }
    }
    override fun onStart() {
        super.onStart()
        gate.start()
        main.post(tick)
        resumeLocked()
    }
    private fun resumeLocked() {
        if (cleanupPending) { lockedPage(); setBusy(true); status.text = "正在完成锁定…"; return }
        setBusy(false)
        if (vault == null) {
            opening = true
            work(task = { _, _ -> Mobilecore.open(database.absolutePath) }, drop = { it.close() }, dropOnWorker = true) {
                opening = false; vault = it; lockedPage()
            }
        } else lockedPage()
    }
    private fun enqueueLockCleanup() {
        cleanupPending = true
        val sequence = ++cleanupSerial
        val base = vault
        worker.execute {
            try { base?.lock() }
            finally {
                main.post {
                    if (sequence == cleanupSerial) {
                        cleanupPending = false
                        if (!destroyed && gate.isForeground()) resumeLocked()
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (secretDeadline?.validAt(SystemClock.elapsedRealtime(), System.currentTimeMillis()) == false) clearDisplay()
    }
    override fun onStop() {
        gate.stop()
        vault?.requestLock()
        promptSlot.cancel()
        clearInputs(); generatedKey?.fill(0); generatedKey = null
        clearDisplay(); currentRow = null; unlockedUi = false; busy = false
        page("Locklark 已锁定")
        enqueueLockCleanup()
        main.removeCallbacks(tick)
        super.onStop()
    }
    override fun onDestroy() {
        destroyed = true
        unregisterReceiver(securityEvents)
        vault?.requestLock()
        val previous = vault
        worker.execute { previous?.close() }
        worker.shutdown()
        super.onDestroy()
    }
    override fun onSaveInstanceState(outState: Bundle) { /* Never persist native input or disclosure. */ }

    private fun clearInputs() { inputs.forEach { it.text?.clear() } }
    private fun clearBackupView() { backupKeyView?.text = ""; backupKeyView = null }
    private fun clearDisplay() {
        secretView?.apply {
            text = ""
            background = null
            setPadding(0, 0, 0, 0)
        }
        secretDeadline = null
    }
    private fun styleStatusBanner(view: TextView, content: CharSequence?) {
        val text = content?.toString().orEmpty()
        if (text.isEmpty()) {
            view.background = null
            view.setPadding(0, 0, 0, 0)
            return
        }
        val isWarning = text.contains("未完成：") || text.startsWith("结果未确认") ||
            text.startsWith("请先确认") || text.contains("已使用或撤销") || text.contains("必须为")
        val isSuccess = text.startsWith("已启用；") || text.startsWith("已明确授权") || text.startsWith("活动登录：")
        val (bg, border, fg) = when {
            isWarning -> Triple("#FEF2F2", "#FECACA", "#991B1B")
            isSuccess -> Triple("#EFF6FF", "#BFDBFE", "#1E40AF")
            else -> Triple("#F8FAFC", "#CBD5E1", "#334155")
        }
        view.background = roundedBox(Color.parseColor(bg), Color.parseColor(border), radiusDp = 8)
        view.setTextColor(Color.parseColor(fg))
        view.setPadding(dp(10), dp(6), dp(10), dp(6))
    }

    private fun page(title: String) {
        clearInputs(); clearDisplay(); clearBackupView(); secretView = null; inputs.clear(); buttons.clear()
        activeContainer = null
        val scroll = ScrollView(this).apply {
            isSaveEnabled = false
            setBackgroundColor(Color.parseColor("#F4F7FB"))
            setOnApplyWindowInsetsListener { view, insets ->
                val safe = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                view.setPadding(safe.left, safe.top, safe.right, safe.bottom)
                insets
            }
        }
        body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(20))
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
            isSaveEnabled = false
        }
        scroll.addView(body); setContentView(scroll)
        label(title).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f)
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor("#0F172A"))
            setPadding(0, 0, 0, dp(4))
        }
        status = label("").apply {
            tag = "status"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(6) }
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: Editable?) { styleStatusBanner(this@apply, s) }
            })
        }
        if (unlockedUi) button("立即锁定", "lock") { lockNow() }
    }
    private fun label(value: String) = TextView(this).also {
        it.text = value
        it.isSaveEnabled = false
        it.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
        if (value.startsWith("ID: ") || value.startsWith("修订: ")) {
            it.typeface = Typeface.MONOSPACE
            it.setTextColor(Color.parseColor("#475569"))
            it.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            it.setPadding(0, dp(1), 0, dp(1))
        } else {
            it.setTextColor(Color.parseColor("#334155"))
            it.setPadding(0, dp(2), 0, dp(4))
        }
        currentParent().addView(it)
    }
    private fun input(hint: String, tag: String, secret: Boolean = false, multiline: Boolean = false): EditText =
        EditText(this).also {
            it.hint = hint; it.contentDescription = hint; it.tag = tag; it.isSaveEnabled = false
            it.inputType = if (multiline) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
                else InputType.TYPE_CLASS_TEXT or if (secret) InputType.TYPE_TEXT_VARIATION_PASSWORD else InputType.TYPE_TEXT_VARIATION_NORMAL
            it.imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_ACTION_DONE
            if (multiline) {
                it.minLines = 3
                it.gravity = Gravity.TOP or Gravity.START
            }
            it.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            it.setTextColor(Color.parseColor("#0F172A"))
            it.setHintTextColor(Color.parseColor("#64748B"))
            val bg = StateListDrawable().apply {
                addState(intArrayOf(android.R.attr.state_focused), roundedBox(Color.parseColor("#FFFFFF"), Color.parseColor("#1A56DB"), radiusDp = 8, strokeWidthDp = 2))
                addState(intArrayOf(-android.R.attr.state_enabled), roundedBox(Color.parseColor("#F1F5F9"), Color.parseColor("#E2E8F0"), radiusDp = 8))
                addState(intArrayOf(), roundedBox(Color.parseColor("#F8FAFC"), Color.parseColor("#CBD5E1"), radiusDp = 8))
            }
            it.background = bg
            it.setPadding(dp(12), dp(8), dp(12), dp(8))
            it.layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dp(6) }
            it.filterTouchesWhenObscured = true
            inputs.add(it); currentParent().addView(it)
        }
    private fun button(title: String, tag: String, action: () -> Unit): Button = Button(this).also {
        it.text = title; it.tag = tag; it.contentDescription = title; it.isSaveEnabled = false
        it.isAllCaps = false
        it.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        it.minHeight = dp(40)
        it.minimumHeight = dp(40)
        val isPrimary = tag in PRIMARY_TAGS
        val isDanger = tag in DANGER_TAGS
        val isItemRow = tag.startsWith("item-")
        val bg = StateListDrawable()
        when {
            isPrimary -> {
                bg.addState(intArrayOf(-android.R.attr.state_enabled), roundedBox(Color.parseColor("#94A3B8"), radiusDp = 8))
                bg.addState(intArrayOf(android.R.attr.state_pressed), roundedBox(Color.parseColor("#1E40AF"), radiusDp = 8))
                bg.addState(intArrayOf(), roundedBox(Color.parseColor("#1A56DB"), radiusDp = 8))
                it.setTextColor(ColorStateList(
                    arrayOf(intArrayOf(-android.R.attr.state_enabled), intArrayOf()),
                    intArrayOf(Color.parseColor("#E2E8F0"), Color.parseColor("#FFFFFF"))
                ))
                it.setTypeface(it.typeface, Typeface.BOLD)
            }
            isDanger -> {
                bg.addState(intArrayOf(-android.R.attr.state_enabled), roundedBox(Color.parseColor("#F8FAFC"), Color.parseColor("#E2E8F0"), radiusDp = 8))
                bg.addState(intArrayOf(android.R.attr.state_pressed), roundedBox(Color.parseColor("#FFE4E6"), Color.parseColor("#FDA4AF"), radiusDp = 8))
                bg.addState(intArrayOf(), roundedBox(Color.parseColor("#FFF1F2"), Color.parseColor("#FECDD3"), radiusDp = 8))
                it.setTextColor(ColorStateList(
                    arrayOf(intArrayOf(-android.R.attr.state_enabled), intArrayOf()),
                    intArrayOf(Color.parseColor("#94A3B8"), Color.parseColor("#BE123C"))
                ))
                it.setTypeface(it.typeface, Typeface.BOLD)
            }
            isItemRow -> {
                bg.addState(intArrayOf(-android.R.attr.state_enabled), roundedBox(Color.parseColor("#F8FAFC"), Color.parseColor("#E2E8F0"), radiusDp = 8))
                bg.addState(intArrayOf(android.R.attr.state_pressed), roundedBox(Color.parseColor("#EFF6FF"), Color.parseColor("#93C5FD"), radiusDp = 8))
                bg.addState(intArrayOf(), roundedBox(Color.parseColor("#F8FAFC"), Color.parseColor("#CBD5E1"), radiusDp = 8))
                it.setTextColor(Color.parseColor("#0F172A"))
                it.gravity = Gravity.START or Gravity.CENTER_VERTICAL
                it.setTypeface(it.typeface, Typeface.BOLD)
            }
            else -> {
                bg.addState(intArrayOf(-android.R.attr.state_enabled), roundedBox(Color.parseColor("#F8FAFC"), Color.parseColor("#E2E8F0"), radiusDp = 8))
                bg.addState(intArrayOf(android.R.attr.state_pressed), roundedBox(Color.parseColor("#E2E8F0"), Color.parseColor("#94A3B8"), radiusDp = 8))
                bg.addState(intArrayOf(), roundedBox(Color.parseColor("#EEF2F8"), Color.parseColor("#CBD5E1"), radiusDp = 8))
                it.setTextColor(ColorStateList(
                    arrayOf(intArrayOf(-android.R.attr.state_enabled), intArrayOf()),
                    intArrayOf(Color.parseColor("#94A3B8"), Color.parseColor("#1E293B"))
                ))
            }
        }
        it.background = bg
        it.stateListAnimator = null
        it.setPadding(dp(12), dp(6), dp(12), dp(6))
        it.layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { bottomMargin = dp(6) }
        it.filterTouchesWhenObscured = true
        it.setOnClickListener { if (!busy || tag == "lock") action() }
        buttons.add(it); currentParent().addView(it)
    }
    private fun setBusy(value: Boolean) {
        busy = value
        buttons.forEach { it.isEnabled = !value || it.tag == "lock" }
        inputs.forEach { it.isEnabled = !value }
    }
    private fun message(failure: NativeCallFailure) {
        status.text = if (failure.code == NativeFailureCode.UNKNOWN) "结果未确认，请重新打开金库核实，勿重复提交。"
            else failure.phase.userText + "未完成：" + failure.code.userText
    }

    private fun <T> work(target: Target? = null, task: (WorkStamp, Vault?) -> T, drop: (T) -> Unit = {}, dropOnWorker: Boolean = false, releaseInputs: () -> Unit = {}, done: (T) -> Unit) {
        if (busy) { releaseInputs(); return }
        val stamp = try { gate.begin(target) } catch (_: IllegalStateException) { releaseInputs(); return }
        // Nonblocking core view capture is on the UI thread before queuing.
        val capturedVault = try { vault?.captureOperation() } catch (error: Exception) { releaseInputs(); message(NativeCallFailure(NativePhase.CAPTURE, NativeFailures.classify(error))); return }
        setBusy(true)
        worker.execute {
            try {
                val value = GuardedWork.run(gate, stamp, target, releaseInputs) { task(stamp, capturedVault) }
                main.post {
                    if (gate.accepts(stamp, target)) { setBusy(false); done(value) }
                    else { if (dropOnWorker) cleanup.execute { drop(value) } else drop(value); if (vault == null) opening = false }
                }
            } catch (error: Exception) {
                val failure = error as? NativeCallFailure ?: NativeCallFailure(NativePhase.OPERATION, NativeFailures.classify(error))
                main.post { if (gate.accepts(stamp, target)) { setBusy(false); opening = false; message(failure) } }
            }
        }
    }
    private fun lockNow() {
        gate.invalidate(); vault?.requestLock(); promptSlot.cancel()
        clearInputs(); generatedKey?.fill(0); generatedKey = null
        clearDisplay(); currentRow = null; unlockedUi = false; busy = false
        enqueueLockCleanup()
        lockedPage(); setBusy(true); status.text = "正在完成锁定…"
    }

    private fun lockedPage() {
        unlockedUi = false; currentRow = null; page("Locklark · 本机离线金库")
        if (!database.exists()) {
            sectionCard("欢迎使用本机零知识金库") {
                label("此设备尚无加密金库。请先生成并离线妥善保存新的 Secret Key；设备快速解锁不能替代完整双因素恢复。")
                button("生成新的 Secret Key", "generate-account-key") {
                    work(task = { _, _ -> Mobilecore.generateSecretKey() }, drop = { it.fill(0) }) { value ->
                        generatedKey?.fill(0); generatedKey = value; createPage(value)
                    }
                }
            }
            return
        }
        sectionCard("双因素完整验证") {
            val password = input("主密码", "master-password", true)
            val key = input("Secret Key", "secret-key", true)
            button("打开本地金库", "unlock") {
                val pw = password.text.toString().toByteArray()
                val encodedKey = key.text.toString().toByteArray()
                clearInputs()
                work(releaseInputs = { pw.fill(0); encodedKey.fill(0) }, task = { stamp, api ->
                    var decoded = ByteArray(0)
                    try { decoded = Mobilecore.parseSecretKey(String(encodedKey, Charsets.UTF_8)); GuardedWork.ensureCurrent(gate, stamp); NativeFailures.call(NativePhase.UNLOCK) { api!!.unlock(pw, decoded) } }
                    finally { pw.fill(0); decoded.fill(0) }
                }) { showList() }
            }
            button("使用此设备认证解锁", "quick-unlock") {
                work(task = { stamp, api -> withStore(stamp) { api!!.unlockWithSystem(it) } }) { showList() }
            }
        }
    }
    private fun createPage(key: ByteArray) {
        page("创建本机金库")
        sectionCard("1. 离线备份 Secret Key") {
            label("请在应用外安全备份此 Secret Key。遗失两项完整因素后，无法依靠设备快速解锁恢复金库。")
            backupKeyView = label(Mobilecore.formatSecretKey(key)).apply {
                tag = "backup-secret-key"
                typeface = Typeface.MONOSPACE
                setTextColor(Color.parseColor("#F8FAFC"))
                background = roundedBox(Color.parseColor("#0F172A"), Color.parseColor("#334155"), radiusDp = 8)
                setPadding(dp(10), dp(8), dp(10), dp(8))
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = dp(6) }
            }
            val acknowledgement = CheckBox(this).apply {
                text = "我已离线保存 Secret Key"
                tag = "backup-ack"
                isSaveEnabled = false
                setTextColor(Color.parseColor("#0F172A"))
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            }
            currentParent().addView(acknowledgement)
            val password = input("新的主密码", "new-master-password", true)
            val repeat = input("再次输入主密码", "repeat-master-password", true)
            button("创建并解锁", "create-vault") {
                if (generatedKey !== key) { status.text = "此 Secret Key 已使用或撤销，请返回并重新生成，或用完整因素打开金库核实。"; return@button }
                if (!acknowledgement.isChecked || password.text.toString() != repeat.text.toString()) {
                    status.text = "请先确认备份，且两次主密码一致。"; return@button
                }
                val pw = password.text.toString().toByteArray()
                if (pw.isEmpty() || pw.size > 1024) { pw.fill(0); status.text = "主密码必须为 1–1024 字节。"; return@button }
                val accountKey = key.copyOf()
                clearInputs(); generatedKey?.fill(0); generatedKey = null
                // Remove the displayed account key before any asynchronous work.
                clearBackupView()
                work(releaseInputs = { pw.fill(0); accountKey.fill(0) }, task = { stamp, api ->
                    val createPassword = pw.copyOf(); val createKey = accountKey.copyOf()
                    try { NativeFailures.call(NativePhase.CREATE) { api!!.create(createPassword, createKey) }; GuardedWork.ensureCurrent(gate, stamp); NativeFailures.call(NativePhase.UNLOCK) { api!!.unlock(pw, accountKey) } }
                    finally { createPassword.fill(0); createKey.fill(0); pw.fill(0); accountKey.fill(0) }
                }) { showList() }
            }
            button("取消创建", "cancel-create") { gate.invalidate(); generatedKey?.fill(0); generatedKey = null; lockedPage() }
        }
    }

    private fun showList(query: String? = null) {
        unlockedUi = true; currentRow = null; page("Locklark · 登录")
        sectionCard("检索与管理") {
            val search = input("搜索标题", "query")
            if (query != null) search.setText(query)
            button("搜索", "search") { val text = search.text.toString(); gate.invalidate(); showList(text) }
            button("新建登录", "new-login") { gate.invalidate(); newLoginPage() }
        }
        sectionCard("此设备生物识别 / 锁屏授权") {
            button("启用此设备认证", "enable-quick-unlock") {
                work(task = { stamp, api -> withStore(stamp) { api!!.enableSystemUnlock(it) } }) { status.text = "已启用；本次完整双因素解锁后的 24 小时内可用。" }
            }
            button("停用此设备认证", "disable-quick-unlock") {
                work(task = { stamp, api -> withStore(stamp) { api!!.disableSystemUnlock(it) } }) { status.text = "本设备授权已删除。" }
            }
        }
        work(task = { _, api -> NativeFailures.call(NativePhase.REFRESH) { if (query == null) api!!.list("active") else api!!.search(query, "active") } }) { rows ->
            sectionCard("已保存的登录凭据") {
                if (rows.count() == 0L) {
                    label("暂无匹配的登录凭据。点击上方「新建登录」添加条目。")
                }
                for (i in 0 until rows.count()) {
                    val row = rows.at(i)
                    label("ID: " + row.getID())
                    button("选择登录：" + visibleTitle(row.getTitle()), "item-" + row.getID()) {
                        gate.invalidate(); detailPage(row)
                    }
                }
            }
            status.text = "活动登录：" + rows.count()
        }
    }
    private fun detailPage(row: Row) {
        currentRow = row; page("登录：" + visibleTitle(row.getTitle()))
        sectionCard("凭据元数据与单次显式读取") {
            label("ID: " + row.getID()); label("修订: " + row.getRevision())
            button("显示用户名", "show-username") { reveal(row, "username") }
            button("显示密码", "show-password") { reveal(row, "password") }
            button("显示备注", "show-notes") { reveal(row, "notes") }
            button("显示验证码", "show-otp") { reveal(row, "otp") }
            button("隐藏已显示字段", "hide-secret") { clearDisplay() }
            button("编辑登录字段", "edit-login") { gate.invalidate(); editPage(row) }
            button("重新生成本地密码", "regenerate-password") { gate.invalidate(); regeneratePage(row) }
            button("返回列表", "back-to-list") { gate.invalidate(); showList() }
            secretView = label("").apply {
                tag = "secret-value"
                typeface = Typeface.MONOSPACE
            }
        }
    }
    private class Delivery(val value: ByteArray, val from: Long, val until: Long) { override fun toString() = "[native secret delivery]" }
    private fun reveal(row: Row, field: String) {
        clearDisplay()
        // Recreate the output widget after clearing its previous reference.
        if (secretView == null) secretView = label("").apply { tag = "secret-value"; typeface = Typeface.MONOSPACE }
        val target = Target(row.getID(), row.getRevision(), field)
        work(target, task = { stamp, api ->
            var secret: SecretValue? = null
            try {
                secret = if (field == "otp") api!!.revealOTP(target.id, target.revision) else api!!.revealField(target.id, target.revision, field)
                if (!gate.accepts(stamp, target)) throw PlatformAuthenticationFailure()
                val bytes = secret.take() ?: byteArrayOf()
                Delivery(bytes, secret.fromUnixMilli(), secret.untilUnixMilli())
            } finally { secret?.clear() }
        }, drop = { it.value.fill(0) }) { delivery ->
            try {
                val selected = currentRow
                val deadline = SecretDeadline.create(delivery.from, delivery.until, System.currentTimeMillis(), SystemClock.elapsedRealtime())
                if (vault!!.isUnlocked() && selected != null && selected.getID() == target.id && selected.getRevision() == target.revision && deadline != null) {
                    secretDeadline = deadline
                    val text = String(delivery.value, Charsets.UTF_8)
                    secretView?.apply {
                        this.text = text
                        if (text.isNotEmpty()) {
                            setTextColor(Color.parseColor("#F8FAFC"))
                            background = roundedBox(Color.parseColor("#0F172A"), Color.parseColor("#334155"), radiusDp = 8)
                            setPadding(dp(10), dp(8), dp(10), dp(8))
                        }
                    }
                    status.text = if (delivery.value.isEmpty()) "字段为空，已完成本次明确读取。" else "已明确授权显示；到期自动隐藏。"
                } else clearDisplay()
            } finally { delivery.value.fill(0) }
        }
    }
    private fun newLoginPage() {
        page("新建登录")
        sectionCard("凭据信息与密码生成") {
            val title = input("登录标题", "login-title")
            val url = input("网站 HTTPS URL（可选）", "login-url")
            val username = input("用户名", "login-username", true)
            val password = input("登录密码", "login-password", true)
            val length = input("生成密码长度（22–256）", "password-length").apply { setText("24"); inputType = InputType.TYPE_CLASS_NUMBER }
            val generate = CheckBox(this).apply {
                text = "生成强密码"
                tag = "generate-password"
                isChecked = true
                isSaveEnabled = false
                setTextColor(Color.parseColor("#0F172A"))
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            }
            currentParent().addView(generate)
            password.isEnabled = false
            generate.setOnCheckedChangeListener { _, checked -> password.isEnabled = !checked }
            button("保存登录", "save-login") {
                val metadataTitle = title.text.toString(); val metadataUrl = url.text.toString()
                val user = username.text.toString().toByteArray(); val pass = password.text.toString().toByteArray()
                val size = length.text.toString().toLongOrNull() ?: 0; val generated = generate.isChecked
                clearInputs()
                work(releaseInputs = { user.fill(0); pass.fill(0) }, task = { _, api ->
                    try { if (generated) api!!.generateLogin(metadataTitle, metadataUrl, user, size) else api!!.createLogin(metadataTitle, metadataUrl, user, pass) }
                    finally { user.fill(0); pass.fill(0) }
                }) { showList() }
            }
            button("取消新建", "cancel-new-login") { gate.invalidate(); showList() }
        }
    }
    private fun editPage(row: Row) {
        page("编辑登录字段")
        sectionCard("安全更新单项字段") {
            label("ID: " + row.getID()); label("修订: " + row.getRevision())
            label("新值从空白开始输入。查看旧值需单独授权；取消操作不会改动已保存内容。")
            val fields = arrayOf("title", "url", "username", "password", "otp", "notes")
            val field = Spinner(this).apply {
                tag = "edit-field"
                adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, fields)
                background = roundedBox(Color.parseColor("#F8FAFC"), Color.parseColor("#CBD5E1"), radiusDp = 8)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = dp(6) }
            }
            currentParent().addView(field)
            val value = input("新值（原生可见多行正文）", "edit-value", multiline = true)
            button("保存字段", "save-field") {
                val selectedField = fields[field.selectedItemPosition]
                val bytes = value.text.toString().toByteArray(); clearInputs()
                val target = Target(row.getID(), row.getRevision(), selectedField)
                work(target, releaseInputs = { bytes.fill(0) }, task = { _, api -> try { api!!.editField(target.id, target.revision, target.field, bytes) } finally { bytes.fill(0) } }) { showList() }
            }
            button("取消编辑", "cancel-edit") { gate.invalidate(); detailPage(row) }
        }
    }
    private fun regeneratePage(row: Row) {
        page("确认重新生成本地密码")
        sectionCard("生成并替换金库密码") {
            label("仅替换此本地金库中的密码记录，不会自动更改对应网站上的账户密码。")
            label("ID: " + row.getID()); label("修订: " + row.getRevision())
            val length = input("密码长度（22–256）", "regenerate-length").apply { setText("24"); inputType = InputType.TYPE_CLASS_NUMBER }
            button("确认生成并替换", "confirm-regenerate") {
                val size = length.text.toString().toLongOrNull() ?: 0
                val target = Target(row.getID(), row.getRevision(), "password")
                work(target, task = { _, api -> api!!.regeneratePassword(target.id, target.revision, size) }) { showList() }
            }
            button("取消重新生成", "cancel-regenerate") { gate.invalidate(); detailPage(row) }
        }
    }
    private class StoreOperation(private val native: PlatformCapsuleStore) : SystemUnlockStore {
        private val returned = ReturnedSecretBuffers()
        private val callbackFailure = AtomicReference<NativeCallFailure?>()
        val failure: NativeCallFailure? get() = callbackFailure.get()
        private fun <T> callback(action: () -> T): T = try { action() }
            catch (error: PlatformAuthenticationFailure) { callbackFailure.compareAndSet(null, error.failure); throw error }
        override fun store(id: String, value: ByteArray) = callback { native.store(id, value) }
        override fun load(id: String): ByteArray = callback { returned.retain(native.load(id)) }
        override fun delete(id: String) = callback { native.delete(id) }
        fun release() = returned.clearAfterCall()
    }
    private fun <T> withStore(stamp: WorkStamp, action: (SystemUnlockStore) -> T): T {
        val attempt = authAttempts.incrementAndGet()
        val prefix = "attempt=$attempt pid=${Process.myPid()}"
        Log.i("LocklarkAuth", "$prefix event=begin")
        val current = { gate.accepts(stamp) }
        val prompt = NativeCryptoPrompt(this, current)
        var adapter: StoreOperation? = null
        try {
            if (!promptSlot.publish(prompt, current)) throw PlatformAuthenticationFailure()
            adapter = StoreOperation(NativeFailures.call(NativePhase.DEVICE_SETUP) { PlatformCapsuleStore(this, prompt, current) })
            return action(adapter)
        } catch (error: Exception) {
            // The Go boundary deliberately normalizes storage callback errors.
            // Retain only this attempt's fixed Kotlin classification locally.
            val failure = adapter?.failure ?: (error as? PlatformAuthenticationFailure)?.failure
                ?: NativeFailures.failure(NativePhase.DEVICE_SETUP, error)
            Log.i("LocklarkAuth", "$prefix event=failed ${NativeFailures.diagnostic(failure)}")
            throw failure
        } finally {
            // Go has returned: its borrowed callback result is no longer live.
            adapter?.release()
            promptSlot.release(prompt)
        }
    }

    private fun visibleTitle(value: String): String = buildString {
        value.codePoints().limit(120).forEach { cp ->
            if (Character.isISOControl(cp) || Character.getType(cp) == Character.FORMAT.toInt()) append("\\u{%X}".format(cp))
            else appendCodePoint(cp)
        }
    }.ifEmpty { "（空标题）" }
}
