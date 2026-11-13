package org.locklark.android.autofill

import android.app.Activity
import android.app.assist.AssistStructure
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.service.autofill.FillResponse
import android.text.InputType
import android.util.Log
import android.util.TypedValue
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import mobilecore.Mobilecore
import mobilecore.Row
import mobilecore.SecretValue
import mobilecore.Vault
import org.locklark.android.R
import org.locklark.android.security.ForegroundGate
import org.locklark.android.security.GuardedWork
import org.locklark.android.security.NativeCallFailure
import org.locklark.android.security.NativeFailureCode
import org.locklark.android.security.NativeFailures
import org.locklark.android.security.NativePhase
import org.locklark.android.security.ObsoleteWork
import org.locklark.android.security.Target
import org.locklark.android.security.WorkStamp
import java.io.File
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * Explicit approval for one OS Autofill authentication request.
 *
 * Flow: claim the one-use handoff against the OS-attached structure, package
 * and AutofillIds (once, in the initial intent only) -> once this Activity is
 * foreground, open a NEW [Vault] on the app's own noBackupFilesDir/personal.ll
 * database -> unlock it only with the entered master password and Secret Key
 * -> list active login metadata -> the user selects one visible title and then
 * presses a separate Approve -> approval revalidates the exact row
 * ID/revision and reads only that row's username/password into the one-use
 * [ApprovedAutofillResult]. Approve is also the final step: when the
 * serialized worker delivers the approval, this Activity takes it exactly once
 * and synchronously builds one Dataset plus the challenge FillResponse into
 * the terminal RESULT_OK authentication result, wipes every approval/caller
 * buffer, retires the BOUND handoff for exactly this token, client nonce and
 * the two OS AutofillIds, requests the fresh vault lock synchronously, queues
 * its close and finishes. A refused handoff returns no fill at all. Android's
 * Dataset selection in the target may then fill only the two bound fields. No
 * credential value is rendered, logged, saved or placed in any extra other
 * than Android's own autofill result values.
 *
 * Nothing here is persisted: no saved state, prefs, logs or extras of factors,
 * credentials, handoff or approval. Every exit invalidates the gate and queues
 * exactly one cleanup on the single serialized worker behind any in-flight
 * open, unlock, list or reveal. A vault already published at exit time is
 * requested to lock synchronously on the main thread; a vault whose install
 * lands after that read is rechecked, locked and closed by the queued worker
 * task. The vault is never closed on main: the only off-worker case is a
 * worker that already shut down, which can run no native call, so only the
 * lock is requested. onStop is a terminal exit for this one-use handoff:
 * nothing is reopened or reused. A missing database is a fixed unavailable
 * state that later onStart never opens, and an unopenable vault ends the
 * handoff the same way.
 */
class AutofillAuthActivity : Activity() {
    private val gate = ForegroundGate()
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val freshVault = FreshVaultGate()
    // Main thread only. A terminal exit is never undone, not even by onStart.
    private val lifecycle = LifecycleState()

    // Set on the worker by a gate-accepted install; read on main for the
    // synchronous lock and cleared on the worker by the exit cleanup.
    @Volatile private var vault: Vault? = null
    // Main thread only. Null once anything no longer matches the OS target.
    private var structureMatches = false
    private var target: AutofillTarget? = null
    // The claimed one-use handoff token; discarded on every exit.
    private var handoffToken: String? = null
    private var masterPassword: EditText? = null
    private var secretKey: EditText? = null
    private var selected: ActiveLogin? = null
    private val buttons = mutableListOf<Button>()
    private val rowButtons = mutableListOf<Pair<Button, ActiveLogin>>()
    private lateinit var content: LinearLayout
    private lateinit var status: TextView

    private val database by lazy { File(noBackupFilesDir, "personal.ll") }

    // Widened for tests only (synthetic gateway, no native or credential use).
    @Volatile internal var gateway: MobilecoreGateway = NativeGateway { vault }

    override fun onCreate(state: Bundle?) {
        // Saved state is never an unlock, handoff or approval source.
        super.onCreate(null)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.setSoftInputMode(
            WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE or
                WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN,
        )

        // The handoff token is claimable exactly once, before any onStart:
        // onStart never claims, so a recreated Activity (state != null) cannot
        // bind the one-use handoff again.
        if (state == null) claimInitialIntent() else {
            structureMatches = false
            target = null
        }
        buildUi()
        if (!structureMatches || target == null) {
            failClosed()
            return
        }
        if (!database.isFile) {
            // Nothing to unlock here; never offer a nonfunctional factors form,
            // and never open later: onStart keeps this unavailable state.
            lifecycle.markDatabaseMissing()
            showUnavailable()
            return
        }
        // The vault is opened only from onStart, once the gate is foreground.
        showOpening()
    }

    private fun claimInitialIntent() {
        val token = intent?.getStringExtra(AutofillHandoff.EXTRA_HANDOFF)
        @Suppress("DEPRECATION")
        val structure = intent?.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        val form = LoginFormParser.parse(structure)
        val clientNonce = clientState()?.getString(AutofillHandoff.EXTRA_CLIENT_NONCE)
        handoffToken = token
        if (!AutofillHandoff.claim(token, clientNonce, form) || form == null) {
            structureMatches = false
            target = null
            return
        }
        structureMatches = true
        target = AutofillTarget.from(form)
    }

    /**
     * The service client state Android attached to this authentication launch;
     * it is forwarded unchanged for exactly the request this Activity serves.
     */
    private fun clientState(): Bundle? = intent?.getBundleExtra(AutofillManager.EXTRA_CLIENT_STATE)

    /** The nonce of the reviewed challenge this launch was claimed with. */
    private fun claimedNonce(): String? = AutofillChallenge.fromBundle(clientState())?.clientNonce
        ?: clientState()?.getString(AutofillHandoff.EXTRA_CLIENT_NONCE)

    /**
     * Closes the one-use handoff, BOUND or not, on every non-success exit. A
     * supplied nonce whose malformed form was never bound is retired too.
     */
    private fun retireHandoff() {
        val token = handoffToken
        if (token != null) {
            AutofillHandoff.discard(token)
        } else {
            AutofillHandoff.consume(null, claimedNonce(), null)
        }
    }

    /**
     * The reviewed challenge for exactly this service request, bound to this
     * exact target. Its absence fails the approval closed: no other response
     * can ever be returned.
     */
    private fun reviewedChallenge(): FillResponse? {
        val challenge = AutofillChallenge.fromBundle(clientState()) ?: return null
        val exactTarget = target ?: return null
        if (!exactTarget.matches(challenge.form)) return null
        // One-use: the reviewed challenge is removed before it is returned.
        return AutofillServiceState.take(challenge.clientNonce)
    }

    override fun onStart() {
        super.onStart()
        if (lifecycle.isTerminal || isFinishing || isDestroyed) return
        if (lifecycle.databaseMissing) {
            // Fixed unavailable: no fresh open, factors UI or row UI, ever.
            gate.start()
            showUnavailable()
            return
        }
        gate.start()
        if (!structureMatches || target == null) {
            failClosed()
            return
        }
        // Normally onStop already ended this handoff. A return without onStop
        // never resumes an earlier session: the open is one-shot.
        if (!freshVault.beginOpen()) {
            gate.invalidate()
            refuseUnavailable()
            return
        }
        openFreshVault()
    }

    /**
     * Backgrounding ends this one-use handoff. After a successful approval this
     * Activity already delivered its terminal result and finished itself in
     * [deliverApprovedResult], so onStop must not report anything again. In
     * every other case it is the terminal exit: the gate is invalidated, an
     * installed vault is locked synchronously, one close is queued, factors,
     * approval and views are wiped, and the Activity reports a non-null
     * canceled result and finishes.
     */
    override fun onStop() {
        if (lifecycle.isTerminal) {
            super.onStop()
            return
        }
        exitConsumed()
        super.onStop()
    }

    override fun onDestroy() {
        // Idempotent after onStop. A close queued by the first exit still runs
        // on the worker; shutdown lets it and every already-queued call finish.
        exitConsumed()
        worker.shutdown()
        super.onDestroy()
    }

    override fun onTrimMemory(level: Int) {
        if (level >= TRIM_MEMORY_UI_HIDDEN) exitConsumed()
        super.onTrimMemory(level)
    }

    override fun onSaveInstanceState(outState: Bundle) { /* Never persist factors, rows, handoff or approval. */ }

    @Deprecated("Back closes the approval without any result")
    override fun onBackPressed() {
        exitConsumed()
        @Suppress("DEPRECATION")
        if (!isFinishing) super.onBackPressed()
    }

    // ---- lifecycle/secret cleanup -------------------------------------------------

    /**
     * Terminal, idempotent cleanup for the one-use handoff, safe to call from
     * onStop, onDestroy, back, cancel, a failed decision and a rejected enqueue
     * in any order. The gate is invalidated first so no queued callback can pass
     * [ForegroundGate.accepts]. The exit winner then queues exactly one worker
     * cleanup. An already-published vault is requested to lock synchronously on
     * this main thread (outside the worker queue, so pending unlock/list/reveal
     * work cannot delay it) before that cleanup closes it; a vault that only
     * publishes after the exit read is rechecked, locked and closed on the
     * serialized worker. A late rejected open is closed by the worker that
     * opened it and never reaches this cleanup, so no vault is closed twice.
     * Widgets and factor buffers are wiped, and the first call reports
     * RESULT_CANCELED and finishes. After the one terminal approval exit it only
     * retires the claimed handoff: the successful result is never overwritten.
     */
    private fun exitConsumed() {
        gate.invalidate()
        retireHandoff()
        handoffToken = null
        if (lifecycle.terminal == LifecycleState.Terminal.APPROVED) return
        if (freshVault.exit()) {
            val published = vault
            freshVault.releaseAfterOpen(
                worker = worker,
                published = published,
                take = { vault.also { vault = null } },
                lock = { current -> runCatching { current.requestLock() } },
                close = { current -> runCatching { current.close() } },
            )
        }
        if (lifecycle.end(LifecycleState.Terminal.CANCELLED)) {
            wipeUiSecrets()
            // Android 12+ requires a non-null response Intent with extras.
            val canceled = AutofillAuthenticationResult.canceled()
            setResult(canceled.resultCode, canceled.copyData().toIntent())
            if (!isFinishing) finish()
        }
    }

    /** Android 12+ requires the authentication extras Bundle to be non-null. */
    private fun Bundle.toIntent(): Intent = Intent().putExtras(this)

    private fun wipeUiSecrets() {
        masterPassword?.text?.clear()
        secretKey?.text?.clear()
        masterPassword = null
        secretKey = null
        selected = null
        if (::content.isInitialized) {
            for (index in 0 until content.childCount) {
                (content.getChildAt(index) as? EditText)?.text?.clear()
            }
            content.removeAllViews()
        }
        rowButtons.clear()
        buttons.clear()
    }

    /** Fails closed without any user progress; same terminal path as every exit. */
    private fun failClosed() {
        exitConsumed()
    }

    /**
     * Fails closed but stays on screen showing the fixed unavailable state, like
     * a missing database: no fresh open, factors UI or row UI afterwards.
     */
    private fun refuseUnavailable() {
        if (!lifecycle.markDatabaseMissing()) return
        exitConsumed()
        if (!isFinishing && !isDestroyed) showUnavailable()
    }

    // ---- worker -----------------------------------------------------------------

    private fun stampOrNull(target: Target? = null): WorkStamp? = try {
        gate.begin(target)
    } catch (_: IllegalStateException) {
        null
    }

    /**
     * Enqueues [task] on the serialized worker. [wipedOnRejection] runs here if
     * the worker refuses the task, so no secret survives an enqueue that never
     * ran.
     */
    private fun enqueue(wipedOnRejection: () -> Unit, task: () -> Unit) {
        try {
            worker.execute(task)
        } catch (_: RejectedExecutionException) {
            wipedOnRejection()
            failClosed()
        }
    }

    /**
     * Runs [task] on the serialized worker under [stamp] and dispatches only
     * its outcome to main. [done] runs on main only while the gate still
     * accepts [stamp]; otherwise the result is discarded unshown and the
     * Activity fails closed. Every exception is a refusal: it fails closed.
     */
    private fun <T> runWork(
        tag: String,
        stamp: WorkStamp,
        target: Target? = null,
        wipedOnRejection: () -> Unit,
        task: (WorkStamp) -> T,
        done: (T) -> Unit,
    ) {
        enqueue(wipedOnRejection) {
            val result = try {
                GuardedWork.run(gate, stamp, target, {}) { task(stamp) }
            } catch (error: Exception) {
                val failure = error as? NativeCallFailure
                    ?: NativeCallFailure(NativePhase.OPERATION, NativeFailures.classify(error))
                if (error !is ObsoleteWork && failure.code != NativeFailureCode.CANCELLED &&
                    failure.code != NativeFailureCode.LOCKED
                ) {
                    Log.i("LocklarkAutofill", "stage=$tag " + NativeFailures.diagnostic(failure))
                }
                main.post { if (!lifecycle.isTerminal) failClosed() }
                return@enqueue
            }
            main.post {
                if (gate.accepts(stamp, target) && !lifecycle.isTerminal) done(result) else {
                    // Never shown after foreground loss; zeroize before cancel.
                    (result as? ApprovedAutofillResult)?.clear()
                    if (!lifecycle.isTerminal) failClosed()
                }
            }
        }
    }

    /**
     * Opens the brand-new [Vault] exactly once, after [onStart]. The worker
     * decides under [FreshVaultGate] whether to install; any other outcome is
     * locked and closed on this same worker and never reaches main.
     */
    private fun openFreshVault() {
        val stamp = stampOrNull()
        if (stamp == null) {
            // No open was enqueued, so nothing can install later: refuse now
            // rather than leave an "opening" page a later onStart could reopen.
            gate.invalidate()
            refuseUnavailable()
            return
        }
        enqueue({}) {
            val opened = try {
                Mobilecore.open(database.absolutePath)
            } catch (error: Exception) {
                val failure = NativeCallFailure(NativePhase.OPERATION, NativeFailures.classify(error))
                main.post {
                    if (gate.accepts(stamp) && !lifecycle.isTerminal) {
                        Log.i("LocklarkAutofill", "stage=open " + NativeFailures.diagnostic(failure))
                        // Nothing is installed, so a late success has no gate to
                        // pass; this refusal is terminal and reopens nothing.
                        refuseUnavailable()
                    }
                }
                return@enqueue
            }
            if (!freshVault.install() || !gate.accepts(stamp)) {
                // Late result after stop/destroy, or superseded: never installed.
                runCatching { opened.requestLock() }
                runCatching { opened.close() }
                main.post { if (gate.accepts(stamp) && !lifecycle.isTerminal) refuseUnavailable() }
                return@enqueue
            }
            if (worker.isShutdown) {
                runCatching { opened.requestLock() }
                runCatching { opened.close() }
                return@enqueue
            }
            vault = opened
            main.post {
                if (gate.accepts(stamp) && !lifecycle.isTerminal) showFactorsPage()
            }
        }
    }

    // ---- UI ---------------------------------------------------------------------

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun color(resId: Int): Int = getColor(resId)

    private fun buildUi() {
        val scroll = ScrollView(this).apply {
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        }
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(24))
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            isSaveEnabled = false
        }
        scroll.addView(content)
        setContentView(scroll)
    }

    private fun add(view: View) {
        view.layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { bottomMargin = dp(8) }
        content.addView(view)
    }

    /** Detach before clearing so no removed widget can still hold a secret. */
    private fun resetPage() {
        masterPassword?.text?.clear()
        secretKey?.text?.clear()
        masterPassword = null
        secretKey = null
        for (index in 0 until content.childCount) {
            (content.getChildAt(index) as? EditText)?.text?.clear()
        }
        content.removeAllViews()
        buttons.clear()
        rowButtons.clear()
    }

    private fun showOpening() {
        resetPage()
        header(R.string.autofill_auth_unlock_guidance)
        status.text = getString(R.string.autofill_auth_opening)
        cancelButton(R.string.autofill_auth_close)
    }

    /** Fixed unavailable state: no factors form, no row list, no approval. */
    private fun showUnavailable() {
        resetPage()
        header(R.string.autofill_auth_no_fill)
        status.text = getString(R.string.autofill_auth_unavailable)
        cancelButton(R.string.autofill_auth_cancel)
    }

    private fun header(bodyRes: Int) {
        val current = target ?: return
        title(getString(R.string.autofill_auth_title)).apply { id = R.id.autofill_auth_title }
        // The exact OS target package, shown literally.
        title(getString(R.string.autofill_auth_target, current.packageName)).apply {
            id = R.id.autofill_auth_target
            typeface = Typeface.MONOSPACE
        }
        label(getString(bodyRes)).apply { id = R.id.autofill_auth_body }
        status = label("").apply {
            id = R.id.autofill_auth_status
            setTextColor(color(R.color.ll_status_warn_text))
        }
    }

    private fun cancelButton(res: Int) {
        button(getString(res), R.id.autofill_auth_cancel, primary = false) { exitConsumed() }
    }

    /**
     * A brand-new TextView for this Activity's own content only (never reused by
     * app containers such as a Toast, which would retain it unboundedly).
     */
    private fun title(value: String) = TextView(this).apply {
        text = value
        isSaveEnabled = false
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
        setTypeface(typeface, Typeface.BOLD)
        setTextColor(color(R.color.ll_text_primary))
        add(this)
    }

    private fun label(value: String) = TextView(this).apply {
        text = value
        isSaveEnabled = false
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
        setTextColor(color(R.color.ll_text_secondary))
    }.also { add(it) }

    private fun secretField(hint: String, id: Int, contentDesc: String) = EditText(this).apply {
        this.id = id
        this.hint = hint
        contentDescription = contentDesc
        isSaveEnabled = false
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_ACTION_DONE
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        filterTouchesWhenObscured = true
        add(this)
    }

    private fun button(text: String, id: Int, primary: Boolean = true, action: () -> Unit) = Button(this).apply {
        this.id = id
        this.text = text
        contentDescription = text
        isSaveEnabled = false
        isAllCaps = false
        minHeight = dp(40)
        minimumHeight = dp(40)
        filterTouchesWhenObscured = true
        if (primary) setTypeface(typeface, Typeface.BOLD)
        setOnClickListener { if (!lifecycle.isTerminal) action() }
        buttons.add(this)
        add(this)
    }

    private fun showFactorsPage() {
        resetPage()
        header(R.string.autofill_auth_unlock_guidance)
        label(getString(R.string.autofill_auth_unlock_guidance))
        masterPassword = secretField(
            getString(R.string.autofill_auth_master_password),
            R.id.autofill_auth_master_password,
            "autofill-master-password",
        )
        secretKey = secretField(getString(R.string.autofill_auth_secret_key), R.id.autofill_auth_secret_key, "autofill-secret-key")
        button(getString(R.string.autofill_auth_unlock), R.id.autofill_auth_unlock) { startUnlock() }
        cancelButton(R.string.autofill_auth_cancel)
    }

    // ---- unlock -----------------------------------------------------------------

    /**
     * Copies both factors into caller-owned CharArrays, wipes the fields, then
     * submits once. Every path below, including a refused enqueue or an
     * obsolete stamp, zeroes them.
     */
    private fun startUnlock() {
        if (lifecycle.isTerminal) return
        val passwordField = masterPassword ?: return
        val keyField = secretKey ?: return
        val password = CharArray(passwordField.text?.length ?: 0)
        val secret = CharArray(keyField.text?.length ?: 0)
        try {
            passwordField.text?.getChars(0, passwordField.text.length, password, 0)
            keyField.text?.getChars(0, keyField.text.length, secret, 0)
        } finally {
            passwordField.text?.clear()
            keyField.text?.clear()
        }
        // No factor String exists at this point; these CharArrays are the copy.
        val wipe = { secret.fill('\u0000'); password.fill('\u0000') }
        val stamp = if (password.isEmpty() || secret.isEmpty()) null else stampOrNull()
        if (stamp == null) {
            wipe()
            // Empty factors, or the foreground was lost before submit.
            status.text = getString(R.string.autofill_auth_failed)
            return
        }
        runWork(
            tag = "unlock",
            stamp = stamp,
            wipedOnRejection = wipe,
            task = { current ->
                val outcome = ApprovalOutcome()
                try {
                    GuardedWork.ensureCurrent(gate, current)
                    gateway.unlock(outcome, password, secret)
                    GuardedWork.ensureCurrent(gate, current)
                    // A gate that reported nothing but threw is still a refusal.
                    outcome.failure?.let { throw it }
                } catch (error: Exception) {
                    throw outcome.failure ?: error
                } finally {
                    wipe()
                }
            },
            done = { showSelectPage() },
        )
    }

    private fun showSelectPage() {
        resetPage()
        header(R.string.autofill_auth_select_guidance)
        val approve = button(getString(R.string.autofill_auth_approve), R.id.autofill_auth_approve) { startApprove() }
        approve.isEnabled = false
        cancelButton(R.string.autofill_auth_cancel)
        status.text = getString(R.string.autofill_auth_refreshing)
        val stamp = stampOrNull()
        if (stamp == null) {
            showUnavailable()
            return
        }
        runWork(
            tag = "list",
            stamp = stamp,
            wipedOnRejection = {},
            task = { NativeFailures.call(NativePhase.REFRESH) { listActive() } },
            done = { result ->
                val logins = (result as? List<*>).orEmpty().filterIsInstance<ActiveLogin>()
                if (logins.isEmpty()) {
                    status.text = getString(R.string.autofill_auth_empty)
                } else {
                    status.text = getString(R.string.autofill_auth_active_count, logins.size)
                    // Metadata only; the title is the sole selection identity.
                    logins.forEachIndexed { index, login -> addRowButton(index, login, approve) }
                }
            },
        )
    }

    /** Active login metadata only (ID, revision, title); never a value. */
    private fun listActive(): List<ActiveLogin> {
        val owner = vault
        if (owner == null || !gate.isForeground()) {
            throw NativeCallFailure(NativePhase.REFRESH, NativeFailureCode.CLOSED)
        }
        val listed = owner.list("active")
        return (0 until listed.count()).mapNotNull { index ->
            val row: Row? = listed.at(index)
            if (row == null) null
            else ActiveLogin.of(row.getID(), row.getRevision(), row.getState(), row.getTitle())
        }
    }

    /**
     * Selection is by visible title only and reveals no value. Rows are
     * distinguished by their sanitized title plus a local display index, never
     * by the row ID (which stays in [ActiveLogin]).
     */
    private fun addRowButton(index: Int, login: ActiveLogin, approve: Button) {
        var row: Button? = null
        val created: Button = button(login.shownTitle, R.id.autofill_auth_row, primary = false) {
            if (lifecycle.isTerminal) return@button
            selected = login
            rowButtons.forEach { (candidate, _) -> candidate.text = candidate.contentDescription }
            row?.text = getString(R.string.autofill_auth_selected_title, login.shownTitle)
            status.text = getString(R.string.autofill_auth_selected, login.shownTitle)
            approve.isEnabled = true
        }
        created.contentDescription = getString(R.string.autofill_auth_row, index + 1, login.shownTitle)
        row = created
        rowButtons.add(created to login)
    }

    // ---- explicit approval --------------------------------------------------------

    private fun startApprove() {
        if (lifecycle.isTerminal) return
        val chosen = selected ?: return
        val expected = target ?: return
        val owner = vault ?: return
        val request = Target(chosen.rowId, chosen.rowRevision, "username,password")
        val stamp = stampOrNull(request) ?: return
        runWork(
            tag = "approve",
            stamp = stamp,
            target = request,
            wipedOnRejection = {},
            task = { current ->
                if (vault !== owner) throw NativeCallFailure(NativePhase.OPERATION, NativeFailureCode.CLOSED)
                var username: SecretValue? = null
                var password: SecretValue? = null
                var usernameBytes = ByteArray(0)
                var passwordBytes = ByteArray(0)
                var approved: ApprovedAutofillResult? = null
                try {
                    // Exact ID and revision must still be one active login.
                    val stillActive = NativeFailures.call(NativePhase.REFRESH) { listActive() }.any {
                        it.rowId == chosen.rowId && it.rowRevision == chosen.rowRevision
                    }
                    if (!stillActive) throw NativeCallFailure(NativePhase.REFRESH, NativeFailureCode.CONFLICT)
                    GuardedWork.ensureCurrent(gate, current, request)
                    username = NativeFailures.call(NativePhase.OPERATION) {
                        owner.revealField(chosen.rowId, chosen.rowRevision, "username")
                    }
                    GuardedWork.ensureCurrent(gate, current, request)
                    password = NativeFailures.call(NativePhase.OPERATION) {
                        owner.revealField(chosen.rowId, chosen.rowRevision, "password")
                    }
                    usernameBytes = username.take()
                        ?: throw NativeCallFailure(NativePhase.OPERATION, NativeFailureCode.EXPIRED)
                    passwordBytes = password.take()
                        ?: throw NativeCallFailure(NativePhase.OPERATION, NativeFailureCode.EXPIRED)
                    GuardedWork.ensureCurrent(gate, current, request)
                    // The approval copies into its own buffers; the source arrays
                    // and SecretValue handles are wiped below on every path.
                    approved = ApprovedAutofillResult.create(
                        target = expected,
                        rowId = chosen.rowId,
                        rowRevision = chosen.rowRevision,
                        username = usernameBytes,
                        password = passwordBytes,
                    )
                } catch (error: Exception) {
                    approved?.clear()
                    approved = null
                    throw error
                } finally {
                    usernameBytes.fill(0)
                    passwordBytes.fill(0)
                    runCatching { username?.clear() }
                    runCatching { password?.clear() }
                }
                approved
            },
            done = { result ->
                // The single synchronous delivery: the approval is taken once,
                // the BOUND handoff is consumed for this token, nonce and the
                // exact two ids, the result is built, every buffer is wiped and
                // the terminal result is returned in this same main-thread
                // callback.
                deliverApprovedResult(result, expected, chosen)
            },
        )
    }

    /**
     * The exact-response step, on main only, after the serialized worker bound,
     * rechecked and delivered the approval: the target, the selected row and its
     * revision must still be the same; the reviewed challenge must still be
     * this request's; the approval is taken exactly once and the two values
     * become AutofillValues inside a response built synchronously here. Every
     * approval/caller buffer is wiped before the result is returned. Only then
     * is the BOUND handoff retired for this token, the challenge's claimed
     * nonce and exactly the two OS AutofillIds; a refusal there retires the
     * record and ends in the ordinary cancel path. On success the fresh vault
     * is requested to lock synchronously and its one close is queued, then the
     * terminal result is set and the Activity finishes. Any other mismatch
     * zeroizes and ends in the ordinary cancel path as well.
     */
    private fun deliverApprovedResult(result: Any?, expected: AutofillTarget, chosen: ActiveLogin) {
        var approved = result as? ApprovedAutofillResult
        var taken: AutofillCredentialBytes? = null
        var username: CharArray? = null
        var password: CharArray? = null
        val response: FillResponse?
        val exactForm = LoginForm(expected.packageName, expected.usernameId, expected.passwordId)
        try {
            val sameTarget = target === expected
            val sameSelection = selected?.let { it.rowId == chosen.rowId && it.rowRevision == chosen.rowRevision } == true
            val challenge = AutofillChallenge.fromBundle(clientState())
            val reviewed = reviewedChallenge()
            if (!lifecycle.isTerminal && sameTarget && sameSelection && challenge != null && reviewed != null &&
                challenge.form == exactForm &&
                approved != null && !approved.isConsumed() && approved.target === expected &&
                approved.targetMatches(exactForm) &&
                AutofillFillResult.isFillable(expected)
            ) {
                taken = approved.take()
                if (taken != null) {
                    username = taken.takeUsername()
                    password = taken.takePassword()
                    response = try {
                        AutofillFillResult.build(
                            target = expected,
                            username = username,
                            password = password,
                            level = BuildAutofillFieldLevel,
                            presentation = NativeAutofillServicePort.presentation(packageName),
                        )
                    } catch (_: Exception) {
                        null
                    }
                    if (response != null && !AutofillHandoff.consume(handoffToken, challenge.clientNonce, exactForm)) {
                        // A refused handoff returns no fill at all; the finally
                        // block then wipes every approval/caller buffer.
                        failClosed()
                        return
                    }
                } else {
                    response = null
                }
            } else {
                response = null
            }
        } finally {
            // AutofillFillResult consumed (wiped) the two CharArrays; wipe any
            // copy left by a refused or throwing path and every other buffer.
            username?.fill('\u0000')
            password?.fill('\u0000')
            taken?.clear()
            approved?.clear()
            approved = null
        }
        if (response == null) {
            failClosed()
            return
        }
        // Terminal, once: this sets the only successful result and finishes.
        if (!lifecycle.end(LifecycleState.Terminal.APPROVED)) {
            failClosed()
            return
        }
        // Terminal: the gate now rejects any late open (only a free-close
        // cleanup runs for it), and onStop can no longer cancel this result.
        freshVault.exit()
        wipeUiSecrets()
        val success = AutofillAuthenticationResult.success(response)
        setResult(success.resultCode, success.copyData().toIntent())
        // Lock synchronously and queue the one close before finishing.
        requestLockAfterApproval(vault.also { vault = null })
        finish()
    }

    /**
     * Locks the vault this approval used synchronously on the main thread
     * before anything else can run on the worker, then queues exactly one close
     * there. A vault that a late open installs after this read is left to the
     * open task: [FreshVaultGate.install] already rejected it (the gate exited)
     * and that same worker locks and closes the unowned vault itself.
     */
    private fun requestLockAfterApproval(published: Vault?) {
        if (published == null) return
        runCatching { published.requestLock() }
        try {
            worker.execute { runCatching { published.close() } }
        } catch (_: RejectedExecutionException) {
            // A shut-down worker can run no native call; the lock above stands.
        }
    }

    override fun onPause() {
        super.onPause()
        // Never keep a revealed factor across a pause; the cleared fields stay
        // empty if the Activity returns foreground.
        masterPassword?.text?.clear()
        secretKey?.text?.clear()
    }

    // ---- native gateway -------------------------------------------------------------

    /**
     * Unlocks the fresh [Vault] with exactly the entered factors: no quick or
     * system unlock. Credential values never become Strings; the Secret Key
     * text is the shortest temporary the existing parseSecretKey API requires
     * and is not kept anywhere. Both caller CharArrays are zeroed on every
     * path, including a refused enqueue or a throwing native call.
     */
    private class NativeGateway(private val currentVault: () -> Vault?) : MobilecoreGateway {
        override fun unlock(outcome: ApprovalOutcome, password: CharArray, secretKey: CharArray) {
            try {
                val api = currentVault()
                if (api == null) {
                    outcome.fail(NativeCallFailure(NativePhase.UNLOCK, NativeFailureCode.CLOSED))
                    return
                }
                var decoded = ByteArray(0)
                var passwordBytes = ByteArray(0)
                try {
                    // The factor String below is a private, uninterned temporary.
                    decoded = try {
                        NativeFailures.call(NativePhase.UNLOCK) { Mobilecore.parseSecretKey(secretKey.concatToString()) }
                    } finally {
                        secretKey.fill('\u0000')
                    }
                    passwordBytes = try {
                        ApprovalSecret.encodeUtf8(password)
                    } finally {
                        password.fill('\u0000')
                    }
                    if (passwordBytes.isEmpty()) {
                        outcome.fail(NativeCallFailure(NativePhase.UNLOCK, NativeFailureCode.INVALID))
                        return
                    }
                    NativeFailures.call(NativePhase.UNLOCK) { api.unlock(passwordBytes, decoded) }
                } finally {
                    decoded.fill(0)
                    passwordBytes.fill(0)
                }
            } catch (error: Exception) {
                outcome.fail(error)
            } finally {
                password.fill('\u0000')
                secretKey.fill('\u0000')
            }
        }
    }
}
