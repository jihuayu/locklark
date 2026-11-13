package org.locklark.android

import android.graphics.Rect
import android.os.SystemClock
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicReference

/**
 * Real-device scroll probe. It is NOT part of the formal BoundOperationTest +
 * OfflineVaultTest selector and is run alone by the scroll investigation. It
 * drives the real MainActivity detail/OTP flow through the same native helpers
 * as [OfflineVaultTest] and reports only fixed numeric scroll geometry.
 */
@RunWith(AndroidJUnit4::class)
class ScrollProbeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val canaries = mutableListOf<String>()
    private lateinit var scenario: ActivityScenario<MainActivity>
    private var currentControl = "unknown"
    private var controlPhase = "ready"
    private var imeHideRequested = false
    private val observedViewport = Rect()
    private val lastGeometry = AtomicReference<List<String>>(emptyList())
    private fun rememberGeometry(entries: List<String>) { lastGeometry.set(entries) }
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
    private var observedTicks = 0

    // ---- shared controller helpers (the same native path OfflineVaultTest uses) ----
    private fun windowHasFocus(): Boolean {
        var focused = false
        scenario.onActivity { focused = it.hasWindowFocus() }
        return focused
    }
    private fun ensureWindowFocus() {
        for (command in listOf("wm dismiss-keyguard", "am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS")) {
            try {
                android.os.ParcelFileDescriptor.AutoCloseInputStream(
                    instrumentation.uiAutomation.executeShellCommand(command)
                ).use { it.readBytes() }
            } catch (_: Exception) {}
        }
        scenario.onActivity { activity -> activity.window.decorView.requestFocus() }
    }
    private fun waitFor(message: String, test: () -> Boolean) =
        waitUntil(message, SystemClock.elapsedRealtime() + 180_000, test)
    private fun waitUntil(message: String, deadline: Long, test: () -> Boolean) {
        instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_wait", "probe") })
        while (SystemClock.elapsedRealtime() < deadline) {
            val satisfied = test()
            val observedAt = SystemClock.elapsedRealtime()
            if (observedAt >= deadline) break
            if (satisfied) return
            SystemClock.sleep(minOf(100L, deadline - observedAt))
        }
        failWait(message)
    }
    private fun failWait(message: String): Nothing {
        reportControl()
        // The current control tag (fixed vocabulary) names the failing wait.
        throw AssertionError("$message [$currentControl]")
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
    private fun ready(tag: String): Boolean {
        val current = view(tag)
        return current?.isEnabled == true && current.isLaidOut && current.width > 0 && current.height > 0
    }
    private fun click(tag: String, dismissKeyboard: Boolean = true, deadline: Long = SystemClock.elapsedRealtime() + 180_000) {
        currentControl = tag
        controlPhase = "ready"
        imeHideRequested = false
        observedViewport.setEmpty(); observedTicks = 0
        waitUntil("Native control unavailable", deadline) { ready(tag) }
        val bounds = Rect()
        val viewport = Rect()
        var previousBounds = Rect()
        var previousViewport = Rect()
        var previousVisible = false
        // Set when a bounded ScrollView.scrollBy or alignment was just issued, so
        // the next observation can tell real container movement from a stuck
        // range instead of waiting out the deadline.
        var awaitingScroll = false
        // The ScrollView offset captured BEFORE the last bounded scrollBy, and
        // whether the target was partially visible when it was requested. A
        // successful scroll changes the offset, so it is never mistaken for a
        // stall.
        var beforeOffset = Long.MIN_VALUE
        var partial = false
        // A control gets at most one native alignment request, only when a
        // measured bounded step found no movable range. A second exhausted
        // observation fails at once instead of re-requesting.
        var alignedOnce = false
        // The last live observation, attached to a failed wait so the
        // diagnostic shows why the control was not clickable.
        var liveGeometry: List<String> = emptyList()
        // IME appearance and padding/layout can arrive after a prior idle
        // observation. React to actual visibility while waiting, not only once
        // at entry. Only the owned window receives one hide request; BACK could
        // navigate if the keyboard disappeared between observation and delivery.
        waitUntil("Native control not visible", deadline) {
            val resumed = scenario.state == androidx.lifecycle.Lifecycle.State.RESUMED
            if (resumed && !windowHasFocus()) ensureWindowFocus()
            var visible = false
            var ime: Boolean? = null
            var requestedNow = false
            var scrolledNow = false
            var inViewport = false
            var stalled = false
            scenario.onActivity { activity ->
                if (SystemClock.elapsedRealtime() >= deadline) return@onActivity
                val target = activity.window.decorView.findViewWithTag<View>(tag)
                ime = activity.window.decorView.rootWindowInsets?.isVisible(WindowInsets.Type.ime())
                if (ime == null) return@onActivity
                if (dismissKeyboard && ime == true) {
                    if (!imeHideRequested && (activity.hasWindowFocus() || resumed) && SystemClock.elapsedRealtime() < deadline) {
                        activity.window.insetsController?.let { controller ->
                            imeHideRequested = true
                            requestedNow = true
                            controller.hide(WindowInsets.Type.ime())
                        }
                    }
                } else if (target != null && target.isEnabled && target.isShown &&
                    (activity.hasWindowFocus() || resumed) &&
                    appViewport(activity, viewport)) {
                    val scroll: ScrollView? = pageScroll(target)
                    // inViewport is only set when the control's own rect lies inside the
                    // app viewport, not merely because an app viewport was computed.
                    val shown = targetInViewport(activity, target, bounds, viewport)
                    inViewport = shown
                    val active = activity.hasWindowFocus() || resumed
                    if (shown) {
                        visible = true
                    } else if (active && SystemClock.elapsedRealtime() < deadline) {
                        liveGeometry = scroll?.let { scrollContext(activity, it, target) } ?: emptyList()
                        // A previously issued bounded scrollBy succeeded only if
                        // the container offset really differs from the one read
                        // before the request; otherwise the range is exhausted.
                        val pending = awaitingScroll
                        val movedNow = scroll != null && pending && scrollOffset(scroll) != beforeOffset
                        if (pending && !movedNow) {
                            // One bounded request was issued and could not move
                            // the container: fail fast instead of the deadline.
                            stalled = true
                        } else if (movedNow) {
                            awaitingScroll = false; scrolledNow = true
                        } else if (scroll == null) {
                            // No owning ScrollView: the native alignment
                            // request stays the only path, once.
                            if (!alignedOnce) {
                                target.requestRectangleOnScreen(Rect(0, 0, target.width, target.height), true)
                                alignedOnce = true
                            }
                        } else {
                            // Every not-yet-contained control now receives one
                            // bounded ScrollView.scrollBy toward the app-safe
                            // viewport, including a partially visible one whose
                            // rect crosses an inset edge.
                            partial = overlaps(bounds, viewport)
                            val down = scrollStep(activity, scroll, target, true, viewport)
                            val right = if (down == 0) scrollStep(activity, scroll, target, false, viewport) else 0
                            val delta = if (down != 0) down else right
                            val before = scrollOffset(scroll)
                            val moved = delta != 0 && scrollPageStep(target, down != 0, delta)
                            if (moved) {
                                awaitingScroll = true; beforeOffset = before; scrolledNow = true
                            } else if (!alignedOnce) {
                                // The bounded step found no movable range (an
                                // exhausted range, no owning scroller, or a
                                // control not laid out in it): one native
                                // alignment request remains.
                                target.requestRectangleOnScreen(Rect(0, 0, target.width, target.height), true)
                                alignedOnce = true
                            } else if (partial) {
                                // A partially visible control whose range and
                                // alignment were both exhausted can never be
                                // made fully visible: fail fast.
                                stalled = true
                            }
                            // A fully offscreen control with no movable range is
                            // still being laid out: the next observation
                            // re-measures it.
                        }
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
                rememberGeometry(liveGeometry)
                previousBounds.setEmpty(); previousViewport.setEmpty()
                previousVisible = false
                controlPhase = "scroll"
                return@waitUntil false
            }
            // An enabled control outside the app viewport is pending real
            // scrolling, not a product failure; report its own phase. A
            // partially visible control that a pending bounded request left
            // unmoved (its range is exhausted) can never reach the viewport:
            // fail at once instead of re-requesting or waiting for the deadline.
            controlPhase = if (inViewport) "visibility" else if (stalled) "clipped" else "offscreen"
            // Only a stable full-rect observation inside the settled app viewport
            // is a click target.
            val stable = visible && previousVisible && bounds == previousBounds && viewport == previousViewport &&
                scrollComplete(viewport)
            if (!stable) rememberGeometry(liveGeometry)
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
    /**
     * True when inset-driven relayout (IME-safe padding) has stopped changing
     * the app viewport, so a stable full-rect observation is a real click.
     */
    private fun scrollComplete(viewport: Rect): Boolean {
        if (viewport.isEmpty) {
            viewport.set(observedViewport); observedTicks = 0
            return false
        }
        if (viewport == observedViewport) observedTicks += 1 else { observedViewport.set(viewport); observedTicks = 0 }
        return observedTicks >= 2
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
            putString("locklark_scroll", lastGeometry.get().joinToString(" ") { it })
        }
        scenario.onActivity { activity ->
            val target = activity.window.decorView.findViewWithTag<View>(currentControl)
            val viewport = Rect()
            diagnostic.putString("locklark_ime", activity.window.decorView.rootWindowInsets?.isVisible(WindowInsets.Type.ime())?.toString() ?: "unknown")
            diagnostic.putString("locklark_window_focus", activity.hasWindowFocus().toString())
            diagnostic.putString("locklark_control_present", (target != null).toString())
            diagnostic.putString("locklark_control_enabled", (target?.isEnabled == true).toString())
            diagnostic.putString("locklark_control_visible", (target != null && targetInViewport(activity, target, Rect(), viewport)).toString())
            diagnostic.putString("locklark_control_focused", (target != null && activity.currentFocus === target && target.hasFocus()).toString())
            diagnostic.putString("locklark_input_active", (target is EditText && activity.getSystemService(InputMethodManager::class.java)?.isActive(target) == true).toString())
        }
        instrumentation.sendStatus(0, diagnostic)
    }
    private fun appRoot(activity: MainActivity): View? =
        activity.findViewById<ViewGroup>(android.R.id.content)?.getChildAt(0)
    private fun appViewport(activity: MainActivity, viewport: Rect): Boolean {
        if (activity.window.decorView.rootWindowInsets == null) return false
        activity.window.decorView.getWindowVisibleDisplayFrame(viewport)
        val root = appRoot(activity) ?: return false
        val inner = Rect()
        if (!root.getGlobalVisibleRect(inner)) return false
        inner.set(inner.left + root.paddingLeft, inner.top + root.paddingTop,
            inner.right - root.paddingRight, inner.bottom - root.paddingBottom)
        return !inner.isEmpty && viewport.intersect(inner)
    }
    /** Full-rect app-safe containment: global-visible bounds inside the screen viewport. */
    private fun targetInViewport(activity: MainActivity, target: View, bounds: Rect, viewport: Rect = Rect()): Boolean {
        if (!appViewport(activity, viewport)) return false
        return target.getGlobalVisibleRect(bounds) &&
            bounds.width() == target.width && bounds.height() == target.height && viewport.contains(bounds)
    }
    private fun scrollStep(activity: MainActivity, scroll: ScrollView, target: View, vertical: Boolean, safe: Rect): Int {
        val root = appRoot(activity) ?: return 0
        val targetRect = descendantRectInScroll(scroll, target) ?: return 0
        return boundedScrollStep(targetRect, safeLocalRect(scroll, safe, root), vertical)
    }
    private fun scrollContext(activity: MainActivity, scroll: ScrollView, target: View): List<String> {
        val rect = descendantRectInScroll(scroll, target) ?: return listOf("scroll=none")
        val location = IntArray(2).also { scroll.getLocationOnScreen(it) }
        val targetScreen = IntArray(2).also { target.getLocationOnScreen(it) }
        val screen = Rect(targetScreen[0], targetScreen[1], targetScreen[0] + target.width, targetScreen[1] + target.height)
        val viewport = Rect()
        if (!appViewport(activity, viewport)) return listOf("scroll=none")
        val visible = appRoot(activity)?.let { safeLocalRect(scroll, viewport, it) } ?: Rect()
        fun frozen(value: Int) = if (value in -999_999..999_999) value.toString() else "clamped"
        return listOf(
            "scroll_y=" + frozen(scroll.scrollY),
            "scroll_span=" + frozen(visible.height()),
            "scroll_range=" + frozen(maxOf(0, scroll.getChildAt(0)?.height?.minus(scroll.height) ?: 0)),
            "scroll_top=" + frozen(location[1]),
            "scroll_height=" + frozen(scroll.height),
            "scroll_pad_top=" + frozen(scroll.paddingTop),
            "scroll_pad_bottom=" + frozen(scroll.paddingBottom),
            "viewport_top=" + frozen(visible.top),
            "viewport_bottom=" + frozen(visible.bottom),
            "safe_top=" + frozen(viewport.top),
            "safe_bottom=" + frozen(viewport.bottom),
            "target_top=" + frozen(rect.top),
            "target_bottom=" + frozen(rect.bottom),
            "screen_top=" + frozen(screen.top),
            "screen_bottom=" + frozen(screen.bottom),
        )
    }
    /** One bounded native scroll toward a visible target (the controller's path). */
    private fun scrollToward(activity: MainActivity, target: View, moved: (Boolean) -> Unit): Boolean {
        val scroll = pageScroll(target) ?: return false
        val safe = Rect()
        if (!appViewport(activity, safe)) return false
        val down = scrollStep(activity, scroll, target, true, safe)
        val right = if (down == 0) scrollStep(activity, scroll, target, false, safe) else 0
        val scrolled = scrollPageStep(target, true, down) || scrollPageStep(target, false, right)
        moved(scrolled)
        return scrolled
    }
    private fun focused(tag: String, moved: (Boolean) -> Unit = {}): Boolean {
        val resumed = scenario.state == androidx.lifecycle.Lifecycle.State.RESUMED
        var focused = false
        scenario.onActivity { activity ->
            val target = activity.window.decorView.findViewWithTag<View>(tag)
            if (target != null && !targetInViewport(activity, target, Rect())) scrollToward(activity, target) { moved(it) }
            if (target is EditText && (activity.hasWindowFocus() || resumed) && !(activity.currentFocus === target && target.hasFocus())) {
                target.requestFocus()
            }
            focused = target is EditText && target.isEnabled && target.isAttachedToWindow &&
                (activity.hasWindowFocus() || resumed) &&
                (activity.currentFocus === target || target.hasFocus())
        }
        return focused
    }
    private fun enter(tag: String, value: String) {
        val deadline = SystemClock.elapsedRealtime() + 180_000
        currentControl = tag
        waitUntil("Native input unavailable", deadline) { ready(tag) }
        click(tag, dismissKeyboard = false, deadline = deadline)
        waitUntil("Native input focus unavailable", deadline) {
            if (scenario.state == androidx.lifecycle.Lifecycle.State.RESUMED && !windowHasFocus()) ensureWindowFocus()
            focused(tag)
        }
        scenario.onActivity { (it.window.decorView.findViewWithTag<View>(tag) as EditText).text.clear() }
        instrumentation.waitForIdleSync()
        waitUntil("Native input focus unavailable", deadline) { focused(tag) }
        if (SystemClock.elapsedRealtime() >= deadline) failWait("Native input delivery incomplete")
        scenario.onActivity { (it.window.decorView.findViewWithTag<View>(tag) as EditText).setText(value) }
        instrumentation.waitForIdleSync()
        waitUntil("Native input delivery incomplete", deadline) { text(tag) == value }
    }
    private fun edit(field: Int, value: String) {
        click("edit-login"); waitFor("Editor unavailable") { ready("edit-value") }
        scenario.onActivity { (it.window.decorView.findViewWithTag<View>("edit-field") as Spinner).setSelection(field) }
        enter("edit-value", value); click("save-field"); waitFor("Saved list unavailable") { ready("new-login") }
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
    private fun shown(tag: String): String {
        click(tag); waitFor("Explicit disclosure unavailable") { text("secret-value").isNotEmpty() }
        return text("secret-value")
    }

    /**
     * Real MainActivity detail page with the OTP field shown. Everything is
     * read in the owning ScrollView's viewport-local coordinates: the target
     * rect from offsetDescendantRectToMyCoords minus the receiver's own scroll
     * (the API excludes it) and the app-safe screen viewport mapped by
     * safeLocalRect (screen intersection with the app root, minus the
     * ScrollView's screen origin, clamped to the padding box).
     *
     * Fixture: this probe needs the owned emulator to run with a real
     * partially-overlapping target, provided OUTSIDE the product by
     * `adb -s emulator-5580 shell wm size 1080x1600` (restored to the physical
     * size afterwards). Neither production logic nor the actual page changes
     * for it. The measured fixture asserts a real positive scroll range, a
     * target whose full rect is NOT inside the safe viewport, and a nonzero
     * step; scrollTo is never used to pre-reveal the target.
     *
     * Right after one bounded ScrollView.scrollBy the real offset change, the
     * target's opposite displacement and the safe full containment are
     * asserted (scrollBy moves content by -delta), and the moved state must
     * pass the same full-rect app-safe containment the controller uses; the
     * post-scroll fixed geometry is reported as a second locklark_scroll state
     * so a reviewer can see scrollY and the target's viewport-local top both
     * move. The original offset is restored before the original physical
     * press path continues to the saved list. Only fixed numeric geometry is
     * reported, never a label or an entered value.
     */
    @Test fun realDetailScrollByMovesControlIntoAppViewport() {
        val random = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val master = record("Android-Scroll-Master-$random")
        val password = record("Android-Scroll-Password-$random")
        val username = record("Android-Scroll-User-$random")
        val seed = record("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            ensureWindowFocus()
            waitFor("Initial create unavailable") { ready("generate-account-key") }
            stage("create"); click("generate-account-key")
            waitFor("Account key unavailable") { text("backup-secret-key").startsWith("LL") }
            val key = record(text("backup-secret-key"))
            enter("new-master-password", master); enter("repeat-master-password", master)
            click("backup-ack"); click("create-vault")
            waitFor("New vault list unavailable") { ready("new-login") }
            stage("add-login"); click("new-login")
            enter("login-title", "Android scroll"); enter("login-username", username)
            // The generated-password checkbox disables the password field, so a
            // fixed password is only typed with generation switched off.
            scenario.onActivity { activity ->
                (activity.window.decorView.findViewWithTag<View>("generate-password") as android.widget.CheckBox).isChecked = false
            }
            enter("login-password", password); click("save-login")
            // The real main flow opens the detail page first; edit-login only
            // exists there, so saving alone is not on the edit path.
            select("Android scroll")
            stage("edit-otp"); edit(4, seed); select("Android scroll")
            stage("show-otp"); shown("show-otp")
            // Let the keyboard disappear and the grown content settle so the
            // probe reads the resting geometry, not a transition frame.
            waitUntil("Detail unavailable", SystemClock.elapsedRealtime() + 180_000) {
                var settled = false
                scenario.onActivity { activity ->
                    settled = activity.window.decorView.rootWindowInsets?.isVisible(WindowInsets.Type.ime()) == false &&
                        activity.window.decorView.findViewWithTag<View>("back-to-list") != null
                }
                settled
            }
            SystemClock.sleep(500)
            // start/end/safe are viewport-local rects of the owning ScrollView.
            var start = Rect(); var end = Rect(); var safe = Rect()
            var step = 0; var realMove = 0; var endInside = false
            var measured: Throwable? = null
            scenario.onActivity { activity ->
                try {
                    val target = activity.window.decorView.findViewWithTag<View>("back-to-list")
                        ?: throw AssertionError("Native control not visible")
                    val scroll = pageScroll(target) ?: throw AssertionError("App viewport unavailable")
                    val root = appRoot(activity) ?: throw AssertionError("App root unavailable")
                    val viewport = Rect()
                    if (!appViewport(activity, viewport)) throw AssertionError("App viewport unavailable")
                    // The probe runs on the live detail page, never detached.
                    safe = safeLocalRect(scroll, viewport, root)
                    // Fixed numeric geometry diagnostic, never text.
                    instrumentation.sendStatus(0, android.os.Bundle().apply {
                        putString("locklark_scroll", scrollContext(activity, scroll, target).joinToString(" "))
                    })
                    // Fixture preconditions: the probe only proves the scroll
                    // fix against a real partially-overlapping target.
                    val range = maxOf(0, (scroll.getChildAt(0)?.height ?: 0) - scroll.height)
                    assertTrue("The fixture must have a real positive scroll range", range > 0)
                    assertTrue("The safe viewport must be non-empty", !safe.isEmpty)
                    start = descendantRectInScroll(scroll, target) ?: throw AssertionError("Native control not visible")
                    assertTrue("The target must not start fully inside the safe viewport", !safe.contains(start))
                    step = scrollStep(activity, scroll, target, true, viewport)
                    assertTrue("The fixture must need a nonzero scroll step", step != 0)
                    val fromY = scroll.scrollY
                    scroll.scrollBy(0, step)
                    // Read the outcome of exactly this one scrollBy at once.
                    realMove = scroll.scrollY - fromY
                    end = descendantRectInScroll(scroll, target) ?: start
                    endInside = targetInViewport(activity, target, Rect())
                    // Post-scroll fixed geometry: scrollY and the target's
                    // viewport-local top must both differ from the pre-scroll state.
                    instrumentation.sendStatus(0, android.os.Bundle().apply {
                        putString("locklark_scroll", scrollContext(activity, scroll, target).joinToString(" "))
                    })
                    try {
                        if (step == 0) {
                            assertEquals("An in-view control must not scroll", 0, realMove)
                            assertEquals("An in-view control must stay put", start, end)
                            assertTrue("An in-view control must pass the full-rect check", endInside)
                        } else {
                            assertEquals("scrollBy must move the ScrollView by the step", step, realMove)
                            // scrollBy moves content by the opposite of delta.
                            assertEquals("The target must move by exactly the opposite delta", -realMove, end.top - start.top)
                            assertEquals("The target must keep its horizontal position", start.left, end.left)
                            // Sign: truncated at the top moves down, at the
                            // bottom (or beyond) moves up.
                            if (start.top < safe.top) assertTrue("The target must move down", end.top > start.top)
                            else assertTrue("The target must move up", end.top < start.top)
                            assertTrue("The moved target must be fully inside the app-safe viewport", safe.contains(end))
                            assertTrue("The moved target must pass the app-safe full-rect check", endInside)
                        }
                    } finally {
                        // Restore the original offset before the physical press.
                        if (realMove != 0) scroll.scrollTo(scroll.scrollX, fromY.toInt())
                    }
                } catch (error: Throwable) {
                    measured = error
                }
            }
            measured?.let { throw it }
            // The original physical press path then has to bring the control
            // into view itself and return to the saved list.
            click("back-to-list")
            waitFor("Saved list unavailable") { ready("new-login") }
        } finally { scenario.close() }
    }
}
