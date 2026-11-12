package org.locklark.android

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.graphics.Rect
import android.os.SystemClock
import android.util.TypedValue
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.ViewParent
import android.view.WindowInsets
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.locklark.android.security.NativeFailureCode
import org.locklark.android.security.NativePhase
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.abs
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
    private val observedViewport = Rect()
    // Fixed scroll geometry of the current wait, reported by failWait().
    private val lastGeometry = AtomicReference<List<String>>(emptyList())
    private fun rememberGeometry(entries: List<String>) { lastGeometry.set(entries) }
    private var observedTicks = 0
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
    /** The app root that [appViewport] clips to; screen-to-content maps use it. */
    private fun appRoot(activity: MainActivity): View? =
        activity.findViewById<ViewGroup>(android.R.id.content)?.getChildAt(0)
    /**
     * Bounded scrollBy delta toward [target]: the target's viewport-local rect
     * (offsetDescendantRectToMyCoords) compared with [safe], the app-safe
     * screen rect mapped into the same local space; 0 also when the target is
     * in a nested scroller or the viewport is absent.
     */
    private fun scrollStep(activity: MainActivity, scroll: ScrollView, target: View, vertical: Boolean, safe: Rect): Int {
        val root = appRoot(activity) ?: return 0
        val targetRect = descendantRectInScroll(scroll, target) ?: return 0
        return boundedScrollStep(targetRect, safeLocalRect(scroll, safe, root), vertical)
    }
    // Geometry values are bounded so the diagnostic stays a fixed-size number.
    private fun frozen(value: Int): String = if (value in -999_999..999_999) value.toString() else "clamped"
    /**
     * Fixed numeric scroll geometry for failure context: the scroll offset, the
     * ScrollView's screen position, padding and scroll range, the app-safe
     * viewport mapped into viewport-local coordinates (viewport top/bottom)
     * and in screen coordinates (safe top/bottom) and the target's full
     * viewport-local rect and screen rect. Only coordinates and rectangle
     * sizes, never text.
     */
    private fun scrollContext(activity: MainActivity, scroll: ScrollView?, target: View?): List<String> {
        if (scroll == null || target == null) return listOf("scroll=none")
        val rect = descendantRectInScroll(scroll, target) ?: return listOf("scroll=detached")
        val location = IntArray(2).also { scroll.getLocationOnScreen(it) }
        val targetScreen = IntArray(2).also { target.getLocationOnScreen(it) }
        val screen = Rect(targetScreen[0], targetScreen[1], targetScreen[0] + target.width, targetScreen[1] + target.height)
        val viewport = Rect()
        if (!appViewport(activity, viewport)) return listOf("scroll=none")
        val visible = appRoot(activity)?.let { safeLocalRect(scroll, viewport, it) } ?: Rect()
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
    /**
     * Whether [target]'s full rect actually lies inside the app viewport of
     * [activity]; computing an app viewport alone is not enough. On success
     * [bounds] holds the target's full rect.
     */
    private fun targetInViewport(activity: MainActivity, target: View, bounds: Rect, viewport: Rect = Rect()): Boolean {
        if (!appViewport(activity, viewport)) return false
        return target.getGlobalVisibleRect(bounds) &&
            bounds.width() == target.width && bounds.height() == target.height && viewport.contains(bounds)
    }
    /** One bounded native scroll toward a visible target; [moved] is set only if the container scrolled. */
    private fun scrollToward(activity: MainActivity, target: View, moved: (Boolean) -> Unit): Boolean {
        // The editor's own ScrollView: its content coordinates, not a page one.
        val scroll = pageScroll(target) ?: return false
        val safe = Rect()
        if (!appViewport(activity, safe)) return false
        // A partially visible target gets a bounded step too, toward full
        // containment in the app-safe viewport.
        val down = scrollStep(activity, scroll, target, true, safe)
        val right = if (down == 0) scrollStep(activity, scroll, target, false, safe) else 0
        val scrolled = scrollPageStep(target, true, down) || scrollPageStep(target, false, right)
        moved(scrolled)
        return scrolled
    }
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
                        liveGeometry = scrollContext(activity, scroll, target)
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
                            val targetRect = descendantRectInScroll(scroll, target)
                            val safe = appRoot(activity)?.let { safeLocalRect(scroll, viewport, it) } ?: Rect()
                            val down = scrollStep(activity, scroll, target, true, viewport)
                            val right = if (down == 0) scrollStep(activity, scroll, target, false, viewport) else 0
                            var delta = if (down != 0) down else right
                            // A control larger than the app-safe viewport
                            // (or a step with no measurable geometry) can never
                            // be fully contained: no-progress must not loop
                            // into a step that only moves the overflow.
                            val oversized = targetRect == null || safe.isEmpty ||
                                targetRect.height() > safe.height() || targetRect.width() > safe.width()
                            if (oversized) delta = 0
                            val before = scrollOffset(scroll)
                            val moved = delta != 0 && scrollPageStep(target, down != 0, delta)
                            if (moved) {
                                awaitingScroll = true; beforeOffset = before; scrolledNow = true
                            } else if (!alignedOnce) {
                                // No movable step (an exhausted range, an
                                // oversized target, no owning scroller, or a
                                // control not laid out in it): one native
                                // alignment request remains.
                                target.requestRectangleOnScreen(Rect(0, 0, target.width, target.height), true)
                                alignedOnce = true
                            } else if (partial || oversized) {
                                // A partially visible or oversized control whose
                                // range and alignment were both exhausted can
                                // never be made fully visible: fail fast, and the
                                // full-rect targetInViewport gate stays closed.
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
    private fun focused(tag: String, moved: (Boolean) -> Unit = {}): Boolean {
        val resumed = scenario.state == androidx.lifecycle.Lifecycle.State.RESUMED
        var focused = false
        var scrolled = false
        scenario.onActivity { activity ->
            val target = activity.window.decorView.findViewWithTag<View>(tag)
            // Input editors get requestRectangleOnScreen below, never a coarse step.
            if (target != null) scrollToward(activity, target) { moved(it); if (it) scrolled = true }
            moved(scrolled)
            if (scrolled) return@onActivity
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
        controlPhase = "input-ready"
        waitUntil("Native input unavailable", deadline) { ready(tag) }
        // One real tap establishes native focus. Main-queue idleness alone does
        // not prove that the IME has switched its served InputConnection.
        click(tag, dismissKeyboard = false, deadline = deadline)
        controlPhase = "input-focus"
        // A grown multiline editor (or a taller IME) can leave the requested
        // editor fully offscreen; pageStep/scrollPageStep scroll natively first.
        waitUntil("Native input focus unavailable", deadline) {
            if (scenario.state == androidx.lifecycle.Lifecycle.State.RESUMED && !windowHasFocus()) ensureWindowFocus()
            var scrolled = false
            val ready = focused(tag) { scrolled = it }
            if (scrolled) { controlPhase = "scroll"; reportControl() }
            ready
        }
        scenario.onActivity { if (SystemClock.elapsedRealtime() < deadline) (it.window.decorView.findViewWithTag<View>(tag) as EditText).text.clear() }
        instrumentation.waitForIdleSync()
        waitUntil("Native input focus unavailable", deadline) { focused(tag) }
        controlPhase = "input-send"
        reportControl()
        if (SystemClock.elapsedRealtime() >= deadline) failWait("Native input delivery incomplete")
        // Full factors go through native keyboard events. Unicode note input
        // uses the native Editable in the test APK, never a product endpoint.
        if (value.isNotEmpty()) {
            if (value.all { it.code in 32..126 }) {
                if (windowHasFocus()) instrumentation.sendStringSync(value)
                instrumentation.waitForIdleSync()
                if (text(tag) != value) {
                    scenario.onActivity { if (SystemClock.elapsedRealtime() < deadline) (it.window.decorView.findViewWithTag<View>(tag) as? EditText)?.setText(value) }
                }
            } else {
                scenario.onActivity { if (SystemClock.elapsedRealtime() < deadline) (it.window.decorView.findViewWithTag<View>(tag) as EditText).setText(value) }
            }
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

    /**
     * Viewport-local bounded step: exact signs and the half-span clamp for
     * partial and far targets, monotone convergence under repeated
     * scrollBy deltas, and no-progress for a target larger than the viewport
     * (it can never be fully contained).
     */
    @Test fun boundedScrollStepHandlesNestedOffsetsAndEdges() {
        val visible = Rect(0, 0, 800, 1600)
        fun target(top: Int, bottom: Int) = Rect(0, top, 800, bottom)
        // Fully inside: 0.
        assertEquals(0, boundedScrollStep(target(900, 1000), visible))
        // Truncated at the top needs a negative delta, at the bottom positive;
        // the partial step is exactly the hidden part.
        assertEquals(-100, boundedScrollStep(target(-100, 100), visible))
        assertEquals(100, boundedScrollStep(target(1500, 1700), visible))
        // Far below: positive and never more than half the visible span.
        val farBelow = boundedScrollStep(target(2600, 3100), visible)
        assertTrue("Far target below must step down", farBelow > 0 && farBelow <= 800)
        // Far above: negative and never more than half the visible span.
        val farAbove = boundedScrollStep(target(-3000, -2500), visible)
        assertTrue("Far target above must step up", farAbove < 0 && farAbove >= -800)
        // Horizontal uses the same rule on x.
        val right = boundedScrollStep(Rect(1000, 0, 1200, 100), visible, false)
        assertTrue("Far target right must step right", right > 0 && right <= 800)
        // A degenerate viewport never produces a step.
        assertEquals(0, boundedScrollStep(target(1800, 1900), Rect(0, 1600, 800, 1600)))
        // Repeated deltas applied to the local rect (content moves by -delta)
        // shrink the overflow monotonically until full containment, for both
        // directions and a partial start.
        for (start in listOf(target(-100, 100), target(1500, 1700), target(2600, 3100), target(-3000, -2500))) {
            var current = Rect(start)
            var overflow = overflow(current, visible)
            assertTrue("A hidden target must overflow", overflow > 0)
            var steps = 0
            while (!visible.contains(current)) {
                val step = boundedScrollStep(current, visible)
                assertTrue("A step is needed while hidden", step != 0)
                assertTrue("A step never exceeds the half span", abs(step) <= 800)
                current.offset(0, -step)
                val next = overflow(current, visible)
                assertTrue("Each step must shrink the overflow ($start)", next < overflow || next == 0)
                overflow = next
                assertTrue("Bounded steps must converge", ++steps < 32)
            }
            assertEquals("Containment ends progress", 0, boundedScrollStep(current, visible))
        }
        // Larger than the visible span at both edges: no direction can make
        // it fully contained, so the step is a no-progress 0 and the rect is
        // never considered contained.
        for (oversized in listOf(target(-200, 1800), target(-100, 1900), target(0, 1700))) {
            assertTrue("An oversized target is never contained", !visible.contains(oversized))
            assertEquals("An oversized target gets no-progress", 0, boundedScrollStep(oversized, visible))
        }
    }
    /** Hidden extent of [target] beyond [visible] along y, 0 when contained. */
    private fun overflow(target: Rect, visible: Rect): Int =
        maxOf(0, visible.top - target.top) + maxOf(0, target.bottom - visible.bottom)
    /**
     * Real-layout regression for the bounded search: a detached tree with only
     * explicit sizes (a fixed row height and the ScrollView's own layout), so
     * its geometry is deterministic without inventing card arithmetic. The
     * actual scroll must carry the control from fully offscreen to visible by
     * bounded steps that never exceed its own extent, and converge.
     */
    @Test fun realNestedLayoutStepsTowardOffscreenControl() {
        val scroll = ScrollView(InstrumentationRegistry.getInstrumentation().targetContext)
        fun card() = LinearLayout(scroll.context).apply { orientation = LinearLayout.VERTICAL }
        val body = LinearLayout(scroll.context).apply { orientation = LinearLayout.VERTICAL }
        repeat(2) {
            body.addView(card().apply { repeat(3) { addView(TextView(scroll.context).apply { height = 96 }) } })
        }
        val target = TextView(scroll.context).apply { height = 96 }
        body.addView(card().apply { addView(TextView(scroll.context).apply { height = 96 }); addView(target) })
        scroll.addView(body)
        // A detached tree is never laid out by the system: measure and lay it
        // out at a fixed size so every nested offset is real.
        scroll.measure(View.MeasureSpec.makeMeasureSpec(360, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(420, View.MeasureSpec.EXACTLY))
        scroll.layout(0, 0, 360, 420)
        val safe = Rect(0, 0, 360, 420)
        // The formal regression's fixture is a detached ScrollView laid out by
        // hand; the detached mode is explicit and test-only, never used by the
        // controller's live click path.
        fun content() = safeLocalRect(scroll, safe, scroll, detached = true)
        fun targetRect() = descendantRectInScroll(scroll, target)!!
        val start = targetRect()
        assertTrue("Fixture control must start offscreen", !content().contains(start))
        assertTrue("It starts below the viewport", start.top >= content().bottom)
        val seen = mutableListOf<Int>()
        while (seen.size < 100 && !content().contains(targetRect())) {
            // The control may be fully below or only partially overlapped while
            // its bottom edge still overflows the safe viewport; either state
            // still needs a bounded step.
            assertTrue("The control must still overflow the viewport bottom",
                targetRect().bottom > content().bottom)
            val step = boundedScrollStep(targetRect(), content(), true)
            assertTrue("A downward step must stay positive", step > 0)
            assertTrue("A bounded step must move the ScrollView", scrollPageStep(target, true, step, { _, _ -> }))
            seen.add(scroll.scrollY)
        }
        assertTrue("Bounded steps must converge", seen.isNotEmpty() && seen.size < 100)
        assertEquals("Each step must advance", seen.size, seen.toSet().size)
        val reached = targetRect()
        assertTrue("A bounded step must reach the control", content().contains(reached))
        // Real scroll offsets moved it all the way from fully offscreen, and the
        // walk stopped only because it is now fully inside the app-safe viewport.
        assertTrue("Real scroll offsets accumulate", scroll.scrollY >= start.top - reached.top)
        val offset = start.top - scroll.scrollY - reached.top
        assertTrue("The control moved only by real offsets ($offset)", abs(offset) <= 1)
        assertEquals("The walk stopped only once visible", 0, boundedScrollStep(targetRect(), content(), true))
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
        val context = instrumentation.targetContext
        val owned = ownedSyntheticVaultPaths(context.noBackupFilesDir)
        // The target Activity owns exactly this path. Refuse before launching
        // unless every path cleanup may remove is absent. NOFOLLOW_LINKS also
        // treats a dangling symlink as present, so it is never overwritten or
        // deleted by this test.
        for (path in owned) {
            assertFalse("An existing target vault must not be overwritten",
                Files.exists(path.toPath(), LinkOption.NOFOLLOW_LINKS))
        }
        var failure: Throwable? = null
        try {
            runOfflineVaultFlow(context)
        } catch (error: Throwable) {
            failure = error
            throw error
        } finally {
            // The owning ActivityScenario is closed before any owned file is
            // removed; a close failure must not hide an earlier assertion.
            val closeFailure = runCatching {
                if (::scenario.isInitialized) scenario.close()
                instrumentation.waitForIdleSync()
            }.exceptionOrNull()
            if (closeFailure != null) {
                if (failure == null) throw closeFailure
                failure.addSuppressed(closeFailure)
            } else {
                runCleanup(failure) {
                    deleteOwnedSyntheticVault(owned, context.noBackupFilesDir)
                }
            }
        }
    }

    private fun runOfflineVaultFlow(context: Context) {
        val random = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val master = record("Android-Master-$random")
        val password = record("Android-Password-$random")
        val changed = record("Android-Edited-$random")
        val username = record("Android-User-$random")
        val notes = record("合成原生备注🔐\n$random\n保留末行  \n")
        val seed = record("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        var flowFailure: Throwable? = null
        try {
            scenario = ActivityScenario.launch(MainActivity::class.java)
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
        } catch (error: Throwable) {
            flowFailure = error
            throw error
        } finally {
            // Close the final scenario here without masking a body failure; the
            // caller removes the owned vault only after this close succeeds.
            runCleanup(flowFailure) {
                if (::scenario.isInitialized) scenario.close()
            }
        }
    }

    /** Reports only fixed numeric scroll geometry; no label or entered text. */
    private fun reportGeometry(scroll: ScrollView?, target: View?) {
        var entries = listOf("scroll=none")
        scenario.onActivity { entries = scrollContext(it, scroll, target) }
        instrumentation.sendStatus(0, android.os.Bundle().apply { putString("locklark_scroll", entries.joinToString(" ")) })
        rememberGeometry(entries)
    }

    /**
     * Runs cleanup without masking an earlier test failure. A cleanup failure
     * is the test failure only when the body did not already fail.
     */
    private fun runCleanup(primary: Throwable?, step: () -> Unit) {
        val cleanupFailure = runCatching(step).exceptionOrNull() ?: return
        if (primary == null) throw cleanupFailure
        primary.addSuppressed(cleanupFailure)
    }

    /**
     * Exact paths this exclusive test run may remove. `personal.Create` stages
     * a random `.locklark-personal-*` temporary file and publishes
     * `personal.ll` by a non-replacing rename; it does not create fixed
     * `.new`/`.bak` sidecars, so none may be treated as owned here.
     */
    private fun ownedSyntheticVaultPaths(parent: File): List<File> =
        listOf(File(parent, "personal.ll"))

    /**
     * Deletes only the preflight-confirmed synthetic target vault. The
     * canonical parent, exact-name and non-symlink checks keep this from
     * touching `device-unlock`, parent directories or any other shared entry.
     */
    private fun deleteOwnedSyntheticVault(paths: List<File>, parent: File) {
        val canonicalParent = parent.canonicalFile
        require(paths.size == 1 && paths.single().name == "personal.ll") { "Owned vault set mismatch" }
        for (path in paths) {
            require(path.canonicalFile.parentFile == canonicalParent) { "Owned vault escaped its directory" }
            require(!Files.isSymbolicLink(path.toPath())) { "Owned vault must not be a symbolic link" }
            if (!Files.exists(path.toPath(), LinkOption.NOFOLLOW_LINKS)) continue
            require(!Files.isDirectory(path.toPath(), LinkOption.NOFOLLOW_LINKS)) { "Owned vault must be a file" }
            if (!Files.deleteIfExists(path.toPath())) throw IOException("Owned vault cleanup failed")
        }
    }
}
