package org.locklark.android

import android.graphics.Rect
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Optional, individually selectable mapping checks for the bounded scroll
 * used by [OfflineVaultTest]. This class is NOT part of the formal
 * BoundOperationTest + OfflineVaultTest selector. The fixtures are detached
 * ScrollViews laid out at a fixed size; [safeLocalRect] is called with
 * `detached = true`, which only affects these fixtures, never the live click
 * path.
 */
@RunWith(AndroidJUnit4::class)
class ScrollGeometryTest {
    /**
     * A fresh detached ScrollView per test; a ScrollView keeps its "cannot
     * scroll" flag from an earlier pass, so one layout per test is exact.
     */
    /**
     * A detached ScrollView; [safeLocalRect] with `detached = true` is an
     * explicit test-only deterministic mode, the live click path always
     * checks the real attached/shown target.
     */
    private fun scrollView() = ScrollView(InstrumentationRegistry.getInstrumentation().targetContext)
    /** Lays [scroll] out detached at [width]x[height], as the system would. */
    private fun layout(scroll: ScrollView, width: Int, height: Int) {
        scroll.measure(View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY))
        scroll.layout(0, 0, width, height)
    }
    /** A detached [scroll] of [height] with [padding] and [content] rows of 100. */
    private fun rows(scroll: ScrollView, height: Int, content: Int, padding: Rect = Rect()) {
        val body = LinearLayout(scroll.context).apply { orientation = LinearLayout.VERTICAL }
        repeat(content) { body.addView(TextView(scroll.context).apply { this.height = 100 }) }
        scroll.addView(body)
        scroll.setPadding(padding.left, padding.top, padding.right, padding.bottom)
        layout(scroll, 400, height)
    }
    /** The controller's step on a detached fixture. */
    private fun step(scroll: ScrollView, target: View, safe: Rect) =
        boundedScrollStep(descendantRectInScroll(scroll, target)!!, safeLocalRect(scroll, safe, scroll, detached = true))
    /**
     * The app-safe screen rect mapped into the ScrollView's viewport-local
     * coordinates: screen edge minus the ScrollView's screen origin, clamped
     * to the padding box; the target rect is offsetDescendantRectToMyCoords,
     * which already subtracts scrollY. Both share the one local system.
     */
    @Test fun safeViewportMapsIntoSameViewportLocalCoordinates() {
        val scroll = scrollView()
        rows(scroll, height = 1000, content = 20)
        val screenTop = IntArray(2).also { scroll.getLocationOnScreen(it) }[1]
        // Rect.intersect mutates the screen rects it is given, so each call
        // builds fresh ones from the ScrollView's screen origin.
        fun safe(from: Int, to: Int) = Rect(0, screenTop + from, 400, screenTop + to)
        // A safe window from 60% of the ScrollView to its bottom is local
        // 600..1000, not a content rect.
        assertEquals(Rect(0, 600, 400, 1000), safeLocalRect(scroll, safe(600, 1000), scroll, detached = true))
        val body = scroll.getChildAt(0) as LinearLayout
        // offsetDescendantRectToMyCoords composes the ancestor scrollY: the
        // same rows are local 600..700 and 1200..1300.
        assertEquals(Rect(0, 600, 400, 700), descendantRectInScroll(scroll, body.getChildAt(6)))
        assertEquals(Rect(0, 1200, 400, 1300), descendantRectInScroll(scroll, body.getChildAt(12)))
        // One bounded scrollBy moves the real offset by exactly its delta
        // (read from the return value; a detached view is not invalidated for
        // a later layout pass).
        assertEquals(600, boundedScrollTo(scroll, body.getChildAt(12), true, 600).second)
        assertEquals(600, scroll.scrollY)
        // The step is a local-space delta and never depends on the offset, so
        // it is identical for the same local rects after the scroll. Row 12
        // (local 1200) is pulled up by its own 100 only, and a row inside the
        // local window (700..800) needs no step.
        assertEquals(100, boundedScrollStep(Rect(0, 1200, 400, 1300), safeLocalRect(scroll, safe(600, 1000), scroll, detached = true)))
        assertEquals(0, boundedScrollStep(Rect(0, 700, 400, 800), safeLocalRect(scroll, safe(600, 1000), scroll, detached = true)))
        // The mapping is a pure function of the local inputs: asking twice
        // gives the same local window.
        assertEquals(safeLocalRect(scroll, safe(600, 1000), scroll, detached = true),
            safeLocalRect(scroll, safe(600, 1000), scroll, detached = true))
        // The map never uses global-visible bounds: a detached fixture has
        // none, yet its deterministic local window is still mapped.
        assertEquals(Rect(0, 600, 400, 1000), safeLocalRect(scroll, safe(600, 1000), scroll, detached = true))
    }
    /**
     * An app-safe edge over the ScrollView's exposed (non-clipping) padding is
     * clamped to the padding box, and a root smaller than the safe rect clips
     * it in screen coordinates before the map into local coordinates.
     */
    @Test fun safeViewportClampsToScrollPadding() {
        val scroll = scrollView()
        rows(scroll, height = 1000, content = 20, padding = Rect(0, 88, 0, 120))
        val top = IntArray(2).also { scroll.getLocationOnScreen(it) }[1]
        val whole = Rect(0, 0, 400, top + 1500)
        assertEquals(Rect(0, 88, 400, 880), safeLocalRect(scroll, whole, scroll, detached = true))
        // A root ending at screen top + 300 (same origin as the ScrollView)
        // limits the local window to the padding box up to 300.
        val root = object : View(scroll.context) {
            override fun getLocationOnScreen(outLocation: IntArray) {
                outLocation[0] = 0; outLocation[1] = top
            }
        }.apply { layout(0, 0, 400, 300) }
        assertEquals(Rect(0, 88, 400, 300), safeLocalRect(scroll, whole, root, detached = true))
    }
    /**
     * Detached-layout regression: a real nested tree (ScrollView -> body ->
     * cards -> control) laid out at a fixed size, so
     * offsetDescendantRectToMyCoords composes every nested offset and the
     * control starts fully offscreen, below the local viewport map.
     */
    @Test fun realNestedLayoutStepsTowardOffscreenControl() {
        val scroll = scrollView()
        fun card() = LinearLayout(scroll.context).apply { orientation = LinearLayout.VERTICAL }
        val body = LinearLayout(scroll.context).apply { orientation = LinearLayout.VERTICAL }
        repeat(2) {
            body.addView(card().apply { repeat(3) { addView(TextView(scroll.context).apply { height = 96 }) } })
        }
        val target = TextView(scroll.context).apply { height = 96 }
        body.addView(card().apply { addView(TextView(scroll.context).apply { height = 96 }); addView(target) })
        scroll.addView(body)
        layout(scroll, 360, 420)
        val safe = Rect(0, 0, 360, 420)
        val visible = safeLocalRect(scroll, safe, scroll, detached = true)
        assertEquals("The safe window is the whole local viewport", Rect(0, 0, 360, 420), visible)
        val start = descendantRectInScroll(scroll, target)!!
        assertEquals("The control height is real", 96, start.height())
        assertTrue("Nested offsets compose past the viewport bottom", start.top >= visible.bottom)
        assertTrue("The control starts fully below the viewport", !visible.contains(start))
        // The hidden overflow is measured, not assumed: the whole control when
        // it starts at or past the bottom edge.
        val overflow = (visible.top - start.top).coerceAtLeast(0) + (start.bottom - visible.bottom).coerceAtLeast(0)
        assertEquals("The overflow is the whole control", start.top + start.height() - visible.bottom, overflow)
        // The first bounded step is positive, bounded by the control extent
        // and half the viewport, and never more than the overflow it fixes.
        val first = boundedScrollStep(start, visible)
        assertTrue("A downward step must stay positive", first > 0 && first <= minOf(96, 210))
        assertTrue("One step never jumps past containment", first < start.top - visible.bottom + 96)
    }
}
