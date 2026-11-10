package org.locklark.android

import android.graphics.Rect
import android.view.View
import android.view.ViewParent
import android.widget.ScrollView

/*
 * Geometry shared by the page-scroll controller in OfflineVaultTest and the
 * detached-layout geometry checks. Everything here is in ONE coordinate system:
 * the owning ScrollView's viewport-local coordinates, the space that
 * offsetDescendantRectToMyCoords returns and that scrollBy deltas act in.
 * The app-safe screen rect is mapped into that space exactly once, by
 * safeLocalRect, so no content, root/global or content-padded rect is mixed in.
 */

/** True when [a] and [b] share any area; either rectangle may be mutated. */
internal fun overlaps(a: Rect, b: Rect): Boolean = Rect.intersects(a, b)

/** The ScrollView's (scrollX, scrollY) as one comparable value. */
internal fun scrollOffset(scroll: ScrollView): Long =
    (scroll.scrollX.toLong() shl 32) or (scroll.scrollY.toLong() and 0xffffffffL)

/**
 * Bounded scrollBy delta that moves [target] toward the full containment of
 * [visible], both viewport-local. 0 only when fully contained. Content is drawn
 * at layout - scrollY, so a target past the trailing edge needs a positive
 * delta and a target above the leading edge a negative one; the step is at
 * least 1 and at most the half of the visible span and of the target, and near
 * the viewport end it never exceeds the hidden part. The exact step size is not
 * a contract: repetition must shrink the overflow monotonically until the
 * target is fully contained.
 *
 * A target larger than the visible span can never be fully contained; it gets
 * no-progress (0) instead of a step that would only move the overflow from one
 * edge to the other.
 */
internal fun boundedScrollStep(target: Rect, visible: Rect, vertical: Boolean = true): Int {
    if (visible.isEmpty) return 0
    val (from, to, begin, end) = if (vertical)
        listOf(target.top, target.bottom, visible.top, visible.bottom)
    else listOf(target.left, target.right, visible.left, visible.right)
    if (from >= begin && to <= end) return 0
    val span = end - begin
    val size = to - from
    if (size > span) return 0
    val clamp = maxOf(1, minOf(span / 2, size))
    val raw = when {
        // Past the trailing edge: pull the leading edge up by the hidden part.
        to > end -> minOf(to - end, clamp)
        // Above the leading edge: pull the trailing edge down.
        from < begin -> -minOf(begin - from, clamp)
        // Equal to the span but offset: align its leading edge.
        else -> from - begin
    }
    // An edge-only overflow is never "in view": one unit toward that edge.
    return if (raw == 0) (if (from < begin) -1 else 1) else raw
}

/** The page ScrollView that owns [target], searched up from the target only. */
internal fun pageScroll(target: View): ScrollView? {
    var parent: ViewParent? = target.parent
    while (parent != null) {
        if (parent is ScrollView) return parent as ScrollView
        parent = parent.parent
    }
    return null
}

/**
 * [target]'s full rect in [scroll]'s viewport-local coordinates. The raw
 * offsetDescendantRectToMyCoords result is in the receiver's own coordinates,
 * NOT its viewport-local ones: the API composes only the scroll of the
 * ancestors between [target] and [scroll], never the receiver's own (scrollX,
 * scrollY). The content is drawn at layout - scroll, so exactly the receiver's
 * offset is subtracted on both axes to share the coordinate system that
 * safeLocalRect and scrollBy deltas use. The result is the drawn position, not
 * a stable content rect. Nested scrolling containers are not composed, so
 * this returns null for a target inside a descendant ScrollView.
 */
internal fun descendantRectInScroll(scroll: ScrollView, target: View): Rect? {
    if (pageScroll(target) !== scroll) return null
    val rect = Rect(0, 0, target.width, target.height)
    scroll.offsetDescendantRectToMyCoords(target, rect)
    // offsetDescendantRectToMyCoords excludes the receiver's own scroll.
    rect.offset(-scroll.scrollX, -scroll.scrollY)
    return rect
}

/**
 * The app-safe screen rect [safe] mapped into [scroll]'s viewport-local
 * coordinates: safeScreen - the ScrollView's screen origin. Only screen rects
 * are intersected (with [root]'s screen rect, so a parent clip is honoured
 * before the map), then the result is clamped to the ScrollView's padding box
 * [paddingLeft, paddingTop, width - paddingRight, height - paddingBottom],
 * which is the stable window scrollTo can address. getLocationOnScreen is
 * used for both rectangles and no global/content rect is mixed in. A
 * ScrollView that is not shown or attached has no local window, unless
 * [detached] allows deterministic detached fixtures (geometry checks only; the
 * controller's click path always calls this for a live, shown target).
 */
internal fun safeLocalRect(scroll: ScrollView, safe: Rect, root: View, detached: Boolean = false): Rect {
    if (!detached && (!scroll.isShown || !scroll.isAttachedToWindow)) return Rect()
    if (scroll.width <= 0 || scroll.height <= 0) return Rect()
    val location = IntArray(2).also { scroll.getLocationOnScreen(it) }
    val origin = IntArray(2).also { root.getLocationOnScreen(it) }
    val visible = Rect(safe)
    visible.intersect(Rect(origin[0], origin[1], origin[0] + root.width, origin[1] + root.height))
    if (visible.isEmpty) return Rect()
    return Rect(visible).apply { offset(-location[0], -location[1]) }.apply {
        intersect(Rect(scroll.paddingLeft, scroll.paddingTop,
            scroll.width - scroll.paddingRight, scroll.height - scroll.paddingBottom))
    }
}

/**
 * One bounded native scroll step; true only if the owning container moved.
 * [moved] receives the real (scrollX, scrollY) change, so a caller can compare
 * it with the requested step instead of assuming it.
 */
internal fun scrollPageStep(target: View, vertical: Boolean, delta: Int, moved: (Int, Int) -> Unit = { _, _ -> }): Boolean {
    val scroll = pageScroll(target) ?: return false
    if (delta == 0) return false
    val fromX = scroll.scrollX
    val fromY = scroll.scrollY
    if (vertical) scroll.scrollBy(0, delta) else scroll.scrollBy(delta, 0)
    val dx = scroll.scrollX - fromX
    val dy = scroll.scrollY - fromY
    if (dx == 0 && dy == 0) return false
    moved(dx, dy)
    return true
}

/**
 * Applies one requested (scroll by, real move) step on the owning ScrollView,
 * measured from the offset before and after scrollBy. A detached ScrollView
 * (only a test fixture) defers "cannot scroll" to a later layout pass: that
 * flag would outlive an offset write, so it is cleared before each step.
 */
internal fun boundedScrollTo(scroll: ScrollView, target: View, vertical: Boolean, delta: Int): Pair<Int, Int> {
    if (!scroll.isAttachedToWindow) scroll.suppressLayout(false)
    val page = pageScroll(target) ?: return 0 to 0
    val before = if (vertical) page.scrollY else page.scrollX
    if (vertical) page.scrollBy(0, delta) else page.scrollBy(delta, 0)
    val real = (if (vertical) page.scrollY else page.scrollX) - before
    return if (real == 0) 0 to 0 else delta to real
}
