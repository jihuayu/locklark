package org.locklark.android.autofill

import android.view.ViewStructure
import android.view.autofill.AutofillId
import java.util.Collections
import java.util.IdentityHashMap

/**
 * JVM-only synthetic stand-in for the platform AssistStructure.ViewNode. It
 * implements the conversion's [LoginFormParser.PlatformNode] contract with the
 * platform getter names and types, so the conversion is compiled and run
 * through the same call sites as for a real adapter. No real AssistStructure,
 * browser or site is involved and no field content is ever read.
 */
internal class FakePlatformNode(
    private val id: AutofillId? = null,
    private val domain: String? = null,
    private val html: ViewStructure.HtmlInfo? = null,
    private val hints: Array<String>? = null,
    private val type: Int = 0,
    private val input: Int = 0,
    private val enabled: Boolean = true,
    private val visible: Int = VISIBLE,
    childNodes: List<FakePlatformNode> = emptyList(),
    private val reportedChildCount: Int? = null,
    /** Shared read log of one synthetic tree; defaults to this node's own. */
    private val reads: ReadLog = ReadLog(),
) : LoginFormParser.PlatformNode {
    // Changed only by the explicit malformed-tree helper.
    private var children: List<FakePlatformNode> = childNodes

    /**
     * Platform child count as the conversion sees it; defaults to the real
     * one. The conversion reads it once per node, so that read (including the
     * root's) is recorded in the shared log.
     */
    override val childCount: Int
        get() {
            reads.nodes.add(this)
            return reportedChildCount ?: children.size
        }

    // Contract members, named as Kotlin sees the platform getters.
    override val autofillId: AutofillId? get() = id
    override val webDomain: String? get() = domain
    override val htmlInfo: ViewStructure.HtmlInfo? get() = html
    override val autofillHints: Array<String>? get() = hints
    override val autofillType: Int get() = type
    override val inputType: Int get() = input
    override val isEnabled: Boolean get() = enabled
    override val visibility: Int get() = visible

    /** Test-only malformed tree: this node is its own only child. */
    fun cycleToSelf() {
        children = listOf(this)
    }

    /**
     * A real adapter resolves exactly the links of 0 until childCount, never
     * past the reported width. An out-of-range index is a real platform
     * anomaly: null (the conversion must fail closed), recorded so a test can
     * tell which bound rejected the tree.
     */
    override val childAt: ((Int) -> FakePlatformNode?)? = { index ->
        if (index !in children.indices) {
            unlinkedReads++
            null
        } else {
            children[index]
        }
    }

    /** Links asked for at or beyond the reported child count. */
    var unlinkedReads = 0
        private set

    /** Identity set of the nodes read in one synthetic tree, root included. */
    class ReadLog {
        val nodes: MutableSet<FakePlatformNode> =
            Collections.newSetFromMap(IdentityHashMap<FakePlatformNode, Boolean>())
    }

    companion object {
        const val VISIBLE = 0
    }
}
