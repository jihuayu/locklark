package org.locklark.android.autofill

import android.app.assist.AssistStructure
import android.os.Parcel
import android.os.Parcelable
import android.text.InputType
import android.view.View
import android.view.ViewStructure
import android.view.autofill.AutofillId
import java.util.Collections
import java.util.IdentityHashMap

/**
 * Plain snapshot of one read platform node. It is constructed exactly once by
 * the bottom-up conversion, after all of its children are complete; the child
 * array is the conversion's own frame slice and is never mutated afterwards,
 * so no node can reference itself or another node twice.
 */
internal class AssistViewNode(
    val autofillId: AutofillId?,
    val webDomain: String?,
    val hasHtmlInfo: Boolean,
    val autofillHints: Array<String>?,
    val autofillType: Int,
    val inputType: Int,
    val isEnabled: Boolean,
    val visibility: Int,
    val children: Array<AssistViewNode>,
) {
    val childCount: Int get() = children.size

    fun childAt(index: Int): AssistViewNode? = children.getOrNull(index)

    override fun toString(): String = "[assist view node]"
}

/**
 * The only shape this checkpoint accepts from the OS: one enabled, visible
 * username field followed by one enabled, visible password field. Field
 * contents, saved values and vault data are never read. Web (HTML) forms and
 * known browsers are refused outright; no site is ever inferred or matched.
 */
internal data class LoginForm(
    val packageName: String,
    val usernameId: AutofillId,
    val passwordId: AutofillId,
) : Parcelable {
    val ids: Array<AutofillId> get() = arrayOf(usernameId, passwordId)

    private constructor(parcel: Parcel) : this(
        parcel.readString().orEmpty(),
        parcel.readParcelable(AutofillId::class.java.classLoader)!!,
        parcel.readParcelable(AutofillId::class.java.classLoader)!!,
    )

    override fun describeContents(): Int = 0

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        parcel.writeString(packageName)
        parcel.writeParcelable(usernameId, flags)
        parcel.writeParcelable(passwordId, flags)
    }

    companion object {
        @JvmField
        val CREATOR: Parcelable.Creator<LoginForm> = object : Parcelable.Creator<LoginForm> {
            override fun createFromParcel(parcel: Parcel): LoginForm = LoginForm(parcel)
            override fun newArray(size: Int): Array<LoginForm?> = arrayOfNulls(size)
        }
    }
}

internal object LoginFormParser {
    private val CARD_HINTS = setOf(
        View.AUTOFILL_HINT_CREDIT_CARD_NUMBER,
        View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_DATE,
        View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_DAY,
        View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_MONTH,
        View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_YEAR,
        View.AUTOFILL_HINT_CREDIT_CARD_SECURITY_CODE,
    )
    // The platform appends its hidden heuristic marker "passwordAuto" to
    // password-variation fields, alongside any declared password hint.
    private val PASSWORD_HINTS = setOf(View.AUTOFILL_HINT_PASSWORD, PASSWORD_AUTO_HINT)
    private val USERNAME_HINTS = setOf(
        View.AUTOFILL_HINT_USERNAME,
        View.AUTOFILL_HINT_EMAIL_ADDRESS,
    )
    private val FORBIDDEN_HINTS = setOf(
        "smsotp", "2faappotp", "otp", "one-time-code", "onetimecode",
        "verificationcode", "newpassword", "newusername",
    )
    // Known browser packages: every form they present is refused, regardless of
    // any webDomain. No browser package is ever treated as a login target.
    private val BROWSER_PACKAGES = setOf(
        "com.android.browser",
        "com.android.chrome",
        "com.android.htmlviewer",
        "com.android.webview",
        "com.brave.browser",
        "com.chrome.beta",
        "com.chrome.canary",
        "com.chrome.dev",
        "com.duckduckgo.mobile.android",
        "com.google.android.apps.chrome",
        "com.google.android.webview",
        "com.microsoft.emmx",
        "com.mozilla.firefox",
        "com.opera.browser",
        "com.sec.android.app.sbrowser",
        "com.vivaldi.browser",
        "org.chromium.chrome",
        "org.chromium.webview_shell",
        "org.mozilla.firefox",
    )

    fun isBrowserPackage(packageName: String): Boolean = packageName in BROWSER_PACKAGES

    private class Field(val id: AutofillId, val password: Boolean)

    fun parse(structure: AssistStructure?): LoginForm? {
        if (structure == null) return null
        val component = structure.activityComponent ?: return null
        val packageName = component.packageName
        if (packageName.isNullOrBlank()) return null
        if (isBrowserPackage(packageName)) return null
        if (structure.windowNodeCount != 1) return null
        val window = structure.getWindowNodeAt(0) ?: return null
        val root = window.rootViewNode ?: return null
        if (!platformIdsReferenced()) return null
        // Only ever the real adapter below: AssistStructure.ViewNode is an
        // unrelated platform class and is never cast to [PlatformNode].
        val converted = convert(PlatformViewNode(root)) ?: return null
        return parse(packageName, converted)
    }

    /** Pure node walk shared by the OS structure and JVM synthetic coverage. */
    fun parse(packageName: String, root: AssistViewNode): LoginForm? {
        if (packageName.isBlank() || isBrowserPackage(packageName)) return null
        val fields = mutableListOf<Field>()
        var rejected = false
        // Node identity: a shared or self-referencing node must not be walked twice.
        val visited = Collections.newSetFromMap(IdentityHashMap<AssistViewNode, Boolean>())
        val pending = ArrayDeque<Pair<AssistViewNode, Int>>()
        pending.addLast(root to 0)
        while (pending.isNotEmpty()) {
            val (node, depth) = pending.removeLast()
            if (depth > MAX_DEPTH) return null
            if (!visited.add(node)) return null
            // Any web-derived node (HTML field, nested webview) fails the whole
            // structure; a native form is never inferred from it. Any non-null
            // domain counts, including the empty string.
            if (node.webDomain != null) return null
            if (node.hasHtmlInfo) return null
            val rawHints = node.autofillHints
            val hints: List<String> = rawHints?.filter { it.isNotBlank() } ?: emptyList()
            if (hints.any(::forbiddenHint)) rejected = true
            val type = node.autofillType
            if (type == View.AUTOFILL_TYPE_TEXT) {
                val id = node.autofillId ?: return null
                if (!node.isEnabled || node.visibility != View.VISIBLE) return null
                val hintSet = hints.toSet()
                val passwordByType = passwordInput(node.inputType)
                val passwordByHint = hintSet.any { it in PASSWORD_HINTS }
                val usernameByHint = hintSet.any { it in USERNAME_HINTS }
                if (passwordByType || passwordByHint) {
                    if (usernameByHint) return null
                    if (hintSet.any { it !in PASSWORD_HINTS }) return null
                    fields.add(Field(id, true))
                } else {
                    // Username/email must be explicit; an unhinted text field is ambiguous.
                    if (!usernameByHint) return null
                    fields.add(Field(id, false))
                }
            } else if (hints.any { it in PASSWORD_HINTS }) {
                // A password hint on a non-text field is malformed input.
                return null
            }
            // Plain children are fixed arrays: no link can be missing and no
            // node can be revisited, because conversion already rejected that.
            val children = node.children
            for (index in children.indices.reversed()) {
                pending.addLast(children[index] to depth + 1)
            }
        }
        if (rejected) return null
        if (fields.size != 2) return null
        val username = fields[0]
        val password = fields[1]
        if (username.password || !password.password) return null
        if (username.id == password.id) return null
        return LoginForm(packageName, username.id, password.id)
    }

    /**
     * Alias for the APK's own, referenced 32-bit AutofillId. Resolved before
     * the platform tree is touched, so an unlinked platform id class fails
     * closed instead of throwing a LinkageError out of the parser.
     */
    @Volatile
    private var referencedAutofillId: Class<*>? = null

    private fun platformIdsReferenced(): Boolean = try {
        referencedAutofillId ?: AutofillId::class.java.also { referencedAutofillId = it }
        true
    } catch (_: LinkageError) {
        false
    }

    /**
     * Narrow read-only view of the real platform node: the AssistStructure
     * .ViewNode getters this conversion uses. The platform ViewNode is final
     * and unrelated to this type, so it is reached only through an explicit
     * adapter ([PlatformViewNode]), never a cast. Child links are read through
     * [childAt], which the owner supplies to resolve an index explicitly.
     */
    internal interface PlatformNode {
        val autofillId: AutofillId?
        val webDomain: String?
        val htmlInfo: ViewStructure.HtmlInfo?
        val autofillHints: Array<String>?
        val autofillType: Int
        val inputType: Int
        val isEnabled: Boolean
        val visibility: Int
        val childCount: Int
        /** Child at [index]; null if unavailable or outside 0 until [childCount]. */
        val childAt: ((Int) -> PlatformNode?)?
        /**
         * Optional observation hook. One level of nesting: it is called after
         * this node's own width read and before any child link is read; the
         * adapter left to the conversion does not need it.
         */
        val onRead: (() -> Unit)? get() = null
    }

    /**
     * Thin adapter around exactly one real [AssistStructure.ViewNode], plus
     * that node's explicit child links. The platform class is only ever read
     * through delegation here; it is never cast to or from [PlatformNode].
     * Every getter fails closed (null/false/0, or a null child link) instead
     * of letting a platform exception escape the parser.
     */
    internal class PlatformViewNode(
        private val node: AssistStructure.ViewNode,
    ) : PlatformNode {
        override val autofillId: AutofillId? get() = read { node.autofillId }
        override val webDomain: String? get() = read { node.webDomain }
        override val htmlInfo: ViewStructure.HtmlInfo? get() = read { node.htmlInfo }
        override val autofillHints: Array<String>? get() = read { node.autofillHints }
        override val autofillType: Int get() = read { node.autofillType } ?: AUTOFILL_TYPE_NONE
        override val inputType: Int get() = read { node.inputType } ?: 0
        override val isEnabled: Boolean get() = read { node.isEnabled } ?: false
        override val visibility: Int get() = read { node.visibility } ?: View.INVISIBLE
        // A negative width makes the conversion fail closed before any link.
        override val childCount: Int get() = read { node.childCount } ?: -1

        /**
         * Resolves child [index] one level only: the platform getter takes the
         * node's internal ID, not an index, and an index outside the reported
         * width is never passed to it. Wrapping happens only after the
         * conversion has checked the child's depth and the node budget.
         */
        override val childAt: ((Int) -> PlatformNode?)? = { index ->
            val child = read {
                if (index < 0 || index >= node.childCount) null else node.getChildAt(index)
            }
            // A missing link inside the width is a platform anomaly: fail closed.
            if (child == null) null else PlatformViewNode(child)
        }

        override fun toString(): String = "[platform view node]"

        private companion object {
            fun <T> read(block: () -> T): T? = try {
                block()
            } catch (_: RuntimeException) {
                null
            } catch (_: LinkageError) {
                null
            }
        }
    }

    /**
     * One explicit-stack entry. [children] holds the already completed child
     * results in child index order, one slot per index; [done] is its filled
     * prefix. A frame is popped only after its last child is complete, and
     * then its plain node is built from this frame's own results.
     */
    private class Frame(val node: PlatformNode, val depth: Int) {
        var childCount = -1
        // Next child index to link.
        var next = 0
        var children: Array<AssistViewNode?>? = null
        var done = 0

        /** Stores [child] at its index and lets the parent resume. */
        fun completed(index: Int, child: AssistViewNode) {
            val slots = children ?: error("links are not reserved")
            slots[index] = child
            done++
        }
    }

    /**
     * Bounded, iterative (no recursion) conversion of an OS-shaped tree into
     * plain nodes.
     *
     * An explicit stack walks depth-first, root first, child index ascending.
     * A node's depth and width are checked, and the [MAX_NODES] budget
     * reserved with [tryReserve], before any of its child links is read, any
     * child slot is allocated or any plain node is built. A missing child link
     * inside the width, a platform node identity seen twice, an excessive
     * width/depth/size or an exhausted budget returns null with nothing beyond
     * the bound read.
     *
     * Each frame collects its children's results itself; a parent's plain node
     * is constructed only after all of its children, with that frame's child
     * array, so every converted node is immutable and its children are in
     * platform index order. Null means fail closed.
     */
    internal fun convert(root: PlatformNode): AssistViewNode? {
        val stack = ArrayList<Frame>()
        // Platform node identity: a shared or self-referencing node fails.
        val seen = Collections.newSetFromMap(IdentityHashMap<PlatformNode, Boolean>())
        // Every committed unit: a frame, a plain node or a child slot.
        val budget = Budget(MAX_NODES)
        if (!budget.tryReserve(1)) return null
        stack.add(Frame(root, 0))
        seen.add(root)
        while (stack.isNotEmpty()) {
            val frame = stack[stack.lastIndex]
            if (frame.childCount < 0) {
                // First visit: depth and width are checked before any child.
                if (frame.depth > MAX_DEPTH) return null
                val count = frame.node.childCount
                if (count < 0 || count > MAX_CHILDREN) return null
                // This node, its plain node and all of its links must fit.
                if (!budget.canAfford(count + 2)) return null
                if (!budget.tryReserve(count + 2)) return null
                frame.children = arrayOfNulls(count)
                frame.childCount = count
                continue
            }
            if (frame.next < frame.childCount) {
                val index = frame.next
                val child = frame.node.childAt?.invoke(index) ?: return null
                frame.next = index + 1
                if (!seen.add(child)) return null
                stack.add(Frame(child, frame.depth + 1))
                continue
            }
            // Every child is already complete: build this plain node now.
            val slots = frame.children ?: return null
            if (frame.done != slots.size) return null
            @Suppress("UNCHECKED_CAST")
            val children = slots as Array<AssistViewNode>
            val plain = AssistViewNode(
                autofillId = frame.node.autofillId,
                webDomain = frame.node.webDomain,
                hasHtmlInfo = frame.node.htmlInfo != null,
                autofillHints = frame.node.autofillHints?.copyOf(),
                autofillType = frame.node.autofillType,
                inputType = frame.node.inputType,
                isEnabled = frame.node.isEnabled,
                visibility = frame.node.visibility,
                children = children,
            )
            stack.removeAt(stack.lastIndex)
            val parent = stack.lastOrNull() ?: return plain
            parent.completed(parent.next - 1, plain)
        }
        return null
    }

    /** Exact, monotone count of units already committed against MAX_NODES. */
    private class Budget(private var amount: Int) {
        fun tryReserve(units: Int): Boolean {
            if (units > amount) return false
            amount -= units
            return true
        }

        fun canAfford(units: Int): Boolean = units <= amount
    }

    private fun passwordInput(inputType: Int): Boolean {
        if (inputType and InputType.TYPE_MASK_CLASS != InputType.TYPE_CLASS_TEXT) return false
        return when (inputType and InputType.TYPE_MASK_VARIATION) {
            InputType.TYPE_TEXT_VARIATION_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD -> true
            else -> false
        }
    }

    private fun forbiddenHint(hint: String): Boolean {
        if (hint in CARD_HINTS) return true
        val normalized = hint.lowercase()
        return normalized in FORBIDDEN_HINTS || "otp" in normalized || "creditcard" in normalized
    }

    private const val PASSWORD_AUTO_HINT = "passwordAuto"
    private const val MAX_DEPTH = 256
    private const val MAX_NODES = 2048
    private const val MAX_CHILDREN = 1024
    private const val AUTOFILL_TYPE_NONE = 0
}
