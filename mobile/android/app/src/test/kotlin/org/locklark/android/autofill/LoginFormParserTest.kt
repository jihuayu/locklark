package org.locklark.android.autofill

import android.app.assist.AssistStructure
import android.view.ViewStructure
import android.view.autofill.AutofillId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Synthetic [AssistViewNode] trees only; no real AssistStructure, browser or
 * site is involved. Ids are test-owned objects and the app's AutofillId
 * is never resolved (it is not in the unit-test android.jar), exactly as on a
 * device without the 32-bit id class. The unit-test android.jar has
 * blank static fields, so platform constants are pinned as literals here:
 * AUTOFILL_TYPE_NONE=0, AUTOFILL_TYPE_TEXT=1, VISIBLE=0, NO_HIDE_DESCENDANTS=0,
 * HINT_USERNAME="username", HINT_PASSWORD="password", HINT_EMAIL_ADDRESS="emailAddress",
 * CLASS_TEXT=1, VARIATION_PASSWORD=0x80, VARIATION_NORMAL=0, VARIATION_WEB_PASSWORD=0xe1.
 */
class LoginFormParserTest {
    private companion object {
        const val AUTOFILL_TYPE_NONE = 0
        const val AUTOFILL_TYPE_TEXT = 1
        const val VISIBLE = 0
        const val HINT_USERNAME = "username"
        const val HINT_PASSWORD = "password"
        const val CLASS_TEXT = 1
        const val VARIATION_NORMAL = 0
        const val VARIATION_PASSWORD = 0x80
        const val VARIATION_WEB_PASSWORD = 0xe1
        // Mirrors the parser's documented bounds.
        const val DEPTH_LIMIT = 256
        const val MAX_CHILDREN = 1024
        const val PATHOLOGICAL_DEPTH = 20_000
    }

    private fun id(): AutofillId = TestAutofillIds.fresh()

    private fun node(
        autofillId: AutofillId? = null,
        webDomain: String? = null,
        hasHtmlInfo: Boolean = false,
        hints: Array<String>? = null,
        autofillType: Int = AUTOFILL_TYPE_NONE,
        inputType: Int = 0,
        children: List<AssistViewNode> = emptyList(),
    ) = AssistViewNode(
        autofillId = autofillId,
        webDomain = webDomain,
        hasHtmlInfo = hasHtmlInfo,
        autofillHints = hints,
        autofillType = autofillType,
        inputType = inputType,
        isEnabled = true,
        visibility = VISIBLE,
        children = children.toTypedArray(),
    )

    private fun username(hints: Array<String>? = arrayOf(HINT_USERNAME), id: AutofillId = id()) = node(
        autofillId = id,
        hints = hints,
        autofillType = AUTOFILL_TYPE_TEXT,
        inputType = CLASS_TEXT or VARIATION_NORMAL,
    )

    private fun password(id: AutofillId = id()) = node(
        autofillId = id,
        hints = arrayOf(HINT_PASSWORD),
        autofillType = AUTOFILL_TYPE_TEXT,
        inputType = CLASS_TEXT or VARIATION_PASSWORD,
    )

    private fun nativeForm() = node(
        children = listOf(username(), password()),
    )

    @Test
    fun syntheticNativeTargetStaysEligible() {
        val form = LoginFormParser.parse("org.locklark.android.test", nativeForm())
        assertNotNull(form)
        assertEquals("org.locklark.android.test", form!!.packageName)
        assertEquals(2, form.ids.size)
    }

    @Test
    fun anyWebDomainIsRejected() {
        // Any non-null domain, including the empty string, means web origin.
        for (domain in listOf("example.com", "login.example.org", " ", "")) {
            val root = node(
                children = listOf(
                    node(webDomain = domain, children = listOf(username(), password())),
                ),
            )
            assertNull("webDomain '$domain' must fail closed", LoginFormParser.parse("com.example.nativeapp", root))
        }
    }

    @Test
    fun webDomainOnLoginFieldsIsRejected() {
        val root = node(
            children = listOf(
                node(
                    autofillId = id(),
                    webDomain = "example.com",
                    hints = arrayOf(HINT_USERNAME),
                    autofillType = AUTOFILL_TYPE_TEXT,
                    inputType = CLASS_TEXT,
                ),
                node(
                    autofillId = id(),
                    webDomain = "example.com",
                    hints = arrayOf(HINT_PASSWORD),
                    autofillType = AUTOFILL_TYPE_TEXT,
                    inputType = CLASS_TEXT or VARIATION_PASSWORD,
                ),
                username(),
                password(),
            ),
        )
        assertNull(LoginFormParser.parse("com.example.nativeapp", root))
    }

    @Test
    fun anyHtmlInfoIsRejected() {
        val root = node(children = listOf(node(hasHtmlInfo = true, children = listOf(username(), password()))))
        assertNull(LoginFormParser.parse("com.example.nativeapp", root))

        val field = node(
            autofillId = id(),
            hasHtmlInfo = true,
            hints = arrayOf(HINT_PASSWORD),
            autofillType = AUTOFILL_TYPE_TEXT,
            inputType = CLASS_TEXT or VARIATION_PASSWORD,
        )
        assertNull(LoginFormParser.parse("com.example.nativeapp", node(children = listOf(username(), field))))
    }

    @Test
    fun knownBrowserPackagesAreRejectedEvenForNativeShapedTrees() {
        val browsers = listOf(
            "com.android.chrome",
            "com.android.browser",
            "org.mozilla.firefox",
            "com.sec.android.app.sbrowser",
            "com.google.android.webview",
        )
        for (name in browsers) {
            assertTrue(name, LoginFormParser.isBrowserPackage(name))
            assertNull(name, LoginFormParser.parse(name, nativeForm()))
            assertNull(
                "$name with web fields",
                LoginFormParser.parse(name, node(children = listOf(node(webDomain = "example.com", children = listOf(username(), password()))))),
            )
        }
    }

    @Test
    fun packageIsNeverInferredFromDomainOrShape() {
        // No browser allowlisting and no web origin: a web domain is never turned
        // into a package and an unknown package without structure fails closed.
        assertNull(LoginFormParser.parse("", nativeForm()))
        assertNull(LoginFormParser.parse(" ", nativeForm()))
        assertNull(LoginFormParser.parse("com.example.nativeapp", node()))
    }

    @Test
    fun depthBeyondLimitFailsClosedInThePureWalk() {
        // The depth chain adds [depth] wrappers: with DEPTH_LIMIT - 1 wrappers
        // username sits at depth == DEPTH_LIMIT and still passes; the next
        // level fails closed.
        assertTrue("depth == limit must stay eligible", depthChain(DEPTH_LIMIT - 1) != null)
        assertNull("depth == limit + 1", depthChain(DEPTH_LIMIT))
        assertNull("depth == limit + 2", depthChain(DEPTH_LIMIT + 1))
    }

    @Test
    fun excessiveDepthFailsClosedBeforeUnboundedConversion() {
        // The conversion is iterative and fails on depth instead of recursing
        // or allocating plain nodes for the deeper levels. Every node at depth
        // 0..DEPTH_LIMIT is read; the node one level beyond is never read.
        val counted = FakePlatformNode.ReadLog()
        assertNull(convert(platformChain(DEPTH_LIMIT + 1, counted)))
        assertEquals("no node deeper than DEPTH_LIMIT is read", DEPTH_LIMIT + 1, counted.nodes.size)
        // Thousands of levels: no recursion, so no stack overflow, still closed.
        assertNull("a 20k-deep structure must fail closed", convert(platformChain(PATHOLOGICAL_DEPTH)))

        val atLimitReads = FakePlatformNode.ReadLog()
        val converted = convert(platformChain(DEPTH_LIMIT, atLimitReads))
        assertNotNull(converted)
        assertEquals(DEPTH_LIMIT + 1, atLimitReads.nodes.size)
        var node: AssistViewNode? = converted
        var seen = 0
        while (node != null) {
            seen++
            node = if (node.childCount > 0) node.childAt(0) else null
        }
        assertEquals("depth is preserved", DEPTH_LIMIT + 1, seen)
    }

    @Test
    fun repeatedPlatformIdentityIsRejected() {
        val shared = FakePlatformNode(childNodes = listOf(FakePlatformNode()))
        val twice = FakePlatformNode(childNodes = listOf(shared, shared))
        assertNull("a shared child must fail closed", convert(twice))
        assertNull("a self-referencing cycle must fail closed", convert(FakePlatformNode().apply { cycleToSelf() }))
    }

    @Test
    fun nonNullWebDomainAndHtmlInfoAreRejectedByConversion() {
        for (domain in listOf("example.com", "")) {
            val root = FakePlatformNode(childNodes = listOf(FakePlatformNode(domain = domain)))
            val converted = convert(root)
            assertNotNull(converted)
            assertNull("conversion output must fail closed for '$domain'", LoginFormParser.parse("com.example.nativeapp", converted!!))
        }
        val html = FakePlatformNode(childNodes = listOf(FakePlatformNode(html = HtmlInfoStub())))
        val converted = convert(html)
        assertNotNull(converted)
        assertNull(LoginFormParser.parse("com.example.nativeapp", converted!!))
    }

    @Test
    fun excessiveSizeFailsClosedInConversion() {
        // The first over-wide root is nested one level in, so the root below
        // is read before the width bound rejects the whole tree.
        val wideReads = FakePlatformNode.ReadLog()
        val wide = FakePlatformNode(childNodes = List(MAX_CHILDREN + 1) { FakePlatformNode() }, reads = wideReads)
        assertNull(convert(wide))
        assertEquals("the over-wide root itself is read once", 1, wideReads.nodes.size)
        // 1024 + 1024 * 16 + 1 nodes far exceed the node budget; the walk stops
        // as soon as the budget runs out, long before the tree is walked.
        val manyReads = FakePlatformNode.ReadLog()
        val many = FakePlatformNode(
            childNodes = List(MAX_CHILDREN) { FakePlatformNode(childNodes = List(16) { FakePlatformNode() }) },
            reads = manyReads,
        )
        assertNull("node budget must cap total size", convert(many))
        assertTrue("the budget must stop the walk early", manyReads.nodes.size <= MAX_CHILDREN + 2)
        assertEquals("no link outside the reported width is ever read", 0, many.unlinkedReads)
        assertEquals("no link is read once the width is rejected", 0, wide.unlinkedReads)
        val missing = FakePlatformNode(reportedChildCount = 1)
        assertNull("a missing child link fails closed", convert(missing))
        assertEquals(1, missing.unlinkedReads)
    }

    @Test
    fun excessiveWidthInsideAnEligibleShapedTreeIsRejected() {
        // First sibling, then a container wider than MAX_CHILDREN: walk order
        // meets the width bound before eligibility is ever decided.
        val reads = FakePlatformNode.ReadLog()
        val wide = FakePlatformNode(childNodes = List(MAX_CHILDREN + 1) { FakePlatformNode(reads = reads) }, reads = reads)
        val first = FakePlatformNode(reads = reads)
        val root = FakePlatformNode(childNodes = listOf(first, wide), reads = reads)
        assertNull(convert(root))
        assertEquals(
            "root, first sibling and the over-wide node are read; no child of it is",
            3,
            reads.nodes.size,
        )
        assertEquals("no link past the width bound is read", 0, root.unlinkedReads)
    }

    @Test
    fun nestedSyntheticPlatformTreeConvertsAndParsesToBothIds() {
        // A nested native tree: root > Linear > (wrapper > Form >
        // [edittext hint "username", edittext hint "password"]), plus a
        // sibling container. Synthetic only; no real AssistStructure is built.
        val usernameId = id()
        val passwordId = id()
        val reads = FakePlatformNode.ReadLog()
        val form = FakePlatformNode(
            childNodes = listOf(
                FakePlatformNode(
                    id = usernameId,
                    hints = arrayOf(HINT_USERNAME),
                    type = AUTOFILL_TYPE_TEXT,
                    input = CLASS_TEXT or VARIATION_NORMAL,
                    reads = reads,
                ),
                FakePlatformNode(
                    id = passwordId,
                    hints = arrayOf(HINT_PASSWORD),
                    type = AUTOFILL_TYPE_TEXT,
                    input = CLASS_TEXT or VARIATION_PASSWORD,
                    reads = reads,
                ),
            ),
            reads = reads,
        )
        val root = FakePlatformNode(
            childNodes = listOf(
                FakePlatformNode(
                    childNodes = listOf(
                        FakePlatformNode(childNodes = listOf(form), reads = reads),
                        FakePlatformNode(reads = reads),
                    ),
                    reads = reads,
                ),
            ),
            reads = reads,
        )
        val converted = convert(root)
        assertNotNull(converted)
        // Root, Linear, (wrapper, Form, username, password) and the empty
        // sibling are each read exactly once.
        assertEquals(7, reads.nodes.size)
        // Parent plain nodes are built after their children, and every child
        // stays at its platform index.
        assertEquals(1, converted!!.childCount)
        val linear = converted.childAt(0)!!
        assertEquals(2, linear.childCount)
        val wrapper = linear.childAt(0)!!
        assertEquals(1, wrapper.childCount)
        val emptySibling = linear.childAt(1)!!
        assertEquals(0, emptySibling.childCount)
        val formNode = wrapper.childAt(0)!!
        assertEquals(2, formNode.childCount)
        assertEquals(usernameId, formNode.childAt(0)!!.autofillId)
        assertEquals(passwordId, formNode.childAt(1)!!.autofillId)
        assertEquals(0, formNode.childAt(0)!!.childCount)
        assertEquals(0, formNode.childAt(1)!!.childCount)
        val parsed = LoginFormParser.parse("org.locklark.android.test", converted)
        assertNotNull("nested native form must stay eligible", parsed)
        assertEquals("org.locklark.android.test", parsed!!.packageName)
        assertEquals(2, parsed.ids.size)
        assertEquals(usernameId, parsed.usernameId)
        assertEquals(passwordId, parsed.passwordId)
        // The conversion is a plain tree: it walks back down without looping.
        // root=1, Linear=2, wrapper=3, Form=4, field=5.
        assertEquals(5, depthOf(converted, usernameId))
        assertEquals(5, depthOf(converted, passwordId))
    }

    private fun depthChain(depth: Int): LoginForm? {
        var node = node(children = listOf(username(), password()))
        repeat(depth) { node = node(children = listOf(node)) }
        return LoginFormParser.parse("com.example.nativeapp", node)
    }

    private fun convert(root: FakePlatformNode): AssistViewNode? = LoginFormParser.convert(root)


    private fun platformChain(
        depth: Int,
        reads: FakePlatformNode.ReadLog = FakePlatformNode.ReadLog(),
    ): FakePlatformNode {
        var node = FakePlatformNode(reads = reads)
        repeat(depth) { node = FakePlatformNode(childNodes = listOf(node), reads = reads) }
        return node
    }

    /** Iterative depth of the converted node holding [target]; -1 if absent. */
    private fun depthOf(root: AssistViewNode, target: AutofillId): Int {
        val pending = ArrayDeque<Pair<AssistViewNode, Int>>()
        pending.addLast(root to 1)
        while (pending.isNotEmpty()) {
            val (node, depth) = pending.removeLast()
            if (node.autofillId == target) return depth
            for (child in node.children) pending.addLast(child to depth + 1)
        }
        return -1
    }

    @Test
    fun passwordFirstIsRejected() {
        val root = node(children = listOf(password(), username()))
        assertNull(LoginFormParser.parse("com.example.nativeapp", root))
    }

    @Test
    fun unhintedTextFieldIsRejected() {
        val unhinted = node(
            autofillId = id(),
            autofillType = AUTOFILL_TYPE_TEXT,
            inputType = CLASS_TEXT,
        )
        assertNull(LoginFormParser.parse("com.example.nativeapp", node(children = listOf(unhinted, password()))))
    }
}

/** JVM-only synthetic HtmlInfo marker; no HTML form is ever involved. */
private class HtmlInfoStub : ViewStructure.HtmlInfo() {
    override fun getAttributes(): MutableList<android.util.Pair<String, String>> = mutableListOf()
    override fun getTag(): String = "form"
    override fun toString(): String = "[synthetic html info]"
}

