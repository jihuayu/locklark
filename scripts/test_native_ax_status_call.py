"""Focused deterministic tests for the per-call status diagnostic hook.

The contract calls the status reader once with an explicit per-call result;
the real ``MacAdapter`` forwards it to ``QuartzApi.status`` only when that
reader accepts a third argument. A refused query then keeps the non-raising
all-false status while its sanitized diagnostic is reported for exactly that
call, never from state left behind by an earlier call. No real OS or GUI.
"""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import browser_native_macos as macos
import native_acceptance_contract as contract

TITLE = "Locklark · 浏览器原生确认"
NO_VALUE, UNSUPPORTED = -25212, -25205
FRAME = {"x": 313, "y": 75, "width": 1102, "height": 822}
WINDOW = {"id": 1, "pid": 4242, "title": TITLE, "executable": "/opt/locklark/desktop",
          "trusted": True, "visible": True, "onscreen": True, "secure": False,
          "bounds": dict(FRAME), "client": dict(FRAME)}
EMPTY = {"available": False, "generic_unlock_error": False,
         "secret_key_format_error": False, "processing": False}


class Element:
    def __init__(self, role, children=None, **extra):
        self.attributes = {"AXRole": (0, role)}
        if children is not None:
            self.attributes["AXChildren"] = (0, children)
        for name, value in extra.items():
            self.attributes[name] = (0, value)
        self.frame = FRAME


class FakeAx:
    def __init__(self, window, script=None):
        self.window, self.script, self.requests = window, dict(script or {}), []
        self.ax = types.SimpleNamespace(
            kAXWindowsAttribute="AXWindows", kAXErrorNoValue=NO_VALUE,
            AXUIElementCreateApplication=lambda pid: "application",
            AXUIElementCopyAttributeValue=self.copy)

    def copy(self, node, name, out):
        self.requests.append(name)
        if name in ("AXValue", "AXSelectedText", "AXParent"):
            raise AssertionError("forbidden accessibility attribute requested")
        if (node, name) in self.script:
            return self.script[(node, name)]
        if node == "application":
            return 0, [self.window] if name == "AXWindows" else None
        return node.attributes.get(name, (NO_VALUE, None))


def locked_view():
    controls = {label: {"present": False, "enabled": False, "showing": False}
                for label in contract.KNOWN_SYNTHETIC_LABELS}
    for label in macos.LOCKED_CONTROLS:
        controls[label] = {"present": True, "enabled": True, "showing": True}
    return controls


def adapter(root, script=None):
    fake = FakeAx(root, script)
    api = macos.QuartzApi.__new__(macos.QuartzApi)
    api.ax, api.frame = fake.ax, lambda node: dict(node.frame)
    return macos.MacAdapter(api=api), fake


def static(label=None):
    extra = {} if label is None else {"AXDescription": label}
    return Element("AXStaticText", **extra)


class StatusCallHookTests(unittest.TestCase):
    def test_failing_call_reports_its_own_diagnostic_without_raising(self):
        leaf = static(macos.STATUS_TEXT[0][1])
        root = Element("AXWindow", [leaf], AXTitle=TITLE)
        adapter_, fake = adapter(root, {(leaf, "AXChildren"): (UNSUPPORTED, None)})
        status, diagnostic = contract.status_snapshot(adapter_, WINDOW, locked_view())
        self.assertEqual(status, EMPTY)
        self.assertEqual(diagnostic, {"operation": "status-walk",
                                      "attribute": "AXChildren", "error": UNSUPPORTED})
        self.assertNotIn("AXValue", fake.requests)

    def test_later_clean_call_never_sees_the_earlier_failure(self):
        leaf = static(macos.STATUS_TEXT[0][1])
        root = Element("AXWindow", [leaf], AXTitle=TITLE)
        adapter_, _ = adapter(root, {(leaf, "AXChildren"): (UNSUPPORTED, None)})
        self.assertEqual(contract.status_snapshot(adapter_, WINDOW, locked_view()),
                         (EMPTY, {"operation": "status-walk",
                                  "attribute": "AXChildren", "error": UNSUPPORTED}))
        adapter_, _ = adapter(root)
        status, diagnostic = contract.status_snapshot(adapter_, WINDOW, locked_view())
        self.assertIsNone(diagnostic)
        self.assertEqual(status, dict(EMPTY, available=True, generic_unlock_error=True))

    def test_direct_read_status_never_raises_and_returns_four_booleans(self):
        leaf = static(macos.STATUS_TEXT[0][1])
        root = Element("AXWindow", [leaf], AXTitle=TITLE)
        cases = (("unsupported-children", {(leaf, "AXChildren"): (UNSUPPORTED, None)}),
                 ("no-value-role", {(leaf, "AXRole"): (NO_VALUE, None)}),
                 ("raising-attribute", {(leaf, "AXRole"): OSError("private AX text")}),
                 ("malformed-tuple", {(leaf, "AXChildren"): 0}))
        for name, script in cases:
            with self.subTest(case=name):
                adapter_, fake = adapter(root, script)
                for controls in (locked_view(), None):
                    status = adapter_.read_status(WINDOW, controls)
                    self.assertEqual(status, EMPTY)
                    self.assertEqual(set(status), set(contract.STATUS_FIELDS))
                    self.assertTrue(all(type(value) is bool for value in status.values()))
                api = adapter_.api
                self.assertEqual(api.status(WINDOW, locked_view()), EMPTY)
                self.assertEqual(api.read_status(WINDOW, locked_view()), EMPTY)
                self.assertNotIn("AXValue", fake.requests)

    def test_status_calls_never_share_a_diagnostic(self):
        leaf = static(macos.STATUS_TEXT[0][1])
        root = Element("AXWindow", [leaf], AXTitle=TITLE)
        adapter_, fake = adapter(root, {(leaf, "AXChildren"): (UNSUPPORTED, None)})
        failing = (EMPTY, {"operation": "status-walk",
                           "attribute": "AXChildren", "error": UNSUPPORTED})
        self.assertEqual(contract.status_snapshot(adapter_, WINDOW, locked_view()), failing)
        # The very same adapter, now clean, reports no earlier failure.
        fake.script.clear()
        self.assertEqual(contract.status_snapshot(adapter_, WINDOW, locked_view()),
                         (dict(EMPTY, available=True, generic_unlock_error=True), None))
        # And a direct call on the same adapter reports nothing either.
        self.assertEqual(adapter_.read_status(WINDOW, locked_view()),
                         dict(EMPTY, available=True, generic_unlock_error=True))
        fake.script[(leaf, "AXChildren")] = (UNSUPPORTED, None)
        self.assertEqual(adapter_.read_status(WINDOW, locked_view()), EMPTY)
        self.assertEqual(contract.status_snapshot(adapter_, WINDOW, locked_view()), failing)

    def test_per_call_results_are_independent(self):
        first, second = contract._AxCall(), contract._AxCall()
        first.record(contract.ContractError(
            "a11y-query", {"operation": "status-walk", "attribute": "AXRole",
                           "error": NO_VALUE}))
        first.record(contract.ContractError(
            "a11y-query", {"operation": "status-walk", "attribute": "AXChildren",
                           "error": UNSUPPORTED}))
        self.assertEqual(first.recorded(), {"operation": "status-walk",
                                            "attribute": "AXRole", "error": NO_VALUE})
        self.assertIsNone(second.recorded())

    def test_unsupported_description_with_call_stays_available(self):
        leaf = static("ignored")
        root = Element("AXWindow", [leaf], AXTitle=TITLE)
        adapter_, _ = adapter(root, {(leaf, "AXDescription"): (UNSUPPORTED, None)})
        status, diagnostic = contract.status_snapshot(adapter_, WINDOW, locked_view())
        self.assertIsNone(diagnostic)
        self.assertEqual(status, dict(EMPTY, available=True))

    def test_raising_hook_still_fails_closed_with_its_diagnostic(self):
        class Raising:
            def read_status(self, window, controls, call):
                raise contract.ContractError(
                    "a11y-query", {"operation": "status-walk",
                                   "attribute": "AXRole", "error": NO_VALUE})

        class TwoArgument:
            def read_status(self, window, controls):
                return dict(EMPTY, available=True)

        self.assertEqual(contract.status_snapshot(Raising(), WINDOW, locked_view()),
                         (EMPTY, {"operation": "status-walk",
                                  "attribute": "AXRole", "error": NO_VALUE}))
        self.assertEqual(contract.status_snapshot(TwoArgument(), WINDOW, locked_view()),
                         (dict(EMPTY, available=True), None))


if __name__ == "__main__":
    unittest.main()
