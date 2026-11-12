"""Focused deterministic tests for the fixed AX status-walk diagnostic.

No real OS, GUI, TCC, prompt or window inventory: the real status walk runs
over an in-memory fake AX through the real ``MacAdapter`` hook, for an
explicitly named owned PID and its one same-title AX window.
"""
import json
import os
import re
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import browser_native_macos as macos
import native_acceptance_contract as contract

TITLE = "Locklark · 浏览器原生确认"
NO_VALUE, UNSUPPORTED, UNKNOWN = -25212, -25205, -25999
FRAME = {"x": 313, "y": 75, "width": 1102, "height": 822}
CANARY = "private title=" + TITLE + " label=确认连接此扩展 path=/tmp/llcb-unit"
WINDOW = {"id": 1, "pid": 4242, "title": TITLE, "executable": "/opt/locklark/desktop",
          "trusted": True, "visible": True, "onscreen": True, "secure": False,
          "bounds": dict(FRAME), "client": dict(FRAME)}
FOUR_FIELD = re.compile(r"Native acceptance input failed \[code=([a-zA-Z0-9-]+) "
                        r"action=[a-z-]+ index=-?[0-9]+ platform=[a-z]+\]")


class Element:
    """One hashable fake AXUIElement: fixed attributes plus a private frame."""

    def __init__(self, role, children=None, **extra):
        self.attributes = {"AXRole": (0, role)}
        if children is not None:
            self.attributes["AXChildren"] = (0, children)
        for name, value in extra.items():
            self.attributes[name] = (0, value)
        self.frame = FRAME


def element(*args, **kwargs):
    return Element(*args, **kwargs)


class FakeAx:
    """The owned application and its named elements; AXValue is a hard failure.

    ``script`` maps an ``(element, attribute)`` pair to a raw ``(AXError,
    value)`` tuple served verbatim for that element only; an absent attribute
    answers the documented ``kAXErrorNoValue``.
    """

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
            return 0, [self.window] if name == "AXWindows" else (_ for _ in ()).throw(
                AssertionError("unexpected application read"))
        return node.attributes.get(name, (NO_VALUE, None))


class StatusDiagnosticTests(unittest.TestCase):
    def locked_view(self):
        controls = {label: {"present": False, "enabled": False, "showing": False}
                    for label in contract.KNOWN_SYNTHETIC_LABELS}
        for label in macos.LOCKED_CONTROLS:
            controls[label] = {"present": True, "enabled": True, "showing": True}
        return controls

    def probe(self, root, script=None):
        """The real hook once: (fixed status, allowlisted diagnostic, fake)."""
        fake = FakeAx(root, script)
        api = macos.QuartzApi.__new__(macos.QuartzApi)
        api.ax, api.frame = fake.ax, lambda node: dict(node.frame)
        try:
            return macos.MacAdapter(api=api).read_status(WINDOW, self.locked_view()), None, fake
        except contract.ContractError as error:
            self.assertEqual(error.code, "a11y-query")
            self.assertEqual(set(error.guard), {"operation", "attribute", "error"})
            return macos._empty_status(), contract.ax_diagnostic(error), fake

    def test_children_no_value_is_a_leaf_not_a_diagnostic(self):
        leaf = element("AXStaticText", AXDescription=macos.STATUS_TEXT[2][1])
        root = element("AXWindow", [element("AXGroup"), leaf], AXTitle=TITLE)
        status, diagnostic, fake = self.probe(root)
        self.assertIsNone(diagnostic)
        self.assertEqual(status, {"available": True, "generic_unlock_error": False,
                                  "secret_key_format_error": False, "processing": True})
        self.assertEqual(fake.requests.count("AXChildren"), 3)

    def test_unsupported_children_reports_fixed_code_and_false_status(self):
        leaf = element("AXStaticText", AXDescription=macos.STATUS_TEXT[0][1])
        root = element("AXWindow", [leaf], AXTitle=TITLE)
        status, diagnostic, fake = self.probe(root, {(leaf, "AXChildren"): (UNSUPPORTED, None)})
        self.assertEqual(status, macos._empty_status())
        self.assertIs(type(diagnostic["error"]), int)
        self.assertEqual(diagnostic, {"operation": "status-walk", "attribute": "AXChildren",
                                      "error": UNSUPPORTED})
        line = contract.failure_line(contract.ContractError("a11y-query", diagnostic),
                                     "snapshot", -1, "macos")
        self.assertEqual(FOUR_FIELD.fullmatch(line).group(1), "a11y-query")
        for text in (line, json.dumps(diagnostic)):
            self.assertNotIn(CANARY, text)
            self.assertNotIn(TITLE, text)
        self.assertEqual(fake.requests.count("AXChildren"), 2)

    def test_unsupported_description_is_an_absent_label(self):
        first = element("AXStaticText", AXDescription=macos.STATUS_TEXT[0][1])
        second = element("AXStaticText", AXDescription=macos.STATUS_TEXT[1][1])
        root = element("AXWindow", [first, second], AXTitle=TITLE)
        status, diagnostic, fake = self.probe(
            root, {(second, "AXDescription"): (UNSUPPORTED, None)})
        self.assertIsNone(diagnostic)
        self.assertEqual(status, {"available": True, "generic_unlock_error": True,
                                  "secret_key_format_error": False, "processing": False})
        self.assertEqual(fake.requests.count("AXDescription"), 2)
        self.assertNotIn("AXValue", fake.requests)

    def test_unsupported_description_on_every_static_text_keeps_walk(self):
        leaf = element("AXStaticText", AXDescription="ignored")
        root = element("AXWindow", [leaf], AXTitle=TITLE)
        status, diagnostic, fake = self.probe(root, {(leaf, "AXDescription"): (UNSUPPORTED, None)})
        self.assertIsNone(diagnostic)
        self.assertEqual(status, {"available": True, "generic_unlock_error": False,
                                  "secret_key_format_error": False, "processing": False})
        self.assertEqual(fake.requests.count("AXChildren"), 2)

    def test_other_description_errors_still_refuse(self):
        leaf = element("AXStaticText", AXDescription=macos.STATUS_TEXT[2][1])
        root = element("AXWindow", [leaf], AXTitle=TITLE)
        for reply in ((-25204, None), (UNKNOWN, None), (-25206, None), (True, None)):
            with self.subTest(reply=reply):
                status, diagnostic, _ = self.probe(root, {(leaf, "AXDescription"): reply})
                self.assertEqual(status, macos._empty_status())
                self.assertEqual(diagnostic["operation"], "status-walk")
                self.assertEqual(diagnostic["attribute"], "AXDescription")

    def test_unsupported_is_not_accepted_for_role_or_other_errors(self):
        leaf = element("AXStaticText", AXDescription=macos.STATUS_TEXT[2][1])
        root = element("AXWindow", [leaf], AXTitle=TITLE)
        for node, name in ((root, "AXRole"), (leaf, "AXRole"), (leaf, "AXChildren")):
            with self.subTest(attribute=name):
                status, diagnostic, _ = self.probe(root, {(node, name): (UNSUPPORTED, None)})
                self.assertEqual(status, macos._empty_status())
                self.assertEqual(diagnostic, {"operation": "status-walk", "attribute": name,
                                              "error": UNSUPPORTED})

    def test_sanitizer_allowlists_codes_and_keeps_four_field_lines(self):
        record = lambda attribute, error: contract.ax_diagnostic(contract.ContractError(
            "a11y-query", {"operation": "status-walk", "attribute": attribute,
                           "error": error}))
        self.assertEqual(record("AXRole", NO_VALUE), {"operation": "status-walk",
                                                      "attribute": "AXRole",
                                                      "error": NO_VALUE})
        self.assertEqual(record("AXWindows", UNSUPPORTED)["attribute"], "other")
        for error in (UNKNOWN, True, float(NO_VALUE), str(UNSUPPORTED), None, CANARY):
            with self.subTest(error=error):
                self.assertEqual(record("AXChildren", error)["error"], "other")
        for guard in ({"operation": "window-bind", "attribute": "AXChildren", "error": NO_VALUE},
                      None):
            line = contract.failure_line(contract.ContractError("a11y-query", guard),
                                         "snapshot", -1, "macos")
            self.assertEqual(FOUR_FIELD.fullmatch(line).group(1), "a11y-query")
            self.assertNotIn(CANARY, line)


if __name__ == "__main__":
    unittest.main()
