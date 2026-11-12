"""Pure contract tests: validation, ordering, refusals, once-only inputs.

No OS window, no GUI, no accessibility permission and no real input is used.
"""
import io
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import native_acceptance_contract as contract

LABEL = "确认连接此扩展"
OTHER_LABEL = "解锁"
PRIVATE = "synthetic-private-canary-value"
TITLE = "Locklark · 浏览器原生确认"
EXE = "/opt/locklark/test-browser"
WINDOW = {"id": 0x200003, "pid": 4242, "title": TITLE, "executable": EXE, "trusted": True,
          "visible": True, "onscreen": True, "secure": False,
          "bounds": {"x": 100, "y": 100, "width": 800, "height": 600},
          "client": {"x": 110, "y": 140, "width": 780, "height": 560}}


def control(label, **overrides):
    value = {"role": "push button", "name": label,
             "bounds": {"x": 200, "y": 300, "width": 80, "height": 30},
             "enabled": True, "visible": True}
    value.update(overrides)
    return value


class SpyAdapter:
    """Records every observation and every physical input, in order."""

    platform = "linux"
    supports_activation = True
    exact_focus = True
    input_evidence = "accepted"

    def __init__(self, windows=None, controls=None, focus=None, capabilities=None,
                 focus_window=None, hit=True, screen=None, visible=True,
                 control_hit=True):
        self.windows = [dict(WINDOW)] if windows is None else windows
        self.controls = [control(LABEL)] if controls is None else controls
        self.focus = WINDOW["pid"] if focus is None else focus
        self.focus_window = WINDOW["id"] if focus_window is None else focus_window
        self.hit = hit
        self.control_hit = control_hit
        self.control_hits = []
        self.screen = screen
        self.visible = visible
        self.calls = []
        self.activations = 0
        self._capabilities = capabilities or []
        self.click_ack = {"move": True, "down": True, "up": True}

    def check_capability(self):
        if self._capabilities:
            raise contract.ContractError(self._capabilities[0])

    def list_windows(self):
        self.calls.append("list_windows")
        return [dict(window) for window in self.windows]

    def read_window(self, identifier):
        self.calls.append("read_window")
        for window in self.windows:
            if window["id"] == identifier:
                return dict(window)
        return None

    def read_controls(self, window):
        self.calls.append("read_controls")
        return [dict(item) for item in self.controls]

    def focus_state(self, window=None):
        self.calls.append("focus_state")
        return {"pid": self.focus, "window": self.focus_window}

    def screen_bounds(self):
        return self.screen

    def hit_test(self, window, x, y):
        self.calls.append("hit_test")
        return self.hit

    def hit_test_control(self, window, label, rect, x, y):
        self.calls.append("hit_test_control")
        self.control_hits.append((window["id"], label, dict(rect), x, y))
        if isinstance(self.control_hit, Exception):
            raise self.control_hit
        return self.control_hit

    def point_visible(self, window, x, y):
        self.calls.append("point_visible")
        return self.visible

    def activate(self, window):
        self.activations += 1
        self.calls.append("activate")

    def click(self, x, y):
        self.calls.append(("click", x, y))
        return dict(self.click_ack)

    def type_text(self, text):
        self.calls.append("type_text")

    def press_chord(self, parts):
        self.calls.append("press_chord")


def request(**overrides):
    document = {"title": TITLE, "executable": EXE, "actions": [{"click_label": LABEL}]}
    document.update(overrides)
    return json.dumps({key: value for key, value in document.items() if value is not None})


class RequestValidationTests(unittest.TestCase):
    def test_x11_compatible_document_parses(self):
        plan = contract.parse_request(request(inspect=True))
        self.assertEqual(plan["title"], TITLE)
        self.assertEqual(plan["executable"], EXE)
        self.assertEqual(plan["actions"][0]["click_label"], LABEL)
        self.assertTrue(plan["inspect"])

    def test_title_prefix_popup_form_and_preserve_focus(self):
        plan = contract.parse_request(json.dumps(
            {"title_prefix": "Locklark acceptance", "actions": [{"key": "Escape"}],
             "preserve_focus": True}))
        self.assertEqual(plan["title_prefix"], "Locklark acceptance")
        self.assertEqual(plan["actions"][0]["key"], ("Escape",))

    def test_exact_title_preserve_focus_is_a_read_only_observation(self):
        # The route-revocation no-prompt check needs: the exact native title
        # (never a prefix), no actions, preserve_focus and no inspect. That
        # combination is the read-only form the X11 adapter implements as an
        # absent report (no raise, focus or click), so it must stay valid here.
        plan = contract.parse_request(json.dumps(
            {"title": TITLE, "executable": EXE, "actions": [],
             "preserve_focus": True}))
        self.assertEqual(plan["title"], TITLE)
        self.assertIsNone(plan["title_prefix"])
        self.assertEqual(plan["actions"], ())
        self.assertTrue(plan["preserve_focus"])
        self.assertFalse(plan["inspect"])
        self.assertFalse(plan["wait_absent"])
        # The raising inspect form is a different mode and is unchanged.
        plain = contract.parse_request(request(inspect=True))
        self.assertTrue(plain["inspect"])
        self.assertFalse(plain["preserve_focus"])
        # The two focus modes can never describe one request.
        for document in ({"title": TITLE, "inspect": True, "preserve_focus": True},
                         {"title_prefix": "Locklark", "actions": [{"click_label": LABEL}],
                          "inspect": True, "preserve_focus": True}):
            with self.subTest(document=str(sorted(document))):
                with self.assertRaises(contract.ContractError) as error:
                    contract.parse_request(json.dumps(document))
                self.assertEqual(error.exception.code, "request-invalid")
                self.assertEqual(error.exception.guard, {"field": "inspect"})

    def test_unknown_request_and_action_keys_rejected(self):
        for document in ({"title": TITLE, "value": PRIVATE},
                         {"title": TITLE, "actions": [{"click_label": LABEL, "secret": PRIVATE}]}):
            with self.subTest(keys=sorted(document)):
                with self.assertRaises(contract.ContractError) as error:
                    contract.parse_request(json.dumps(document))
                self.assertEqual(error.exception.code, "request-unknown-key")

    def test_duplicate_json_key_rejected(self):
        raw = '{"title":"%s","title":"%s"}' % (TITLE, TITLE)
        with self.assertRaises(contract.ContractError) as error:
            contract.parse_request(raw)
        self.assertEqual(error.exception.code, "request-duplicate-key")

    def test_bounded_limits_rejected(self):
        cases = [
            {"title": TITLE, "actions": [{"click_label": LABEL}] * (contract.MAX_ACTIONS + 1)},
            {"title": TITLE, "actions": [{"text": "a" * (contract.MAX_TEXT + 1)}]},
            {"title": TITLE, "actions": [{"text": "naïve"}]},
            {"title": TITLE, "actions": [{"click": [contract.CLICK_LIMIT + 1, 0]}]},
            {"title": TITLE, "actions": [{"click": [0]}]},
            {"title": TITLE, "actions": [{"key": "+".join(["a"] * (contract.MAX_CHORD_PARTS + 1))}]},
            {"title": "x" * (contract.MAX_TITLE + 1)},
            {"title": TITLE, "executable": "relative/browser"},
            {"title": TITLE, "actions": "click"},
            {"title": TITLE, "inspect": "yes"},
            {"title": TITLE, "title_prefix": "Locklark"},
            {"actions": [{"click_label": LABEL}]},
        ]
        for document in cases:
            with self.subTest(document=str(sorted(document))):
                with self.assertRaises(contract.ContractError):
                    contract.parse_request(json.dumps(document))

    def test_oversize_and_malformed_requests_rejected(self):
        with self.assertRaises(contract.ContractError) as error:
            contract.parse_request("{" + " " * contract.MAX_REQUEST_BYTES)
        self.assertEqual(error.exception.code, "request-oversize")
        for raw in (b"not-json", b"[]", b"\xff\xfe", b"null"):
            with self.assertRaises(contract.ContractError) as error:
                contract.parse_request(raw)
            self.assertEqual(error.exception.code, "request-invalid")

    def test_malicious_label_is_refused_without_echo(self):
        with self.assertRaises(contract.ContractError) as error:
            contract.parse_request(request(actions=[{"click_label": PRIVATE}]))
        self.assertEqual(error.exception.code, "label-not-allowed")
        line = contract.failure_line(error.exception, "discover", 0, "windows")
        self.assertNotIn(PRIVATE, line)
        self.assertIn("code=label-not-allowed", line)

    def test_absence_request_requires_exact_identity_and_no_actions(self):
        plan = contract.parse_request(json.dumps({"title": TITLE, "executable": EXE, "wait_absent": True}))
        self.assertTrue(plan["wait_absent"])
        for document in ({"title": TITLE, "wait_absent": True},
                         {"title": TITLE, "executable": EXE, "wait_absent": True,
                          "actions": [{"click_label": LABEL}]},
                         {"title": TITLE, "executable": EXE, "wait_absent": True, "inspect": True}):
            with self.subTest(document=str(sorted(document))):
                with self.assertRaises(contract.ContractError) as error:
                    contract.parse_request(json.dumps(document))
                self.assertEqual(error.exception.code, "absence-invalid")

    def test_labels_come_only_from_the_existing_x11_constant(self):
        import browser_native_x11 as x11
        self.assertIs(contract.X11_CONTROL_LABELS, x11.CONTROL_LABELS)
        self.assertEqual(len(contract.KNOWN_SYNTHETIC_LABELS), len(x11.CONTROL_LABELS))
        self.assertIn(LABEL, contract.KNOWN_SYNTHETIC_LABELS)

    def test_importing_contract_never_initialises_a_platform_library(self):
        code = (
            "import ctypes, sys\n"
            "real = ctypes.CDLL\n"
            "created = []\n"
            "ctypes.CDLL = lambda *a, **k: created.append(a or k) or real(*a, **k)\n"
            "sys.path.insert(0, %r)\n"
            "import native_acceptance_contract as c\n"
            "import browser_native_windows, browser_native_macos, native_acceptance_driver\n"
            "assert created == [], created\n"
            "print(len(c.KNOWN_SYNTHETIC_LABELS))\n"
        ) % os.path.dirname(os.path.abspath(contract.__file__))
        done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(int(done.stdout.strip()), len(contract.KNOWN_SYNTHETIC_LABELS))


class ExecutionGuardTests(unittest.TestCase):
    def execute(self, adapter, **overrides):
        plan = contract.parse_request(request(**overrides))
        with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
            return contract.execute(plan, adapter)

    def assert_refused(self, adapter, code, **overrides):
        with self.assertRaises(contract.ContractError) as error:
            self.execute(adapter, **overrides)
        self.assertEqual(error.exception.code, code, error.exception.args)
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)], [])

    def test_click_is_emitted_once_after_reobservation(self):
        adapter = SpyAdapter()
        result = self.execute(adapter)
        self.assertEqual(adapter.calls[0], "list_windows")
        self.assertEqual(adapter.calls[-1], ("click", 240, 315))
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)],
                         [("click", 240, 315)])
        self.assertEqual(result["clicks"][0]["x"], 240)
        self.assertEqual(result["clicks"][0]["y"], 315)
        self.assertEqual(result["clicks"][0]["label"], LABEL)
        self.assertEqual(result["clicks"][0]["ack"], {"move": True, "down": True, "up": True})
        self.assertEqual(result["clicks"][0]["evidence"], "accepted")
        self.assertNotIn("title", result)

    def test_failed_ack_is_not_retried(self):
        adapter = SpyAdapter()
        adapter.click_ack = {"move": False, "down": False, "up": False}
        result = self.execute(adapter)
        self.assertEqual(len([call for call in adapter.calls if isinstance(call, tuple)]), 1)
        self.assertEqual(result["clicks"][0]["ack"], {"move": False, "down": False, "up": False})

    def test_multiple_windows_refused_before_input(self):
        adapter = SpyAdapter(windows=[dict(WINDOW), dict(WINDOW, id=0x200004)])
        self.assert_refused(adapter, "window-ambiguous")

    def test_hidden_missing_and_off_screen_windows_refused(self):
        for overrides, code in (({"visible": False}, "window-hidden"),
                                ({"onscreen": False}, "window-offscreen"),
                                ({"bounds": {"x": 0, "y": 0, "width": 0, "height": 0}}, "window-geometry"),
                                ({"secure": True}, "secure-desktop"),
                                ({"trusted": False}, "process-untrusted"),
                                ({"executable": "/opt/other/browser"}, "process-untrusted"),
                                ({"pid": 0}, "process-ambiguous")):
            with self.subTest(code=code):
                self.assert_refused(SpyAdapter(windows=[dict(WINDOW, **overrides)]), code)

    def test_control_states_refused_before_input(self):
        for overrides, code in (({"enabled": False}, "control-disabled"),
                                ({"visible": False}, "control-hidden"),
                                ({"bounds": {"x": 0, "y": 0, "width": 0, "height": 0}}, "control-geometry"),
                                ({"bounds": {"x": 900, "y": 300, "width": 40, "height": 20}}, "control-offscreen"),
                                ({"role": "panel"}, "control-missing")):
            with self.subTest(code=code):
                self.assert_refused(SpyAdapter(controls=[control(LABEL, **overrides)]), code)

    def test_ambiguous_control_refused(self):
        self.assert_refused(SpyAdapter(controls=[control(LABEL), control(LABEL)]), "control-ambiguous")

    def test_focus_mismatch_activates_once_then_refuses(self):
        adapter = SpyAdapter(focus=999)
        self.assert_refused(adapter, "focus-lost")
        self.assertEqual(adapter.activations, 1)

    def test_same_pid_other_window_refused(self):
        adapter = SpyAdapter(focus_window=0x200004)
        self.assert_refused(adapter, "focus-lost")
        self.assertEqual(adapter.activations, 1)

    def test_click_point_must_hit_the_selected_window(self):
        adapter = SpyAdapter(hit=False)
        self.assert_refused(adapter, "control-offscreen")

    def test_click_point_must_be_on_a_visible_display(self):
        for verdict in (False, None, "yes", 1):
            with self.subTest(verdict=verdict):
                self.assert_refused(SpyAdapter(visible=verdict), "control-offscreen")

    def test_click_point_outside_virtual_screen_refused(self):
        adapter = SpyAdapter(screen={"x": 0, "y": 0, "width": 100, "height": 100})
        self.assert_refused(adapter, "control-offscreen")

    def test_unknown_input_evidence_refused_before_input(self):
        adapter = SpyAdapter()
        adapter.input_evidence = "native"
        self.assert_refused(adapter, "input-unsupported")

    def test_posted_evidence_is_reported_for_post_only_platforms(self):
        adapter = SpyAdapter()
        adapter.input_evidence = "posted"
        result = self.execute(adapter)
        self.assertEqual(result["clicks"][0]["evidence"], "posted")

    def test_preserve_focus_never_steals_focus(self):
        adapter = SpyAdapter(windows=[dict(WINDOW, title="Locklark acceptance popup")], focus=999)
        self.assert_refused(adapter, "preserve-focus-lost", title=None,
                            title_prefix="Locklark acceptance", preserve_focus=True)
        self.assertEqual(adapter.activations, 0)

    def test_capability_refusal_precedes_every_observation(self):
        adapter = SpyAdapter(capabilities=["capability-unavailable"])
        self.assert_refused(adapter, "capability-unavailable")
        self.assertEqual(adapter.calls, [])

    def test_late_control_query_cannot_authorise_input(self):
        adapter = SpyAdapter()
        plan = contract.parse_request(request(actions=[{"wait_label": LABEL},
                                                       {"click_label": LABEL}]))
        with patch.object(contract, "monotonic", side_effect=[0, 0, 0, 11]), \
                patch.object(contract, "sleep"):
            with self.assertRaises(contract.ContractError) as error:
                contract.execute(plan, adapter)
        self.assertEqual(error.exception.code, "control-ready-timeout")
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)], [])

    def test_observation_overrun_refused(self):
        adapter = SpyAdapter(controls=[control(LABEL)] * (contract.MAX_CONTROLS + 1))
        self.assert_refused(adapter, "control-overrun")

    def test_pointer_offset_resolves_inside_client_area(self):
        adapter = SpyAdapter()
        result = self.execute(adapter, actions=[{"click": [10, 20]}])
        self.assertEqual(adapter.calls[-1], ("click", 120, 160))
        self.assertEqual(result["clicks"][0]["label"], "pointer")

    def test_pointer_offset_outside_client_refused(self):
        self.assert_refused(SpyAdapter(), "control-offscreen", actions=[{"click": [5000, 10]}])

    def test_text_and_key_emit_once_each_after_focus(self):
        adapter = SpyAdapter()
        self.execute(adapter, actions=[{"text": "abc"}, {"key": "Control_L+a"}])
        self.assertEqual(adapter.calls.count("type_text"), 1)
        self.assertEqual(adapter.calls.count("press_chord"), 1)
        self.assertLess(adapter.calls.index("type_text"), adapter.calls.index("press_chord"))
        self.assertGreater(adapter.calls.index("type_text"), adapter.calls.index("focus_state"))

    def test_absent_window_reports_only_absence(self):
        adapter = SpyAdapter(windows=[])
        result = self.execute(adapter, actions=[], wait_absent=True)
        self.assertEqual(result, {"absent": True})

    def test_absence_timeout_refused(self):
        adapter = SpyAdapter()
        plan = contract.parse_request(json.dumps(
            {"title": TITLE, "executable": EXE, "wait_absent": True}))
        with patch.object(contract, "monotonic", side_effect=[0, 0, 0, 11]), \
                patch.object(contract, "sleep"):
            with self.assertRaises(contract.ContractError) as error:
                contract.execute(plan, adapter)
        self.assertEqual(error.exception.code, "window-changed")

    def test_inspect_snapshot_has_only_public_state(self):
        adapter = SpyAdapter(controls=[control(LABEL), control(OTHER_LABEL, enabled=False)])
        result = self.execute(adapter, actions=[], inspect=True)
        self.assertEqual(set(result["controls"]), set(contract.KNOWN_SYNTHETIC_LABELS))
        self.assertEqual(result["controls"][LABEL],
                         {"present": True, "enabled": True, "showing": True})
        self.assertEqual(result["controls"][OTHER_LABEL],
                         {"present": True, "enabled": False, "showing": True})
        self.assertNotIn(PRIVATE, json.dumps(result))


class _Hookless(SpyAdapter):
    """An adapter that never implemented the strict control-hit hook."""

    def __getattribute__(self, name):
        if name == "hit_test_control":
            raise AttributeError(name)
        return super().__getattribute__(name)


class ControlHitIdentityTests(unittest.TestCase):
    """The point must resolve to the SELECTED control, not just its window."""

    def execute(self, adapter, **overrides):
        plan = contract.parse_request(request(**overrides))
        with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
            return contract.execute(plan, adapter)

    def clicks(self, adapter):
        return [call for call in adapter.calls if isinstance(call, tuple)]

    def refused(self, adapter, code, **overrides):
        with self.assertRaises(contract.ContractError) as error:
            self.execute(adapter, **overrides)
        self.assertEqual(error.exception.code, code, error.exception.args)
        self.assertEqual(self.clicks(adapter), [])
        return error.exception

    def test_selected_control_is_re_probed_between_point_check_and_click(self):
        adapter = SpyAdapter()
        result = self.execute(adapter)
        self.assertEqual(adapter.calls.count("hit_test"), 1)
        self.assertEqual(adapter.calls.count("hit_test_control"), 1)
        self.assertLess(adapter.calls.index("hit_test"), adapter.calls.index("hit_test_control"))
        self.assertLess(adapter.calls.index("hit_test_control"),
                        adapter.calls.index(("click", 240, 315)))
        self.assertEqual(result["clicks"][0]["x"], 240)

    def test_probe_receives_the_authorising_control_rect_and_centre(self):
        adapter = SpyAdapter()
        self.execute(adapter)
        self.assertEqual(adapter.control_hits, [
            (WINDOW["id"], LABEL, control(LABEL)["bounds"], 240, 315)])

    def test_sibling_or_transparent_overlay_at_the_centre_refuses(self):
        adapter = SpyAdapter(control_hit=False)
        self.refused(adapter, "control-hit")
        self.assertEqual(len(adapter.control_hits), 1)

    def test_only_the_literal_true_authorises_the_click(self):
        for verdict in (False, None, 1, "yes", [], {"hit": True}):
            with self.subTest(verdict=verdict):
                self.refused(SpyAdapter(control_hit=verdict), "control-hit")
        result = self.execute(SpyAdapter(control_hit=True))
        self.assertEqual(len(result["clicks"]), 1)

    def test_a_missing_hook_is_refused_not_trusted_by_omission(self):
        self.refused(_Hookless(), "control-hit")

    def test_a_failing_probe_refuses_without_any_click(self):
        self.refused(SpyAdapter(control_hit=ValueError("boom")), "a11y-query")
        self.refused(SpyAdapter(control_hit=contract.ContractError("control-missing")),
                     "control-missing")

    def test_ambiguous_control_is_refused_before_the_strict_probe(self):
        adapter = SpyAdapter(controls=[control(LABEL), control(LABEL)])
        self.refused(adapter, "control-ambiguous")
        self.assertEqual(adapter.control_hits, [])

    def test_pointer_offset_clicks_keep_the_window_root_check_only(self):
        adapter = SpyAdapter()
        result = self.execute(adapter, actions=[{"click": [10, 20]}])
        self.assertEqual(result["clicks"][0]["label"], "pointer")
        self.assertEqual(adapter.calls.count("hit_test"), 1)
        self.assertEqual(adapter.control_hits, [])

    def test_wait_text_and_key_actions_never_probe_a_control_hit(self):
        for action in ({"wait_label": LABEL}, {"text": "ascii"}, {"key": "Tab"}):
            with self.subTest(action=action):
                adapter = SpyAdapter()
                self.execute(adapter, actions=[action])
                self.assertEqual(adapter.control_hits, [])


class OutputSafetyTests(unittest.TestCase):
    def run_driver(self, adapter, raw, platform="windows"):
        stdout, stderr = io.StringIO(), io.StringIO()
        status = contract.run_stdin(adapter, platform, io.BytesIO(raw), stdout, stderr)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_failure_output_is_one_fixed_line_without_request_values(self):
        adapter = SpyAdapter(windows=[])
        with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
            with patch.object(contract, "DISCOVER_TIMEOUT", -1):
                status, out, err = self.run_driver(
                    adapter, request(title=PRIVATE + " title").encode())
        self.assertEqual(status, 1)
        self.assertEqual(out, "")
        self.assertNotIn(PRIVATE, err)
        self.assertEqual(err.count("\n"), 1)
        self.assertRegex(err, r"^Native acceptance input failed \[code=[a-z-]+ action=[a-z-]+ index=-?\d+ platform=windows\]$")

    def test_unexpected_exception_is_reported_without_details(self):
        class Broken(SpyAdapter):
            def list_windows(self):
                raise ValueError(PRIVATE)

        status, out, err = self.run_driver(Broken(), request().encode())
        self.assertEqual(status, 1)
        self.assertEqual(out, "")
        self.assertIn("code=unexpected", err)
        self.assertNotIn(PRIVATE, err)

    def test_success_output_is_bounded_json(self):
        adapter = SpyAdapter()
        with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
            status, out, err = self.run_driver(adapter, request().encode())
        self.assertEqual(status, 0)
        self.assertEqual(err, "")
        payload = json.loads(out)
        self.assertEqual(payload["window"], "0x200003")
        self.assertEqual(len(payload["clicks"]), 1)
        self.assertNotIn("title", payload)
        self.assertNotIn(PRIVATE, out)

    def test_success_output_contains_no_request_title_or_prefix(self):
        adapter = SpyAdapter(windows=[dict(WINDOW, title="Locklark acceptance popup")])
        with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
            status, out, err = self.run_driver(
                adapter,
                request(title=None, title_prefix="Locklark acceptance").encode())
        self.assertEqual(status, 0, err)
        self.assertNotIn("title", json.loads(out))
        self.assertNotIn("Locklark acceptance", out)

    def test_unknown_platform_name_in_failure_line_is_neutralised(self):
        line = contract.failure_line(contract.ContractError("request-invalid"), PRIVATE, PRIVATE, PRIVATE)
        self.assertNotIn(PRIVATE, line)
        self.assertIn("platform=unknown", line)
        self.assertIn("action=setup", line)


if __name__ == "__main__":
    unittest.main()
