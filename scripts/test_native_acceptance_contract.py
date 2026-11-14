"""Pure contract tests: validation, ordering, refusals, once-only inputs.

No OS window, no GUI, no accessibility permission and no real input is used.
"""
import io
import json
import os
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import browser_native_macos as macos
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
        # A prefix, a missing title or executable, or any action is never the
        # read-only form. The refusal stays the fixed request-invalid guard.
        no_prompt = {"title": TITLE, "executable": EXE, "actions": [],
                     "inspect": True, "preserve_focus": True}
        for change in ({"title": None, "title_prefix": "Locklark"},
                       {"title": None},
                       {"executable": None},
                       {"executable": "relative/browser"},
                       {"actions": [{"click_label": LABEL}]},
                       {"actions": [{"wait_label": LABEL}]},
                       {"actions": [{"key": "Escape"}]},
                       {"actions": [{"click": [10, 20]}]},
                       {"wait_absent": True}):
            document = {key: value for key, value in {**no_prompt, **change}.items()
                        if value is not None}
            with self.subTest(change=str(sorted(change))):
                with self.assertRaises(contract.ContractError) as error:
                    contract.parse_request(json.dumps(document))
                self.assertIn(error.exception.code, ("request-invalid", "absence-invalid",
                                                     "title-invalid", "executable-invalid"))
                if error.exception.code == "request-invalid":
                    self.assertEqual(error.exception.guard, {"field": "inspect"})

    def test_exact_title_preserve_focus_inspection_parses_read_only(self):
        # The route no-prompt check sends exactly this document and reads
        # result["controls"]; it must parse AND snapshot without naming any
        # absent-window mode.
        document = {"title": TITLE, "executable": EXE, "actions": [],
                    "inspect": True, "preserve_focus": True}
        plan = contract.parse_request(json.dumps(document))
        self.assertEqual(plan["title"], TITLE)
        self.assertIsNone(plan["title_prefix"])
        self.assertEqual(plan["executable"], EXE)
        self.assertEqual(plan["actions"], ())
        self.assertTrue(plan["inspect"])
        self.assertTrue(plan["preserve_focus"])
        self.assertFalse(plan["wait_absent"])
        adapter = SpyAdapter(controls=[control(LABEL)])
        with patch.object(contract, "monotonic",
                          side_effect=[0, 0, 0, contract.DISCOVER_TIMEOUT + 1]), \
                patch.object(contract, "sleep"):
            result = contract.execute(contract.parse_request(json.dumps(document)), adapter)
        self.assertNotIn("absent", result)
        self.assertEqual(result["controls"][LABEL],
                         {"present": True, "enabled": True, "showing": True})
        self.assertNotIn("title", result)
        # It stays a read-only snapshot: no activation and no physical input.
        self.assertEqual(adapter.activations, 0)
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)], [])

    def test_focus_preserving_inspection_never_absorbs_a_missing_or_ambiguous_window(self):
        document = {"title": TITLE, "executable": EXE, "actions": [],
                    "inspect": True, "preserve_focus": True}
        plan = contract.parse_request(json.dumps(document))
        for windows, code in (([], "window-timeout"),
                              ([dict(WINDOW), dict(WINDOW, id=0x200004)], "window-ambiguous"),
                              ([dict(WINDOW, visible=False)], "window-hidden")):
            with self.subTest(code=code):
                adapter = SpyAdapter(windows=windows)
                with patch.object(contract, "monotonic",
                                  side_effect=[0, 0, 0, contract.DISCOVER_TIMEOUT + 1]), \
                        patch.object(contract, "sleep"):
                    with self.assertRaises(contract.ContractError) as error:
                        contract.execute(plan, adapter)
                self.assertEqual(error.exception.code, code)
                self.assertEqual(adapter.activations, 0)
                self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)], [])

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

    def test_cli_broker_review_labels_are_allowlisted(self):
        import browser_native_x11 as x11
        expected = ("仅批准本次 CLI 请求", "拒绝本次请求")
        for label in expected:
            with self.subTest(label=label):
                self.assertIn(label, x11.CONTROL_LABELS)
                self.assertIn(label, contract.KNOWN_SYNTHETIC_LABELS)
                for action in ({"click_label": label}, {"wait_label": label}):
                    with self.subTest(action=sorted(action)):
                        plan = contract.parse_request(request(actions=[action]))
                        self.assertEqual(plan["actions"][0], action)

    def test_unapproved_cli_broker_like_label_is_rejected(self):
        for label in ("仅批准本次 CLI 请求。", "仅批准本次 CLI 请求 ", "批准本次 CLI 请求",
                      "拒绝本次 CLI 请求", "拒绝本次请求（CLI）"):
            with self.subTest(label=label):
                with self.assertRaises(contract.ContractError) as error:
                    contract.parse_request(request(actions=[{"click_label": label}]))
                self.assertEqual(error.exception.code, "label-not-allowed")

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


def activation(pid=4242, executable=EXE):
    return json.dumps({"activate_pid": pid, "executable": executable})


class ActivationRequestTests(unittest.TestCase):
    def test_exact_pid_and_executable_form_is_accepted(self):
        plan = contract.parse_request(activation())
        self.assertEqual(plan["activation"], {"pid": 4242, "executable": EXE})
        self.assertEqual(plan["actions"], ())
        self.assertIsNone(plan["title"])
        self.assertFalse(plan["inspect"] or plan["wait_absent"] or plan["preserve_focus"])

    def test_pid_must_be_a_positive_plain_int(self):
        for pid in (True, False, 0, -1, 1.0, "4242", None, [4242]):
            with self.subTest(pid=pid):
                with self.assertRaises(contract.ContractError) as error:
                    contract.parse_request(activation(pid=pid))
                self.assertEqual(error.exception.code, "activation-invalid")
        self.assertEqual(contract.parse_request(activation(pid=2))["activation"]["pid"], 2)

    def test_executable_must_be_absolute_and_exact(self):
        for executable in ("locklark-desktop", "", "/opt//locklark", None, ["/opt/x"]):
            with self.subTest(executable=executable):
                with self.assertRaises(contract.ContractError) as error:
                    contract.parse_request(activation(executable=executable))
                self.assertEqual(error.exception.code, "executable-invalid")
        with self.assertRaises(contract.ContractError) as error:
            contract.parse_request(json.dumps({"activate_pid": 4242}))
        self.assertEqual(error.exception.code, "activation-invalid")

    def test_title_action_inspect_and_window_fields_are_rejected(self):
        extras = ({"title": TITLE}, {"title_prefix": "Locklark"},
                  {"actions": [{"click_label": LABEL}]}, {"inspect": False},
                  {"wait_absent": True}, {"preserve_focus": True},
                  {"window": 0x200003}, {"value": PRIVATE})
        for extra in extras:
            with self.subTest(extra=sorted(extra)):
                raw = json.dumps(dict({"activate_pid": 4242, "executable": EXE}, **extra))
                with self.assertRaises(contract.ContractError) as error:
                    contract.parse_request(raw)
                self.assertEqual(error.exception.code, "activation-invalid")
                self.assertNotIn(PRIVATE, contract.failure_line(error.exception, "activate", -1, "macos"))

    def test_duplicate_key_and_oversize_keep_their_fixed_refusals(self):
        with self.assertRaises(contract.ContractError) as error:
            contract.parse_request('{"activate_pid":4242,"activate_pid":4242,"executable":"%s"}' % EXE)
        self.assertEqual(error.exception.code, "request-duplicate-key")
        with self.assertRaises(contract.ContractError) as error:
            contract.parse_request(activation(executable="/" + "a" * contract.MAX_REQUEST_BYTES))
        self.assertEqual(error.exception.code, "request-oversize")

    def test_normal_requests_keep_their_matching_and_input_authorisation(self):
        plan = contract.parse_request(request(inspect=True))
        self.assertNotIn("activation", plan)
        adapter = SpyAdapter()
        budget = contract.Budget()
        window = contract.find_window(plan, adapter, budget)
        self.assertEqual(window["id"], WINDOW["id"])
        self.assertEqual(adapter.calls, ["list_windows"])
        self.assertEqual(adapter.activations, 0)

    def test_activation_only_request_never_observes_or_inputs(self):
        adapter = SpyAdapter()

        def activate_process(pid, executable):
            adapter.calls.append(("activate_process", pid, executable))
            return True

        adapter.activate_process = activate_process
        result = contract.execute(contract.parse_request(activation()), adapter)
        self.assertEqual(result, {"activated": True})
        self.assertEqual(adapter.calls, [("activate_process", 4242, EXE)])
        self.assertEqual(adapter.activations, 0)

    def test_activation_refusals_are_fixed_without_request_values(self):
        class Refusing(SpyAdapter):
            def activate_process(self, pid, executable):
                raise contract.ContractError("process-untrusted")

        plan = contract.parse_request(activation())
        with self.assertRaises(contract.ContractError) as error:
            contract.execute(plan, Refusing())
        line = contract.failure_line(error.exception, "activate", -1, "macos")
        self.assertEqual(line, "Native acceptance input failed [code=process-untrusted "
                               "action=activate index=-1 platform=macos]")
        self.assertNotIn(EXE, line)

    def test_only_a_literal_true_activation_result_succeeds(self):
        for verdict, code in ((True, None), (1, "activation-failed"), (None, "activation-failed"),
                              ("yes", "activation-failed")):
            with self.subTest(verdict=verdict):
                class Verdict(SpyAdapter):
                    def activate_process(self, pid, executable):
                        self.activations += 1
                        return verdict

                plan = contract.parse_request(activation())
                if code is None:
                    self.assertEqual(contract.execute(plan, Verdict()), {"activated": True})
                else:
                    with self.assertRaises(contract.ContractError) as error:
                        contract.execute(plan, Verdict())
                    self.assertEqual(error.exception.code, code)

    def test_run_stdin_reports_fixed_activation_result_and_failure(self):
        def stdin_adapter(verdict):
            class Adapter(SpyAdapter):
                def activate_process(self, pid, executable):
                    self.calls.append(("activate_process", pid, executable))
                    if isinstance(verdict, Exception):
                        raise verdict
                    return verdict
            return Adapter()

        adapter = stdin_adapter(True)
        stdout, stderr = io.StringIO(), io.StringIO()
        status = contract.run_stdin(adapter, "macos", stdin=io.BytesIO(activation().encode()),
                                    stdout=stdout, stderr=stderr)
        self.assertEqual((status, stdout.getvalue(), stderr.getvalue()),
                         (0, '{"activated": true}\n', ""))
        self.assertEqual(adapter.calls, [("activate_process", 4242, EXE)])
        adapter = stdin_adapter(OSError(PRIVATE))
        stdout, stderr = io.StringIO(), io.StringIO()
        status = contract.run_stdin(adapter, "macos", stdin=io.BytesIO(activation().encode()),
                                    stdout=stdout, stderr=stderr)
        self.assertEqual((status, stdout.getvalue()), (1, ""))
        self.assertEqual(stderr.getvalue(), "Native acceptance input failed [code=activation-failed "
                                            "action=activate index=-1 platform=macos]\n")
        self.assertNotIn(PRIVATE, stderr.getvalue())


class ExecutionGuardTests(unittest.TestCase):
    def run_plan(self, adapter, **overrides):
        plan = contract.parse_request(request(**overrides))
        with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
            return contract.execute(plan, adapter)

    def assert_refused(self, adapter, code, **overrides):
        with self.assertRaises(contract.ContractError) as error:
            self.run_plan(adapter, **overrides)
        self.assertEqual(error.exception.code, code, error.exception.args)
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)], [])

    def test_click_is_emitted_once_after_reobservation(self):
        adapter = SpyAdapter()
        result = self.run_plan(adapter)
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
        result = self.run_plan(adapter)
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
                                # A wrong-executable title match is not a candidate for an
                                # executable-scoped request: the target is absent, never selected,
                                # so with the frozen clock the bounded poll budget ends discovery.
                                # (The zero-timeout refusal is covered by ExecutableScopedDiscoveryTests.)
                                ({"executable": "/opt/other/browser"}, "observe-overrun"),
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
        for verdict in (None, 1, "yes"):
            with self.subTest(verdict=verdict):
                self.assert_refused(SpyAdapter(hit=verdict), "a11y-query")

    def test_click_point_must_be_on_a_visible_display(self):
        # A successful False proves the point outside every active display.
        self.assert_refused(SpyAdapter(visible=False), "control-offscreen")
        # Any other answer is an unknown query state, never a miss.
        for verdict in (None, "yes", 1, 0):
            with self.subTest(verdict=verdict):
                self.assert_refused(SpyAdapter(visible=verdict), "a11y-query")
        adapter = SpyAdapter()
        adapter.point_visible = lambda window, x, y: (_ for _ in ()).throw(OSError("display"))
        self.assert_refused(adapter, "a11y-query")
        adapter = SpyAdapter(hit=None)
        adapter.hit_test = lambda window, x, y: (_ for _ in ()).throw(OSError("root"))
        self.assert_refused(adapter, "a11y-query")

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
        result = self.run_plan(adapter)
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
        result = self.run_plan(adapter, actions=[{"click": [10, 20]}])
        self.assertEqual(adapter.calls[-1], ("click", 120, 160))
        self.assertEqual(result["clicks"][0]["label"], "pointer")

    def test_pointer_offset_outside_client_refused(self):
        self.assert_refused(SpyAdapter(), "control-offscreen", actions=[{"click": [5000, 10]}])

    def test_text_and_key_emit_once_each_after_focus(self):
        adapter = SpyAdapter()
        self.run_plan(adapter, actions=[{"text": "abc"}, {"key": "Control_L+a"}])
        self.assertEqual(adapter.calls.count("type_text"), 1)
        self.assertEqual(adapter.calls.count("press_chord"), 1)
        self.assertLess(adapter.calls.index("type_text"), adapter.calls.index("press_chord"))
        self.assertGreater(adapter.calls.index("type_text"), adapter.calls.index("focus_state"))

    def test_absent_window_reports_only_absence(self):
        adapter = SpyAdapter(windows=[])
        result = self.run_plan(adapter, actions=[], wait_absent=True)
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
        result = self.run_plan(adapter, actions=[], inspect=True)
        self.assertEqual(set(result["controls"]), set(contract.KNOWN_SYNTHETIC_LABELS))
        self.assertEqual(result["controls"][LABEL],
                         {"present": True, "enabled": True, "showing": True})
        self.assertEqual(result["controls"][OTHER_LABEL],
                         {"present": True, "enabled": False, "showing": True})
        self.assertNotIn(PRIVATE, json.dumps(result))


class ExecutableScopedDiscoveryTests(unittest.TestCase):
    """Title collisions from other executables never make the request ambiguous."""

    def setUp(self):
        self.clock = FakeClock()
        for name in ("monotonic", "sleep"):
            patcher = patch.object(contract, name, getattr(self.clock, name))
            patcher.start()
            self.addCleanup(patcher.stop)

    def clicks(self, adapter):
        return [call for call in adapter.calls if isinstance(call, tuple)]

    def test_foreign_same_title_window_plus_target_selects_only_target(self):
        # The other process owns an exact-title window with its own PID and id.
        foreign = dict(WINDOW, id=0x500001, pid=5150, executable="/opt/other/locklark")
        adapter = ChurningAdapter([[foreign], [foreign, dict(WINDOW)]])
        result = contract.execute(contract.parse_request(request()), adapter)
        self.assertEqual(result["window"], hex(WINDOW["id"]))
        self.assertEqual(adapter.lists, 2)
        self.assertEqual(self.clicks(adapter), [("click", 240, 315)])
        self.assertEqual([hit[0] for hit in adapter.control_hits], [WINDOW["id"]])

    def test_two_exact_title_windows_from_requested_executable_still_ambiguous(self):
        # Same executable, distinct PID and window ids: still two candidates.
        for sibling in (dict(WINDOW, id=0x200004),
                        dict(WINDOW, id=0x200004, pid=4243)):
            with self.subTest(sibling=sibling):
                adapter = SpyAdapter(windows=[dict(WINDOW), sibling])
                with self.assertRaises(contract.ContractError) as error:
                    contract.execute(contract.parse_request(request()), adapter)
                self.assertEqual(error.exception.code, "window-ambiguous")
                self.assertEqual(self.clicks(adapter), [])

    def test_wrong_executable_only_snapshot_is_absent_and_never_selected(self):
        foreign = dict(WINDOW, id=0x500001, pid=5150, executable="/opt/other/locklark")
        adapter = ChurningAdapter([[foreign]])
        plan = contract.parse_request(request())
        with patch.object(contract, "DISCOVER_TIMEOUT", -1):
            with self.assertRaises(contract.ContractError) as error:
                contract.execute(plan, adapter)
        self.assertEqual(error.exception.code, "window-timeout")
        self.assertEqual(adapter.lists, 1)
        self.assertEqual(self.clicks(adapter), [])
        self.assertNotIn("read_controls", adapter.calls)
        self.assertNotIn("hit_test", adapter.calls)
        self.assertNotIn("focus_state", adapter.calls)
        self.assertEqual(adapter.activations, 0)

    def test_no_executable_request_keeps_title_only_ambiguity(self):
        foreign = dict(WINDOW, id=0x500001, pid=5150, executable="/opt/other/locklark")
        adapter = SpyAdapter(windows=[dict(WINDOW), foreign])
        with self.assertRaises(contract.ContractError) as error:
            contract.execute(contract.parse_request(request(executable=None)), adapter)
        self.assertEqual(error.exception.code, "window-ambiguous")
        self.assertEqual(self.clicks(adapter), [])


class FakeClock:
    """Deterministic monotonic/sleep aliases for the discovery deadline."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def background_window(index):
    """A visible foreign window that shares no title or executable with the target.

    Even indices compress onto one small tile, so many distinct identities can
    be folded into a single snapshot that still stays under the 512 cap.
    """
    w, h = divmod(0x300000 + index, 600)
    tiled = index % 2 == 0
    return dict(WINDOW, id=0x300000 + 0x200 * index, pid=100000 + index,
                title=f"background {index}", executable=f"/usr/bin/other-{index}",
                bounds=({"x": 0, "y": 0, "width": 20, "height": 20} if tiled else
                        {"x": (w % 10) * 200, "y": h * 120, "width": 180, "height": 100}),
                client={"x": 110, "y": 140, "width": 780, "height": 560})


class RepeatingAdapter(SpyAdapter):
    """Replays one snapshot per discovery poll, then the exact target."""

    def __init__(self, repeated, target, target_poll):
        super().__init__(windows=repeated)
        self.target = target
        self.target_poll = target_poll
        self.lists = 0

    def list_windows(self):
        self.lists += 1
        if self.lists > self.target_poll:
            self.windows = [self.target]
        return super().list_windows()


class ChurningAdapter(SpyAdapter):
    """Serves a per-poll sequence of window snapshots."""

    def __init__(self, snapshots):
        super().__init__(windows=snapshots[0])
        self.snapshots = snapshots
        self.lists = 0

    def list_windows(self):
        self.windows = self.snapshots[min(self.lists, len(self.snapshots) - 1)]
        self.lists += 1
        return super().list_windows()


class WindowSnapshotBudgetTests(unittest.TestCase):
    """A stable desktop is charged once; unbounded window churn still refuses."""

    def setUp(self):
        self.clock = FakeClock()
        for name in ("monotonic", "sleep"):
            patcher = patch.object(contract, name, getattr(self.clock, name))
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_plan(self, adapter, **overrides):
        return contract.execute(contract.parse_request(request(**overrides)), adapter)

    def test_stable_background_polls_then_exact_target_succeeds(self):
        background = [background_window(index) for index in range(20)]
        # 80 background polls is 4.0s of the 5.0s discovery window.
        adapter = RepeatingAdapter(background, dict(WINDOW), target_poll=80)
        result = self.run_plan(adapter)
        self.assertEqual(adapter.lists, 81)
        self.assertLess(self.clock.now, contract.DISCOVER_TIMEOUT)
        self.assertEqual(len(self.clock.sleeps), 80)
        self.assertEqual(result["window"], hex(WINDOW["id"]))
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)],
                         [("click", 240, 315)])

    def test_stable_background_never_overruns_and_still_times_out(self):
        background = [background_window(index) for index in range(400)]
        adapter = RepeatingAdapter(background, dict(WINDOW), target_poll=10 ** 6)
        with self.assertRaises(contract.ContractError) as error:
            self.run_plan(adapter)
        self.assertEqual(error.exception.code, "window-timeout")
        self.assertGreaterEqual(self.clock.now, contract.DISCOVER_TIMEOUT)
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)], [])

    def test_single_snapshot_over_limit_refuses(self):
        over = [background_window(index) for index in range(contract.MAX_WINDOWS + 1)]
        adapter = ChurningAdapter([over, [dict(WINDOW)]])
        with self.assertRaises(contract.ContractError) as error:
            self.run_plan(adapter)
        self.assertEqual(error.exception.code, "window-overrun")
        self.assertEqual(adapter.lists, 1)
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)], [])

    def test_snapshot_at_limit_is_accepted(self):
        exact = [background_window(index) for index in range(contract.MAX_WINDOWS - 1)]
        adapter = ChurningAdapter([exact + [dict(WINDOW)]])
        self.assertEqual(self.run_plan(adapter)["window"], hex(WINDOW["id"]))
        self.assertEqual(adapter.lists, 1)

    def test_repeated_identities_are_deduplicated(self):
        budget = contract.Budget()
        background = [background_window(index) for index in range(20)]
        for _ in range(10):
            budget.charge_windows([dict(window) for window in background])
        self.assertEqual(budget.counts["windows"], 20)
        self.assertEqual(budget.counts["observations"], 10)
        budget.charge_windows([background_window(0), dict(WINDOW)])
        self.assertEqual(budget.counts["windows"], 21)

    def test_same_window_id_under_other_pid_is_distinct(self):
        budget = contract.Budget()
        budget.charge_windows([background_window(0)])
        budget.charge_windows([dict(background_window(0), pid=777)])
        self.assertEqual(budget.counts["windows"], 2)
        self.assertEqual(budget.identities, {(100000, background_window(0)["id"]),
                                             (777, background_window(0)["id"])})

    def test_more_than_limit_distinct_identities_across_snapshots_refuses(self):
        # Fold many distinct identities into a small snapshot under the
        # per-snapshot cap: 0..499, then 55..451 (all repeats), then 500..512
        # for the first time.  The distinct cap must catch what the per-snapshot
        # cap misses even though no single snapshot exceeds MAX_WINDOWS.
        identities = [background_window(index) for index in range(contract.MAX_WINDOWS + 1)]
        budget = contract.Budget()
        budget.charge_windows([dict(window) for window in identities[:500]])
        repeats = identities[55:452]
        budget.charge_windows([dict(window) for window in repeats])
        self.assertEqual(budget.counts["windows"], 500)  # repeats deduplicated
        final = identities[500:513]
        self.assertLessEqual(len(final), contract.MAX_WINDOWS)
        with self.assertRaises(contract.ContractError) as error:
            budget.charge_windows(final)
        self.assertEqual(error.exception.code, "window-overrun")
        self.assertEqual(budget.counts["windows"], contract.MAX_WINDOWS + 1)

    def test_distinct_identity_churn_before_target_refuses(self):
        churn = [[background_window(index * 512 + step) for step in range(512)]
                 for index in range(2)]
        adapter = ChurningAdapter(churn + [[dict(WINDOW)]])
        with self.assertRaises(contract.ContractError) as error:
            self.run_plan(adapter)
        self.assertEqual(error.exception.code, "window-overrun")
        self.assertEqual(adapter.lists, 2)
        self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)], [])

    def test_absence_polling_of_stable_desktop_does_not_overrun(self):
        # A background-only desktop stays stable for 120 absence polls, then
        # the foreign snapshot vanishes; a repeated snapshot is never recharged.
        adapter = RepeatingAdapter([dict(WINDOW)], [], target_poll=120)
        result = self.run_plan(adapter, actions=None, wait_absent=True)
        self.assertEqual(result, {"absent": True})
        self.assertLess(self.clock.now, contract.CONTROL_TIMEOUT)


class _Hookless(SpyAdapter):
    """An adapter that never implemented the strict control-hit hook."""

    def __getattribute__(self, name):
        if name == "hit_test_control":
            raise AttributeError(name)
        return super().__getattribute__(name)


class ControlHitIdentityTests(unittest.TestCase):
    """The point must resolve to the SELECTED control, not just its window."""

    def run_plan(self, adapter, **overrides):
        plan = contract.parse_request(request(**overrides))
        with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
            return contract.execute(plan, adapter)

    def clicks(self, adapter):
        return [call for call in adapter.calls if isinstance(call, tuple)]

    def refused(self, adapter, code, **overrides):
        with self.assertRaises(contract.ContractError) as error:
            self.run_plan(adapter, **overrides)
        self.assertEqual(error.exception.code, code, error.exception.args)
        self.assertEqual(self.clicks(adapter), [])
        return error.exception

    def test_selected_control_is_re_probed_between_point_check_and_click(self):
        adapter = SpyAdapter()
        result = self.run_plan(adapter)
        self.assertEqual(adapter.calls.count("hit_test"), 1)
        self.assertEqual(adapter.calls.count("hit_test_control"), 1)
        self.assertLess(adapter.calls.index("hit_test"), adapter.calls.index("hit_test_control"))
        self.assertLess(adapter.calls.index("hit_test_control"),
                        adapter.calls.index(("click", 240, 315)))
        self.assertEqual(result["clicks"][0]["x"], 240)

    def test_probe_receives_the_authorising_control_rect_and_centre(self):
        adapter = SpyAdapter()
        self.run_plan(adapter)
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
        result = self.run_plan(SpyAdapter(control_hit=True))
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
        result = self.run_plan(adapter, actions=[{"click": [10, 20]}])
        self.assertEqual(result["clicks"][0]["label"], "pointer")
        self.assertEqual(adapter.calls.count("hit_test"), 1)
        self.assertEqual(adapter.control_hits, [])

    def test_wait_text_and_key_actions_never_probe_a_control_hit(self):
        for action in ({"wait_label": LABEL}, {"text": "ascii"}, {"key": "Tab"}):
            with self.subTest(action=action):
                adapter = SpyAdapter()
                self.run_plan(adapter, actions=[action])
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


HOSTILE_CALLS = []


class HostileMixin:
    """Every comparison, arithmetic, conversion or representation is recorded.

    If the contract ever used these values as geometry (normalising them into a
    plain int, comparing or adding them in ``rect_within`` or the click
    arithmetic), one of these methods would run; the tests assert none does.
    """

    def __bool__(self):
        HOSTILE_CALLS.append("__bool__")
        return True

    def __int__(self):
        HOSTILE_CALLS.append("__int__")
        return int.__int__(self)

    def __index__(self):
        HOSTILE_CALLS.append("__index__")
        return int.__index__(self)

    def __float__(self):
        HOSTILE_CALLS.append("__float__")
        return float.__float__(self)

    def __complex__(self):
        HOSTILE_CALLS.append("__complex__")
        return complex(self)

    def __trunc__(self):
        HOSTILE_CALLS.append("__trunc__")
        return int(self)

    def __round__(self, ndigits=None):
        HOSTILE_CALLS.append("__round__")
        return 0

    def __eq__(self, other):
        HOSTILE_CALLS.append("__eq__")
        return NotImplemented

    def __ne__(self, other):
        HOSTILE_CALLS.append("__ne__")
        return NotImplemented

    def __lt__(self, other):
        HOSTILE_CALLS.append("__lt__")
        return NotImplemented

    def __le__(self, other):
        HOSTILE_CALLS.append("__le__")
        return NotImplemented

    def __gt__(self, other):
        HOSTILE_CALLS.append("__gt__")
        return NotImplemented

    def __ge__(self, other):
        HOSTILE_CALLS.append("__ge__")
        return NotImplemented

    def __add__(self, other):
        HOSTILE_CALLS.append("__add__")
        return NotImplemented

    def __radd__(self, other):
        HOSTILE_CALLS.append("__radd__")
        return NotImplemented

    def __sub__(self, other):
        HOSTILE_CALLS.append("__sub__")
        return NotImplemented

    def __rsub__(self, other):
        HOSTILE_CALLS.append("__rsub__")
        return NotImplemented

    def __mul__(self, other):
        HOSTILE_CALLS.append("__mul__")
        return NotImplemented

    def __floordiv__(self, other):
        HOSTILE_CALLS.append("__floordiv__")
        return NotImplemented

    def __truediv__(self, other):
        HOSTILE_CALLS.append("__truediv__")
        return NotImplemented

    def __hash__(self):
        HOSTILE_CALLS.append("__hash__")
        return 0

    def __repr__(self):
        HOSTILE_CALLS.append("__repr__")
        return "Hostile"


class HostileInt(HostileMixin, int):
    """A positive integral int subclass with overridden comparison/addition."""


class HostileIntNegative(HostileInt):
    def __new__(cls, value):
        return int.__new__(cls, -value)


class HostileFloat(HostileMixin, float):
    """A finite float subclass with overridden comparison/addition."""


FRACTIONAL = {"x": 200.5, "y": 300.25, "width": 81.0, "height": 31.5}


class GeometryValidationTests(unittest.TestCase):
    """Shared rectangles: exact built-in ints or finite built-in floats only."""

    def setUp(self):
        del HOSTILE_CALLS[:]

    def hostile(self):
        # Hostile int and float subclasses (positive, zero and negative
        # ints, finite fractional and integral floats).
        return [HostileInt(800), HostileInt(1), HostileInt(0), HostileIntNegative(800),
                HostileFloat(800.5), HostileFloat(1.0), HostileFloat(0.0)]

    def window_with(self, value, key="width"):
        # A hostile adapter hands the hostile value through unchanged (``dict``
        # copies references, so no method of the value runs); the shared
        # contract must still refuse it.
        window = dict(WINDOW, bounds=dict(WINDOW["bounds"], **{key: value}))
        adapter = SpyAdapter(windows=[window])
        adapter.list_windows = lambda: [dict(window)]
        return adapter

    def test_window_and_control_accept_finite_fractional_floats(self):
        window = dict(WINDOW, bounds={"x": 100.5, "y": 99.75, "width": 800.0, "height": 600.5})
        self.assertTrue(contract.rect_positive(window["bounds"]))
        self.assertTrue(contract.rect_within(FRACTIONAL, window["client"]))
        adapter = SpyAdapter(windows=[window], controls=[control(LABEL, bounds=dict(FRACTIONAL))])
        result = self.executed(adapter)
        self.assertEqual(self.clicks(adapter), [("click", 241.0, 316.0)])
        self.assertEqual((result["clicks"][0]["x"], result["clicks"][0]["y"]), (241.0, 316.0))
        self.assertEqual(adapter.control_hits,
                         [(WINDOW["id"], LABEL, dict(FRACTIONAL), 241.0, 316.0)])

    def test_geometry_value_is_exactly_the_builtin_value(self):
        for value, expected in ((800, 800), (800.0, 800.0)):
            with self.subTest(value=value):
                self.assertEqual(contract.geometry_value(value), expected)
                self.assertIs(type(contract.geometry_value(value)), type(value))

    def test_geometry_rejects_bool_nonfinite_subclass_and_nonnumeric_values(self):
        malformed = [True, False, float("nan"), float("inf"), float("-inf"),
                     "1", None, [1], object()] + self.hostile()
        for value in malformed:
            for key in ("x", "y", "width", "height"):
                with self.subTest(value=value, key=key):
                    rect = dict(WINDOW["bounds"], **{key: value})
                    self.assertIsNone(contract.geometry_value(value))
                    self.assertFalse(contract.rect_positive(rect))
                    with self.assertRaises(contract.ContractError) as error:
                        self.executed(self.window_with(value, key))
                    self.assertEqual(error.exception.code, "window-geometry")
        self.assertEqual(HOSTILE_CALLS, [])

    def test_int_subclass_window_geometry_is_rejected_at_every_field(self):
        for value in self.hostile():
            for key in ("x", "y", "width", "height"):
                with self.subTest(value=value, key=key):
                    adapter = self.window_with(value, key)
                    with self.assertRaises(contract.ContractError) as error:
                        self.executed(adapter)
                    self.assertEqual(error.exception.code, "window-geometry")
                    self.assertEqual(self.clicks(adapter), [])
        self.assertEqual(HOSTILE_CALLS, [])

    def test_control_geometry_rejects_every_non_plain_nonfinite_and_subclass_value(self):
        for value in [True, float("nan"), float("inf"), float("-inf"), "80", None] + self.hostile():
            with self.subTest(value=value):
                adapter = SpyAdapter(controls=[control(LABEL, bounds=dict(FRACTIONAL, width=value))])
                self.assert_refused(adapter, "control-geometry")
        self.assert_refused(SpyAdapter(controls=[control(LABEL, bounds={})]), "control-geometry")
        self.assertEqual(HOSTILE_CALLS, [])

    def test_int_subclass_control_geometry_never_reaches_rect_within_or_click(self):
        # A fractional control whose fields compare/add cleanly as plain values
        # but whose subclass methods are hostile: a normalised copy would pass
        # rect_within and the click path, so the exact-type check must refuse
        # first, before any comparison, addition or conversion runs.
        for value in self.hostile():
            for key in ("x", "y", "width", "height"):
                with self.subTest(value=value, key=key):
                    adapter = SpyAdapter(controls=[control(LABEL, bounds=dict(FRACTIONAL, **{key: value}))])
                    self.assert_refused(adapter, "control-geometry")
                    self.assertNotIn("hit_test", adapter.calls)
                    self.assertNotIn("hit_test_control", adapter.calls)
        self.assertEqual(HOSTILE_CALLS, [])

    def test_hostile_window_bounds_are_rejected_before_discovery(self):
        # A hostile window-bound field is never geometry: discovery refuses.
        for value in self.hostile():
            for key in ("x", "y", "width", "height"):
                with self.subTest(value=value, key=key):
                    adapter = self.window_with(value, key)
                    with self.assertRaises(contract.ContractError) as error:
                        self.executed(adapter)
                    self.assertEqual(error.exception.code, "window-geometry")
                    self.assertEqual(self.clicks(adapter), [])
        self.assertEqual(HOSTILE_CALLS, [])

    def test_hostile_window_client_is_never_used_as_geometry(self):
        # A hostile client rectangle is not geometry: rect_positive and
        # rect_within refuse it, so the click paths fall back to the plain
        # window bounds and never offset by the hostile value.
        for value in self.hostile():
            with self.subTest(value=value):
                client = {"x": value, "y": 140, "width": 780, "height": 560}
                self.assertFalse(contract.rect_positive(client))
                self.assertFalse(contract.rect_within(FRACTIONAL, client))
        self.assertEqual(HOSTILE_CALLS, [])
        # The selected pointer click then reports the plain-bounds offset.
        window = dict(WINDOW, client={"x": HostileInt(110), "y": 140,
                                      "width": 780, "height": 560})
        adapter = SpyAdapter(windows=[window])
        result = self.executed(adapter, actions=[{"click": [10, 20]}])
        self.assertEqual(self.clicks(adapter), [("click", 110, 120)])
        self.assertEqual((result["clicks"][0]["x"], result["clicks"][0]["y"]), (110, 120))
        # And no comparison, addition or conversion on the hostile value ran
        # during discovery, authorisation, input or the receipt.
        self.assertEqual(HOSTILE_CALLS, [])

    def test_integer_rect_accepts_integral_and_rejects_fractional_values(self):
        # Exact ints are handed back as ints; integral finite floats convert.
        self.assertEqual(contract.integer_rect(dict(WINDOW["bounds"])), WINDOW["bounds"])
        for key in ("x", "y", "width", "height"):
            self.assertIs(type(contract.integer_rect(dict(WINDOW["bounds"]))[key]), int)
        integral = {"x": 100.0, "y": 200.0, "width": 800.0, "height": 600.0}
        result = contract.integer_rect(integral)
        self.assertEqual(result, {"x": 100, "y": 200, "width": 800, "height": 600})
        self.assertEqual([type(value) for value in result.values()], [int, int, int, int])
        mixed = {"x": 100, "y": 200.0, "width": 801.0, "height": 600}
        self.assertEqual(contract.integer_rect(mixed),
                         {"x": 100, "y": 200, "width": 801, "height": 600})
        # A fractional coordinate or extent is refused, never truncated.
        for key in ("x", "y"):
            with self.subTest(fractional=key):
                rect = dict(integral, **{key: 100.5})
                self.assertTrue(contract.rect_positive(rect))
                self.assertIsNone(contract.integer_rect(rect))
        for key in ("width", "height"):
            with self.subTest(fractional=key):
                rect = dict(integral, **{key: 800.25})
                self.assertTrue(contract.rect_positive(rect))
                self.assertIsNone(contract.integer_rect(rect))
        # Non-positive extents and unusable values are refused too.
        self.assertIsNone(contract.integer_rect(dict(integral, width=0.0)))
        self.assertIsNone(contract.integer_rect(dict(integral, height=-1)))
        for value in [True, float("nan"), float("inf"), "1", None] + self.hostile():
            with self.subTest(value=value):
                self.assertIsNone(contract.integer_rect(dict(integral, width=value)))
        self.assertIsNone(contract.integer_rect(None))
        self.assertEqual(HOSTILE_CALLS, [])

    def test_int_subclass_window_rect_is_refused_by_rect_within_directly(self):
        # rect_within compares the ORIGINAL dict fields, so an int subclass
        # must be refused there even without going through discovery.
        inner = dict(FRACTIONAL)
        self.assertTrue(contract.rect_within(inner, WINDOW["client"]))
        for key in ("x", "y", "width", "height"):
            with self.subTest(key=key):
                self.assertFalse(contract.rect_within(dict(inner, **{key: HostileInt(1)}),
                                                      WINDOW["client"]))
                outer = dict(WINDOW["client"], **{key: HostileInt(1)})
                self.assertFalse(contract.rect_within(inner, outer))
        self.assertEqual(HOSTILE_CALLS, [])

    def test_fractional_rect_must_still_fit_inside_the_window_client(self):
        rect = {"x": 890.5, "y": 400.25, "width": 10.0, "height": 10.0}
        self.assertFalse(contract.rect_within(rect, WINDOW["client"]))
        self.assert_refused(SpyAdapter(controls=[control(LABEL, bounds=rect)]), "control-offscreen")
        # The exact integer limits are unchanged.
        edge = {"x": 880, "y": 690, "width": 10, "height": 10}
        self.assertTrue(contract.rect_within(edge, WINDOW["client"]))
        overflow = dict(edge, x=881)
        self.assertFalse(contract.rect_within(overflow, WINDOW["client"]))
        self.assert_refused(SpyAdapter(controls=[control(LABEL, bounds=overflow)]),
                            "control-offscreen")

    def test_control_and_observation_limits_are_unchanged(self):
        filler = [control(OTHER_LABEL, bounds={"x": 200 + index, "y": 400,
                                                "width": 10, "height": 10})
                  for index in range(contract.MAX_CONTROLS)]
        at_limit = SpyAdapter(controls=[control(LABEL)] + filler[:contract.MAX_CONTROLS - 1])
        self.executed(at_limit)  # exactly MAX_CONTROLS is still accepted
        over = SpyAdapter(controls=[control(LABEL)] + filler)
        self.assert_refused(over, "control-overrun")

    def test_click_receipt_keeps_the_exact_fraction_passed_to_the_adapter(self):
        for rect, point in ((FRACTIONAL, (241.0, 316.0)),
                            ({"x": 200.25, "y": 300.5, "width": 0.5, "height": 0.25},
                             (200.5, 300.625))):
            with self.subTest(rect=rect):
                adapter = SpyAdapter(controls=[control(LABEL, bounds=rect)])
                result = self.executed(adapter)
                self.assertEqual(self.clicks(adapter), [("click", point[0], point[1])])
                recorded = (result["clicks"][0]["x"], result["clicks"][0]["y"])
                self.assertEqual(recorded, point)
                for value in recorded:
                    self.assertIs(type(value), float)

    def test_receipt_refuses_a_point_that_is_not_the_clicked_geometry(self):
        window = dict(WINDOW)
        fractional = {"x": 200.5, "y": 300.25, "width": 80.5, "height": 30.5}
        for x, y in ((True, 315.5), (281.5, 315.5), (float("nan"), 315.5),
                     ("240", 315.5), (240.5, float("inf"))):
            with self.subTest(point=(x, y)):
                with self.assertRaises(contract.ContractError) as error:
                    contract.click_record(window, LABEL, x, y, None, rect=fractional)
                self.assertEqual(error.exception.code, "control-hit")
        # No rectangle: only integer geometry is the provable click geometry.
        self.assertEqual(contract.click_record(window, LABEL, 240, 315, None)["x"], 240)
        with self.assertRaises(contract.ContractError):
            contract.click_record(window, LABEL, 240.5, 315.25, None)
        recorded = contract.click_record(window, LABEL, 240.5, 315.25, None, rect=fractional)
        self.assertEqual((recorded["x"], recorded["y"]), (240.5, 315.25))

    def test_pointer_offset_preserves_fractional_client_geometry(self):
        adapter = SpyAdapter(windows=[dict(WINDOW, client={"x": 110.5, "y": 140.25,
                                                            "width": 780, "height": 560})])
        result = self.executed(adapter, actions=[{"click": [10, 20]}])
        self.assertEqual(self.clicks(adapter), [("click", 120.5, 160.25)])
        self.assertEqual((result["clicks"][0]["x"], result["clicks"][0]["y"]), (120.5, 160.25))

    def executed(self, adapter, **overrides):
        return ExecutionGuardTests.run_plan(self, adapter, **overrides)

    def clicks(self, adapter):
        return [call for call in adapter.calls if isinstance(call, tuple)]

    def assert_refused(self, adapter, code):
        with self.assertRaises(contract.ContractError) as error:
            self.executed(adapter)
        self.assertEqual(error.exception.code, code)
        self.assertEqual(self.clicks(adapter), [])
        self.assertEqual(adapter.control_hits, [])


def mac_points(rect):
    """The required candidate grid, as (x, y) pairs.

    The centre comes first: the historical integer centre for an integer
    rectangle (bit-for-bit the Windows/X11 point), the exact true centre
    otherwise.  Then the 20%/50%/80% fractions in row-major order,
    deduplicated against the centre, so the list is at most nine long (the
    50%/50% point is the centre already listed).
    """
    if all(type(rect[key]) is int for key in ("x", "y", "width", "height")):
        centre = (rect["x"] + rect["width"] // 2, rect["y"] + rect["height"] // 2)
    else:
        centre = (rect["x"] + rect["width"] / 2, rect["y"] + rect["height"] / 2)
    points = [centre]
    for fy in (0.2, 0.5, 0.8):
        for fx in (0.2, 0.5, 0.8):
            point = (rect["x"] + rect["width"] * fx, rect["y"] + rect["height"] * fy)
            if point not in points:
                points.append(point)
    return points[:contract.MAX_CLICK_CANDIDATES]


class CandidateAdapter(object):
    """A minimal macOS-shaped adapter; every observation is a local stub.

    ``hits`` maps the index of a point in ``points`` (the fixed 3x3 list of the
    served control rectangle) to True/False/an exception; every other point,
    including a covered centre, is a miss.  ``root_hit`` is the window-root
    verdict (a literal or a callable), ``hidden`` the indices of the invisible
    points, ``on_hit`` runs at each control probe and ``candidates`` replaces
    the list.
    """

    platform = "macos"
    input_evidence = "posted"
    exact_focus = True
    supports_activation = True
    screen = None

    def __init__(self, hits=None, hidden=(), on_hit=None, candidates=None,
                 root_hit=True, windows=None, control=None, focus_window=None):
        self.calls = []
        self.hits = dict(hits or {})
        self.hidden = list(hidden)
        self.on_hit = on_hit
        self.supplied = candidates
        self.root_hit = root_hit
        self.windows = [dict(WINDOW)] if windows is None else windows
        served = control if control is not None else CandidateClickTests.fractional_control()
        self.served = [dict(served)]
        self.focus_window = WINDOW["id"] if focus_window is None else focus_window
        bounds = self.served[0]["bounds"]
        self.points = mac_points(bounds) if type(bounds) is dict else []
        self.calls = []
        self.clicked = []
        self.probed = []
        self.control_hits = []

    # -- observation -------------------------------------------------------
    def check_capability(self):
        pass

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
        return [dict(item) for item in self.served]

    def focus_state(self, window=None):
        self.calls.append("focus_state")
        return {"pid": WINDOW["pid"], "window": self.focus_window}

    def hit_test(self, window, x, y):
        self.calls.append("hit_test")
        if not _within(window["client"], x, y):
            return False
        return self.root_hit(window, x, y) if callable(self.root_hit) else self.root_hit

    def point_visible(self, window, x, y):
        self.calls.append("point_visible")
        for index in self.hidden:
            point = self.points[index]
            if point[0] == x and point[1] == y:
                return False
        return True

    def click_candidates(self, rect):
        """The real MacAdapter list (the stub's points follow its order)."""
        self.calls.append("click_candidates")
        if self.supplied is not None:
            return self.supplied(rect)
        listed = macos.MacAdapter.click_candidates(rect)
        self.points = [(item["x"], item["y"]) for item in listed]
        return listed

    def hit_test_control(self, window, label, rect, x, y):
        self.calls.append("hit_test_control")
        self.control_hits.append((window["id"], label, dict(rect), x, y))
        self.probed.append((x, y))
        if self.on_hit is not None:
            self.on_hit((x, y))
        for index, point in enumerate(self.points):
            if point[0] == x and point[1] == y:
                verdict = self.hits.get(index, False)
                if isinstance(verdict, Exception):
                    raise verdict
                return verdict
        return False

    def activate(self, window):
        self.calls.append("activate")

    def click(self, x, y):
        self.clicked.append((x, y))
        return {"move": True, "down": True, "up": True}


def _within(rect, x, y):
    return (rect["x"] <= x < rect["x"] + rect["width"] and
            rect["y"] <= y < rect["y"] + rect["height"])


CANDIDATE_CONTROL = control(LABEL)


# The same control with genuine fractional (CGFloat) geometry: only such
# geometry takes the macOS candidate path at all.
CANDIDATE_FRACTIONAL = {"x": 200.5, "y": 300.25, "width": 80.5, "height": 30.5}
CANDIDATE_GRID = mac_points(CANDIDATE_FRACTIONAL)


class CandidateClickTests(unittest.TestCase):
    """macOS: the exact centre first, then bounded exact in-rect alternates."""

    BOUNDS = CANDIDATE_FRACTIONAL
    POINTS = CANDIDATE_GRID
    CENTRE = (CANDIDATE_FRACTIONAL["x"] + CANDIDATE_FRACTIONAL["width"] / 2,
              CANDIDATE_FRACTIONAL["y"] + CANDIDATE_FRACTIONAL["height"] / 2)

    @classmethod
    def fractional_control(cls):
        """A fresh copy of the shared label click with fractional bounds."""
        return control(LABEL, bounds=dict(CANDIDATE_FRACTIONAL))

    def run_plan(self, adapter, **overrides):
        plan = contract.parse_request(request(**overrides))
        with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
            return contract.execute(plan, adapter)

    def refused(self, adapter, code, **overrides):
        with self.assertRaises(contract.ContractError) as error:
            self.run_plan(adapter, **overrides)
        self.assertEqual(error.exception.code, code)
        self.assertEqual(adapter.clicked, [])
        return error.exception

    def execute(self, adapter, **overrides):
        return self.run_plan(adapter, **overrides)

    def test_candidates_are_bounded_fixed_and_strictly_in_bounds(self):
        # The fixed set: the centre first, then the 20%/50%/80% fractions in
        # row-major order, deduplicated against the centre, bounded at nine.
        rect = self.BOUNDS
        self.assertEqual(self.grid(rect),
                         [(240.75, 315.5), (216.6, 306.35), (240.75, 306.35),
                          (264.9, 306.35), (216.6, 315.5), (264.9, 315.5),
                          (216.6, 324.65), (240.75, 324.65), (264.9, 324.65)])
        self.assertEqual(self.POINTS, self.grid(rect))
        self.assertEqual(self.POINTS[0], self.CENTRE)
        self.assertEqual(len(self.POINTS), contract.MAX_CLICK_CANDIDATES)
        self.assertEqual(len(set(self.POINTS)), len(self.POINTS))
        for x, y in self.POINTS:
            self.assertEqual((type(x), type(y)), (float, float))
            self.assertTrue(rect["x"] <= x < rect["x"] + rect["width"])
            self.assertTrue(rect["y"] <= y < rect["y"] + rect["height"])
        # A different fractional rectangle keeps exactly the same shape: the
        # true centre first, then the same eight in-bounds fractions.
        odd = {"x": 400.5, "y": 300.25, "width": 80.5, "height": 31.25}
        listed = mac_points(odd)
        self.assertEqual(listed, self.grid(odd))
        self.assertEqual(listed[0], (400.5 + 80.5 / 2, 300.25 + 31.25 / 2))
        for x, y in listed:
            self.assertTrue(odd["x"] <= x < odd["x"] + odd["width"])
            self.assertTrue(odd["y"] <= y < odd["y"] + odd["height"])
        # An integer rectangle still starts at the historical integer centre
        # (the Windows/X11 point) and offers the same fixed in-bounds grid.
        for integral in ({"x": 200, "y": 300, "width": 80, "height": 30},
                         {"x": 200, "y": 300, "width": 81, "height": 31}):
            with self.subTest(integral=integral):
                expected = (integral["x"] + integral["width"] // 2,
                            integral["y"] + integral["height"] // 2)
                grid = mac_points(integral)
                self.assertEqual(grid[0], expected)
                self.assertEqual([(item["x"], item["y"]) for item in
                                  macos.MacAdapter.click_candidates(integral)], grid)
                self.assertLessEqual(len(grid), contract.MAX_CLICK_CANDIDATES)
                self.assertEqual(len(set(grid)), len(grid))
                for x, y in grid:
                    self.assertTrue(integral["x"] <= x < integral["x"] + integral["width"])
                    self.assertTrue(integral["y"] <= y < integral["y"] + integral["height"])

    def grid(self, rect):
        """The required set, rebuilt independently of MacAdapter."""
        if all(type(rect[key]) is int for key in ("x", "y", "width", "height")):
            points = [(rect["x"] + rect["width"] // 2, rect["y"] + rect["height"] // 2)]
        else:
            points = [(rect["x"] + rect["width"] / 2, rect["y"] + rect["height"] / 2)]
        for fy in (0.2, 0.5, 0.8):
            for fx in (0.2, 0.5, 0.8):
                point = (rect["x"] + rect["width"] * fx, rect["y"] + rect["height"] * fy)
                if point not in points:
                    points.append(point)
        return points[:contract.MAX_CLICK_CANDIDATES]

    def test_uncovered_centre_clicks_once_without_trying_alternates(self):
        adapter = CandidateAdapter(hits={0: True})
        result = self.run_plan(adapter)
        self.assertEqual(adapter.clicked, [self.CENTRE])
        # Proved once to accept, then the complete check again on the fresh
        # window before the single click.
        self.assertEqual(adapter.probed, [self.CENTRE, self.CENTRE])
        self.assertEqual(adapter.control_hits,
                         [(WINDOW["id"], LABEL, dict(self.BOUNDS), *self.CENTRE)] * 2)
        self.assertEqual(adapter.calls.count("click_candidates"), 1)
        recorded = result["clicks"][0]
        self.assertEqual((recorded["x"], recorded["y"]), self.CENTRE)
        self.assertEqual((type(recorded["x"]), type(recorded["y"])), (float, float))
        self.assertEqual(recorded["evidence"], "posted")
        self.assertEqual(recorded["ack"], {"move": True, "down": True, "up": True})
        self.assertEqual(recorded["label"], LABEL)
        self.assertEqual(recorded["window"], hex(WINDOW["id"]))
        self.assertEqual(result["window"], hex(WINDOW["id"]))

    def test_covered_centre_but_an_in_rect_candidate_reaches_the_control(self):
        for index in (1, 5, 8):
            with self.subTest(index=index):
                point = self.POINTS[index]
                adapter = CandidateAdapter(hits={index: True})
                result = self.run_plan(adapter)
                self.assertEqual(adapter.clicked, [point])
                self.assertEqual(adapter.calls.count("click_candidates"), 1)
                # Exactly the candidates up to and including the accepted one
                # were probed against the fresh selected control and its exact
                # authorising rectangle; the accepted point is then proved a
                # second time before input, and no later candidate is tried.
                self.assertEqual(adapter.probed, self.POINTS[:index + 1] + [point])
                self.assertEqual(adapter.control_hits,
                                 [(WINDOW["id"], LABEL, dict(self.BOUNDS), x, y)
                                  for x, y in self.POINTS[:index + 1] + [point]])
                recorded = result["clicks"][0]
                self.assertEqual((recorded["x"], recorded["y"]), point)
                self.assertEqual((type(recorded["x"]), type(recorded["y"])), (float, float))
                self.assertTrue(_within(self.BOUNDS, recorded["x"], recorded["y"]))
                self.assertEqual(recorded["ack"], {"move": True, "down": True, "up": True})

    def test_all_candidates_covered_refuses_without_any_click(self):
        adapter = CandidateAdapter(hits={})
        self.refused(adapter, "control-hit")
        self.assertEqual(adapter.probed, self.POINTS)
        self.assertLessEqual(len(adapter.probed), contract.MAX_CLICK_CANDIDATES)
        self.assertEqual(adapter.calls.count("click_candidates"), 1)
        # No point was accepted, so there is no post-accept re-proof.
        self.assertEqual(adapter.calls.count("hit_test_control"), len(self.POINTS))

    def test_invisible_points_move_to_the_next_candidate(self):
        point = self.POINTS[2]
        adapter = CandidateAdapter(hits={2: True}, hidden={0, 1})
        self.run_plan(adapter)
        self.assertEqual(adapter.clicked, [point])
        # A successful off-display verdict is a miss: those points were never
        # probed against the control and raise no refusal, so the search simply
        # moves on to the next in-bounds point (proved twice once accepted).
        self.assertEqual(adapter.probed, [point, point])

    def test_a_window_root_miss_moves_to_the_next_candidate(self):
        adapter = CandidateAdapter(
            hits={1: True}, root_hit=lambda window, x, y: (x, y) != self.POINTS[0])
        self.run_plan(adapter)
        self.assertEqual(adapter.clicked, [self.POINTS[1]])
        self.assertEqual(adapter.probed, [self.POINTS[1], self.POINTS[1]])

    def test_rect_change_during_search_refuses_without_any_click(self):
        adapter = CandidateAdapter(hits={3: True})

        def shrink(point):
            if point == self.POINTS[1]:
                adapter.served[0]["bounds"] = dict(CANDIDATE_FRACTIONAL, width=80.0)

        adapter.on_hit = shrink
        self.refused(adapter, "control-hit")
        self.assertEqual(adapter.probed, self.POINTS[:2])

    def test_query_error_during_search_refuses_without_any_click(self):
        adapter = CandidateAdapter(hits={4: True})

        def fail(point):
            if point == self.POINTS[1]:
                raise contract.ContractError("a11y-query")

        adapter.on_hit = fail
        self.refused(adapter, "a11y-query")
        self.assertEqual(adapter.probed, self.POINTS[:2])

    def test_probe_exception_is_a_query_refusal(self):
        adapter = CandidateAdapter(hits={3: True})
        original = adapter.hit_test_control

        def probe(window, label, rect, x, y):
            if (x, y) == self.POINTS[1]:
                raise OSError("AX position query failed")
            return original(window, label, rect, x, y)

        adapter.hit_test_control = probe
        self.refused(adapter, "a11y-query")

    def test_successful_probe_never_relaxes_to_a_later_candidate_on_click_uncertainty(self):
        # The single physical click is attempted exactly once; a click failure
        # is reported, never turned into permission to try the next point.
        adapter = CandidateAdapter(hits={0: True})

        def click(x, y):
            adapter.clicked.append((x, y))
            raise contract.ContractError("input-unknown")

        adapter.click = click
        with self.assertRaises(contract.ContractError) as error:
            self.run_plan(adapter)
        self.assertEqual(error.exception.code, "input-unknown")
        self.assertEqual(adapter.clicked, [self.CENTRE])
        self.assertEqual(adapter.calls.count("click_candidates"), 1)

    def test_ambiguity_and_missing_control_refuse_before_any_candidate(self):
        adapter = CandidateAdapter(hits={1: True})
        adapter.served = [self.fractional_control(), self.fractional_control()]
        self.refused(adapter, "control-ambiguous")
        self.assertEqual(adapter.probed, [])
        self.assertNotIn("click_candidates", adapter.calls)
        adapter = CandidateAdapter(hits={1: True}, control=control(OTHER_LABEL))
        self.refused(adapter, "control-missing")
        self.assertNotIn("click_candidates", adapter.calls)
        adapter = CandidateAdapter(hits={1: True}, control=control(LABEL, visible=False))
        self.refused(adapter, "control-hidden")
        self.assertNotIn("click_candidates", adapter.calls)

    def test_window_screen_control_and_focus_identity_failures_refuse(self):
        # A second (title, executable) match is ambiguous whatever its state;
        # a single ineligible tuple refuses its own fixed code.  Either way no
        # candidate is ever listed and nothing is probed or clicked.
        for change, code in (({"visible": False}, "window-hidden"),
                             ({"trusted": False}, "process-untrusted"),
                             ({"secure": True}, "secure-desktop"),
                             ({"visible": False, "trusted": False}, "window-hidden")):
            with self.subTest(code=code, change=change):
                adapter = CandidateAdapter(hits={5: True},
                                           windows=[dict(WINDOW), dict(WINDOW, **change)])
                self.refused(adapter, "window-ambiguous")
                self.assertNotIn("click_candidates", adapter.calls)
                self.assertEqual(adapter.probed, [])
                adapter = CandidateAdapter(hits={5: True}, windows=[dict(WINDOW, **change)])
                self.refused(adapter, code)
                self.assertNotIn("click_candidates", adapter.calls)
                self.assertEqual(adapter.probed, [])
        adapter = CandidateAdapter(hits={5: True}, focus_window=0x200004)
        self.refused(adapter, "focus-lost")
        self.assertNotIn("click_candidates", adapter.calls)
        # A changed window identity in the fresh observation refuses first.
        adapter = CandidateAdapter(hits={5: True}, windows=[dict(WINDOW)])
        adapter.read_window = lambda identifier: dict(WINDOW, id=0x200004)
        self.refused(adapter, "window-changed")
        self.assertNotIn("click_candidates", adapter.calls)
        # The window root never resolves to the selected window: a soft miss
        # for every candidate, then one refusal, with no probe.
        adapter = CandidateAdapter(hits={0: True}, root_hit=False)
        self.refused(adapter, "control-hit")
        self.assertEqual(adapter.probed, [])
        # No candidate reaches the freshly selected control element.
        self.refused(CandidateAdapter(hits={}), "control-hit")

    def test_post_accept_root_change_refuses_instead_of_resuming_the_search(self):
        # The accepted centre passes its full proof; an overlay then takes the
        # window root at that same point.  The fresh observation and the
        # complete re-proof on the SAME point must refuse before input, never
        # fall back to an in-bounds alternate that would still reach the field.
        for error in (False, contract.ContractError("a11y-query")):
            with self.subTest(error=error):
                state = {"accepted": False}

                def root(window, x, y):
                    if state["accepted"] and (x, y) == self.POINTS[0]:
                        if error is False:
                            return False
                        raise error
                    return True

                adapter = CandidateAdapter(hits={0: True, 1: True}, root_hit=root)
                original = adapter.hit_test_control

                def probe(window, label, rect, x, y):
                    if (x, y) == self.POINTS[0]:
                        state["accepted"] = True
                    return original(window, label, rect, x, y)

                adapter.hit_test_control = probe
                self.refused(adapter, "control-hit" if error is False else "a11y-query")
                self.assertEqual(adapter.clicked, [])
                # The re-proof stops at the root/display gate of the SAME
                # accepted point: no control probe and no alternate candidate.
                self.assertEqual(adapter.probed, [self.POINTS[0]])
                # It always follows the fresh window/control/focus observation.
                self.assertEqual(adapter.calls.count("read_window"), 2)

    def test_post_accept_display_change_refuses_instead_of_resuming_the_search(self):
        # The display is switched away (a valid False) or the display query
        # fails after acceptance; either way no input and no resume.
        for verdict in (False, contract.ContractError("a11y-query")):
            with self.subTest(verdict=verdict):
                # The window root always resolves: only the display query is
                # made to answer differently after acceptance.
                state = {"accepted": False}
                adapter = CandidateAdapter(hits={0: True, 1: True}, root_hit=True)
                original = adapter.hit_test_control

                def probe(window, label, rect, x, y):
                    if (x, y) == self.POINTS[0]:
                        state["accepted"] = True
                    return original(window, label, rect, x, y)

                def display(window, x, y):
                    if state["accepted"] and (x, y) == self.POINTS[0]:
                        if verdict is False:
                            return False
                        raise verdict
                    return True

                adapter.hit_test_control = probe
                adapter.point_visible = display
                # A valid miss refuses the whole search (control-hit), while
                # the failed display query aborts as a11y-query; neither clicks
                # nor resumes with an alternate.
                self.refused(adapter, "control-hit" if verdict is False else "a11y-query")
                self.assertEqual(adapter.clicked, [])
                self.assertEqual(adapter.probed, [self.POINTS[0]])
                self.assertEqual(adapter.calls.count("read_window"), 2)

    def test_post_accept_control_change_refuses_instead_of_resuming_the_search(self):
        state = {"accepted": False, "calls": 0}

        adapter = CandidateAdapter(hits={0: True, 1: True})
        original = adapter.read_controls

        def controls(window):
            if state["accepted"]:
                # The control is rebuilt under the point after acceptance.
                adapter.served[0]["bounds"] = dict(CANDIDATE_FRACTIONAL, width=80.0)
            return original(window)

        def probe(window, label, rect, x, y):
            state["calls"] += 1
            state["accepted"] = True
            return True

        adapter.read_controls = controls
        adapter.hit_test_control = probe
        self.refused(adapter, "control-hit")
        self.assertEqual(adapter.clicked, [])
        self.assertEqual(state["calls"], 1)  # no alternate was ever probed

    def test_first_hit_control_returns_fresh_window_and_point(self):
        adapter = CandidateAdapter(hits={0: True})
        plan = contract.parse_request(request())
        rect = dict(self.BOUNDS)
        with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
            fresh, point = contract.first_hit_control(
                plan, adapter, dict(WINDOW), LABEL, rect, [self.CENTRE],
                contract.Budget())
        self.assertEqual(point, self.CENTRE)
        self.assertIs(type(fresh), dict)
        self.assertEqual(fresh["id"], WINDOW["id"])
        for result in (None, self.CENTRE, (dict(WINDOW),), (dict(WINDOW), (1.0,)),
                       ("window", self.CENTRE), (dict(WINDOW), (True, 315.0)),
                       (dict(WINDOW), (float("nan"), 315.0))):
            with self.subTest(result=result):
                with self.assertRaises(contract.ContractError) as error:
                    contract.accepted_candidate(result)
                self.assertEqual(error.exception.code, "control-hit")
        # The module keeps no accepted-candidate state between calls.
        self.assertFalse(hasattr(contract, "_ACCEPTED_WINDOW"))
        self.assertFalse(hasattr(contract, "_accepted_window"))

    def test_focus_loss_during_search_refuses_without_any_click(self):
        adapter = CandidateAdapter(hits={1: True})

        def lose_focus(point):
            if point == self.POINTS[0]:
                adapter.focus_window = 0x200004

        adapter.on_hit = lose_focus
        self.refused(adapter, "focus-lost")
        self.assertEqual(adapter.probed, self.POINTS[:1])

    def test_invalid_candidate_shape_is_refused_before_any_probe(self):
        cases = (
            lambda rect: [],                                    # empty
            lambda rect: {"x": 216.0, "y": 306.0},              # not a list
            lambda rect: [{"x": 216.0, "y": 306.0}] * 10,       # overrun
            lambda rect: [{"x": 216.0}],                        # missing y
            lambda rect: [{"x": 216.0, "y": 306.0, "s": 1}],    # extra key
            lambda rect: [(216.0, 306.0)],                      # not named
            lambda rect: [{"x": True, "y": 306.0}],             # bool
            lambda rect: [{"x": "216", "y": 306.0}],            # string
            lambda rect: [{"x": float("nan"), "y": 306.0}],     # non-finite
            lambda rect: [{"x": 199.5, "y": 306.0}],            # left of the edge
            lambda rect: [{"x": 281.0, "y": 306.0}],            # right edge (x + width)
            lambda rect: [{"x": 216.0, "y": 330.75}],           # bottom edge (y + height)
            lambda rect: [{"x": 216.0, "y": 299.0}],            # above
            lambda rect: [{"x": 216.0, "y": 306.0}, {"x": 400.0, "y": 400.0}],
            lambda rect: [None],                                # not a record
        )
        for listed in cases:
            with self.subTest(listed=listed(self.BOUNDS)):
                adapter = CandidateAdapter(hits={0: True}, candidates=listed)
                self.refused(adapter, "control-hit")
                self.assertEqual(adapter.probed, [])
                self.assertNotIn("point_visible", adapter.calls)

    def test_outer_edges_and_out_of_rect_points_are_never_candidates(self):
        right = self.BOUNDS["x"] + self.BOUNDS["width"]
        bottom = self.BOUNDS["y"] + self.BOUNDS["height"]
        for point in ((right, 315.0), (240.0, bottom), (199.999, 315.0)):
            with self.subTest(point=point):
                adapter = CandidateAdapter(
                    hits={0: True},
                    candidates=lambda rect, point=point: [{"x": point[0], "y": point[1]}])
                self.refused(adapter, "control-hit")

    def test_int_and_float_subclasses_are_never_candidates(self):
        class HostileFloat(float):
            def __float__(self):
                raise AssertionError("float() dispatch on a candidate")

        class HostileInt(int):
            def __index__(self):
                raise AssertionError("index dispatch on a candidate")

        class HostileDict(dict):
            def __getitem__(self, key):
                raise AssertionError("candidate dict dispatch")

        for value in (HostileFloat(216.0), HostileInt(216)):
            with self.subTest(value=type(value).__name__):
                adapter = CandidateAdapter(
                    hits={0: True},
                    candidates=lambda rect, value=value: [{"x": value, "y": 306.0}])
                self.refused(adapter, "control-hit")
                self.assertEqual(adapter.probed, [])
        adapter = CandidateAdapter(hits={0: True}, candidates=lambda rect: [
            HostileDict(x=216.0, y=306.0)])
        self.refused(adapter, "control-hit")
        self.assertEqual(adapter.probed, [])

    def test_missing_or_raising_hook_refuses(self):
        adapter = CandidateAdapter(hits={0: True})

        def raising(rect):
            raise ValueError("boom")

        adapter.click_candidates = raising
        self.refused(adapter, "a11y-query")
        adapter.click_candidates = lambda rect: None
        self.refused(adapter, "control-hit")

    def test_non_candidate_platforms_keep_the_centre_only_path(self):
        # Windows/X11 list no candidates and keep exactly the shared centre
        # arithmetic: an integer rectangle is the historical integer centre,
        # fractional geometry is the same true centre, and the adapter's hook
        # verdict is never consulted as a search history.
        for platform in ("linux", "windows", "unknown"):
            with self.subTest(platform=platform):
                adapter = CandidateAdapter(hits={0: True, 1: True})
                adapter.platform = platform
                adapter.click_candidates = self.fail  # never queried
                result = self.run_plan(adapter)
                self.assertEqual(adapter.clicked, [self.CENTRE])
                self.assertEqual(adapter.control_hits,
                                 [(WINDOW["id"], LABEL, dict(self.BOUNDS), *self.CENTRE)])
                self.assertNotIn("click_candidates", adapter.calls)
                self.assertEqual((result["clicks"][0]["x"], result["clicks"][0]["y"]),
                                 self.CENTRE)
                # An unreachable centre refuses; no alternate is tried.
                refusing = CandidateAdapter(hits={1: True})
                refusing.platform = platform
                self.refused(refusing, "control-hit")
                self.assertNotIn("click_candidates", refusing.calls)
                self.assertEqual(refusing.calls.count("hit_test_control"), 1)
                # A bare integer rectangle: the historical integer centre.
                integral = CandidateAdapter(
                    hits={0: True}, control=control(LABEL, bounds={"x": 200, "y": 300,
                                                                   "width": 81, "height": 31}))
                integral.platform = platform
                self.run_plan(integral)
                self.assertEqual(integral.clicked, [(240, 315)])

    def test_the_centre_only_layers_share_one_strict_hook(self):
        # probe_control_hit answers with the very verdict the strict layer
        # would judge, so both platform paths see the same refusal.
        for verdict in (True, False, None, 1):
            with self.subTest(verdict=verdict):
                adapter = SpyAdapter(control_hit=verdict)
                window = dict(WINDOW)
                self.assertEqual(
                    contract.probe_control_hit(adapter, window, LABEL,
                                               dict(self.BOUNDS), 240, 315),
                    verdict is True)
                if verdict is True:
                    contract.confirm_control_hit(adapter, window, LABEL,
                                                 dict(self.BOUNDS), 240, 315)
                else:
                    with self.assertRaises(contract.ContractError) as error:
                        contract.confirm_control_hit(adapter, window, LABEL,
                                                     dict(self.BOUNDS), 240, 315)
                    self.assertEqual(error.exception.code, "control-hit")

    def test_only_the_macos_platform_takes_the_candidate_path(self):
        # Both platform paths click their own uncovered centre point here; the
        # candidate list is listed for macOS only.
        for platform, candidate_path in (("macos", True), ("linux", False),
                                         ("windows", False), ("unknown", False)):
            with self.subTest(platform=platform):
                adapter = CandidateAdapter(hits={0: True}, root_hit=True)
                adapter.platform = platform
                result = self.run_plan(adapter)
                self.assertEqual(adapter.clicked, [self.CENTRE])
                self.assertEqual(adapter.probed,
                                 [self.CENTRE] * (2 if candidate_path else 1))
                self.assertEqual((result["clicks"][0]["x"], result["clicks"][0]["y"]),
                                 self.CENTRE)
                if candidate_path:
                    self.assertEqual(adapter.calls.count("click_candidates"), 1)
                else:
                    self.assertNotIn("click_candidates", adapter.calls)

    def test_pointer_and_label_wait_actions_never_list_candidates(self):
        adapter = CandidateAdapter(hits={1: True})
        result = self.run_plan(adapter, actions=[{"click": [10, 20]}, {"wait_label": LABEL}])
        self.assertNotIn("click_candidates", adapter.calls)
        self.assertEqual(adapter.clicked, [(120, 160)])
        self.assertEqual(result["clicks"][0]["label"], "pointer")

    def test_the_first_candidate_is_the_unchanged_platform_centre(self):
        for rect in ({"x": 200, "y": 300, "width": 81, "height": 31},
                     {"x": 200, "y": 300, "width": 80, "height": 30}):
            with self.subTest(rect=rect):
                self.assertEqual(mac_points(rect)[0], contract._center(rect))


class IntegerGeometryRegressionTests(unittest.TestCase):
    """X11/Windows keep the historical integer behaviour, odd sizes included."""

    INTEGRAL_ADAPTERS = ("linux", "windows")

    def strategy(self, adapter, **overrides):
        plan = contract.parse_request(request(**overrides))
        with patch.object(contract, "monotonic", return_value=0), patch.object(contract, "sleep"):
            return contract.execute(plan, adapter)

    def test_integer_odd_and_even_centres_are_unchanged_for_x11_and_windows(self):
        for platform in self.INTEGRAL_ADAPTERS:
            for rect, point in (
                    ({"x": 200, "y": 300, "width": 81, "height": 31}, (240, 315)),
                    ({"x": 200, "y": 300, "width": 80, "height": 30}, (240, 315)),
                    ({"x": 200, "y": 300, "width": 79, "height": 29}, (239, 314)),
                    ({"x": 201, "y": 301, "width": 81, "height": 35}, (241, 318))):
                with self.subTest(platform=platform, rect=rect):
                    adapter = SpyAdapter(controls=[control(LABEL, bounds=dict(rect))])
                    adapter.platform = platform
                    adapter.input_evidence = "accepted"
                    adapter.click_ack = {"move": True, "down": True, "up": True}  # acknowledged
                    result = self.strategy(adapter)
                    self.assertEqual([call for call in adapter.calls if isinstance(call, tuple)],
                                     [("click", point[0], point[1])])
                    recorded = result["clicks"][0]
                    self.assertEqual((recorded["x"], recorded["y"]), point)
                    for value in (recorded["x"], recorded["y"]):
                        self.assertIs(type(value), int)
                    self.assertEqual(recorded["ack"], adapter.click_ack)
                    self.assertEqual(recorded["evidence"], "accepted")

    def test_integer_window_limits_and_refusals_are_unchanged(self):
        limits = {"x": 0, "y": 0, "width": 1920, "height": 1080}
        for platform in ("linux", "windows"):
            with self.subTest(platform=platform):
                screen = SpyAdapter(screen=dict(limits))
                screen.platform = platform
                result = self.strategy(screen)
                self.assertEqual(result["clicks"][0]["x"], 240)
                outside = SpyAdapter(screen={"x": 0, "y": 0, "width": 100, "height": 100})
                outside.platform = platform
                with self.assertRaises(contract.ContractError) as error:
                    self.strategy(outside)
                self.assertEqual(error.exception.code, "control-offscreen")
                self.assertEqual([call for call in outside.calls if isinstance(call, tuple)], [])

    def test_integer_control_center_helper_is_bit_for_bit_unchanged(self):
        for rect in ({"x": 200, "y": 300, "width": 81, "height": 31},
                     {"x": 200, "y": 300, "width": 80, "height": 30},
                     {"x": -15, "y": -7, "width": 3, "height": 5}):
            with self.subTest(rect=rect):
                expected = (rect["x"] + rect["width"] // 2, rect["y"] + rect["height"] // 2)
                point = contract._center(rect)
                self.assertEqual(point, expected)
                self.assertEqual(tuple(type(value) for value in point), (int, int))


if __name__ == "__main__":
    unittest.main()
