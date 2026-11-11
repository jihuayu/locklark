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


class HostileFloat(float):
    """A float subclass whose every conversion would be visible to a test."""

    def __float__(self):
        raise AssertionError("float() dispatch on hostile geometry")

    def __int__(self):
        raise AssertionError("int() dispatch on hostile geometry")


class HostileInt(int):
    """An int subclass whose every conversion would be visible to a test."""

    def __float__(self):
        raise AssertionError("float() dispatch on hostile geometry")

    def __int__(self):
        raise AssertionError("int() dispatch on hostile geometry")


FRACTIONAL = {"x": 200.5, "y": 300.25, "width": 81.0, "height": 31.5}


class GeometryValidationTests(unittest.TestCase):
    """Shared rectangles: plain ints or finite built-in floats, nothing else."""

    def window_with(self, value, key="width"):
        # The adapter's own normalisation passes a hostile value through
        # unchanged only when it is already a plain int/float; a hostile
        # adapter must still never get it accepted by the shared contract.
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

    def test_window_integral_float_and_int_subclass_values_are_safely_normalised(self):
        for value, expected in ((800.0, 800), (HostileInt(800), 800)):
            with self.subTest(value=value):
                self.executed(self.window_with(value))
                self.assertEqual(contract.geometry_value(value), expected)
                if type(value) is not float:
                    self.assertIs(type(contract.geometry_value(value)), int)
                # Already-plain geometry is handed back unconverted.
                self.assertEqual(contract.integer_rect(dict(WINDOW["bounds"])), WINDOW["bounds"])

    def test_geometry_rejects_bool_nonfinite_subclass_and_nonnumeric_values(self):
        malformed = [True, False, float("nan"), float("inf"), float("-inf"),
                     HostileFloat(1.0), "1", None, [1], object()]
        for value in malformed:
            for key in ("x", "y", "width", "height"):
                with self.subTest(value=value, key=key):
                    rect = dict(WINDOW["bounds"], **{key: value})
                    self.assertIsNone(contract.geometry_value(value))
                    self.assertFalse(contract.rect_positive(rect))
                    with self.assertRaises(contract.ContractError) as error:
                        self.executed(self.window_with(value, key))
                    self.assertEqual(error.exception.code, "window-geometry")

    def test_control_geometry_rejects_every_non_plain_nonfinite_and_subclass_value(self):
        for value in (True, float("nan"), float("inf"), "80", None,
                      HostileFloat(80.0), HostileInt(81)):
            with self.subTest(value=value):
                adapter = SpyAdapter(controls=[control(LABEL, bounds=dict(FRACTIONAL, width=value))])
                self.assert_refused(adapter, "control-geometry")
        self.assert_refused(SpyAdapter(controls=[control(LABEL, bounds={})]), "control-geometry")

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
        return ExecutionGuardTests.execute(self, adapter, **overrides)

    def clicks(self, adapter):
        return [call for call in adapter.calls if isinstance(call, tuple)]

    def assert_refused(self, adapter, code):
        with self.assertRaises(contract.ContractError) as error:
            self.executed(adapter)
        self.assertEqual(error.exception.code, code)
        self.assertEqual(self.clicks(adapter), [])
        self.assertEqual(adapter.control_hits, [])


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
