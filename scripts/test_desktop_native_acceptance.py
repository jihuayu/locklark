"""Secret scanning checks for persistent desktop acceptance artifacts."""
import json
import ast
import inspect
import pathlib
import tempfile
import textwrap
import unittest
import urllib.parse
from unittest.mock import Mock, call, patch

import desktop_native_acceptance as desktop
from desktop_native_acceptance import Acceptance, AcceptanceFailure


class ArtifactPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.private = tempfile.TemporaryDirectory()
        self.addCleanup(self.private.cleanup)
        self.acceptance = Acceptance.__new__(Acceptance)
        self.acceptance.state = pathlib.Path(self.private.name)
        self.acceptance.fixture_path = self.acceptance.state / "fixture.json"
        self.acceptance.values = {"Synthetic-秘密-🔐-only"}
        self.acceptance.codes = {"19384756"}
        self.path = self.acceptance.state / "native.log"

    def test_secret_encodings_are_rejected(self):
        value = next(iter(self.acceptance.values))
        for encoded in (value, json.dumps(value)[1:-1], urllib.parse.quote(value, safe="")):
            with self.subTest(encoding="private"):
                self.path.write_text("failure: " + encoded)
                with self.assertRaises(AcceptanceFailure):
                    self.acceptance.scan()

    def test_standalone_otp_code_is_rejected(self):
        self.path.write_text('{"code":"19384756"}')
        with self.assertRaises(AcceptanceFailure):
            self.acceptance.scan()

    def test_unrelated_identifier_substring_is_allowed(self):
        self.path.write_text('{"id":"a19384756b"}')
        self.assertEqual(self.acceptance.scan(), 1)

    def test_only_explicit_fixture_is_excluded(self):
        value = next(iter(self.acceptance.values))
        self.acceptance.fixture_path.write_text(value)
        self.assertEqual(self.acceptance.scan(), 0)
        (self.acceptance.state / "failure.json").write_text(json.dumps({"error": value}))
        with self.assertRaises(AcceptanceFailure):
            self.acceptance.scan()


class ProbeTransportTests(unittest.TestCase):
    def acceptance(self, line=""):
        acceptance = Acceptance.__new__(Acceptance)
        acceptance.probe = Mock()
        acceptance.probe.stdout.readline.return_value = line
        acceptance.probe_healthy = True
        acceptance.probe_read_attempts_max = 0
        acceptance.reason = "acceptance"
        return acceptance

    def test_transport_timeout_poison_prevents_late_response_reuse(self):
        acceptance = self.acceptance()
        with patch.object(desktop.select, "select", return_value=([], [], [])) as select, patch.object(desktop.time, "monotonic", side_effect=[0, 15]):
            with self.assertRaises(AcceptanceFailure):
                acceptance.probe_request({"op":"clipboard", "expected":["synthetic-private"]})
            self.assertEqual(acceptance.reason, "probe-response-timeout")
            self.assertEqual(acceptance.probe_elapsed_ms, 15000)
            self.assertFalse(acceptance.probe_healthy)
            with self.assertRaises(AcceptanceFailure):
                acceptance.probe_request({"op":"display"})
        self.assertEqual(acceptance.reason, "probe-unavailable")
        self.assertEqual(acceptance.probe.stdin.write.call_count, 1)
        acceptance.probe.stdout.readline.assert_not_called()
        select.assert_called_once()

    def test_eof_and_invalid_json_poison_transport(self):
        for line, reason in (("", "probe-response-eof"), ("not-json-private", "probe-response-json")):
            with self.subTest(reason=reason):
                acceptance = self.acceptance(line)
                with patch.object(desktop.select, "select", return_value=([acceptance.probe.stdout], [], [])), patch.object(desktop.time, "monotonic", side_effect=[0, 0.1]):
                    with self.assertRaises(AcceptanceFailure):
                        acceptance.probe_request({"op":"clipboard"})
                self.assertEqual(acceptance.reason, reason)
                self.assertFalse(acceptance.probe_healthy)

    def test_broken_pipe_is_fixed_and_poisoned(self):
        acceptance = self.acceptance()
        acceptance.probe.stdin.write.side_effect = BrokenPipeError("synthetic-private-error")
        with patch.object(desktop.time, "monotonic", side_effect=[0, 0.1]):
            with self.assertRaises(AcceptanceFailure):
                acceptance.probe_request({"op":"clipboard"})
        self.assertEqual(acceptance.reason, "probe-write-failed")
        self.assertFalse(acceptance.probe_healthy)

    def test_explicit_clipboard_timeout_keeps_live_transport(self):
        acceptance = self.acceptance('{"ok":false,"reason":"clipboard-response-timeout"}\n')
        with patch.object(desktop.select, "select", return_value=([acceptance.probe.stdout], [], [])), patch.object(desktop.time, "monotonic", side_effect=[0, 1]):
            with self.assertRaises(AcceptanceFailure):
                acceptance.probe_request({"op":"clipboard"})
        self.assertEqual(acceptance.reason, "probe-clipboard-response-timeout")
        self.assertTrue(acceptance.probe_healthy)

    def test_untrusted_probe_error_is_not_echoed(self):
        acceptance = self.acceptance('{"ok":false,"reason":"synthetic-private-error"}\n')
        with patch.object(desktop.select, "select", return_value=([acceptance.probe.stdout], [], [])), patch.object(desktop.time, "monotonic", side_effect=[0, 0.1]):
            with self.assertRaises(AcceptanceFailure):
                acceptance.probe_request({"op":"clipboard"})
        self.assertEqual(acceptance.reason, "probe-unexpected")


class IndependentClipboardTests(unittest.TestCase):
    def acceptance(self):
        acceptance = Acceptance.__new__(Acceptance)
        acceptance.log, acceptance.env = Mock(), {}
        acceptance.reason = "acceptance"
        return acceptance

    def test_fresh_reader_must_exactly_match(self):
        acceptance = self.acceptance()
        result = Mock(returncode=0,stdout=b'{"ready":true}\n{"ok":true,"empty":false,"matches":[true]}\n')
        with patch.object(desktop.subprocess,"run",return_value=result) as run, patch.object(desktop.time,"monotonic",side_effect=[0,0.2]):
            acceptance.assert_independent_clipboard("synthetic-private-marker")
        run.assert_called_once()
        self.assertEqual(acceptance.probe_operation,"independent-clipboard")
        self.assertEqual(acceptance.probe_elapsed_ms,200)

    def test_mismatch_is_not_repaired_or_retried(self):
        acceptance = self.acceptance()
        result = Mock(returncode=0,stdout=b'{"ready":true}\n{"ok":true,"empty":true,"matches":[false]}\n')
        with patch.object(desktop.subprocess,"run",return_value=result) as run, patch.object(desktop.time,"monotonic",side_effect=[0,0.2]):
            with self.assertRaises(AcceptanceFailure):
                acceptance.assert_independent_clipboard("synthetic-private-marker")
        run.assert_called_once()
        self.assertEqual(acceptance.reason,"independent-clipboard-mismatch")

    def test_timeout_is_fixed_hard_failure(self):
        acceptance = self.acceptance()
        error = desktop.subprocess.TimeoutExpired("synthetic-private-command",15,output=b"synthetic-private-value")
        with patch.object(desktop.subprocess,"run",side_effect=error) as run, patch.object(desktop.time,"monotonic",side_effect=[0,15]):
            with self.assertRaises(AcceptanceFailure) as failure:
                acceptance.assert_independent_clipboard("synthetic-private-marker")
        run.assert_called_once()
        self.assertEqual(acceptance.reason,"independent-clipboard-response-timeout")
        self.assertEqual(str(failure.exception),"")


class ForeignAllowTransitionTests(unittest.TestCase):
    def test_request_after_stats_but_before_allow_still_fails(self):
        acceptance = Acceptance.__new__(Acceptance)
        acceptance.foreign_request = Mock(return_value={"requests":1})
        observation = {"requests":0}
        with self.assertRaises(AcceptanceFailure):
            acceptance.allow_foreign_reads("synthetic-owner",observation)
        self.assertEqual(observation["requests_at_allow"],1)
        self.assertEqual(acceptance.reason,"foreign-clipboard-request-before-allow")
        acceptance.foreign_request.assert_called_once_with("synthetic-owner","respond")

    def test_zero_requests_at_allow_is_explicitly_recorded(self):
        acceptance = Acceptance.__new__(Acceptance)
        acceptance.foreign_request = Mock(return_value={"requests":0})
        observation = {"requests":0}
        acceptance.allow_foreign_reads("synthetic-owner",observation)
        self.assertEqual(observation["requests_at_allow"],0)


class SingleForeignLockTests(unittest.TestCase):
    def test_exactly_one_lock_click_in_function(self):
        tree = ast.parse(textwrap.dedent(inspect.getsource(Acceptance.foreign_lock_case)))
        clicks = [node for node in ast.walk(tree) if isinstance(node,ast.Call)
                  and isinstance(node.func,ast.Attribute) and node.func.attr=="click"
                  and node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value=="立即锁定"]
        self.assertEqual(len(clicks),1)

    def test_success_and_timeout_each_issue_one_lock(self):
        for ready in (True,False):
            with self.subTest(ready=ready):
                acceptance = Acceptance.__new__(Acceptance)
                acceptance.select,acceptance.phase,acceptance.show_copy_otp = Mock(),Mock(),Mock()
                acceptance.start_foreign_owner = Mock(return_value=Mock(clipboard_owner_id="0x200003"))
                acceptance.click = Mock()
                acceptance.input = Mock() if ready else Mock(side_effect=AcceptanceFailure())
                acceptance.foreign_request = Mock(return_value={"owner":"0x200003","requests":0,"payload_requests":0,"metadata_requests":0})
                acceptance.foreign_observations = []
                acceptance.displays_empty = Mock(return_value=True)
                acceptance.allow_foreign_reads,acceptance.assert_independent_clipboard = Mock(),Mock()
                with patch.object(desktop,"current_owner",return_value="0x200003"), patch.object(desktop.time,"monotonic",side_effect=[0,0.1,0.2]), patch.object(desktop.time,"sleep"):
                    if ready:
                        acceptance.foreign_lock_case()
                    else:
                        with self.assertRaises(AcceptanceFailure):
                            acceptance.foreign_lock_case()
                acceptance.click.assert_called_once_with("立即锁定")
                acceptance.input.assert_called_once()
                if not ready:
                    acceptance.allow_foreign_reads.assert_not_called()


class NativeStartupDiagnosticTests(unittest.TestCase):
    def test_preinput_error_is_not_reported_as_last_planned_action(self):
        acceptance = Acceptance.__new__(Acceptance)
        acceptance.host = pathlib.Path("/synthetic-native-host")

        def command(*_args,**_kwargs):
            acceptance.native_failed_index = -1
            acceptance.native_x_error_codes = [8]
            raise AcceptanceFailure()

        acceptance.command = command
        with patch.object(desktop.time,"monotonic",side_effect=[0,0.065]):
            with self.assertRaises(AcceptanceFailure):
                acceptance.input([{"wait_label":"新建登录"}])
        self.assertEqual(acceptance.native_action,"window-ready")
        self.assertEqual(acceptance.native_x_error_codes,[8])


class FakeClock:
    def __init__(self, walls):
        self._walls = walls
        self._index = 0
        self.mono = 0.0
        self.sleeps = 0

    def time(self):
        if callable(self._walls):
            return self._walls()
        value = self._walls[min(self._index, len(self._walls) - 1)]
        self._index += 1
        return value

    def monotonic(self):
        self.mono += 1.0
        return self.mono

    def sleep(self, _seconds):
        self.sleeps += 1


class OtpWindowTests(unittest.TestCase):
    def await_window(self, walls):
        acceptance = Acceptance.__new__(Acceptance)
        acceptance.reason = "acceptance"
        clock = FakeClock(walls)
        with (
            patch.object(desktop.time, "time", clock.time),
            patch.object(desktop.time, "monotonic", clock.monotonic),
            patch.object(desktop.time, "sleep", clock.sleep),
        ):
            return acceptance, acceptance.await_new_otp_window(), clock

    def test_prerollover_samples_are_ignored(self):
        acceptance, sample, clock = self.await_window([100.5, 100.7, 100.9, 120.3])
        self.assertEqual(sample, 120.3)
        self.assertEqual(acceptance.otp_window(sample), 6)
        self.assertGreaterEqual(acceptance.otp_remaining(sample), 18)
        self.assertEqual(clock.sleeps, 2)

    def test_new_window_requires_remaining_margin(self):
        acceptance, sample, _ = self.await_window([100.5, 123.0, 140.5])
        self.assertEqual(sample, 140.5)
        self.assertEqual(acceptance.otp_window(sample), 7)
        self.assertGreaterEqual(acceptance.otp_remaining(sample), 18)
        # 123.0 is a new window but already leaves only 17s of preparation.
        self.assertLess(acceptance.otp_remaining(123.0), 18)

    def test_fixed_timeout_fails_closed(self):
        acceptance = Acceptance.__new__(Acceptance)
        acceptance.reason = "acceptance"
        clock = FakeClock(lambda: 100.5)
        with (
            patch.object(desktop.time, "time", clock.time),
            patch.object(desktop.time, "monotonic", clock.monotonic),
            patch.object(desktop.time, "sleep", clock.sleep),
        ):
            with self.assertRaises(AcceptanceFailure):
                acceptance.await_new_otp_window()
        self.assertEqual(acceptance.reason, "otp-window-timeout")


class ShowCopyOtpFlowTests(unittest.TestCase):
    def test_exactly_one_show_and_one_hide_wait(self):
        acceptance = Acceptance.__new__(Acceptance)
        acceptance.reason = "acceptance"
        acceptance.wait = Mock()
        acceptance.align = Mock()
        acceptance.await_new_otp_window = Mock(return_value=120.3)
        acceptance.click = Mock()
        acceptance.display = Mock(return_value={"matches": [True]})
        acceptance.otp = Mock(return_value="12345678")
        acceptance.eventually = Mock()
        acceptance.clipboard = Mock(return_value={"matches": [True]})
        acceptance.show_copy_otp()
        self.assertEqual(acceptance.wait.call_args_list,
                         [call("显示验证码"), call("隐藏验证码")])
        self.assertEqual(acceptance.click.call_args_list,
                         [call("显示验证码"), call("复制验证码")])
        acceptance.await_new_otp_window.assert_called_once_with()
        acceptance.otp.assert_called_once_with(120.3)
        acceptance.display.assert_called_once()
        acceptance.eventually.assert_called_once()
        acceptance.align.assert_not_called()


def record(line):
    """Parse a diagnostic line, asserting the fixed prefix and bound."""
    assert line.startswith(desktop.OTP_DIAGNOSTIC_PREFIX), line
    assert line.isascii() and "\n" not in line, line
    assert len(line.encode("utf-8")) <= desktop.OTP_DIAGNOSTIC_LIMIT, line
    return json.loads(line[len(desktop.OTP_DIAGNOSTIC_PREFIX):])


PRIVATE = ("Synthetic-Private-OTP-19384756-SeedJBSWY3DPEHPK3PXP-Locklark · 本地金库")
UNAVAILABLE = {"copy_window_delta":"unavailable", "failure_window_delta":"unavailable",
               "clipboard_empty":"unavailable"}


class OtpDiagnosticProjectionTests(unittest.TestCase):
    """The projection owns every bound of the printed record."""

    def test_exact_three_field_record(self):
        self.assertEqual(record(desktop.otp_diagnostic(1, 0, True)),
                         {"copy_window_delta":1, "failure_window_delta":0, "clipboard_empty":True})
        self.assertEqual(record(desktop.otp_diagnostic()),
                         {"copy_window_delta":"unavailable", "failure_window_delta":"unavailable",
                          "clipboard_empty":"unavailable"})

    def test_exact_delta_bounds_are_kept(self):
        for value in (-64, -1, 0, 1, 63, 64):
            with self.subTest(delta=value):
                self.assertEqual(record(desktop.otp_diagnostic(value, value, False)),
                                 {"copy_window_delta":value, "failure_window_delta":value,
                                  "clipboard_empty":False})

    def test_out_of_range_delta_is_unavailable_not_clamped(self):
        for value in (-65, 65, 10**12, -(10**12)):
            with self.subTest(delta=value):
                self.assertEqual(record(desktop.otp_diagnostic(value, value, True)),
                                 {"copy_window_delta":"unavailable", "failure_window_delta":"unavailable",
                                  "clipboard_empty":True})

    def test_non_integral_delta_is_unavailable_and_never_echoed(self):
        # A float window difference, bools and arbitrary objects are not ints.
        for bad in (1.0, -1.0, 0.5, True, False, "1", "0", [1], {"a":1}, None, object(), PRIVATE, b"1"):
            with self.subTest(kind=type(bad).__name__, value=bad):
                line = desktop.otp_diagnostic(bad, bad)
                self.assertNotIn(PRIVATE, line)
                self.assertEqual(record(line), {**UNAVAILABLE, "clipboard_empty":"unavailable"})

    def test_clipboard_empty_requires_exact_bool(self):
        for bad in (1, 0, "true", "false", None, [True], PRIVATE):
            with self.subTest(kind=type(bad).__name__, value=bad):
                self.assertEqual(record(desktop.otp_diagnostic(0, 0, bad))["clipboard_empty"], "unavailable")
        self.assertIs(record(desktop.otp_diagnostic(0, 0, True))["clipboard_empty"], True)
        self.assertIs(record(desktop.otp_diagnostic(0, 0, False))["clipboard_empty"], False)

    def test_record_has_only_the_three_fixed_keys(self):
        # No absolute accepted window, raw timestamp, OTP code or seed.
        for values in ((2, -3, True), (0, 0, False), (None, None, None), (64, -64, True)):
            with self.subTest(values=values):
                text = desktop.otp_diagnostic(*values)[len(desktop.OTP_DIAGNOSTIC_PREFIX):]
                self.assertEqual(set(json.loads(text)),
                                 {"copy_window_delta", "failure_window_delta", "clipboard_empty"})
                self.assertRegex(text, r'^\{"copy_window_delta":(?:-?\d{1,2}|"unavailable"),'
                                       r'"failure_window_delta":(?:-?\d{1,2}|"unavailable"),'
                                       r'"clipboard_empty":(?:true|false|"unavailable")\}$')


class OtpCopyFailureProbeTests(unittest.TestCase):
    """The catch-time probe: one clipboard read, deltas only, no retry."""

    CODE = "19384756"

    def acceptance(self):
        acceptance = Acceptance.__new__(Acceptance)
        acceptance.stage, acceptance.reason, acceptance.native_action = "otp-selection-clears", "acceptance", "click:复制验证码"
        acceptance.otp_copy, acceptance.otp_diagnostic = None, None
        acceptance.clipboard = Mock()
        acceptance.click = Mock()
        return acceptance

    def await_window(self, walls):
        clock = FakeClock(walls)
        with (
            patch.object(desktop.time, "time", clock.time),
            patch.object(desktop.time, "monotonic", clock.monotonic),
            patch.object(desktop.time, "sleep", clock.sleep),
        ):
            return Acceptance.await_new_otp_window(Acceptance.__new__(Acceptance))

    def test_float_sample_converts_only_via_otp_window(self):
        # await_new_otp_window returns a float; the accepted sample is kept
        # as-is and converted with otp_window only to form the deltas.
        acceptance = self.acceptance()
        sample = self.await_window([100.7, 120.3])
        self.assertEqual((sample, Acceptance.otp_window(sample)), (120.3, 6))
        # The copy runs within the accepted window, the failure in the next.
        acceptance.otp_copy = (sample, 121.0)
        self.assertIsInstance(acceptance.otp_copy[0], float)
        with patch.object(desktop.time, "time", return_value=140.9), \
             patch("builtins.print") as output:
            acceptance.record_otp_copy_failure()
        acceptance.clipboard.assert_called_once_with()
        acceptance.click.assert_not_called()
        self.assertEqual(record(acceptance.otp_diagnostic),
                         {"copy_window_delta":0, "failure_window_delta":1, "clipboard_empty":False})
        output.assert_called_once_with(acceptance.otp_diagnostic, flush=True)

    def test_clipboard_read_failure_keeps_other_fields(self):
        acceptance = self.acceptance()
        acceptance.otp_copy = (1005 * 20 + 18.0, 1005 * 20 + 19.5)
        acceptance.clipboard = Mock(side_effect=AcceptanceFailure())
        with patch.object(desktop.time, "time", return_value=1005 * 20 + 19.9), \
             patch("builtins.print") as output:
            acceptance.record_otp_copy_failure()
        self.assertEqual(record(acceptance.otp_diagnostic),
                         {"copy_window_delta":0, "failure_window_delta":0, "clipboard_empty":"unavailable"})
        output.assert_called_once_with(acceptance.otp_diagnostic, flush=True)
        self.assertEqual((acceptance.stage, acceptance.reason, acceptance.native_action),
                         ("otp-selection-clears", "acceptance", "click:复制验证码"))

    def test_probe_errors_never_raise_and_restore_state(self):
        for failure in (RuntimeError(PRIVATE), OSError(PRIVATE), KeyboardInterrupt(), SystemExit(2)):
            with self.subTest(kind=type(failure).__name__):
                acceptance = self.acceptance()
                acceptance.otp_copy = (1005 * 20 + 18.0, 1005 * 20 + 19.5)
                acceptance.otp_window = Mock(side_effect=failure)
                with patch("builtins.print") as output:
                    acceptance.record_otp_copy_failure()
                self.assertIsNone(acceptance.otp_diagnostic)
                output.assert_not_called()
                self.assertEqual((acceptance.stage, acceptance.reason, acceptance.native_action),
                                 ("otp-selection-clears", "acceptance", "click:复制验证码"))

    def copy_failure(self, acceptance):
        """Drive show_copy_otp with its real poll and catch-time probe."""
        acceptance.wait, acceptance.click = Mock(), Mock()
        acceptance.await_new_otp_window = Mock(return_value=1005 * 20 + 18.0)
        acceptance.display = Mock(return_value={"matches": [True]})
        acceptance.otp = Mock(return_value="19384756")
        # The real poll runs once against the accepted window; it then fails.
        scoped = []

        def poll(check, timeout=10):
            if not scoped:
                scoped.append(check())
            raise AcceptanceFailure()

        acceptance.eventually = Mock(side_effect=poll)
        with patch.object(desktop.time, "time", return_value=1005 * 20 + 18.0), \
             patch.object(desktop.time, "monotonic", SimulatedClock().monotonic), \
             patch("builtins.print") as output, \
             self.assertRaises(AcceptanceFailure) as failure:
            acceptance.show_copy_otp()
        self.assertEqual(str(failure.exception), "")
        return output

    def test_state_mutation_during_probe_is_restored_and_not_reused(self):
        acceptance = self.acceptance()
        seen = []

        def clipboard(expected=None):
            seen.append("copy" if expected is not None else "probe")
            if expected is None:
                acceptance.stage = "hijacked"
                acceptance.reason, acceptance.native_action = "otp-copy-window-delta", "none"
                acceptance.otp_copy = (1, 1)
            return {"matches": [False]} if expected is not None else {"empty": True}

        acceptance.clipboard = Mock(side_effect=clipboard)
        output = self.copy_failure(acceptance)
        # One copy check, one probe read; the probe's mutation is not reused.
        self.assertEqual(seen, ["copy", "probe"])
        output.assert_called_once_with(acceptance.otp_diagnostic, flush=True)
        self.assertEqual((acceptance.stage, acceptance.reason, acceptance.native_action),
                         ("otp-selection-clears", "acceptance", "click:复制验证码"))
        self.assertEqual(record(acceptance.otp_diagnostic),
                         {"copy_window_delta":0, "failure_window_delta":0, "clipboard_empty":True})

    def test_recursive_catch_probes_nothing(self):
        acceptance = self.acceptance()
        seen = []

        def clipboard(expected=None):
            seen.append("copy" if expected is not None else "probe")
            if expected is not None:
                if seen.count("copy") == 1:
                    raise AcceptanceFailure()
                return {"matches": [False]}
            acceptance.show_copy_otp()
            return {"empty": False}

        acceptance.clipboard = Mock(side_effect=clipboard)
        output = self.copy_failure(acceptance)
        # The probe reads once, then its re-entrant copy checks once and finds
        # the probe busy: no second read or nested record, and the outer probe
        # still emits exactly one fixed line with the empty state unavailable.
        self.assertEqual(seen, ["copy", "probe", "copy"])
        output.assert_called_once_with(acceptance.otp_diagnostic, flush=True)
        self.assertEqual(record(acceptance.otp_diagnostic),
                         {"copy_window_delta":0, "failure_window_delta":0, "clipboard_empty":"unavailable"})
        self.assertFalse(acceptance.otp_probe_busy)

    def test_nothing_recorded_without_a_copy_attempt(self):
        acceptance = self.acceptance()
        acceptance.record_otp_copy_failure()
        acceptance.clipboard.assert_not_called()
        self.assertIsNone(acceptance.otp_diagnostic)


class SimulatedClock:
    STEP = 0.5

    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        self.now += self.STEP
        return self.now


class OtpCopyFlowIntegrationTests(unittest.TestCase):
    """show_copy_otp keeps the original flow and records only on failure."""

    CODE = "19384756"

    def acceptance(self, results):
        acceptance = Acceptance.__new__(Acceptance)
        acceptance.stage, acceptance.reason, acceptance.native_action = "otp-selection-clears", "acceptance", "click:复制验证码"
        acceptance.otp_copy, acceptance.otp_diagnostic, acceptance.output_lines = None, None, []
        acceptance.fixture = {"OTPSeed": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}
        acceptance.wait, acceptance.click = Mock(), Mock()
        acceptance.await_new_otp_window = Mock(return_value=1005 * 20 + 0.5)
        acceptance.display = Mock(return_value={"matches": [True]})
        acceptance.otp = Mock(return_value=self.CODE)
        copy_result, probe_result = (list(results) + [results[-1]])[:2]
        def clipboard(expected=None):
            if expected is None:
                return probe_result
            if isinstance(copy_result, BaseException):
                raise copy_result
            return copy_result
        acceptance.clipboard = Mock(side_effect=clipboard)

        def poll(check, timeout=10):
            # The real poll runs its copy check once, then fails.
            try:
                returns = check()
            except AcceptanceFailure:
                raise
            raise AcceptanceFailure()
        acceptance.eventually = Mock(side_effect=poll)
        acceptance.emit = lambda message: acceptance.output_lines.append(str(message))
        return acceptance

    def test_window_rollover_records_failure_without_retrying(self):
        acceptance = self.acceptance([{"matches": [False]}, {"empty": False}])
        # The copy click keeps the accepted window; the failure is next.
        with patch.object(desktop.time, "time", side_effect=[1005 * 20 + 19.5, 1006 * 20 + 0.25]), \
             patch.object(desktop.time, "monotonic", SimulatedClock().monotonic), \
             patch("builtins.print"):
            with self.assertRaises(AcceptanceFailure):
                acceptance.show_copy_otp()
        self.assertEqual(acceptance.click.call_args_list, [call("显示验证码"), call("复制验证码")])
        acceptance.otp.assert_called_with(1005 * 20 + 0.5)
        self.assertEqual(acceptance.clipboard.call_args_list, [call([self.CODE]), call()])
        self.assertEqual(acceptance.reason, "acceptance")
        self.assertEqual(record(acceptance.otp_diagnostic),
                         {"copy_window_delta":0, "failure_window_delta":1, "clipboard_empty":False})
        self.assertNotIn(self.CODE, acceptance.otp_diagnostic)

    def test_same_window_failure(self):
        acceptance = self.acceptance([{"matches": [False]}, {"empty": True}])
        with patch.object(desktop.time, "time", return_value=1005 * 20 + 12.5), \
             patch.object(desktop.time, "monotonic", SimulatedClock().monotonic), \
             patch("builtins.print"):
            with self.assertRaises(AcceptanceFailure):
                acceptance.show_copy_otp()
        self.assertEqual(record(acceptance.otp_diagnostic),
                         {"copy_window_delta":0, "failure_window_delta":0, "clipboard_empty":True})

    def test_success_records_nothing(self):
        acceptance = self.acceptance([{"matches": [True]}])
        acceptance.eventually = lambda check, **_kwargs: True
        with patch.object(desktop.time, "time", return_value=1005 * 20 + 1.0):
            acceptance.show_copy_otp()
        self.assertIsNone(acceptance.otp_diagnostic)
        self.assertEqual(acceptance.otp_copy, (1005 * 20 + 0.5, 1005 * 20 + 1.0))

    def test_probe_failure_keeps_original_exception_and_emits_no_code(self):
        acceptance = self.acceptance([{"matches": [False]}, AcceptanceFailure()])
        with patch.object(desktop.time, "time", side_effect=[1005 * 20 + 19.5, 1006 * 20 + 0.25]), \
             patch.object(desktop.time, "monotonic", SimulatedClock().monotonic), \
             patch("builtins.print"):
            with self.assertRaises(AcceptanceFailure) as failure:
                acceptance.show_copy_otp()
        self.assertEqual(str(failure.exception), "")
        self.assertEqual(acceptance.clipboard.call_args_list, [call([self.CODE]), call()])
        self.assertEqual(record(acceptance.otp_diagnostic)["clipboard_empty"], "unavailable")
        self.assertNotIn(self.CODE, acceptance.otp_diagnostic)


class OtpDiagnosticIsolationTests(unittest.TestCase):
    """The outer failure path keeps the original outcome and transcript."""

    FAILURE = "Desktop native acceptance failed at otp-selection-clears [acceptance] action=click:复制验证码"
    NONE = "Desktop OTP failure diagnostic: none"

    def acceptance(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        acceptance = Acceptance.__new__(Acceptance)
        acceptance.state = pathlib.Path(root.name)
        acceptance.diagnostics = acceptance.state / "diagnostics"
        acceptance.diagnostics.mkdir()
        # Transcript log exists; the bound probe is the only log holder.
        acceptance.fixture_binary = acceptance.state / "fixture-observer"
        acceptance.env, acceptance.host = {}, pathlib.Path("/synthetic-native-host")
        acceptance.log = (acceptance.state / "native.log").open("w")
        self.addCleanup(acceptance.log.close)
        acceptance.fixture_path = acceptance.state / "fixture.json"
        acceptance.values, acceptance.codes = set(), set()
        acceptance.started, acceptance.stage = 0, "otp-selection-clears"
        acceptance.reason, acceptance.native_action = "acceptance", "click:复制验证码"
        acceptance.native_failed_index, acceptance.native_x_error_codes = None, []
        acceptance.native_elapsed_ms, acceptance.probe_read_attempts_max = 0, 0
        acceptance.probe_operation, acceptance.probe_elapsed_ms = "unsupported", 0
        acceptance.probe_diagnostic, acceptance.last_native_click = {}, {}
        acceptance.foreign_observations, acceptance.output_lines = [], []
        acceptance.otp_copy, acceptance.otp_diagnostic = None, None
        acceptance.phase = Mock()
        acceptance.create = Mock(side_effect=AcceptanceFailure())
        acceptance.setup, acceptance.close = Mock(), Mock()
        acceptance.probe, acceptance.app = Mock(), Mock()
        acceptance.observe = Mock(return_value={"items": [], "events": []})
        acceptance.controls = Mock(return_value={})
        acceptance.display = Mock(return_value={"present": False, "empty": True})
        acceptance.otp_acceptance = Mock(side_effect=AcceptanceFailure())
        acceptance.emit = lambda message: acceptance.output_lines.append(str(message))
        return acceptance

    def test_record_prints_after_failure_summary_without_artifact(self):
        acceptance = self.acceptance()
        acceptance.otp_diagnostic = desktop.otp_diagnostic(0, 1, True)
        with patch("builtins.print") as output:
            self.assertEqual(acceptance.run(), 1)
        lines = [item.args[0] for item in output.call_args_list]
        self.assertLess(lines.index(self.FAILURE), lines.index(acceptance.otp_diagnostic))
        self.assertEqual(lines.count(acceptance.otp_diagnostic), 1)
        self.assertNotIn(self.NONE, lines)
        self.assertNotIn("PASS", " ".join(lines))
        self.assertFalse((acceptance.state / "diagnostics" / "otp-failure.json").exists())

    def test_without_record_prints_fixed_none(self):
        acceptance = self.acceptance()
        with patch("builtins.print") as output:
            self.assertEqual(acceptance.run(), 1)
        lines = [item.args[0] for item in output.call_args_list]
        self.assertIn(self.FAILURE, lines)
        self.assertIn(self.NONE, lines)
        self.assertEqual(lines[-1], self.NONE)
        self.assertNotIn("PASS", " ".join(lines))

    def test_artifact_failures_keep_summary_and_exit(self):
        acceptance = self.acceptance()
        acceptance.otp_diagnostic = desktop.otp_diagnostic(0, 1, True)
        with patch("builtins.print") as output, \
             patch.object(pathlib.Path, "write_text", side_effect=OSError(PRIVATE)), \
             patch.object(desktop.os, "fdopen", side_effect=OSError(PRIVATE)):
            self.assertEqual(acceptance.run(), 1)
        lines = [item.args[0] for item in output.call_args_list]
        # failure.json fails, so the original failure line is not emitted;
        # the fixed OTP record still is, exactly once, with exit 1.
        self.assertIn(acceptance.otp_diagnostic, lines)
        self.assertEqual(lines.count(acceptance.otp_diagnostic), 1)

    def test_file_write_failure_still_projects_record_to_stdout(self):
        acceptance = self.acceptance()
        acceptance.otp_diagnostic = desktop.otp_diagnostic(-1, 0, False)
        acceptance.scan = Mock(return_value=0)
        with patch("builtins.print") as output, \
             patch.object(desktop.os, "fdopen", side_effect=OSError(PRIVATE)):
            self.assertEqual(acceptance.run(), 1)
        lines = [item.args[0] for item in output.call_args_list]
        self.assertIn("Desktop native privacy scan failed", lines)
        self.assertIn(acceptance.otp_diagnostic, lines)


if __name__ == "__main__":
    unittest.main()
