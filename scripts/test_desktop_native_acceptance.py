"""Secret scanning checks for persistent desktop acceptance artifacts."""
import json
import ast
import inspect
import pathlib
import tempfile
import textwrap
import unittest
import urllib.parse
from unittest.mock import Mock, patch

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


if __name__ == "__main__":
    unittest.main()
