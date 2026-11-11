"""Independent signature/audit/privacy negatives for the host controller."""
import contextlib
import copy
import ctypes
import argparse
import io
import json
import os
import pathlib
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ssh_agent_acceptance as acceptance
import ssh_native_x11 as native
from run_cli_acceptance import scan


class ProtocolOracleTests(unittest.TestCase):
    def test_identities_reject_private_trailing_bytes_or_wrong_algorithm(self):
        public = acceptance.ssh_string(b"ssh-ed25519") + acceptance.ssh_string(bytes(range(32)))
        wire = b"\x0c" + struct.pack(">I", 1) + acceptance.ssh_string(public) + acceptance.ssh_string(b"public comment")
        self.assertEqual(len(acceptance.identities(wire)), 1)
        for invalid in (wire + b"private extra field", wire[:-1], wire.replace(b"ssh-ed25519", b"ssh-private")):
            with self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.identities(invalid)

    def test_openssl_rejects_wrong_payload_signature_or_public_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            key, payload_file, signature_file = [root / name for name in ("key", "payload", "sig")]
            payload = b"independent exact payload\0" + os.urandom(32)
            payload_file.write_bytes(payload)
            subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True, capture_output=True)
            der = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
            subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(payload_file), "-out", str(signature_file)],
                           check=True, capture_output=True)
            public = acceptance.ssh_string(b"ssh-ed25519") + acceptance.ssh_string(der[-32:])
            signature = signature_file.read_bytes()
            response = b"\x0e" + acceptance.ssh_string(acceptance.ssh_string(b"ssh-ed25519") + acceptance.ssh_string(signature))
            runner = acceptance.Acceptance.__new__(acceptance.Acceptance)
            runner.root, runner.env = root, dict(os.environ)
            runner.cli = mock.Mock(counter=0, logs=[])
            runner.verify_signature(response, public, payload, "valid")
            variants = ((response, public, payload + b"altered"),
                        (response[:-1] + bytes([response[-1] ^ 1]), public, payload),
                        (response, public[:-1] + bytes([public[-1] ^ 1]), payload))
            for index, (reply, keywire, data) in enumerate(variants):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    runner.verify_signature(reply, keywire, data, "negative-" + str(index))


class AuditOracleTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            {"action": "item.ssh.generate", "item_id": "generated", "result": "succeeded"},
            {"action": "item.ssh.import", "item_id": "imported", "result": "succeeded"},
            {"action": "item.ssh.sign", "item_id": "imported", "base_revision": "exact", "result": "intent"},
            {"action": "audit.list", "result": "succeeded"},
        ]
        self.approvals = [{"密钥 ID": "imported", "精确修订": "exact", "请求 ID": "one"}]

    def test_exact_fixture_with_explicit_audit_read_allowed(self):
        acceptance.verify_audit(self.events, self.approvals)

    def test_extra_signature_or_mutation_rejected(self):
        for event in (self.events[2], self.events[0], {"action": "item.ssh.export-private", "result": "intent"}):
            with self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.verify_audit(self.events + [event], self.approvals)

    def test_wrong_revision_or_success_claim_rejected(self):
        for field, value in (("base_revision", "stale"), ("result", "succeeded"), ("item_id", "other")):
            events = copy.deepcopy(self.events)
            events[2][field] = value
            with self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.verify_audit(events, self.approvals)

    def test_reusing_one_prompt_for_two_signatures_rejected(self):
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.verify_audit(self.events + [self.events[2]], self.approvals * 2)


class PrivacyTests(unittest.TestCase):
    def test_clipboard_refuses_private_pem_or_invalid_text_with_fixed_error(self):
        observer = native.PublicClipboard.__new__(native.PublicClipboard)
        for secret in (b"-----BEGIN OPENSSH PRIVATE KEY-----\nNeverExposePrivate\n", b"\xff\xfe"):
            observer.pending = {1: {"deadline": time.monotonic() + 1, "result": None}}
            memory = ctypes.create_string_buffer(secret)
            out, error = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(error):
                observer.received(None, ctypes.addressof(memory), 1)
            self.assertEqual(observer.pending[1]["result"], {"error": "clipboard-response-invalid"})
            self.assertEqual(out.getvalue() + error.getvalue(), "")

    def test_late_clipboard_callback_does_not_read_invalid_pointer(self):
        observer = native.PublicClipboard.__new__(native.PublicClipboard)
        observer.pending = {}
        observer.received(None, 1, 987654321)

    def test_failed_control_exception_cannot_print_secret_arguments(self):
        secret = "NeverPrintThisSecret-" + "f" * 48
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake = mock.Mock()
            fake.root, fake.stage, fake.operation, fake.reason = root, secret, secret, "none"
            fake.control_diagnostic, fake.checks = {}, []
            fake.run.side_effect = RuntimeError(secret)
            out = io.StringIO()
            with mock.patch.object(acceptance, "Acceptance", return_value=fake), contextlib.redirect_stdout(out):
                status = acceptance.main(["--host", "/unused", "--cli", "/unused", "--peer", "/unused"])
            self.assertEqual(status, 1)
            self.assertNotIn(secret, out.getvalue())
            self.assertIn("at prerequisites", out.getvalue())
            fake.diagnose.assert_called_once_with()


class PrivacyStageTests(unittest.TestCase):
    # AcceptanceFailure's message is its fixed code, so these distinct canaries
    # are allowlisted codes; constructing it directly never touches args.
    primary_canary = "oracle-stream-truncated"
    privacy_canary = "privacy-canary-disclosed"

    class Controller:
        """Fake controller whose privacy stage is the production method."""

        # Unbound production method, so the real stage, scan and failure run.
        privacy = acceptance.Acceptance.privacy

        def __init__(self, root, primary=None):
            self.root, self.primary = root, primary
            self.stage, self.step, self.operation, self.reason = "slow-frame", "none", "approve", "none"
            self.checks, self.control_diagnostic, self.secret_bytes = [], {}, []
            self.locked_failure = b""
            self.runtime_endpoint_bytes, self.runtime_owned, self.runtime_cleaned = 40, True, True
            self.error_class, self.error_line, self.privacy_error_class = "none", 0, "none"
            self.cli = mock.Mock(counter=0, logs=[(root / "desktop.stdout-stderr", set())], values=[])
            self.cli.write = mock.Mock()
            self.last_command = {"category": "native-observe", "state": "completed", "exit_code": 0, "elapsed_ms": 5}

        def run(self):
            if self.primary:
                raise self.primary
            self.stage = "lock"

        def diagnose(self):
            # main() records the failure's source line before diagnosing.
            # Keep that line; diagnosis only captures it.
            self.diagnosed_error_line = self.error_line

        def close(self):
            self.last_command = {"category": "native-observe", "state": "completed", "exit_code": 0, "elapsed_ms": 5}

        def mark(self, name):
            self.checks.append(name)

    def run_main(self, primary=None, privacy=None):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "desktop.stdout-stderr").write_bytes(b"public evidence only\n")
            if primary is not None:
                primary = acceptance.AcceptanceFailure(self.primary_canary)
            fake = self.Controller(root, primary)
            calls, stages, real_scan = [], [], acceptance.scan
            def scan(raw, values):
                calls.append(values)
                stages.append(fake.stage)
                if privacy is not None:
                    raise privacy
                return real_scan(raw, values)
            out = io.StringIO()
            with mock.patch.object(acceptance, "Acceptance", return_value=fake), \
                    mock.patch.object(acceptance, "scan", scan), \
                    contextlib.redirect_stdout(out):
                status = acceptance.main(["--host", "/unused", "--cli", "/unused", "--peer", "/unused"])
            path, result = fake.cli.write.call_args.args
            self.assertEqual(path, root / "ssh-result.json")
        # Neither exception message's canary may reach stdout (FAIL line and
        # diagnostic) or the serialized result. The only private path in output
        # is the intended evidence line; the result must not carry it at all.
        serialized = json.dumps(result)
        for value in (self.primary_canary, self.privacy_canary):
            self.assertNotIn(value, out.getvalue() + serialized)
        for value in (str(root), "desktop.stdout-stderr", "/tmp/"):
            self.assertNotIn(value, serialized)
        # privacy() reached the production scan loop exactly once, after it
        # set the stage.
        self.assertEqual(len(calls), 1)
        self.assertEqual(stages, ["privacy"])
        return root, status, result, out.getvalue(), fake, stages

    def test_earlier_slow_frame_failure_stays_primary_when_privacy_also_fails(self):
        primary = acceptance.AcceptanceFailure(self.primary_canary)
        root, status, result, output, fake, stages = self.run_main(
            primary=primary, privacy=acceptance.AcceptanceFailure(self.privacy_canary))
        self.assertTrue(root)
        self.assertEqual(fake.checks, [])
        self.assertEqual(status, 1)
        # main() recorded a positive line for the primary failure; the privacy
        # failure must not replace it.
        self.assertIsInstance(fake.diagnosed_error_line, int)
        self.assertGreater(fake.diagnosed_error_line, 0)
        self.assertEqual(result["source_line"], fake.diagnosed_error_line)
        self.assertEqual(result["diagnostic"]["source_line"], fake.diagnosed_error_line)
        # The earlier stage and class stay primary.
        self.assertEqual(result["stage"], "slow-frame")
        self.assertEqual(result["diagnostic"]["stage"], "slow-frame")
        self.assertEqual(result["error_class"], "assertion")
        self.assertEqual(result["diagnostic"]["error_class"], "assertion")
        # The privacy failure is reported separately as a fixed class.
        self.assertEqual(result["privacy_error_class"], "assertion")
        self.assertEqual(result["diagnostic"]["privacy_error_class"], "assertion")
        self.assertEqual(fake.privacy_error_class, "assertion")
        self.assertIn("FAIL: SSH acceptance at slow-frame", output)

    def test_privacy_only_failure_reports_privacy_stage(self):
        _root, status, result, output, fake, stages = self.run_main(
            privacy=acceptance.AcceptanceFailure(self.privacy_canary))
        self.assertEqual(fake.stage, "privacy")
        self.assertEqual(fake.checks, [])
        self.assertEqual(status, 1)
        # No primary failure, so privacy keeps the stage and its fixed class.
        self.assertEqual(result["stage"], "privacy")
        self.assertEqual(result["diagnostic"]["stage"], "privacy")
        self.assertEqual(result["error_class"], "none")
        self.assertEqual(result["diagnostic"]["error_class"], "none")
        self.assertEqual(result["privacy_error_class"], "assertion")
        self.assertEqual(result["diagnostic"]["privacy_error_class"], "assertion")
        self.assertIn("FAIL: SSH acceptance at privacy", output)

    def test_clean_privacy_scan_reports_complete_with_no_privacy_class(self):
        _root, status, result, output, fake, stages = self.run_main()
        self.assertEqual(status, 0)
        self.assertEqual(result["stage"], "complete")
        self.assertEqual(result["diagnostic"]["stage"], "complete")
        self.assertEqual(result["privacy_error_class"], "none")
        self.assertEqual(result["diagnostic"]["privacy_error_class"], "none")
        self.assertEqual(fake.checks, ["full_public_outputs_and_observed_agent_wire_contain_no_factors_or_private_seed"])
        self.assertIn("PASS: SSH acceptance at complete", output)

    def test_privacy_failure_class_is_a_fixed_value_never_exception_text(self):
        canary = "PrivatePrivacyClassCanary-" + "d" * 48
        value, key = ValueError(canary), KeyError(canary)
        unwanted = RuntimeError(canary)
        for error, expected in ((value, "value"), (key, "key"), (unwanted, "unexpected"),
                                (acceptance.AcceptanceFailure("privacy-canary-disclosed"), "assertion"),
                                (subprocess.TimeoutExpired([canary], 1), "timeout"), (OSError(canary), "os")):
            self.assertTrue(acceptance.error_class(error) == expected)
        runner = mock.Mock(privacy_error_class=canary)
        self.assertEqual(acceptance.public_diagnostic(runner)["privacy_error_class"], "unexpected")


class PickerObservationTests(unittest.TestCase):
    def test_pre_submit_query_failure_is_fatal_without_skipping_a_bad_node(self):
        for reason, guard in (("Native accessibility child limit", {"children": -1}),
                              ("Native accessibility child limit", {"children": 257}),
                              ("Native accessibility tree limit", {"depth": 13}),
                              ("Native accessibility tree limit", {"visited": 512, "remaining": 0})):
            error = RuntimeError(reason)
            error.native_guard = guard
            with mock.patch.object(native, "picker_observation_once", side_effect=error) as reader:
                with self.assertRaises(RuntimeError):
                    native.picker_observation({})
                reader.assert_called_once_with({})

    def test_closing_picker_uses_only_clean_x11_absence_and_zero_inputs(self):
        request = {"observation_deadline": time.monotonic() + 1}
        with mock.patch.object(native, "picker_window_present", side_effect=[True, native.PickerWindowQueryUnavailable(), False]) as reader:
            with mock.patch.object(native, "picker_observation_once") as deep_tree, mock.patch.object(native.native, "main") as input_driver:
                self.assertEqual(native.wait_picker_closed(request), {"absent": True})
                self.assertEqual(reader.call_count, 3)
                deep_tree.assert_not_called()
                input_driver.assert_not_called()

    def test_x11_query_exception_is_not_absence_and_original_deadline_is_kept(self):
        with mock.patch.object(native.time, "monotonic", side_effect=[9.9, 9.9, 10.0]):
            with mock.patch.object(native, "picker_window_present", side_effect=native.PickerWindowQueryUnavailable()) as reader:
                with self.assertRaises(RuntimeError):
                    native.wait_picker_closed({"observation_deadline": 10.0})
                reader.assert_called_once()

    def test_late_x11_absence_does_not_extend_original_deadline(self):
        with mock.patch.object(native.time, "monotonic", side_effect=[9.9, 9.9, 10.01]):
            with mock.patch.object(native, "picker_window_present", return_value=False):
                with self.assertRaises(RuntimeError):
                    native.wait_picker_closed({"observation_deadline": 10.0})

    def test_x11_query_requires_exact_owned_title_pid_and_executable(self):
        request = {"title": "选择未加密 OpenSSH Ed25519 私钥", "pid": os.getpid(), "executable": "/wrong/executable"}
        with mock.patch.object(native.C, "CDLL") as x11:
            with self.assertRaises(RuntimeError):
                native.picker_window_present(request)
            x11.assert_not_called()
        with mock.patch.object(native, "picker_window_present", side_effect=OSError("fixed process unavailable")):
            with self.assertRaises(OSError):
                native.wait_picker_closed({"observation_deadline": time.monotonic() + 1})

    def test_normal_confirm_follows_exact_path_one_return_submission_and_real_modal_absence(self):
        self.check_selection(path_matches=1, closed=True, expected=["type-path", "verify-path", "return-submit", "x11-absence", "confirm", "imported"])

    def test_mismatched_path_never_submits_or_confirms(self):
        self.check_selection(path_matches=0, closed=True, expected=["type-path", "verify-path"], refuses=True)

    def test_remaining_modal_never_confirms_or_repeats_return_submission(self):
        self.check_selection(path_matches=1, closed=False, expected=["type-path", "verify-path", "return-submit", "x11-absence"], refuses=True)

    def check_selection(self, path_matches, closed, expected, refuses=False):
        with tempfile.TemporaryDirectory() as directory:
            runner = acceptance.Acceptance.__new__(acceptance.Acceptance)
            runner.root, runner.cli, trace = pathlib.Path(directory), mock.Mock(), []
            def driver(actions=(), **options):
                if options.get("observe") == "picker":
                    trace.append("verify-path")
                    return {"path_match": path_matches}
                if options.get("observe") == "picker-closed":
                    trace.append("x11-absence")
                    self.assertGreater(options["observation_deadline"], time.monotonic())
                    self.assertLessEqual(options["timeout"], 10)
                    return {"absent": closed}
                if actions == [{"key": "Return"}]:
                    trace.append("return-submit")
                elif actions == [{"click_label": acceptance.LABELS["import-confirm"]}]:
                    trace.append("confirm")
                elif actions == [{"wait_label": acceptance.LABELS["imported"]}]:
                    trace.append("imported")
                else:
                    trace.append("type-path")
                return {}
            runner.native = mock.Mock(side_effect=driver)
            if refuses:
                with self.assertRaises(acceptance.AcceptanceFailure):
                    runner.complete_import_selection(runner.root / "fixture-key")
            else:
                runner.complete_import_selection(runner.root / "fixture-key")
            self.assertEqual(trace, expected)
            submissions = 0
            for call in runner.native.call_args_list:
                self.assertNotEqual(call.args, ([{"click_label": "Open"}],))
                if call.args == ([{"key": "Return"}],):
                    submissions += 1
                    self.assertIsNone(call.kwargs.get("observe"))
                if submissions:
                    self.assertNotEqual(call.kwargs.get("observe"), "picker")
            self.assertEqual(submissions, 1 if "return-submit" in expected else 0)

    def test_fixed_a11y_refusal_classification_retains_digit(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = acceptance.Acceptance.__new__(acceptance.Acceptance)
            runner.root, runner.env = pathlib.Path(directory), dict(os.environ)
            runner.cli = mock.Mock(counter=0, logs=[])
            result = subprocess.CompletedProcess([], 1, b"", b"SSH native driver failed [a11y-query]\n")
            with mock.patch.object(acceptance.subprocess, "run", return_value=result):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    runner.command(["owned-fixture"], category="native-observe")
            self.assertEqual(runner.reason, "native-a11y-query")


class SlowFrameAbsenceTests(unittest.TestCase):
    class Clock:
        def __init__(self):
            self.now = 0.0

        def __call__(self):
            return self.now

    def test_transient_fault_prompt_fails_before_it_disappears_with_zero_input(self):
        clock, connection, input_driver = self.Clock(), mock.Mock(), mock.Mock()
        connection.recv.return_value = b""

        def observe(timeout):
            # The fake faulty product displays a brief prompt, then would
            # hide it well before its eventual socket EOF at t=0.8.
            self.assertGreater(timeout, 0)
            clock.now += 0.025
            return 0.20 <= clock.now < 0.45

        def readiness(read, _write, _errors, timeout):
            clock.now += timeout
            return (read if clock.now >= 0.8 else [], [], [])

        with mock.patch.object(native.native, "main", input_driver):
            with self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.observe_absence_until_eof(connection, observe, 1.0, clock=clock, readiness=readiness)
        self.assertLess(clock.now, 0.45)
        connection.recv.assert_not_called()
        input_driver.assert_not_called()

    def test_real_controller_fault_observer_requests_contain_zero_input_actions(self):
        clock, connection, requests = self.Clock(), mock.Mock(), []
        connection.recv.return_value = b""
        with tempfile.TemporaryDirectory() as directory:
            runner = acceptance.Acceptance.__new__(acceptance.Acceptance)
            runner.root, runner.env, runner.host = pathlib.Path(directory), {}, "/owned/frozen-desktop"
            runner.app, runner.cli = mock.Mock(pid=123), mock.Mock(counter=0, logs=[])
            def driver(arguments, **options):
                request = json.loads(options["input"])
                requests.append(request)
                self.assertEqual(request["observe"], "approval")
                self.assertEqual(request["actions"], [])
                self.assertLessEqual(options["timeout"], 1)
                clock.now += 0.025
                values = ["批准本次 SSH 签名？"] if 0.20 <= clock.now < 0.45 else []
                return subprocess.CompletedProcess(arguments, 0, json.dumps({"values": values}).encode(), b"")
            def readiness(read, _write, _errors, timeout):
                clock.now += timeout
                return (read if clock.now >= 0.8 else [], [], [])
            with mock.patch.object(acceptance.subprocess, "run", side_effect=driver):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    acceptance.observe_absence_until_eof(connection, runner.approval_present, 1,
                        clock=clock, readiness=readiness)
            self.assertGreaterEqual(len(requests), 3)
            connection.recv.assert_not_called()

    def test_warm_external_observer_fault_is_caught_without_any_input_command(self):
        script = r'''
import json,pathlib,sys
record=pathlib.Path(sys.argv[1])
config=json.loads(sys.stdin.readline())
assert set(config)=={"title","pid","executable"}
print('{"ready":true}',flush=True)
count=0
for line in sys.stdin:
    with record.open("a") as output: output.write(line)
    assert line=="observe\n"
    count+=1
    print(json.dumps({"present":count==3}),flush=True)
'''
        with tempfile.TemporaryDirectory() as directory:
            root, clock, connection = pathlib.Path(directory), self.Clock(), mock.Mock()
            owner = mock.Mock(root=root, env=dict(os.environ), app=mock.Mock(pid=os.getpid()), host=sys.executable,
                              cli=mock.Mock(logs=[]))
            record = root / "fixed-observer-commands"
            observer = acceptance.WarmApprovalObserver(owner, 1, [sys.executable, "-u", "-c", script, str(record)])
            def readiness(read, _write, _errors, timeout):
                clock.now += timeout
                return (read if clock.now >= 0.8 else [], [], [])
            try:
                with self.assertRaises(acceptance.AcceptanceFailure):
                    acceptance.observe_absence_until_eof(connection, observer.query, 1, clock=clock, readiness=readiness)
            finally:
                observer.close()
            self.assertEqual(record.read_text().splitlines(), ["observe"] * 3)
            connection.recv.assert_not_called()
            self.assertLess(clock.now, 0.8)

    def test_warm_observer_query_timeout_reaps_owned_process_and_closes_stdin(self):
        script = 'import sys,time;sys.stdin.readline();print(\'{"ready":true}\',flush=True);sys.stdin.readline();time.sleep(30)'
        with tempfile.TemporaryDirectory() as directory:
            owner = mock.Mock(root=pathlib.Path(directory), env=dict(os.environ), app=mock.Mock(pid=os.getpid()),
                              host=sys.executable, cli=mock.Mock(logs=[]))
            observer = acceptance.WarmApprovalObserver(owner, 1, [sys.executable, "-u", "-c", script])
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    observer.query(0.02)
            finally:
                observer.close()
            self.assertIsNotNone(observer.process.poll())
            self.assertTrue(observer.process.stdin.closed)
            self.assertTrue(observer.process.stdout.closed)

    def test_warm_observer_startup_timeout_reaps_process_before_constructor_returns(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = mock.Mock(root=pathlib.Path(directory), env=dict(os.environ), app=mock.Mock(pid=os.getpid()),
                              host=sys.executable, cli=mock.Mock(logs=[]))
            original, started = subprocess.Popen, []
            def launch(*args, **options):
                process = original(*args, **options)
                started.append(process)
                return process
            with mock.patch.object(acceptance.subprocess, "Popen", side_effect=launch):
                with self.assertRaises(subprocess.TimeoutExpired):
                    acceptance.WarmApprovalObserver(owner, 0.02, [sys.executable, "-c", "import time;time.sleep(30)"])
            self.assertEqual(len(started), 1)
            self.assertIsNotNone(started[0].poll())
            self.assertTrue(started[0].stdin.closed)

    def test_absence_is_observed_continuously_and_again_after_eof(self):
        clock, connection, samples = self.Clock(), mock.Mock(), []
        connection.recv.return_value = b""

        def observe(timeout):
            samples.append(clock.now)
            clock.now += 0.025
            return False

        def readiness(read, _write, _errors, timeout):
            clock.now += timeout
            return (read if clock.now >= 0.5 else [], [], [])

        evidence = acceptance.observe_absence_until_eof(connection, observe, 1.0, clock=clock, readiness=readiness)
        self.assertGreaterEqual(len(samples), 5)
        self.assertGreaterEqual(samples[-1], 0.5)
        self.assertEqual(evidence["observations"], len(samples))
        self.assertTrue(evidence["eof"])

    def test_observation_gap_or_original_deadline_cannot_be_treated_as_absence(self):
        for elapsed in (1.6, 38.0):
            clock = self.Clock()
            def stalled_observation(timeout):
                self.assertLessEqual(timeout, 1)
                clock.now += elapsed
                return False
            with self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.observe_absence_until_eof(mock.Mock(), stalled_observation, 38.0, clock=clock)

    def test_wire_bytes_or_observer_error_fail_closed_without_input(self):
        for error in (False, True):
            clock, connection, input_driver = self.Clock(), mock.Mock(), mock.Mock()
            connection.recv.return_value = b"\x05"
            observer = mock.Mock(side_effect=RuntimeError("fixed read-only failure")) if error else mock.Mock(return_value=False)
            with mock.patch.object(native.native, "main", input_driver):
                with self.assertRaises((acceptance.AcceptanceFailure, RuntimeError)):
                    acceptance.observe_absence_until_eof(connection, observer, 38.0, clock=clock,
                        readiness=lambda read, _w, _e, _t: (read, [], []))
            input_driver.assert_not_called()


class RuntimeAndDiagnosticTests(unittest.TestCase):
    def test_bounded_native_guard_distinguishes_negative_query_from_structural_limit(self):
        for children in (-1, 257):
            raw = b"SSH native driver failed [a11y-child-limit]\nSSH_NATIVE_DIAGNOSTIC " + json.dumps(
                {"target": "app", "action": "label-wait", "index": 0,
                 "guard": {"children": children, "depth": 2, "visited": 10, "remaining": 502}}).encode() + b"\n"
            self.assertEqual(acceptance.driver_failure(raw), "a11y-child-limit")
            self.assertEqual(acceptance.driver_context(raw)["guard"]["children"], children)

    def test_native_guard_never_copies_arbitrary_error_or_metadata_values(self):
        secret = "NeverPrintNativeFailure-" + "e" * 48
        error = RuntimeError(secret)
        error.native_guard = {"children": -1, "depth": secret, secret: secret}
        diagnostic = native.failure_diagnostic(error)
        self.assertNotIn(secret, json.dumps(diagnostic))
        self.assertEqual(diagnostic["guard"], {"children": -1})
        safe = acceptance.safe_native_context({"target": secret, "action": secret, "index": secret,
                                               "guard": {"children": -1, "remaining": secret, secret: secret}})
        self.assertNotIn(secret, json.dumps(safe))
        self.assertEqual(safe["guard"], {"children": -1})

    def test_long_evidence_destination_uses_short_canonical_private_owned_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = pathlib.Path(directory) / ("long-owned-evidence-" + "a" * 70)
            args = argparse.Namespace(artifacts=str(artifacts), cli="/bin/true", host="/bin/true", gh="/usr/bin/gh",
                                      fixture_bin=None, window_manager=None)
            runner = acceptance.Acceptance(args)
            try:
                old_endpoint = runner.root / "desktop-runtime" / ("locklark-ssh-" + str(os.geteuid())) / "agent.sock"
                self.assertGreater(len(os.fsencode(old_endpoint)), 100)
                self.assertLessEqual(runner.runtime_endpoint_bytes, 100)
                self.assertNotEqual(runner.runtime.parent, runner.root)
                self.assertEqual(runner.runtime, runner.runtime.resolve(strict=True))
                info = runner.runtime.lstat()
                self.assertEqual(info.st_uid, os.geteuid())
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
                runtime = runner.runtime
            finally:
                runner.close()
            self.assertFalse(runtime.exists())
            self.assertTrue(runner.runtime_cleaned)

    def test_runtime_cleanup_rejects_changed_identity_and_never_follows_child_link(self):
        runtime, identity = acceptance.owned_runtime()
        with tempfile.TemporaryDirectory() as directory:
            outside = pathlib.Path(directory) / "sentinel"
            outside.write_text("owned independent sentinel")
            (runtime / "outside-link").symlink_to(outside)
            try:
                with self.assertRaises(acceptance.AcceptanceFailure):
                    acceptance.remove_owned_runtime(runtime, (identity[0], identity[1] + 1, identity[2]))
                self.assertTrue(runtime.exists())
                acceptance.remove_owned_runtime(runtime, identity)
                self.assertTrue(outside.exists())
            finally:
                if runtime.exists():
                    acceptance.remove_owned_runtime(runtime, identity)

    def test_public_diagnostic_contains_only_fixed_aliases_counts_and_booleans(self):
        secret = "NeverPrintDiagnosticCanary-" + "b" * 48
        runner = mock.Mock(stage=secret, step=secret, operation=secret, reason=secret, error_class=secret, error_line=secret,
            last_command={"category": secret, "state": secret, "exit_code": secret, "elapsed_ms": secret},
            runtime_endpoint_bytes=secret, runtime_owned=secret, runtime_cleaned=secret,
            control_diagnostic={secret: {secret: secret}, "app": {"import-confirm": {"present": secret, "enabled": secret, "showing": secret},
                                                               secret: secret}})
        diagnostic = acceptance.public_diagnostic(runner)
        raw = json.dumps(diagnostic)
        self.assertNotIn(secret, raw)
        self.assertEqual(diagnostic["stage"], "unknown")
        self.assertEqual(diagnostic["controls"]["app"]["import-confirm"], {"present": False, "enabled": False, "showing": False})

    def test_public_substep_distinguishes_picker_confirm_and_agent_readiness(self):
        runner = mock.Mock(stage="import", step="picker-close-observe", operation="import-file", reason="native-window-close-timeout",
            error_class="assertion", error_line=123, last_command={"category": "picker-absence", "state": "completed", "exit_code": 1, "elapsed_ms": 10},
            runtime_endpoint_bytes=50, runtime_owned=True, runtime_cleaned=True, control_diagnostic={})
        for stage, step in (("import", "picker-close-observe"), ("import", "import-confirm"), ("agent-start", "agent-ready")):
            runner.stage, runner.step = stage, step
            diagnostic = acceptance.public_diagnostic(runner)
            self.assertEqual((diagnostic["stage"], diagnostic["step"]), (stage, step))

    def test_external_timeout_keeps_partial_output_private_and_fixed_metadata(self):
        canary = "PrivateCommandFailureCanary-" + "d" * 48
        with tempfile.TemporaryDirectory() as directory:
            runner = acceptance.Acceptance.__new__(acceptance.Acceptance)
            runner.root, runner.env = pathlib.Path(directory), {}
            runner.cli = mock.Mock(counter=0, logs=[])
            timeout = subprocess.TimeoutExpired([canary], 1, output=canary.encode(), stderr=canary.encode())
            with mock.patch.object(acceptance.subprocess, "run", side_effect=timeout):
                with self.assertRaises(subprocess.TimeoutExpired):
                    runner.command([canary], category="native-observe")
            self.assertEqual(runner.last_command["state"], "timeout")
            self.assertEqual(runner.reason, "external-timeout")
            self.assertEqual(len(runner.cli.logs), 2)
            self.assertTrue(all(path.read_bytes() == canary.encode() for path, _allowed in runner.cli.logs))




class LockedFailureFrameTests(unittest.TestCase):
    """Deterministic units for the locked pending-reply reader and the private
    correlation of its capture. Only in-memory socket pairs and temp files are
    used. The forced Go checkpoint only shows an injected ordering can end the
    reply after the canonical header; it is not evidence of CI's actual bytes."""

    canonical = acceptance.frame(bytes([5]))
    mark = "full_public_outputs_and_observed_agent_wire_contain_no_factors_or_private_seed"

    def reply(self, *parts, close=True):
        """Feed parts through an in-memory socket pair, then EOF or stall."""
        server, client = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(client.close)
        for part in parts:
            client.sendall(part)
        server.settimeout(0.1)
        if close:
            client.shutdown(socket.SHUT_WR)
        return server

    def read(self, *parts, close=True):
        return acceptance.read_cancelled_failure(self.reply(*parts, close=close))

    def rejected(self, *parts, close=True):
        try:
            self.read(*parts, close=close)
        except acceptance.AcceptanceFailure:
            return
        self.fail("reply became a partial failure frame")

    def signed_reply(self):
        signature = b"\x0e" + acceptance.ssh_string(acceptance.ssh_string(b"ssh-ed25519") + acceptance.ssh_string(bytes(64)))
        return acceptance.frame(signature)

    def runner(self, root, observed, values=()):
        """Minimal Acceptance whose privacy stage is the production method."""
        runner = acceptance.Acceptance.__new__(acceptance.Acceptance)
        runner.root, runner.relay = root, None
        runner.locked_failure, runner.secret_bytes = observed, []
        runner.cli = mock.Mock(values=list(values), logs=[])
        runner.checks = []
        runner.mark = runner.checks.append
        log = root / "desktop.stdout-stderr"
        log.write_bytes(b"public evidence\n")
        runner.cli.logs.append((log, set()))
        return runner

    def cannot_parse(self, message, response, observed):
        try:
            self.privacy(response, observed)
        except acceptance.AcceptanceFailure:
            return
        self.fail(message)

    def privacy(self, response, observed):
        """Run the privacy stage over one response capture and a CLI log."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        (root / "agent-wire-0.response").write_bytes(response)
        self.runner(root, observed).privacy()

    def test_empty_eof_of_a_pending_reply_is_accepted(self):
        self.assertEqual(self.read(), b"")

    def test_full_canonical_failure_is_accepted(self):
        self.assertEqual(self.read(self.canonical), self.canonical)
        # Split deliveries still assemble the same frame within the bound.
        self.assertEqual(self.read(self.canonical[:4], self.canonical[4:]), self.canonical)

    def test_each_strict_canonical_prefix_followed_by_eof_is_accepted(self):
        for size in range(1, len(self.canonical)):
            self.assertEqual(self.read(self.canonical[:size]), self.canonical[:size])

    def test_noncanonical_header_prefix_is_rejected(self):
        for raw in (b"\x01", self.canonical[:2] + b"\x02", self.canonical[:3] + b"\x07"):
            self.rejected(raw)

    def test_identities_or_signature_commands_are_rejected(self):
        identities_reply = acceptance.frame(b"\x0c" + bytes(4))
        for data in (identities_reply, self.signed_reply()):
            for size in (5, 6, 8, 11, len(data) - 1, len(data)):
                self.rejected(data[:size])

    def test_a_timeout_after_a_prefix_never_passes_as_a_partial(self):
        for size in range(1, len(self.canonical)):
            self.rejected(self.canonical[:size], close=False)

    def test_exact_stays_strict_for_an_empty_eof(self):
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.exact(_Closed(), 1)

    def test_privacy_accepts_the_correlated_canonical_suffix(self):
        # A header-only capture, the forced ordering's observable suffix, and
        # wire that is exactly the observed bytes, including from offset zero.
        for observed in (self.canonical[:size] for size in range(1, len(self.canonical))):
            self.privacy(observed, observed)
        # A complete frame, then its normal same-size reply, then the partial.
        wire = self.canonical * 2 + self.canonical[:4]
        self.privacy(wire, self.canonical[:4])
        # The locked reply completed in full: nothing may stay partial.
        self.privacy(self.canonical, self.canonical)

    def test_privacy_rejects_any_other_or_inconsistent_partial_capture(self):
        canonical = self.canonical
        identities_reply = acceptance.frame(b"\x0c" + bytes(4))
        cannot = "the capture may not keep this as a partial"
        cases = ((canonical[:4], canonical[:3]),        # suffix differs from observed
                 (canonical[:3], canonical[:2]),        # shorter observed than suffix
                 (b"", canonical[:3]),                  # nothing observed, no header parsed
                 (canonical[:4], canonical),            # a complete reply when a partial was seen
                 (canonical, canonical[:4]),            # a partial when the reply completed
                 (canonical[:4], canonical * 2 + canonical[:2]),  # a second partial
                 (canonical[:2], canonical[:2] + b"\x00\x00\x00\x02"),  # incomplete header
                 (canonical[:3], canonical[:3] + identities_reply[:6]))   # partial signature
        for observed, response in cases:
            self.cannot_parse(cannot, response, observed)
        # Later bytes after the observed prefix are not that prefix.
        self.cannot_parse(cannot, canonical[:4] + b"\x00", canonical[:4])

    def test_privacy_never_treats_a_signed_reply_as_a_failure_prefix(self):
        signed = self.signed_reply()
        # The signed frame shares only its leading zero bytes with the
        # canonical header, so no short remainder of it is that header.
        for observed in (self.canonical[:1], self.canonical[:2], self.canonical[:3]):
            self.cannot_parse("a signed reply is not a failure prefix", signed, observed)

    def captures(self, *responses):
        """Run the privacy stage over separate captures and one CLI log."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        for index, response in enumerate(responses):
            (root / ("agent-wire-" + str(index) + ".response")).write_bytes(response)
        return self.runner(root, self.canonical[:4])

    def test_privacy_accepts_one_correlated_locked_prefix_among_separate_complete_captures(self):
        # Separate captures: the ordinary failure, identities and signature
        # replies must each still be parsed, beside the one lock capture that
        # ends at the observed four-byte canonical length header.
        identities_reply = acceptance.frame(b"\x0c" + bytes(4))
        runner = self.captures(self.canonical, identities_reply, self.signed_reply(), self.canonical[:4])
        runner.privacy()
        self.assertEqual(runner.checks, [self.mark])

    def test_privacy_rejects_two_captures_ending_in_the_correlated_locked_prefix(self):
        runner = self.captures(self.canonical, self.canonical[:4], self.signed_reply(), self.canonical[:4])
        with self.assertRaises(acceptance.AcceptanceFailure):
            runner.privacy()
        self.assertEqual(runner.checks, [])

    def test_privacy_still_scans_the_log_and_response_without_enriching_diagnostics(self):
        # The run has no locked failure, so the response must parse in full.
        wire = self.canonical + acceptance.frame(b"\x0c" + bytes(4))
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        (root / "agent-wire-0.response").write_bytes(wire)
        # A foreign value present in neither file must not stop either scan.
        runner = self.runner(root, b"", ["PublicFixtureValue-" + "f" * 32])
        seen, real = [], acceptance.scan
        with mock.patch.object(acceptance, "scan", lambda raw, values: seen.append((raw, list(values))) or real(raw, values)):
            runner.privacy()
        self.assertEqual([raw for raw, _values in seen], [b"public evidence\n", wire])
        self.assertEqual(runner.checks, [self.mark])
        runner.stage, runner.step, runner.operation = "privacy", "none", "none"
        runner.error_class, runner.error_line, runner.reason = "none", 0, "none"
        runner.last_command, runner.control_diagnostic = {}, {}
        runner.runtime_endpoint_bytes, runner.runtime_owned, runner.runtime_cleaned = 40, True, True
        self.assertNotIn("locked_failure", repr(acceptance.public_diagnostic(runner)))


class _Closed:
    """A reader already at end of stream."""

    def recv(self, size):
        return b""


if __name__ == "__main__":
    unittest.main()
