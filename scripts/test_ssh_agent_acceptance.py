"""Independent signature/audit/privacy negatives for the host controller."""
import contextlib
import copy
import ctypes
import argparse
import io
import json
import os
import pathlib
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


if __name__ == "__main__":
    unittest.main()
