"""Independent signature/audit/privacy negatives for the host controller."""
import contextlib
import copy
import ctypes
import io
import json
import os
import pathlib
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
    def test_destroyed_picker_query_reobserves_absence_without_any_input(self):
        absent = {"present": False, "path_match": 0}
        request = {"observation_deadline": time.monotonic() + 1}
        with mock.patch.object(native, "picker_observation_once", side_effect=[native.native.AccessibilityQueryUnavailable(), absent]) as reader:
            with mock.patch.object(native.native, "main") as input_driver:
                self.assertEqual(native.picker_observation(request), absent)
                self.assertEqual(reader.call_count, 2)
                input_driver.assert_not_called()

    def test_structural_error_is_not_retried_or_reclassified_as_absence(self):
        request = {"observation_deadline": time.monotonic() + 1}
        with mock.patch.object(native, "picker_observation_once", side_effect=RuntimeError("fixed structural failure")) as reader:
            with self.assertRaises(RuntimeError):
                native.picker_observation(request)
            self.assertEqual(reader.call_count, 1)

    def test_transient_query_cannot_extend_original_deadline(self):
        request = {"observation_deadline": 10.0}
        with mock.patch.object(native.time, "monotonic", side_effect=[9.9, 9.9, 10.0]):
            with mock.patch.object(native, "picker_observation_once", side_effect=native.native.AccessibilityQueryUnavailable()) as reader:
                with self.assertRaises(native.native.AccessibilityQueryUnavailable):
                    native.picker_observation(request)
                self.assertEqual(reader.call_count, 1)

    def test_late_successful_absence_does_not_extend_original_deadline(self):
        with mock.patch.object(native.time, "monotonic", side_effect=[9.9, 9.9, 10.01]):
            with mock.patch.object(native, "picker_observation_once", return_value={"present": False}):
                with self.assertRaises(RuntimeError):
                    native.picker_observation({"observation_deadline": 10.0})

    def test_fixed_a11y_refusal_classification_retains_digit(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = acceptance.Acceptance.__new__(acceptance.Acceptance)
            runner.root, runner.env = pathlib.Path(directory), dict(os.environ)
            runner.cli = mock.Mock(counter=0, logs=[])
            result = subprocess.CompletedProcess([], 1, b"", b"SSH native driver failed [a11y-query]\n")
            with mock.patch.object(acceptance.subprocess, "run", return_value=result):
                with self.assertRaises(acceptance.AcceptanceFailure):
                    runner.command(["owned-fixture"])
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


if __name__ == "__main__":
    unittest.main()
