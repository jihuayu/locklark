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


if __name__ == "__main__":
    unittest.main()
