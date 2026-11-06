"""Host privacy/oracle tests only; no simulator/UI evidence is fabricated."""

import base64
import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("ios_ui_evidence", pathlib.Path(__file__).with_name("verify-ui-evidence.py"))
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class PrivacyTests(unittest.TestCase):
    def test_raw_and_encoded_secret_output_is_rejected_without_value(self):
        value = "PrivateSyntheticFixtureValue998877"
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "runtime.log"
            for raw in (value.encode(), base64.b64encode(value.encode()), value.encode().hex().encode()):
                path.write_bytes(raw)
                with self.subTest(encoding=len(raw)), self.assertRaises(evidence.EvidenceFailure) as failure:
                    evidence.scan_file(path, [value])
                self.assertEqual(str(failure.exception), "")

    def test_complete_stream_scan_finds_secret_across_chunk_boundary(self):
        value = "PrivateBoundaryFixture"
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "runtime.log"
            path.write_bytes(b"x" * ((1 << 20) - 5) + value.encode() + b"z" * (1 << 20))
            with self.assertRaises(evidence.EvidenceFailure):
                evidence.scan_file(path, [value])

    def test_numeric_window_edges_do_not_confuse_long_timestamps_with_otp(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "runtime.log"
            for raw in (b"time 1234567890", b"x" * ((1 << 20) - 7) + b" 1234567890",
                        b"x" * (1 << 20) + b"99123456 public"):
                path.write_bytes(raw)
                evidence.scan_file(path, ["123456"])
            for raw in (b"OTP=123456", b"x" * ((1 << 20) - 7) + b" 123456\n",
                        b"x" * (1 << 20) + b" 123456\n"):
                path.write_bytes(raw)
                with self.assertRaises(evidence.EvidenceFailure):
                    evidence.scan_file(path, ["123456"])

    def test_exception_and_child_output_never_reach_public_failure_output(self):
        secret = "PrivateFailureFixtureValue667788"

        class FailedVerifier:
            root = pathlib.Path("/private/ios-evidence")
            stage = "manifest"
            manifest_valid = False
            manifest_complete = False
            export_complete = False
            files = []

            def __init__(self, _):
                pass

            def execute(self):
                raise RuntimeError(secret)

            def scan(self):
                pass

        with mock.patch.object(evidence, "EvidenceVerifier", FailedVerifier), \
             mock.patch.object(pathlib.Path, "write_text"), contextlib.redirect_stdout(io.StringIO()) as output:
            result = evidence.main(["--simulator", "unused", "--runtime-log", "unused", "--xcresult", "unused", "--test-exit-code", "1"])
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "FAIL: iOS UI evidence validation\nPrivate iOS UI evidence: /private/ios-evidence\n")
        self.assertNotIn(secret, output.getvalue())


class EvidenceIntegrityTests(unittest.TestCase):
    @staticmethod
    def manifest(complete=True):
        return {"version": 1, "run_id": "12345678-1234-4234-8234-1234567890AB", "test": evidence.TEST_NAME,
                "complete": complete, "canaries": ["MasterFixture", "PasswordFixture", "EditedFixture", "UserFixture",
                    "LL1-" + "A" * 26, "A" * 32, "otpauth://totp/Fixture?secret=" + "A" * 32,
                    "123456", "GeneratedFixturePassword", "RegeneratedFixturePassword"]}

    def test_partial_failed_manifest_retains_available_canaries_for_scan(self):
        manifest = self.manifest(False)
        values, valid, complete = evidence.parse_canaries(json.dumps(manifest))
        self.assertTrue(valid)
        self.assertFalse(complete)
        self.assertEqual(values, manifest["canaries"])
        manifest["complete"] = "not-a-boolean"
        values, valid, complete = evidence.parse_canaries(json.dumps(manifest))
        self.assertFalse(valid or complete)
        self.assertEqual(values, manifest["canaries"])

    def test_success_manifest_requires_complete_set_and_native_key(self):
        manifest = self.manifest()
        self.assertEqual(evidence.parse_canaries(json.dumps(manifest))[1:], (True, True))
        manifest["canaries"][4] = "wrong-key"
        self.assertFalse(evidence.parse_canaries(json.dumps(manifest))[2])

    def test_only_fresh_named_booted_simulator_is_accepted(self):
        identifier = "12345678-1234-4234-8234-1234567890AB"
        device = {"udid": identifier, "name": "Locklark-CI-test", "isAvailable": True, "state": "Booted"}
        evidence.owned_device(json.dumps({"devices": {"runtime": [device]}}), identifier)
        for change in ({"name": "Personal phone"}, {"state": "Shutdown"}, {"isAvailable": False}):
            with self.subTest(change=change), self.assertRaises(evidence.EvidenceFailure):
                evidence.owned_device(json.dumps({"devices": {"runtime": [{**device, **change}]}}), identifier)

    def test_nested_xcresult_references_include_text_and_data(self):
        def reference(identifier, target):
            return {"_type": {"_name": "Reference"}, "id": {"_value": identifier}, "targetType": {"_value": target}}
        value = {"root": [reference("opaque/log", "ActionLogSection"), {"attachment": reference("opaque/data", "Data")}],
                 "duplicate": reference("opaque/log", "ActionLogSection")}
        self.assertEqual(evidence.references(value), {"opaque/log": "ActionLogSection", "opaque/data": "Data"})

    def test_failed_ui_case_still_exports_and_scans_available_evidence(self):
        secret = "PrivateFailedCaseFixture"
        with tempfile.TemporaryDirectory() as root:
            runtime = pathlib.Path(root) / "runtime.log"
            runtime.write_text(secret)
            args = types.SimpleNamespace(artifacts=root, runtime_log=str(runtime), test_exit_code=65)
            verifier = evidence.EvidenceVerifier(args)

            def manifest():
                verifier.canaries = [secret]
                verifier.manifest_valid = True
                verifier.manifest_complete = False

            with mock.patch.object(verifier, "load_manifest", side_effect=manifest), \
                 mock.patch.object(verifier, "export_xcresult") as export:
                self.assertFalse(verifier.execute())
            export.assert_called_once()
            self.assertEqual(verifier.stage, "canary-scan")

    def test_failed_reference_does_not_skip_other_available_payloads(self):
        def reference(identifier):
            return {"_type": {"_name": "Reference"}, "id": {"_value": identifier}, "targetType": {"_value": "Data"}}
        with tempfile.TemporaryDirectory() as root:
            bundle = pathlib.Path(root) / "results.xcresult"
            bundle.mkdir()
            args = types.SimpleNamespace(artifacts=root, xcresult=str(bundle))
            verifier = evidence.EvidenceVerifier(args)
            with mock.patch.object(verifier, "get_object", return_value={"refs": [reference("first"), reference("second")]}), \
                 mock.patch.object(verifier, "export_data", side_effect=[evidence.EvidenceFailure(), None]) as export, \
                 self.assertRaises(evidence.EvidenceFailure):
                verifier.export_xcresult()
            self.assertEqual(export.call_args_list, [mock.call("first"), mock.call("second")])
            self.assertFalse(verifier.export_complete)


if __name__ == "__main__":
    unittest.main()
