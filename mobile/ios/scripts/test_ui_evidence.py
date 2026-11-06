"""Host privacy/oracle tests only; no simulator/UI evidence is fabricated."""

import base64
import contextlib
import importlib.util
import io
import json
import pathlib
import stat
import subprocess
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
            result = evidence.main(["--simulator", "12345678-1234-4234-8234-1234567890AB", "--owned-simulator",
                                    "--runtime-log", "unused", "--xcresult", "unused", "--test-exit-code", "1"])
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "FAIL: iOS UI evidence validation stage=manifest files=0 manifest_valid=false manifest_complete=false export_complete=false\nPrivate iOS UI evidence: /private/ios-evidence\n")
        self.assertNotIn(secret, output.getvalue())

    def test_failure_summary_allows_only_fixed_stage_count_and_booleans(self):
        secret = "PrivateDiagnosticInjectionFixture"
        summary = evidence.failure_summary(secret, secret, secret, secret, secret)
        self.assertEqual(summary, "FAIL: iOS UI evidence validation stage=prerequisites files=0 manifest_valid=false manifest_complete=false export_complete=false")
        self.assertNotIn(secret, summary)
        self.assertEqual(evidence.failure_summary("test-outcome", 42, True, False, True),
                         "FAIL: iOS UI evidence validation stage=test-outcome files=42 manifest_valid=true manifest_complete=false export_complete=true")


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


class PhysicalTransportTests(unittest.TestCase):
    device = "00008110-0008040A0A11801E"
    simulator = "12345678-1234-4234-8234-1234567890AB"
    runner = "com.example.locklark.acceptance.uitests.xctrunner"

    def arguments(self, root, **changes):
        values = dict(artifacts=root, xcrun="/unused-xcrun", simulator=None, device=self.device,
                      owned_simulator=False, runner_bundle=self.runner)
        return types.SimpleNamespace(**{**values, **changes})

    def test_physical_copy_uses_only_validated_test_runner_container(self):
        with tempfile.TemporaryDirectory() as root:
            verifier = evidence.EvidenceVerifier(self.arguments(root))
            calls = []

            def copied(command, **options):
                calls.append(command)
                destination = pathlib.Path(command[command.index("--destination") + 1])
                destination.write_text(json.dumps(EvidenceIntegrityTests.manifest()))
                destination.chmod(0o644)
                options["stdout"].write(b"test runner manifest copied\n")
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(evidence.subprocess, "run", side_effect=copied):
                verifier.load_manifest()
            destination = verifier.root / "runner-canaries-private.json"
            self.assertEqual(calls, [["/unused-xcrun", "devicectl", "device", "copy", "from",
                "--device", self.device, "--domain-type", "appDataContainer", "--domain-identifier", self.runner,
                "--source", "Library/Application Support/LocklarkUITestEvidence/canaries.json",
                "--destination", str(destination)]])
            self.assertTrue(verifier.manifest_valid and verifier.manifest_complete)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            verifier.scan()

    def test_failed_copy_retains_manifest_for_output_leak_scan(self):
        with tempfile.TemporaryDirectory() as root:
            verifier = evidence.EvidenceVerifier(self.arguments(root))
            manifest = EvidenceIntegrityTests.manifest(False)

            def copied(command, **options):
                destination = pathlib.Path(command[command.index("--destination") + 1])
                destination.write_text(json.dumps(manifest))
                options["stderr"].write(manifest["canaries"][0].encode())
                return subprocess.CompletedProcess(command, 1)

            with mock.patch.object(evidence.subprocess, "run", side_effect=copied), self.assertRaises(evidence.EvidenceFailure):
                verifier.load_manifest()
            self.assertEqual(verifier.canaries, manifest["canaries"])
            self.assertTrue(verifier.manifest_valid)
            self.assertFalse(verifier.manifest_complete)
            with self.assertRaises(evidence.EvidenceFailure) as failure:
                verifier.scan()
            self.assertEqual(str(failure.exception), "")

    def test_physical_copy_cannot_bypass_complete_manifest_or_test_exit_gate(self):
        for exit_code, complete in ((65, True), (0, False)):
            with self.subTest(exit_code=exit_code, complete=complete), tempfile.TemporaryDirectory() as root:
                runtime = pathlib.Path(root) / "runtime.log"
                runtime.write_text("fixed runtime output\n")
                args = self.arguments(root, runtime_log=str(runtime), test_exit_code=exit_code)
                verifier = evidence.EvidenceVerifier(args)

                def copied(command, **_):
                    destination = pathlib.Path(command[command.index("--destination") + 1])
                    destination.write_text(json.dumps(EvidenceIntegrityTests.manifest(complete)))
                    return subprocess.CompletedProcess(command, 0)

                def exported():
                    verifier.export_complete = True

                with mock.patch.object(evidence.subprocess, "run", side_effect=copied), \
                     mock.patch.object(verifier, "export_xcresult", side_effect=exported):
                    self.assertFalse(verifier.execute())
                self.assertTrue(verifier.manifest_valid and verifier.export_complete)
                self.assertEqual(verifier.stage, "test-outcome")

    def test_ambiguous_modes_and_non_test_bundles_never_construct_subprocess(self):
        with tempfile.TemporaryDirectory() as root:
            changes = [dict(device=None), dict(simulator=self.simulator), dict(owned_simulator=True),
                       dict(runner_bundle=None), dict(device="Personal iPhone"),
                       dict(runner_bundle=evidence.RUNNER_BUNDLE),
                       dict(runner_bundle="com.example.application.uitests.xctrunner"),
                       dict(runner_bundle="com.locklark.acceptance.uitests.xctrunner"),
                       dict(runner_bundle=self.runner + ".extra"),
                       dict(device=None, simulator=self.simulator, owned_simulator=True, runner_bundle=self.runner)]
            for change in changes:
                with self.subTest(change=change), mock.patch.object(evidence.subprocess, "run") as run, \
                     self.assertRaises((evidence.EvidenceFailure, ValueError)):
                    evidence.EvidenceVerifier(self.arguments(root, **change)).load_manifest()
                run.assert_not_called()

    def test_existing_simulator_ownership_and_fixed_runner_contract_is_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            container = pathlib.Path(root) / "runner-container"
            source = container / evidence.MANIFEST
            source.parent.mkdir(parents=True)
            source.write_text(json.dumps(EvidenceIntegrityTests.manifest()))
            source.chmod(0o600)
            inventory, path = pathlib.Path(root) / "devices.json", pathlib.Path(root) / "container.txt"
            inventory.write_text(json.dumps({"devices": {"runtime": [{"udid": self.simulator, "name": "Locklark-CI-unit",
                "state": "Booted", "isAvailable": True}]}}))
            path.write_text(str(container) + "\n")
            args = self.arguments(root, device=None, simulator=self.simulator, owned_simulator=True, runner_bundle=None)
            verifier = evidence.EvidenceVerifier(args)
            with mock.patch.object(verifier, "command", side_effect=[(True, inventory), (True, path)]) as command:
                verifier.load_manifest()
            self.assertEqual(command.call_args_list, [mock.call("devices", ["simctl", "list", "devices", "--json"]),
                mock.call("runner-container", ["simctl", "get_app_container", self.simulator, evidence.RUNNER_BUNDLE, "data"])])
            self.assertTrue(verifier.manifest_complete)

    def test_invalid_physical_or_ambiguous_cli_has_only_fixed_public_failure(self):
        secret = "PrivateBundleInjectionFixture"
        arguments = ["--device", self.device, "--runner-bundle", secret,
                     "--runtime-log", "unused", "--xcresult", "unused", "--test-exit-code", "1"]
        for argv in (arguments, arguments + ["--simulator", self.simulator]):
            with mock.patch.object(evidence.subprocess, "run") as run, contextlib.redirect_stdout(io.StringIO()) as output:
                result = evidence.main(argv)
            self.assertEqual(result, 1)
            self.assertEqual(output.getvalue(), "FAIL: iOS UI evidence validation stage=prerequisites files=0 manifest_valid=false manifest_complete=false export_complete=false\n")
            self.assertNotIn(secret, output.getvalue())
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
