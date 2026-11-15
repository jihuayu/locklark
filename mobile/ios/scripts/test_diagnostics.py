import json
import subprocess
import sys
import tempfile
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

spec = spec_from_file_location("ios_diagnostics", Path(__file__).with_name("summarize-failure.py"))
diagnostics = module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class DiagnosticPrivacyTests(unittest.TestCase):
    def run_cli(self, text, *arguments):
        with tempfile.TemporaryDirectory(prefix="private-fixture-canary-") as directory:
            log = Path(directory) / "private-fixture-canary.log"
            log.write_text(text)
            return subprocess.run([sys.executable, str(Path(__file__).with_name("summarize-failure.py")), str(log), *arguments], capture_output=True, text=True)

    def test_source_excerpts_values_paths_and_assertion_diffs_never_escape(self):
        secret = "private-fixture-canary"
        text = "/private/" + secret + "/VaultModel.swift:12:3: error: cannot find '" + secret + "' in scope\n"
        text += "    let value = \"" + secret + "\"\nTest Case 'fixture' failed\n"
        output = diagnostics.summary(text)
        self.assertNotIn(secret, json.dumps(output))
        self.assertEqual(output["compile_diagnostics"], [{"file": "VaultModel.swift", "line": 12, "category": "missing-symbol"}])
        self.assertEqual(output["runtime_failed_cases"], 1)

    def test_arbitrary_filename_cannot_publish_a_secret(self):
        self.assertEqual(diagnostics.summary("/tmp/private-canary.swift:1:1: error: failure")["compile_diagnostics"], [])

    def test_runtime_reports_only_owned_case_line_and_fixed_source_reason(self):
        secret = "private-fixture-canary"
        text = "/tmp/" + secret + "/OfflineVaultFlowTests.swift:17: error: -[LocklarkUITests.OfflineVaultFlowTests testActualOfflineCreateUnlockEditRevealAndBackgroundLock] : XCTAssertTrue failed: (\"" + secret + "\") - native input must exist\n"
        output = diagnostics.summary(text)
        self.assertNotIn(secret, json.dumps(output))
        self.assertEqual(output["compile_diagnostics"], [])
        self.assertEqual(output["runtime_diagnostics"], [{"file": "OfflineVaultFlowTests.swift", "line": 17, "case": "OfflineVaultFlowTests.testActualOfflineCreateUnlockEditRevealAndBackgroundLock", "reason": "native input must exist"}])

    def test_unknown_runtime_case_and_interpolated_values_are_omitted(self):
        text = "/tmp/CoreIntegrationTests.swift:5: error: -[Unknown privateValue] : private-fixture-canary\n"
        self.assertEqual(diagnostics.summary(text)["runtime_diagnostics"], [])

    def test_unexpected_thrown_error_uses_static_method_location_only(self):
        text = "<unknown>:0: error: -[LocklarkTests.CoreIntegrationTests testActualGoCreateAndReopenKeepsDatabaseCompletelyProtected] : threw private-fixture-canary"
        output = diagnostics.summary(text)
        self.assertNotIn("private-fixture-canary", json.dumps(output))
        self.assertEqual(output["runtime_diagnostics"][0]["location"], "method-declaration")
        self.assertEqual(output["runtime_diagnostics"][0]["reason"], "unexpected-error")

    def test_fixed_phase_does_not_publish_original_error(self):
        text = "/tmp/CoreIntegrationTests.swift:45: error: -[LocklarkTests.CoreIntegrationTests testActualGoCreateAndReopenKeepsDatabaseCompletelyProtected] : failed - core-phase-default-protection private-fixture-canary"
        output = diagnostics.summary(text)
        self.assertNotIn("private-fixture-canary", json.dumps(output))
        self.assertEqual(output["runtime_diagnostics"][0]["reason"], "core-phase-default-protection")

    def test_actionability_helper_literals_are_narrowly_allowlisted(self):
        source = r'''let unrelated = "private-fixture-canary"
waitActionable(element, timeout: 10, message: "native input must exist")
tapActionable(element, message: "native selected control must open")
other(element, message: "private-fixture-canary")
waitActionable(element, message: "prefix \(privateValue)")'''
        reasons = diagnostics.fixed_reasons(source)
        self.assertIn("native input must exist", reasons)
        self.assertIn("native selected control must open", reasons)
        self.assertIn("native control must be actionable", reasons)
        self.assertNotIn("private-fixture-canary", reasons)
        self.assertNotIn(r"prefix \(privateValue)", reasons)

    def test_capability_denial_failures_keep_only_fixed_reasons(self):
        text = "/private/fixture/ProtectionCapabilityDenialTests.swift:19: error: -[LocklarkCapabilityTests.ProtectionCapabilityDenialTests testUnavailableCompleteProtectionIsRefusedBeforeVaultCreation] : XCTAssertThrowsError failed - product must refuse unverifiable or weaker complete protection private-fixture-canary"
        output = diagnostics.summary(text)
        self.assertNotIn("private-fixture-canary", json.dumps(output))
        self.assertEqual(output["runtime_diagnostics"][0]["reason"], "product must refuse unverifiable or weaker complete protection")

    def test_real_cli_reports_non_source_xcodebuild_failure_without_error_values(self):
        result = self.run_cli("xcodebuild: error: private-fixture-canary /private/fixture\n** TEST FAILED **\n", "--phase", "capability-denial", "--exit-code", "65")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertNotIn("private-fixture-canary", result.stdout)
        self.assertNotIn("/private/", result.stdout)
        output = json.loads(result.stdout.removeprefix("ios failure metadata "))
        self.assertEqual(output["phase"], "capability-denial")
        self.assertEqual(output["exit_class"], "exit-65")
        self.assertEqual(output["xcodebuild_terminal"], "testing-failed-marker")
        self.assertEqual(output["denial_tests"], {"unit": "unknown", "ui": "unknown"})
        self.assertEqual(output["compile_diagnostics"], [])
        self.assertEqual(output["runtime_diagnostics"], [])
        self.assertEqual(output["runtime_failed_cases"], 0)

    def test_existing_log_only_cli_remains_compatible_with_device_ci(self):
        result = self.run_cli("xcodebuild: error: private-fixture-canary\n")
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout.removeprefix("ios failure metadata "))
        self.assertEqual(output["phase"], "unknown")
        self.assertEqual(output["exit_class"], "unknown")
        self.assertEqual(output["xcodebuild_terminal"], "unknown")
        self.assertNotIn("private-fixture-canary", result.stdout + result.stderr)

    def test_phase_and_exit_classes_are_bounded_and_never_infer_a_cause(self):
        for phase in diagnostics.PHASES:
            for code, expected in [(0, "zero"), (65, "exit-65"), (70, "exit-70"), (1, "other-nonzero"), (255, "other-nonzero")]:
                with self.subTest(phase=phase, exit_code=code):
                    output = diagnostics.summary("xcodebuild: error: private-fixture-canary\n", phase, code)
                    self.assertEqual(output["phase"], phase)
                    self.assertEqual(output["exit_class"], expected)
                    self.assertEqual(output["xcodebuild_terminal"], "unknown")
                    self.assertEqual(output["denial_tests"], {"unit": "unknown", "ui": "unknown"})
                    self.assertNotIn("private-fixture-canary", json.dumps(output))
        for code in [None, True, -1, 256, "private-fixture-canary"]:
            output = diagnostics.summary("", "private-fixture-canary", code)
            self.assertEqual(output["phase"], "unknown")
            self.assertEqual(output["exit_class"], "unknown")
            self.assertNotIn("private-fixture-canary", json.dumps(output))

    def test_only_exact_fixed_terminal_lines_are_observed(self):
        for marker, expected in [("** BUILD FAILED **", "build-failed-marker"), ("** TEST FAILED **", "testing-failed-marker"), ("** TEST SUCCEEDED **", "test-succeeded-marker")]:
            with self.subTest(marker=marker):
                self.assertEqual(diagnostics.summary(marker + "\n" + marker)["xcodebuild_terminal"], expected)
                for decorated in ["private-fixture-canary " + marker, marker + " private-fixture-canary", 'print("' + marker + '")', marker.lower()]:
                    self.assertEqual(diagnostics.summary(decorated)["xcodebuild_terminal"], "unknown")
        output = diagnostics.summary("** BUILD FAILED **\n** TEST FAILED **\n** TEST SUCCEEDED **\n")
        self.assertEqual(output["xcodebuild_terminal"], "conflicting")

    def test_denial_unit_and_ui_lifecycle_observations_are_separate(self):
        unit = "Test Case '-[LocklarkCapabilityTests.ProtectionCapabilityDenialTests testUnavailableCompleteProtectionIsRefusedBeforeVaultCreation]' "
        ui = "Test Case '-[LocklarkCapabilityUITests.ProtectionCapabilityDenialUITests testActualAppKeepsCreationDisabledWhenProtectionIsUnavailable]' "
        text = unit + "started.\n" + unit + "passed (0.125 seconds).\n" + ui + "started.\n" + ui + "failed (1.250 seconds).\n"
        output = diagnostics.summary(text, "capability-denial", 65)
        self.assertEqual(output["denial_tests"], {"unit": "passed", "ui": "failed"})
        self.assertEqual(output["runtime_diagnostics"], [])
        self.assertEqual(output["xcodebuild_terminal"], "unknown")
        self.assertEqual(diagnostics.summary(unit + "started.\n", "capability-denial", 70)["denial_tests"], {"unit": "started", "ui": "unknown"})
        self.assertEqual(diagnostics.summary(text, "full-positive", 65)["denial_tests"], {"unit": "unknown", "ui": "unknown"})

    def test_denial_conflicts_are_not_resolved_as_a_pass_or_failure(self):
        unit = "Test Case '-[ProtectionCapabilityDenialTests testUnavailableCompleteProtectionIsRefusedBeforeVaultCreation]' "
        text = unit + "passed (0.125 seconds).\n" + unit + "failed (0.250 seconds).\n"
        self.assertEqual(diagnostics.summary(text, "capability-denial", 65)["denial_tests"], {"unit": "conflicting", "ui": "unknown"})

    def test_unowned_and_decorated_denial_cases_remain_unknown(self):
        unit = "Test Case '-[LocklarkCapabilityTests.ProtectionCapabilityDenialTests testUnavailableCompleteProtectionIsRefusedBeforeVaultCreation]' "
        lines = [unit.replace("LocklarkCapabilityTests.", "PrivateModule.") + "failed (0.125 seconds).", unit.replace("testUnavailableCompleteProtectionIsRefusedBeforeVaultCreation", "testPrivateFixture") + "failed (0.125 seconds).", "private-fixture-canary " + unit + "started.", unit + "failed (private-fixture-canary seconds).", unit + "failed (0.125 seconds). private-fixture-canary"]
        output = diagnostics.summary("\n".join(lines), "capability-denial", 70)
        self.assertEqual(output["denial_tests"], {"unit": "unknown", "ui": "unknown"})
        self.assertNotIn("private-fixture-canary", json.dumps(output))
        self.assertNotIn("PrivateModule", json.dumps(output))

    def test_cli_argument_and_read_failures_never_publish_private_values(self):
        for arguments in [("--phase", "private-fixture-canary"), ("--exit-code", "private-fixture-canary"), ("--exit-code", "256"), ("--private-fixture-canary",)]:
            with self.subTest(argument_kind=arguments[0]):
                result = self.run_cli("", *arguments)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "ios failure metadata unavailable\n")
                self.assertEqual(result.stderr, "")
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("summarize-failure.py")), "/private/private-fixture-canary/missing.log"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "ios failure metadata unavailable\n")
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
