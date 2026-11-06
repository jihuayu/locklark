import json
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

spec = spec_from_file_location("ios_diagnostics", Path(__file__).with_name("summarize-failure.py"))
diagnostics = module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class DiagnosticPrivacyTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
