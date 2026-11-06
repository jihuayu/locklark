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


if __name__ == "__main__":
    unittest.main()
