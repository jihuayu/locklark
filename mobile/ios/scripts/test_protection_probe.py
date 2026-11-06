import json
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

spec = spec_from_file_location("protection_probe", Path(__file__).with_name("read-protection-probe.py"))
probe = module_from_spec(spec)
spec.loader.exec_module(probe)


class ProtectionProbePrivacyTests(unittest.TestCase):
    def test_only_fixed_categories_and_known_codes_escape(self):
        value = {"version": 1, "wrapper": "fail", "secret": "private-canary", "setup": {"status": "error", "domain": "private-canary", "code": 123456}, "nodes": [{"role": "file", "setter": "raw", "backup_fresh": {"status": "ok", "value": "nil"}, "complete_after": {"status": "ok", "representation": "string", "class": "complete", "raw": "private-canary"}}]}
        output = probe.sanitize(value)
        self.assertNotIn("private-canary", json.dumps(output))
        self.assertNotIn("123456", json.dumps(output))
        self.assertEqual(output["setup"], {"status": "error", "domain": "other", "code": "other"})
        self.assertEqual(output["nodes"][0]["complete_after"]["class"], "complete")

    def test_known_numeric_error_code_is_preserved(self):
        self.assertEqual(probe.step({"status": "error", "domain": "NSPOSIXErrorDomain", "code": 13}), {"status": "error", "domain": "NSPOSIXErrorDomain", "code": 13})

    def test_untrusted_roles_and_attribute_values_are_not_published(self):
        output = probe.sanitize({"version": 1, "nodes": [{"role": "private-canary", "setter": "raw"}]})
        self.assertEqual(output["nodes"], [])
        self.assertEqual(probe.protection({"status": "ok", "representation": "private-canary", "class": "private-canary"}), {"status": "ok", "representation": "other", "class": "unknown"})


if __name__ == "__main__": unittest.main()
