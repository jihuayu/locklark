import unittest
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from device_policy import validate_test_bundle_base, validate_runner_bundle, validate_device_id, validate_team_id, require_fresh_test_apps


class DevicePolicyTests(unittest.TestCase):
    def test_test_only_bundle_and_exact_runner(self):
        base = "com.example.locklark.acceptance"
        self.assertEqual(validate_test_bundle_base(base), base)
        self.assertEqual(validate_runner_bundle(base + ".uitests.xctrunner"), base)

    def test_production_other_namespace_and_unsafe_input_are_refused(self):
        for value in ["org.locklark.mobile.ios", "com.example.real", "example.locklark.acceptance", "com.1example.locklark.acceptance", "com.exa_mple.locklark.acceptance", "com.example.locklark.acceptance\n", "com.example.锁.locklark.acceptance", "a." * 101 + "locklark.acceptance"]:
            with self.assertRaises(ValueError): validate_test_bundle_base(value)
        with self.assertRaises(ValueError): validate_runner_bundle("com.example.locklark.acceptance.other.xctrunner")

    def test_device_ids_are_identifiers_not_aliases_or_commands(self):
        for value in ["00008110-001234567890ABCD", "a" * 40, "12345678-1234-1234-1234-123456789abc"]:
            self.assertEqual(validate_device_id(value), value)
        for value in ["booted", "My iPhone", "--device", "$(command)", "a" * 39, "00008110-001234567890ABCD\n"]:
            with self.assertRaises(ValueError): validate_device_id(value)

    def test_signing_team_is_metadata_only_and_preconfigured(self):
        self.assertEqual(validate_team_id("AB12CD34EF"), "AB12CD34EF")
        with self.assertRaises(ValueError): validate_team_id("personal signing certificate")

    def test_existing_test_container_is_refused_without_cleanup(self):
        base = "com.example.locklark.acceptance"
        require_fresh_test_apps({"result": {"apps": [{"bundleIdentifier": "com.apple.example"}]}}, base)
        for identifier in [base, base + ".uitests.xctrunner"]:
            with self.assertRaises(ValueError): require_fresh_test_apps({"result": {"apps": [{"bundleIdentifier": identifier}]}}, base)
        for payload in [{}, {"result": {"apps": [{}]}}]:
            with self.assertRaises(ValueError): require_fresh_test_apps(payload, base)

    def test_entry_reports_config_and_real_inventory_as_distinct_steps(self):
        command = [sys.executable, str(Path(__file__).with_name("device-preflight.py"))]
        environment = dict(os.environ, IOS_TEST_BUNDLE_BASE="com.example.locklark.acceptance", IOS_DEVICE_ID="00008110-001234567890ABCD", IOS_DEVELOPMENT_TEAM="AB12CD34EF")
        config = subprocess.run(command, env=environment, capture_output=True, text=True)
        self.assertEqual(config.returncode, 0)
        self.assertEqual(config.stdout.strip(), "ios physical configuration PASS")
        with tempfile.TemporaryDirectory() as folder:
            inventory = Path(folder) / "apps.json"
            inventory.write_text(json.dumps({"result": {"apps": []}}))
            checked = subprocess.run(command + [str(inventory)], env=environment, capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0)
            self.assertEqual(checked.stdout.strip(), "ios physical fresh-test inventory PASS")
            extra = subprocess.run(command + [str(inventory), "private-fixture-canary"], env=environment, capture_output=True, text=True)
            self.assertNotEqual(extra.returncode, 0)
            self.assertNotIn("private-fixture-canary", extra.stdout + extra.stderr)


if __name__ == "__main__": unittest.main()
