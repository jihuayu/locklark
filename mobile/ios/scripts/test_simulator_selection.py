import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

spec = spec_from_file_location("ios_selection", Path(__file__).with_name("select-simulator.py"))
selection = module_from_spec(spec)
spec.loader.exec_module(selection)


class SimulatorSelectionTests(unittest.TestCase):
    runtime = "com.apple.CoreSimulator.SimRuntime.iOS-26-0"
    phone = "com.apple.CoreSimulator.SimDeviceType.iPhone-17"

    def fixtures(self):
        return ({"runtimes": [{"identifier": self.runtime, "version": "26.0", "isAvailable": True}]},
                {"devices": {self.runtime: [{"deviceTypeIdentifier": self.phone, "isAvailable": True, "udid": "personal-existing-device"}]}})

    def test_pair_comes_from_the_same_available_runtime(self):
        runtimes, devices = self.fixtures()
        self.assertEqual(selection.select(runtimes, devices), (self.runtime, self.phone))
        self.assertNotIn("personal-existing-device", selection.select(runtimes, devices))

    def test_unrelated_latest_device_type_cannot_be_mixed_with_runtime(self):
        runtimes, devices = self.fixtures()
        devices["devices"]["unsupported-runtime"] = [{"deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-99", "isAvailable": True}]
        self.assertEqual(selection.select(runtimes, devices), (self.runtime, self.phone))

    def test_unavailable_runtime_is_refused(self):
        runtimes, devices = self.fixtures()
        runtimes["runtimes"][0]["isAvailable"] = False
        with self.assertRaises(ValueError): selection.select(runtimes, devices)

    def test_unavailable_device_or_unmatched_matrix_is_refused(self):
        runtimes, devices = self.fixtures()
        devices["devices"][self.runtime][0]["isAvailable"] = False
        with self.assertRaises(ValueError): selection.select(runtimes, devices)
        with self.assertRaises(ValueError): selection.select(runtimes, {"devices": {"other": []}})


if __name__ == "__main__":
    unittest.main()
