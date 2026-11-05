"""Pure readiness tests; no X server, native values, or approval actions."""
import unittest
from unittest.mock import Mock, patch

import browser_native_x11 as native


class NativeReadinessTests(unittest.TestCase):
    def controls(self, side_effect):
        controls = native.NativeControls.__new__(native.NativeControls)
        controls.snapshot = Mock(side_effect=side_effect)
        return controls

    def query_error(self):
        return native.AccessibilityQueryUnavailable("Native accessibility query failed")

    def test_one_query_failure_then_ready(self):
        control = {"enabled": True, "showing": True, "width": 20, "height": 10}
        controls = self.controls([self.query_error(), {"确认连接此扩展": [control]}])
        with patch.object(native.time, "monotonic", side_effect=[0, 0, 0.05]), patch.object(native.time, "sleep") as sleep:
            self.assertIs(controls.ready("确认连接此扩展"), control)
        self.assertEqual(controls.snapshot.call_count, 2)
        sleep.assert_called_once_with(0.05)

    def test_permanent_query_failure_uses_original_deadline(self):
        controls = self.controls(self.query_error())
        with patch.object(native.time, "monotonic", side_effect=[0, 0, 4, 9.99, 10]), patch.object(native.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "Native acceptance control not ready"):
                controls.ready("确认连接此扩展")
        self.assertEqual(controls.snapshot.call_count, 3)
        self.assertEqual(sleep.call_count, 3)

    def test_ambiguous_control_fails_immediately(self):
        controls = self.controls([{"确认连接此扩展": [{}, {}]}])
        with patch.object(native.time, "monotonic", side_effect=[0, 0]), patch.object(native.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "Native acceptance control must be unique"):
                controls.ready("确认连接此扩展")
        controls.snapshot.assert_called_once()
        sleep.assert_not_called()

    def test_tree_limit_fails_immediately(self):
        controls = self.controls(RuntimeError("Native accessibility tree limit"))
        with patch.object(native.time, "monotonic", side_effect=[0, 0]), patch.object(native.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "Native accessibility tree limit"):
                controls.ready("确认连接此扩展")
        controls.snapshot.assert_called_once()
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
