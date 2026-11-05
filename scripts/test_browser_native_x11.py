"""Pure readiness tests; no X server, native values, or approval actions."""
import unittest
import json
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


class NativeSnapshotReferenceTests(unittest.TestCase):
    def controls(self):
        controls = native.NativeControls.__new__(native.NativeControls)
        controls.title = "synthetic-window"
        controls.pid = None
        controls.desktop = "desktop"
        controls.at, controls.gl, controls.go = Mock(), Mock(), Mock()
        controls.gl.g_main_context_iteration.return_value = 0
        controls.string = Mock(return_value=controls.title)
        controls.go.g_object_ref.side_effect = lambda node: "ref-" + node
        return controls

    def test_query_failure_releases_discovered_window(self):
        controls = self.controls()

        def walk(_node, visit):
            visit("one", 0)
            raise native.AccessibilityQueryUnavailable("Native accessibility query failed")

        controls.walk = Mock(side_effect=walk)
        with self.assertRaises(native.AccessibilityQueryUnavailable):
            controls.snapshot()
        controls.go.g_object_unref.assert_called_once_with("ref-one")

    def test_query_failure_releases_all_discovered_windows(self):
        controls = self.controls()

        def walk(_node, visit):
            visit("one", 0)
            visit("two", 0)
            raise native.AccessibilityQueryUnavailable("Native accessibility query failed")

        controls.walk = Mock(side_effect=walk)
        with self.assertRaises(native.AccessibilityQueryUnavailable):
            controls.snapshot()
        self.assertEqual(controls.go.g_object_unref.call_args_list,
                         [(("ref-one",),), (("ref-two",),)])

    def test_ambiguous_windows_release_all_references(self):
        controls = self.controls()
        controls.walk = Mock(side_effect=lambda _node, visit: (visit("one", 0), visit("two", 0)))
        with self.assertRaisesRegex(RuntimeError, "Native accessibility window must be unique"):
            controls.snapshot()
        self.assertEqual(controls.go.g_object_unref.call_count, 2)

    def test_control_query_failure_releases_window(self):
        controls = self.controls()

        def walk(node, visit):
            if node == "desktop":
                visit("one", 0)
            else:
                raise native.AccessibilityQueryUnavailable("Native accessibility query failed")

        controls.walk = Mock(side_effect=walk)
        with self.assertRaises(native.AccessibilityQueryUnavailable):
            controls.snapshot()
        controls.go.g_object_unref.assert_called_once_with("ref-one")


class NativeGuardMetadataTests(unittest.TestCase):
    def test_depth_guard_is_unchanged_and_reports_only_counts(self):
        controls = native.NativeControls.__new__(native.NativeControls)
        with self.assertRaises(RuntimeError) as error:
            controls.walk("synthetic-node", lambda *_: True, depth=13)
        self.assertEqual(native.failure_reason(error.exception), "a11y-tree-limit")
        self.assertEqual(error.exception.native_guard, {"depth":13,"visited":0,"remaining":512})

    def test_large_child_count_still_fails_closed(self):
        controls = native.NativeControls.__new__(native.NativeControls)
        controls.at = Mock()
        controls.at.atspi_accessible_get_child_count.return_value = 1000
        controls.checked = lambda function,*args: function(*args)
        with self.assertRaises(RuntimeError) as error:
            controls.walk("synthetic-node", lambda *_: True)
        self.assertEqual(native.failure_reason(error.exception), "a11y-child-limit")
        self.assertEqual(error.exception.native_guard, {"depth":0,"visited":1,"remaining":511,"children":1000})


class ClickMetadataTests(unittest.TestCase):
    def test_fixed_click_fields_are_preserved(self):
        result = native.safe_click_record({"label":"立即锁定","target":"0x200003","x":12,"y":25,
                                          "before":{"focus":"0x200003","x":0,"y":0,"button_mask":0,"pointer_available":True},
                                          "x_test":{"motion":True,"down":True,"up":True}})
        self.assertEqual(result["label"],"立即锁定")
        self.assertEqual(result["x_test"],{"motion":True,"down":True,"up":True})
        self.assertEqual(result["before"]["focus"],result["target"])

    def test_private_or_unknown_metadata_is_not_echoed(self):
        private = "synthetic-private-value"
        result = native.safe_click_record({"label":private,"target":private,"x":private,"value":private,
                                          "before":{"focus":private,"field":private},
                                          "x_test":{"motion":private,"down":True,"up":True}})
        self.assertNotIn(private,json.dumps(result))
        self.assertEqual(result["label"],"pointer")


class WindowViewabilityTests(unittest.TestCase):
    def test_unmapped_and_unviewable_wait_until_viewable(self):
        read = Mock(side_effect=[0,1,2])
        with patch.object(native.time,"monotonic",side_effect=[0,0,0.05,0.05,0.1,0.1]), patch.object(native.time,"sleep") as sleep:
            native.wait_window_viewable(read,5)
        self.assertEqual(read.call_count,3)
        self.assertEqual(sleep.call_count,2)

    def test_existing_find_deadline_is_not_restarted(self):
        read = Mock(return_value=0)
        with patch.object(native.time,"monotonic",side_effect=[4.98,4.99,5]), patch.object(native.time,"sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError,"window not viewable"):
                native.wait_window_viewable(read,5)
        read.assert_called_once()
        self.assertAlmostEqual(sleep.call_args.args[0],0.01)

    def test_late_positive_query_is_not_accepted(self):
        read = Mock(return_value=2)
        with patch.object(native.time,"monotonic",side_effect=[4.9,5.1]), patch.object(native.time,"sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError,"window not viewable"):
                native.wait_window_viewable(read,5)
        read.assert_called_once()
        sleep.assert_not_called()

    def test_failed_attributes_do_not_retry_or_focus(self):
        read = Mock(return_value=None)
        focus = Mock()
        with patch.object(native.time,"monotonic",side_effect=[0,0.01]), patch.object(native.time,"sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError,"window attributes unavailable"):
                native.wait_window_viewable(read,5)
                focus()
        read.assert_called_once()
        focus.assert_not_called()
        sleep.assert_not_called()

    def test_already_expired_deadline_does_not_query(self):
        read = Mock()
        with patch.object(native.time,"monotonic",return_value=5):
            with self.assertRaisesRegex(RuntimeError,"window not viewable"):
                native.wait_window_viewable(read,5)
        read.assert_not_called()

    def test_badmatch_and_target_badwindow_stop_before_input(self):
        for errors in ([(8,5)],[(3,5)]):
            with self.subTest(errors=errors):
                input = Mock()
                with self.assertRaisesRegex(RuntimeError,"X target unavailable"):
                    native.check_x_target_errors(errors,5)
                    input()
                input.assert_not_called()
        native.check_x_target_errors([(3,9)],5)  # Other popup destruction only.


if __name__ == "__main__":
    unittest.main()
