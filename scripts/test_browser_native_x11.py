"""Pure readiness tests; no X server, native values, or approval actions."""
import unittest
import json
import ctypes
import types
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
        with patch.object(native.time, "monotonic", side_effect=[0, 0, 0.01, 0.06, 0.06]), patch.object(native.time, "sleep") as sleep:
            self.assertIs(controls.ready("确认连接此扩展"), control)
        self.assertEqual(controls.snapshot.call_count, 2)
        sleep.assert_called_once_with(0.05)

    def test_permanent_query_failure_uses_original_deadline(self):
        controls = self.controls(self.query_error())
        with patch.object(native.time, "monotonic", side_effect=[0, 0, 0, 4, 4, 9.99, 9.99, 10]), patch.object(native.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "Native acceptance control not ready"):
                controls.ready("确认连接此扩展")
        self.assertEqual(controls.snapshot.call_count, 3)
        self.assertEqual(sleep.call_count, 3)
        self.assertAlmostEqual(sleep.call_args.args[0], 0.01)

    def test_ambiguous_control_fails_immediately(self):
        controls = self.controls([{"确认连接此扩展": [{}, {}]}])
        with patch.object(native.time, "monotonic", side_effect=[0, 0, 0]), patch.object(native.time, "sleep") as sleep:
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

    def test_late_successful_snapshot_cannot_authorize_input(self):
        control = {"enabled": True, "showing": True, "width": 20, "height": 10}
        controls = self.controls([{ "确认连接此扩展": [control]}])
        action = Mock()
        with patch.object(native.time, "monotonic", side_effect=[0, 0, 10.01]), patch.object(native.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "Native acceptance control not ready"):
                action(controls.ready("确认连接此扩展"))
        controls.snapshot.assert_called_once()
        action.assert_not_called()
        sleep.assert_not_called()


class NativeChildCountSentinelTests(unittest.TestCase):
    def controls(self, counts):
        controls = native.NativeControls.__new__(native.NativeControls)
        returns, calls = iter(counts), []
        callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
        @callback_type
        def child_count(node, error):
            # Exercise the actual C ABI return path with a NULL GError, as in
            # the observed stale accessible. No Python exception is injected.
            calls.append(node)
            return next(returns)
        controls.at = types.SimpleNamespace(atspi_accessible_get_child_count=child_count,
                                            atspi_accessible_get_child_at_index=Mock())
        controls.gl, controls.go = Mock(), Mock()
        return controls, calls

    def test_exact_c_abi_minus_one_is_query_unavailable_not_structural_limit(self):
        controls, calls = self.controls([-1])
        with self.assertRaises(native.AccessibilityQueryUnavailable):
            controls.walk(1, lambda *_: True)
        self.assertEqual(len(calls), 1)
        controls.at.atspi_accessible_get_child_at_index.assert_not_called()
        controls.gl.g_error_free.assert_not_called()

    def test_real_sentinel_aborts_snapshot_then_reobserves_before_one_action(self):
        controls, calls = self.controls([-1, 0])
        control = {"enabled": True, "showing": True, "width": 20, "height": 10}
        def snapshot():
            controls.walk(1, lambda *_: True)
            return {"确认连接此扩展": [control]}
        controls.snapshot = Mock(side_effect=snapshot)
        action = Mock()
        with patch.object(native.time, "monotonic", return_value=0), patch.object(native.time, "sleep"):
            action(controls.ready("确认连接此扩展"))
        self.assertEqual(len(calls), 2)
        self.assertEqual(controls.snapshot.call_count, 2)
        action.assert_called_once_with(control)

    def test_other_negative_or_oversized_c_abi_counts_stay_structural(self):
        for count in (-2, 257, 1000):
            with self.subTest(count=count):
                controls, calls = self.controls([count])
                with self.assertRaisesRegex(RuntimeError, "Native accessibility child limit") as error:
                    controls.walk(1, lambda *_: True)
                self.assertNotIsInstance(error.exception, native.AccessibilityQueryUnavailable)
                self.assertEqual(error.exception.native_guard["children"], count)
                self.assertEqual(len(calls), 1)
                controls.at.atspi_accessible_get_child_at_index.assert_not_called()

    def test_exhausted_node_budget_stays_fatal_before_child_query(self):
        controls, calls = self.controls([-1])
        with self.assertRaisesRegex(RuntimeError, "Native accessibility tree limit"):
            controls.walk(1, lambda *_: True, budget=[0])
        self.assertEqual(calls, [])


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


class AllowlistTests(unittest.TestCase):
    def test_v2_approval_labels_are_exact_literals(self):
        for label in ("批准本次操作", "拒绝本次操作"):
            self.assertIn(label, native.CONTROL_LABELS)
            self.assertTrue(native.control_label_allowed(label))
        # Nearby variants are never allowlisted; matching stays by full equality.
        for label in ("批准本次操作 ", "批准本次操作。", "拒绝本次操作。", "批准操作",
                      "批准本次动作", "确认本次操作", "批 准本次操作", ""):
            with self.subTest(label=label):
                self.assertFalse(native.control_label_allowed(label))

    def test_passkey_remove_labels_are_exact_literals(self):
        for label in ("批准删除 Passkey", "拒绝删除 Passkey"):
            self.assertIn(label, native.CONTROL_LABELS)
            self.assertTrue(native.control_label_allowed(label))
        # Nearby variants are never allowlisted; matching stays by full equality.
        for label in ("批准删除 Passkey ", " 批准删除 Passkey", "批准删除  Passkey",
                      "批准删除 passkey", "批准删除Passkey", "批准删除 Passkey。",
                      "批准删除 Passkey！", "批准删除凭据", "批准删除 Passkey 名称",
                      "拒绝删除 Passkey ", "拒绝删除 passkey", "拒绝删除Passkey",
                      "拒绝删除", "批准删除", ""):
            with self.subTest(label=label):
                self.assertFalse(native.control_label_allowed(label))

    def test_quick_fill_status_text_is_not_allowlisted(self):
        # The fixed host status line is absent from the native AT-SPI snapshot.
        for label in ("快捷填充已启用：在浏览器选择账号即可继续。自动登录设置由扩展管理。",
                      "快捷填充已启用"):
            with self.subTest(label=label):
                self.assertFalse(native.control_label_allowed(label))


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
