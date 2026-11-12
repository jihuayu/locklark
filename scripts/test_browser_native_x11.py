"""Pure readiness tests; no X server, native values, or approval actions."""
import unittest
import io
import json
import ctypes
import os
import tempfile
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

    def test_field_disclosure_labels_are_exact_literals(self):
        for label in ("批准本次字段披露", "拒绝本次字段披露"):
            self.assertIn(label, native.CONTROL_LABELS)
            self.assertTrue(native.control_label_allowed(label))
        # Nearby variants are never allowlisted; matching stays by full equality.
        for label in ("批准本次字段披露 ", " 批准本次字段披露", "批准本次字段披露。",
                      "批准本次字段披露！", "批准字段披露", "批准本次字段", "批准本次披露",
                      "批准本次字段读取", "拒绝本次字段披露 ",
                      "拒绝本次字段披露。", "拒绝字段披露", "拒绝本次披露", ""):
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


def owner_request(**overrides):
    # Synthetic fixture values exist only inside this process; no test prints
    # them and the driver never echoes them.
    request = {
        "owner": True,
        "title": "chooser-probe-title",
        "title_prefix": "chooser-probe-title",
        "chooser_title_prefix": "chooser-prefix.",
        "owner_title_prefix": "manager-prefix",
        "user_data_dir": "/synthetic/profile-1",
        "executable": "/synthetic/edge",
        "preserve_focus": True,
        "owner_pid": 101,
        "actions": [{"text": "-none"}],
    }
    request.update(overrides)
    return request


def probe_request(**overrides):
    # The exact zero-action attribution shape used for the real chooser.
    request = {
        "ownership_probe": True,
        "owner_title_prefix": "Extensions",
        "chooser_title_prefix": "Select the extension directory.",
        "user_data_dir": "/synthetic/profile-1",
        "executable": "/opt/microsoft/msedge/microsoft-edge",
    }
    request.update(overrides)
    return request


def input_request(**overrides):
    # The reviewed input shape without any caller-supplied owner PID: the
    # driver derives the PID from the unique real manager window.
    request = owner_request()
    del request["owner_pid"]
    request.update(overrides)
    return request


class ChooserContractTests(unittest.TestCase):
    def test_exact_owner_profile_and_actions_are_accepted(self):
        parsed = native.parse_owner_request(owner_request())
        self.assertEqual(set(parsed), set(native.OWNER_FIELDS) | {"caller_pid", "probe"})
        self.assertEqual(parsed["caller_pid"], 101)
        self.assertIs(parsed["probe"], False)

    def test_input_shape_derives_the_owner_pid_without_a_caller_value(self):
        parsed = native.parse_owner_request(input_request())
        self.assertEqual(set(parsed), set(native.OWNER_FIELDS) | {"caller_pid", "probe"})
        self.assertIs(parsed["probe"], False)
        self.assertIsNone(parsed["caller_pid"])
        # Optional PID absent and present use the same fixed attribution keys.
        self.assertEqual(set(parsed), set(native.parse_owner_request(owner_request())))
        self.assertEqual(parsed["owner_title_prefix"], "manager-prefix")
        self.assertEqual(parsed["chooser_title_prefix"], "chooser-prefix.")
        self.assertEqual(parsed["user_data_dir"], "/synthetic/profile-1")
        self.assertEqual(parsed["executable"], "/synthetic/edge")

    def test_input_pid_is_bound_to_the_unique_manager_window(self):
        derived = 101
        no_pid = native.parse_owner_request(input_request())
        self.assertEqual(native.derived_owner_pid(no_pid, derived), derived)
        matching = native.parse_owner_request(owner_request(owner_pid=derived))
        self.assertEqual(native.derived_owner_pid(matching, derived), derived)
        mismatched = native.parse_owner_request(owner_request(owner_pid=202))
        self.assertIsNone(native.derived_owner_pid(mismatched, derived))
        # Probe mode derives its own PID and never carries a caller value.
        probe = native.parse_owner_request(probe_request())
        self.assertEqual(native.derived_owner_pid(probe, derived), derived)
        # A malformed derived PID can never authorize input.
        for bad in (None, 0, 1, -1, "101", 101.0, native.PID_LIMIT + 1):
            with self.subTest(bad=bad):
                self.assertIsNone(native.derived_owner_pid(no_pid, bad))
        self.assertIsNone(native.derived_owner_pid(None, derived))
        self.assertIsNone(native.derived_owner_pid({"probe": "no"}, derived))
        for caller in (bool(1), True, 101.0, "101"):
            with self.subTest(caller=caller):
                self.assertIsNone(native.derived_owner_pid(
                    {"probe": False, "caller_pid": caller}, derived))

    def test_zero_action_probe_derives_its_own_pid(self):
        parsed = native.parse_owner_request(probe_request())
        self.assertEqual(set(parsed), set(native.OWNER_FIELDS) | {"probe"})
        self.assertIs(parsed["probe"], True)
        self.assertNotIn("owner_pid", parsed)
        self.assertEqual(parsed["owner_title_prefix"], "Extensions")
        self.assertEqual(parsed["chooser_title_prefix"], "Select the extension directory.")
        # No actions at all, or an explicitly empty list, is the zero-action
        # probe; preserve_focus is irrelevant and may be absent or true.
        for request in (probe_request(actions=[]), probe_request(preserve_focus=True)):
            with self.subTest(request=request):
                self.assertEqual(native.parse_owner_request(request)["probe"], True)

    def test_unrelated_or_malformed_fields_are_rejected(self):
        cases = {
            "other profile": owner_request(user_data_dir="/synthetic/profile-2/"),
            "relative profile": owner_request(user_data_dir="relative/profile"),
            "profile newline": owner_request(user_data_dir="/synthetic/a\nb"),
            "other executable": owner_request(executable="edge.bin"),
            "other title": owner_request(chooser_title_prefix=""),
            "non-ascii title": owner_request(owner_title_prefix="管理器"),
            "focus not preserved": owner_request(preserve_focus=False),
            "unrelated title prefix": owner_request(title_prefix="other-prefix"),
            "pid string": owner_request(owner_pid="101"),
            "pid root": owner_request(owner_pid=1),
            "input pid string": input_request(owner_pid="101"),
            "input pid null": input_request(owner_pid=None),
            "input pid float": input_request(owner_pid=101.0),
            "input pid bool": input_request(owner_pid=True),
            "input pid zero": input_request(owner_pid=0),
            "input pid negative": input_request(owner_pid=-101),
            "input pid over limit": input_request(owner_pid=native.PID_LIMIT + 1),
            "input no actions": input_request(actions=[]),
            "input actions missing": input_request(actions=None),
            "input actions mapping": input_request(actions={"text": "x"}),
            "input action string": input_request(actions=["x"]),
            "input action empty": input_request(actions=[{}]),
            "input action key empty": input_request(actions=[{"key": ""}]),
            "input action text non-ascii": input_request(actions=[{"text": "路径"}]),
            "input action text newline": input_request(actions=[{"text": "/a\nb"}]),
            "input unknown action field": input_request(actions=[{"click_label": "解锁"}]),
            "input unknown field": input_request(extra="x"),
            "input focus false": input_request(preserve_focus=False),
            "input focus absent": {k: v for k, v in input_request().items()
                                   if k != "preserve_focus"},
            "input title differs": input_request(title="other-title"),
            "input title absent": {k: v for k, v in input_request().items() if k != "title"},
            "input profile trailing slash": input_request(user_data_dir="/synthetic/profile-1/"),
            "input profile newline": input_request(user_data_dir="/synthetic/a\nb"),
            "input chooser prefix empty": input_request(chooser_title_prefix=""),
            "input missing user data dir": {k: v for k, v in input_request().items()
                                            if k != "user_data_dir"},
            "input missing executable": {k: v for k, v in input_request().items()
                                         if k != "executable"},
            "input profile relative": input_request(user_data_dir="relative/profile"),
            "input executable relative": input_request(executable="msedge"),
            "input manager title non-ascii": input_request(owner_title_prefix="管理器"),
            "input both modes": input_request(ownership_probe=True),
            "no actions": owner_request(actions=[]),
            "unknown action field": owner_request(actions=[{"click": [1, 2]}]),
            "non-ascii text": owner_request(actions=[{"text": "路径"}]),
            "escape key": owner_request(actions=[{"key": "a+b+c"}]),
            "owner mapping": owner_request(owner={"x": 1}),
            "owner false": owner_request(owner=False),
            "unknown field": owner_request(extra="x"),
            "missing mode marker": {key: value for key, value in owner_request().items()
                                    if key != "owner"},
            "probe false": probe_request(ownership_probe=False),
            "probe actions": probe_request(actions=[{"key": "Return"}]),
            "probe caller pid": probe_request(owner_pid=101),
            "probe title": probe_request(title="chooser-probe-title"),
            "probe unknown field": probe_request(extra="x"),
            "probe focus false": probe_request(preserve_focus=False),
            "probe missing executable": probe_request(executable=None),
            "both modes": probe_request(owner=True),
            "input also probe": owner_request(ownership_probe=True),
        }
        for name, request in cases.items():
            with self.subTest(name):
                self.assertIsNone(native.parse_owner_request(request))
        # Printable spaces are legal in a title prefix and in an absolute path.
        self.assertIsNotNone(native.parse_owner_request(
            owner_request(user_data_dir="/synthetic/a b")))
        self.assertIsNone(native.parse_owner_request([]))
        # Without a caller PID only the fixed attribution values decide, so a
        # different private profile is a well-formed input request; the driver
        # still proves that exact profile against the real owner process.
        self.assertIsNotNone(native.parse_owner_request(
            input_request(user_data_dir="/synthetic/profile-2")))

    def test_parser_never_raises_on_malformed_requests(self):
        base = input_request()
        # Only the optional caller PID may be absent; every fixed attribution
        # field is required and any missing one is refused.
        for key in base:
            with self.subTest(removed=key):
                request = {k: v for k, v in base.items() if k != key}
                self.assertIsNone(native.parse_owner_request(request))
        for value in (None, 1, "x", [], [{}], {"owner": True}, True):
            with self.subTest(value=value):
                self.assertIsNone(native.parse_owner_request(value))
        # "/" is a legal one-character ASCII title prefix but not a path.
        for key in native.OWNER_FIELDS:
            for value in (None, 1, "", "a b\tc", "a\nb", ["x"]):
                with self.subTest(key=key, value=value):
                    self.assertIsNone(native.parse_owner_request(input_request(**{key: value})))
        for key in ("user_data_dir", "executable"):
            for value in ("/", "/a/"):
                with self.subTest(key=key, value=value):
                    self.assertIsNone(native.parse_owner_request(input_request(**{key: value})))

    def test_safe_owner_record_has_only_fixed_classes(self):
        for relation in ("transient-leader", "process-parent"):
            self.assertEqual(native.safe_owner_record({"owned": True, "relation": relation}),
                             {"owned": True, "relation": relation})
        self.assertEqual(native.safe_owner_record({"owned": False, "relation": "none"}),
                         {"owned": False, "relation": "none"})
        # Raw title/pid/path/cmdline/property values are never copied through.
        self.assertEqual(
            native.safe_owner_record({"owned": True, "relation": "transient-leader",
                                      "title": "secret", "pid": 101, "path": "/p",
                                      "cmdline": "c", "property": [1, 2]}),
            {"owned": True, "relation": "transient-leader"})
        for value in (None, {}, {"owned": True, "relation": "other"}, {"owned": "yes"},
                      {"owned": False, "relation": "process-parent"}):
            self.assertIsNone(native.safe_owner_record(value))

    def test_probe_output_has_only_the_fixed_class(self):
        record = {"owned": True, "relation": "process-parent",
                  "title": "secret", "pid": 101, "cmdline": "c", "property": [1]}
        self.assertEqual(native.probe_output(record),
                         {"ownership": {"owned": True, "relation": "process-parent"}})
        self.assertIsNone(native.probe_output(None))
        self.assertIsNone(native.probe_output({"owned": True, "relation": "other"}))

    def test_title_matches_is_minimal_and_fixed(self):
        self.assertTrue(native.title_matches("Extensions - Profile", "Extensions"))
        self.assertFalse(native.title_matches("extensions", "Extensions"))
        self.assertFalse(native.title_matches("Extensions", ""))
        self.assertFalse(native.title_matches("Extensions", None))
        self.assertFalse(native.title_matches(None, "Extensions"))
        self.assertFalse(native.title_matches("bad\n", "bad"))
        # A prefix longer than the title never matches.
        self.assertFalse(native.title_matches("Extensions", "Extensions" + "x"))


class ChooserRelationTests(unittest.TestCase):
    def properties(self, overrides=None):
        values = {("WM_TRANSIENT_FOR", None): [11],
                  ("WM_TRANSIENT_FOR", 11): [11],
                  ("WM_CLIENT_LEADER", None): [11],
                  ("_NET_WM_PID", None): [101],
                  ("_NET_WM_PID", 101): [101],
                  ("_NET_WM_PID", 11): [101],
                  ("WM_CLIENT_LEADER", 11): [11],
                  ("WM_CLIENT_LEADER", 101): [11]}
        values.update(overrides or {})
        return lambda name, window: ({"status": "missing"} if values[(name, window)] is None
                                     else {"status": "ok", "values": values[(name, window)]})

    def test_linked_chooser_and_exact_profile_process_are_accepted(self):
        prop = self.properties()
        self.assertIsNone(native.check_chooser_relations(prop, 11, 101))
        record, reason = native.prove_chooser_ownership("wm", prop, 101, 11, 11, None)
        self.assertIsNone(reason)
        self.assertEqual(record, {"owned": True, "relation": "transient-leader"})
        process = self.properties({("_NET_WM_PID", None): [211]})
        self.assertEqual(native.prove_chooser_ownership("process", process, 101, 11, 211,
                                                        lambda owner, pid: (owner, pid) == (101, 211)),
                         ({"owned": True, "relation": "process-parent"}, None))

    def test_missing_owner_leader_falls_back_to_the_exact_same_process(self):
        # Edge 157 does not set WM_CLIENT_LEADER on the Extensions window; the
        # chooser is still transient of it and carries the exact same PID.
        prop = self.properties({("WM_CLIENT_LEADER", 11): None,
                                ("_NET_WM_PID", None): [101]})
        self.assertIsNotNone(native.check_chooser_relations(prop, 11, 101))
        self.assertIsNone(native.prove_chooser_ownership(
            "wm", prop, 101, 11, 101, None)[0])
        record, reason = native.prove_chooser_ownership(
            "process", prop, 101, None, 101,
            lambda owner, pid: owner == pid == 101)
        self.assertEqual(record, {"owned": True, "relation": "process-parent"})
        self.assertIsNone(reason)

    def test_property_single_int_never_treats_a_record_as_values(self):
        self.assertEqual(native.property_single_int({"status": "ok", "values": [101]}), 101)
        for record in ({"status": "ok", "values": [101, 102]}, {"status": "missing"},
                       {"status": "malformed"}, {"status": "ok", "values": ["101"]},
                       {"status": "ok", "values": [0x100000000]}, None, []):
            with self.subTest(record=record):
                self.assertIsNone(native.property_single_int(record))

    def test_unlinked_chooser_is_rejected(self):
        cases = (
            {("WM_TRANSIENT_FOR", None): None},
            {("WM_TRANSIENT_FOR", None): [0]},
            {("WM_TRANSIENT_FOR", None): [11, 11]},
            {("WM_CLIENT_LEADER", None): None},
            {("WM_CLIENT_LEADER", None): [12]},
            {("WM_CLIENT_LEADER", None): [11, 11]},
            {("WM_CLIENT_LEADER", None): [11, 12]},
            {("WM_CLIENT_LEADER", 11): None},
            {("WM_CLIENT_LEADER", 11): [12]},
            {("_NET_WM_PID", 11): None},
            {("_NET_WM_PID", 11): [102]},
            {("_NET_WM_PID", 11): [101, 102]},
        )
        for override in cases:
            with self.subTest(override=list(override)):
                prop = self.properties(override)
                self.assertIsNotNone(native.check_chooser_relations(prop, 11, 101))
                self.assertIsNone(native.prove_chooser_ownership("wm", prop, 101, 11, 11, None)[0])
        refused = lambda name, window: {"status": "refused"}
        self.assertIsNone(native.prove_chooser_ownership("wm", refused, 101, 11, 11, None)[0])
        self.assertIsNone(native.prove_chooser_ownership("wm", self.properties(), 101, 0, 11, None)[0])

    def test_process_mode_requires_the_actual_owner_pid(self):
        prop = self.properties()
        for owner, candidate, relation in ((101, 202, False), (101, 101, False),
                                           (101, 202, None), (101, 102, True),
                                           (0, 202, True), (101, "202", True)):
            with self.subTest(owner=owner, candidate=candidate):
                self.assertIsNone(native.prove_chooser_ownership(
                    "process", prop, owner, 11, candidate, lambda _o, _p, r=relation: r)[0])
        self.assertIsNone(native.prove_chooser_ownership("other", prop, 101, 11, 11, None)[0])

    def proc_stat(self, parents):
        def open_proc(path, mode):
            pid = int(path.split("/")[2])
            if pid not in parents:
                raise FileNotFoundError
            text = b"1 (name with ) paren) S " + str(parents[pid]).encode() + b" rest"
            return io.BytesIO(text)
        return open_proc

    def test_unrelated_process_parent_chain_is_rejected(self):
        for parents, owner, candidate in (
            ({211: 2}, 101, 211),
            ({211: 303, 303: 2}, 101, 211),
            ({211: 212, 212: 213, 213: 211}, 101, 211),  # Cycle never reaches the owner.
            ({211: 101}, 101, 0),
        ):
            with self.subTest(owner=owner, candidate=candidate), \
                    patch("builtins.open", side_effect=self.proc_stat(parents)):
                self.assertFalse(native.chooser_pid_relation(owner, candidate))
        self.assertFalse(native.chooser_pid_relation("101", 211))
        self.assertFalse(native.chooser_pid_relation(101, "211"))

    def test_actual_bounded_parent_chain_is_accepted(self):
        self.assertTrue(native.chooser_pid_relation(101, 101))
        parents = {211: 101, 212: 211}
        with patch("builtins.open", side_effect=self.proc_stat(parents)):
            self.assertTrue(native.chooser_pid_relation(101, 211))
            self.assertTrue(native.chooser_pid_relation(101, 212))
        deep = {pid: pid - 1 for pid in range(2, 20)}
        with patch("builtins.open", side_effect=self.proc_stat(deep)):
            self.assertFalse(native.chooser_pid_relation(1, 19))

    def test_owner_process_requires_exact_executable_and_profile(self):
        def fake_readlink(link):
            return {"/proc/101/exe": "/synthetic/edge",
                    "/proc/102/exe": "/synthetic/edge-helper"}[link]
        owner = native.parse_owner_request(owner_request())
        cmdline = lambda path, mode: io.BytesIO(
            b"/synthetic/edge\0--user-data-dir=/synthetic/profile-1\0--headless\0")
        with patch.object(native.os, "readlink", side_effect=fake_readlink), \
                patch("builtins.open", side_effect=cmdline):
            self.assertEqual(native.owner_process_matches(101, owner), 101)
            self.assertIsNone(native.owner_process_matches(102, owner))
            other = native.parse_owner_request(owner_request(user_data_dir="/synthetic/profile-2"))
            self.assertIsNone(native.owner_process_matches(101, other))
            with patch.object(native.os, "readlink", side_effect=OSError):
                self.assertIsNone(native.owner_process_matches(101, owner))
        # A duplicate exact profile switch is never a second match.
        duplicate = lambda path, mode: io.BytesIO(
            b"/synthetic/edge\0--user-data-dir=/synthetic/profile-1\0"
            b"--user-data-dir=/synthetic/profile-1\0")
        with patch.object(native.os, "readlink", side_effect=fake_readlink), \
                patch("builtins.open", side_effect=duplicate):
            self.assertIsNone(native.owner_process_matches(101, owner))
        # A command line without its terminating NUL is truncated; so is an
        # over-limit read. Both refuse instead of matching a prefix token.
        for truncated in (
            b"/synthetic/edge\0--user-data-dir=/synthetic/profile-1",
            b"--user-data-dir=/synthetic/profile-1\0" + b"a" * native.CMDLINE_MAX,
        ):
            with self.subTest(size=len(truncated)), \
                    patch.object(native.os, "readlink", side_effect=fake_readlink), \
                    patch("builtins.open", side_effect=lambda p, m, data=truncated:
                          io.BytesIO(data)):
                self.assertIsNone(native.owner_process_matches(101, owner))
        with patch.object(native.os, "readlink", side_effect=fake_readlink), \
                patch("builtins.open", side_effect=FileNotFoundError):
            self.assertIsNone(native.owner_process_matches(101, owner))

    def test_owner_process_compares_the_real_executable_image(self):
        with tempfile.TemporaryDirectory() as directory:
            real = os.path.join(directory, "edge-real")
            link = os.path.join(directory, "edge")
            other = os.path.join(directory, "edge-other")
            for path in (real, other):
                with open(path, "w"):
                    pass
            os.symlink(real, link)
            owner = native.parse_owner_request(owner_request(executable=link))
            cmdline = lambda path, mode: io.BytesIO(
                ("/synthetic/edge\0--user-data-dir=" + owner["user_data_dir"] + "\0").encode())
            # Patch the /proc link read, not os.readlink: realpath itself uses
            # os.readlink to resolve the symlink under test.
            with patch.object(native, "read_proc_link", return_value=real), \
                    patch("builtins.open", side_effect=cmdline):
                self.assertEqual(native.owner_process_matches(101, owner), 101)
            with patch.object(native, "read_proc_link", return_value=other), \
                    patch("builtins.open", side_effect=cmdline):
                self.assertIsNone(native.owner_process_matches(101, owner))


_ABSENT = object()

# The exact native manager X title captured for official Edge 157: U+200B sits
# exactly between "Microsoft" and " Edge".
NATIVE_TITLE = "Extensions - Profile 1 - Microsoft\u200b Edge"


EXTENSION_DIR = "/synthetic/package/chromium"


def folder_request(**overrides):
    # The exact purpose-bound chooser action shape sent by the Edge install
    # caller. By default it is the navigate action, which carries exactly the
    # one absolute package directory: the chooser title is the fixed reviewed
    # literal, while title, title_prefix and owner_title_prefix carry exactly
    # the observed page title Playwright reports, never a native X11 decorated
    # form.
    request = {
        "owner": True,
        "chooser_action": {"chooser_navigate": True},
        "extension_dir": EXTENSION_DIR,
        "chooser_title_prefix": "Select the extension directory.",
        "title": "Extensions",
        "title_prefix": "Extensions",
        "owner_title_prefix": "Extensions",
        "user_data_dir": "/synthetic/profile-1",
        "executable": "/synthetic/edge",
    }
    request.update(overrides)
    for key in [key for key, value in overrides.items() if value is _ABSENT]:
        del request[key]
    return request


def open_request(**overrides):
    # The separate Open action: no path, key, focus or coordinate at all.
    return folder_request(**{"chooser_action": {"chooser_open": True},
                             "extension_dir": _ABSENT, **overrides})


def decorated_request(title=NATIVE_TITLE, **overrides):
    # The same shape with a native (decorated) X title carried in all three
    # request title slots; the parser must refuse it.
    return folder_request(title=title, title_prefix=title, owner_title_prefix=title,
                          **overrides)


class FolderActionTests(unittest.TestCase):
    def test_exact_semantic_action_is_the_only_accepted_shape(self):
        self.assertEqual(native.EDGE_MANAGER_TITLE, "Extensions")
        self.assertEqual(native.CHOOSER_ACTIONS, {
            "navigate": {"chooser_navigate": True},
            "open": {"chooser_open": True},
        })
        parsed = native.parse_folder_action_request(folder_request())
        self.assertEqual(parsed, {"owner_title_prefix": "Extensions",
                                  "title": "Extensions",
                                  "title_prefix": "Extensions",
                                  "chooser_title_prefix": "Select the extension directory.",
                                  "user_data_dir": "/synthetic/profile-1",
                                  "executable": "/synthetic/edge",
                                  "caller_pid": None, "probe": False,
                                  "chooser": "navigate", "navigate_path": EXTENSION_DIR})
        self.assertEqual(set(parsed), set(native.OWNER_FIELDS) |
                         set(native.FOLDER_MANAGER_FIELDS) |
                         {"caller_pid", "probe", "chooser", "navigate_path"})
        opened = native.parse_folder_action_request(open_request())
        self.assertEqual(opened["chooser"], "open")
        self.assertIsNone(opened["navigate_path"])
        self.assertEqual(set(opened), set(parsed))

    def test_closed_request_shapes_are_exactly_two_actions(self):
        self.assertEqual(native.FOLDER_ACTION_KEYS, frozenset({
            "chooser_action", "chooser_title_prefix", "executable", "owner",
            "owner_pid", "owner_title_prefix", "title", "title_prefix",
            "user_data_dir",
        }))
        # navigate adds exactly the one package directory; open adds nothing.
        self.assertEqual(native.FOLDER_NAVIGATE_KEYS,
                         native.FOLDER_ACTION_KEYS | {"extension_dir"})
        self.assertEqual(native.FOLDER_OPEN_KEYS, native.FOLDER_ACTION_KEYS)
        self.assertEqual(
            set(folder_request()) - {"extension_dir", "chooser_action"},
            set(native.FOLDER_ACTION_KEYS) - {"chooser_action", "owner_pid"})
        self.assertEqual(set(folder_request()) - set(native.FOLDER_NAVIGATE_KEYS), set())
        self.assertEqual(set(open_request()) - set(native.FOLDER_OPEN_KEYS), set())
        for key in ("actions", "preserve_focus", "click", "point", "x", "y",
                    "width", "height", "label", "click_label", "wait_label",
                    "key", "text", "path", "owner_pid"):
            with self.subTest(key=key):
                self.assertNotIn(key, folder_request())
                self.assertNotIn(key, open_request())
        # owner_pid remains the one optional, exactly bound field.
        self.assertEqual(native.parse_folder_action_request(
            open_request(owner_pid=101))["caller_pid"], 101)

    def test_navigate_path_must_be_the_existing_absolute_ascii_path(self):
        self.assertEqual(native.parse_folder_action_request(
            folder_request())["navigate_path"], EXTENSION_DIR)
        cases = {
            "absent": folder_request(extension_dir=_ABSENT),
            "null": folder_request(extension_dir=None),
            "empty": folder_request(extension_dir=""),
            "relative": folder_request(extension_dir="package/chromium"),
            "root": folder_request(extension_dir="/"),
            "trailing slash": folder_request(extension_dir=EXTENSION_DIR + "/"),
            "newline": folder_request(extension_dir=EXTENSION_DIR + "\n"),
            "return": folder_request(extension_dir="/synthetic/a\rb"),
            "tab": folder_request(extension_dir="/synthetic/a\tb"),
            "non-ascii": folder_request(extension_dir="/synthetic/路径"),
            "nul": folder_request(extension_dir="/synthetic/a\u0000b"),
            "non-string": folder_request(extension_dir=1),
            "list": folder_request(extension_dir=[EXTENSION_DIR]),
        }
        for name, request in cases.items():
            with self.subTest(name):
                self.assertIsNone(native.parse_folder_action_request(request))
        # The Open action never carries a path, package directory included.
        for value in (EXTENSION_DIR, "", None):
            with self.subTest(value=value):
                self.assertIsNone(native.parse_folder_action_request(
                    {**open_request(), "extension_dir": value}))
        # The keyboard/path request keeps its own owner shape with the path in
        # its actions; it is never the navigate action.
        self.assertIsNone(native.parse_folder_action_request(input_request()))
        self.assertIsNone(native.parse_folder_action_request(
            input_request(chooser_navigate=True)))

    def test_manager_title_must_be_the_exact_observed_manager_title(self):
        # The exact observed title is the only accepted value, never a
        # prefix, a generic prefix, a case variant or an altered title.
        self.assertTrue(native.folder_manager_title_matches("Extensions"))
        for value in ("Ext", "Extension", "Extensions - Profile 1", "Extensions - "
                      "Profile 1 - Microsoft Edge", " extensions", "Extensions ",
                      "extensions", "EXTENSIONS", "Extensionss", "Extensions.",
                      "Edge Extensions", "", None, 1, True, ["Extensions"]):
            with self.subTest(value=value):
                self.assertFalse(native.folder_manager_title_matches(value))
        cases = {
            "generic owner prefix": folder_request(owner_title_prefix="Ext",
                                                   title_prefix="Ext", title="Ext"),
            "generic prefix only": folder_request(owner_title_prefix="Ext"),
            "absent title": folder_request(title=_ABSENT),
            "absent title prefix": folder_request(title_prefix=_ABSENT),
            "absent owner title prefix": folder_request(owner_title_prefix=_ABSENT),
            "null title": folder_request(title=None),
            "title mismatch": folder_request(title="Extensions - Profile 1",
                                             title_prefix="Extensions - Profile 1",
                                             owner_title_prefix="Extensions - Profile 1"),
            "title_prefix differs": folder_request(title_prefix="Extension"),
            "owner prefix is only a prefix": folder_request(owner_title_prefix="Extension"),
            "owner prefix longer": folder_request(owner_title_prefix="Extensions - Profile 1"),
            "title differs from prefix": folder_request(title="Extensions",
                                                        title_prefix="Extension"),
            "case altered": folder_request(title="extensions", title_prefix="extensions",
                                           owner_title_prefix="extensions"),
            "suffixed": folder_request(title="Extensions - Profile 1 - Microsoft Edge",
                                       title_prefix="Extensions - Profile 1 - Microsoft Edge",
                                       owner_title_prefix="Extensions - Profile 1 - Microsoft Edge"),
            "padded": folder_request(title=" Extensions", title_prefix=" Extensions",
                                     owner_title_prefix=" Extensions"),
            "non-ascii": folder_request(title="扩展", title_prefix="扩展",
                                        owner_title_prefix="扩展"),
            "non-string": folder_request(title=1, title_prefix=1, owner_title_prefix=1),
        }
        for name, request in cases.items():
            with self.subTest(name):
                self.assertIsNone(native.parse_folder_action_request(request))
        # The request parser never returns the generic-prefix shape.
        self.assertIsNone(native.parse_folder_action_request({**folder_request(),
                                                             "owner_title_prefix": "Ext"}))
        # A caller PID is optional but only well formed and never trusted alone.
        self.assertEqual(native.parse_folder_action_request(
            folder_request(owner_pid=101))["caller_pid"], 101)
        self.assertIsNone(native.derived_owner_pid(
            native.parse_folder_action_request(folder_request(owner_pid=101)), 202))
        self.assertEqual(native.derived_owner_pid(
            native.parse_folder_action_request(folder_request()), 101), 101)

    def test_native_manager_title_literals_are_exactly_verified(self):
        # Official Edge 157: exactly the two verified native manager X title
        # literals, the plain page title and the profile-prefixed form with
        # its U+200B exactly between "Microsoft" and " Edge".
        self.assertEqual(native.EDGE_MANAGER_NATIVE_TITLES,
                         ("Extensions", "Extensions - Profile 1 - Microsoft\u200b Edge"))
        self.assertEqual(native.EDGE_MANAGER_NATIVE_TITLES[1], NATIVE_TITLE)
        self.assertEqual(native.EDGE_MANAGER_TITLE, "Extensions")
        self.assertEqual(NATIVE_TITLE.index("\u200b"),
                         len("Extensions - Profile 1 - Microsoft"))
        self.assertEqual(NATIVE_TITLE[NATIVE_TITLE.index("\u200b") + 1], " ")
        self.assertEqual(NATIVE_TITLE.replace("\u200b", ""),
                         "Extensions - Profile 1 - Microsoft Edge")
        # The removed convenience helpers stay removed: only the exact
        # matcher remains for manager-window selection and re-proof.
        for name in ("is_native_manager_title", "is_manager_prefix",
                     "EDGE_MANAGER_WINDOW_TITLE"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(native, name))
        for value in native.EDGE_MANAGER_NATIVE_TITLES:
            with self.subTest(accepted=value):
                self.assertTrue(native.folder_manager_title_matches(value))

    def test_native_manager_title_near_misses_are_rejected(self):
        # No prefix/suffix match and no Unicode/whitespace/case normalization.
        near_misses = (
            "Extensions - Profile 1 - Microsoft Edge",
            "Extensions - Profile 1 - Microsoft Edge\u200b",
            "Extensions - Profile 1 - Microsoft \u200bEdge",
            "Extensions - Profile 1 - Microsoft\u200b\u200b Edge",
            "Extensions - Profile 1 - Microsoft\u200b\u200bEdge",
            "Extensions - Profile 1 -  Microsoft\u200b Edge",
            "Extensions - Profile 1 - Microsoft\u200b  Edge",
            "Extensions - Profile 1 - Microsoft\u200bEdge",
            "Extensions - Profile 1 - Microsoft\u200bEdge ",
            "Extensions - Profile 1 - Microsoft\u200b Edge ",
            " Extensions - Profile 1 - Microsoft\u200b Edge",
            "Extensions - Profile 0 - Microsoft\u200b Edge",
            "Extensions - Profile 2 - Microsoft\u200b Edge",
            "Extensions - Profile 01 - Microsoft\u200b Edge",
            "Extensions - Profile 1 - Microsoft\u200b edge",
            "Extensions - Profile 1 - microsoft\u200b Edge",
            "extensions - Profile 1 - Microsoft\u200b Edge",
            "Extensions - profile 1 - Microsoft\u200b Edge",
            "Extensions - Profile  1 - Microsoft\u200b Edge",
            "Extensions - Profile 1 - Microsoft\u00a0Edge",
            "Extensions - Profile 1 - Microsoft\u200c Edge",
            "Extensions - Profile 1 - Microsoft\u200b",
            "Extensions - Profile 1",
            "Extensions\n- Profile 1 - Microsoft\u200b Edge",
            NATIVE_TITLE + " - 1 tab",
            "x " + NATIVE_TITLE,
            NATIVE_TITLE[:-1],
            NATIVE_TITLE.lower(),
            "Ext",
            "Extension",
            "Extensionss",
            "\u200bExtensions",
            "",
            None,
            1,
            True,
            ["Extensions"],
        )
        for value in near_misses:
            with self.subTest(value=value):
                self.assertFalse(native.folder_manager_title_matches(value))

    def test_decorated_native_title_is_rejected_in_request_fields(self):
        # The install caller sends page.title() == "Extensions"; a decorated
        # native X11 title is a separate observation and never a request value,
        # in any one slot or in all three.
        self.assertIsNone(native.parse_folder_action_request(decorated_request()))
        for key in native.FOLDER_MANAGER_FIELDS + ("owner_title_prefix",):
            with self.subTest(key=key):
                self.assertIsNone(native.parse_folder_action_request(
                    folder_request(**{key: NATIVE_TITLE})))
        for value in ("Extensions - Profile 2 - Microsoft\u200b Edge",
                      "Extensions - Profile 1 - Microsoft\u200bEdge",
                      "Extensions - Profile 1 - Microsoft Edge",
                      NATIVE_TITLE + " - 1 tab", " " + NATIVE_TITLE):
            with self.subTest(value=value):
                self.assertIsNone(native.parse_folder_action_request(
                    decorated_request(value)))
        # Only the exact page title in every title slot is accepted.
        self.assertIsNotNone(native.parse_folder_action_request(folder_request()))

    def test_generic_coordinates_and_unknown_actions_are_rejected(self):
        # The removed select_folder behaviour is never accepted again: it hit
        # the chooser's Select folder filter, not the package-directory commit.
        for shape in ({"select_folder": True}, {"select_folder": False},
                      {"chooser_open": "true"}, {"chooser_navigate": 1}):
            with self.subTest(shape=shape):
                self.assertIsNone(native.parse_folder_action_request(
                    folder_request(chooser_action=shape)))
                self.assertIsNone(native.parse_folder_action_request(
                    open_request(chooser_action=shape)))
        for request in (folder_request(), open_request()):
            with self.subTest(action=request["chooser_action"]):
                request = dict(request)
                request["chooser_action"] = {**request["chooser_action"], "select_folder": True}
                self.assertIsNone(native.parse_folder_action_request(request))
        cases = {
            "open false": open_request(chooser_action={"chooser_open": False}),
            "navigate false": folder_request(chooser_action={"chooser_navigate": False}),
            "open null": open_request(chooser_action={"chooser_open": None}),
            "navigate null": folder_request(chooser_action={"chooser_navigate": None}),
            "open absent value": open_request(chooser_action={}),
            "both actions": folder_request(chooser_action={"chooser_navigate": True,
                                                           "chooser_open": True}),
            "open extra action key": open_request(
                chooser_action={"chooser_open": True, "click": [1076, 799]}),
            "navigate extra action key": folder_request(
                chooser_action={"chooser_navigate": True, "click": [1076, 799]}),
            "open action true": open_request(chooser_action=True),
            "open action list": open_request(chooser_action=[{"chooser_open": True}]),
            "open action null": open_request(chooser_action=None),
            "unknown key": folder_request(chooser_action={"select_directory": True}),
            "actions": folder_request(actions=[{"click": [1076, 799]}]),
            "keyboard actions": open_request(actions=[{"key": "Return"}]),
            "empty actions": open_request(actions=[]),
            "click field": open_request(click=[1076, 799]),
            "point field": open_request(point={"x": 1076, "y": 799}),
            "label field": open_request(label="Open"),
            "click_label": open_request(click_label="Open"),
            "wait_label": open_request(wait_label="Open"),
            "screen point": open_request(x=1158, y=832),
            "local point": open_request(x=1076, y=799),
            "screen origin": open_request(x=82, y=33),
            "geometry": open_request(width=1124, height=822),
            "window": open_request(window=20),
            "target": open_request(target=20),
            "title override": folder_request(title="Other"),
            "title prefix": folder_request(title_prefix="Ext"),
            "focus": folder_request(preserve_focus=True),
            "probe": folder_request(ownership_probe=True),
            "owner false": folder_request(owner=False),
            "owner absent": folder_request(owner=_ABSENT),
            "nearby title": folder_request(chooser_title_prefix="Select the extension directory"),
            "title suffix": folder_request(chooser_title_prefix="Select the extension directory.x"),
            "title case": folder_request(chooser_title_prefix="select the extension directory."),
            "other title": folder_request(chooser_title_prefix="Select a folder"),
            "missing owner prefix": folder_request(owner_title_prefix=_ABSENT),
            "generic manager prefix": folder_request(title="Ext", title_prefix="Ext",
                                                     owner_title_prefix="Ext"),
            "relative profile": folder_request(user_data_dir="relative/profile"),
            "profile trailing slash": folder_request(user_data_dir="/synthetic/profile-1/"),
            "relative executable": folder_request(executable="edge"),
            "pid string": folder_request(owner_pid="101"),
            "pid bool": folder_request(owner_pid=True),
            "pid root": folder_request(owner_pid=1),
            "pid over limit": folder_request(owner_pid=native.PID_LIMIT + 1),
        }
        for name, request in cases.items():
            with self.subTest(name):
                self.assertIsNone(native.parse_folder_action_request(request))
        for value in (None, [], "x", True):
            with self.subTest(value=value):
                self.assertIsNone(native.parse_folder_action_request(value))
        # Neither chooser action ever routes through the generic owner input
        # parser, and the zero-action probe keeps its own closed shape.
        for request in (folder_request(), open_request(),
                        folder_request(actions=[{"key": "Return"}], preserve_focus=False),
                        open_request(preserve_focus=False),
                        open_request(click=[1076, 799])):
            with self.subTest(request=sorted(request)):
                self.assertIsNone(native.parse_owner_request(request))
                self.assertIsNone(native.parse_owner_request(
                    {**probe_request(), **request}))
        # The generic popup-preserving input mode is not weakened: it still
        # needs preserve_focus true and never gains a chooser action.
        for fields in ({"preserve_focus": False}, {"preserve_focus": _ABSENT},
                       {"preserve_focus": None}, {"preserve_focus": 1}):
            with self.subTest(fields=fields):
                self.assertIsNone(native.parse_owner_request(owner_request(**fields)))
        self.assertIsNotNone(native.parse_owner_request(owner_request()))
        self.assertIsNotNone(native.parse_owner_request(input_request()))

    def test_only_the_measured_open_point_is_derived(self):
        self.assertEqual(native.FOLDER_CHOOSER_SIZE, (1124, 822))
        self.assertEqual(native.FOLDER_CHOOSER_ORIGIN, (82, 33))
        self.assertEqual(native.FOLDER_OPEN_LOCAL, (1076, 799))
        self.assertEqual(native.FOLDER_POINT_OFFSETS, (("width", -48), ("height", -23)))
        width, height = native.FOLDER_CHOOSER_SIZE
        self.assertEqual(native.folder_point(1124, 822), (width - 48, height - 23))
        self.assertEqual((width - 48, height - 23), native.FOLDER_OPEN_LOCAL)
        self.assertTrue(0 < 1076 < width and 0 < 799 < height)
        # The measured screen center of the visible Open button.
        origin = native.FOLDER_CHOOSER_ORIGIN
        self.assertEqual((origin[0] + 1076, origin[1] + 799), (1158, 832))
        # The old width-62,height-69 point hit the Select folder filter.
        self.assertNotEqual(native.folder_point(1124, 822), (1062, 753))
        for shape in ((1123, 822), (1124, 821), (1125, 822), (1124, 823), (1124, 824),
                      (1120, 822), (1062, 753), (0, 0), (-1124, -822), (2248, 1644),
                      (1076, 799), (1124 - 48, 822 - 24), (1124 - 49, 822 - 23)):
            with self.subTest(size=shape):
                self.assertIsNone(native.folder_point(*shape))
        for shape in ((1124, 822.0), ("1124", 822), (True, 822), (None, 822), (822, 1124)):
            with self.subTest(size=shape):
                self.assertIsNone(native.folder_point(*shape))

    def test_geometry_requires_a_mapped_non_override_window(self):
        mapped = types.SimpleNamespace(width=1124, height=822, map_state=2, override_redirect=0)
        self.assertEqual(native.chooser_geometry(mapped), (1124, 822))
        for change in ({"map_state": 0}, {"map_state": 1}, {"override_redirect": 1},
                       {"width": 0}, {"height": -822}, {"width": None}, {"height": "822"}):
            with self.subTest(change=change):
                self.assertIsNone(native.chooser_geometry(
                    types.SimpleNamespace(**{**vars(mapped), **change})))
        self.assertIsNone(native.chooser_geometry(None))
        # A mapped window of any other size is not a measured chooser: the
        # point helper, not this reader, rejects it before any click.
        for shape in ((1125, 822), (1124, 821), (1123, 823)):
            with self.subTest(shape=shape):
                self.assertIsNotNone(native.chooser_geometry(
                    types.SimpleNamespace(width=shape[0], height=shape[1],
                                          map_state=2, override_redirect=0)))
                self.assertIsNone(native.folder_point(*shape))

    def test_output_is_fixed_and_privacy_safe(self):
        self.assertEqual(native.folder_output("open", 1),
                         {"chooser_action": "chooser_open", "clicks": 1})
        self.assertEqual(native.folder_output("navigate", 0),
                         {"chooser_action": "chooser_navigate", "clicks": 0})
        # Only Open clicks; navigate never claims a click and nothing claims an
        # installation, window, path or coordinate.
        for action, clicks in (("open", 0), ("open", 2), ("navigate", 1),
                               ("navigate", 2), ("select_folder", 1), ("", 0),
                               (None, 0), (True, 1), ("open", True),
                               ("open", None), ("navigate", -1)):
            with self.subTest(action=action, clicks=clicks):
                self.assertIsNone(native.folder_output(action, clicks))
        for output in (native.folder_output("open", 1),
                       native.folder_output("navigate", 0)):
            self.assertEqual(set(output), {"chooser_action", "clicks"})
        for message in ("Chooser action request required",
                        "Chooser focus failed",
                        "Chooser shortcut unavailable",
                        "Chooser navigation path required",
                        "Chooser folder point is not inside the chooser",
                        "Chooser must keep the requested title",
                        "Chooser must keep the measured geometry",
                        "Chooser folder point is not inside the chooser",
                        "Chooser folder pointer is not at the measured point",
                        "Chooser folder pointer is not over the owned chooser",
                        "Chooser folder input failed"):
            self.assertRegex(native.FAILURE_REASONS[message], r"^[a-z-]+$")


class ChooserDispatchTests(unittest.TestCase):
    def test_chooser_actions_select_the_folder_parser(self):
        # Both closed Edge chooser requests carry owner: true, which the
        # generic owner parser deliberately rejects; dispatch must still
        # select the folder parser and produce its exact attribution record.
        for request, mode, path in ((folder_request(), "navigate", EXTENSION_DIR),
                                    (open_request(), "open", None)):
            with self.subTest(mode=mode):
                self.assertIs(request.get("owner"), True)
                self.assertIsNone(native.parse_owner_request(request))
                folder_mode, owner, error = native.dispatch_owner_request(request)
                self.assertIs(folder_mode, True)
                self.assertIsNone(error)
                self.assertEqual(owner, native.parse_folder_action_request(request))
                self.assertEqual(owner["chooser"], mode)
                self.assertEqual(owner["navigate_path"], path)
                self.assertIs(owner["probe"], False)

    def test_ordinary_owner_and_probe_select_the_generic_parser(self):
        for request in (owner_request(), input_request(), probe_request(),
                        {**owner_request(), "actions": [{"key": "Return"}]}):
            with self.subTest(request=sorted(request)):
                folder_mode, owner, error = native.dispatch_owner_request(request)
                self.assertIs(folder_mode, False)
                self.assertIsNone(error)
                self.assertEqual(owner, native.parse_owner_request(request))
                self.assertIsNotNone(owner)
                self.assertFalse("chooser" in owner)
        self.assertIs(native.dispatch_owner_request(probe_request())[1]["probe"], True)
        self.assertIs(native.dispatch_owner_request(probe_request())[0], False)

    def test_requests_without_an_owner_shape_select_no_owner(self):
        for request in ({"title": "x"}, {"actions": [{"key": "Return"}]}, {},
                        [], None, "x", True):
            with self.subTest(request=request):
                self.assertEqual(native.dispatch_owner_request(request),
                                 (False, None, None))

    def test_invalid_chooser_shapes_stay_fail_closed(self):
        # Every shape that fails the folder parser keeps the dedicated
        # chooser-action rejection and never falls back to the owner parser.
        cases = {
            "open false": open_request(chooser_action={"chooser_open": False}),
            "navigate false": folder_request(chooser_action={"chooser_navigate": False}),
            "both actions": folder_request(chooser_action={"chooser_navigate": True,
                                                          "chooser_open": True}),
            "unknown key": folder_request(chooser_action={"select_directory": True}),
            "action true": open_request(chooser_action=True),
            "action list": open_request(chooser_action=[{"chooser_open": True}]),
            "action null": open_request(chooser_action=None),
            "empty action": open_request(chooser_action={}),
            "owner false": folder_request(owner=False),
            "owner absent": folder_request(owner=_ABSENT),
            "probe": folder_request(ownership_probe=True),
            "click field": open_request(click=[1076, 799]),
            "actions": open_request(actions=[{"key": "Return"}]),
            "preserve focus": open_request(preserve_focus=True),
            "decorated title": decorated_request(),
            "relative path": folder_request(extension_dir="package/chromium"),
            "missing path": open_request(extension_dir="/synthetic/p"),
            "pid mismatch shape": folder_request(owner_pid="101"),
        }
        for name, request in cases.items():
            with self.subTest(name):
                self.assertIsNone(native.parse_folder_action_request(request))
                self.assertEqual(native.dispatch_owner_request(request),
                                 (True, None, "Chooser action request required"))
                self.assertEqual(native.failure_reason(
                    RuntimeError(native.dispatch_owner_request(request)[2])),
                    "chooser-action-request")
        # The generic parser's own rejection keeps its distinct class.
        for request in (owner_request(preserve_focus=False),
                        owner_request(actions=[]), probe_request(owner_pid=101)):
            with self.subTest(request=sorted(request)):
                self.assertIsNone(native.parse_owner_request(request))
                self.assertEqual(native.dispatch_owner_request(request),
                                 (False, None, "Chooser ownership request required"))


class ChooserOwnerChainTests(unittest.TestCase):
    def test_owner_chain_requires_unique_linked_terminal(self):
        owner = (11, 101, True)
        # The unique owner window itself is the normal transient terminal.
        self.assertTrue(native.window_chain_ok(owner, [11], [11]))
        self.assertTrue(native.window_chain_ok(owner, [11], [12]))
        self.assertFalse(native.window_chain_ok(owner, [11], [0]))
        self.assertFalse(native.window_chain_ok(owner, [11], [11, 11]))
        for bad in ((owner, [11, 12], [11]), (owner, [12], [11]), ((11, 0, True), [11], [11]),
                    ((11, 101, False), [11], [11]), ((11, 101, True), [], [11]),
                    (owner, [11], []), (owner, [11], [11, 11]), (owner, [11], [12, 13]),
                    (None, [11], [11])):
            with self.subTest(bad=bad):
                self.assertFalse(native.window_chain_ok(*bad))


class ChooserXlibTests(unittest.TestCase):
    def test_children_come_from_loaded_xlib_functions(self):
        calls = []

        array = (ctypes.c_ulong * 2)(21, 22)

        class Lib:
            def XQueryTree(self, display, parent, root_out, parent_out, result_out, count_out):
                calls.append((display, parent))
                # ctypes gives a plain python callable fresh CArgObject
                # wrappers; the scratch array is written through its address.
                ctypes.cast(result_out, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(array)
                count_out._obj.value = 2
                return 1

            def XFree(self, pointer):
                calls.append("free")

        self.assertEqual(native.query_children(Lib(), "display", 5), [21, 22])
        self.assertEqual(calls, [("display", 5), "free"])

    def test_refused_tree_query_fails_closed(self):
        class Lib:
            def XQueryTree(self, *args):
                return 0

        with self.assertRaisesRegex(RuntimeError, "X window query refused"):
            native.query_children(Lib(), "display", 5)
        with self.assertRaises(RuntimeError):
            native.query_children(Lib(), "display", 0)

    def test_viewable_tree_walk_is_total_and_bounded(self):
        # The real tree: root -> 10 (parent) -> 20 (chooser) -> 21, with an
        # unrelated root child 30 and an override-redirect overlay 31 that is
        # still visited but never reported as a normal viewable window.
        tree = {1: [10, 30, 31], 10: [20], 20: [21], 30: [], 31: [], 21: []}
        normal = {20, 30, 21}
        queries = []

        def children(parent):
            queries.append(parent)
            return list(tree[parent])

        viewable = lambda candidate: candidate in normal
        self.assertEqual(native.bounded_viewable_tree(children, viewable, 1), [30, 20, 21])
        self.assertEqual(sorted(queries), [1, 10, 20, 21, 30, 31])
        self.assertEqual((native.VIEWABLE_TREE_VISITS, native.VIEWABLE_TREE_DEPTH),
                         (1024, 12))
        # The total visited-window budget counts every window strictly below
        # the root, not only the matches, and one window over it refuses.
        wide = {1: list(range(10, 15))}
        wide.update({index: [index + 10] for index in range(10, 15)})
        wide.update({index: [] for index in range(20, 25)})
        walk = lambda budget: native.bounded_viewable_tree(
            lambda parent: list(wide[parent]), lambda _c: True, 1,
            budget=budget, depth=native.VIEWABLE_TREE_DEPTH)
        # The walk is deterministic: root children are queried deepest first.
        self.assertEqual(walk(11), [10, 11, 12, 13, 14, 24, 23, 22, 21, 20])
        for budget in (10, 9, 5, 1):
            with self.subTest(budget=budget):
                self.assertIsNone(walk(budget))
        # The depth bound counts levels below the root; a window at the
        # limit level is accepted and one level deeper fails closed. This
        # chain stays inside the default budget, so only depth decides.
        chain = {1: [10], 10: [11], 11: [12], 12: [13], 13: []}
        deep = lambda depth: native.bounded_viewable_tree(
            lambda parent: list(chain[parent]), lambda _c: True, 1, depth=depth)
        # 13 is not a leaf, so its children must still be queried to prove
        # the tree; depth 3 refuses that query and depth 4 accepts the tree.
        self.assertIsNone(deep(3))
        self.assertEqual(deep(4), [10, 11, 12, 13])
        tail = {1: [10], 10: [11], 11: [12], 12: []}
        self.assertEqual(native.bounded_viewable_tree(
            lambda parent: list(tail[parent]), lambda _c: True, 1, depth=3),
            [10, 11, 12])
        self.assertIsNone(native.bounded_viewable_tree(
            lambda parent: list(tail[parent]), lambda _c: True, 1, depth=2))
        for depth in (2, 1, 0, -1):
            with self.subTest(depth=depth):
                self.assertIsNone(deep(depth))
        # A refused child query, a malformed answer, a repeated window (a
        # cycle) or a root reached again fails closed instead of looping.
        refusing = Mock(side_effect=RuntimeError("X window query refused"))
        self.assertIsNone(native.bounded_viewable_tree(refusing, viewable, 1))
        for bad in (None, "x", [None], [0], [-1], [True], [10, 10], [1]):
            with self.subTest(bad=bad):
                lib = Mock(return_value=bad)
                self.assertIsNone(native.bounded_viewable_tree(lib, viewable, 1))
        self.assertEqual(len(lib.mock_calls), 1)
        cycle = native.bounded_viewable_tree(
            lambda parent: [10] if parent == 1 else [1], lambda _c: True, 1)
        self.assertIsNone(cycle)
        raising = Mock(side_effect=RuntimeError("attributes failed"))
        self.assertIsNone(native.bounded_viewable_tree(children, raising, 1))
        # A caller-supplied viewable failure on a deeper window also refuses.
        self.assertIsNone(native.bounded_viewable_tree(
            children, raising, 1, budget=8, depth=8))
        for value in (0, -1, None, True, "1"):
            with self.subTest(root=value):
                self.assertIsNone(native.bounded_viewable_tree(children, viewable, value))
        for budget, depth in ((0, 12), (-1, 12), (1024, 0), (1024, -1), (1024.0, 12)):
            with self.subTest(budget=budget, depth=depth):
                self.assertIsNone(native.bounded_viewable_tree(
                    children, viewable, 1, budget=budget, depth=depth))
        # Failures are a plain None: no window id, count or message leaks.
        self.assertIs(type(native.bounded_viewable_tree(refusing, viewable, 1)), type(None))

    def property_lib(self, values, status=0, actual=7, fmt=32, remaining=0):
        kept = []
        class Lib:
            def XInternAtom(self, display, name, only_if_exists):
                return 7

            def XGetWindowProperty(self, display, window, atom, offset, length,
                                   delete, request, actual_out, format_out,
                                   count_out, remaining_out, data_out):
                array = (ctypes.c_ulong * max(1, len(values)))(*values)
                if status == 0 and values:
                    kept.append(array)
                    data_out._obj.value = ctypes.addressof(array)
                actual_out._obj.value = actual
                format_out._obj.value = fmt
                count_out._obj.value = len(values)
                remaining_out._obj.value = remaining
                return status

            def XFree(self, pointer):
                return None

        return Lib()

    def test_transient_parents_are_distinct_and_well_formed(self):
        lib = self.property_lib([31, 31])
        self.assertEqual(native.distinct_transients(lib, "display", 5), [31])
        self.assertEqual(native.distinct_transients(self.property_lib([31, 32]), "d", 5), [31, 32])
        for lib in (self.property_lib([], status=0),
                    self.property_lib([31], status=1),
                    self.property_lib([31], fmt=8),
                    self.property_lib([31], remaining=1),
                    # FORMAT 32 is not enough: the actual type must be WINDOW.
                    self.property_lib([31], actual=8)):
            with self.subTest(lib=lib):
                self.assertIsNone(native.distinct_transients(lib, "display", 5))

    def typed_property_lib(self, name_atom, type_atom, actual_type, values, calls=None):
        kept = []

        class Lib:
            def XInternAtom(self, display, name, only_if_exists):
                if calls is not None:
                    calls.append(name)
                return type_atom if name in (b"WINDOW", b"CARDINAL") else name_atom

            def XGetWindowProperty(self, display, window, atom, offset, length,
                                   delete, request, actual_out, format_out,
                                   count_out, remaining_out, data_out):
                array = (ctypes.c_ulong * max(1, len(values)))(*values)
                if values:
                    kept.append(array)
                    data_out._obj.value = ctypes.addressof(array)
                actual_out._obj.value = actual_type
                format_out._obj.value = 32
                count_out._obj.value = len(values)
                remaining_out._obj.value = 0
                return 0

            def XFree(self, pointer):
                return None

        return Lib()

    def test_property_actual_type_is_window_or_cardinal(self):
        self.assertEqual(native.PROPERTY_TYPES, {
            "WM_TRANSIENT_FOR": "WINDOW",
            "WM_CLIENT_LEADER": "WINDOW",
            "_NET_WM_PID": "CARDINAL",
        })
        for name in ("WM_TRANSIENT_FOR", "WM_CLIENT_LEADER"):
            with self.subTest(name=name):
                ok = self.typed_property_lib(70, 33, 33, [11])
                self.assertEqual(native.property_record(ok, "display", 5, name),
                                 {"status": "ok", "values": [11]})
                # A 32-bit CARDINAL is not a WINDOW id.
                wrong = self.typed_property_lib(70, 33, 6, [11])
                self.assertEqual(native.property_record(wrong, "display", 5, name),
                                 {"status": "malformed"})
        ok = self.typed_property_lib(71, 6, 6, [101])
        self.assertEqual(native.property_record(ok, "display", 5, "_NET_WM_PID"),
                         {"status": "ok", "values": [101]})
        # A WINDOW id is not a CARDINAL process id.
        wrong = self.typed_property_lib(71, 6, 33, [101])
        self.assertEqual(native.property_record(wrong, "display", 5, "_NET_WM_PID"),
                         {"status": "malformed"})
        calls = []
        unknown = self.typed_property_lib(70, 33, 33, [11], calls)
        self.assertEqual(native.property_record(unknown, "display", 5, "TITLE"),
                         {"status": "malformed"})
        self.assertEqual(calls, [])

    def test_x_property_rejects_a_mismatched_actual_type(self):
        lib = self.property_lib([31], actual=7)
        self.assertEqual(native.x_property(lib, "d", 5, 7, 7), ("ok", [31]))
        self.assertEqual(native.x_property(lib, "d", 5, 7, 8), ("malformed", []))
        self.assertEqual(native.x_property(lib, "d", 5, 0, 7), ("malformed", []))

    def test_fake_xlib_records_do_not_leak_raw_values(self):
        lib = self.typed_property_lib(71, 6, 6, [101])
        record = native.property_record(lib, "display", 5, "_NET_WM_PID")
        self.assertEqual(set(record), {"status", "values"})
        self.assertEqual(
            native.probe_output({"owned": True, "relation": "process-parent",
                                 "values": [101], "title": "t", "pid": 101}),
            {"ownership": {"owned": True, "relation": "process-parent"}})


ROOT = 1


def tree_parents(parent):
    """A real XQueryTree parent_of over edges; an unknown window is refused."""
    def parent_of(child):
        if type(child) is not int or child not in parent:
            raise RuntimeError("X window query refused")
        return parent[child]
    return parent_of


# The real hierarchy: root -> 10 -> 20 (chooser 1124x822, placed at 100,200)
# -> 21 (frame) -> 22 (button); 30 is an unrelated overlay with a child 31.
OWNED_PARENT = {10: ROOT, 20: 10, 21: 20, 22: 21, 30: ROOT, 31: 30}
OWNED_TREE = {**OWNED_PARENT, ROOT: ROOT}
CHOOSER, FRAME, BUTTON, OUTER, OVERLAY, OVERLAY_CHILD = 20, 21, 22, 10, 30, 31
GEOMETRY = (1124, 822)
POINT = (1076, 799)
ORIGIN = (100, 200)
EXPECTED_ROOT = (ORIGIN[0] + POINT[0], ORIGIN[1] + POINT[1])


class PointerIO:
    """A real XTest/XQueryPointer stand-in; records only that it was called."""
    def __init__(self, qchild, state=None, motion=1, query_error=False):
        self.qchild = qchild
        self.state = state
        self.motion_result = motion
        self.query_error = query_error
        self.calls = []

    def motion(self, root_x, root_y):
        self.calls.append(("motion", root_x, root_y))
        return self.motion_result

    def flush(self):
        self.calls.append("flush")

    def sync(self):
        self.calls.append("sync")

    def queried(self):
        self.calls.append("query")
        if self.query_error:
            raise RuntimeError("Chooser folder pointer is not at the measured point")
        # A real XQueryPointer(root) result: root_x/root_y and win_x/win_y
        # are both root-relative, so the win slot is the root point too.
        state = self.state or root_query(self.qchild)
        return state


def root_query(qchild, point=EXPECTED_ROOT, window_point=None, mask=0, qroot=ROOT):
    """One real XQueryPointer(display, root, ...) tuple.

    The query window is the root, so qroot is the root, qchild is the root's
    child under the pointer and both the win and the root coordinates are
    relative to the root.
    """
    if window_point is None:
        window_point = point
    return (qroot, qchild, point[0], point[1], window_point[0], window_point[1], mask)


class PointerContainmentTests(unittest.TestCase):
    def setUp(self):
        self.parent_of = tree_parents(OWNED_TREE)
        self.chain = native.window_ancestry(self.parent_of, CHOOSER, ROOT)
        self.assertEqual(self.chain, [20, 10, ROOT])
        self.assertEqual(native.folder_point(*GEOMETRY), POINT)

    def judgement(self, io_parent=OWNED_TREE, state=None, geometry=GEOMETRY,
                  chain=None, qchild=CHOOSER, root_point=EXPECTED_ROOT, window_point=None,
                  qroot=ROOT, mask=0):
        parent_of = tree_parents(io_parent)
        if chain is None:
            chain = native.window_ancestry(parent_of, CHOOSER, ROOT)
        if state is None:
            state = root_query(qchild, root_point, window_point, mask, qroot)
        return native.pointer_containment(parent_of, ROOT, state, chain, ORIGIN, geometry)

    def test_true_owned_ancestry_children_are_accepted(self):
        # XQueryPointer(root) reports the root's direct child containing the
        # pointer. With an intermediate parent (10) that is only 10; the
        # chooser (20) and its own descendants (21, 22) are deeper windows
        # that a root query can never report.
        self.assertIs(self.judgement(qchild=OUTER), True)
        for qchild in (CHOOSER, FRAME, BUTTON):
            with self.subTest(qchild=qchild):
                self.assertIs(self.judgement(qchild=qchild), False)
        # Target at the root: the chooser's parent is the root, so chain[-2]
        # is the chooser itself and that exact qchild is accepted.
        direct = {CHOOSER: ROOT, FRAME: CHOOSER, ROOT: ROOT}
        self.assertIs(self.judgement(io_parent=direct, qchild=CHOOSER), True)
        # The chooser's frame under a direct chooser is still deeper than the
        # root child and is never accepted for the root query.
        self.assertIs(self.judgement(io_parent=direct, qchild=FRAME), False)

    def test_real_trees_accept_only_the_root_child_on_the_chooser_chain(self):
        # root -> 10 (parent) -> 20 (chooser): only the intermediate root
        # child 10 is the qchild of a root query.
        intermediate = {OUTER: ROOT, CHOOSER: OUTER, ROOT: ROOT}
        self.assertIs(self.judgement(io_parent=intermediate, qchild=OUTER), True)
        for qchild in (CHOOSER, ROOT, 0):
            with self.subTest(tree="intermediate", qchild=qchild):
                self.assertIs(self.judgement(io_parent=intermediate, qchild=qchild), False)
        # root -> 20 (chooser): the chooser is its own direct root child.
        direct = {CHOOSER: ROOT, ROOT: ROOT}
        self.assertIs(self.judgement(io_parent=direct, qchild=CHOOSER), True)
        # root -> 10 -> 20 -> 21: qchild 21 is a deeper chooser XID and is
        # refused even though it sits inside the verified chooser's tree.
        deeper = {FRAME: OUTER, CHOOSER: FRAME, OUTER: ROOT, ROOT: ROOT}
        self.assertIs(self.judgement(io_parent=deeper, qchild=OUTER), True)
        for qchild in (FRAME, CHOOSER):
            with self.subTest(tree="deeper", qchild=qchild):
                self.assertIs(self.judgement(io_parent=deeper, qchild=qchild), False)
        # There is no chain form where the chooser still has a parent yet is
        # accepted as qchild: the same real tree refuses it every time.
        self.assertIs(self.judgement(io_parent=OWNED_TREE, qchild=CHOOSER), False)
        self.assertIs(self.judgement(io_parent=OWNED_TREE, qchild=OUTER), True)

    def test_false_overlay_on_another_root_child_is_refused(self):
        # A viewable overlay is another root child: it would take the press.
        # The chooser's own descendants cannot be a root query's qchild.
        for qchild in (OVERLAY, OVERLAY_CHILD, FRAME, BUTTON, 99, ROOT, 0):
            with self.subTest(qchild=qchild):
                self.assertIs(self.judgement(qchild=qchild), False)
        # The pointer query root is not the display root (inside a query).
        self.assertIs(self.judgement(qroot=OVERLAY), False)
        # The chooser re-parented under the overlay (30) by the live tree
        # while the proven chain still points through 10: the two disagree,
        # so the stale chain and the actual tree are both refused, whether the
        # qchild is the stale root child or the overlay itself.
        other = dict(OWNED_PARENT)
        other[CHOOSER] = OVERLAY
        other[OVERLAY] = ROOT
        for qchild in (CHOOSER, OUTER):
            with self.subTest(qchild=qchild):
                self.assertIs(self.judgement(io_parent=other, qchild=qchild,
                                             chain=self.chain), False)
        # A decoy overlay inside the chooser's parent chain is not accepted
        # as the chooser's own descendant.
        decoy = dict(OWNED_PARENT)
        decoy[OVERLAY] = OUTER
        self.assertIs(self.judgement(io_parent=decoy, qchild=OVERLAY,
                                     chain=self.chain), False)

    def test_false_pointer_coordinates_are_refused(self):
        # Both root slots must be the chooser origin plus the derived point.
        for dx, dy in ((1, 0), (0, 1), (-1, 0), (0, -1), (62, 69), (-1062, -753)):
            point = (EXPECTED_ROOT[0] + dx, EXPECTED_ROOT[1] + dy)
            # Root-coordinate ints are never negative: a drifting probe there
            # is malformed anyway.
            if point[0] < 0 or point[1] < 0:
                continue
            with self.subTest(dx=dx, dy=dy):
                self.assertIs(self.judgement(root_point=point), False)
                self.assertIs(self.judgement(window_point=point), False)
        # With an intermediate parent the root query reports that parent (10)
        # only, even when the pointer point itself is exactly correct.
        parent_of = tree_parents(OWNED_TREE)
        chain = native.window_ancestry(parent_of, CHOOSER, ROOT)
        self.assertIs(native.pointer_containment(
            parent_of, ROOT, root_query(CHOOSER, EXPECTED_ROOT), chain, ORIGIN,
            GEOMETRY), False)
        # A chooser at the root origin needs the derived point in both slots.
        with self.subTest(origin=(0, 0)):
            direct = tree_parents({CHOOSER: ROOT, ROOT: ROOT})
            chain = native.window_ancestry(direct, CHOOSER, ROOT)
            self.assertIs(native.pointer_containment(
                direct, ROOT, root_query(CHOOSER, POINT), chain, (0, 0), GEOMETRY), True)
            self.assertIs(native.pointer_containment(
                direct, ROOT, root_query(CHOOSER, EXPECTED_ROOT), chain, (0, 0),
                GEOMETRY), False)
        # The old syntheses are refused: chooser-local win coordinates
        # (the measured point itself) and root coordinates in a chooser-local
        # slot cannot both come from one XQueryPointer(root).
        for window_point in (POINT, (POINT[0] + 1, POINT[1]), (POINT[0], POINT[1] + 1),
                             (ORIGIN[0], ORIGIN[1]), (0, 0)):
            with self.subTest(window_point=window_point):
                self.assertIs(self.judgement(window_point=window_point), False)
        # A held button or modifier before the press (Button1Mask=0x100,
        # ShiftMask=0x1, ControlMask=0x4) refuses.
        for mask in (0x100, 0x1, 0x4, 0x8, 0x2000):
            with self.subTest(mask=mask):
                self.assertIs(self.judgement(mask=mask), False)
        # The query must be for the display root itself.
        for qroot in (0, CHOOSER, OUTER, OVERLAY, ROOT + 1):
            with self.subTest(qroot=qroot):
                self.assertIs(self.judgement(qroot=qroot), False)
        # The point is derived from the geometry: only the exact measured
        # 1124x822 chooser is accepted, never a caller-supplied point.
        for geometry in ((1123, 822), (1124, 821), (822, 1124), (0, 0), None, (1124,)):
            with self.subTest(geometry=geometry):
                self.assertIs(self.judgement(geometry=geometry), False)

    def test_false_other_tree_and_ambiguous_paths_are_refused(self):
        # The pointer's qchild sits on a different tree: never on our path.
        other = tree_parents({20: 10, 10: ROOT, 30: ROOT, 31: 30, ROOT: ROOT})
        self.assertIs(native.pointer_containment(
            other, ROOT, root_query(31),
            native.window_ancestry(other, 20, ROOT), ORIGIN, GEOMETRY), False)
        # An ambiguous chain (never reaching the root) has no ancestry.
        self.assertIsNone(native.window_ancestry(
            tree_parents({20: 10, 10: 11, 11: 12, 12: 11}), 20, ROOT))
        # A cycle is ambiguous, not an owned descendant.
        self.assertIsNone(native.window_ancestry(tree_parents({20: 21, 21: 20}), 20, ROOT))
        # A self-parent never reaches the root and refuses before querying root.
        self.assertIsNone(native.window_ancestry(lambda _c: 20, 20, ROOT))
        # Stale or guessed chains that do not match the actual tree refuse.
        for chain in ([20, ROOT], [20, OVERLAY, ROOT], [OVERLAY, ROOT], [20, 10],
                      [0, ROOT], []):
            with self.subTest(chain=chain):
                self.assertIs(self.judgement(chain=chain), False)
        # A window with no known parent is off the path, not a descendant.
        self.assertIs(self.judgement(qchild=99), False)
        # qchild 10 is on the verified chain, but the live tree re-parented
        # the chooser under 40 by the time of the proof: the chain is stale,
        # so the matching qchild alone must not authorize the press.
        moved = dict(OWNED_PARENT)
        moved[CHOOSER] = 40
        moved[40] = ROOT
        self.assertIs(self.judgement(io_parent=moved, qchild=OUTER,
                                     chain=self.chain), False)

    def test_false_query_failure_is_refused(self):
        state = root_query(CHOOSER)

        def raising(_child):
            raise RuntimeError("X window query refused")

        self.assertIsNone(native.window_ancestry(lambda _c: None, CHOOSER, ROOT))
        self.assertIs(native.pointer_containment(
            lambda _c: None, ROOT, state, [CHOOSER, OUTER, ROOT], ORIGIN, GEOMETRY),
            False)
        self.assertIs(native.pointer_containment(
            raising, ROOT, state, [CHOOSER, OUTER, ROOT], ORIGIN, GEOMETRY), False)
        for value in (None, [], (ROOT, CHOOSER, EXPECTED_ROOT[0], EXPECTED_ROOT[1],
                                 EXPECTED_ROOT[0], EXPECTED_ROOT[1]),
                      (ROOT, CHOOSER, str(EXPECTED_ROOT[0]), EXPECTED_ROOT[1],
                       EXPECTED_ROOT[0], EXPECTED_ROOT[1], 0),
                      (ROOT, CHOOSER, EXPECTED_ROOT[0], EXPECTED_ROOT[1],
                       EXPECTED_ROOT[0], EXPECTED_ROOT[1], None),
                      (ROOT, "20", EXPECTED_ROOT[0], EXPECTED_ROOT[1],
                       EXPECTED_ROOT[0], EXPECTED_ROOT[1], 0),
                      (ROOT, CHOOSER, -1, EXPECTED_ROOT[1],
                       EXPECTED_ROOT[0], EXPECTED_ROOT[1], 0)):
            with self.subTest(value=value):
                self.assertIs(native.pointer_containment(
                    raising, ROOT, value, [CHOOSER, OUTER, ROOT], ORIGIN, GEOMETRY),
                    False)

    def test_path_depth_is_bounded(self):
        self.assertEqual(native.POINTER_PATH_DEPTH, 16)
        deep = {40: ROOT, ROOT: ROOT}
        deep.update({40 + index: (40 + index - 1) for index in range(1, 18)})
        self.assertIsNone(native.window_ancestry(tree_parents(deep), 57, ROOT))
        self.assertEqual(native.window_ancestry(tree_parents(deep), 40, ROOT), [40, ROOT])

    def test_decision_returns_only_a_boolean(self):
        for result in (self.judgement(qchild=CHOOSER), self.judgement(qchild=OVERLAY)):
            self.assertIs(type(result), bool)


class PointerDriverTests(unittest.TestCase):
    """The runtime motion/proof step: no button here, fail closed everywhere."""

    def run_driver(self, io, require_motion=True):
        return native.move_and_prove_pointer(
            io, tree_parents(OWNED_TREE), ROOT, CHOOSER, ORIGIN, GEOMETRY,
            require_motion)

    def test_only_the_derived_point_is_moved_then_proven(self):
        # The chooser sits under an intermediate root child: the root query
        # reports that child (10), never the chooser XID below it.
        io = PointerIO(OUTER)
        self.assertEqual(self.run_driver(io), [CHOOSER, OUTER, ROOT])
        self.assertEqual(io.calls, [("motion", *EXPECTED_ROOT), "flush", "sync", "query"])

    def test_overlay_refuses_after_motion_before_any_button(self):
        io = PointerIO(OVERLAY)
        with self.assertRaisesRegex(RuntimeError, "not over the owned chooser"):
            self.run_driver(io)
        self.assertEqual(io.calls, [("motion", *EXPECTED_ROOT), "flush", "sync", "query"])

    def test_pointer_drift_or_refused_query_refuses(self):
        drift = root_query(CHOOSER, (EXPECTED_ROOT[0] + 1, EXPECTED_ROOT[1]))
        moved_chooser = root_query(CHOOSER, EXPECTED_ROOT,
                                   (POINT[0], POINT[1] - 1))
        chooser_local = root_query(CHOOSER, EXPECTED_ROOT, POINT)
        for io in (PointerIO(OUTER, state=drift),
                   PointerIO(OUTER, state=moved_chooser),
                   PointerIO(OUTER, state=chooser_local),
                   # A deeper chooser XID than the root child is not the
                   # window XQueryPointer(root) reports.
                   PointerIO(CHOOSER),
                   PointerIO(FRAME),
                   PointerIO(ROOT)):
            with self.subTest(state=io.state):
                with self.assertRaisesRegex(RuntimeError, "not over the owned chooser"):
                    self.run_driver(io)
        # A failed XQueryPointer is a fixed, privacy-safe refusal too.
        with self.assertRaisesRegex(RuntimeError, "not at the measured point"):
            self.run_driver(PointerIO(CHOOSER, query_error=True))

    def test_refused_motion_stops_before_flush_and_query(self):
        io = PointerIO(OUTER, motion=0)
        with self.assertRaisesRegex(RuntimeError, "^Chooser folder input failed$"):
            self.run_driver(io)
        self.assertEqual(io.calls, [("motion", *EXPECTED_ROOT)])

    def test_reexecution_without_motion_never_moves_the_pointer(self):
        io = PointerIO(OUTER)
        self.run_driver(io, require_motion=False)
        self.assertEqual(io.calls, ["query"])
        overlay = PointerIO(OVERLAY)
        with self.assertRaises(RuntimeError):
            self.run_driver(overlay, require_motion=False)
        self.assertEqual(overlay.calls, ["query"])

    def test_errors_are_fixed_and_carry_no_state(self):
        for message in ("Chooser folder pointer is not at the measured point",
                        "Chooser folder pointer is not over the owned chooser",
                        "Chooser folder input failed"):
            self.assertRegex(native.FAILURE_REASONS[message], r"^[a-z-]+$")
        io = PointerIO(OVERLAY)
        with self.assertRaises(RuntimeError) as raised:
            self.run_driver(io)
        text = str(raised.exception)
        for value in (str(EXPECTED_ROOT[0]), str(EXPECTED_ROOT[1]), str(OVERLAY),
                      str(CHOOSER), "/"):
            self.assertNotIn(value, text)


class ChooserNavigationTests(unittest.TestCase):
    """The navigate action only maps Ctrl+L, the one path and Return."""

    SHORTCUTS = {"Control_L": 0x100, "Shift_L": 0x400, "Return": 0xFF, "l": ord("l")}

    def xlib(self, code, first_level=None):
        """A fixed Xlib stand-in: keysym name -> keycode -> first-level keysym."""
        first_level = first_level or {}
        inverse = {value: key for key, value in code.items()}
        return types.SimpleNamespace(
            # The driver passes one ASCII bytes keysym name, as Xlib expects.
            XStringToKeysym=lambda name: self.SHORTCUTS.get(
                name.decode("ascii"), ord(name.decode("ascii"))
                if len(name) == 1 else 0),
            XKeysymToKeycode=lambda display, keysym: code.get(keysym, 0),
            XKeycodeToKeysym=lambda display, keycode, index: first_level.get(
                keycode, inverse.get(keycode, 0)),
        )

    def test_exact_plan_is_ctrl_l_path_return(self):
        path = "/synthetic/package/chromium"
        code = {0x100: 37, ord("l"): 46, 0xFF: 36, 0x400: 50}
        code.update({ord(char): 100 + index for index, char in enumerate(path)})
        plan = native.chooser_navigation(self.xlib(code), "display", path)
        # Exactly Control_L, l, each path character and Return: no other key.
        self.assertEqual([keycode for keycode, _shift in plan],
                         [37, 46] + [code[ord(char)] for char in path] + [36])
        self.assertEqual(len(plan), len(path) + 3)
        self.assertTrue(all(shift is None for _keycode, shift in plan))

    def test_shifted_symbols_are_shift_chords(self):
        code = {0x100: 37, ord("l"): 46, 0xFF: 36, 0x400: 50, ord("/"): 61,
                ord("Q"): 24, ord("e"): 26}
        first_level = {24: ord("q"), 26: ord("e"), 61: ord("/")}
        plan = native.chooser_navigation(self.xlib(code, first_level), "display", "/Qe")
        self.assertEqual(plan, [(37, None), (46, None), (61, None), (24, 50),
                                (26, None), (36, None)])

    def test_unmapped_keys_are_refused(self):
        code = {0x100: 37, ord("l"): 46, 0xFF: 36, 0x400: 50, ord("/"): 61,
                ord("z"): 52}
        xlib = self.xlib(code, {61: ord("/"), 52: ord("z")})
        with self.assertRaisesRegex(RuntimeError,
                                    "^Acceptance keyboard mapping unavailable$"):
            native.chooser_navigation(xlib, "display", "/unmapped")
        for key in (0x100, ord("l"), 0xFF, 0x400):
            with self.subTest(missing=key):
                with self.assertRaisesRegex(RuntimeError, "^Chooser shortcut unavailable$"):
                    native.chooser_navigation(self.xlib({**code, key: 0}), "display", "/z")

    def test_non_ascii_or_relative_path_never_maps_a_key(self):
        calls = []
        xlib = types.SimpleNamespace(
            XStringToKeysym=lambda name: calls.append(name) or 1,
            XKeysymToKeycode=lambda *args: 1,
            XKeycodeToKeysym=lambda *args: ord("/"),
        )
        for path in ("relative/dir", "", "/", "/tmp/x/", "/路径", "/tmp/a\n",
                     "/tmp/a\u0000b", None, 1):
            with self.subTest(path=path):
                with self.assertRaisesRegex(
                        RuntimeError, "^Chooser navigation path required$"):
                    native.chooser_navigation(xlib, "display", path)
        self.assertEqual(calls, [])

    def test_navigate_answer_is_not_installation_success(self):
        self.assertEqual(native.folder_output("navigate", 0),
                         {"chooser_action": "chooser_navigate", "clicks": 0})
        self.assertEqual(native.folder_output("open", 1),
                         {"chooser_action": "chooser_open", "clicks": 1})
        for output in (native.folder_output("navigate", 0),
                       native.folder_output("open", 1)):
            self.assertEqual(set(output), {"chooser_action", "clicks"})
            self.assertNotIn("installed", output)
            self.assertNotIn("ownership", output)


class ChooserOwnershipRecordTests(unittest.TestCase):
    def test_only_the_owned_record_is_accepted(self):
        for record in ({"owned": True, "relation": "process-parent"},
                       {"owned": True, "relation": "transient-leader"}):
            self.assertEqual(native.safe_owner_record(record)["owned"], True)
        for record in (None, {}, {"owned": True}, {"owned": True, "relation": "none"},
                       {"owned": False, "relation": "process-parent"},
                       {"owned": "true", "relation": "process-parent"}):
            with self.subTest(record=record):
                self.assertIsNone(native.safe_owner_record(record))


if __name__ == "__main__":
    unittest.main()
