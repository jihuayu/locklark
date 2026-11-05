"""Privacy boundaries of the limited external authorized-display reader."""
import ctypes
import json
import unittest
from unittest.mock import Mock, patch

import desktop_native_probe as probe


class DisplayReaderTests(unittest.TestCase):
    def reader(self, role="label", group_role="panel", duplicates=False):
        reader = probe.DisplayReader.__new__(probe.DisplayReader)
        reader.title, reader.pid, reader.desktop = "synthetic-window", 23, "desktop"
        reader.at, reader.go, reader.gl = Mock(), Mock(), Mock()
        reader.gl.g_main_context_iteration.return_value = 0
        reader.go.g_object_ref.side_effect = lambda node: "ref-" + node
        text = ctypes.create_string_buffer(b"synthetic-expected-value")
        reader.at.atspi_accessible_get_process_id.return_value = 23
        reader.at.atspi_accessible_get_text_iface.return_value = "text-interface"
        reader.at.atspi_text_get_text.return_value = ctypes.addressof(text)
        reader.checked = lambda function, *args: function(*args)

        def string(function, node):
            node = node.removeprefix("ref-")
            if function == reader.at.atspi_accessible_get_role_name:
                return group_role if node == "group" else role
            return {"window": reader.title, "group": "已授权显示的验证码"}.get(node, "unrelated")

        def walk(node, visit):
            if node == "desktop":
                visit("window", 0)
            elif node == "ref-window":
                visit("group", 1)
                if duplicates:
                    visit("group", 1)
            elif node == "ref-group":
                visit("group", 0)
                visit("static-child", 1)

        reader.string, reader.walk, reader._buffer = string, walk, text
        return reader

    def test_authorized_static_child_returns_only_booleans(self):
        reader = self.reader()
        result = reader.inspect_display("已授权显示的验证码", ["synthetic-expected-value", "wrong"])
        self.assertEqual(result, {"present": True, "empty": False, "matches": [True, False], "read_attempts":1})
        reader.at.atspi_text_get_text.assert_called_once()
        self.assertNotIn("synthetic-expected-value", str(result))

    def test_editable_text_is_never_read(self):
        for role in ("text", "entry", "password text"):
            with self.subTest(role=role):
                reader = self.reader(role=role)
                with self.assertRaisesRegex(RuntimeError, "display-static-text-required"):
                    reader.inspect_display("已授权显示的验证码", [])
                reader.at.atspi_text_get_text.assert_not_called()
                self.assertEqual(reader.go.g_object_unref.call_args_list[-1].args, ("ref-window",))

    def test_plain_label_is_not_an_authorized_group(self):
        reader = self.reader(group_role="label")
        with self.assertRaisesRegex(RuntimeError, "display-group-required"):
            reader.inspect_display("已授权显示的验证码", [])
        reader.at.atspi_text_get_text.assert_not_called()

    def test_arbitrary_label_is_rejected_before_tree_query(self):
        reader = self.reader()
        reader.walk = Mock()
        with self.assertRaisesRegex(RuntimeError, "display-request"):
            reader.inspect_display("新登录密码", [])
        reader.walk.assert_not_called()

    def test_ambiguous_group_fails_and_releases_window(self):
        reader = self.reader(duplicates=True)
        with self.assertRaisesRegex(RuntimeError, "display-ambiguous"):
            reader.inspect_display("已授权显示的验证码", [])
        reader.at.atspi_text_get_text.assert_not_called()
        self.assertEqual(reader.go.g_object_unref.call_args_list[-1].args, ("ref-window",))


class GuardReasonTests(unittest.TestCase):
    def test_known_native_guards_have_fixed_reasons(self):
        for message, reason in (("Native accessibility tree limit", "a11y-tree-limit"),
                                ("Native accessibility child limit", "a11y-child-limit")):
            with self.subTest(reason=reason):
                self.assertEqual(probe.failure_reason(RuntimeError(message)), reason)

    def test_diagnostic_never_contains_error_args_or_locals(self):
        private = "synthetic-private-error-value"
        try:
            raise RuntimeError(private)
        except RuntimeError as error:
            diagnostic = probe.error_diagnostic(error)
        self.assertEqual(diagnostic["error_class"], "runtime")
        self.assertNotIn(private, json.dumps(diagnostic))
        self.assertEqual(diagnostic["locations"], [])

    def test_diagnostic_only_accepts_fixed_aliases_and_numeric_guards(self):
        private = "synthetic-private-error-value"
        result = probe.safe_diagnostic({"error_class":private,
            "locations":[{"function":private,"line":2},{"function":"probe.inspect_display","line":40}],
            "guard":{"depth":13,"children":-1,"value":private,"remaining":private}})
        self.assertEqual(result, {"error_class":"unexpected", "locations":[{"function":"probe.inspect_display","line":40}], "guard":{"depth":13,"children":-1}})
        self.assertNotIn(private, json.dumps(result))


class DisplayReadRetryTests(unittest.TestCase):
    def reader(self, effect):
        reader = probe.DisplayReader.__new__(probe.DisplayReader)
        reader.inspect_display_once = Mock(side_effect=effect)
        return reader

    def query_error(self):
        return probe.AccessibilityQueryUnavailable("Native accessibility query failed")

    def test_one_typed_query_error_then_exact_comparison(self):
        reader = self.reader([self.query_error(), {"present":True, "empty":False, "matches":[True]}])
        with patch.object(probe.time, "monotonic", side_effect=[0, 0.1, 0.12]), patch.object(probe.time, "sleep") as sleep:
            result = reader.inspect_display("已授权显示的验证码", ["synthetic-expected"])
        self.assertEqual(result, {"present":True, "empty":False, "matches":[True], "read_attempts":2})
        self.assertEqual(reader.inspect_display_once.call_count, 2)
        sleep.assert_called_once_with(0.02)

    def test_persistent_query_error_stops_at_original_half_second_budget(self):
        reader = self.reader(self.query_error())
        with patch.object(probe.time, "monotonic", side_effect=[0, 0.1, 0.12, 0.4, 0.42, 0.5]), patch.object(probe.time, "sleep") as sleep:
            with self.assertRaises(probe.AccessibilityQueryUnavailable):
                reader.inspect_display("已授权显示的验证码", [])
        self.assertEqual(reader.inspect_display_once.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_structural_failure_is_not_retried(self):
        reader = self.reader(RuntimeError("display-ambiguous"))
        with patch.object(probe.time, "monotonic", return_value=0), patch.object(probe.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "display-ambiguous"):
                reader.inspect_display("已授权显示的验证码", [])
        reader.inspect_display_once.assert_called_once()
        sleep.assert_not_called()

    def test_expired_display_remains_empty_and_comparison_false(self):
        reader = self.reader([self.query_error(), {"present":False, "empty":True, "matches":[False]}])
        with patch.object(probe.time, "monotonic", side_effect=[0, 0.1, 0.12]), patch.object(probe.time, "sleep"):
            result = reader.inspect_display("已授权显示的验证码", ["synthetic-expected"])
        self.assertEqual(result, {"present":False, "empty":True, "matches":[False], "read_attempts":2})


class ClipboardResponseTests(unittest.TestCase):
    def clipboard(self):
        clipboard = probe.Clipboard.__new__(probe.Clipboard)
        clipboard.gtk = Mock()
        clipboard.clipboard = "synthetic-clipboard"
        clipboard.sequence, clipboard.pending = 0, {}
        clipboard.text_received = clipboard.received
        clipboard.pump = Mock()
        return clipboard

    def test_immediate_response_returns_only_exact_booleans(self):
        clipboard = self.clipboard()
        buffer = ctypes.create_string_buffer(b"synthetic-private-text")
        clipboard.gtk.gtk_clipboard_request_text.side_effect = lambda _clip, callback, token: callback(None, ctypes.addressof(buffer), token)
        with patch.object(probe.time, "monotonic", side_effect=[0, 0.1]):
            result = clipboard.compare(["synthetic-private-text", "other"])
        self.assertEqual(result, {"empty":False, "matches":[True, False]})
        self.assertEqual(clipboard.pending, {})

    def test_no_response_is_hard_timeout_not_empty(self):
        clipboard = self.clipboard()
        with patch.object(probe.time, "monotonic", side_effect=[0, 0, 0.5, 1]), patch.object(probe.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "clipboard-response-timeout"):
                clipboard.compare([])
        self.assertEqual(clipboard.pending, {})

    def test_late_callback_does_not_read_expired_text(self):
        clipboard = self.clipboard()
        with patch.object(probe.time, "monotonic", side_effect=[0, 1]):
            with self.assertRaisesRegex(RuntimeError, "clipboard-response-timeout"):
                clipboard.compare([])
        with patch.object(probe.C, "string_at") as read:
            clipboard.received(None, 123, 1)
        read.assert_not_called()
        self.assertEqual(clipboard.pending, {})

    def test_old_callback_cannot_complete_a_new_operation(self):
        clipboard = self.clipboard()
        with patch.object(probe.time, "monotonic", side_effect=[0, 1]):
            with self.assertRaisesRegex(RuntimeError, "clipboard-response-timeout"):
                clipboard.compare([])
        buffer = ctypes.create_string_buffer(b"later-private-text")

        def callbacks(_clip, callback, token):
            callback(None, 123, 1)
            callback(None, ctypes.addressof(buffer), token)

        clipboard.gtk.gtk_clipboard_request_text.side_effect = callbacks
        string_at = ctypes.string_at
        with patch.object(probe.time, "monotonic", side_effect=[2, 2.1]), patch.object(probe.C, "string_at", wraps=string_at) as read:
            result = clipboard.compare(["later-private-text"])
        self.assertEqual(result, {"empty":False, "matches":[True]})
        read.assert_called_once_with(ctypes.addressof(buffer))

    def test_callback_after_deadline_does_not_read_even_active_token(self):
        clipboard = self.clipboard()
        clipboard.gtk.gtk_clipboard_request_text.side_effect = lambda _clip, callback, token: callback(None, 123, token)
        with patch.object(probe.time, "monotonic", side_effect=[0, 1]), patch.object(probe.C, "string_at") as read:
            with self.assertRaisesRegex(RuntimeError, "clipboard-response-timeout"):
                clipboard.compare([])
        read.assert_not_called()

    def test_invalid_text_callback_has_fixed_error(self):
        clipboard = self.clipboard()
        buffer = ctypes.create_string_buffer(b"\xff")
        clipboard.gtk.gtk_clipboard_request_text.side_effect = lambda _clip, callback, token: callback(None, ctypes.addressof(buffer), token)
        with patch.object(probe.time, "monotonic", side_effect=[0, 0.1]):
            with self.assertRaisesRegex(RuntimeError, "clipboard-response-invalid"):
                clipboard.compare([])


if __name__ == "__main__":
    unittest.main()
