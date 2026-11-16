"""C4a unit tests for the dedicated private local-vault target branch.

No X server, AT-SPI process, App, GUI input or real accessibility value is
used. Every label/PID/path below is synthetic; failures assert fixed strings
and booleans only, never request/label/PID/object dumps.
"""
import json
import types
import unittest
from unittest.mock import Mock, patch

import browser_native_x11 as native


LABEL = "示例金库 · 0123abcd"
LABEL_OTHER = "家庭 📁 · deadbeef"
LABEL_BIDI = "金库\\u202E · 0123abcd"
LABEL_RAW_BIDI = "金库\u202E · 0123abcd"
DYNAMIC = "synthetic-dynamic-value"


def request(**overrides):
    value = {
        "title": native.LOCAL_VAULT_TARGET_TITLE,
        "executable": "/synthetic/locklark-desktop",
        "expected_pid": 321,
        "local_vault_target": target(),
    }
    value.update(overrides)
    return value


def target(**overrides):
    value = {
        "action": "select-sidebar",
        "known_labels": [LABEL],
        "target_index": 0,
    }
    value.update(overrides)
    return value


class LocalVaultLabelFormatTests(unittest.TestCase):
    """Finite format check of the reviewed Go helper's normal display rows."""

    def test_normal_chinese_emoji_and_separator_names_are_accepted(self):
        values = (
            LABEL,
            LABEL_OTHER,
            LABEL_BIDI,
            "登录 · 副本 · 0123abcd",
            "x" * 255 + " · " + "a" * 32,
            "a" * 255 + " · " + "0" * 8,
        )
        for value in values:
            self.assertTrue(native.local_vault_display_label(value) == value)

    def test_prefix_is_eight_to_thirty_two_lowercase_hex(self):
        self.assertTrue(native.local_vault_display_label("名 · " + "a" * 8) is not None)
        self.assertTrue(native.local_vault_display_label("名 · " + "f" * 32) is not None)
        self.assertFalse(native.local_vault_display_label("名 · " + "a" * 7) is not None)
        self.assertFalse(native.local_vault_display_label("名 · " + "a" * 33) is not None)
        self.assertFalse(native.local_vault_display_label("名 · " + "A" * 8) is not None)
        self.assertFalse(native.local_vault_display_label("名 · " + "g" * 8) is not None)
        self.assertFalse(native.local_vault_display_label("名 · ") is not None)

    def test_review_and_duplicate_forms_are_not_normal_labels(self):
        values = (
            "待核查文件",
            "待核查文件 #2",
            "待核查文件 #10",
            LABEL + " · 重复待核查",
        )
        for value in values:
            self.assertIsNone(native.local_vault_display_label(value))

    def test_validname_shape_is_reconstructed_and_enforced(self):
        values = (
            " · 0123abcd",
            ".hidden · 0123abcd",
            "trail. · 0123abcd",
            "trail  · 0123abcd",
            "./x · 0123abcd",
            "a\\b · 0123abcd",
            "a\u0001b · 0123abcd",
            "图" * 86 + " · 0123abcd",
        )
        for value in values:
            self.assertIsNone(native.local_vault_display_label(value))

    def test_visible_bidi_escapes_only(self):
        self.assertIsNotNone(native.local_vault_display_label(LABEL_BIDI))
        self.assertIsNone(native.local_vault_display_label(LABEL_RAW_BIDI))
        self.assertIsNone(native.local_vault_display_label("名\\u202e · 0123abcd"))
        self.assertIsNone(native.local_vault_display_label("名\\u0041 · 0123abcd"))
        self.assertIsNone(native.local_vault_display_label("名\\u202 · 0123abcd"))
        self.assertIsNone(native.local_vault_display_label("名\\ · 0123abcd"))
        self.assertIsNone(native.local_vault_display_label("名\\\\u202E · 0123abcd"))

    def test_reconstructed_name_stays_within_reviewed_byte_and_escape_bounds(self):
        escaped = "\\u202E" * 85 + native.LOCAL_VAULT_LABEL_SEPARATOR + "a" * 32
        self.assertEqual(len(escaped.encode("utf-8")), native.LOCAL_VAULT_LABEL_MAX_BYTES)
        self.assertIsNotNone(native.local_vault_display_label(escaped))
        over = "\\u202E" * 86 + native.LOCAL_VAULT_LABEL_SEPARATOR + "a" * 32
        self.assertIsNone(native.local_vault_display_label(over))

    def test_non_string_values_are_rejected(self):
        for value in (None, True, 1, [], {}, ("x",)):
            self.assertIsNone(native.local_vault_display_label(value))


class LocalVaultRequestSchemaTests(unittest.TestCase):
    """Closed purpose-bound schema; every rejection is a fixed enum."""

    def rejected(self, value):
        with self.assertRaises(RuntimeError) as caught:
            native.parse_local_vault_target_request(value)
        self.assertEqual(str(caught.exception),
                         "Exact private local-vault target request required")
        self.assertEqual(native.failure_reason(caught.exception),
                         "local-vault-request")

    def test_exact_schema_is_accepted(self):
        parsed = native.parse_local_vault_target_request(request())
        self.assertIsNotNone(parsed)
        self.assertEqual(set(parsed),
                         (set(native.LOCAL_VAULT_TARGET_KEYS) - {"local_vault_target"}) |
                         set(native.LOCAL_VAULT_TARGET_FIELDS))
        self.assertEqual(parsed["action"], "select-sidebar")
        self.assertEqual(parsed["target_index"], 0)
        self.assertEqual(len(parsed["known_labels"]), 1)
        self.assertEqual(parsed["title"], native.LOCAL_VAULT_TARGET_TITLE)

    def test_two_distinct_known_labels_select_the_requested_index(self):
        value = request(local_vault_target=target(
            action="wait-title", known_labels=[LABEL, LABEL_OTHER], target_index=1))
        parsed = native.parse_local_vault_target_request(value)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["action"], "wait-title")
        self.assertEqual(parsed["target_index"], 1)
        self.assertEqual(len(parsed["known_labels"]), 2)

    def test_unknown_top_level_nested_and_missing_fields_are_rejected(self):
        extra_top = request(private="synthetic-extra")
        self.rejected(extra_top)
        extra_nested = request(local_vault_target=target(inspect=True))
        self.rejected(extra_nested)
        replacement = request(local_vault_target=target(match_rule="prefix"))
        self.rejected(replacement)
        for key in native.LOCAL_VAULT_TARGET_KEYS - {"local_vault_target"}:
            value = request()
            del value[key]
            self.rejected(value)
        for key in native.LOCAL_VAULT_TARGET_FIELDS:
            value = target()
            del value[key]
            self.rejected(request(local_vault_target=value))

    def test_closed_actions_only(self):
        self.assertIsNotNone(native.parse_local_vault_target_request(
            request(local_vault_target=target(action="select-sidebar"))))
        self.assertIsNotNone(native.parse_local_vault_target_request(
            request(local_vault_target=target(action="wait-title"))))
        for action in ("click", "snapshot", "", None, True, 1, [], {}):
            self.rejected(request(local_vault_target=target(action=action)))

    def test_known_labels_are_one_or_two_distinct_exact_strings(self):
        for labels in (None, [], "0123abcd", {}, [LABEL] * 2,
                       [LABEL, LABEL_OTHER, LABEL_BIDI], (LABEL,)):
            self.rejected(request(local_vault_target=target(known_labels=labels)))

    def test_known_label_format_rejections_are_closed(self):
        values = (
            "", "待核查文件", "待核查文件 #2", "名", "名 · 0123abc",
            "名 · 0123abcdeZ", "名 · " + "A" * 8, LABEL + " · 重复待核查",
            "名 · " + "a" * 33, LABEL_RAW_BIDI, ".hidden · 0123abcd",
            "a/b · 0123abcd", "a\\b · 0123abcd",
        )
        for value in values:
            self.rejected(request(local_vault_target=target(known_labels=[value])))

    def test_target_index_is_a_real_in_range_integer(self):
        for index in (True, False, 1.0, "0", None, -1, 1, 2):
            self.rejected(request(local_vault_target=target(target_index=index)))
        two = target(known_labels=[LABEL, LABEL_OTHER], target_index=1)
        self.assertIsNotNone(native.parse_local_vault_target_request(
            request(local_vault_target=two)))

    def test_identity_fields_reuse_fixed_title_executable_and_positive_pid_checks(self):
        self.rejected(request(title=native.LOCAL_VAULT_TARGET_TITLE + " "))
        for executable in ("relative/locklark", "/synthetic/locklark/", "/synthetic/../locklark",
                           "/synthetic/locklark\x00", "", None):
            self.rejected(request(executable=executable))
        for pid in (True, False, 0, -1, 1.0, "321", None):
            self.rejected(request(expected_pid=pid))

    def test_nested_false_or_malformed_purpose_intent_fails_closed(self):
        values = (
            {"local_vault_target": False},
            {"a": [{"local_vault_target": {"action": "select-sidebar"}}]},
            {"a": {"b": {"local_vault_target": None}}},
        )
        for value in values:
            self.assertTrue(native.local_vault_purpose_present(value))
            self.rejected(value)

    def test_absence_of_the_purpose_key_selects_no_branch(self):
        self.assertIsNone(native.parse_local_vault_target_request({"title": "ordinary"}))
        self.assertFalse(native.local_vault_purpose_present({"actions": [{"text": "x"}]}))

    def test_recovery_keeps_first_priority_and_mixing_is_rejected(self):
        mixed = request()
        mixed["read_recovery"] = True
        with self.assertRaises(RuntimeError) as caught:
            native.parse_recovery_request(mixed)
        self.assertEqual(native.failure_reason(caught.exception), "recovery-request")
        nested = request(local_vault_target=target(note={"read_recovery": False}))
        with self.assertRaises(RuntimeError) as caught:
            native.parse_recovery_request(nested)
        self.assertEqual(native.failure_reason(caught.exception), "recovery-request")
        local_mixed = request()
        local_mixed["local_vault_target"]["note"] = {"read_recovery": False}
        self.rejected(local_mixed)

    def test_recovery_schema_and_global_label_gate_are_unchanged(self):
        recovery = {
            "title": native.RECOVERY_TITLE,
            "executable": "/synthetic/locklark-desktop",
            "expected_pid": 321,
            "preserve_focus": True,
            "read_recovery": True,
        }
        parsed = native.parse_recovery_request(recovery)
        self.assertIsNotNone(parsed)
        self.assertEqual(set(parsed), set(native.RECOVERY_KEYS))
        before = set(native.CONTROL_LABELS)
        self.assertFalse(native.control_label_allowed(LABEL))
        self.assertNotIn(LABEL, native.CONTROL_LABELS)
        native.parse_local_vault_target_request(request())
        self.assertEqual(set(native.CONTROL_LABELS), before)
        self.assertFalse(native.control_label_allowed(LABEL))


class LocalVaultNativeMemberTests(unittest.TestCase):
    """Fake AT-SPI metadata only: exact name/role/state/bounds."""

    def controls(self, nodes):
        controls = native.NativeControls.__new__(native.NativeControls)
        controls.title = native.LOCAL_VAULT_TARGET_TITLE
        controls.pid = 321
        controls.go = Mock()
        controls.window_refs = Mock(return_value=["window"])
        controls.walk = Mock(side_effect=lambda _root, visit: [visit(node, 0) for node in nodes])
        names = {node: value["name"] for node, value in nodes.items()}
        roles = {node: value["role"] for node, value in nodes.items()}
        states = {node: value.get("state", set()) for node, value in nodes.items()}
        components = {node: value.get("component", node) for node, value in nodes.items()}
        rects = {node: types.SimpleNamespace(contents=types.SimpleNamespace(
            x=value.get("x", 1), y=value.get("y", 2),
            width=value.get("width", 10), height=value.get("height", 5)))
            for node, value in nodes.items()}
        controls.at = types.SimpleNamespace(
            atspi_accessible_get_name=object(),
            atspi_accessible_get_role_name=object(),
            atspi_accessible_get_state_set=Mock(
                side_effect=lambda node: node if states[node] else None),
            atspi_state_set_contains=Mock(
                side_effect=lambda state, bit: bit in states[state]),
            atspi_accessible_get_component_iface=Mock(
                side_effect=lambda node: components[node]),
            atspi_component_get_extents=Mock(
                side_effect=lambda component, _coord: rects[component]),
            atspi_rect_free=Mock(),
        )
        controls.checked = lambda function, *args: function(*args)

        def string(function, node):
            if function is controls.at.atspi_accessible_get_name:
                return names[node]
            if function is controls.at.atspi_accessible_get_role_name:
                return roles[node]
            raise AssertionError("unexpected accessibility accessor")

        controls.string = string
        return controls

    def visible(self, **overrides):
        value = {"name": LABEL, "role": "push button",
                 "state": {8, 24, 25, 30}, "width": 10, "height": 5}
        value.update(overrides)
        return value

    def test_select_accepts_exact_pushbutton_or_button_with_valid_bounds(self):
        for role in ("push button", "button"):
            bounds = self.controls({"node": self.visible(role=role)}).local_vault_member(
                LABEL, "select-sidebar")
            self.assertIsNotNone(bounds)
            self.assertEqual(bounds["width"], 10)
            self.assertEqual(bounds["height"], 5)

    def test_wait_accepts_exact_visible_label_and_ignores_enabled(self):
        bounds = self.controls({"node": self.visible(role="label", state={25, 30})}) \
            .local_vault_member(LABEL, "wait-title")
        self.assertIsNotNone(bounds)

    def test_wrong_role_is_not_a_match(self):
        for role in ("label", "text", "entry", "password text", "button"):
            if role == "button":
                continue
            bounds = self.controls({"node": self.visible(role=role)}) \
                .local_vault_member(LABEL, "select-sidebar")
            self.assertIsNone(bounds)
        for role in ("push button", "button", "text", "entry"):
            bounds = self.controls({"node": self.visible(role=role)}) \
                .local_vault_member(LABEL, "wait-title")
            self.assertIsNone(bounds)

    def test_hidden_disabled_and_invalid_bounds_are_not_ready(self):
        cases = (
            self.visible(state={8, 24}),
            self.visible(state={8, 25, 30}),
            self.visible(width=0),
            self.visible(height=-1),
            self.visible(component=None),
        )
        for node in cases:
            bounds = self.controls({"node": node}).local_vault_member(
                LABEL, "select-sidebar")
            self.assertIsNone(bounds)

    def test_wait_requires_showing_and_valid_bounds(self):
        for node in (self.visible(role="label", state={8, 24}),
                     self.visible(role="label", state={25, 30}, width=0)):
            bounds = self.controls({"node": node}).local_vault_member(
                LABEL, "wait-title")
            self.assertIsNone(bounds)

    def test_duplicate_exact_member_rejects_even_when_one_is_hidden(self):
        nodes = {
            "one": self.visible(),
            "two": self.visible(),
        }
        with self.assertRaises(RuntimeError) as caught:
            self.controls(nodes).local_vault_member(LABEL, "select-sidebar")
        self.assertEqual(str(caught.exception), "Native local-vault target must be unique")
        hidden = {
            "one": self.visible(),
            "two": self.visible(state={8, 24}),
        }
        with self.assertRaises(RuntimeError) as caught:
            self.controls(hidden).local_vault_member(LABEL, "select-sidebar")
        self.assertEqual(str(caught.exception), "Native local-vault target must be unique")

    def test_exact_member_only_never_prefix_or_other_known_label(self):
        for name in (LABEL[:-1], LABEL + "x", "示例金库", "0123abcd"):
            bounds = self.controls({"node": self.visible(name=name)}) \
                .local_vault_member(LABEL, "select-sidebar")
            self.assertIsNone(bounds)

    def test_missing_window_and_query_refusal_fail_closed(self):
        controls = self.controls({"node": self.visible()})
        controls.window_refs = Mock(return_value=[])
        with self.assertRaises(RuntimeError) as caught:
            controls.local_vault_member(LABEL, "select-sidebar")
        self.assertEqual(native.failure_reason(caught.exception),
                         "a11y-window-unavailable")
        controls = self.controls({"node": self.visible()})
        controls.walk = Mock(side_effect=native.AccessibilityQueryUnavailable(
            "Native accessibility query failed"))
        with self.assertRaises(RuntimeError) as caught:
            controls.local_vault_member(LABEL, "select-sidebar")
        self.assertEqual(native.failure_reason(caught.exception), "a11y-query")

    def test_ready_returns_the_one_control_and_rejects_ambiguity_without_retry(self):
        control = {"enabled": True, "showing": True, "width": 10, "height": 5}
        controls = self.controls({})
        controls.local_vault_member = Mock(return_value=control)
        with patch.object(native.time, "monotonic", return_value=0):
            self.assertIs(controls.local_vault_ready(LABEL, "select-sidebar"), control)
        controls = self.controls({})
        controls.local_vault_member = Mock(side_effect=RuntimeError(
            "Native local-vault target must be unique"))
        with patch.object(native.time, "sleep") as sleep:
            with self.assertRaises(RuntimeError) as caught:
                controls.local_vault_ready(LABEL, "select-sidebar")
        self.assertEqual(str(caught.exception), "Native local-vault target must be unique")
        sleep.assert_not_called()

    def test_ready_uses_the_existing_ten_second_budget(self):
        controls = self.controls({})
        controls.local_vault_member = Mock(return_value=None)
        with patch.object(native.time, "monotonic",
                          side_effect=[0, 0, 0, 9.99, 9.99, 10]), \
                patch.object(native.time, "sleep") as sleep:
            with self.assertRaises(RuntimeError) as caught:
                controls.local_vault_ready(LABEL, "select-sidebar")
        self.assertEqual(native.failure_reason(caught.exception),
                         "local-vault-target-timeout")
        self.assertEqual(sleep.call_count, 2)
        self.assertAlmostEqual(sleep.call_args.args[0], 0.01)


class LocalVaultOutputPrivacyTests(unittest.TestCase):
    """Closed success/error shapes never echo caller or runtime identity."""

    def test_select_output_is_fixed_action_and_pointer_only(self):
        record = {
            "label": LABEL,
            "target": "0xdeadbeef",
            "x": 11, "y": 22,
            "before": {"x": 11, "y": 22, "button_mask": 0,
                       "focus": "0xcafe", "pointer_available": True},
            "after": {"x": 11, "y": 22, "button_mask": 0,
                      "focus": "0xcafe", "pointer_available": True},
            "x_test": {"motion": True, "down": True, "up": True},
            "expected_pid": 987654,
            "executable": "/synthetic/private-executable",
            "request": DYNAMIC,
        }
        output = native.local_vault_select_output(0, record)
        self.assertEqual(set(output), {"action", "target_index", "clicks"})
        self.assertEqual(output["action"], "select-sidebar")
        click = output["clicks"][0]
        self.assertEqual(click["label"], "pointer")
        self.assertFalse("target" in click)
        self.assertFalse("focus" in click["before"])
        self.assertFalse("focus" in click["after"])
        text = json.dumps(output)
        self.assertFalse(LABEL in text)
        self.assertFalse("0xdeadbeef" in text)
        self.assertFalse("987654" in text)
        self.assertFalse("/synthetic/private-executable" in text)
        self.assertFalse(DYNAMIC in text)

    def test_wait_output_is_one_fixed_boolean(self):
        output = native.local_vault_wait_output()
        self.assertEqual(set(output), {"action", "matched"})
        self.assertEqual(output["action"], "wait-title")
        self.assertIs(output["matched"], True)

    def test_error_messages_are_fixed_and_never_echo_input(self):
        bad = request(local_vault_target=target(
            known_labels=[LABEL], target_index=1, note=DYNAMIC))
        with self.assertRaises(RuntimeError) as caught:
            native.parse_local_vault_target_request(bad)
        message = str(caught.exception)
        self.assertEqual(message, "Exact private local-vault target request required")
        self.assertFalse(LABEL in message)
        self.assertFalse(DYNAMIC in message)
        self.assertFalse("321" in message)

    def test_dedicated_failure_reasons_are_fixed_enums(self):
        expected = {
            "Exact private local-vault target request required": "local-vault-request",
            "Native local-vault target identity mismatch": "local-vault-identity",
            "Native local-vault target not ready": "local-vault-target-timeout",
            "Native local-vault target must be unique": "local-vault-target-ambiguous",
            "Native local-vault target input failed": "local-vault-input",
        }
        for message, reason in expected.items():
            self.assertEqual(native.failure_reason(RuntimeError(message)), reason)


class LocalVaultDriverBoundaryTests(unittest.TestCase):
    """Source-order guards: reject before input, no ordinary snapshot."""

    source = open(native.__file__, encoding="utf-8").read()

    def branch_source(self):
        start = self.source.index("if local_target is not None:")
        end = self.source.index("def window_parent(candidate):", start)
        return self.source[start:end]

    def test_schema_check_precedes_x_open_and_owner_dispatch(self):
        parse = self.source.index("local_target = parse_local_vault_target_request(request)")
        self.assertLess(parse, self.source.index('x = C.CDLL("libX11.so.6")'))
        self.assertLess(parse, self.source.index(
            "folder_mode, owner, owner_error = dispatch_owner_request(request)"))
        self.assertLess(self.source.index("recovery = parse_recovery_request(request)"), parse)

    def test_branch_follows_unique_viewable_discovery_and_identity_precedes_input(self):
        branch = self.branch_source()
        self.assertGreater(self.source.index("if local_target is not None:"),
                           self.source.index("if not target:"))
        self.assertGreater(self.source.index("if local_target is not None:"),
                           self.source.index("if len(matches)>1:"))
        identity = branch.index("Native local-vault target identity mismatch")
        member = branch.index('controls.local_vault_ready(known_label, "select-sidebar")')
        first_input = branch.index("xt.XTestFakeMotionEvent")
        self.assertLess(identity, first_input)
        self.assertLess(member, first_input)
        self.assertIn("wait_window_viewable(local_map_state, discovery_deadline)", branch)
        self.assertIn("normal_viewable(target)", branch)
        self.assertIn("window_title(target)", branch)
        self.assertIn("window_pid(target)", branch)
        self.assertIn("expected_process(target)", branch)

    def test_wait_title_path_has_no_focus_input_or_click(self):
        branch = self.branch_source()
        start = branch.index('if local_target["action"] == "wait-title":')
        end = branch.index('bounds = controls.local_vault_ready', start)
        wait = branch[start:end]
        for forbidden in ("XRaiseWindow(", "XSetInputFocus(", "XTestFakeKeyEvent(",
                          "XTestFakeButtonEvent(", "XTestFakeMotionEvent(", "click(",
                          "navigate(", "click_folder("):
            self.assertNotIn(forbidden, wait)
        self.assertIn('local_vault_ready(known_label, "wait-title")', wait)
        self.assertIn("local_vault_wait_output()", wait)

    def test_select_path_is_one_existing_xtest_click_after_member(self):
        branch = self.branch_source()
        self.assertEqual(branch.count("xt.XTestFakeMotionEvent"), 1)
        self.assertEqual(branch.count("xt.XTestFakeButtonEvent(display, 1, 1, 0)"), 1)
        self.assertEqual(branch.count("xt.XTestFakeButtonEvent(display, 1, 0, 0)"), 1)
        self.assertIn("local_vault_select_output(", branch)
        self.assertNotIn("snapshot(", branch)
        self.assertNotIn("snapshot =", branch)
        for forbidden in ("XRaiseWindow(", "XSetInputFocus(", "XTestFakeKeyEvent("):
            self.assertNotIn(forbidden, branch)

    def test_dedicated_reader_does_not_call_ordinary_snapshot_or_mutate_allowlist(self):
        method = self.source[self.source.index("    def local_vault_member(self, label, action):"):
                             self.source.index("    def local_vault_ready(self, label, action):")]
        self.assertNotIn("snapshot(", method)
        self.assertNotIn("CONTROL_LABELS", method)
        self.assertIn("atspi_accessible_get_name", method)
        self.assertIn("atspi_accessible_get_role_name", method)
        self.assertIn("atspi_accessible_get_state_set", method)
        self.assertNotIn("atspi_accessible_get_value", method)
        self.assertNotIn("atspi_accessible_get_text", method)
        self.assertNotIn("XTestFake", method)
        self.assertNotIn("CONTROL_LABELS.add", self.source)
        self.assertNotIn("CONTROL_LABELS.update", self.source)


if __name__ == "__main__":
    unittest.main()
