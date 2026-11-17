import base64
import unittest
from test_emulator import scan_output, complete_pass, RuntimeFailure, safe_diagnostic


class RuntimeWrapperTests(unittest.TestCase):
    def test_device_auth_failure_phases_remain_fixed_and_specific(self):
        for phase in ("device_ready", "device_wait", "device_crypto"):
            with self.subTest(phase=phase):
                raw = (b"INSTRUMENTATION_STATUS: locklark_stage=platform-auth-refusal\n"
                       b"INSTRUMENTATION_STATUS: locklark_core_phase=" + phase.encode() + b"\n"
                       b"INSTRUMENTATION_STATUS: locklark_core_error=unavailable\n"
                       b"INSTRUMENTATION_STATUS_CODE: -2\n")
                result = safe_diagnostic(raw)
                self.assertEqual(result["core_phase"], phase)
                self.assertEqual(result["core_error"], "unavailable")
                invalid = safe_diagnostic(raw.replace(phase.encode(), b"private-native-error-text"))
                self.assertEqual(invalid["core_phase"], "unknown")
                self.assertNotIn("private-native-error-text", str(invalid))

    def test_unavailable_ime_observation_remains_unknown(self):
        raw = (b"INSTRUMENTATION_STATUS: locklark_stage=edit-notes\n"
               b"INSTRUMENTATION_STATUS: locklark_control=save-field\n"
               b"INSTRUMENTATION_STATUS: locklark_control_phase=ime-observe\n"
               b"INSTRUMENTATION_STATUS: locklark_ime=unknown\n"
               b"INSTRUMENTATION_STATUS: locklark_ime_hide_requested=false\n"
               b"INSTRUMENTATION_STATUS_CODE: -2\n")
        failure = safe_diagnostic(raw)["failed_contexts"][0]
        self.assertEqual(failure["control_phase"], "ime-observe")
        self.assertEqual(failure["ime"], "unknown")
        self.assertEqual(failure["ime_hide_requested"], "false")

    def test_late_ime_hide_request_is_fixed_and_preserves_failure(self):
        raw = (b"INSTRUMENTATION_STATUS: locklark_stage=edit-notes\n"
               b"INSTRUMENTATION_STATUS: locklark_wait=native-visible\n"
               b"INSTRUMENTATION_STATUS: locklark_control=save-field\n"
               b"INSTRUMENTATION_STATUS: locklark_control_phase=ime-wait-hidden\n"
               b"INSTRUMENTATION_STATUS: locklark_ime=true\n"
               b"INSTRUMENTATION_STATUS: locklark_ime_hide_requested=true\n"
               b"INSTRUMENTATION_STATUS_CODE: -2\n"
               b"INSTRUMENTATION_STATUS: locklark_ime_hide_requested=false\n")
        result = safe_diagnostic(raw)
        failure = result["failed_contexts"][0]
        self.assertEqual(failure["control_phase"], "ime-wait-hidden")
        self.assertEqual(failure.get("ime_hide_requested"), "true")
        self.assertEqual(failure["ime"], "true")
        invalid = safe_diagnostic(raw.replace(b"hide_requested=true", b"hide_requested=private-field-contents"))
        self.assertEqual(invalid["failed_contexts"][0].get("ime_hide_requested"), "unknown")
        self.assertNotIn("private-field-contents", str(invalid))

    def test_input_focus_context_is_fixed_and_survives_later_status(self):
        raw = (b"INSTRUMENTATION_STATUS: locklark_stage=regenerate\n"
               b"INSTRUMENTATION_STATUS: locklark_wait=native-input-focus\n"
               b"INSTRUMENTATION_STATUS: locklark_control=regenerate-length\n"
               b"INSTRUMENTATION_STATUS: locklark_control_phase=input-focus\n"
               b"INSTRUMENTATION_STATUS: locklark_control_focused=true\n"
               b"INSTRUMENTATION_STATUS: locklark_input_active=false\n"
               b"INSTRUMENTATION_STATUS_CODE: -2\n"
               b"INSTRUMENTATION_STATUS: locklark_control=private-input-text\n"
               b"INSTRUMENTATION_STATUS: locklark_input_active=private-input-text\n")
        result = safe_diagnostic(raw)
        failure = result["failed_contexts"][0]
        self.assertEqual((failure["step"], failure["wait"], failure["control"], failure["control_phase"]),
                         ("regenerate", "native-input-focus", "regenerate-length", "input-focus"))
        self.assertEqual((failure["control_focused"], failure["input_active"]), ("true", "false"))
        self.assertNotIn("private-input-text", str(result))
        invalid = safe_diagnostic(raw.replace(b"true", b"private-input-text").replace(b"false", b"private-input-text"))
        self.assertEqual(invalid["failed_contexts"][0]["control_focused"], "unknown")
        self.assertEqual(invalid["failed_contexts"][0]["input_active"], "unknown")

    def test_failure_or_partial_instrumentation_cannot_pass(self):
        passed = b"OK (4 tests)\nINSTRUMENTATION_CODE: -1\n"
        self.assertTrue(complete_pass(0, passed, 4))
        self.assertTrue(complete_pass(0, b"Time: 12.34\nOK (4 tests)\nINSTRUMENTATION_CODE: -1\n", 4))
        for code, raw in ((1, passed), (0,b"INSTRUMENTATION_CODE: -1"), (0,passed+b"FAILURES!!!"), (0,passed+b"Process crashed")):
            self.assertFalse(complete_pass(code, raw, 4))
        for count in (0, 2, 3, 5):
            with self.subTest(count=count):
                partial = passed.replace(b"4 tests", str(count).encode() + b" tests")
                self.assertFalse(complete_pass(0, partial, 4))
                self.assertFalse(complete_pass(0, passed + b"OK (" + str(count).encode() + b" tests)\nINSTRUMENTATION_CODE: -1\n", 4))
                self.assertFalse(complete_pass(0, passed + b"FAILURES!!! Tests run: " + str(count).encode() + b", Failures: 1\n", 4))
                self.assertFalse(complete_pass(0, passed.replace(b"OK (", b"FAILURES!!! Tests run: " + str(count).encode() + b"\nOK ("), 4))
        self.assertFalse(complete_pass(0, passed.replace(b"OK (4 tests)", b"OK (4 tests)\nFAILURES!!! Tests run: 4, Failures: 1"), 4))
        # The full native suite count is pinned separately from the sample.
        self.assertFalse(complete_pass(0, b"OK (5 tests)\nINSTRUMENTATION_CODE: -1\n", 6))
        self.assertTrue(complete_pass(0, b"OK (6 tests)\nINSTRUMENTATION_CODE: -1\n", 6))

    def test_diagnostic_returns_only_fixed_classes_steps_and_source_integers(self):
        raw = b"INSTRUMENTATION_STATUS: locklark_stage=create\njava.lang.AssertionError: private-field-contents\nat org.locklark.android.OfflineVaultTest.run(OfflineVaultTest.kt:123)\nTests run: 1"
        result = safe_diagnostic(raw)
        self.assertEqual(result["step"], "create")
        self.assertEqual(result["own_source_line"], 123)
        self.assertEqual(result["tests_run"], 1)
        self.assertNotIn("private-field-contents", str(result))
        self.assertEqual(safe_diagnostic(b"INSTRUMENTATION_STATUS: locklark_stage=private-field-contents")["step"], "unknown")

    def test_later_success_does_not_replace_failed_test_context(self):
        raw = b"INSTRUMENTATION_STATUS: locklark_stage=create\nINSTRUMENTATION_STATUS: locklark_wait=account-key\nINSTRUMENTATION_STATUS_CODE: -2\nINSTRUMENTATION_STATUS: locklark_stage=bound-operation\nINSTRUMENTATION_STATUS_CODE: 0\n"
        self.assertEqual(safe_diagnostic(raw)["step"], "create")
        self.assertEqual(safe_diagnostic(raw)["wait"], "account-key")

    def test_control_geometry_diagnostic_is_fixed_and_preserves_failed_context(self):
        raw = (b"INSTRUMENTATION_STATUS: locklark_stage=add-login\n"
               b"INSTRUMENTATION_STATUS: locklark_control=generate-password\n"
               b"INSTRUMENTATION_STATUS: locklark_control_phase=visibility\n"
               b"INSTRUMENTATION_STATUS: locklark_ime=true\n"
               b"INSTRUMENTATION_STATUS: locklark_window_focus=true\n"
               b"INSTRUMENTATION_STATUS: locklark_control_visible=false\n"
               b"INSTRUMENTATION_STATUS: locklark_control_enabled=true\n"
               b"INSTRUMENTATION_STATUS: locklark_control_present=true\n"
               b"INSTRUMENTATION_STATUS: locklark_activity=RESUMED\n"
               b"INSTRUMENTATION_STATUS_CODE: -2\n"
               b"INSTRUMENTATION_STATUS: locklark_control=private-field-contents\n")
        result = safe_diagnostic(raw)
        self.assertEqual(result["failed_contexts"][0]["control"], "generate-password")
        self.assertEqual(result["failed_contexts"][0]["control_phase"], "visibility")
        self.assertEqual(result["failed_contexts"][0]["ime"], "true")
        self.assertEqual(result["failed_contexts"][0]["control_visible"], "false")
        self.assertEqual(result["failed_contexts"][0]["activity"], "RESUMED")
        self.assertNotIn("private-field-contents", str(result))

    def test_offscreen_control_context_stays_distinct_from_visibility(self):
        raw = (b"INSTRUMENTATION_STATUS: locklark_stage=search\n"
               b"INSTRUMENTATION_STATUS: locklark_wait=native-visible\n"
               b"INSTRUMENTATION_STATUS: locklark_control=back-to-list\n"
               b"INSTRUMENTATION_STATUS: locklark_control_phase=offscreen\n"
               b"INSTRUMENTATION_STATUS: locklark_ime=false\n"
               b"INSTRUMENTATION_STATUS: locklark_control_visible=false\n"
               b"INSTRUMENTATION_STATUS: locklark_control_enabled=true\n"
               b"INSTRUMENTATION_STATUS: locklark_activity=RESUMED\n"
               b"INSTRUMENTATION_STATUS_CODE: -2\n")
        failure = safe_diagnostic(raw)["failed_contexts"][0]
        self.assertEqual((failure["step"], failure["wait"], failure["control"], failure["control_phase"]),
                         ("search", "native-visible", "back-to-list", "offscreen"))
        self.assertEqual((failure["control_enabled"], failure["control_visible"]), ("true", "false"))

    def scroll_record(self, **changes):
        # Independent copy of the Android fixture's fixed emission order.
        fields = (
            ("scroll_y", "0"), ("scroll_span", "80"), ("scroll_range", "120"),
            ("scroll_top", "10"), ("scroll_height", "100"),
            ("scroll_pad_top", "5"), ("scroll_pad_bottom", "5"),
            ("viewport_top", "0"), ("viewport_bottom", "80"),
            ("safe_top", "10"), ("safe_bottom", "90"),
            ("target_top", "20"), ("target_bottom", "40"),
            ("screen_top", "30"), ("screen_bottom", "50"),
        )
        self.assertTrue(set(changes).issubset({key for key, _ in fields}))
        return b" ".join((key + "=" + changes.get(key, value)).encode() for key, value in fields)

    def diagnosed_scroll(self, record):
        raw = b"INSTRUMENTATION_STATUS: locklark_scroll=" + record + b"\nINSTRUMENTATION_STATUS_CODE: -2\n"
        return safe_diagnostic(raw)

    def test_clipped_phase_and_scroll_snapshot_remain_with_failure(self):
        raw = (b"INSTRUMENTATION_STATUS: locklark_stage=search\n"
               b"INSTRUMENTATION_STATUS: locklark_control_phase=clipped\n"
               b"INSTRUMENTATION_STATUS: locklark_scroll=" + self.scroll_record() + b"\n"
               b"INSTRUMENTATION_STATUS_CODE: -2\n"
               b"INSTRUMENTATION_STATUS: locklark_scroll=scroll=none\n")
        result = safe_diagnostic(raw)
        self.assertEqual(result["failed_contexts"][0]["control_phase"], "clipped")
        self.assertEqual(result["scroll"], result["failed_contexts"][0]["scroll"])
        self.assertEqual(result["scroll"]["state"], "measured")
        invalid = safe_diagnostic(raw.replace(b"phase=clipped", b"phase=clipped-private"))
        self.assertEqual(invalid["failed_contexts"][0]["control_phase"], "unknown")
        self.assertNotIn("clipped-private", str(invalid))

    def test_scroll_projection_uses_only_scroll_offset_and_range(self):
        expected = {"state": "measured", "valid": True, "clamped": False,
                    "has_range": "true", "at_start": "true", "at_end": "false"}
        self.assertEqual(self.diagnosed_scroll(self.scroll_record())["scroll"], expected)
        at_end = self.diagnosed_scroll(self.scroll_record(scroll_y="120"))["scroll"]
        self.assertEqual((at_end["has_range"], at_end["at_start"], at_end["at_end"]),
                         ("true", "false", "true"))
        no_range = self.diagnosed_scroll(self.scroll_record(scroll_range="0"))["scroll"]
        self.assertEqual((no_range["has_range"], no_range["at_start"], no_range["at_end"]),
                         ("false", "true", "true"))
        bounded = self.diagnosed_scroll(self.scroll_record(scroll_top="-999999", screen_bottom="999999"))["scroll"]
        self.assertTrue(bounded["valid"])
        self.assertEqual(bounded["state"], "measured")
        self.assertNotIn("999999", str(bounded))

    def test_scroll_projection_keeps_clamped_and_missing_ranges_unknown(self):
        offset = self.diagnosed_scroll(self.scroll_record(scroll_y="clamped"))["scroll"]
        self.assertEqual((offset["state"], offset["valid"], offset["clamped"]), ("measured", True, True))
        self.assertEqual((offset["has_range"], offset["at_start"], offset["at_end"]),
                         ("true", "unknown", "unknown"))
        span = self.diagnosed_scroll(self.scroll_record(scroll_range="clamped"))["scroll"]
        self.assertEqual((span["has_range"], span["at_start"], span["at_end"]),
                         ("unknown", "true", "unknown"))
        unrelated = self.diagnosed_scroll(self.scroll_record(screen_top="clamped"))["scroll"]
        self.assertTrue(unrelated["clamped"])
        self.assertEqual((unrelated["has_range"], unrelated["at_start"], unrelated["at_end"]),
                         ("true", "true", "false"))

    def test_scroll_projection_accepts_only_exact_none_and_detached_states(self):
        for value, state in ((b"scroll=none", "none"), (b"scroll=detached", "detached")):
            with self.subTest(state=state):
                projection = self.diagnosed_scroll(value)["scroll"]
                self.assertEqual(projection, {"state": state, "valid": True, "clamped": False,
                                              "has_range": "unknown", "at_start": "unknown", "at_end": "unknown"})
        absent = safe_diagnostic(b"INSTRUMENTATION_STATUS_CODE: -2\n")["scroll"]
        self.assertEqual((absent["state"], absent["valid"]), ("unknown", False))

    def test_scroll_projection_rejects_malformed_records_without_leaking_values(self):
        record = self.scroll_record()
        cases = (
            b"", b"scroll=other", b"scroll=none private-canary", record + b" unknown=private-canary",
            record + b" scroll_y=1", record.replace(b"scroll_span=80 ", b""),
            record.replace(b"scroll_span=80", b"scroll_y=80"),
            record.replace(b"scroll_y=0", b"scroll_y=1000000"),
            record.replace(b"scroll_y=0", b"scroll_y=-1000000"),
            record.replace(b"scroll_y=0", b"scroll_y=01"),
            record.replace(b"scroll_y=0", b"scroll_y=+1"),
            record.replace(b"scroll_y=0", b"scroll_y=private-canary"),
            b"private-canary" * 100,
        )
        for case_index, candidate in enumerate(cases):
            with self.subTest(case=case_index):
                result = self.diagnosed_scroll(candidate)
                self.assertEqual(result["scroll"], {"state": "invalid", "valid": False, "clamped": False,
                                                     "has_range": "unknown", "at_start": "unknown", "at_end": "unknown"})
                self.assertEqual(result["failed_contexts"][0]["scroll"], result["scroll"])
                self.assertNotIn("private-canary", str(result))
                self.assertNotIn("1000000", str(result))

    def test_autofill_fill_stages_are_fixed_and_unknown_ones_redacted(self):
        raw = (b"INSTRUMENTATION_STATUS: locklark_autofill_stage=dataset-visible\n"
               b"INSTRUMENTATION_STATUS_CODE: -2\n")
        self.assertEqual(safe_diagnostic(raw)["autofill_stage"], "dataset-visible")
        for accepted in ("fixture-create", "unlocked", "row-selected", "approved",
                         "dataset-clicked", "fields-filled", "no-ui-disclosure"):
            stage = safe_diagnostic(b"INSTRUMENTATION_STATUS: locklark_autofill_stage=" + accepted.encode() + b"\n")
            self.assertEqual(stage["autofill_stage"], accepted)
        invalid = safe_diagnostic(b"INSTRUMENTATION_STATUS: locklark_autofill_stage=synthetic-fixture-value\n")
        self.assertEqual(invalid["autofill_stage"], "unknown")
        self.assertNotIn("synthetic-fixture-value", str(invalid))

    def test_autofill_only_gate_counts_two_tests_exactly(self):
        passed = b"OK (2 tests)\nINSTRUMENTATION_CODE: -1\n"
        self.assertTrue(complete_pass(0, passed, 2))
        for code, raw in ((1, passed), (0, passed + b"FAILURES!!!"),
                          (0, passed + b"Process crashed"),
                          (0, passed.replace(b"2 tests", b"3 tests")),
                          (0, passed.replace(b"2 tests", b"1 test"))):
            self.assertFalse(complete_pass(code, raw, 2))

    def test_even_failed_test_output_must_be_scanned(self):
        values = ["master-fixture", "account-fixture", "username-fixture", "password-fixture", "line one private\nline two private"]
        scan_output(b"fixed failure stage only", values)
        for leak in (values[0].encode(),base64.b64encode(values[1].encode()),values[2].encode().hex().encode(), b"line two private"):
            with self.assertRaises(RuntimeFailure): scan_output(b"FAILURES!!! "+leak,values)


if __name__ == "__main__": unittest.main()
