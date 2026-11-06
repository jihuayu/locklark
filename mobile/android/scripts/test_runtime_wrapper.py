import base64
import unittest
from test_emulator import scan_output, complete_pass, RuntimeFailure, safe_diagnostic


class RuntimeWrapperTests(unittest.TestCase):
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
        passed = b"OK (2 tests)\nINSTRUMENTATION_CODE: -1\n"
        self.assertTrue(complete_pass(0, passed))
        for code, raw in ((1, passed), (0,b"INSTRUMENTATION_CODE: -1"), (0,passed+b"FAILURES!!!"), (0,passed.replace(b"2 tests",b"0 tests")), (0,passed+b"Process crashed")):
            self.assertFalse(complete_pass(code, raw))

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

    def test_even_failed_test_output_must_be_scanned(self):
        values = ["master-fixture", "account-fixture", "username-fixture", "password-fixture", "line one private\nline two private"]
        scan_output(b"fixed failure stage only", values)
        for leak in (values[0].encode(),base64.b64encode(values[1].encode()),values[2].encode().hex().encode(), b"line two private"):
            with self.assertRaises(RuntimeFailure): scan_output(b"FAILURES!!! "+leak,values)


if __name__ == "__main__": unittest.main()
