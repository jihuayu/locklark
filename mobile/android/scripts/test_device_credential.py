import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
import device_credential_acceptance as auth
from device_credential_acceptance import credential_marker, focused_identity, validated_evidence, AcceptanceFailure, DeviceCredentialAcceptance


class DeviceCredentialHarnessTests(unittest.TestCase):
    def key_policy_output(self, validity="0"):
        fields = {"class":"org.locklark.android.DeviceKeyProtectionTest", "test":"realDeviceCapsuleUsesNonexportablePerOperationKey",
                  "locklark_key_stage":"complete", "locklark_key_assertion":"none", "locklark_key_level":"tee",
                  "locklark_key_auth_required":"true", "locklark_key_auth_validity":validity, "locklark_key_nonexportable":"true",
                  "locklark_key_cipher_exact":"true", "locklark_key_auth_types_exact":"true", "locklark_key_fresh_rejected":"true"}
        fields["locklark_key_fresh_denial"] = "keystore_authentication_required"
        return ("\n".join("INSTRUMENTATION_STATUS: " + name + "=" + value for name, value in fields.items()) +
                "\nOK (1 test)\nINSTRUMENTATION_CODE: -1\n").encode()

    def test_key_policy_accepts_only_documented_per_use_forms_with_all_strict_proofs(self):
        for validity in ("-1", "0"):
            self.assertTrue(auth.key_policy_passed(auth.key_policy_metadata(0, self.key_policy_output(validity))))
        for validity in ("1", "30", "86400", "-2", "out-of-range", "12345678-private-body"):
            self.assertFalse(auth.key_policy_passed(auth.key_policy_metadata(0, self.key_policy_output(validity))))
        for field in ("auth_required", "nonexportable", "cipher_exact", "auth_types_exact", "fresh_rejected"):
            raw = self.key_policy_output().replace(("locklark_key_" + field + "=true").encode(), ("locklark_key_" + field + "=false").encode())
            self.assertFalse(auth.key_policy_passed(auth.key_policy_metadata(0, raw)))

    def test_key_policy_diagnostic_keeps_fixed_failure_stage_and_no_private_body(self):
        raw = self.key_policy_output().replace(b"locklark_key_stage=complete", b"locklark_key_stage=auth-validity").replace(
            b"locklark_key_assertion=none", b"locklark_key_assertion=per-operation") + b"INSTRUMENTATION_STATUS: locklark_key_exception=assertion\nINSTRUMENTATION_STATUS: locklark_key_source_line=84\nFAILURES!!!\nprivate-alias-value-body\n"
        metadata = auth.key_policy_metadata(0, raw)
        self.assertFalse(auth.key_policy_passed(metadata))
        self.assertEqual(metadata["stage"], "auth-validity")
        self.assertEqual(metadata["assertion"], "per-operation")
        self.assertEqual(metadata["own_source_line"], 84)
        self.assertEqual(metadata["auth_validity"], "0")
        self.assertNotIn("private-alias-value-body", json.dumps(metadata))

    def test_key_policy_counts_identity_level_and_fresh_probe_are_required(self):
        raw = self.key_policy_output()
        bad = [raw.replace(b"OK (1 test)", b"OK (2 tests)"), raw.replace(b"DeviceKeyProtectionTest", b"private-class-body"),
               raw.replace(b"realDeviceCapsuleUsesNonexportablePerOperationKey", b"private-test-body"),
               raw + b"INSTRUMENTATION_STATUS: locklark_key_level=tee\n",
               raw.replace(b"locklark_key_fresh_denial=keystore_authentication_required", b"locklark_key_fresh_denial=none"),
               raw.replace(b"INSTRUMENTATION_STATUS: locklark_key_fresh_rejected=true\n", b"")]
        for value in bad:
            metadata = auth.key_policy_metadata(0, value)
            self.assertFalse(auth.key_policy_passed(metadata))
            self.assertNotIn("private-class-body", json.dumps(metadata))
            self.assertNotIn("private-test-body", json.dumps(metadata))

    def test_key_policy_unknown_exception_stage_and_oversized_metadata_are_sanitized(self):
        raw = self.key_policy_output("99999999") + b"INSTRUMENTATION_STATUS: locklark_key_exception=private-body\nINSTRUMENTATION_STATUS: locklark_key_stage=private-stage\nINSTRUMENTATION_STATUS: locklark_key_source_line=private-path\n"
        metadata = auth.key_policy_metadata(99999999, raw)
        self.assertFalse(auth.key_policy_passed(metadata))
        self.assertEqual(metadata["exit_code"], "outside-range")
        self.assertEqual(metadata["stage"], "unknown")
        self.assertEqual(metadata["exception"], "unknown")
        self.assertEqual(metadata["own_source_line"], 0)
        self.assertNotIn("private", json.dumps(metadata))

    def test_auth_diagnostic_requires_new_attempt_same_live_PID_and_fixed_enums(self):
        failed = b"event=failed stage=DEVICE_PROMPT code=UNAVAILABLE exception=NONE os=NO_DEVICE_CREDENTIAL\n"
        raw = b"attempt=3 pid=42 event=begin\n" + b"attempt=3 pid=42 " + failed
        self.assertEqual(auth.fresh_auth_failure(raw, 42, 2), {"phase":"DEVICE_PROMPT", "code":"UNAVAILABLE", "exception":"NONE", "os_error":"NO_DEVICE_CREDENTIAL"})
        self.assertEqual(auth.fresh_auth_failure(raw, 42, 3), {})
        self.assertEqual(auth.fresh_auth_failure(raw, 43, 0), {})
        self.assertEqual(auth.fresh_auth_failure(b"attempt=4 pid=42 " + failed, 42, 3), {})
        self.assertEqual(auth.fresh_auth_failure(raw + b"attempt=4 pid=42 event=begin\n", 42, 2), {})
        for private in (b"stage=private-factor", b"exception=private-path", b"os=private-alias"):
            poisoned = raw.replace({b"stage":b"stage=DEVICE_PROMPT", b"exception":b"exception=NONE", b"os":b"os=NO_DEVICE_CREDENTIAL"}[private.partition(b"=")[0]], private)
            self.assertEqual(auth.fresh_auth_failure(poisoned, 42, 2), {})
        self.assertNotIn("private", json.dumps(auth.fresh_auth_failure(raw + b"private-factor-body\n", 42, 2)))

    def test_device_failure_ui_is_classified_without_exposing_text(self):
        nodes = [self.node(package="org.locklark.android", text="准备设备加密未完成：固定类别", **{"class":"android.widget.TextView"})]
        self.assertEqual(auth.native_ui_state(nodes), "refused")

    def node(self, **values):
        return {"package":"com.android.systemui","enabled":"true","bounds":"[0,0][100,100]",**values}

    def credential_runner(self, snapshots, tokens):
        runner = DeviceCredentialAcceptance.__new__(DeviceCredentialAcceptance)
        runner.args = SimpleNamespace(timeout=.01)
        runner.pin = "12345678"
        runner.size = (500, 500)
        runner.stage = "enable-prompt"
        runner.trusted_window_uids = {"com.android.systemui":10123}
        runner.observe_lifecycle = lambda *args:None
        frames, focus = list(snapshots), list(tokens)
        runner.snapshot = lambda *args, **kwargs:frames.pop(0) if len(frames) > 1 else frames[0]
        calls = []
        def shell(*args, **kwargs):
            if args == ("dumpsys", "window"):
                token = focus.pop(0) if len(focus) > 1 else focus[0]
                return SimpleNamespace(stdout=("mCurrentFocus=Window{" + token + " u0 BiometricPrompt}\nWindow #0 Window{" + token + " u0 BiometricPrompt}:\n mOwnerUid=10123 showForAllUsers=false package=com.android.systemui appop=NONE\n").encode())
            calls.append(args)
            return SimpleNamespace(stdout=b"")
        runner.shell = shell
        return runner, calls

    def test_same_package_window_change_never_types_from_old_hierarchy(self):
        entry = self.node(**{"resource-id":"com.android.systemui:id/pinEntry", "class":"android.widget.EditText", "password":"true", "focused":"true"})
        unrelated = self.node(text="Notifications")
        runner, calls = self.credential_runner([[entry], [unrelated]], ["abc", "def"])
        try: runner.authenticate_pin()
        except AcceptanceFailure: pass
        self.assertFalse(any(call[:2] == ("input", "text") for call in calls))

    def test_hidden_or_offscreen_credential_entry_never_receives_PIN(self):
        for extra in ({"visible-to-user":"false"}, {"bounds":"[600,0][700,100]"}):
            entry = self.node(**{"resource-id":"com.android.systemui:id/pinEntry", "class":"android.widget.EditText", "password":"true", "focused":"true", **extra})
            runner, calls = self.credential_runner([[entry]], ["abc"])
            try: runner.authenticate_pin()
            except AcceptanceFailure: pass
            self.assertFalse(any(call[:2] == ("input", "text") for call in calls))

    def test_duplicate_credential_entries_never_receive_PIN(self):
        entry = self.node(**{"resource-id":"com.android.systemui:id/pinEntry", "class":"android.widget.EditText", "password":"true", "focused":"true"})
        runner, calls = self.credential_runner([[entry, dict(entry)]], ["abc"])
        with self.assertRaises(AcceptanceFailure): runner.authenticate_pin()
        self.assertFalse(any(call[:2] == ("input", "text") for call in calls))

    def test_hidden_marker_is_never_a_real_credential_control(self):
        node = self.node(**{"resource-id":"com.android.systemui:id/pinEntry", "visible-to-user":"false"})
        self.assertFalse(credential_marker([node], "com.android.systemui"))

    def test_stable_visible_entry_without_visibility_attribute_gets_one_PIN(self):
        entry = self.node(**{"resource-id":"com.android.systemui:id/pinEntry", "class":"android.widget.EditText", "password":"true", "focused":"true"})
        runner, calls = self.credential_runner([[entry]], ["abc"])
        runner.args.timeout = 1
        runner.authenticate_pin()
        self.assertEqual(sum(call[:2] == ("input", "text") for call in calls), 1)
        self.assertEqual(sum(call[:2] == ("input", "tap") for call in calls), 1)
        self.assertEqual(sum(call[:2] == ("input", "keyevent") for call in calls), 1)

    def test_window_change_after_entry_tap_does_not_send_PIN(self):
        entry = self.node(**{"resource-id":"com.android.systemui:id/pinEntry", "class":"android.widget.EditText", "password":"true", "focused":"true"})
        runner, calls = self.credential_runner([[entry]], ["abc", "abc", "abc", "abc", "def"])
        runner.args.timeout = 1
        with self.assertRaises(AcceptanceFailure): runner.authenticate_pin()
        self.assertEqual(sum(call[:2] == ("input", "tap") for call in calls), 1)
        self.assertFalse(any(call[:2] == ("input", "text") for call in calls))

    def test_keypad_mode_does_not_send_Enter_to_fallback_or_entry_mode(self):
        keys = [self.node(**{"resource-id":"com.android.systemui:id/key" + digit}) for digit in "0123456789"]
        entry = [self.node(**{"resource-id":"com.android.systemui:id/pinEntry", "class":"android.widget.EditText", "focused":"true"})]
        fallback = [self.node(text="认证此设备以解封本地金库授权"), self.node(text="Use PIN", **{
            "resource-id":"com.android.systemui:id/button_use_credential", "class":"android.widget.Button"})]
        for final in (entry, fallback):
            runner, calls = self.credential_runner([keys] * 9 + [final], ["abc"])
            runner.args.timeout = 1
            runner.authenticate_pin()
            self.assertEqual(sum(call[:2] == ("input", "tap") for call in calls), len(runner.pin))
            self.assertFalse(any(call[:2] == ("input", "keyevent") for call in calls))

    def test_duplicate_keypad_digit_not_used_by_PIN_still_refuses_all_input(self):
        keys = [self.node(**{"resource-id":"com.android.systemui:id/key" + digit}) for digit in "0123456789"]
        keys.append(dict(keys[9]))
        runner, calls = self.credential_runner([keys], ["abc"])
        runner.args.timeout = 1
        with self.assertRaises(AcceptanceFailure): runner.authenticate_pin()
        self.assertFalse(any(call[0] == "input" for call in calls))

    def test_failed_focus_query_does_not_inject_or_retry_PIN(self):
        entry = self.node(**{"resource-id":"com.android.systemui:id/pinEntry", "class":"android.widget.EditText", "password":"true", "focused":"true"})
        runner, calls = self.credential_runner([[entry]], ["abc"])
        original = runner.shell
        queries = 0
        def shell(*args, **kwargs):
            nonlocal queries
            if args == ("dumpsys", "window"):
                queries += 1
                if queries == 2: raise AcceptanceFailure()
            return original(*args, **kwargs)
        runner.shell = shell
        with self.assertRaises(AcceptanceFailure): runner.authenticate_pin()
        self.assertEqual(queries, 2)
        self.assertFalse(any(call[0] == "input" for call in calls))

    def test_keypad_uses_fresh_bound_control_positions_for_every_digit(self):
        original = [self.node(**{"resource-id":"com.android.systemui:id/key" + digit,
                    "bounds":f"[{i%3*100},{i//3*100}][{i%3*100+50},{i//3*100+50}]"}) for i, digit in enumerate("0123456789")]
        moved = [self.node(**{"resource-id":"com.android.systemui:id/key" + digit,
                 "bounds":f"[{i%3*100+150},{i//3*100}][{i%3*100+200},{i//3*100+50}]"}) for i, digit in enumerate("0123456789")]
        runner, calls = self.credential_runner([original, moved], ["abc"])
        runner.args.timeout = 1
        runner.authenticate_pin()
        taps = [call[2:] for call in calls if call[:2] == ("input", "tap")]
        self.assertEqual(len(taps), len(runner.pin))
        self.assertTrue(all(point in {auth.center(node) for node in moved} for point in taps))
        self.assertFalse(any(call[:2] == ("input", "text") for call in calls))

    def test_single_OS_fallback_transition_can_capture_new_credential_window(self):
        fallback = [self.node(text="认证此设备以解封本地金库授权"), self.node(text="Use PIN", **{
            "resource-id":"com.android.systemui:id/button_use_credential", "class":"android.widget.Button"})]
        entry = self.node(**{"resource-id":"com.android.systemui:id/pinEntry", "class":"android.widget.EditText", "focused":"true"})
        runner, calls = self.credential_runner([fallback, fallback, [entry]], ["abc", "abc", "abc", "abc", "def"])
        runner.args.timeout = 1
        runner.authenticate_pin()
        self.assertEqual(sum(call[:2] == ("input", "text") for call in calls), 1)
        self.assertEqual(sum(call[:2] == ("input", "tap") for call in calls), 2)

    def test_OS_fallback_is_not_reissued_if_credential_control_never_appears(self):
        fallback = [self.node(text="认证此设备以解封本地金库授权"), self.node(text="Use PIN", **{
            "resource-id":"com.android.systemui:id/button_use_credential", "class":"android.widget.Button"})]
        runner, calls = self.credential_runner([fallback], ["abc"])
        runner.args.timeout = 1
        with self.assertRaises(AcceptanceFailure): runner.authenticate_pin()
        self.assertEqual(sum(call[:2] == ("input", "tap") for call in calls), 1)
        self.assertFalse(any(call[:2] == ("input", "text") for call in calls))

    def test_final_fallback_or_different_entry_never_receives_Enter(self):
        entry = self.node(**{"resource-id":"com.android.systemui:id/pinEntry", "class":"android.widget.EditText", "focused":"true"})
        fallback = [self.node(text="认证此设备以解封本地金库授权"), self.node(text="Use PIN", **{
            "resource-id":"com.android.systemui:id/button_use_credential", "class":"android.widget.Button"})]
        different_entry = [{**entry, "resource-id":"com.android.systemui:id/passwordEntry"}]
        for final in (fallback, different_entry):
            runner, calls = self.credential_runner([[entry], [entry], [entry], final], ["abc"])
            runner.args.timeout = 1
            runner.authenticate_pin()
            self.assertEqual(sum(call[:2] == ("input", "text") for call in calls), 1)
            self.assertFalse(any(call[:2] == ("input", "keyevent") for call in calls))

    def test_unrelated_os_window_is_not_an_auth_prompt(self):
        self.assertFalse(credential_marker([self.node(text="Notifications")],"com.android.systemui"))
        self.assertFalse(credential_marker([self.node(**{"class":"android.widget.EditText","password":"true","resource-id":"com.android.settings:id/wifi_password","package":"com.android.settings"})],"com.android.settings"))
        self.assertFalse(credential_marker([self.node(**{"resource-id":"com.android.systemui:id/pinEntry"})],"org.locklark.android"))

    def test_real_credential_markers_are_required_and_enabled(self):
        pin=self.node(**{"resource-id":"com.android.systemui:id/pinEntry"})
        self.assertTrue(credential_marker([pin],"com.android.systemui"))
        self.assertFalse(credential_marker([{**pin,"enabled":"false"}],"com.android.systemui"))
        fallback=self.node(text="Use PIN", **{"resource-id":"com.android.systemui:id/button_use_credential", "class":"android.widget.Button"})
        self.assertFalse(credential_marker([fallback],"com.android.systemui"))
        self.assertTrue(credential_marker([fallback,self.node(text="认证此设备以解封本地金库授权")],"com.android.systemui"))

    def test_notification_text_and_foreign_resource_ids_are_not_credential_controls(self):
        title = self.node(text="认证此设备以解封本地金库授权")
        self.assertFalse(credential_marker([title, self.node(text="Use PIN")], "com.android.systemui"))
        self.assertFalse(credential_marker([self.node(**{"resource-id":"untrusted.app:id/pinEntry"})], "com.android.systemui"))
        self.assertFalse(credential_marker([title, self.node(text="Use PIN", **{"resource-id":"android:id/action0", "class":"android.widget.Button"})], "com.android.systemui"))

    def test_api35_lockPassword_marker_stays_bound_to_OS(self):
        lock = self.node(**{"resource-id":"com.android.systemui:id/lockPassword","class":"com.android.internal.widget.ImeAwareEditText"})
        self.assertTrue(credential_marker([lock],"com.android.systemui"))
        self.assertFalse(credential_marker([{**lock,"package":"org.locklark.android"}],"org.locklark.android"))
        self.assertFalse(credential_marker([self.node(**{"package":"com.android.settings","resource-id":"com.android.settings:id/wifi_password","class":"android.widget.EditText","password":"true"})],"com.android.settings"))
        self.assertFalse(credential_marker([{**lock,"enabled":"false"}],"com.android.systemui"))

    def test_title_only_window_requires_system_uid_record(self):
        nodes=[self.node(**{"resource-id":"com.android.systemui:id/pinEntry"})]
        raw=b"mCurrentFocus=Window{abc u0 BiometricPrompt}\nWindow #0 Window{abc u0 BiometricPrompt}:\n mOwnerUid=1000 showForAllUsers=false package=com.android.systemui appop=NONE\n"
        self.assertEqual(focused_identity(raw,nodes,{"com.android.systemui":1000}),"com.android.systemui")
        self.assertEqual(focused_identity(raw.replace(b"1000",b"10123"),nodes,{"com.android.systemui":1000}),"unknown")
        self.assertEqual(focused_identity(raw,nodes),"unknown")

    def test_title_window_uses_verified_system_package_UID_not_hardcoded_1000(self):
        nodes = [self.node(**{"resource-id":"com.android.systemui:id/pinEntry"})]
        raw = b"mCurrentFocus=Window{abc u0 BiometricPrompt}\nWindow #0 Window{abc u0 BiometricPrompt}:\n mOwnerUid=10123 showForAllUsers=false package=com.android.systemui appop=NONE\n"
        self.assertEqual(focused_identity(raw, nodes, {"com.android.systemui":10123}), "com.android.systemui")

    def test_component_like_title_does_not_override_wrong_window_owner(self):
        nodes = [self.node(**{"resource-id":"com.android.systemui:id/pinEntry"})]
        raw = b"mCurrentFocus=Window{abc u0 com.android.systemui/Fake}\nWindow #0 Window{abc u0 com.android.systemui/Fake}:\n mOwnerUid=11234 showForAllUsers=false package=untrusted.app appop=NONE\n"
        self.assertEqual(focused_identity(raw, nodes, {"com.android.systemui":10123}), "unknown")

    def test_prompt_observer_requests_full_window_dump(self):
        runner = DeviceCredentialAcceptance.__new__(DeviceCredentialAcceptance)
        runner.trusted_window_uids = {"com.android.systemui":10123}
        calls = []
        runner.shell = lambda *args: calls.append(args) or SimpleNamespace(stdout=b"")
        self.assertEqual(runner.focused_package([]), "unknown")
        self.assertEqual(calls, [("dumpsys", "window")])

    def test_system_package_UID_requires_exact_unique_record(self):
        self.assertEqual(auth.exact_package_uid(b"package:com.android.systemui.plugin uid:10099\npackage:com.android.systemui uid:10123\n", "com.android.systemui"), 10123)
        for raw in (b"", b"package:com.android.systemui.fake uid:10123\n",
                    b"package:com.android.systemui uid:10123\npackage:com.android.systemui uid:10123\n",
                    b"package:com.android.systemui uid:10123 private-body\n"):
            with self.assertRaises(AcceptanceFailure): auth.exact_package_uid(raw, "com.android.systemui")

    def test_UID_lookup_uses_system_package_filter_for_OS_identities(self):
        runner = DeviceCredentialAcceptance.__new__(DeviceCredentialAcceptance)
        calls = []
        def shell(*args):
            calls.append(args)
            return SimpleNamespace(stdout=("package:" + args[-1] + " uid:10123\n").encode())
        runner.shell = shell
        runner.load_trusted_window_uids()
        for package in auth.OS_PACKAGES:
            self.assertIn(("pm", "list", "packages", "-s", "-U", package), calls)
        self.assertIn(("pm", "list", "packages", "-U", "org.locklark.android"), calls)

    def test_missing_or_ambiguous_window_authority_never_accepts_marker(self):
        nodes = [self.node(**{"resource-id":"com.android.systemui:id/pinEntry"})]
        mapping = {"com.android.systemui":10123}
        focus = b"mCurrentFocus=Window{abc u0 private-title-body}\n"
        window = b"Window #0 Window{abc u0 private-title-body}:\n mOwnerUid=10123 showForAllUsers=false package=com.android.systemui appop=NONE\n"
        for raw in (window, focus, focus + window.replace(b"{abc", b"{def"),
                    focus + b"mCurrentFocus=Window{def u0 other}\n" + window,
                    focus + window.replace(b"package=com.android.systemui", b"package=untrusted.app")):
            identity, evidence = auth.focus_evidence(raw, nodes, mapping)
            self.assertEqual(identity, "unknown")
            self.assertTrue(evidence["credential_resource_marker"])
            self.assertNotIn("private-title-body", json.dumps(evidence))
            self.assertNotIn("untrusted.app", json.dumps(evidence))

    def test_verified_OS_window_without_actual_credential_controls_is_not_auth(self):
        raw = b"mCurrentFocus=Window{abc u0 Notifications}\nWindow #0 Window{abc u0 Notifications}:\n mOwnerUid=10123 showForAllUsers=false package=com.android.systemui appop=NONE\n"
        nodes = [self.node(text="Notifications")]
        identity, evidence = auth.focus_evidence(raw, nodes, {"com.android.systemui":10123})
        self.assertEqual(identity, "com.android.systemui")
        self.assertFalse(credential_marker(nodes, identity))
        self.assertFalse(evidence["credential_resource_marker"])
        self.assertTrue(evidence["owner_package_verified"])

    def test_disabled_queued_lock_page_does_not_refuse_prompt(self):
        queued = [self.node(package="org.locklark.android",text="打开本地金库",**{"class":"android.widget.Button","enabled":"false"})]
        prompt = [self.node(**{"resource-id":"com.android.systemui:id/pinEntry"})]
        runner = DeviceCredentialAcceptance.__new__(DeviceCredentialAcceptance)
        runner.args = SimpleNamespace(timeout=1)
        runner.size = (500, 500)
        runner.stage = "quick-prompt"
        frames = iter([queued,prompt])
        def observation(deadline):
            nodes = next(frames)
            package = "org.locklark.android" if nodes is queued else "com.android.systemui"
            return nodes, package, (b"abc", 10123, package)
        runner.bound_snapshot = observation
        observed=[]
        runner.observe_lifecycle = lambda nodes,package:observed.append((nodes,package))
        self.assertEqual(runner.os_prompt()[1],"com.android.systemui")
        self.assertEqual(observed,[(prompt,"com.android.systemui")])

    def test_timeout_after_PIN_attempt_still_cleans_only_verified_candidate(self):
        runner = DeviceCredentialAcceptance.__new__(DeviceCredentialAcceptance)
        runner.pin_attempted=True;runner.pin_owned=False;runner.pin="12345678"
        calls=[]
        runner.shell=lambda *args,**kwargs:calls.append(args) or SimpleNamespace(returncode=0)
        runner.cleanup_pin()
        self.assertIn(("locksettings","clear","--old","12345678"),calls)
        self.assertFalse(runner.pin_attempted)

    def test_locksettings_classification_never_includes_remote_text(self):
        cases = [
            (b"The device does not support lock screen - ignoring the command.", b"", "unsupported-secure-lock-screen"),
            (b"Old password 'synthetic-private-value' didn't match", b"", "credential-mismatch"),
            (b"Request throttled", b"", "credential-throttled"),
            (b"", b"java.lang.SecurityException: synthetic-private-value", "security-exception"),
            (b"", b"java.lang.IllegalStateException: synthetic-private-value", "illegal-state"),
            (b"synthetic-private-value", b"", "command-failed"),
        ]
        for stdout, stderr, expected in cases:
            with self.subTest(expected=expected):
                status = auth.locksettings_status(SimpleNamespace(returncode=255, stdout=stdout, stderr=stderr))
                self.assertEqual(status, {"exit_code":255,"classification":expected})
                self.assertNotIn("synthetic-private-value", json.dumps(status))
        self.assertEqual(auth.locksettings_status(SimpleNamespace(returncode=0, stdout=b"", stderr=b"")),
                         {"exit_code":0,"classification":"success"})

    def pin_runner(self, results, feature=True):
        runner = DeviceCredentialAcceptance.__new__(DeviceCredentialAcceptance)
        runner.pin_attempted=False; runner.pin_owned=False; runner.pin="12345678"
        runner.locksettings_diagnostic={}; runner.secure_lock_screen=None
        calls=[]
        def shell(*args,**kwargs):
            calls.append((runner.stage,args,kwargs))
            if args == ("pm","list","features"):
                return SimpleNamespace(returncode=0,stdout=b"feature:android.software.secure_lock_screen\n" if feature else b"",stderr=b"")
            return results.pop(0)
        runner.shell=shell
        return runner,calls

    def test_PIN_precondition_has_no_empty_remote_argument_and_set_has_distinct_stage(self):
        ok=SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
        runner,calls=self.pin_runner([ok,ok])
        runner.provision_pin()
        self.assertEqual([(stage,args) for stage,args,_ in calls], [
            ("pin-capabilities",("pm","list","features")),
            ("pin-empty-precondition",("locksettings","verify")),
            ("pin-set",("locksettings","set-pin","12345678"))])
        self.assertTrue(runner.pin_attempted and runner.pin_owned)

    def test_unsupported_empty_precondition_never_attempts_PIN_change(self):
        unsupported=SimpleNamespace(returncode=255,stdout=b"",stderr=b"The device does not support lock screen - ignoring the command.")
        runner,calls=self.pin_runner([unsupported],feature=False)
        with self.assertRaises(AcceptanceFailure): runner.provision_pin()
        self.assertEqual(runner.stage,"pin-empty-precondition")
        self.assertFalse(runner.pin_attempted or runner.pin_owned or runner.secure_lock_screen)
        self.assertEqual(runner.locksettings_diagnostic,{"operation":"verify-empty","exit_code":255,"classification":"unsupported-secure-lock-screen"})
        self.assertFalse(any(args[:2]==("locksettings","set-pin") for _,args,_ in calls))

    def test_successful_verify_without_advertised_secure_lock_screen_never_mutates(self):
        ok=SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
        runner,calls=self.pin_runner([ok,ok],feature=False)
        with self.assertRaises(AcceptanceFailure): runner.provision_pin()
        self.assertEqual(runner.stage,"pin-empty-precondition")
        self.assertFalse(runner.pin_attempted or runner.pin_owned)
        self.assertFalse(any(args[:2]==("locksettings","set-pin") for _,args,_ in calls))

    def test_failed_PIN_set_stays_owned_attempt_for_exact_cleanup(self):
        ok=SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
        failed=SimpleNamespace(returncode=255,stdout=b"",stderr=b"java.lang.SecurityException: synthetic-private-value")
        runner,_=self.pin_runner([ok,failed])
        with self.assertRaises(AcceptanceFailure): runner.provision_pin()
        self.assertEqual(runner.stage,"pin-set")
        self.assertTrue(runner.pin_attempted)
        self.assertFalse(runner.pin_owned)
        self.assertEqual(runner.locksettings_diagnostic["classification"],"security-exception")

    def test_unknown_credential_is_never_cleared(self):
        runner = DeviceCredentialAcceptance.__new__(DeviceCredentialAcceptance)
        runner.pin_attempted=True;runner.pin_owned=False;runner.pin="12345678"
        calls=[]
        def shell(*args,**kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=1 if args[0]=="locksettings" else 0)
        runner.shell=shell
        with self.assertRaises(AcceptanceFailure):runner.cleanup_pin()
        self.assertFalse(any(args[:2]==("locksettings","clear") for args in calls))

    def fixture(self, root):
        run=root/"android-host-ui-owned";run.mkdir(mode=0o700)
        key="LL1-"+"A"*26
        fixture={"master":"MasterFixture","key":key,"items":[{"id":"a"*32,"revision":"b"*64,"title":"HostFirst","password":"FirstPassword"},{"id":"c"*32,"revision":"d"*64,"title":"HostSecond","password":"SecondPassword"}]}
        for name,value in (("result.json",{"success":True,"stage":"complete","checks":["full_controller_and_logcat_outputs_contain_no_secret_canaries"]}),
                           ("expected-private.json",fixture),("canaries.json",["MasterFixture",key,"FirstPassword","SecondPassword"])):
            path=run/name;path.write_text(json.dumps(value));path.chmod(0o600)
        return run

    def test_evidence_is_exactly_one_private_completed_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);run=self.fixture(root)
            self.assertEqual(validated_evidence(root)[0],run)
            (root/"android-host-ui-other").mkdir(mode=0o700)
            with self.assertRaises(AcceptanceFailure):validated_evidence(root)

    def test_incomplete_or_public_fixture_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);run=self.fixture(root)
            (run/"expected-private.json").chmod(0o644)
            with self.assertRaises(AcceptanceFailure):validated_evidence(root)
            (run/"expected-private.json").chmod(0o600)
            (run/"result.json").write_text(json.dumps({"success":False,"stage":"create"}))
            with self.assertRaises(AcceptanceFailure):validated_evidence(root)


if __name__=="__main__":unittest.main()
