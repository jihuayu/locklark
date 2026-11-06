"""Pure controller/privacy/oracle tests; these never claim Android UI evidence."""

import base64
import contextlib
import io
import pathlib
import os
import subprocess
import tempfile
import types
import unittest
import venv
from unittest import mock

import mobile_android_acceptance as acceptance


class SafetyTests(unittest.TestCase):
    def test_manual_password_mode_is_enabled_before_keyboard_input(self):
        controller = mock.Mock(spec=acceptance.AndroidAcceptance)
        controller.locate.return_value = {"checked": "true"}
        generated_mode = True
        sequence = []

        def tap(label, *, class_name):
            nonlocal generated_mode
            self.assertTrue(label == "生成强密码" and class_name == "android.widget.CheckBox")
            generated_mode = False
            sequence.append("manual-mode")

        def enter(label, value):
            if generated_mode:
                raise AssertionError("disabled password input must not receive keyboard input")
            self.assertTrue(label == "登录密码" and value == "UnitSyntheticPassword")
            sequence.append("password-input")

        controller.tap.side_effect = tap
        controller.enter.side_effect = enter
        # Negative oracle: the original reversed order is refused.
        with self.assertRaises(AssertionError):
            enter("登录密码", "UnitSyntheticPassword")
        acceptance.AndroidAcceptance.enter_manual_password(controller, "UnitSyntheticPassword")
        self.assertEqual(sequence, ["manual-mode", "password-input"])
        controller.locate.assert_called_once_with("生成强密码", class_name="android.widget.CheckBox")

    def test_unexpected_manual_mode_default_is_not_blindly_toggled(self):
        controller = mock.Mock(spec=acceptance.AndroidAcceptance)
        controller.locate.return_value = {"checked": "false"}
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.AndroidAcceptance.enter_manual_password(controller, "UnitSyntheticPassword")
        controller.tap.assert_not_called()
        controller.enter.assert_not_called()

    def test_wrong_factor_requires_the_specific_public_unlock_refusal(self):
        status = {"package": acceptance.PACKAGE, "class": "android.widget.TextView", "enabled": "true",
                  "text": "解锁未完成：认证被取消或完整因素未通过验证。"}
        self.assertTrue(acceptance.is_unlock_refusal([status]))
        for text in ("操作未完成：认证失败", "保存未完成：目标已变化", "提示：解锁未完成：认证失败", ""):
            with self.subTest(text=text):
                self.assertFalse(acceptance.is_unlock_refusal([{**status, "text": text}]))
        self.assertFalse(acceptance.is_unlock_refusal([{**status, "package": "other.app"}]))
        self.assertFalse(acceptance.is_unlock_refusal([{**status, "class": "android.widget.EditText"}]))

    def test_explicit_emulator_reset_required_before_adb(self):
        for serial, reset in (("device-1234", True), ("emulator-5556", False), ("emulator-5556;reboot", True)):
            with self.subTest(serial=serial), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.validate_target(serial, reset)
        acceptance.validate_target("emulator-5556", True)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.validate_target("emulator-5556", True, "/python", None)

    def test_rejected_target_runs_no_adb_and_prints_fixed_stage(self):
        with mock.patch.object(acceptance, "AndroidAcceptance") as constructor, contextlib.redirect_stdout(io.StringIO()) as output:
            result = acceptance.main(["--adb", "/not-used", "--serial", "device-secret", "--apk", "/not-used", "--reset-test-app"])
        self.assertEqual(result, 1)
        constructor.assert_not_called()
        self.assertEqual(output.getvalue(), "FAIL: Android host UI at prerequisites\n")

    def test_failure_never_renders_exception_or_secret(self):
        secret = "DoNotPrintSyntheticFactor998877"

        class FailedController:
            stage = "otp"
            root = pathlib.Path("/private/controller-evidence")
            checks = []
            diagnosis = {"activity": secret, "foreground": "app", "control": secret,
                         "wait": "background-stopped", "ime": "shown", "extra": secret}

            def __init__(self, _):
                pass

            def setup(self):
                raise subprocess.TimeoutExpired(["input", "text", secret], 1, output=secret.encode(), stderr=secret.encode())

            def close(self):
                pass

            def scan(self):
                pass

            def write_private(self, *_):
                pass

        with mock.patch.object(acceptance, "AndroidAcceptance", FailedController), contextlib.redirect_stdout(io.StringIO()) as output:
            result = acceptance.main(["--adb", "/unused", "--serial", "emulator-5556", "--apk", "/unused", "--reset-test-app"])
        self.assertEqual(result, 1)
        self.assertNotIn(secret, output.getvalue())
        self.assertEqual(output.getvalue(), "FAIL: Android host UI at otp\nFixed Android host diagnosis: {\"activity\": \"unknown\", \"control\": \"unknown\", \"foreground\": \"app\", \"identity\": \"unknown\", \"ime\": \"shown\", \"wait\": \"background-stopped\"}\nPrivate Android host UI evidence: /private/controller-evidence\n")

    def test_command_does_not_log_secret_argv_but_detects_echo(self):
        with tempfile.TemporaryDirectory() as root:
            args = types.SimpleNamespace(adb="/unused-adb", serial="emulator-5556", artifacts=root)
            controller = acceptance.AndroidAcceptance(args)
            secret = controller.record("SyntheticArgumentDoNotEcho4422")
            try:
                empty = subprocess.CompletedProcess([], 0, b"", b"")
                with mock.patch.object(acceptance.subprocess, "run", return_value=empty):
                    controller.shell("input", "text", secret)
                controller.scan()
                self.assertNotIn(secret.encode(), (controller.root / "controller.log").read_bytes())
                echoed = subprocess.CompletedProcess([], 1, b"", secret.encode())
                with mock.patch.object(acceptance.subprocess, "run", return_value=echoed), self.assertRaises(acceptance.AcceptanceFailure):
                    controller.shell("input", "text", secret)
                with self.assertRaises(acceptance.AcceptanceFailure):
                    controller.scan()
            finally:
                controller.close()

    def test_remote_folder_cleanup_is_owned_before_launch(self):
        with tempfile.TemporaryDirectory() as root:
            apk = pathlib.Path(root) / "fixture.apk"
            apk.write_bytes(b"unused unit fixture")
            args = types.SimpleNamespace(adb="/unused-adb", serial="emulator-5556", artifacts=root,
                                         reset_test_app=True, peer=None, cli=None, apk=str(apk))
            controller = acceptance.AndroidAcceptance(args)
            success = subprocess.CompletedProcess([], 0, b"1\n", b"")
            try:
                with mock.patch.object(controller, "shell", return_value=success), \
                     mock.patch.object(controller, "command", return_value=success), \
                     mock.patch.object(controller, "dimensions", return_value=(720, 1280)), \
                     mock.patch.object(controller, "start_logcat", side_effect=acceptance.AcceptanceFailure), \
                     mock.patch.object(controller, "launch") as launch, \
                     self.assertRaises(acceptance.AcceptanceFailure):
                    controller.setup()
                launch.assert_not_called()
                self.assertTrue(controller.remote_owned)
                with mock.patch.object(controller, "shell", return_value=success) as shell:
                    controller.close()
                shell.assert_any_call("rm", "-rf", controller.remote, required=False)
            finally:
                controller.close()


class IndependentOracleTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX venv interpreter symlink regression")
    def test_peer_uses_configured_virtualenv_instead_of_base_interpreter(self):
        with tempfile.TemporaryDirectory() as root:
            environment = pathlib.Path(root) / "peer-environment"
            venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
            python = environment / "bin/python"
            self.assertTrue(python.is_symlink())
            result = subprocess.run([str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertTrue(result.returncode == 0)
            site = pathlib.Path(result.stdout.decode().strip())
            (site / "locklark_private_peer_probe.py").write_text("available = True\n")
            code = "import locklark_private_peer_probe; assert locklark_private_peer_probe.available"
            configured = subprocess.run([acceptance.peer_executable(python), "-c", code],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            bypassed = subprocess.run([str(python.resolve()), "-c", code],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertTrue(configured.returncode == 0)
            self.assertTrue(bypassed.returncode != 0)

    def test_rfc6238_vector_and_incorrect_code_rejected(self):
        seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(acceptance.otp_code(seed, 59 // 30, 8), "94287082")
        acceptance.verify_otp(seed, "287082", 59, 59)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.verify_otp(seed, "287083", 59, 59)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.verify_otp(seed, "287082", 59, 91)

    @staticmethod
    def audit_fixture():
        disclosure = ("item.desktop.show.password", "item-one", "revision-one")
        mutation = ("item.edit.password", "item-one", "revision-one")
        events = [
            {"action": "vault.create", "result": "succeeded"},
            {"action": "item.add", "item_id": "item-one", "result": "succeeded"},
            {"action": "item.generate", "item_id": "generated", "result": "succeeded"},
            {"action": "item.list", "result": "succeeded"},
            {"action": "audit.list", "result": "succeeded"},
            {"action": disclosure[0], "item_id": disclosure[1], "base_revision": disclosure[2], "result": "intent"},
            {"action": mutation[0], "item_id": mutation[1], "base_revision": mutation[2], "result": "succeeded"},
        ]
        return events, disclosure, mutation

    def test_exact_revision_and_disclosure_count_are_required(self):
        events, disclosure, mutation = self.audit_fixture()
        acceptance.verify_audit(events, [disclosure], [mutation], "generated")
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.verify_audit(events, [disclosure, disclosure], [mutation], "generated")
        altered = [dict(event) for event in events]
        altered[-1]["base_revision"] = "other-revision"
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.verify_audit(altered, [disclosure], [mutation], "generated")

    def test_unexpected_duplicate_intent_and_success_are_rejected(self):
        events, disclosure, mutation = self.audit_fixture()
        for extra in (dict(events[-2]), dict(events[-1]),
                      {"action": disclosure[0], "item_id": disclosure[1], "base_revision": disclosure[2], "result": "succeeded"}):
            with self.subTest(action=extra["action"], result=extra["result"]), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.verify_audit(events + [extra], [disclosure], [mutation], "generated")

    def test_extra_item_mutations_are_rejected_for_known_and_foreign_ids(self):
        events, disclosure, mutation = self.audit_fixture()
        for item in ("item-one", "generated", "unexpected-third-item"):
            extra = {"action": "item.edit.otp", "item_id": item, "base_revision": "other-revision", "result": "succeeded"}
            with self.subTest(item=item), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.verify_audit(events + [extra], [disclosure], [mutation], "generated")

    def test_only_explicit_itemless_cli_export_intent_is_permitted(self):
        events, disclosure, mutation = self.audit_fixture()
        exported = events + [{"action": "vault.export.kdbx", "result": "intent"},
                             {"action": "audit.list", "result": "succeeded"}]
        acceptance.verify_audit(exported, [disclosure], [mutation], "generated", expected_exports=1, expected_audits=2)
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.verify_audit(exported, [disclosure], [mutation], "generated")
        altered = [dict(event) for event in exported]
        altered[-2]["item_id"] = "item-one"
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.verify_audit(altered, [disclosure], [mutation], "generated", expected_exports=1, expected_audits=2)

    def test_encoded_leaks_fail_without_returning_matched_value(self):
        value = "SyntheticSecretWithSymbols-_9988"
        for raw in (value.encode(), base64.b64encode(value.encode()), value.encode().hex().encode()):
            with self.subTest(encoding=len(raw)), self.assertRaises(acceptance.AcceptanceFailure) as failure:
                acceptance.scan_public(raw, [value])
            self.assertEqual(str(failure.exception), "")
        acceptance.scan_public(b"public fixed stage and booleans", [value])
        acceptance.scan_public(b"time 1234567890", ["123456"])
        with self.assertRaises(acceptance.AcceptanceFailure):
            acceptance.scan_public(b"OTP=123456\n", ["123456"])


class BackgroundTransitionTests(unittest.TestCase):
    @staticmethod
    def activity_dump(state, foreground="com.google.android.apps.nexuslauncher/.NexusLauncherActivity"):
        top_token, top_task = ("abc123", "4") if foreground == acceptance.COMPONENT else ("fed789", "1")
        return ("ACTIVITY MANAGER ACTIVITIES\n"
                " * Task{app-task}\n"
                "   * Hist #0: ActivityRecord{abc123 u0 org.locklark.android/.MainActivity t4}\n"
                "     packageName=org.locklark.android\n"
                f"     state={state} stopped={'true' if state == 'STOPPED' else 'false'}\n"
                f" topResumedActivity=ActivityRecord{{{top_token} u0 {foreground} t{top_task}}}\n").encode()

    @staticmethod
    def locked_nodes():
        return [{"package": acceptance.PACKAGE, "class": kind, "text": "", "content-desc": label,
                 "enabled": "true", "bounds": "[0,0][100,20]"}
                for label, kind in (("打开本地金库", "android.widget.Button"), ("主密码", "android.widget.EditText"),
                                    ("Secret Key", "android.widget.EditText"))]

    def test_launcher_visibility_and_pause_do_not_count_as_actual_stop(self):
        for state in ("PAUSED", "STOPPING", "STOPPED"):
            parsed = acceptance.lifecycle_state(self.activity_dump(state))
            self.assertEqual(parsed, {"activity": state.lower(), "foreground": "launcher"})
            self.assertEqual(acceptance.background_is_stopped(parsed), state == "STOPPED")
        for state in ({"activity": "stopped", "foreground": "app"},
                      {"activity": "stopped", "foreground": "unknown"},
                      {"activity": "destroyed", "foreground": "launcher"}):
            self.assertFalse(acceptance.background_is_stopped(state))

    def test_other_task_state_cannot_supply_missing_app_stopped_evidence(self):
        raw = (b" * Hist #0: ActivityRecord{app u0 org.locklark.android/.MainActivity t4}\n"
               b" * Task{other-task}\n state=STOPPED\n"
               b" topResumedActivity=ActivityRecord{other u0 com.android.launcher3/.Launcher t1}\n")
        parsed = acceptance.lifecycle_state(raw)
        self.assertEqual(parsed, {"activity": "unknown", "foreground": "launcher"})
        self.assertFalse(acceptance.background_is_stopped(parsed))

    def test_single_home_waits_for_stop_before_single_relaunch_and_locked_form(self):
        controller = object.__new__(acceptance.AndroidAcceptance)
        controller.args = types.SimpleNamespace(timeout=10)
        controller.diagnosis = acceptance.safe_host_diagnosis({})
        controller.canaries = ["PrivateBackgroundFixture"]
        controller.write_private = mock.Mock()
        sequence = []
        controller.shell = mock.Mock(side_effect=lambda *a, **k: sequence.append("home"))
        states = iter([("original-resumed", {"activity": "resumed", "foreground": "app"}),
                       ("paused", {"activity": "paused", "foreground": "launcher"}),
                       ("stopped", {"activity": "stopped", "foreground": "launcher"}),
                       ("returned-resumed", {"activity": "resumed", "foreground": "app"})])

        def observe(_):
            label, state = next(states)
            controller.last_activity_records = [{"token": "abc123", "task": "4", "state": state["activity"]}]
            controller.last_foreground_identity = ("abc123", "4") if state["foreground"] == "app" else None
            sequence.append(label)
            return state

        def locked(predicate, *, deadline):
            sequence.append("locked-form")
            self.assertGreater(deadline, acceptance.time.monotonic())
            nodes = self.locked_nodes()
            self.assertIs(predicate(nodes), nodes)
            self.assertIsNone(predicate(nodes[:-1]))
            return nodes

        controller.observe_activity_state = mock.Mock(side_effect=observe)
        controller.launch = mock.Mock(side_effect=lambda **k: sequence.append("launch"))
        controller.wait = mock.Mock(side_effect=locked)
        with mock.patch.object(acceptance.time, "sleep"):
            controller.background_and_relaunch()
        self.assertEqual(sequence, ["original-resumed", "home", "paused", "stopped", "launch", "returned-resumed", "locked-form"])
        self.assertEqual(controller.shell.call_count, 1)
        self.assertEqual(controller.shell.call_args.args, ("input", "keyevent", "KEYCODE_HOME"))
        controller.launch.assert_called_once()
        self.assertLessEqual(controller.launch.call_args.kwargs["timeout"], controller.args.timeout)
        self.assertTrue(controller.launch.call_args.kwargs["reuse_existing"])
        self.assertEqual(controller.diagnosis["identity"], "resumed-match")

    def test_timeout_does_not_retry_home_or_relaunch_without_stop_evidence(self):
        controller = object.__new__(acceptance.AndroidAcceptance)
        controller.args = types.SimpleNamespace(timeout=0.001)
        controller.diagnosis = acceptance.safe_host_diagnosis({})
        controller.write_private = mock.Mock()
        controller.shell, controller.launch, controller.wait = mock.Mock(), mock.Mock(), mock.Mock()
        def observe(_):
            initial = controller.diagnosis["wait"] == "capture-original"
            state = {"activity": "resumed" if initial else "paused", "foreground": "app" if initial else "launcher"}
            controller.last_activity_records = [{"token": "abc123", "task": "4", "state": state["activity"]}]
            controller.last_foreground_identity = ("abc123", "4") if initial else None
            return state

        controller.observe_activity_state = mock.Mock(side_effect=observe)
        with mock.patch.object(acceptance.time, "sleep"), self.assertRaises(acceptance.AcceptanceFailure):
            controller.background_and_relaunch()
        self.assertEqual(controller.shell.call_count, 1)
        controller.launch.assert_not_called()
        controller.wait.assert_not_called()

    def test_public_diagnosis_is_only_fixed_control_and_lifecycle_enums(self):
        secret = "PrivateDiagnosticFixture"
        value = acceptance.safe_host_diagnosis({"activity": secret, "foreground": "launcher", "control": secret,
                                                "wait": "background-stopped", "ime": secret, "extra": secret})
        self.assertEqual(value, {"activity": "unknown", "foreground": "launcher", "control": "unknown",
                                 "wait": "background-stopped", "identity": "unknown", "ime": "unknown"})
        self.assertNotIn(secret, str(value))
        nodes = self.locked_nodes()
        self.assertEqual(acceptance.ui_control_state(nodes), "unlock-ready")
        nodes[0]["enabled"] = "false"
        self.assertEqual(acceptance.ui_control_state(nodes), "unlock-busy")

    def test_same_task_and_activity_token_are_parsed_without_public_identifier_output(self):
        records = acceptance.app_activity_records(self.activity_dump("RESUMED", acceptance.COMPONENT))
        self.assertEqual(records, [{"token": "abc123", "task": "4", "state": "resumed"}])
        self.assertEqual(acceptance.top_activity_identity(self.activity_dump("RESUMED", acceptance.COMPONENT)), ("abc123", "4"))
        safe = acceptance.safe_host_diagnosis({"identity": records[0]["token"], "task": records[0]["task"]})
        self.assertEqual(safe["identity"], "unknown")
        self.assertNotIn("abc123", str(safe))

    def test_new_instance_or_task_cannot_substitute_for_original_after_home(self):
        for token, task, destroyed in (("def456", "4", False), ("abc123", "5", False), ("def456", "4", True)):
            with self.subTest(token=token, task=task, destroyed=destroyed):
                controller = object.__new__(acceptance.AndroidAcceptance)
                controller.args = types.SimpleNamespace(timeout=10)
                controller.diagnosis = acceptance.safe_host_diagnosis({})
                controller.shell, controller.launch, controller.wait, controller.write_private = mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock()

                def observe(_):
                    phase = controller.diagnosis["wait"]
                    if phase == "capture-original":
                        controller.last_activity_records = [{"token": "abc123", "task": "4", "state": "resumed"}]
                        controller.last_foreground_identity = ("abc123", "4")
                        return {"activity": "resumed", "foreground": "app"}
                    if phase == "background-stopped":
                        controller.last_activity_records = [{"token": "abc123", "task": "4", "state": "stopped"}]
                        controller.last_foreground_identity = None
                        return {"activity": "stopped", "foreground": "launcher"}
                    controller.last_activity_records = [{"token": "abc123", "task": "4", "state": "destroyed" if destroyed else "stopped"},
                                                        {"token": token, "task": task, "state": "resumed"}]
                    controller.last_foreground_identity = token, task
                    return {"activity": "resumed", "foreground": "app"}

                controller.observe_activity_state = mock.Mock(side_effect=observe)
                with self.assertRaises(acceptance.AcceptanceFailure):
                    controller.background_and_relaunch()
                self.assertEqual(controller.shell.call_count, 1)
                controller.launch.assert_called_once()
                controller.wait.assert_not_called()
                self.assertEqual(controller.diagnosis["identity"], "destroyed" if destroyed else "changed")

    def test_relaunch_requests_existing_record_once_without_clear_or_stop(self):
        controller = object.__new__(acceptance.AndroidAcceptance)
        controller.shell = mock.Mock()
        controller.launch(timeout=7, reuse_existing=True)
        controller.shell.assert_called_once_with("am", "start", "-W", "--activity-reorder-to-front", "--activity-single-top",
                                                 "-n", acceptance.COMPONENT, timeout=7)

    def test_top_resumed_record_must_match_the_resumed_history_record(self):
        controller = object.__new__(acceptance.AndroidAcceptance)
        controller.diagnosis = acceptance.safe_host_diagnosis({})
        controller.last_activity_records = [{"token": "abc123", "task": "4", "state": "resumed"}]
        controller.last_foreground_identity = "def456", "4"
        with self.assertRaises(acceptance.AcceptanceFailure):
            controller.resumed_activity_identity()
        self.assertEqual(controller.diagnosis["identity"], "changed")

    def test_explicit_null_top_field_cannot_fall_back_to_stale_legacy_app(self):
        history = self.activity_dump("RESUMED", acceptance.COMPONENT).split(b" topResumedActivity", 1)[0]
        stale = b" mResumedActivity: ActivityRecord{abc123 u0 org.locklark.android/.MainActivity t4}\n"
        for field in (b"mTopResumedActivity", b"topResumedActivity"):
            with self.subTest(field=field):
                raw = history + b" " + field + b"=null\n" + stale
                self.assertEqual(acceptance.top_resumed_record(raw), (None, True))
                self.assertIsNone(acceptance.top_activity_identity(raw))
                self.assertEqual(acceptance.lifecycle_state(raw)["foreground"], "none")

    def test_legacy_fallback_requires_absent_not_unknown_or_conflicting_top_field(self):
        legacy = b" mResumedActivity: ActivityRecord{abc123 u0 org.locklark.android/.MainActivity t4}\n"
        self.assertEqual(acceptance.top_activity_identity(legacy), ("abc123", "4"))
        for top in (b" mTopResumedActivity=<unavailable>\n", b" topResumedActivity=\n",
                    b" mTopResumedActivity=null\n topResumedActivity=ActivityRecord{abc123 u0 org.locklark.android/.MainActivity t4}\n"):
            with self.subTest(top=top):
                self.assertEqual(acceptance.top_resumed_record(top + legacy), (None, False))
                self.assertIsNone(acceptance.top_activity_identity(top + legacy))
                self.assertEqual(acceptance.lifecycle_state(top + legacy)["foreground"], "unknown")


if __name__ == "__main__":
    unittest.main()
