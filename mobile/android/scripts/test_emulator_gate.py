import contextlib
import importlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import test_emulator as gate


CANARIES = ["MasterFixture", "AccountFixture", "UserFixture", "FirstPassword", "LL1-SECRETCANARY"]
RAWTEXT = "raw-stderr-adb-clean-5572-factor-fixture"
ERROR = "FAIL: Android native runtime validation at "
RESTORE = "Android autofill setting restore failed: "
RESTORE_STAGE = "autofill-setting-restore"
# Captured at import, before gate.subprocess is patched for any test.
CLIENT_TIMEOUT = subprocess.TimeoutExpired
ENVIRONMENT = {"ANDROID_HOME": "/nonexistent-sdk", "ANDROID_SERIAL": "emulator-5572",
               "LOCKLARK_ANDROID_TEST_RESET": "1", "LOCKLARK_ANDROID_AUTOFILL_ONLY": "0"}
# The Autofill-only mode is read at import and bound to its own owned AVD.
AUTOFILL_ENVIRONMENT = {**ENVIRONMENT, "LOCKLARK_ANDROID_AUTOFILL_ONLY": "1",
                        "LOCKLARK_ANDROID_TEST_RESET": "1"}


class FakeDevice:
    """Fake adb for the real gate.main(); the same object serves the finally restore.

    Only gate.subprocess.run/Popen (plus the exception class it catches) are
    patched, for the duration of one main() call. tempfile.mkdtemp stays real;
    the private state directory it creates is removed in close().
    """

    PRIOR = "com.example.prior/com.example.prior.Service"

    def __init__(self, *, runtime_fails, restore_fails):
        self.runtime_fails = runtime_fails
        self.restore_fails = restore_fails
        # A prior service exists, so the owned restore is a put that can fail.
        self.setting = self.PRIOR
        self.previous_tempdir = tempfile.tempdir
        self.root = Path(tempfile.mkdtemp(prefix="locklark-gate-test-"))
        tempfile.tempdir = str(self.root)

    def close(self):
        tempfile.tempdir = self.previous_tempdir
        shutil.rmtree(self.root, ignore_errors=True)

    def reply(self, stdout=b"", failed=False, exact=False):
        # exact: the real command's output is that value alone (getprop, settings
        # get, canary record). Otherwise the fake carries raw device text too.
        return mock.Mock(returncode=1 if failed else 0, stdout=stdout if exact else stdout + RAWTEXT.encode() + b"\n",
                         stderr=RAWTEXT.encode() + b" stderr\n")

    def run(self, arguments, **kwargs):
        arguments = list(arguments)[3:]           # [adb, "-s", serial, ...] -> device command
        if arguments[:3] == ["shell", "settings", "put"]:
            failed = self.restore_fails and not arguments[-1].startswith("org.locklark")
            if not failed:
                self.setting = arguments[-1]
            return self.reply(failed=failed)
        if arguments[:3] == ["shell", "settings", "delete"]:
            self.setting = ""
            return self.reply()
        if arguments[:3] == ["shell", "settings", "get"]:
            return self.reply((self.setting or "null").encode() + b"\n", exact=True)
        if arguments[:2] == ["shell", "getprop"]:
            value = {"ro.build.version.sdk": gate.AUTOFILL_API.encode()}.get(arguments[2], b"1")
            return self.reply(value + b"\n", exact=True)
        if arguments[:3] == ["shell", "service", "check"]:
            return self.reply(b"Service package: found\n", exact=True)
        if arguments[0] == "install":
            return self.reply()
        if arguments[:3] == ["shell", "am", "instrument"]:
            if self.runtime_fails:
                # Non-zero instrumentation reply, as when the run itself fails.
                return self.reply(b"INSTRUMENTATION_STATUS_CODE: -2\nFAILURES!!!\n", failed=True)
            return self.reply(b"OK (6 tests)\nINSTRUMENTATION_CODE: -1\n")
        if arguments[:2] == ["shell", "am"]:
            return self.reply()
        if arguments[:2] == ["exec-out", "run-as"]:
            return self.reply(json.dumps(CANARIES).encode() + b"\n", exact=True)
        return self.reply()

    def facade(self):
        """subprocess-like facade the gate calls; the real module is untouched."""
        return mock.Mock(PIPE=-1, STDOUT=-2, TimeoutExpired=CLIENT_TIMEOUT,
                         run=self.run, Popen=self.popen)

    def popen(self, arguments, **kwargs):
        return mock.Mock(stdout=io.BytesIO(RAWTEXT.encode() + b"\n"), terminate=mock.Mock(),
                         kill=mock.Mock(), wait=mock.Mock(return_value=0))


class CleanDevice(FakeDevice):
    """The same fake device, answering exactly like adb so a run goes deeper.

    getprop, service check and the instrument reply return exact adb output,
    so a run the base fake fails early fails in run_gate instead. Other
    commands answer clean; the cleanup never needs this device.
    """

    def __init__(self, runtime_fails, *, cleanup_fails=False):
        # cleanup_fails: the restore's own write/readback is rejected.
        super().__init__(runtime_fails=runtime_fails, restore_fails=False)
        self.cleanup_fails = cleanup_fails
        self.commands = []

    def run(self, arguments, **kwargs):
        command = list(arguments)[3:]
        what = tuple(command[:3])
        self.commands.append(command)
        if command[:2] == ["shell", "getprop"]:
            return self.reply({"ro.build.version.sdk": gate.AUTOFILL_API.encode()}.get(command[2], b"1") + b"\n",
                              exact=True)
        if what == ("shell", "service", "check"):
            return self.reply(b"Service package: found\n", exact=True)
        # The base fake's raw text would fail the canary scan before the
        # instrument reply is judged, so every other command is answered clean.
        if what == ("shell", "settings", "put") and self.cleanup_fails and not command[-1].startswith("org.locklark"):
            return self.reply(failed=True)
        if what == ("shell", "settings", "put"):
            self.setting = command[-1]
            return self.reply()
        if what == ("shell", "settings", "get"):
            # What the run itself wrote, read back the way adb prints it.
            return self.reply((self.setting or "null").encode() + b"\n", exact=True)
        if (command[:2], command[-1]) == (["exec-out", "run-as"], "cache/instrumentation-canaries.json"):
            # The record the test APK writes; cleaning is a device-side test.
            return self.reply(json.dumps(CANARIES).encode() + b"\n", exact=True)
        if what == ("shell", "am", "instrument"):
            if self.runtime_fails:
                return self.reply(b"INSTRUMENTATION_STATUS_CODE: -2\nFAILURES!!!\n", failed=True)
            return self.reply(b"OK (6 tests)\nINSTRUMENTATION_CODE: -1\n")
        return self.reply()


def screen(*values):
    """Render a print call the way the real print would."""
    return " ".join(map(str, values))


class GateOutcomeTests(unittest.TestCase):
    def run_gate(self, *, runtime_fails, restore_fails):
        """Return (return value or raised name, page, state dir)."""
        device = FakeDevice(runtime_fails=runtime_fails, restore_fails=restore_fails)
        self.addCleanup(device.close)
        result, page = self.attempt(device)
        runs = list(device.root.glob("locklark-android-runtime-*"))
        self.assertEqual(len(runs), 1)
        return result, page, runs[0]

    def attempt(self, device):
        printed = []
        try:
            with mock.patch.dict(os.environ, ENVIRONMENT), \
                    mock.patch.object(gate, "subprocess", new=device.facade(), create=True), \
                    mock.patch("builtins.print", side_effect=lambda *a: printed.append(screen(*a))):
                result = gate.main()
            page = list(printed)
        except gate.RuntimeFailure:
            # main() re-raises the original, and the __main__ handler is the
            # only writer of a failure page, so that page is produced here from
            # the module's own fixed values.
            result = "RuntimeFailure"
            page = [screen(ERROR + gate.STAGE),
                    screen("Android autofill setting restore failed: " + str(gate.cleanup_failed).lower())]
        return result, page

    def only(self, output, prefix):
        matches = [line for line in output if line.startswith(prefix)]
        self.assertEqual(len(matches), 1, output)
        return matches[0]

    def test_double_failure_keeps_runtime_stage_and_marks_cleanup_failed(self):
        result, output, state = self.run_gate(runtime_fails=True, restore_fails=True)
        self.assertEqual(result, "RuntimeFailure")
        self.assertEqual(self.only(output, ERROR), ERROR + "complete-test-count")
        self.assertNotIn(RESTORE_STAGE, "\n".join(output))
        self.assertEqual(self.only(output, RESTORE), RESTORE + "true")
        self.assertFalse(any(line.startswith("PASS: ") for line in output))

    def test_runtime_failure_only_keeps_stage_and_reports_false(self):
        result, output, state = self.run_gate(runtime_fails=True, restore_fails=False)
        self.assertEqual(result, "RuntimeFailure")
        self.assertEqual(self.only(output, ERROR), ERROR + "complete-test-count")
        self.assertEqual(self.only(output, RESTORE), RESTORE + "false")
        self.assertFalse(any(line.startswith("PASS: ") for line in output))

    def test_handler_page_keeps_the_instrumentation_stage(self):
        # The __main__ handler's failure page (the same fixed statements) is
        # fed the exception main() actually raises, after the real finally
        # restore has run; the reached stage must not be replaced.
        device = FakeDevice(runtime_fails=True, restore_fails=True)
        self.addCleanup(device.close)
        with mock.patch.dict(os.environ, ENVIRONMENT), \
                mock.patch.object(gate, "subprocess", new=device.facade(), create=True):
            with self.assertRaises(gate.RuntimeFailure) as raised:
                gate.main()
        page = []
        with mock.patch("builtins.print", side_effect=lambda *a: page.append(screen(*a))):
            try:
                raise raised.exception
            except (Exception, KeyboardInterrupt):
                print("FAIL: Android native runtime validation at " + gate.STAGE)
                print("Android autofill setting restore failed: " + str(gate.cleanup_failed).lower())
        self.assertEqual(gate.STAGE, "complete-test-count")
        self.assertEqual(page, [ERROR + "complete-test-count", RESTORE + "true"])

    def test_cleanup_failure_only_still_fails_at_restore_stage(self):
        result, output, state = self.run_gate(runtime_fails=False, restore_fails=True)
        self.assertEqual(result, 1)
        self.assertEqual(self.only(output, ERROR), ERROR + RESTORE_STAGE)
        self.assertEqual(self.only(output, RESTORE), RESTORE + "true")
        self.assertFalse(any(line.startswith("PASS: ") for line in output))

    def test_success_is_the_only_pass(self):
        result, output, state = self.run_gate(runtime_fails=False, restore_fails=False)
        self.assertEqual(result, 0)
        self.assertEqual([line for line in output if line.startswith("PASS: ")],
                         ["PASS: Android native offline UI instrumentation, real OS autofill authentication handoff; controller/logcat canary scan"])
        self.assertFalse(any(line.startswith(ERROR) for line in output))
        self.assertFalse(any(line.startswith(RESTORE) for line in output))

    @contextlib.contextmanager
    def run_in(self, module, device, environment):
        """Real module.main() with only its subprocess reference replaced."""
        with mock.patch.dict(os.environ, environment), \
                mock.patch.object(module, "subprocess", new=mock.Mock(
                    PIPE=-1, STDOUT=-2, TimeoutExpired=CLIENT_TIMEOUT, run=device.run,
                    Popen=device.popen), create=True):
            yield

    def test_autofill_only_cleans_up_both_owned_packages(self):
        # Real main() in Autofill-only mode; the runtime fails in run_gate's
        # instrumentation stage. Before the adb argument was passed, the clean
        # cleanup was a NameError, so both packages were never cleared.
        module = importlib.util.spec_from_file_location("test_emulator_autofill", Path(gate.__file__))
        autofill = importlib.util.module_from_spec(module)
        with mock.patch.dict(os.environ, AUTOFILL_ENVIRONMENT):
            module.loader.exec_module(autofill)
        self.assertTrue(autofill.AUTOFILL_ONLY)
        # The runtime fails in the gate but its non-zero reply cannot be
        # scanned; the finally restore then clears both owned packages.
        device = CleanDevice(runtime_fails=False)
        self.addCleanup(device.close)
        with self.run_in(autofill, device, AUTOFILL_ENVIRONMENT), \
                mock.patch("builtins.print", side_effect=lambda *a: None):
            with self.assertRaises(autofill.RuntimeFailure) as raised:
                autofill.main()
        self.assertNotIsInstance(raised.exception, NameError)
        cleared = [command[3] for command in device.commands if command[:3] == ["shell", "pm", "clear"]]
        self.assertEqual(cleared[-2:], ["org.locklark.android", "org.locklark.android.test"])
        self.assertEqual((autofill.STAGE, autofill.cleanup_failed), ("complete-test-count", False))

    def failure_page(self):
        """The __main__ branch's two fixed lines, read from module state."""
        return [ERROR + gate.STAGE, RESTORE + str(gate.cleanup_failed).lower()]

    def test_second_run_does_not_inherit_previous_state(self):
        # First run passes the runtime and fails on cleanup alone, leaving all
        # four module states behind and printing the restore page.
        first = CleanDevice(runtime_fails=False, cleanup_fails=True)
        self.addCleanup(first.close)
        printed = []
        with self.run_in(gate, first, ENVIRONMENT), \
                mock.patch("builtins.print", side_effect=lambda *a: printed.append(screen(*a))):
            self.assertEqual(gate.main(), 1)
        self.assertEqual(printed, [ERROR + RESTORE_STAGE, RESTORE + "true"])
        inherited = (gate.STAGE, gate.STATE, gate.DIAGNOSTIC, gate.cleanup_failed)
        self.assertIsNotNone(inherited[1])
        self.assertNotEqual(inherited[2], {})
        self.assertIsInstance(inherited[3], bool)
        # The run itself failed, so the page keeps that stage and only the
        # bool says the cleanup failed.
        self.assertEqual(self.failure_page(), [ERROR + "complete-test-count", RESTORE + "true"])
        self.assertEqual(inherited[:1] + inherited[3:], ("complete-test-count", True))
        # Second run fails at the first prerequisite, the serial check: a new
        # exception, four fresh states, no device command, and a page whose
        # stage was not rewritten by either cleanup attempt.
        second = CleanDevice(runtime_fails=True, cleanup_fails=True)
        self.addCleanup(second.close)
        with self.run_in(gate, second, {**ENVIRONMENT, "ANDROID_SERIAL": "tcp-1:5555"}), \
                mock.patch("builtins.print", side_effect=lambda *a: None):
            with self.assertRaises(gate.RuntimeFailure) as raised:
                gate.main()
        self.assertEqual(self.failure_page(), [ERROR + "prerequisites", RESTORE + "false"])
        self.assertEqual((gate.STAGE, gate.STATE, gate.DIAGNOSTIC, gate.cleanup_failed),
                         ("prerequisites", None, {}, False))
        self.assertEqual(second.commands, [])
        self.assertEqual(inherited[0], "complete-test-count")

    def test_report_has_no_raw_device_text_and_private_files_stay_closed(self):
        for runtime_fails, restore_fails in ((True, True), (True, False), (False, True), (False, False)):
            with self.subTest(runtime=runtime_fails, restore=restore_fails):
                result, output, state = self.run_gate(runtime_fails=runtime_fails, restore_fails=restore_fails)
                self.assertNotIn(RAWTEXT, "\n".join(output))
                self.assertEqual(state.stat().st_mode & 0o777, 0o700)
                for name in ("controller.log", "runtime.log"):
                    self.assertEqual((state / name).stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
