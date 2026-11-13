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
DIAGNOSIS = "Fixed Android runtime diagnosis: "
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
        # restore_fails: the restore's put of the prior service is rejected.
        self.restore_fails = restore_fails
        # A prior service exists, so the restore is a put that can fail.
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
            # A rejected restore leaves the setting unchanged, so its
            # readback differs, as on a device where the write was refused.
            if self.restore_fails and not arguments[-1].startswith("org.locklark"):
                return self.reply(failed=True)
            self.setting = arguments[-1]
            return self.reply()
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
        # cleanup_fails: the restore's own settings put is rejected; the run's
        # own write to this device still succeeds.
        super().__init__(runtime_fails=runtime_fails, restore_fails=cleanup_fails)
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
        if what in (("shell", "settings", "put"), ("shell", "settings", "get")):
            # The base fake tracks the setting and its cleanup_fails switch.
            return FakeDevice.run(self, arguments, **kwargs)
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
        """Return (entrypoint exit code, its page, state dir)."""
        device = FakeDevice(runtime_fails=runtime_fails, restore_fails=restore_fails)
        self.addCleanup(device.close)
        result, page = self.attempt(device)
        runs = list(device.root.glob("locklark-android-runtime-*"))
        self.assertEqual(len(runs), 1)
        return result, page, runs[0]

    def attempt(self, device):
        # The real entrypoint over the real main(): main() itself never writes
        # a failure page, so the one page printed here is entrypoint()'s.
        printed = []
        with mock.patch.dict(os.environ, ENVIRONMENT), \
                mock.patch.object(gate, "subprocess", new=device.facade(), create=True), \
                mock.patch("builtins.print", side_effect=lambda *a: printed.append(screen(*a))):
            result = gate.entrypoint()
        return result, printed

    def only(self, output, prefix):
        matches = [line for line in output if line.startswith(prefix)]
        self.assertEqual(len(matches), 1, output)
        return matches[0]

    def test_double_failure_keeps_runtime_stage_and_marks_cleanup_failed(self):
        # The run fails inside run_gate at its first private state file, which
        # exists: the reached stage is kept, and the restore also fails.
        result, output, state = self.run_gate(runtime_fails=True, restore_fails=True)
        self.assertEqual(result, 1)
        self.assertEqual(self.only(output, ERROR), ERROR + "complete-test-count")
        self.assertNotIn(RESTORE_STAGE, "\n".join(output))
        self.assertEqual(self.only(output, RESTORE), RESTORE + "true")
        self.assertFalse(any(line.startswith("PASS: ") for line in output))

    def test_runtime_failure_only_keeps_stage_and_reports_false(self):
        result, output, state = self.run_gate(runtime_fails=True, restore_fails=False)
        self.assertEqual(result, 1)
        self.assertEqual(self.only(output, ERROR), ERROR + "complete-test-count")
        self.assertEqual(self.only(output, RESTORE), RESTORE + "false")
        self.assertFalse(any(line.startswith("PASS: ") for line in output))

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
    def run_in(self, module, device, environment, run=None):
        """One real main() call, with only its subprocess reference replaced."""
        with mock.patch.dict(os.environ, environment), \
                mock.patch.object(module, "subprocess", new=mock.Mock(
                    PIPE=-1, STDOUT=-2, TimeoutExpired=CLIENT_TIMEOUT, run=run or device.run,
                    Popen=device.popen), create=True):
            yield

    def run_entry(self, module, device, environment, run=None):
        """Real entrypoint() over the real main(), capturing what it prints.

        run replaces the adb run (see raise_after). Returns (exit code,
        printed lines). An escaping exception propagates.
        """
        printed = []
        with self.run_in(module, device, environment, run), \
                mock.patch("builtins.print", side_effect=lambda *a: printed.append(screen(*a))):
            return module.entrypoint(), printed

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

    def test_second_run_does_not_inherit_previous_state(self):
        # First run passes the runtime and fails on cleanup alone: the real
        # failure page says so, then leaves all four module states behind.
        first = CleanDevice(runtime_fails=False, cleanup_fails=True)
        self.addCleanup(first.close)
        code, printed = self.run_entry(gate, first, ENVIRONMENT)
        self.assertEqual(code, 1)
        self.fixed(printed, flag=True)
        self.assertEqual(json.loads(printed[1][len(DIAGNOSIS):])["tests_run"], 6)
        inherited = (gate.STAGE, gate.STATE, gate.DIAGNOSTIC, gate.cleanup_failed)
        self.assertEqual(inherited[:1] + inherited[3:], ("autofill-setting-restore", True))
        self.assertIsNotNone(inherited[1])
        self.assertNotEqual(inherited[2], {})
        # Second run fails at the first prerequisite, the serial check: a new
        # failure, four fresh states, no device command, and its own page.
        second = CleanDevice(runtime_fails=True, cleanup_fails=True)
        self.addCleanup(second.close)
        code, printed = self.run_entry(gate, second, {**ENVIRONMENT, "ANDROID_SERIAL": "tcp-1:5555"})
        self.assertEqual(code, 1)
        self.assertEqual(printed[0], ERROR + "prerequisites")
        self.assertEqual(printed[2], RESTORE + "false")
        self.assertEqual((gate.STAGE, gate.STATE, gate.DIAGNOSTIC, gate.cleanup_failed),
                         ("prerequisites", None, {}, False))
        self.assertEqual(second.commands, [])

    def raise_after(self, device, at, error):
        """device.run, but adb runs the one command at `at`, then raises error.

        The command has already reached the device (it is tracked, and its
        reply is built), but no reply is returned: an adb that acted and was
        then interrupted, or asked to exit. Every other command replies.
        """
        run = device.run
        def answer(arguments, **kwargs):
            command = list(arguments)[3:]
            # The run's own write starts with org.locklark; the restore's put
            # brings the prior service back, and so does not.
            hit = (at == "instrument" and command[:3] == ["shell", "am", "instrument"]) or \
                (at == "restore" and command[:3] == ["shell", "settings", "put"] and
                 not command[-1].startswith("org.locklark"))
            reply = run(arguments, **kwargs)
            if hit:
                raise error
            return reply
        return answer

    def case(self, *, runtime_fails=False, cleanup_fails=False, escaped=None):
        """Run the real entrypoint(); escaped is (where, kind or instance)."""
        device = CleanDevice(runtime_fails=runtime_fails, cleanup_fails=cleanup_fails)
        self.addCleanup(device.close)
        run, raised = device.run, None
        if escaped is not None:
            where, kind = escaped
            run = self.raise_after(device, where, kind() if isinstance(kind, type) else kind)
        try:
            code, printed = self.run_entry(gate, device, ENVIRONMENT, run)
        except BaseException as error:
            raised, code, printed = error, None, []
        return code, printed, raised, gate.STAGE, gate.cleanup_failed

    def fixed(self, printed, flag):
        """The one failure page: the fixed stage and BOOL lines in place."""
        self.assertEqual(len(printed), 4, printed)
        self.assertEqual(printed[0], ERROR + gate.STAGE)
        self.assertEqual(printed[1], DIAGNOSIS + json.dumps(gate.DIAGNOSTIC, sort_keys=True))
        self.assertEqual(printed[2], RESTORE + str(flag).lower())
        self.assertIs(flag, gate.cleanup_failed)
        self.assertTrue(printed[3].startswith("Private Android runtime evidence: "))
        self.assertFalse(any(line.startswith("PASS: ") for line in printed))
        self.assertNotIn(RAWTEXT, "\n".join(printed))

    def test_main_raises_the_same_primary_instance(self):
        primary, cleanup = gate.RuntimeFailure("primary"), gate.RuntimeFailure("cleanup")
        device = CleanDevice(runtime_fails=False, cleanup_fails=False)
        self.addCleanup(device.close)
        def run(arguments, **kwargs):
            command = list(arguments)[3:]
            if command[:3] == ["shell", "am", "instrument"]:
                raise primary
            if command[:3] == ["shell", "settings", "put"] and not command[-1].startswith("org.locklark"):
                raise cleanup
            return device.run(arguments, **kwargs)
        with self.run_in(gate, device, ENVIRONMENT, run), mock.patch("builtins.print"):
            with self.assertRaises(gate.RuntimeFailure) as raised:
                gate.main()
        self.assertIs(raised.exception, primary)
        self.assertIsNot(raised.exception, cleanup)
        self.assertTrue(gate.cleanup_failed)
        # The same instance reaches the entrypoint's page as the reached stage.
        page = []
        with self.run_in(gate, device, ENVIRONMENT, run), \
                mock.patch("builtins.print", side_effect=lambda *a: page.append(screen(*a))):
            self.assertEqual(gate.entrypoint(), 1)
        # The page is the primary's stage; the restore ran after it, and it
        # escaped main() too, so the bool records that failed cleanup.
        self.fixed(page, gate.cleanup_failed)

        # The restore succeeded on its own, so the bool is false.
        clean = CleanDevice(runtime_fails=True)
        self.addCleanup(clean.close)
        with self.run_in(gate, clean, ENVIRONMENT), mock.patch("builtins.print"):
            with self.assertRaises(gate.RuntimeFailure):
                gate.main()
        self.assertFalse(gate.cleanup_failed)
        self.assertEqual(clean.setting, FakeDevice.PRIOR)

    def test_entrypoint_is_the_only_exit(self):
        source = Path(gate.__file__).read_text(encoding="utf-8")
        self.assertTrue(source.rstrip().endswith(
            'if __name__ == "__main__":\n    raise SystemExit(entrypoint())'))

    def test_entrypoint_matches_every_combination(self):
        expected = {(True, True): ("complete-test-count", True), (True, False): ("complete-test-count", False),
                    (False, True): (RESTORE_STAGE, True), (False, False): None}
        for (runtime_fails, cleanup_fails), outcome in expected.items():
            with self.subTest(runtime=runtime_fails, cleanup=cleanup_fails):
                code, printed, raised, stage, flag = self.case(
                    runtime_fails=runtime_fails, cleanup_fails=cleanup_fails)
                self.assertIsNone(raised)
                if outcome is None:
                    self.assertEqual((code, stage, flag), (0, "complete-test-count", False))
                    self.assertEqual(sum(line.startswith("PASS: ") for line in printed), 1)
                else:
                    self.assertEqual((code, stage, flag), (1, *outcome))
                    self.fixed(printed, outcome[1])

    def test_cleanup_exception_never_replaces_the_primary(self):
        # Both fail with RuntimeFailure: main() raises only the primary.
        device = CleanDevice(runtime_fails=True, cleanup_fails=True)
        self.addCleanup(device.close)
        with self.run_in(gate, device, ENVIRONMENT):
            with self.assertRaises(gate.RuntimeFailure) as raised:
                gate.main()
        self.assertIs(type(raised.exception), gate.RuntimeFailure)
        self.assertEqual((gate.STAGE, gate.cleanup_failed), ("complete-test-count", True))
        # Through the real entrypoint: the reached stage and the bool, no PASS.
        code, printed, raised, stage, flag = self.case(runtime_fails=True, cleanup_fails=True)
        self.assertIsNone(raised)
        self.assertEqual((code, stage, flag), (1, "complete-test-count", True))
        self.fixed(printed, True)
        # Only the cleanup fails: main() names that one stage and returns 1.
        code, printed, raised, stage, flag = self.case(cleanup_fails=True)
        self.assertIsNone(raised)
        self.assertEqual((code, stage, flag), (1, RESTORE_STAGE, True))
        self.fixed(printed, True)

    def test_runtime_interrupt_escapes_main_as_its_instance(self):
        # The interrupt comes from the fake device at am instrument: that is
        # the runtime primary, not a cleanup result. main() lets it out as the
        # same instance, and the restore that follows still succeeds.
        device = CleanDevice(runtime_fails=True)
        self.addCleanup(device.close)
        interrupt = KeyboardInterrupt()
        with self.run_in(gate, device, ENVIRONMENT, self.raise_after(device, "instrument", interrupt)):
            with self.assertRaises(KeyboardInterrupt) as raised:
                gate.main()
        self.assertIs(raised.exception, interrupt)
        self.assertEqual(gate.STAGE, "instrumentation")
        self.assertFalse(gate.cleanup_failed)
        # Through the entrypoint the same instance is reported at that stage.
        code, printed, raised, stage, flag = self.case(
            runtime_fails=True, escaped=("instrument", interrupt))
        self.assertIsNone(raised)
        self.assertEqual((code, stage, flag), (1, "instrumentation", False))
        self.fixed(printed, False)

    def test_cleanup_interrupt_is_recorded_not_raised(self):
        # The interrupt comes from the restore's own put, with no runtime
        # failure: the interrupt is the failed cleanup, recorded as the bool.
        device = CleanDevice(runtime_fails=False)
        self.addCleanup(device.close)
        run = self.raise_after(device, "restore", KeyboardInterrupt())
        with self.run_in(gate, device, ENVIRONMENT, run):
            self.assertEqual(gate.main(), 1)
        self.assertEqual((gate.STAGE, gate.cleanup_failed), (RESTORE_STAGE, True))
        # The prior service is still in place: the put never landed.
        self.assertEqual(device.setting, FakeDevice.PRIOR)
        code, printed, raised, stage, flag = self.case(escaped=("restore", KeyboardInterrupt))
        self.assertIsNone(raised)
        self.assertEqual((code, stage, flag), (1, RESTORE_STAGE, True))
        self.fixed(printed, True)

    def test_exit_inside_the_run_never_exits_zero(self):
        # From the runtime it is the primary, escaping main() as itself and
        # reported at the reached stage; from the restore it is a failed
        # cleanup, recorded and reported at the restore. Never a success.
        for where, status, stage, flag in (("instrument", 0, "instrumentation", False),
                                           ("instrument", 1, "instrumentation", False),
                                           ("restore", 0, RESTORE_STAGE, True),
                                           ("restore", 1, RESTORE_STAGE, True)):
            with self.subTest(where=where, status=status):
                code, printed, raised, found, reported = self.case(
                    runtime_fails=where == "instrument",
                    escaped=(where, SystemExit(status)))
                self.assertIsNone(raised)
                self.assertEqual((code, found, reported), (1, stage, flag))
                self.fixed(printed, flag)
                self.assertFalse(any(line.startswith("PASS: ") for line in printed))

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
