"""Fixed adb_category: pure classification, then the real page over the old fake device."""
import json
import os
import subprocess
import unittest
from unittest import mock
import test_emulator as gate
import test_emulator_gate as old

# The real client exception class, and private device text that must never print.
def TIMEOUT():
    """The real client timeout, with the fields its __init__ requires."""
    return subprocess.TimeoutExpired(["adb"], 1)
PRIVATE = old.RAWTEXT
DIAGNOSIS = old.DIAGNOSIS
ERROR = old.ERROR
# [adb, "-s", serial, ...]: index 1 is the old fake's own serial slot.
SERIAL = ["-s", old.ENVIRONMENT["ANDROID_SERIAL"]]
GETPROP = ["shell", "getprop"]
INSTALL = ["install", "-t", "-r"]
INSTRUMENT = ["shell", "am", "instrument"]


def reply(*, stderr=b"", returncode=1, stdout=b"FAILURES!!!\nINSTRUMENTATION_STATUS_CODE: -2\n"):
    return mock.Mock(returncode=returncode, stderr=stderr, stdout=stdout)


class CategoryTests(unittest.TestCase):
    def test_required_stderr_maps_to_fixed_categories(self):
        cases = ((b"error: device offline\n", "offline"),
                 (b"device unauthorized. This adbd's authentication is required.\n", "unauthorized"),
                 (b"error: device still authorizing\n", "unauthorized"),
                 (b"adb: failed to install app.apk: Failure [INSTALL_FAILED_INVALID_APK]\n", "other"),
                 (b"adb: failed to stat app.apk: No such file or directory\n", "other"),
                 (b"error: no devices/emulators found\n", "not_found"),
                 (b"", "other"), (None, "other"), ("private-text", "other"),
                 (b"Failure [INSTALL_FAILED_INSUFFICIENT_STORAGE] " + PRIVATE.encode(), "other"))
        for stderr, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(gate.adb_category(stderr), expected)

    def test_failure_carries_nothing_but_a_fixed_category(self):
        self.assertIsNone(gate.RuntimeFailure().adb_category)
        self.assertEqual(gate.RuntimeFailure(PRIVATE).args, (), "args must not carry text")
        # Only the six fixed categories are ever printed; text is never kept.
        for value in ("missing", "timeout", "other", "offline", "unauthorized", "not_found"):
            self.assertIn(value, gate.ADB_CATEGORIES)


class EntryTests(unittest.TestCase):
    """Real entrypoint() over real main(), on the unmodified old fake devices."""

    def attempt(self, device, run=None):
        """(exit code, printed page) for one real entrypoint() call."""
        printed = []
        with mock.patch.dict(os.environ, old.ENVIRONMENT), \
                mock.patch.object(gate, "subprocess", new=mock.Mock(
                    PIPE=-1, STDOUT=-2, TimeoutExpired=subprocess.TimeoutExpired,
                    run=device.run if run is None else run, Popen=device.popen), create=True), \
                mock.patch("builtins.print", side_effect=lambda *a: printed.append(old.screen(*a))):
            code = gate.entrypoint()
        return code, printed

    def device(self, **kwargs):
        device = old.CleanDevice(runtime_fails=kwargs.pop("runtime_fails", False), **kwargs)
        self.addCleanup(device.close)
        return device

    def at(self, device, command, answer):
        """device.run, but every `command` (device argv) is answered by
        answer(), which either returns its reply or raises; all else is old."""
        target, run = SERIAL + command, device.run
        def dispatch(arguments, **kwargs):
            if list(arguments[1:1 + len(target)]) == target:
                return answer()
            return run(arguments, **kwargs)
        return dispatch

    def test_getprop_required_refusals(self):
        # ro.kernel.qemu is the first device command: before main()'s own try,
        # so only the entrypoint's except can report its fixed category.
        for error, category in ((TIMEOUT, "timeout"), (FileNotFoundError, "missing"),
                                (OSError, "other")):
            with self.subTest(category=category):
                device = self.device()
                def answer(error=error):
                    raise error()
                code, printed = self.attempt(device, self.at(device, GETPROP, answer))
                self.page(code, printed, "prerequisites", category)

    def test_install_required_refusals(self):
        # The second install is the last command before the autofill try.
        for stderr, category in ((b"error: device offline\n", "offline"),
                                 (b"device unauthorized\n", "unauthorized"),
                                 (b"adb: failed to install: Failure [INSTALL_FAILED_INVALID_APK]\n", "other"),
                                 (b"adb: failed to stat: No such file or directory\n", "other")):
            with self.subTest(category=category):
                device = self.device()
                code, printed = self.attempt(device, self.at(device, INSTALL, lambda: reply(stderr=stderr)))
                self.page(code, printed, "install", category)
        for error, category in ((TIMEOUT, "timeout"), (FileNotFoundError, "missing")):
            with self.subTest(category=category):
                device = self.device()
                def answer(error=error):
                    raise error()
                code, printed = self.attempt(device, self.at(device, INSTALL, answer))
                self.page(code, printed, "install", category)

    def test_install_success_is_still_a_completed_process(self):
        # The old device answers install cleanly, so the run passes untouched
        # and no category is ever written.
        device = self.device()
        code, printed = self.attempt(device)
        self.assertEqual(code, 0)
        self.assertEqual(len([line for line in printed if line.startswith("PASS: ")]), 1)
        self.assertNotIn("adb_category", gate.DIAGNOSTIC)

    def test_instrument_required_refusals(self):
        for stderr, category in ((b"error: device offline\n", "offline"),
                                 (b"device unauthorized\n", "unauthorized"),
                                 (b"INSTRUMENTATION_FAILED: process crashed\n", "other")):
            with self.subTest(category=category):
                device = self.device()
                code, printed = self.attempt(device, self.at(device, INSTRUMENT, lambda: reply(stderr=stderr)))
                self.assertNotIn(["shell", "am", "force-stop", "org.locklark.android"], device.commands)
                self.page(code, printed, "complete-test-count", category)

    def test_instrument_timeout_is_fixed_and_keeps_the_page(self):
        device = self.device()
        def timeout():
            raise TIMEOUT()
        code, printed = self.attempt(device, self.at(device, INSTRUMENT, timeout))
        self.page(code, printed, "complete-test-count", "timeout")
        self.assertIn(["shell", "am", "force-stop", "org.locklark.android"], device.commands)

    def test_run_primary_beyond_getprop_install_instrument(self):
        # A later required reply refused carries its fixed category too.
        for stderr, category in ((b"error: device offline\n", "offline"), (b"denied\n", "other")):
            with self.subTest(category=category):
                device = self.device()
                code, printed = self.attempt(device, self.at(device, ["shell", "pm", "clear"], lambda: reply(stderr=stderr)))
                self.page(code, printed, "install", category)

    def test_non_adb_primary_adds_no_field(self):
        # The old Interrupt is the primary but carries no adb category: the
        # page prints the plain diagnosis it always printed.
        device = self.device()
        def interrupt():
            raise KeyboardInterrupt()
        code, printed = self.attempt(device, self.at(device, INSTRUMENT, interrupt))
        self.page(code, printed, "instrumentation", "absent")

    def test_cleanup_never_overwrites_nor_adds_the_field(self):
        # Cleanup only: the restore's own refusal writes nothing.
        device = self.device(cleanup_fails=True)
        code, printed = self.attempt(device)
        self.page(code, printed, old.RESTORE_STAGE, "absent", flag=True)
        # Double failure: the page keeps the primary's field, not the restore's.
        device = self.device(runtime_fails=True, cleanup_fails=True)
        code, printed = self.attempt(device)
        self.page(code, printed, "complete-test-count", "other", flag=True)

    def test_private_stderr_never_reaches_the_page(self):
        for stderr in (PRIVATE.encode(), b"device offline " + PRIVATE.encode(),
                       b"unauthorized " + PRIVATE.encode(), b"unknown package " + PRIVATE.encode()):
            with self.subTest(category=gate.adb_category(stderr)):
                device = self.device()
                code, printed = self.attempt(device, self.at(device, INSTALL, lambda: reply(stderr=stderr)))
                self.page(code, printed, "install", gate.adb_category(stderr))
                for line in printed:
                    self.assertNotIn(PRIVATE, line)
                    self.assertNotIn(PRIVATE.encode().hex(), line)

    def test_private_state_files_stay_private(self):
        device = self.device()
        code, printed = self.attempt(device, self.at(device, INSTALL, lambda: reply(stderr=b"error: device offline\n")))
        self.page(code, printed, "install", "offline")
        state = gate.STATE
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
        self.assertEqual((state / "controller.log").stat().st_mode & 0o777, 0o600)

    def page(self, code, printed, stage, category, flag=False):
        """The four unchanged lines; only the diagnosis may carry the field."""
        self.assertEqual(code, 1)
        self.assertEqual(len(printed), 4, printed)
        self.assertEqual(printed[0], ERROR + stage)
        self.assertEqual(printed[1], DIAGNOSIS + printed[1][len(DIAGNOSIS):])
        payload = json.loads(printed[1][len(DIAGNOSIS):])
        self.assertEqual(payload.pop("adb_category", "absent"), category)
        primary = {key: value for key, value in gate.DIAGNOSTIC.items() if key != "adb_category"}
        self.assertEqual(payload, primary)
        self.assertEqual(printed[2], old.RESTORE + str(flag).lower())
        self.assertTrue(printed[3].startswith("Private Android runtime evidence: "))
        self.assertFalse(any(line.startswith("PASS: ") for line in printed))
        self.assertNotIn(PRIVATE, "\n".join(printed))


if __name__ == "__main__":
    unittest.main()
