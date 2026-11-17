"""Focused tests: the CLI broker harness scopes macOS native requests to its
own live desktop Popen PID.

No real OS, GUI, TCC, window enumeration or input: the harness is built with
in-memory attributes and ``run_driver`` is replaced by a recorder, so only the
request documents it would send are inspected. The real driver entry point is
exercised separately with poisoned CoreGraphics fakes in
``test_native_macos_owned_ax.py``.
"""
import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cli_broker_acceptance as harness

TITLE = "Locklark · 本地金库"
DESKTOP = "/opt/locklark/locklark-desktop"


class FakeProcess:
    """A live desktop Popen stand-in with an exact positive int PID."""

    def __init__(self, pid=4242, returncode=None):
        self.pid = pid
        self.returncode = returncode

    def poll(self):
        return self.returncode


_UNSET = object()


def acceptance(process=_UNSET, desktop=DESKTOP):
    """A real Acceptance with only the attributes these tests need."""
    instance = harness.Acceptance.__new__(harness.Acceptance)
    instance.stage = "desktop"
    instance.desktop_process = FakeProcess() if process is _UNSET else process
    instance.desktop = desktop
    instance.sent = []
    instance.run_driver = lambda request: instance.sent.append(request) or {"ok": 1}
    return instance


class OwnedPidRequestTests(unittest.TestCase):
    def document(self, instance, actions=None, inspect=False):
        request = instance.scoped_request(actions or [], inspect=inspect)
        return json.loads(request)

    def test_driver_and_inspect_carry_the_live_popen_pid(self):
        instance = acceptance(FakeProcess(pid=4242))
        instance.driver([{"wait_label": "解锁"}], "desktop")
        # The real inspect flow runs the driver with the inspect request.
        instance.run_driver(instance.inspect_request())
        self.assertEqual(len(instance.sent), 2)
        for raw in instance.sent:
            document = json.loads(raw)
            self.assertEqual(document["owned_pid"], 4242)
            self.assertEqual(document["title"], TITLE)          # exact fixture
            self.assertEqual(document["executable"], DESKTOP)   # canonical exe
        self.assertEqual(json.loads(instance.sent[0])["actions"], [{"wait_label": "解锁"}])
        self.assertTrue(json.loads(instance.sent[1])["inspect"])

    def test_pid_is_always_a_plain_positive_int(self):
        for pid in (1, 4242, 2 ** 31):
            with self.subTest(pid=pid):
                document = self.document(acceptance(FakeProcess(pid=pid)))
                self.assertIs(type(document["owned_pid"]), int)
                self.assertEqual(document["owned_pid"], pid)

    def test_exited_or_missing_process_refuses_before_any_request(self):
        for process in (None, FakeProcess(returncode=0), FakeProcess(returncode=1)):
            with self.subTest(process=process):
                instance = acceptance(process)
                with self.assertRaises(harness.AcceptanceFailure):
                    instance.scoped_request([], inspect=False)
                self.assertEqual(instance.sent, [])

    def test_malformed_pid_refuses_before_any_request(self):
        for pid in (0, -1, True, 4242.0, "4242", None):
            with self.subTest(pid=pid):
                instance = acceptance(FakeProcess(pid=pid))
                with self.assertRaises(harness.AcceptanceFailure):
                    instance.scoped_request([], inspect=False)
                self.assertEqual(instance.sent, [])

    def test_relative_or_missing_desktop_refuses_before_any_request(self):
        for desktop in (None, "locklark-desktop", "relative/path"):
            with self.subTest(desktop=desktop):
                instance = acceptance(desktop=desktop)
                with self.assertRaises(harness.AcceptanceFailure):
                    instance.scoped_request([], inspect=False)
                self.assertEqual(instance.sent, [])

    def test_activation_request_is_unchanged_and_unscoped(self):
        instance = acceptance()
        document = json.loads(instance.activation_request())
        self.assertEqual(document, {"activate_pid": 4242, "executable": DESKTOP})
        self.assertNotIn("owned_pid", document)


if __name__ == "__main__":
    unittest.main()
