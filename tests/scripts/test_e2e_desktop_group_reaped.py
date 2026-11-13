"""Focused tests for ``support.desktop_group_reaped``.

The owned session is a real ``subprocess.Popen`` with ``start_new_session=True``
so its group id is its pid. Only the ``killpg(pid, 0)`` *probe* is mocked; no
group signal is ever sent. Cleanup uses only ``Popen.kill()``/``wait()`` on the
children this file created, which spawn no descendants.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.e2e import support  # noqa: E402


class DesktopGroupReapedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.procs: list[subprocess.Popen] = []
        self.addCleanup(self._cleanup)

    def _spawn(self) -> subprocess.Popen:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time\ntime.sleep(60)\n"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.procs.append(proc)
        self.assertEqual(os.getpgid(proc.pid), proc.pid, "owned group id is the pid")
        return proc

    def _exited(self) -> subprocess.Popen:
        proc = self._spawn()
        # This file's own child only: a per-process kill, never a group signal.
        proc.kill()
        proc.wait(timeout=30)
        self.assertIsNotNone(proc.poll())
        return proc

    def _cleanup(self) -> None:
        # Only this file's own Popen objects are reaped, via Popen.kill() with a
        # bounded wait. No group signal is sent: these children have no
        # descendants, so their own process is all there is to reap.
        for proc in self.procs:
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass

    def test_esrch_proves_reaped(self):
        proc = self._exited()
        with mock.patch.object(
            support.os, "killpg", side_effect=ProcessLookupError
        ) as probe:
            self.assertTrue(support.desktop_group_reaped(proc))
        probe.assert_called_once_with(proc.pid, 0)
        self.assertIsNotNone(proc.poll(), "cleanup must not leave the test child running")

    def test_eperm_is_unknown_and_not_reaped(self):
        proc = self._exited()
        with mock.patch.object(
            support.os, "killpg", side_effect=PermissionError
        ) as probe:
            self.assertFalse(support.desktop_group_reaped(proc))
        probe.assert_called_once_with(proc.pid, 0)

    def test_other_oserror_is_unknown_and_not_reaped(self):
        proc = self._exited()
        for error in (OSError(5, "I/O error"), BlockingIOError(11, "busy")):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(support.os, "killpg", side_effect=error) as probe:
                    self.assertFalse(support.desktop_group_reaped(proc))
                probe.assert_called_once_with(proc.pid, 0)

    def test_live_owned_group_is_false_without_any_probe(self):
        proc = self._spawn()
        self.assertIsNone(proc.poll())
        with mock.patch.object(support.os, "killpg") as probe:
            self.assertFalse(support.desktop_group_reaped(proc))
        probe.assert_not_called()

    def test_unproven_reap_makes_the_smoke_outcome_a_failure(self):
        # Pure decision: an unproven reap is a real cleanup failure, so it
        # can never report success even though the exit code was normal.
        facts = {
            "pre_mutated": False,
            "post_mutated": False,
            "exit_code": 0,
            "reaped": False,
            "body_error": None,
            "teardown_error": None,
            "hash_error": None,
        }
        note = support.desktop_cleanup_note(facts)
        self.assertIn(support.DESKTOP_SMOKE_CLEANUP_FAILED, note)
        self.assertIn("unproven", note)
        failure = support._smoke_outcome(facts, None)
        self.assertIsInstance(failure, AssertionError)
        self.assertIsNot(failure, None)


if __name__ == "__main__":
    unittest.main()
