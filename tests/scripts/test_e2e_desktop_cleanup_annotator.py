"""Process-level tests for the desktop smoke cleanup annotator.

``support._annotate_cleanup_failure`` must correct a ``SystemExit`` success
code before any note dedup/early return, keeping the same exception object
and ``args``. These tests run the real annotator inside fresh Python
subprocesses and read the *actual* interpreter exit status, so a fix that
only rewrites ``args`` (or only adds a note) fails here.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

NOTE = "{cleanup=desktop-smoke-cleanup-failed teardown(OSError)}"

# One child process: import the helper, build the requested SystemExit,
# optionally annotate it once or twice, write what it observed, and exit.
_CHILD = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from tests.e2e import support

request = json.loads(sys.argv[2])
# SystemExit is a builtin and is not re-exported by ``support``; the annotator
# checks against this same class.
exc = SystemExit(request["code"])
before = (id(exc), exc.args)
if "pre" in request:
    exc.add_note(request["pre"])
if "note" in request:
    calls = request.get("calls", 1)
    for _ in range(calls):
        support._annotate_cleanup_failure(exc, request["note"])
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    json.dump(
        {
            "same": id(exc) == before[0],
            "args_before": list(before[1]),
            "args_after": list(exc.args),
            "code": exc.code,
            "notes": list(getattr(exc, "__notes__", []) or []),
            "type": type(exc).__name__,
        },
        handle,
    )
raise exc
"""


class AnnotatorExitStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="ll-annotator-"))
        self.addCleanup(_remove_tree, self.temp)
        self.script = self.temp / "child.py"
        self.script.write_text(_CHILD, encoding="utf-8")

    def run_child(self, request: dict) -> tuple[int, dict]:
        out = self.temp / "observed.json"
        proc = subprocess.run(
            [sys.executable, str(self.script), str(ROOT), json.dumps(request), str(out)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return proc.returncode, json.loads(out.read_text(encoding="utf-8"))

    def assert_success_annotated(self, request: dict) -> None:
        code, observed = self.run_child(request)
        self.assertEqual(code, 1, f"interpreter exit must be 1: {request}")
        self.assertTrue(observed["same"], "the same SystemExit object must be kept")
        self.assertEqual(observed["type"], "SystemExit")
        notes = observed["notes"]
        self.assertTrue(
            any("desktop-smoke-cleanup-failed" in note for note in notes),
            f"cleanup note missing: {notes!r}",
        )
        self.assertEqual(observed["code"], 1)

    def test_none_code_exits_one_with_note(self):
        self.assert_success_annotated({"code": None, "note": NOTE})

    def test_zero_code_exits_one_with_note(self):
        self.assert_success_annotated({"code": 0, "note": NOTE})

    def test_false_code_exits_one_with_note(self):
        self.assert_success_annotated({"code": False, "note": NOTE})

    def test_existing_cleanup_note_still_exits_one(self):
        # Dedup path: the note is already present, so the annotator returns
        # early after adding notes — the exit status must still be corrected.
        self.assert_success_annotated({"code": 0, "note": NOTE, "pre": NOTE})

    def test_repeated_annotation_still_exits_one(self):
        self.assert_success_annotated({"code": None, "note": NOTE, "calls": 3})

    def test_nonzero_seven_stays_seven(self):
        code, observed = self.run_child({"code": 7, "note": NOTE})
        self.assertEqual(code, 7)
        self.assertTrue(observed["same"])
        self.assertEqual(observed["code"], 7)
        self.assertEqual(observed["args_after"], observed["args_before"])
        self.assertIn(NOTE, observed["notes"])

    def test_clean_system_exit_zero_is_untouched(self):
        code, observed = self.run_child({"code": 0})
        self.assertEqual(code, 0, "a clean SystemExit(0) must still exit 0")
        self.assertEqual(observed["code"], 0)
        self.assertEqual(observed["args_after"], observed["args_before"])
        self.assertEqual(observed["notes"], [])

    def test_annotator_only_rewrites_args_is_rejected(self):
        # Counter-control: the same child, but the code correction disabled,
        # shows the note/args alone would still exit 0.
        fake = self.temp / "fake.py"
        fake.write_text(
            _CHILD.replace(
                "support._annotate_cleanup_failure(exc, request[\"note\"])",
                "exc.add_note(request[\"note\"])",
            ),
            encoding="utf-8",
        )
        out = self.temp / "fake.json"
        proc = subprocess.run(
            [sys.executable, str(fake), str(ROOT), json.dumps({"code": 0, "note": NOTE}), str(out)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, "notes alone must not change the exit status")


def _remove_tree(path: Path) -> None:
    for child in sorted(path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if child.is_dir():
            child.rmdir()
        else:
            child.unlink()
    path.rmdir()


if __name__ == "__main__":
    unittest.main()
