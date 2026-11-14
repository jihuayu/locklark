"""Unit tests for the real-CLI smoke gate's fixed failure handling.

The positive path is exercised in CI by running scripts/cli_smoke.py against
the just-built product executable. These tests only verify that invalid CLI
paths and malformed child behavior fail closed and never echo child output;
they do not stand in for that real smoke.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "cli_smoke", ROOT / "scripts" / "cli_smoke.py"
)
assert SPEC is not None and SPEC.loader is not None
cli_smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli_smoke)


class CliSmokeFailureTests(unittest.TestCase):
    def invoke(self, *args: str) -> tuple[int, str]:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = cli_smoke.main(list(args))
        return result, stderr.getvalue()

    def test_missing_executable_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            result, stderr = self.invoke(
                "--cli", str(pathlib.Path(directory) / "absent")
            )
        self.assertEqual(result, 1)
        self.assertEqual(stderr, "FAIL: CLI path is not an executable file\n")

    @unittest.skipIf(os.name == "nt", "POSIX executable bit is not portable to Windows")
    def test_non_executable_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = pathlib.Path(directory) / "locklark"
            candidate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            candidate.chmod(0o600)
            result, stderr = self.invoke("--cli", str(candidate))
        self.assertEqual(result, 1)
        self.assertEqual(stderr, "FAIL: CLI path is not an executable file\n")

    @unittest.skipIf(os.name == "nt", "POSIX executable bit is not portable to Windows")
    def test_nonzero_command_failure_does_not_echo_child_output(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = pathlib.Path(directory) / "locklark"
            candidate.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--help\" ]; then\n"
                "  printf 'Locklark help\\n'\n"
                "  exit 0\n"
                "fi\n"
                "printf 'private child output\\n' >&2\n"
                "exit 7\n",
                encoding="utf-8",
            )
            candidate.chmod(0o700)
            result, stderr = self.invoke("--cli", str(candidate))
        self.assertEqual(result, 1)
        self.assertEqual(stderr, "FAIL: CLI command failed: demo\n")


class CliSmokeOutputFailureTests(unittest.TestCase):
    """Exercise the smoke's own parsing against a scripted stand-in CLI.

    The stand-in only imitates the output contract used by the smoke, so these
    tests check the smoke gate's refusal and redaction behavior. They are not
    real-product smoke evidence; that remains the CI invocation above.
    """

    def cli(self, directory: str, script: str) -> pathlib.Path:
        candidate = pathlib.Path(directory) / "locklark"
        candidate.write_text("#!/bin/sh\n" + script, encoding="utf-8")
        candidate.chmod(0o700)
        return candidate

    def run_smoke(self, candidate: pathlib.Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "cli_smoke.py"), "--cli", str(candidate)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )

    def test_directory_cli_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = pathlib.Path(directory) / "locklark"
            candidate.mkdir()
            candidate.chmod(0o700)
            completed = self.run_smoke(candidate)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(
            completed.stderr, b"FAIL: CLI path is not an executable file\n"
        )

    @unittest.skipUnless(
        os.name != "nt" and not (hasattr(os, "geteuid") and os.geteuid() == 0),
        "POSIX executable bit and unprivileged account are required",
    )
    def test_malformed_json_fails_closed_without_echo(self):
        if shutil.which("sh") is None:
            self.skipTest("sh is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            candidate = self.cli(
                directory,
                "if [ \"$1\" = \"--help\" ]; then printf 'Locklark help\\n'; exit 0; fi\n"
                "printf 'not-json-private\\n'\n",
            )
            completed = self.run_smoke(candidate)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stderr, b"FAIL: CLI returned malformed JSON: demo\n")
        self.assertEqual(completed.stdout, b"")
        self.assertNotIn(b"not-json-private", completed.stderr + completed.stdout)

    @unittest.skipUnless(
        os.name != "nt" and not (hasattr(os, "geteuid") and os.geteuid() == 0),
        "POSIX executable bit and unprivileged account are required",
    )
    def test_mismatched_summary_fails_closed(self):
        if shutil.which("sh") is None:
            self.skipTest("sh is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            candidate = self.cli(
                directory,
                "if [ \"$1\" = \"--help\" ]; then printf 'Locklark help\\n'; exit 0; fi\n"
                "if [ \"$1\" = \"demo\" ]; then\n"
                f"  printf '%s\\n' '{json.dumps({'epochs': [1, 2, 3], 'synthetic': True})}'\n"
                "  exit 0\n"
                "fi\n"
                f"printf '%s\\n' '{json.dumps({'epoch': 1, 'items': 2, 'attachments': 0})}'\n",
            )
            completed = self.run_smoke(candidate)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(
            completed.stderr,
            "FAIL: synthetic epoch 1 summary mismatch\n".encode(),
        )


if __name__ == "__main__":
    unittest.main()
