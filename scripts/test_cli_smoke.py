"""Unit tests for the real-CLI smoke gate's fixed failure handling.

The positive path is exercised in CI by running scripts/cli_smoke.py against
the just-built product executable. These tests only verify that invalid CLI
paths fail closed; they do not stand in for that real smoke.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import pathlib
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


if __name__ == "__main__":
    unittest.main()
