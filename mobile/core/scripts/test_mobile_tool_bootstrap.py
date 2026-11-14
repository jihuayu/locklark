#!/usr/bin/env python3
"""Pure contract tests for the mobile pinned-tool bootstrap and go shim."""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SHIM = HERE / "mobile_go_shim.py"
BOOTSTRAP = HERE / "mobile-tool-bootstrap.sh"
ANDROID = HERE.parent.parent / "core/scripts/bind-android.sh"
IOS = HERE.parent.parent / "ios/scripts/build-core.sh"
VERSION = "v0.0.0-20260908204917-8b95e45f8d3e"


class ShimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = pathlib.Path(self.tmp.name)
        self.args_file = self.root / "args"
        self.real_go = self.root / "go"
        self.real_go.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ARG_FILE\"\nexit 0\n")
        self.real_go.chmod(0o700)
        self.env = dict(os.environ)
        self.env.update({
            "LOCKLARK_REAL_GO": str(self.real_go),
            "LOCKLARK_MOBILE_VERSION": VERSION,
            "ARG_FILE": str(self.args_file),
        })

    def tearDown(self):
        self.tmp.cleanup()

    def run_shim(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(SHIM), *args],
            env=self.env if env is None else env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)

    def test_exact_latest_install_is_rewritten(self):
        result = self.run_shim(
            "install", "golang.org/x/mobile/cmd/gobind@latest")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.args_file.read_text().splitlines(),
            ["install", "golang.org/x/mobile/cmd/gobind@" + VERSION])

    def test_other_go_commands_and_extra_args_are_unchanged(self):
        cases = (
            ["build", "./cmd/locklark"],
            ["install", "-x", "golang.org/x/mobile/cmd/gobind@latest"],
            ["install", "example.com/other/cmd/tool@latest"],
            ["list", "-m", "golang.org/x/mobile"],
        )
        for args in cases:
            with self.subTest(args=args):
                result = self.run_shim(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    self.args_file.read_text().splitlines(), args)

    def test_missing_real_go_and_bad_pin_fail(self):
        cases = (
            ({"LOCKLARK_REAL_GO": ""}, "missing"),
            ({"LOCKLARK_REAL_GO": str(self.root / "missing")}, "missing"),
            ({"LOCKLARK_MOBILE_VERSION": ""}, "badpin"),
            ({"LOCKLARK_MOBILE_VERSION": "latest"}, "badpin"),
        )
        for update, _ in cases:
            with self.subTest(update=update):
                env = dict(self.env)
                env.update(update)
                result = self.run_shim(
                    "install", "golang.org/x/mobile/cmd/gobind@latest",
                    env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.args_file.exists())


class ScriptTests(unittest.TestCase):
    def test_shell_syntax(self):
        for path in (BOOTSTRAP, ANDROID, IOS):
            result = subprocess.run(
                ["bash", "-n", str(path)], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(result.returncode, 0, path)

    def test_only_gomobile_is_preinstalled_and_gobind_comes_from_init(self):
        text = BOOTSTRAP.read_text()
        self.assertIn(
            'install "golang.org/x/mobile/cmd/gomobile@$version"', text)
        self.assertIn('"$tools/gomobile" init', text)
        self.assertNotIn('install "golang.org/x/mobile/cmd/gobind', text)
        self.assertIn("mobile_go_shim.py", text)


if __name__ == "__main__":
    unittest.main()
