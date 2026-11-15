"""CLI refusal checks that never build or execute binding tools."""
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("source-manifest.py")


def executable(path, marker):
    path.write_text("#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit 87\n")
    path.chmod(0o700)


class InstalledToolPathTests(unittest.TestCase):
    def check_shadow_refused(self, preceding_directory):
        for name in ("gobind", "gomobile"):
            with self.subTest(tool=name), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                tools = root / "installed"
                shadow = root / preceding_directory
                tools.mkdir()
                shadow.mkdir()
                marker = root / "wrong-process-ran"
                for tool in ("gobind", "gomobile"):
                    executable(tools / tool, marker)
                executable(shadow / name, marker)
                probe_go = root / "selected-go"
                executable(probe_go, marker)
                env = dict(os.environ, GO_BIN=str(probe_go),
                           PATH=os.pathsep.join((str(shadow), str(tools), os.defpath)))
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--prepare", "--tools-dir", str(tools)],
                    env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "Binding tool PATH mismatch: " + name + "\n")
                self.assertFalse(marker.exists(), "Go and binding tools must not run on a mismatch")

    def test_go_directory_shadow_refused_before_process_start(self):
        self.check_shadow_refused("go-bin")

    def test_java_directory_shadow_refused_before_process_start(self):
        self.check_shadow_refused("java-bin")

    def test_installed_tools_directory_is_required(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--prepare"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--tools-dir", result.stderr)


if __name__ == "__main__":
    unittest.main()
