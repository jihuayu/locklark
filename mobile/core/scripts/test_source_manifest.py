"""CLI refusal checks that never build or execute binding tools."""
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("source-manifest.py")


def executable(path, marker, exit_code=87):
    path.write_text("#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit " + str(exit_code) + "\n")
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
                probe_go = root / "go"
                executable(probe_go, marker)
                env = dict(os.environ, GO_BIN=str(probe_go),
                           PATH=os.pathsep.join((str(shadow), str(tools), str(root), os.defpath)))
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

    def check_go_shadow_refused(self, shadow_in_tools):
        for phase in ("--prepare", "--check-tool-paths"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                tools, selected, preceding = (root / name for name in ("installed", "selected", "preceding"))
                for directory in (tools, selected, preceding):
                    directory.mkdir()
                marker = root / "wrong-process-ran"
                for name in ("gobind", "gomobile"):
                    executable(tools / name, marker)
                explicit_go = selected / "go"
                executable(explicit_go, marker)
                executable((tools if shadow_in_tools else preceding) / "go", marker)
                prefix = (tools, selected) if shadow_in_tools else (preceding, tools, selected)
                env = dict(os.environ, GO_BIN=str(explicit_go),
                           PATH=os.pathsep.join((*map(str, prefix), os.defpath)))
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), phase, "--tools-dir", str(tools)],
                    env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                expected = ("Binding tool directory contains an unexpected entry\n"
                            if shadow_in_tools else "Binding Go PATH mismatch\n")
                self.assertEqual(result.stderr, expected)
                self.assertFalse(marker.exists(), "A different PATH Go must never run")

    def test_go_shadow_in_installed_tools_refused_before_process_start(self):
        self.check_go_shadow_refused(shadow_in_tools=True)

    def test_go_shadow_in_preceding_path_refused_before_process_start(self):
        self.check_go_shadow_refused(shadow_in_tools=False)

    def check_unexpected_entry_refused(self, name, kind, phase):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            tools = root / "installed"
            tools.mkdir()
            marker = root / "wrong-process-ran"
            for tool in ("gobind", "gomobile"):
                executable(tools / tool, marker)
            entry = tools / name
            if entry.exists():
                entry.unlink()
            if kind == "directory":
                entry.mkdir()
            elif kind == "symlink":
                entry.symlink_to(root / "missing-target")
            else:
                executable(entry, marker, exit_code=0 if name == "python3" else 87)
            executable(root / "go", marker)
            env = dict(os.environ, GO_BIN=str(root / "go"),
                       PATH=os.pathsep.join((str(tools), str(root), os.defpath)))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), phase, "--tools-dir", str(tools)],
                env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "Binding tool directory contains an unexpected entry\n")
            self.assertFalse(marker.exists(), "The shadow checker and all other tools must never run")
            self.assertTrue(entry.exists() or entry.is_symlink(), "Unexpected contents must be preserved")

    def test_cached_python_shadow_cannot_replace_explicit_checker(self):
        self.check_unexpected_entry_refused("python3", "executable", "--check-tool-dir")

    def test_cached_directory_is_closed_to_other_executables_directories_and_symlinks(self):
        for name, kind in (("dirname", "executable"), ("helper", "executable"),
                           ("gobind", "directory"), ("gomobile", "symlink")):
            with self.subTest(name=name, kind=kind):
                self.check_unexpected_entry_refused(name, kind, "--prepare")

    def test_preinstall_check_allows_missing_or_empty_cache_without_creating_or_running_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            tools, marker = root / "installed", root / "wrong-process-ran"
            executable(root / "go", marker)
            env = dict(os.environ, GO_BIN=str(root / "go"), PATH=str(root) + os.pathsep + os.defpath)
            for created in (False, True):
                if created:
                    tools.mkdir()
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--check-tool-dir", "--tools-dir", str(tools)],
                    env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stderr, "")
                self.assertEqual(tools.exists(), created)
                self.assertFalse(marker.exists())

    def test_installed_tools_directory_is_required(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--prepare"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("--tools-dir", result.stderr)


if __name__ == "__main__":
    unittest.main()
