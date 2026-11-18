"""CLI refusal checks that never build or execute binding tools."""
import hashlib
import json
import os
import shutil
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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


class BindingWrapperTests(unittest.TestCase):
    module = "golang.org/x/mobile"
    scripts = (
        "mobile/scripts/bind-android.sh",
        "mobile/core/scripts/bind-android.sh",
        "mobile/core/scripts/source-manifest.py",
        "mobile/ios/scripts/build-core.sh",
    )
    stub = """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

program = Path(sys.argv[0]).name
args = sys.argv[1:]
fixture = Path(os.environ["LOCKLARK_TEST_ROOT"])
with (fixture / "trace.jsonl").open("a") as trace:
    trace.write(json.dumps([sys.argv[0], *args]) + "\\n")

if program == "uname" and args == ["-s"]:
    print("Darwin")
elif program == "git" and args == ["rev-parse", "HEAD"]:
    print("0" * 40)
elif program in ("go", "selected-go"):
    module = os.environ["LOCKLARK_TEST_MODULE"]
    if args[0] == "install" and len(args) == 2:
        tool = args[1].removeprefix(module + "/cmd/")
        if tool not in ("gobind", "gomobile"):
            sys.exit(1)
        installed = Path(os.environ["GOBIN"]) / tool
        shutil.copyfile(__file__, installed)
        installed.chmod(0o755)
    elif args == ["list", "-deps", "-json", "./mobile/core"]:
        print(json.dumps({
            "Dir": str(fixture / "mobile/core"),
            "Module": {"Main": True},
            "GoFiles": ["core.go"],
        }))
    elif args[:2] == ["version", "-m"] and len(args) == 3:
        print("mod", module, os.environ["LOCKLARK_TEST_VERSION"], os.environ["LOCKLARK_TEST_SUM"])
    elif args != ["env", "GOROOT"]:
        sys.exit(1)
elif program == "gomobile" and args == ["init"]:
    pass
elif program == "gomobile" and args[0] == "bind":
    subprocess.run(["go", "env", "GOROOT"], check=True)
    subprocess.run(["gobind"], check=True)
    output = Path(args[args.index("-o") + 1])
    if output.suffix == ".xcframework":
        output.mkdir(parents=True)
        output /= "Info.plist"
    output.write_bytes(b"stub binding output")
elif program != "gobind" or args:
    sys.exit(1)
"""

    def run_wrapper(self, root, platform, failure=None):
        repo = SCRIPT.resolve().parents[3]
        for name in (*self.scripts, "go.mod", "go.sum"):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(repo / name, target)
        (root / "mobile/core/core.go").write_text("package core\n")
        version = next(
            fields[1] for line in (root / "go.mod").read_text().splitlines()
            if (fields := line.split())[:1] == [self.module]
        )
        checksum = next(
            fields[2] for line in (root / "go.sum").read_text().splitlines()
            if (fields := line.split())[:2] == [self.module, version]
        )

        host = root / "host"
        selected = root / "selected"
        java = root / "java"
        for directory in (host, selected, java / "bin"):
            directory.mkdir(parents=True)
        (host / "python3").symlink_to(sys.executable)
        go = selected / ("selected-go" if failure == "go-identity" else "go")
        for command in (host / "uname", host / "git", go):
            command.write_text(self.stub)
            command.chmod(0o755)

        shadow = root / "shadow-ran"
        executable(host / "go", shadow)
        for directory in (selected, java / "bin"):
            for tool in ("gobind", "gomobile"):
                executable(directory / tool, shadow)
        if failure == "go-identity":
            executable(selected / "go", shadow)

        if platform == "android":
            script = root / "mobile/scripts/bind-android.sh"
            tools = root / "android-tools/bin"
            artifact = root / "mobile/core/build/mobilecore.aar"
            artifact.parent.mkdir()
        else:
            script = root / "mobile/ios/scripts/build-core.sh"
            tools = root / "mobile/ios/Build/Tools"
            artifact = tools.parent / "Mobilecore.xcframework/Info.plist"
        if failure == "cache":
            tools.mkdir(parents=True)
            executable(tools / "python3", shadow)

        env = {
            "PATH": os.pathsep.join((str(host), os.defpath)),
            "GO_BIN": str(go),
            "ANDROID_HOME": str(root / "android-sdk"),
            "JAVA_HOME": str(java),
            "LOCKLARK_MOBILE_TOOLS": str(tools.parent),
            "LOCKLARK_TEST_ROOT": str(root),
            "LOCKLARK_TEST_MODULE": self.module,
            "LOCKLARK_TEST_VERSION": version,
            "LOCKLARK_TEST_SUM": checksum,
        }
        result = subprocess.run(
            ["/bin/bash", str(script)], cwd=root, env=env,
            capture_output=True, text=True, timeout=15,
        )
        trace_path = root / "trace.jsonl"
        trace = [
            json.loads(line) for line in trace_path.read_text().splitlines()
        ] if trace_path.exists() else []
        self.assertFalse(shadow.exists())
        installs = {tuple(call) for call in trace if call[1:2] == ["install"]}
        expected_installs = {
            (str(go), "install", self.module + "/cmd/" + tool)
            for tool in ("gomobile", "gobind")
        }
        binding_calls = [
            call for call in trace if Path(call[0]).name in ("gomobile", "gobind")
        ]
        if failure:
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(installs, expected_installs if failure == "go-identity" else set())
            self.assertEqual(binding_calls, [])
            self.assertFalse(artifact.exists())
            if failure == "cache":
                self.assertTrue((tools / "python3").is_file())
                self.assertEqual(result.stderr, "Binding tool directory contains an unexpected entry\n")
            else:
                self.assertEqual(result.stderr, 'Binding Go PATH mismatch\n')
            return

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(installs, expected_installs)
        self.assertEqual(binding_calls[0], [str(tools / "gomobile"), "init"])
        self.assertEqual(binding_calls[1][:2], [str(tools / "gomobile"), "bind"])
        self.assertEqual(binding_calls[2:], [[str(tools / "gobind")]])
        self.assertIn([str(go), "env", "GOROOT"], trace)
        self.assertEqual(artifact.read_bytes(), b"stub binding output")
        if platform == "android":
            manifest = json.loads(artifact.with_name("source-manifest.json").read_text())
            for tool in ("gomobile", "gobind"):
                executable_path = tools / tool
                self.assertIn([str(go), "version", "-m", str(executable_path)], trace)
                self.assertEqual(
                    manifest["binding_tools"][tool + "_sha256"],
                    hashlib.sha256(executable_path.read_bytes()).hexdigest(),
                )
            self.assertEqual(manifest["aar_sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())

    def test_wrappers_use_pinned_tools(self):
        for platform in ("android", "ios"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as directory:
                self.run_wrapper(pathlib.Path(directory).resolve(), platform)

    def test_wrappers_refuse_unexpected_cache_before_install(self):
        for platform in ("android", "ios"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as directory:
                self.run_wrapper(pathlib.Path(directory).resolve(), platform, failure="cache")

    def test_wrappers_refuse_go_identity_mismatch_before_init(self):
        for platform in ("android", "ios"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as directory:
                self.run_wrapper(pathlib.Path(directory).resolve(), platform, failure="go-identity")


if __name__ == "__main__":
    unittest.main()
