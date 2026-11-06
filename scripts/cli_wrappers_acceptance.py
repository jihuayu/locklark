#!/usr/bin/env python3
"""End-to-end acceptance for F16 locklark CLI wrappers.

The controller builds (or accepts) a locklark binary and the independent
cli-wrappers fixture. It verifies only non-secret metadata, the NeedsAuth fast
path, denied-argument refusal before prompting, executable pinning, generated
shell functions and privacy of every captured public stream. Failure output is
limited to a fixed stage; private exceptions and stream contents are never
printed.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILES = {
    "gh", "aws", "kubectl", "docker", "npm", "terraform", "git", "netrc",
    "psql", "openai", "anthropic", "stripe", "flyctl", "vercel", "token",
}
DEFAULT_TOOLS = ["aws", "docker", "gh", "git", "kubectl", "npm", "psql", "terraform"]
STAGES = {
    "prerequisites", "profiles", "binding", "list-show", "shell-init",
    "run-help", "run-deny", "tamper", "privacy", "cleanup", "complete",
}
TEST_ID = "0123456789abcdef0123456789abcdef"
TEST_REVISION = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class AcceptanceFailure(Exception):
    pass


def require(condition):
    if not condition:
        raise AcceptanceFailure()


def scan(raw, values):
    """Refuse a secret canary in plain, base64, hex or JSON-escaped form."""
    if isinstance(raw, str):
        raw = raw.encode()
    for value in values:
        if not value:
            continue
        source = value.encode()
        patterns = [
            source,
            base64.b64encode(source),
            source.hex().encode(),
            json.dumps(value)[1:-1].encode(),
        ]
        for pattern in patterns:
            require(pattern not in raw)


def file_mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def write_private(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(raw)
    path.chmod(0o600)


class Acceptance:
    def __init__(self, args):
        self.args = args
        parent = pathlib.Path(args.artifacts).resolve() if args.artifacts else pathlib.Path(tempfile.mkdtemp(prefix="cli-wrappers-artifacts-"))
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            parent.chmod(0o700)
        except OSError:
            pass
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="cli-wrappers-", dir=parent))
        self.root.chmod(0o700)
        self.stage = "prerequisites"
        self.checks = []
        self.logs = []
        self.counter = 0
        self.parent_environment = dict(os.environ)
        self.values = ["Canary" + os.urandom(24).hex() for _ in range(3)]
        self.environment = dict(os.environ)
        self.environment.pop("LOCKLARK_CLI_ACTIVE", None)
        self.environment["LOCKLARK_TEST_SECRET_CANARY"] = self.values[0]
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir(mode=0o700)
        self.cli = pathlib.Path(args.cli).resolve() if args.cli else self.bin_dir / "locklark"
        self.fixture = pathlib.Path(args.fixture_bin).resolve() if args.fixture_bin else self.bin_dir / "cli-wrappers-fixture"
        self.binding_dir = self.root / "binding"
        self.binding_dir.mkdir(mode=0o700)
        self.binding = self.binding_dir / ".locklark-cli.json"
        self.vault = self.root / "owner.ll"

    def private_bytes(self, name, raw):
        self.counter += 1
        path = self.root / f"{self.counter:02d}-{name}"
        write_private(path, raw)
        self.logs.append((path, set()))
        return path

    def mark(self, name):
        self.checks.append(name)
        print("PASS: cli-wrappers " + name, flush=True)

    def go_environment(self):
        environment = dict(os.environ)
        environment.pop("LOCKLARK_CLI_ACTIVE", None)
        environment.setdefault("GOTOOLCHAIN", "go1.27.3")
        return environment

    def build(self, output, package):
        if output.is_file():
            return
        self.bin_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.bin_dir.chmod(0o700)
        except OSError:
            pass
        result = subprocess.run(
            [self.args.go, "build", "-o", str(output), package],
            cwd=ROOT, env=self.go_environment(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=180,
        )
        self.private_bytes("build.stdout", result.stdout)
        self.private_bytes("build.stderr", result.stderr)
        require(result.returncode == 0)

    def prepare(self):
        if not self.args.cli:
            self.build(self.cli, "./cmd/locklark")
        if not self.args.fixture_bin:
            self.build(self.fixture, "./scripts/cli_wrappers_fixture")
        require(self.cli.is_file() and self.fixture.is_file())
        require(self.binding_dir.is_dir())
        if os.name != "nt":
            require(file_mode(self.binding_dir) & 0o077 == 0)
        self.cli = self.cli.resolve()
        self.fixture = self.fixture.resolve()
        self.environment["PATH"] = str(self.fixture.parent) + os.pathsep + self.environment.get("PATH", "")
        self.stage = "prerequisites"

    def command(self, arguments, expected=0, input_bytes=None, timeout=30):
        result = subprocess.run(
            [str(argument) for argument in arguments],
            cwd=self.root, env=self.environment,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout,
        )
        self.private_bytes("command.stdout", result.stdout)
        self.private_bytes("command.stderr", result.stderr)
        require(result.returncode == expected)
        return result

    def init_tool(self, tool, extra=(), profile=None, program=None):
        arguments = [self.cli, "cli", "init", tool]
        if profile:
            arguments.extend(["--profile", profile])
        arguments.extend([
            "--file", self.vault, "--program", program or self.fixture,
            "--binding", self.binding,
        ])
        arguments.extend(extra)
        result = self.command(arguments)
        payload = json.loads(result.stdout)
        require(payload["status"] == "bound" and payload["tool"] == tool)
        return payload

    def read_binding(self):
        require(self.binding.is_file())
        if os.name != "nt":
            require(file_mode(self.binding) == 0o600)
        raw = self.binding.read_bytes()
        scan(raw, self.values)
        payload = json.loads(raw)
        require(payload["version"] == 1 and isinstance(payload["bindings"], dict))
        return payload, raw

    def profiles(self):
        self.stage = "profiles"
        result = self.command([self.cli, "cli", "profiles"])
        payload = json.loads(result.stdout)
        require(isinstance(payload, list))
        require({entry["name"] for entry in payload} == PROFILES)
        for entry in payload:
            require(entry["id"] and isinstance(entry["executables"], list))
            require(entry["slots"] and isinstance(entry["passthrough_env"], list))
            require(isinstance(entry["max_timeout"], int) and entry["max_timeout"] > 0)
        self.mark("all_builtin_profiles_reported")

    def binding_flow(self):
        self.stage = "binding"
        receipt = self.init_tool("gh", ["--id", TEST_ID, "--revision", TEST_REVISION, "--timeout", "60"])
        expected_digest = hashlib.sha256(self.fixture.read_bytes()).hexdigest()
        require(receipt["program"] == str(self.fixture) and receipt["program_sha256"] == expected_digest)
        require(receipt["binding_file"] == str(self.binding) and receipt["profile"] == "gh")
        payload, raw = self.read_binding()
        require(set(payload["bindings"]["gh"]) == {
            "profile", "vault_path", "program", "program_sha256", "targets",
            "helper_path", "timeout_seconds",
        })
        require(payload["bindings"]["gh"]["program_sha256"] == expected_digest)
        require(all(key not in raw for key in (b"token_value", b"secret_value", b"password_value")))
        self.init_tool("docker", ["--id", TEST_ID, "--revision", TEST_REVISION, "--timeout", "60"])
        self.init_tool("npm", ["--id", TEST_ID, "--revision", TEST_REVISION, "--timeout", "60"])
        self.init_tool("aws", ["--id", TEST_ID, "--revision", TEST_REVISION, "--timeout", "60"])
        payload, _ = self.read_binding()
        require(set(payload["bindings"]) == {"gh", "docker", "npm", "aws"})
        require(len(payload["bindings"]["aws"]["targets"]) == 2)
        require(len(payload["bindings"]["docker"]["targets"]) == 2)
        self.mark("owner_only_binding_pinned_program_and_zero_secret_values")

    def list_show(self):
        self.stage = "list-show"
        payload, _ = self.read_binding()
        listed = json.loads(self.command([self.cli, "cli", "list", "--binding", self.binding]).stdout)
        require(listed == payload)
        shown = json.loads(self.command([self.cli, "cli", "show", "gh", "--binding", self.binding]).stdout)
        require(shown == payload["bindings"]["gh"])
        self.command([self.cli, "cli", "list", "--config", self.binding])
        self.mark("list_and_show_return_non_secret_metadata")

    def shell_init(self):
        self.stage = "shell-init"
        for shell in ("bash", "zsh", "fish", "pwsh"):
            result = self.command([self.cli, "cli", "shell-init", shell, "--binding", self.binding, "--tools", "gh,docker"])
            script = result.stdout.decode()
            require("--binding" in script)
            require(not any(line.lstrip().startswith("alias ") for line in script.splitlines()))
            if shell in ("bash", "zsh"):
                require("gh() {" in script and 'command locklark cli run gh' in script and '-- "$@"' in script)
                require("docker() {" in script and "aws()" not in script)
            elif shell == "fish":
                require("function gh --wraps=gh" in script and " -- $argv" in script)
                require("function docker --wraps=docker" in script and "function aws" not in script)
            else:
                require("function Invoke-LocklarkCli_gh" in script)
                require("Set-Alias -Name gh -Value Invoke-LocklarkCli_gh" in script)
                require(" -- @args" in script and "Invoke-LocklarkCli_aws" not in script)
        result = self.command([self.cli, "cli", "shell-init", "--shell", "bash"])
        script = result.stdout.decode()
        require("aws() {" in script and "terraform() {" in script)
        self.mark("shell_functions_not_bare_aliases")

    def run_help(self):
        self.stage = "run-help"
        for tool in ("gh", "docker"):
            result = self.command([self.cli, "cli", "run", tool, "--binding", self.binding, "--", "--help"])
            require(result.stdout == b"fixture help output\n")
            require("主密码".encode() not in result.stdout + result.stderr)
            result = self.command([self.cli, "cli", "run", tool, "--binding", self.binding, "--", "--version"])
            require(result.stdout == b"fixture help output\n")
        self.mark("needs_auth_false_fast_path_runs_without_prompt")

    def denied(self):
        self.stage = "run-deny"
        cases = {
            "gh": ["auth", "login"],
            "docker": ["login"],
            "npm": ["login"],
            "aws": ["configure"],
        }
        for tool, denied_arguments in cases.items():
            report = self.root / ("denied-" + tool + ".json")
            result = self.command([
                self.cli, "cli", "run", tool, "--binding", self.binding, "--",
                report, *denied_arguments,
            ], expected=1)
            require(not result.stdout)
            require("主密码".encode() not in result.stdout + result.stderr)
            require(not report.exists())
        self.mark("denied_arguments_refused_before_prompt_or_execution")

    def tamper(self):
        self.stage = "tamper"
        tampered = self.root / "tampered-tool"
        shutil.copy2(self.fixture, tampered)
        tampered.chmod(0o700)
        payload = self.init_tool("gh-tampered", [
            "--id", TEST_ID, "--revision", TEST_REVISION,
        ], profile="gh", program=tampered)
        require(payload["program"] == str(tampered))
        with open(tampered, "ab") as handle:
            handle.write(b"\n# tampered\n")
        result = self.command([
            self.cli, "cli", "run", "gh-tampered", "--binding", self.binding, "--", "--help",
        ], expected=1)
        require(b"fixture help output" not in result.stdout)
        require("主密码".encode() not in result.stdout + result.stderr)
        require(b"invalid or untrusted CLI binding configuration" in result.stderr)
        self.mark("tampered_pinned_executable_refused")

    def privacy(self):
        self.stage = "privacy"
        for path, allowed in self.logs:
            scan(path.read_bytes(), [value for value in self.values if value not in allowed])
        scan(self.binding.read_bytes(), self.values)
        require(dict(os.environ) == self.parent_environment)
        self.mark("public_streams_and_binding_are_canary_clean")

    def run(self):
        self.prepare()
        self.profiles()
        self.binding_flow()
        self.list_show()
        self.shell_init()
        self.run_help()
        self.denied()
        self.tamper()
        self.privacy()
        self.stage = "complete"
        self.mark("complete")

    def write_result(self):
        write_private(self.root / "result.json", json.dumps({
            "success": self.stage == "complete",
            "stage": self.stage if self.stage in STAGES else "prerequisites",
            "checks": self.checks,
        }).encode())

    def close(self):
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", help="prebuilt locklark executable")
    parser.add_argument("--fixture-bin", help="independently built cli-wrappers fixture")
    parser.add_argument("--go", default="go")
    parser.add_argument("--artifacts", help="private artifact directory")
    args = parser.parse_args(argv)
    os.umask(0o077)
    acceptance = None
    success = False
    try:
        acceptance = Acceptance(args)
        acceptance.run()
        success = True
    except Exception:
        pass
    finally:
        if acceptance:
            try:
                acceptance.close()
            except Exception:
                success, acceptance.stage = False, "cleanup"
            try:
                for path, allowed in acceptance.logs:
                    scan(path.read_bytes(), [value for value in acceptance.values if value not in allowed])
            except Exception:
                success, acceptance.stage = False, "privacy"
            stage = acceptance.stage if acceptance.stage in STAGES else "prerequisites"
            if not success and acceptance.stage not in ("cleanup", "privacy"):
                acceptance.stage = stage
            try:
                acceptance.write_result()
            except Exception:
                success = False
            if not success:
                print("FAIL: cli-wrappers acceptance at " + stage)
            else:
                print("Private cli-wrappers evidence: " + str(acceptance.root))
        else:
            print("FAIL: cli-wrappers acceptance at prerequisites")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
