#!/usr/bin/env python3
"""Actual Windows ConPTY + normal CLI + three independent child stdio pipes.

Requires pywinpty==3.1.2 and the separately built trusted acceptance executable.
Synthetic factors/transcripts stay under an OS-known-folder owner-only ACL.
"""
import argparse
import base64
import ctypes
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.parse


class AcceptanceFailure(Exception):
    pass


def require(value):
    if not value:
        raise AcceptanceFailure()


def screen(raw):
    raw = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", raw)
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw).replace("\r", "")


def scan(raw, values):
    cleaned = screen(raw.decode("utf-8", errors="replace")).encode()
    for value in values:
        require(isinstance(value, str) and bool(value))
        data = value.encode()
        forms = (data, json.dumps(value)[1:-1].encode(), urllib.parse.quote(value, safe="").encode(),
                 base64.b64encode(data), data.hex().encode(), data.hex().upper().encode())
        require(not any(form in raw or form in cleaned for form in forms))


def verify_approved(result, child, stdout, stderr):
    require(result.get("exit_code") == 23 and result.get("timed_out") is False and result.get("console_available") is True)
    require(isinstance(result.get("console_mode_before"), int) and
            result.get("console_mode_before") == result.get("console_mode_after") == child.get("console_mode"))
    require(all(child.get(key) is True for key in ("token_matches", "stdin_matches", "stdio_are_pipes", "only_allowed_environment")))
    require(stdout == b"owned Windows child stdout\n" and stderr == b"owned Windows child stderr\n")


def fixture_phase(raw):
    found = re.findall(rb"owned Windows CLI fixture failed at ([a-z-]+)", raw)
    allowed = {"entry", "artifact-security", "private-root", "vault-create", "vault-login", "owned-job",
               "console-probe", "cli-start", "cli-wait", "pipe-capture", "child-console", "signed-audit"}
    return found[-1].decode() if found and found[-1].decode() in allowed else "unknown"


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.root = None
        self.stage = "prerequisites"
        self.wait = "prerequisites"
        self.fixture_phase = "unknown"
        self.values, self.checks = [], []
        require(os.name == "nt")
        self.cli, self.fixture = str(Path(args.cli).resolve()), str(Path(args.fixture_bin).resolve())
        require(Path(self.cli).is_file() and Path(self.fixture).is_file())

    def command(self, arguments, label, timeout=120):
        result = None
        try:
            result = subprocess.run([self.fixture, *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            raw = result.stdout+result.stderr
        except subprocess.TimeoutExpired as error:
            raw = (error.stdout or b"")+(error.stderr or b"")
        if self.root:
            (self.root / (label+"-controller.log")).write_bytes(raw)
        self.fixture_phase = fixture_phase(raw)
        require(result is not None and result.returncode == 0)
        return result

    def read_json(self, name):
        return json.loads((self.root / name).read_text())

    def setup(self):
        result = self.command(["setup"], "setup")
        lines = result.stdout.decode().splitlines()
        require(len(lines) == 1)
        self.root = Path(lines[0])
        require(self.root.is_absolute() and self.root.is_dir())
        self.command(["verify-private", str(self.root)], "initial-security")
        (self.root / "setup-controller.log").write_bytes(result.stdout+result.stderr)
        fixture = self.read_json("fixture-private.json")
        require(set(fixture) == {"master", "key", "token", "username", "id", "revision"})
        require(bool(re.fullmatch(r"LL1-[A-Z2-7]{26}", fixture["key"])))
        require(bool(re.fullmatch(r"[a-f0-9]{32}", fixture["id"])) and bool(re.fullmatch(r"[a-f0-9]{64}", fixture["revision"])))
        self.values = [fixture[name] for name in ("master", "key", "token", "username")]
        self.factors = fixture

    def conpty(self, label, approval):
        from winpty import PTY
        terminal = PTY(2000, 40, backend=0)  # Explicit native ConPTY.
        view, offset = "", 0
        deadline = time.monotonic()+150
        started = False

        def pump():
            nonlocal view
            try:
                view += terminal.read(blocking=False)
            except EOFError:
                return False
            require(len(view) <= 2*1024*1024)
            time.sleep(.01)
            return True

        try:
            self.wait = "console-start"
            require(terminal.spawn(self.fixture, " "+subprocess.list2cmdline(["launch", str(self.root), self.cli, label])))
            started = True
            for waiting, prompt, value in (("password-prompt", "主密码:", self.factors["master"]),
                                            ("key-prompt", "Secret Key:", self.factors["key"]),
                                            ("approval-prompt", "输入 RUN 确认本次可信命令披露:", approval)):
                self.wait = waiting
                while prompt not in screen(view)[offset:]:
                    require(time.monotonic() < deadline and terminal.isalive())
                    pump()
                rendered = screen(view)
                offset = rendered.index(prompt, offset)+len(prompt)
                terminal.write(value+"\r")
            self.wait = "console-exit"
            while terminal.isalive():
                require(time.monotonic() < deadline)
                pump()
            require(terminal.get_exitstatus() == 0)
            self.wait = "console-drain"
            quiet = time.monotonic()
            while time.monotonic() < min(deadline, quiet+1):
                length = len(view)
                if not pump():
                    break
                if len(view) != length:
                    quiet = time.monotonic()
            require("OWNED_WINDOWS_CLI_DONE" in screen(view)[offset:])
        finally:
            try:
                if started and terminal.isalive():
                    # Exact process handle, avoiding PID reuse; fixture Job Object
                    # closes/kills only its CLI/child tree when this owner exits.
                    terminate = ctypes.WinDLL("kernel32", use_last_error=True).TerminateProcess
                    terminate.argtypes, terminate.restype = [ctypes.c_void_p, ctypes.c_uint], ctypes.c_int
                    require(terminal.fd is not None and terminate(terminal.fd, 95))
            finally:
                (self.root / (label+"-conpty.log")).write_text(view, encoding="utf-8")
                self.fixture_phase = fixture_phase(screen(view).encode())

    def mark(self, value):
        self.checks.append(value)
        print("PASS: Windows RunCLI "+value, flush=True)

    def run(self):
        self.setup()
        self.stage = "approved-console-and-pipes"
        self.conpty("approved", "RUN")
        self.wait = "approved-oracle"
        child = self.read_json("approved-child.json")
        verify_approved(self.read_json("approved-result.json"), child,
                        (self.root / "approved-stdout.log").read_bytes(), (self.root / "approved-stderr.log").read_bytes())
        require(isinstance(child.get("temporary_root"), str) and not Path(child["temporary_root"]).exists())
        self.scan()
        self.mark("native_CONIN_CONOUT_hidden_factors_explicit_RUN_exact_token_three_pipes_exit23_no_footer_and_cleanup")
        self.stage = "deny-before-child"
        self.conpty("denied", "NO")
        self.wait = "denial-oracle"
        result = self.read_json("denied-result.json")
        require(result.get("exit_code") == 1 and result.get("timed_out") is False)
        require(not (self.root / "denied-child.json").exists() and not (self.root / "denied-stdout.log").read_bytes())
        require(b"local process cancelled" in (self.root / "denied-stderr.log").read_bytes())
        self.mark("explicit_denial_never_starts_child")
        self.stage = "no-controlling-console"
        self.wait = "no-console-oracle"
        self.command(["launch", str(self.root), self.cli, "no-console"], "no-console", timeout=130)
        result = self.read_json("no-console-result.json")
        require(result.get("exit_code") == 1 and result.get("timed_out") is False)
        require(not (self.root / "no-console-child.json").exists() and not (self.root / "no-console-stdout.log").read_bytes())
        error = (self.root / "no-console-stderr.log").read_bytes()
        require(b"requires an interactive terminal with a controlling console" in error and "主密码".encode() not in error)
        self.mark("CREATE_NO_WINDOW_refuses_before_factors_or_child")
        self.stage = "signed-audit"
        self.command(["audit", str(self.root)], "audit")
        require(self.read_json("audit-result.json") == {"run_intents":1, "exact_target":True})
        self.mark("real_vault_has_one_exact_target_signed_intent_only")
        self.stage = "privacy"
        self.scan()
        self.command(["verify-private", str(self.root)], "final-security")
        self.scan()
        self.mark("private_OS_known_folder_ACLs_and_complete_output_canaries")
        self.stage = "complete"

    def scan(self):
        require(bool(self.values))
        for path in self.root.iterdir():
            if path.is_file() and path.name != "fixture-private.json":
                scan(path.read_bytes(), self.values)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--fixture-bin", required=True)
    args = parser.parse_args(argv)
    acceptance, success = None, False
    try:
        acceptance = Acceptance(args)
        acceptance.run()
        success = True
    except (Exception, KeyboardInterrupt):
        pass
    finally:
        if acceptance and acceptance.root:
            try:
                acceptance.scan()
            except Exception:
                success, acceptance.stage = False, "privacy"
            try:
                (acceptance.root / "result.json").write_text(json.dumps({"success":success,"stage":acceptance.stage,"wait":acceptance.wait,"checks":acceptance.checks}))
            except Exception:
                success, acceptance.stage = False, "private-evidence"
            print("Private Windows RunCLI evidence: "+str(acceptance.root))
    if not success:
        print("FAIL: Windows RunCLI acceptance at "+(acceptance.stage if acceptance else "prerequisites"))
        if acceptance:
            print("Fixed Windows RunCLI wait: "+acceptance.wait)
            print("Fixed Windows fixture phase: "+acceptance.fixture_phase)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
