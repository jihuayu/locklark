#!/usr/bin/env python3
"""Real external acceptance for the desktop CLI credential approval.

The controller reuses ``desktop_native_acceptance.Acceptance`` for the private
synthetic vault fixture, the real desktop App, the private observer pipe and
physical native input. It binds one ordinary fixture login to the ``openai``
profile through the real ``locklark cli init``, then starts a real
``locklark cli run`` inside a genuine controlling terminal and lets the owner
decide in the real native window.

Default mode (unchanged one-shot acceptance): one approval, then one refusal of
a second fresh request. Each request is a new CLI process; the launcher
``scripts/run_cli_fixture ctty`` opens the caller-supplied pseudo terminal,
claims it as the controlling terminal and execs the normal CLI, so no product
test switch is involved.

Optional ``--lease`` mode adds the explicit five-minute terminal lease proof on
top of the one-shot cases. ``scripts/run_cli_fixture ctty`` calls ``setsid()``
per invocation, so it can never present two CLI processes on one terminal. The
owner fixture ``scripts/cli_lease_terminal_fixture`` therefore keeps one
session leader alive on a private pseudo terminal and launches successive
ordinary CLI processes inside that same kernel session and controlling tty, each
with its own pid, its own externally owned stdio pipes and its own exit status.
The acceptance reads the real ``/proc/<pid>/stat`` session and tty number and
``/proc/<pid>/exe`` of every child; there is no attestation seam or hook. The
same ordinary CLI executable, binding, targets, argv, cwd, helper and
environment are used, and only the report argument differs for the
changed-argument case.

The fake child is the existing ``scripts/cli_wrappers_fixture``: it writes a
hash-only JSON report and never prints a credential.

Nothing here opens a socket message, injects JavaScript authorization, calls an
approval API or passes a credential in argv or in the environment of the
controller. Controller commands are fully formed argv lists of owned
executables: no shell text is ever used. Only fixed stages and booleans are
printed publicly; captured streams and owned artifacts stay private and are
scanned for every synthetic canary.
"""
import argparse
import hashlib
import json
import os
import pathlib
import pty
import re
import select
import stat
import subprocess
import sys
import tempfile
import threading
import time

from desktop_native_acceptance import Acceptance as DesktopAcceptance
from desktop_native_acceptance import AcceptanceFailure, require
import cli_wrappers_acceptance as wrappers
from cli_lease_terminal_fixture import FixtureError, TerminalSession

ROOT = pathlib.Path(__file__).resolve().parents[1]

TOOL = "openai"
PROFILE = "openai"
TARGET_TITLE = "Daily other login"
ENVIRONMENT_NAME = "OPENAI_API_KEY"
APPROVE_LABEL = "仅批准本次 CLI 请求"
REFUSE_LABEL = "拒绝本次请求"
# Exact product label from internal/desktop/ipc_broker.go (cliV2LeaseLabel); the
# pure unit test pins this literal against the product source.
LEASE_LABEL = "批准此终端相同命令 5 分钟"
LOCK_LABEL = "立即锁定"
UNLOCKED_LABEL = LOCK_LABEL
DIALOG_LABELS = (APPROVE_LABEL, LEASE_LABEL, REFUSE_LABEL)
# The product TTL is an absolute, non-extending five minutes. This acceptance
# never waits 300 real seconds and never fakes a clock: the wall-clock expiry
# proof is reported as not-run and stays with the product's own timer/race
# tests.
LEASE_TTL_SECONDS = 300
# The local full-factor fallback is the only path that may render these. Their
# appearance before a decision, or during a refusal, is a hard failure.
FACTOR_MARKERS = (b"\xe4\xb8\xbb\xe5\xaf\x86\xe7\xa0\x81", b"Secret Key", b"\xe8\xbe\x93\xe5\x85\xa5 RUN",
                  "\u5c06\u4ee5\u4e0b\u4e00\u6b21\u6027\u51ed\u636e".encode())
STAGES = {"setup", "unlock", "binding", "approve-request", "approve", "deliver",
          "cleanup", "refuse-request", "refuse", "refusal", "privacy", "complete",
          "internal",
          "lease-terminal", "oneshot-request", "oneshot", "repeat-request", "repeat",
          "lease-request", "lease", "reuse", "changed-arg-request", "changed-arg",
          "changed-terminal-request", "changed-terminal", "lock", "after-lock",
          "after-unlock-request", "after-unlock"}
APPROVAL_TIMEOUT = 25.0
EXIT_TIMEOUT = 120.0
# The fixture already reports only fixed short codes. They are whitelisted here
# so a controller failure can name the failed launch substep without ever
# printing an exception body, captured bytes or a fixture factor.
FIXTURE_FAILURE_REASONS = frozenset({
    "argv", "env", "program", "cwd", "stdio", "fork", "run", "status", "stop",
    "pid", "operation", "session-control", "session-eof", "session-frame",
    "session-ready", "session-identity", "session-not-started", "child-exe",
    "child-noexe", "child-waitingstatus", "child-wrongexe",
    "child-identity", "proc-stat",
})
# Every lease substep that can fail has a fixed public reason. The reason is
# written to the private failure.json and the single public FAIL line; it never
# contains payload bytes, paths or exception text.
LEASE_REASONS = frozenset({
    "lease-command", "lease-spawn", "lease-argv", "lease-executable",
    "lease-kernel-live", "lease-kernel-pid", "lease-kernel-session",
    "lease-kernel-tty", "lease-kernel-leader", "lease-kernel-exe",
    "lease-live-proof-missing", "lease-finished-pid", "lease-finished-session",
    "lease-finished-tty", "lease-finished-exe", "lease-finished-state",
    "lease-finished-signaled", "lease-finished-zero",
    "lease-factor-fallback", "unexpected-lease-dialog", "lease-run-timeout",
    "lease-refusal-signaled", "lease-refusal-zero", "lease-refusal-exit",
    "lease-grant-exit", "lease-intent-count", "lease-intent-fresh",
    "lease-intent-present", "lease-lock-kernel-peek", "lease-lock-report",
    "lease-lock-intent", "lease-lock-code", "lease-temp", "lease-captures",
    "lease-intent-shape", "lease-report-present", "lease-refusal-product-marker",
})


def child_report_matches(raw, tool, expected_sha256):
    """True only for the fake child's fixed hash-only report shape."""
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return False
    if not isinstance(payload, dict) or payload.get("ok") is not True or payload.get("tool") != tool:
        return False
    digests = payload.get("env_sha256")
    if not isinstance(digests, dict):
        return False
    return digests.get(ENVIRONMENT_NAME) == expected_sha256


def factor_prompt_present(raw):
    """True when a captured stream contains a local fallback factor prompt."""
    if isinstance(raw, str):
        raw = raw.encode()
    return any(marker in raw for marker in FACTOR_MARKERS)


def cli_run_arguments(wrapper, cli, terminal, binding, report):
    """Fixed launcher argv: only public paths, the tool name and selectors."""
    return [str(wrapper), "ctty", str(terminal), str(cli), "cli", "run", TOOL,
            "--binding", str(binding), "--", str(report), TOOL]


def cli_init_arguments(cli, vault, program, binding, item_id, revision):
    """Normal documented ``cli init`` metadata; it never carries a value."""
    return [str(cli), "cli", "init", TOOL, "--profile", PROFILE, "--file", str(vault),
            "--program", str(program), "--binding", str(binding),
            "--id", item_id, "--revision", revision, "--timeout", "60"]


def lease_command(cli, binding, report):
    """The exact ordinary CLI argv used for every shared-terminal run.

    It is byte for byte the command ``run_cli_fixture ctty`` execs, minus the
    launcher: the persistent owner fixture already owns the real terminal. The
    changed-argument case reuses this builder with a different report path, so
    only the report argument differs from the lease command.
    """
    return [str(cli), "cli", "run", TOOL, "--binding", str(binding), "--", str(report), TOOL]


def validate_lease_command(arguments, cli, binding, report):
    """Refuse anything that is not this fixture's known owned CLI argv.

    The controller must never hand a shell string or an arbitrary program to
    the terminal fixture. Only the resolved ordinary CLI executable and the
    fixed subcommand/flags/paths below are allowed.
    """
    require(isinstance(arguments, list) and arguments)
    require(all(isinstance(part, str) and part for part in arguments))
    for part in arguments:
        require("\x00" not in part and "\n" not in part and "\r" not in part)
    require(os.path.realpath(arguments[0]) == os.path.realpath(str(cli)))
    require(arguments[1:] == ["cli", "run", TOOL, "--binding", str(binding),
                              "--", str(report), TOOL])
    return arguments


class CliRun:
    """One real ``locklark cli run`` inside a genuine controlling terminal."""

    def __init__(self, wrapper, cli, binding, report, environment, directory):
        master, slave = pty.openpty()
        try:
            arguments = cli_run_arguments(wrapper, cli, os.ttyname(slave), binding, report)
            self.process = subprocess.Popen(
                arguments, cwd=str(directory), env=environment, stdin=slave,
                stdout=subprocess.PIPE, stderr=slave, start_new_session=True,
                close_fds=True)
        except BaseException:
            os.close(master)
            os.close(slave)
            raise
        os.close(slave)
        self.master = master
        self.terminal = bytearray()
        self.standard_output = bytearray()
        self.lock = threading.Lock()
        self.running = True
        self.readers = [threading.Thread(target=self.read_terminal, daemon=True),
                        threading.Thread(target=self.read_standard_output, daemon=True)]
        for reader in self.readers:
            reader.start()

    def read_terminal(self):
        while self.running:
            try:
                ready = select.select([self.master], [], [], 0.1)[0]
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 4096)
            except OSError:
                return
            if not chunk:
                return
            with self.lock:
                self.terminal.extend(chunk)

    def read_standard_output(self):
        while self.running:
            try:
                chunk = self.process.stdout.read(4096)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            with self.lock:
                self.standard_output.extend(chunk)

    def captured_terminal(self):
        with self.lock:
            return bytes(self.terminal)

    def captured_standard_output(self):
        with self.lock:
            return bytes(self.standard_output)

    def wait(self, timeout):
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def stop(self):
        self.running = False
        if self.process.poll() is None:
            self.process.kill()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        for reader in self.readers:
            reader.join(timeout=5)
        try:
            os.close(self.master)
        except OSError:
            pass
        try:
            self.process.stdout.close()
        except (OSError, ValueError):
            pass


class Acceptance(DesktopAcceptance):
    # The five-minute terminal lease proof is opt-in; the default acceptance is
    # the unchanged one-shot approve/refuse run.
    lease = False

    def __init__(self, args):
        self.args = args
        self.lease = bool(getattr(args, "lease", False))
        self.observed = {}
        self.captured = []
        self.cli_runs = []
        self.lease_runs = []
        self.sessions = []
        self.primary = None
        self.alternate = None
        self.intents = set()
        self.processes = set()
        self.private = pathlib.Path(tempfile.mkdtemp(prefix="locklark-cli-desktop-"))
        self.private.chmod(0o700)
        self.bin = self.directory("bin")
        self.cli = pathlib.Path(args.cli).resolve() if args.cli else self.bin / "locklark"
        self.child = pathlib.Path(args.fixture_bin).resolve() if args.fixture_bin else self.bin / "cli-wrappers-fixture"
        self.wrapper = pathlib.Path(args.wrapper_bin).resolve() if args.wrapper_bin else self.bin / "run-cli-fixture"
        self.desktop_host = pathlib.Path(args.desktop_host).resolve() if args.desktop_host else self.bin / "locklark-desktop"
        self.go = args.go or os.environ.get("LOCKLARK_GO", "go")
        for output, package in ((self.cli, "./cmd/locklark"),
                                (self.child, "./scripts/cli_wrappers_fixture"),
                                (self.wrapper, "./scripts/run_cli_fixture"),
                                (self.desktop_host, "./cmd/locklark-desktop")):
            if not output.is_file():
                self.build(output, package)
        os.environ["LOCKLARK_DESKTOP_HOST"] = str(self.desktop_host)
        super().__init__()
        self.go = args.go or os.environ.get("LOCKLARK_GO", "go")
        # Isolated private runtime roots for both the App and the CLI: never the
        # owner's real HOME, TMPDIR, XDG directories or default broker socket.
        self.home = self.directory("home")
        self.iso_tmp = self.directory("tmp")
        self.cli_tmp = self.directory("cli-tmp")
        self.xdg = {name: self.directory(name.lower().replace("_home", ""))
                    for name in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR")}
        self.socket = str(self.directory("sock") / "s")
        self.isolated = {"HOME": str(self.home), "TMPDIR": str(self.iso_tmp),
                         "LOCKLARK_BROWSER_SOCKET": self.socket}
        self.isolated.update({name: str(path) for name, path in self.xdg.items()})
        self.env.update(self.isolated)
        self.env.pop("LOCKLARK_CLI_ACTIVE", None)
        # The CLI gets its own empty temporary root so "cleaned" is observable.
        self.cli_env = dict(self.env)
        self.cli_env["TMPDIR"] = str(self.cli_tmp)
        self.reports = self.directory("reports")
        self.work = self.directory("work")
        self.binding = self.directory("binding") / "binding.json"
        self.report_approve = self.reports / "approve.json"
        self.report_refuse = self.reports / "refuse.json"
        # Shared-terminal report paths. Runs that must present the *same*
        # command reuse the same path, and the file is removed before the next
        # run so "absent before, present after" proves a fresh execution.
        self.report_oneshot = self.reports / "oneshot.json"
        self.report_lease = self.reports / "lease.json"

    def directory(self, name):
        path = self.private / name
        path.mkdir(mode=0o700)
        return path

    def build(self, output, package):
        environment = dict(os.environ)
        environment.pop("LOCKLARK_CLI_ACTIVE", None)
        environment.setdefault("GOTOOLCHAIN", "go1.27.3")
        result = subprocess.run([self.go, "build", "-o", str(output), package],
                                cwd=ROOT, env=environment, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=900)
        if result.returncode != 0:
            self.reason = "build"
            raise AcceptanceFailure()
        return output

    def phase(self, value):
        # Public transcript: only the fixed stage vocabulary is ever printed.
        self.stage = value if value in STAGES else "internal"
        self.emit("CLI desktop native stage: " + self.stage)

    def fail(self, reason):
        self.reason = reason
        raise AcceptanceFailure()

    def check(self, condition, reason):
        """Fail with one fixed lease substep reason, never arbitrary text."""
        self.reason = reason if reason in LEASE_REASONS else "lease-command"
        if not condition:
            raise AcceptanceFailure()

    def fixture_reason(self, error):
        """Map a fixture's fixed short code to a fixed controller reason."""
        code = str(error)
        return "fixture-" + code if code in FIXTURE_FAILURE_REASONS else "fixture-unknown"

    @staticmethod
    def run_has_live_identity(run):
        """True only for a real live /proc peek of the actual CLI executable."""
        identity = getattr(run, "identity", None)
        if not isinstance(identity, dict) or identity.get("live_exe") is not True:
            return False
        return isinstance(identity.get("exe"), str) and bool(identity.get("exe"))

    def capture(self, arguments, environment=None, timeout=60, expected=0):
        result = subprocess.run([str(argument) for argument in arguments], cwd=ROOT,
                                env=environment or self.env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout)
        self.captured.extend((result.stdout, result.stderr))
        if result.returncode != expected:
            self.fail("cli-command")
        return result

    def unlock(self):
        # The funded default UI shows 立即锁定 once unlocked; the legacy
        # 新建登录 wait belongs to an older layout and never appears here.
        self.phase("unlock")
        self.input([{"click_label": "金库文件"}, {"key": "Control_L+a"},
                    {"text": self.fixture["Path"]},
                    {"click_label": "主密码"}, {"text": self.fixture["Password"]},
                    {"click_label": "Secret Key"}, {"text": self.fixture["Secret"]},
                    {"click_label": "解锁"}, {"wait_label": UNLOCKED_LABEL}])

    def bind(self):
        self.phase("binding")
        snapshot = self.observe()
        rows = [item for item in snapshot["items"]
                if item["title"] == TARGET_TITLE and item["state"] == "active"]
        require(len(rows) == 1)
        target = rows[0]
        require(target["Password"] == self.fixture["Value"])
        item_id, revision = target["id"], target["revision"]
        require(re.fullmatch(r"[0-9a-f]{32}", item_id) is not None)
        require(re.fullmatch(r"[0-9a-f]{64}", revision) is not None)
        result = self.capture(cli_init_arguments(self.cli, self.fixture["Path"], self.child,
                                                 self.binding, item_id, revision))
        receipt = json.loads(result.stdout)
        require(receipt["status"] == "bound" and receipt["tool"] == TOOL and receipt["profile"] == PROFILE)
        require(receipt["program"] == str(self.child) and receipt["binding_file"] == str(self.binding))
        require(receipt["program_sha256"] == hashlib.sha256(self.child.read_bytes()).hexdigest())
        require(stat.S_IMODE(os.stat(self.binding).st_mode) == 0o600)
        raw = self.binding.read_bytes()
        wrappers.scan(raw, self.values)
        store = json.loads(raw)
        require(store["version"] == 1 and set(store["bindings"]) == {TOOL})
        binding = store["bindings"][TOOL]
        require(binding["profile"] == PROFILE and binding["program"] == str(self.child))
        require(binding["vault_path"] == self.fixture["Path"])
        require(binding["targets"] == [{"slot": "token", "id": item_id,
                                        "revision": revision, "field": "password"}])
        self.observed["binding-pinned-exact-revision"] = True

    def assert_no_factor_fallback(self, run):
        if factor_prompt_present(run.captured_terminal()):
            self.fail("fallback-factor-prompt")
        if factor_prompt_present(run.captured_standard_output()):
            self.fail("fallback-factor-prompt")

    def await_decision(self, label, run):
        deadline = time.monotonic() + APPROVAL_TIMEOUT
        while time.monotonic() < deadline:
            self.assert_no_factor_fallback(run)
            if run.process.poll() is not None:
                self.fail("cli-exited-before-decision")
            try:
                present = self.controls().get(label, {}).get("present") is True
            except AcceptanceFailure:
                present = False
            if present:
                return
            time.sleep(0.15)
        self.fail("approval-window-timeout")

    def verify_child_report(self, report, expected):
        require(report.is_file())
        if stat.S_IMODE(os.stat(report).st_mode) != 0o600:
            self.fail("child-report-mode")
        raw = report.read_bytes()
        wrappers.scan(raw, self.values)
        if not child_report_matches(raw, TOOL, expected):
            self.fail("child-report-mismatch")

    def cli_temp_is_clean(self):
        try:
            return not os.listdir(self.cli_tmp)
        except OSError:
            return False

    def assert_clean_run_roots(self):
        try:
            remaining = os.listdir(self.cli_tmp)
        except OSError:
            self.fail("isolated-temp")
        if remaining:
            self.fail("isolated-temp-not-clean")

    def request_decision(self, label, report, request_stage, decide_stage):
        self.phase(request_stage)
        require(not report.exists())
        run = CliRun(self.wrapper, self.cli, self.binding, report, self.cli_env, self.work)
        self.cli_runs.append(run)
        self.await_decision(label, run)
        # Before the owner decides: no child execution artifact and no local
        # master-password / Secret Key / disclosure prompt.
        require(not report.exists())
        self.assert_no_factor_fallback(run)
        self.phase(decide_stage)
        self.click(label)  # one physical native decision, never repeated
        code = run.wait(EXIT_TIMEOUT)
        if code is None:
            self.fail("cli-run-timeout")
        return run, code

    def approve_case(self):
        run, code = self.request_decision(APPROVE_LABEL, self.report_approve,
                                          "approve-request", "approve")
        self.phase("deliver")
        self.observed["approve-exit-zero"] = code == 0
        require(code == 0)
        self.verify_child_report(self.report_approve,
                                 hashlib.sha256(self.fixture["Value"].encode()).hexdigest())
        self.observed["approve-hash-match"] = True
        self.assert_no_factor_fallback(run)
        wrappers.scan(run.captured_terminal(), self.values)
        wrappers.scan(run.captured_standard_output(), self.values)
        self.phase("cleanup")
        self.assert_clean_run_roots()
        self.observed["approve-isolated-clean"] = True

    def refuse_case(self):
        run, code = self.request_decision(REFUSE_LABEL, self.report_refuse,
                                          "refuse-request", "refuse")
        self.phase("refusal")
        self.observed["refuse-exit-nonzero"] = code != 0
        require(code != 0)
        require(not self.report_refuse.exists())
        self.observed["refuse-report-absent"] = True
        # A refusal is final: it must never fall back to local factor prompts.
        self.assert_no_factor_fallback(run)
        self.observed["refuse-no-factor-fallback"] = True
        wrappers.scan(run.captured_terminal(), self.values)
        wrappers.scan(run.captured_standard_output(), self.values)
        self.assert_clean_run_roots()
        self.observed["refuse-isolated-clean"] = True

    # --- optional explicit five-minute terminal lease mode -----------------

    def open_sessions(self):
        """Fork both private session leaders before any helper thread exists."""
        self.phase("lease-terminal")
        sessions = []
        try:
            sessions.append(TerminalSession())
            sessions.append(TerminalSession())
            for session in sessions:
                session.start()
                identity = session.identity
                require(identity["session"] == identity["pid"])
                require(identity["tty_nr"] != 0)
                require(identity["fd0"] == identity["tty_path"])
                require(stat.S_ISCHR(os.stat(session.tty_path).st_mode))
        except BaseException:
            for session in sessions:
                session.close()
            raise
        self.primary, self.alternate = sessions
        self.sessions = sessions
        # A changed terminal/session must be a genuinely different kernel
        # terminal, otherwise the negative case below would prove nothing.
        require(self.primary.identity["tty_nr"] != self.alternate.identity["tty_nr"])
        require(self.primary.identity["session"] != self.alternate.identity["session"])
        self.observed["lease-terminal-distinct"] = True

    def assert_kernel_identity(self, session, run):
        """Require the real kernel evidence for one ordinary CLI process."""
        identity, terminal = run.identity, session.identity
        self.check(identity.get("live_exe") is True, "lease-kernel-live")
        self.check(identity.get("pid") == run.pid and identity.get("pid") != terminal.get("pid"),
                   "lease-kernel-pid")
        self.check(identity.get("session") == terminal.get("session") == terminal.get("pid"),
                   "lease-kernel-session")
        self.check(identity.get("tty_nr") == terminal.get("tty_nr") and identity.get("tty_nr") != 0,
                   "lease-kernel-tty")
        self.check(identity.get("session") != identity.get("pid"), "lease-kernel-leader")
        self.check(os.path.realpath(identity["exe"]) == os.path.realpath(str(self.cli)),
                   "lease-kernel-exe")
        self.processes.add(identity["pid"])
        self.observed["lease-child-exe-proof"] = True
        observed = self.observed.setdefault("lease-pids", [])
        if identity["pid"] not in observed:
            observed.append(identity["pid"])

    def assert_run_no_factor_prompt(self, run):
        self.reason = "lease-factor-fallback"
        for raw in (run.captured_terminal(), run.captured_stdout(), run.captured_stderr()):
            if factor_prompt_present(raw):
                self.fail("fallback-factor-prompt")

    def assert_run_captures_clean(self, run):
        self.reason = "lease-captures"
        wrappers.scan(run.captured_terminal(), self.values)
        wrappers.scan(run.captured_stdout(), self.values)
        wrappers.scan(run.captured_stderr(), self.values)

    def safe_controls(self):
        try:
            return self.controls()
        except AcceptanceFailure:
            return {}

    def launch_shared(self, session, report, expect_refusal=False):
        """Start one ordinary CLI process on the persistent real terminal.

        ``expect_refusal`` is set by exactly one caller: the request after the
        real native lock. That request is expected to be refused by the product
        before any dialog, so the real CLI may already have exited by the time
        the controller looks at it. Only that explicit mode may accept a
        finished process without a live /proc/<pid>/exe peek, and only when
        all of the other evidence is still real: the controller's exact
        whitelisted executable/argv/binding, the actual forked pid and the
        kernel session/tty captured at fork, a real reaped nonzero exit, no
        child and no intent. Every grant, reuse and wrong-terminal run still
        requires the full live kernel exe proof.
        """
        self.reason = "lease-command"
        require(not report.exists())
        arguments = validate_lease_command(lease_command(self.cli, self.binding, report),
                                           self.cli, self.binding, report)
        self.reason = "lease-spawn"
        try:
            run = session.run(arguments, self.work, self.cli_env,
                              allow_finished=expect_refusal is True)
        except FixtureError as error:
            self.reason = self.fixture_reason(error)
            raise
        self.lease_runs.append(run)
        self.check(tuple(run.argv) == tuple(arguments), "lease-argv")
        self.check(os.path.realpath(arguments[0]) == os.path.realpath(str(self.cli)),
                   "lease-executable")
        if self.run_has_live_identity(run):
            self.assert_kernel_identity(session, run)
            return run
        # No live /proc/<pid>/exe peek. This is only acceptable for the one
        # expected post-lock refusal; anything else is an unknown outcome, not
        # a proven refusal.
        self.check(expect_refusal is True, "lease-live-proof-missing")
        identity = run.identity or {}
        terminal = session.identity
        self.check(identity.get("pid") == run.pid and identity.get("pid") != terminal.get("pid"),
                   "lease-finished-pid")
        self.check(isinstance(identity.get("session"), int)
                   and identity.get("session") == terminal.get("session") == terminal.get("pid"),
                   "lease-finished-session")
        self.check(isinstance(identity.get("tty_nr"), int)
                   and identity.get("tty_nr") == terminal.get("tty_nr")
                   and identity.get("tty_nr") != 0,
                   "lease-finished-tty")
        self.check(identity.get("live_exe") is False and identity.get("exe") is None,
                   "lease-finished-exe")
        state = run.status()
        self.check(isinstance(state, dict)
                   and state.get("state") in ("exited", "signaled"),
                   "lease-finished-state")
        self.check(state.get("state") == "exited", "lease-finished-signaled")
        self.check(isinstance(state.get("code"), int) and state.get("code") != 0,
                   "lease-finished-zero")
        self.processes.add(identity["pid"])
        # The controller must not pretend it saw the fast refusal's live
        # executable; the receipt reports this honestly as not-available.
        self.observed["lease-finished-refusal-peek"] = "not-available"
        return run

    def await_dialog(self, run):
        """Wait for the real native approval view; returns the controls seen."""
        deadline = time.monotonic() + APPROVAL_TIMEOUT
        while time.monotonic() < deadline:
            self.assert_run_no_factor_prompt(run)
            if run.status() is not None:
                self.fail("cli-exited-before-decision")
            controls = self.safe_controls()
            if any(controls.get(label, {}).get("present") is True for label in DIALOG_LABELS):
                return controls
            time.sleep(0.15)
        self.fail("approval-window-timeout")

    def decided_run(self, session, report, request_stage, decide_stage, label):
        """One CLI process in the shared terminal decided by a physical click."""
        self.phase(request_stage)
        run = self.launch_shared(session, report)
        controls = self.await_dialog(run)
        if controls.get(label, {}).get("present") is not True:
            # The v2 dialog is up but this decision control is missing: most
            # likely the product refused the kernel terminal proof, which must
            # never be downgraded to a silent one-shot here.
            self.fail("lease-button-missing" if label == LEASE_LABEL else "decision-label-missing")
        self.assert_run_no_factor_prompt(run)
        require(not report.exists())
        self.phase(decide_stage)
        self.click(label)  # one physical native decision, never repeated
        code = run.wait(EXIT_TIMEOUT)
        if code is None:
            self.fail("cli-run-timeout")
        return run, code

    def quiet_run(self, session, report, stage, expect_refusal=False):
        """Run to completion without a dialog; any dialog seen is fatal.

        ``expect_refusal`` is only for the request after the real native lock.
        It still requires the same exact executable/argv/binding and the real
        kernel session/tty captured at fork, plus a real nonzero reaped exit,
        no child, no intent and no local factor prompt. A zero exit, a signal
        or a missing identity is never turned into a refusal.
        """
        self.phase(stage)
        run = self.launch_shared(session, report, expect_refusal=expect_refusal)
        deadline = time.monotonic() + EXIT_TIMEOUT
        while True:
            self.reason = "lease-factor-fallback"
            self.assert_run_no_factor_prompt(run)
            controls = self.safe_controls()
            if any(controls.get(label, {}).get("present") is True for label in DIALOG_LABELS):
                self.fail("unexpected-lease-dialog")
            state = run.status()
            if state is not None:
                if expect_refusal:
                    # Drain the actual externally owned pipes so a late local
                    # factor prompt cannot hide in an unread kernel buffer.
                    run.drain(5.0)
                    self.reason = "lease-factor-fallback"
                    self.assert_run_no_factor_prompt(run)
                    self.check(state.get("state") == "exited", "lease-refusal-signaled")
                    self.check(isinstance(state.get("code"), int) and state.get("code") != 0,
                               "lease-refusal-zero")
                    self.check(b"locklark: desktop browser broker refused the request" in run.captured_stderr(),
                               "lease-refusal-product-marker")
                return run, state.get("code", -1)
            if time.monotonic() >= deadline:
                self.fail("lease-run-timeout")
            time.sleep(0.1)

    def intent_links(self):
        """Committed ``item.run.bundle`` intents from the real vault audit."""
        snapshot = self.observe()
        links = []
        for event in self.events(snapshot, "item.run.bundle"):
            if event.get("result") != "intent":
                continue
            link = event.get("link")
            if not isinstance(link, str) or re.fullmatch(r"[0-9a-f]{64}", link) is None:
                self.fail("lease-intent-shape")
            links.append(link)
        return links

    def expect_new_intent(self, before):
        after = self.intent_links()
        self.check(len(after) == len(before) + 1, "lease-intent-count")
        fresh = [link for link in after if link not in set(before)]
        self.check(len(fresh) == 1, "lease-intent-fresh")
        self.check(fresh[0] not in self.intents, "lease-intent-fresh")
        self.intents.add(fresh[0])
        return fresh[0]

    def expect_no_intent(self, before):
        self.check(self.intent_links() == before, "lease-intent-present")

    def forget_report(self, report):
        try:
            report.unlink()
        except FileNotFoundError:
            pass

    def assert_expected_refusal_evidence(self, run, code, before, report):
        """No child, no intent, no factor fallback, real nonzero exit, clean."""
        self.check(isinstance(code, int) and code != 0, "lease-lock-code")
        self.check(not report.exists(), "lease-lock-report")
        self.check(self.intent_links() == before, "lease-lock-intent")
        self.assert_run_no_factor_prompt(run)
        self.assert_run_captures_clean(run)
        self.check(self.cli_temp_is_clean(), "lease-temp")

    def approved_run(self, session, report, request_stage, decide_stage, label):
        """A granted run: exit 0, exact env hash, fresh intent, clean temp."""
        before = self.intent_links()
        run, code = self.decided_run(session, report, request_stage, decide_stage, label)
        self.check(code == 0, "lease-grant-exit")
        self.verify_child_report(report, hashlib.sha256(self.fixture["Value"].encode()).hexdigest())
        self.expect_new_intent(before)
        self.assert_run_no_factor_prompt(run)
        self.assert_run_captures_clean(run)
        self.assert_clean_run_roots()
        self.observed["lease-isolated-clean"] = True
        self.forget_report(report)
        return run

    def refused_run(self, session, report, request_stage, decide_stage, label):
        """A refused request: dialog required, no child, no intent, clean temp."""
        before = self.intent_links()
        run, code = self.decided_run(session, report, request_stage, decide_stage, label)
        self.check(code != 0, "lease-refusal-exit")
        self.check(not report.exists(), "lease-report-present")
        self.expect_no_intent(before)
        self.assert_run_no_factor_prompt(run)
        self.assert_run_captures_clean(run)
        self.assert_clean_run_roots()
        self.observed["lease-isolated-clean"] = True
        return run

    def lease_cases(self):
        self.open_sessions()
        # 1+2. Default one-shot approval, twice, on the same real terminal with
        # the identical command: no lease may be created implicitly and every
        # run must still require a new physical approval.
        first = self.approved_run(self.primary, self.report_oneshot, "oneshot-request",
                                  "oneshot", APPROVE_LABEL)
        self.observed["oneshot-env-hash"] = True
        second = self.approved_run(self.primary, self.report_oneshot, "repeat-request",
                                   "repeat", APPROVE_LABEL)
        require(first.pid != second.pid)
        self.observed["oneshot-dialog-each-run"] = True
        self.observed["lease-terminal-shared"] = True

        # 3. Explicit five-minute terminal lease instead of a one-shot grant.
        self.approved_run(self.primary, self.report_lease, "lease-request", "lease", LEASE_LABEL)
        self.observed["lease-grant-dialog"] = True
        self.observed["lease-grant-hash"] = True
        self.observed["lease-grant-intent"] = True
        self.observed["lease-grant-exit-zero"] = True

        # 4. A brand-new CLI process on the same terminal and exact command:
        # no new dialog, but a brand-new intent and the real child env hash.
        before = self.intent_links()
        run, code = self.quiet_run(self.primary, self.report_lease, "reuse")
        require(code == 0)
        self.verify_child_report(self.report_lease,
                                 hashlib.sha256(self.fixture["Value"].encode()).hexdigest())
        self.expect_new_intent(before)
        require(run.pid not in (first.pid, second.pid))
        self.assert_kernel_identity(self.primary, run)
        self.assert_run_no_factor_prompt(run)
        self.assert_run_captures_clean(run)
        self.assert_clean_run_roots()
        self.forget_report(self.report_lease)
        self.observed["lease-reuse-no-dialog"] = True
        self.observed["lease-reuse-fresh-intent"] = True
        self.observed["lease-reuse-env-hash"] = True

        # 5. One changed child argument (the report path) on the same terminal
        # and session is a different command: the dialog must appear again and
        # the owner refuses it with no child.
        self.refused_run(self.primary, self.report_refuse, "changed-arg-request",
                         "changed-arg", REFUSE_LABEL)
        self.observed["lease-changed-arg-dialog"] = True
        self.observed["lease-changed-arg-refused"] = True

        # 6. The exact lease command on a genuinely different terminal/session
        # must never reuse the lease.
        self.refused_run(self.alternate, self.report_refuse, "changed-terminal-request",
                         "changed-terminal", REFUSE_LABEL)
        self.observed["lease-changed-terminal-dialog"] = True
        self.observed["lease-changed-terminal-refused"] = True

        # 7. A real native lock revokes the lease. The next exact request is
        # refused with no dialog, no child and no local factor fallback.
        self.phase("lock")
        require(self.safe_controls().get(LOCK_LABEL, {}).get("present") is True)
        self.click(LOCK_LABEL)
        self.wait("解锁")
        controls = self.safe_controls()
        require(controls.get(LOCK_LABEL, {}).get("present") is False)
        require(controls.get("解锁", {}).get("present") is True)
        self.observed["lease-lock-native"] = True
        before = self.intent_links()
        run, code = self.quiet_run(self.primary, self.report_lease, "after-lock",
                                   expect_refusal=True)
        self.observed["lease-lock-kernel-peek"] = (
            "live" if self.run_has_live_identity(run) else "not-available")
        self.assert_expected_refusal_evidence(run, code, before, self.report_lease)
        self.observed["lease-lock-refused"] = True
        self.observed["lease-lock-no-fallback"] = True

        # 8. After a real unlock the stale lease must not come back: the same
        # command needs a new dialog, which the owner refuses.
        self.unlock()
        self.refused_run(self.primary, self.report_lease,
                         "after-unlock-request", "after-unlock", REFUSE_LABEL)
        self.observed["lease-lock-revoked"] = True

        self.phase("cleanup")
        self.assert_clean_run_roots()
        self.observed["lease-isolated-clean"] = True

    def write_terminal_log(self):
        path = self.private / "cli-terminal.log"
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            for run in self.cli_runs:
                output.write(b"\n--- private controlling-terminal capture ---\n")
                output.write(run.captured_terminal())
                output.write(b"\n--- private standard-output capture ---\n")
                output.write(run.captured_standard_output())
            for session in self.sessions:
                output.write(b"\n--- private shared-terminal capture ---\n")
                output.write(session.captured_terminal())
            for run in self.lease_runs:
                output.write(b"\n--- private shared-terminal child stdout ---\n")
                output.write(run.captured_stdout())
                output.write(b"\n--- private shared-terminal child stderr ---\n")
                output.write(run.captured_stderr())

    def close_cli_runs(self):
        for run in self.cli_runs:
            run.stop()
        try:
            self.write_terminal_log()
        finally:
            for run in self.lease_runs:
                try:
                    run.release()
                except Exception:
                    pass
            for session in self.sessions:
                try:
                    session.close()
                except Exception:
                    pass

    def privacy(self):
        for raw in self.captured:
            wrappers.scan(raw, self.values)
        for run in self.cli_runs:
            wrappers.scan(run.captured_terminal(), self.values)
            wrappers.scan(run.captured_standard_output(), self.values)
        for run in self.lease_runs:
            wrappers.scan(run.captured_terminal(), self.values)
            wrappers.scan(run.captured_stdout(), self.values)
            wrappers.scan(run.captured_stderr(), self.values)
        count = 0
        for path in self.private.rglob("*"):
            if not path.is_file() or path.suffix not in (".log", ".txt", ".json", ".jsonl"):
                continue
            wrappers.scan(path.read_bytes(), self.values)
            count += 1
        require(count >= 1)
        # The App/probe/native logs and the private fixture observer stay in the
        # reused controller state; its existing scan covers them unchanged.
        require(self.scan() > 0)

    def record_failure(self, error):
        failure = {
            "stage": self.stage,
            "reason": self.reason,
            "native_action": self.native_action,
            "error_class": {AcceptanceFailure: "acceptance", OSError: "os",
                            subprocess.TimeoutExpired: "timeout",
                            json.JSONDecodeError: "json", FixtureError: "fixture"}.get(type(error), "unexpected"),
            "native_x_error_codes": self.native_x_error_codes,
            "last_native_click": self.last_native_click,
        }
        try:
            with os.fdopen(os.open(self.diagnostics / "failure.json",
                                   os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
                json.dump(failure, output)
        except OSError:
            pass
        self.reason = failure["reason"]

    def flag(self, name):
        return "true" if self.observed.get(name) is True else "false"

    def one_shot_lines(self, success):
        return [
            "CLI desktop native approve: report-absent-before=true env-hash-match=" + self.flag("approve-hash-match") +
            " exit-zero=" + self.flag("approve-exit-zero") + " isolated-clean=" + self.flag("approve-isolated-clean"),
            "CLI desktop native refuse: report-absent=" + self.flag("refuse-report-absent") +
            " exit-nonzero=" + self.flag("refuse-exit-nonzero") +
            " no-fallback-factor=" + self.flag("refuse-no-factor-fallback") +
            " isolated-clean=" + self.flag("refuse-isolated-clean"),
            "CLI desktop native binding: pinned-exact-id-and-revision=" + self.flag("binding-pinned-exact-revision"),
            "PASS: real native one-shot desktop CLI approval and refusal through a real controlling terminal"
            if success else
            "FAIL: CLI desktop native acceptance at " + self.stage + " [" + self.reason + "] action=" + self.native_action,
        ]

    def lease_lines(self, success):
        return [
            "CLI desktop native lease: distinct-terminal-fixtures=" + self.flag("lease-terminal-distinct") +
            " shared-kernel-terminal=" + self.flag("lease-terminal-shared") +
            " separate-pids=" + ("true" if len(self.observed.get("lease-pids", [])) >= 3 else "false") +
            " child-exe-proof=" + self.flag("lease-child-exe-proof"),
            "CLI desktop native one-shot: dialog-each-run-on-shared-terminal=" + self.flag("oneshot-dialog-each-run") +
            " env-hash-match=" + self.flag("oneshot-env-hash"),
            "CLI desktop native lease grant: dialog=" + self.flag("lease-grant-dialog") +
            " env-hash-match=" + self.flag("lease-grant-hash") +
            " fresh-intent=" + self.flag("lease-grant-intent") +
            " exit-zero=" + self.flag("lease-grant-exit-zero") +
            " isolated-clean=" + self.flag("lease-isolated-clean"),
            "CLI desktop native lease reuse: no-new-dialog=" + self.flag("lease-reuse-no-dialog") +
            " fresh-intent=" + self.flag("lease-reuse-fresh-intent") +
            " env-hash-match=" + self.flag("lease-reuse-env-hash") +
            " isolated-clean=" + self.flag("lease-isolated-clean"),
            "CLI desktop native lease changed-arg: dialog-required=" + self.flag("lease-changed-arg-dialog") +
            " refused=" + self.flag("lease-changed-arg-refused") + " no-child=true",
            "CLI desktop native lease changed-terminal: dialog-required=" + self.flag("lease-changed-terminal-dialog") +
            " refused=" + self.flag("lease-changed-terminal-refused") + " no-child=true",
            "CLI desktop native lease lock: native-lock=" + self.flag("lease-lock-native") +
            " revoked-lease=" + self.flag("lease-lock-revoked") +
            " following-request-refused=" + self.flag("lease-lock-refused") +
            " fast-refusal-kernel-peek=" + str(self.observed.get("lease-lock-kernel-peek", "not-run")) +
            " no-fallback-factor=" + self.flag("lease-lock-no-fallback"),
            "CLI desktop native lease ttl: absolute-" + str(LEASE_TTL_SECONDS // 60) + "min-real-expiry=not-run" +
            " (no wall-clock wait in this acceptance; the product timer/race tests own the absolute deadline)",
            "PASS: real native five-minute terminal lease reuse, exact-command binding and lock revocation"
            if success else
            "FAIL: CLI desktop native acceptance at " + self.stage + " [" + self.reason + "] action=" + self.native_action,
        ]

    def run(self):
        success = False
        try:
            self.phase("setup")
            self.setup()
            self.bind()
            if self.lease:
                self.lease_cases()
            else:
                self.approve_case()
                self.refuse_case()
            success = True
        except Exception as error:
            # Never print or persist an arbitrary exception, payload or command.
            self.record_failure(error)
        finally:
            try:
                self.close_cli_runs()
            except Exception:
                success, self.reason = False, "cleanup"
            try:
                self.close()
            except Exception:
                success, self.reason = False, "cleanup"
        privacy_failed = False
        try:
            self.privacy()
        except Exception:
            # A canary in a captured stream or an owned artifact is fatal, but
            # never print the offending bytes or the scan exception.
            privacy_failed, success = True, False

        final_lines = self.lease_lines(success) if self.lease else self.one_shot_lines(success)
        final_lines.insert(-1, "CLI desktop native captured streams and owned artifacts: canary-scan=" +
                           ("passed" if not privacy_failed else "failed"))
        for line in final_lines:
            print(line, flush=True)
        return 0 if success else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", help="prebuilt locklark executable")
    parser.add_argument("--fixture-bin", help="independently built cli-wrappers fixture child")
    parser.add_argument("--wrapper-bin", help="prebuilt run-cli-fixture controlling-terminal launcher")
    parser.add_argument("--desktop-host", help="prebuilt locklark-desktop executable")
    parser.add_argument("--go", default=os.environ.get("LOCKLARK_GO", "go"))
    parser.add_argument("--lease", action="store_true",
                        help="also prove the explicit five-minute terminal lease on one persistent real terminal")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        acceptance = Acceptance(args)
    except Exception:
        print("FAIL: CLI desktop native acceptance at setup")
        return 1
    try:
        return acceptance.run()
    except Exception:
        print("FAIL: CLI desktop native acceptance at internal")
        return 1


if __name__ == "__main__":
    sys.exit(main())
