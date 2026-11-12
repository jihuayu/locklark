#!/usr/bin/env python3
"""Darwin success-path acceptance for issue #64: native CLI broker approval.

This is one external, opaque-box checkpoint for exactly the approved journey:

  synthetic vault -> one login -> explicit `token` binding -> real desktop
  native unlock -> real `locklark cli run` in a controlling PTY -> native
  "仅批准本次 CLI 请求" click -> one deterministic child -> one audited
  `item.run.bundle` intent.

Only the real built `cmd/locklark` and `cmd/locklark-desktop` executables are
accepted (as explicit absolute paths). Native input is emitted exclusively by
the existing external `scripts/native_acceptance_driver.py --platform macos`;
this script never grants or requests Accessibility trust and never uses a
product test hook, a direct Go handler, or a socket-only shortcut.

All synthetic factors stay in memory. The script prints only fixed stage codes
and PASS labels; raw driver/prompt diagnostics are owner-only or discarded
after the privacy scan. Every wait is bounded, and cleanup stops and reaps only
processes this script created.
"""
import base64
import hashlib
import json
import os
import pathlib
import re
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time

try:
    import pty
except ImportError:  # pragma: no cover - Windows has no pty module
    pty = None

ROOT = pathlib.Path(__file__).resolve().parents[1]
DRIVER = ROOT / "scripts" / "native_acceptance_driver.py"
# The only result an activation-only driver request may report.
ACTIVATION_RESULT = {"activated": True}

TITLE = "Locklark · 本地金库"
APPROVE_LABEL = "仅批准本次 CLI 请求"
UNLOCK_FIELDS = ("金库文件", "主密码", "Secret Key")
UNLOCK_LABEL = "解锁"
UNLOCKED_LABEL = "新建登录"

# Optional read-only inspect diagnostic after the terminal unlock wait. Only
# these fixed labels and fixed control record fields are read; every value must
# be a built-in boolean. The status object is exactly four built-in booleans.
LOCKED_CONTROLS = ("金库文件", "主密码", "Secret Key", UNLOCK_LABEL)
CONTROL_RECORD_FIELDS = ("present", "enabled", "showing")
STATUS_FIELDS = ("available", "generic_unlock_error",
                 "secret_key_format_error", "processing")
INSPECT_SUMMARY_FIELDS = (
    "snapshot_available", "locked_present", "locked_showing",
    "new_login_present", "generic_unlock_error", "secret_key_format_error",
    "processing",
)


def empty_inspect_summary():
    """The fixed all-false inspect summary: exactly seven built-in booleans."""
    return {field: False for field in INSPECT_SUMMARY_FIELDS}


def inspect_summary(result):
    """Strictly classify one inspect result into a fixed boolean summary.

    Only the five expected label records are read, each with exactly the fixed
    ``present``/``enabled``/``showing`` built-in booleans, and ``status`` with
    exactly the four fixed built-in booleans. Unknown labels, fields, text,
    exception details, stdout and stderr are never read or echoed. Any bad
    shape returns the fixed all-false summary.
    """
    summary = empty_inspect_summary()
    if type(result) is not dict:
        return summary
    controls = result.get("controls")
    status = result.get("status")
    if type(controls) is not dict or type(status) is not dict:
        return summary
    if set(status) != set(STATUS_FIELDS):
        return summary
    if any(type(status[field]) is not bool for field in STATUS_FIELDS):
        return summary
    records = {}
    for label in LOCKED_CONTROLS + (UNLOCKED_LABEL,):
        if label not in controls:
            return summary
        record = controls[label]
        if type(record) is not dict or set(record) != set(CONTROL_RECORD_FIELDS):
            return summary
        if any(type(record[field]) is not bool for field in CONTROL_RECORD_FIELDS):
            return summary
        records[label] = record
    summary["snapshot_available"] = status["available"]
    summary["locked_present"] = all(
        records[label]["present"] is True for label in LOCKED_CONTROLS)
    summary["locked_showing"] = all(
        records[label]["showing"] is True for label in LOCKED_CONTROLS)
    summary["new_login_present"] = records[UNLOCKED_LABEL]["present"] is True
    for field in STATUS_FIELDS[1:]:
        summary[field] = status[field]
    return summary


def inspect_summary_line(summary):
    """One fixed diagnostic line: only summary field names and 0/1 values."""
    values = []
    for field in INSPECT_SUMMARY_FIELDS:
        value = summary.get(field) if type(summary) is dict else None
        values.append(field + "=" + ("1" if value is True else "0"))
    return "DIAG: cli-broker unlock_inspect " + " ".join(values)


def unlock_plans(vault, master, secret):
    """Fixed synthetic unlock actions split into bounded driver plans.

    The order is the original nine-action sequence. Each plan is one fresh
    request, so the per-request observation budget is never shared across the
    whole unlock flow; a failing plan still stops the sequence.
    """
    return (
        ({"click_label": "金库文件"}, {"key": "Super_L+a"}, {"text": str(vault)}),
        ({"click_label": "主密码"}, {"text": master}),
        ({"click_label": "Secret Key"}, {"text": secret}),
        ({"click_label": UNLOCK_LABEL},),
        ({"wait_label": UNLOCKED_LABEL},),
    )


TOOL = "synthetic-cli"
TOKEN_ENV = "LOCKLARK_SYNTHETIC_TOKEN"
CHILD_STDOUT = b"cli-broker-child-stdout\n"
CHILD_STDERR = b"cli-broker-child-stderr\n"
CHILD_EXIT = 23
CHILD_TIMEOUT = 30
TTY_PATTERN = r'"/dev/ttys[0-9]{3}"'

STAGES = (
    "prerequisites", "fixture", "vault", "binding", "desktop", "unlock",
    "approval", "child", "receipt", "audit", "privacy", "cleanup", "complete",
)
UNAVAILABLE_REASONS = frozenset({"platform", "driver", "accessibility", "dependency"})
LOCAL_FALLBACK_MARKERS = (
    "主密码: ".encode("utf-8"),
    "Secret Key: ".encode("utf-8"),
    "输入 RUN 确认本次可信命令披露: ".encode("utf-8"),
)
RETRY_DRIVER_CODES = frozenset({
    "window-timeout", "control-missing", "control-ready-timeout",
    "control-disabled", "control-hidden",
})
DIRECTORY_NAMES = ("vault", "settings", "s", "bin", "run", "logs", "receipt", "state")
# The code class includes digits so fixed codes such as ``a11y-query`` parse;
# the trailing ``]`` still anchors it to the driver's fixed four-field line.
DRIVER_FAILURE = re.compile(
    rb"Native acceptance input failed \[code=([a-zA-Z0-9-]+) action=[a-z-]+ index=-?[0-9]+ platform=[a-z]+\]")

# One in-memory, fixed driver-failure category for the next no-input smoke
# triage. It reuses only the code already parsed above; exactly these
# categories are ever stored, and anything else (including a missing or
# unexpected code) becomes "other". No stderr, message, path, title, label,
# control text or other user data is kept, and the seven-boolean inspect
# summary schema is unchanged.
DRIVER_ERROR_CATEGORIES = frozenset({
    "window-timeout", "control-missing", "control-ready-timeout",
    "control-disabled", "control-hidden",
    "window-ambiguous", "capability-unavailable", "a11y-query",
})
DRIVER_ERROR_OTHER = "other"
SECRET_PATTERN = re.compile(rb"LL1-[A-Z2-7]{26}")

# The helper is generated into the private fixture. It reads the synthetic
# token only from the product-injected environment variable, writes exactly one
# SHA-256 line to the caller-owned receipt path, emits two distinct fixed
# markers and exits with the fixed nonzero status 23. It never uses a network
# and needs no PATH lookup (all executables are absolute).
HELPER_SCRIPT = """#!/bin/sh
set -eu
umask 077
: "$LOCKLARK_SYNTHETIC_TOKEN"
digest=$(printf '%s' "$LOCKLARK_SYNTHETIC_TOKEN" | /usr/bin/shasum -a 256)
digest=${digest%% *}
printf '%s\\n' "$digest" > "$1"
printf 'cli-broker-child-stdout\\n'
printf 'cli-broker-child-stderr\\n' >&2
exit 23
"""


class AcceptanceFailure(Exception):
    """A fixed-stage refusal; no dynamic message is ever printed."""


class Unavailable(Exception):
    """A fixed unavailable result for a missing Darwin capability."""

    def __init__(self, reason):
        self.reason = reason if reason in UNAVAILABLE_REASONS else "platform"
        super().__init__(self.reason)


class DriverRetry(Exception):
    """One bounded native-discovery attempt missed a provisional control."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition):
    if not condition:
        raise AcceptanceFailure()


def scan(raw, values):
    """Refuse a synthetic factor in plain, base64, hex or JSON-escaped form."""
    if isinstance(raw, str):
        raw = raw.encode()
    for value in values:
        if not value:
            continue
        source = value.encode()
        for pattern in (
            source,
            base64.b64encode(source),
            source.hex().encode(),
            json.dumps(value, ensure_ascii=True)[1:-1].encode(),
        ):
            require(pattern not in raw)


def file_mode(path):
    return path.stat().st_mode & 0o777


def owner_only(path, executable=False):
    return (
        path.is_file()
        and not path.is_symlink()
        and path.stat().st_uid == os.geteuid()
        and file_mode(path) & 0o077 == 0
        and (not executable or os.access(path, os.X_OK))
    )


def write_private(path, raw, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(raw)
    path.chmod(mode)


def require_within(path, root):
    """True only for a path whose fully resolved form stays under root."""
    root = pathlib.Path(os.path.realpath(root))
    target = pathlib.Path(os.path.realpath(path))
    try:
        common = pathlib.Path(os.path.commonpath([str(root), str(target)]))
    except ValueError:
        raise AcceptanceFailure() from None
    require(common == root and target != root)


def validate_binary(value, label):
    """Accept one explicit absolute path to a real, executable regular file."""
    del label
    if not isinstance(value, str) or not value or not os.path.isabs(value):
        raise AcceptanceFailure()
    path = pathlib.Path(value)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise AcceptanceFailure()
    return path.resolve(strict=True)


def current_platform():
    return sys.platform


def validate_settings(settings, root):
    """The explicit settings path must remain inside the private fixture."""
    require(not pathlib.Path(settings).is_symlink())
    require_within(settings, root)
    parent = pathlib.Path(settings).parent
    require(parent.is_dir() and not parent.is_symlink())
    require(file_mode(parent) & 0o077 == 0)
    if pathlib.Path(settings).exists():
        require(owner_only(pathlib.Path(settings)))
    return pathlib.Path(settings)


def go_quote(value):
    """Quote an ASCII display value exactly as Go's strconv.QuoteToASCII."""
    if not isinstance(value, str) or any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
        raise AcceptanceFailure()
    return json.dumps(value, ensure_ascii=True)


def broker_summary_pattern(vault, program, program_sha, cwd, timeout, token_env,
                           target_id, target_revision, helper_dir, args):
    """Exact stderr preamble the CLI prints before its one broker request.

    The private run root is product-chosen, so only that one quoted value is a
    bounded capture; every other field is the exact reviewed value. The child's
    fixed stderr marker follows this preamble byte-for-byte.
    """
    quoted = go_quote
    lines = [
        "桌面代理 CLI 执行请求（locklark cli run）",
        "  密码库  ：" + re.escape(quoted(vault)),
        "  Profile ：" + re.escape(quoted("token")),
        "  终端    ：" + TTY_PATTERN + "（平台 " + re.escape(quoted("darwin")) + "）",
        "  执行程序：" + re.escape(quoted(program)),
        "  SHA-256 ：" + re.escape(program_sha),
        "  工作目录：" + re.escape(quoted(cwd)),
        "  临时目录：" + r'"[^"\r\n]+"',
        "  超时上限：" + str(int(timeout)) + " 秒",
        "  Tokens  ：" + re.escape(quoted(token_env)),
        "槽位目标（读取不可变修订）：",
        "  " + re.escape(quoted("token")) + " = " + re.escape(target_id)
        + " @ " + re.escape(target_revision) + "（字段 " + re.escape(quoted("password")) + "）",
        "透传环境变量名（不显示值）：",
        "辅助 PATH：",
        "  " + re.escape(quoted(helper_dir)),
        "命令参数（会显示在终端与系统进程列表中，请勿在参数内写入秘密）：",
    ]
    for index, argument in enumerate(args):
        lines.append("  " + re.escape("[" + str(index) + "] ") + re.escape(quoted(argument)))
    return re.compile(r"\r\n".join(lines) + r"\r\n\Z")


def extract_secret(transcript):
    match = SECRET_PATTERN.search(transcript)
    require(match is not None)
    return match.group(0)


def require_no_local_fallback(raw):
    """A real approval never reaches the local-factor prompt on its PTY."""
    for marker in LOCAL_FALLBACK_MARKERS:
        require(marker not in raw)


def expected_receipt(token):
    return hashlib.sha256(token.encode()).hexdigest().encode() + b"\n"


def validate_child_output(stdout, stderr, exit_code, receipt, expected):
    """Exact child streams, exact exit status and an exact private receipt."""
    require(exit_code == CHILD_EXIT)
    require(stdout == CHILD_STDOUT)
    require(stderr.endswith(CHILD_STDERR))
    require(owner_only(receipt))
    require(receipt.read_bytes() == expected)
    return stderr[:-len(CHILD_STDERR)]


def validate_audit(events, item_id, revision):
    intents = [event for event in events
               if isinstance(event, dict) and event.get("action") == "item.run.bundle"]
    require(len(intents) == 1)
    intent = intents[0]
    require(intent.get("result") == "intent")
    require(intent.get("item_id") == item_id)
    require(intent.get("base_revision") == revision)
    return intent


def desktop_environment(base, socket):
    environment = dict(base)
    environment["LOCKLARK_DESKTOP_LAYOUT"] = "classic"
    environment["LOCKLARK_BROWSER_SOCKET"] = str(socket)
    return environment


def cli_environment(base, socket):
    environment = dict(base)
    environment.pop("LOCKLARK_CLI_ACTIVE", None)
    environment["LOCKLARK_BROWSER_SOCKET"] = str(socket)
    return environment


def desktop_arguments(desktop, settings):
    return [str(desktop), "--settings", str(settings)]


def cli_run_arguments(cli, binding, cwd, helper, receipt, timeout=CHILD_TIMEOUT):
    return [
        str(cli), "cli", "run", TOOL,
        "--binding", str(binding),
        "--cwd", str(cwd),
        "--timeout", str(timeout),
        "--", str(helper), str(receipt),
    ]


def cli_init_arguments(cli, vault, binding, helper, item_id, revision):
    return [
        str(cli), "cli", "init", TOOL,
        "--profile", "token",
        "--file", str(vault),
        "--program", str(helper),
        "--binding", str(binding),
        "--slot-token", item_id + ":" + revision,
        "--name", TOKEN_ENV,
        "--timeout", str(CHILD_TIMEOUT),
    ]


class Fixture:
    """Owner-only synthetic fixture under a short private temporary root."""

    def __init__(self, base):
        base_path = pathlib.Path(base)
        require(base_path.is_absolute() and base_path.is_dir())
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="llcb-", dir=str(base_path)))
        os.chmod(self.root, 0o700)
        for name in DIRECTORY_NAMES:
            (self.root / name).mkdir(mode=0o700)
        self.vault = self.root / "vault" / "synthetic.ll"
        self.settings = self.root / "settings" / "settings.json"
        self.socket = self.root / "s" / "b.sock"
        self.binding = self.root / "state" / "binding.json"
        self.run = self.root / "run"
        self.logs = self.root / "logs"
        self.receipt = self.root / "receipt" / "receipt.txt"
        self.helper = self.root / "bin" / "child-helper"
        self.install_helper()

    def install_helper(self):
        write_private(self.helper, HELPER_SCRIPT.encode(), 0o700)

    def verify_layout(self):
        require(self.root.is_dir() and not self.root.is_symlink())
        require(self.root.stat().st_uid == os.geteuid())
        require(file_mode(self.root) & 0o077 == 0)
        for name in DIRECTORY_NAMES:
            directory = self.root / name
            require(directory.is_dir() and not directory.is_symlink())
            require(directory.stat().st_uid == os.geteuid())
            require(file_mode(directory) & 0o077 == 0)
        require(owner_only(self.helper, executable=True))
        require(self.helper.read_bytes() == HELPER_SCRIPT.encode())
        require_within(self.settings, self.root)
        require_within(self.socket, self.root)
        require(pathlib.Path(self.socket).parent == self.root / "s")
        require(not self.vault.exists())
        require(not self.binding.exists())
        require(not self.receipt.exists())


class PTYChild:
    """One kernel-backed controlling PTY with separate captured streams.

    By default stdin and stderr stay on the PTY, so an interactive personal
    command keeps its hidden prompts there. ``capture_stderr=True`` is used
    only for the real ``cli run``: stdin remains the controlling PTY while
    stdout and stderr are captured independently.
    """

    def __init__(self, executable, argv, environment, cwd, capture_stderr=False):
        require(pty is not None)
        self.executable = str(executable)
        self.argv = [str(argument) for argument in argv]
        self.environment = dict(environment)
        self.cwd = str(cwd)
        self.capture_stderr = capture_stderr
        self.pid = None
        self.master = None
        self.exit_status = None
        self.offset = 0
        self._lock = threading.Lock()
        self._terminal = b""
        self._stdout = b""
        self._stderr = b""
        self._master_fd = None
        self._stdout_fd = None
        self._stderr_fd = None
        self._fds = []
        self._thread = None

    def start(self):
        stdout_read, stdout_write = os.pipe()
        stderr_read = stderr_write = None
        if self.capture_stderr:
            stderr_read, stderr_write = os.pipe()
        try:
            pid, master = pty.fork()
        except Exception:
            os.close(stdout_read)
            os.close(stdout_write)
            if stderr_read is not None:
                os.close(stderr_read)
                os.close(stderr_write)
            raise AcceptanceFailure() from None
        if pid == 0:
            # Child of the kernel-backed pty fork: stdin stays on the slave, so
            # the session keeps its real controlling terminal. Only the
            # requested capture streams are redirected.
            try:
                os.close(stdout_read)
                os.dup2(stdout_write, 1)
                if stdout_write != 1:
                    os.close(stdout_write)
                if stderr_write is not None:
                    os.close(stderr_read)
                    os.dup2(stderr_write, 2)
                    if stderr_write != 2:
                        os.close(stderr_write)
                os.chdir(self.cwd)
                os.execve(self.executable, self.argv, self.environment)
            except BaseException:
                os._exit(127)
        self.pid = pid
        self.master = master
        self._master_fd = master
        self._stdout_fd = stdout_read
        self._stderr_fd = stderr_read
        os.close(stdout_write)
        if stderr_write is not None:
            os.close(stderr_write)
        os.set_blocking(master, False)
        os.set_blocking(stdout_read, False)
        if stderr_read is not None:
            os.set_blocking(stderr_read, False)
        self._fds = [master, stdout_read]
        if stderr_read is not None:
            self._fds.append(stderr_read)
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def _pump(self):
        descriptors = list(self._fds)
        while descriptors:
            try:
                ready, _, _ = select.select(descriptors, [], [], 0.1)
            except (OSError, ValueError):
                break
            for descriptor in ready:
                try:
                    chunk = os.read(descriptor, 65536)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    descriptors.remove(descriptor)
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                    continue
                with self._lock:
                    if descriptor == self._master_fd:
                        self._terminal += chunk
                    elif descriptor == self._stdout_fd:
                        self._stdout += chunk
                    elif descriptor == self._stderr_fd:
                        self._stderr += chunk
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def terminal(self):
        with self._lock:
            return self._terminal

    def stdout(self):
        with self._lock:
            return self._stdout

    def stderr(self):
        with self._lock:
            return self._stderr

    def poll(self):
        if self.pid is None:
            return self.exit_status
        try:
            done, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            done, status = self.pid, 0
        if not done:
            return None
        self.exit_status = os.waitstatus_to_exitcode(status)
        self.pid = None
        return self.exit_status

    def expect(self, prompt, answer, deadline):
        """Wait for one exact hidden prompt, then write one owner-held answer."""
        require(isinstance(prompt, bytes) and prompt)
        require(self.pid is not None)
        while True:
            transcript = self.terminal()
            index = transcript.find(prompt, self.offset)
            if index >= 0:
                self.offset = index + len(prompt)
                value = answer(transcript) if callable(answer) else answer
                require(isinstance(value, bytes) and value)
                require(b"\n" not in value and b"\r" not in value)
                try:
                    os.write(self.master, value + b"\n")
                except OSError:
                    raise AcceptanceFailure() from None
                return value
            require(time.monotonic() < deadline and self.pid is not None)
            time.sleep(0.02)

    def wait(self, deadline):
        while True:
            status = self.poll()
            if status is not None:
                self._finish()
                return status
            require(time.monotonic() < deadline)
            time.sleep(0.02)

    def _finish(self):
        if self._thread is not None:
            self._thread.join(5)
        if self.master is not None:
            try:
                os.close(self.master)
            except OSError:
                pass
            self.master = None

    def terminate(self):
        """Stop and reap this process group only; never touch a foreign pid."""
        if self.pid is not None:
            try:
                os.killpg(self.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            end = time.monotonic() + 5
            while time.monotonic() < end and self.poll() is None:
                time.sleep(0.02)
            if self.pid is not None:
                try:
                    os.killpg(self.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            if self.pid is not None:
                try:
                    _, status = os.waitpid(self.pid, 0)
                except ChildProcessError:
                    status = 0
                self.exit_status = os.waitstatus_to_exitcode(status)
                self.pid = None
        self._finish()


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.stage = "prerequisites"
        self.checks = []
        self.output_lines = []
        self.parent_environment = dict(os.environ)
        self.fixture = None
        self.settings = None
        self.cli = None
        self.desktop = None
        self.env = {}
        self.desktop_process = None
        self.cli_child = None
        self.driver_index = 0
        self.values = []
        self.master = "SyntheticMaster-" + os.urandom(24).hex()
        self.token = "synthetic-token-" + os.urandom(32).hex()
        self.secret = None
        self.item_id = None
        self.revision = None
        self.unlock_inspect_summary = empty_inspect_summary()
        self.driver_error_category = None
        self.values.extend([self.master, self.token])
        self.deadline = time.monotonic() + int(args.timeout)

    # ------------------------------------------------------------- output --
    def stage_code(self, name):
        require(name in STAGES)
        self.stage = name
        print("STAGE: cli-broker " + name, flush=True)

    def mark(self, name):
        self.checks.append(name)
        line = "PASS: cli-broker " + name
        self.output_lines.append(line)
        print(line, flush=True)

    def private_bytes(self, name, raw):
        path = self.fixture.logs / name
        write_private(path, raw)
        return path

    # ---------------------------------------------------------- lifecycle --
    def prepare(self):
        if current_platform() != "darwin":
            raise Unavailable("platform")
        self.cli = validate_binary(self.args.cli, "cli")
        self.desktop = validate_binary(self.args.desktop, "desktop")
        if not DRIVER.is_file():
            raise Unavailable("driver")
        if not pathlib.Path("/usr/bin/shasum").is_file():
            raise Unavailable("dependency")
        self.mark("explicit_binaries_understood")
        self.stage_code("fixture")
        self.fixture = Fixture("/tmp")
        require(str(self.fixture.root).startswith("/tmp/"))
        require(len(str(self.fixture.root)) <= 48)
        self.fixture.verify_layout()
        self.settings = validate_settings(self.fixture.settings, self.fixture.root)
        self.env = dict(os.environ)
        self.mark("private_fixture_ready")

    def personal(self, action, steps):
        require(self.fixture is not None)
        argv = [str(self.cli), "personal", action, "--file", str(self.fixture.vault)]
        child = PTYChild(self.cli, argv, self.env, self.fixture.root, capture_stderr=False)
        try:
            child.start()
            for prompt, answer in steps:
                child.expect(prompt, answer, self.deadline)
            status = child.wait(self.deadline)
            self.private_bytes("personal-" + action + ".stdout", child.stdout())
            require(status == 0)
            return child.stdout()
        finally:
            child.terminate()

    def create_vault(self):
        self.stage_code("vault")
        raw = self.personal("init", [
            ("主密码: ".encode(), self.master.encode()),
            ("再次输入主密码: ".encode(), self.master.encode()),
            ("重新输入刚保存的 Secret Key: ".encode(), lambda transcript: self._capture_secret(transcript)),
        ])
        require(json.loads(raw).get("status") == "created")
        raw = self.personal("add-login", [
            ("主密码: ".encode(), self.master.encode()),
            ("Secret Key: ".encode(), self.secret.encode()),
            ("登录标题: ".encode(), b"Synthetic broker login"),
            ("用户名（可留空）: ".encode(), b"synthetic-owner"),
            ("登录密码: ".encode(), self.token.encode()),
        ])
        self.item_id = json.loads(raw)["id"]
        raw = self.personal("list", [
            ("主密码: ".encode(), self.master.encode()),
            ("Secret Key: ".encode(), self.secret.encode()),
        ])
        rows = [row for row in json.loads(raw) if row.get("id") == self.item_id]
        require(len(rows) == 1)
        self.revision = rows[0]["revision"]
        self.mark("synthetic_vault_and_login_created")

    def _capture_secret(self, transcript):
        if self.secret is None:
            self.secret = extract_secret(transcript).decode("ascii")
            self.values.append(self.secret)
            require(self.secret.startswith("LL1-"))
        return self.secret.encode()

    def create_binding(self):
        self.stage_code("binding")
        command = cli_init_arguments(self.cli, self.fixture.vault, self.fixture.binding,
                                     self.fixture.helper, self.item_id, self.revision)
        scan(" ".join(command), self.values)
        result = subprocess.run(
            command, cwd=self.fixture.root, env=self.env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60,
        )
        self.private_bytes("cli-init.stdout", result.stdout)
        self.private_bytes("cli-init.stderr", result.stderr)
        require(result.returncode == 0)
        payload = json.loads(result.stdout)
        require(payload.get("status") == "bound")
        require(owner_only(self.fixture.binding))
        scan(self.fixture.binding.read_bytes(), self.values)
        self.mark("explicit_one_item_token_binding_created")

    # ------------------------------------------------------------- native --
    def driver(self, actions, stage):
        if self.stage != stage:
            self.stage_code(stage)
        request = json.dumps({
            "title": TITLE,
            "executable": str(self.desktop),
            "actions": actions,
            "inspect": False,
        }).encode()
        return self.run_driver(request)

    def run_driver(self, request):
        """One bounded driver invocation; saves owner-only stdout/stderr.

        Every call starts by resetting the fixed error category; only the
        allowlisted code below is ever stored, in memory.
        """
        self.driver_error_category = None
        try:
            result = subprocess.run(
                [sys.executable, str(DRIVER), "--platform", "macos"],
                cwd=ROOT, env=self.env, input=request,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40,
            )
        except subprocess.TimeoutExpired:
            # A hung driver is unknown delivery, never a retryable discovery.
            raise AcceptanceFailure() from None
        self.driver_index += 1
        self.private_bytes("driver-" + str(self.driver_index) + ".stdout", result.stdout)
        self.private_bytes("driver-" + str(self.driver_index) + ".stderr", result.stderr)
        if result.returncode != 0:
            match = DRIVER_FAILURE.search(result.stderr)
            code = match.group(1).decode("ascii") if match else "unexpected"
            self.driver_error_category = (
                code if code in DRIVER_ERROR_CATEGORIES else DRIVER_ERROR_OTHER)
            if code == "capability-unavailable":
                raise Unavailable("accessibility")
            if code in RETRY_DRIVER_CODES:
                raise DriverRetry(code)
            raise AcceptanceFailure()
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            raise AcceptanceFailure() from None

    def start_desktop(self):
        self.stage_code("desktop")
        environment = desktop_environment(self.env, self.fixture.socket)
        arguments = desktop_arguments(self.desktop, self.settings)
        scan(" ".join(arguments), self.values)
        log = os.open(self.fixture.logs / "desktop.log",
                      os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            self.desktop_process = subprocess.Popen(
                arguments, cwd=self.fixture.root, env=environment,
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True,
            )
        finally:
            os.close(log)
        os.chmod(self.fixture.logs / "desktop.log", 0o600)
        self.activate_desktop()
        self.wait_unlock_fields()
        self.mark("real_desktop_started_with_explicit_settings_socket")

    def activation_request(self):
        """Activation-only request for the exact pid this harness launched.

        Only the PID and the already validated canonical executable are named;
        there is no title, action, inspect or window field. A native refusal is
        an acceptance failure, never retried.
        """
        process = self.desktop_process
        require(process is not None and process.poll() is None)
        require(type(process.pid) is int and process.pid > 0)
        require(self.desktop is not None and os.path.isabs(str(self.desktop)))
        return json.dumps({
            "activate_pid": process.pid,
            "executable": str(self.desktop),
        }).encode()

    def activate_desktop(self):
        """Ask once for activation before any window title is observed.

        Title, executable, unique-window and control readiness are still
        re-proved by the normal ``wait_unlock_fields`` driver flow afterwards.
        """
        require(self.run_driver(self.activation_request()) == ACTIVATION_RESULT)

    def wait_unlock_fields(self):
        retry_deadline = min(self.deadline, time.monotonic() + 45)
        actions = [{"wait_label": label} for label in UNLOCK_FIELDS]
        while True:
            try:
                self.driver(actions, "desktop")
                return
            except DriverRetry:
                if time.monotonic() >= retry_deadline:
                    raise AcceptanceFailure() from None
                require(self.desktop_process.poll() is None)
                time.sleep(0.5)

    def inspect_request(self):
        """One read-only inspect of the already-owned app window.

        It carries no action, text, key, click or wait: the same title and the
        exact already-validated executable bind the existing window, and
        ``inspect`` asks only for the existing controls/status boolean maps.
        """
        require(self.desktop is not None and os.path.isabs(str(self.desktop)))
        return json.dumps({
            "title": TITLE,
            "executable": str(self.desktop),
            "actions": [],
            "inspect": True,
        }).encode()

    def inspect_unlock_wait_failure(self):
        """One inspect for the terminal final wait; never retries or replays.

        Any request failure stores the fixed all-false summary. Exactly one
        fixed diagnostic line is emitted and added to the existing private
        fixture scan, so no driver output, JSON, label or path is ever echoed.
        """
        try:
            result = self.run_driver(self.inspect_request())
            summary = inspect_summary(result)
        except Exception:
            summary = empty_inspect_summary()
        self.unlock_inspect_summary = summary
        line = inspect_summary_line(summary)
        self.output_lines.append(line)
        print(line, flush=True)

    def unlock(self):
        self.stage_code("unlock")
        plans = unlock_plans(self.fixture.vault, self.master, self.secret)
        for index, actions in enumerate(plans):
            try:
                self.driver(list(actions), "unlock")
            except DriverRetry:
                if index == len(plans) - 1:
                    try:
                        self.inspect_unlock_wait_failure()
                    except Exception:
                        pass
                raise
        self.mark("native_unlock_fields_and_button")

    def approve(self):
        self.stage_code("approval")
        command = cli_run_arguments(self.cli, self.fixture.binding, self.fixture.run,
                                    self.fixture.helper, self.fixture.receipt)
        scan(" ".join(command), self.values)
        child = PTYChild(self.cli, command,
                         cli_environment(self.env, self.fixture.socket), self.fixture.run,
                         capture_stderr=True)
        self.cli_child = child
        try:
            child.start()
            retry_deadline = min(self.deadline, time.monotonic() + 120)
            clicked = False
            while time.monotonic() < retry_deadline:
                require_no_local_fallback(child.terminal())
                require_no_local_fallback(child.stderr())
                if child.poll() is not None:
                    break
                try:
                    self.driver(
                        [{"wait_label": APPROVE_LABEL}, {"click_label": APPROVE_LABEL}],
                        "approval",
                    )
                    clicked = True
                    break
                except DriverRetry:
                    time.sleep(0.25)
            require(clicked)
            status = child.wait(self.deadline)
            require_no_local_fallback(child.terminal())
            require_no_local_fallback(child.stderr())
            self.private_bytes("cli-run.stdout", child.stdout())
            self.private_bytes("cli-run.stderr", child.stderr())
            self.private_bytes("cli-run.terminal", child.terminal())
            self.mark("native_approval_clicked")
            return status, child.stdout(), child.stderr(), child.terminal()
        finally:
            child.terminate()
            self.cli_child = None

    # ------------------------------------------------------------ evidence --
    def child_evidence(self, status, stdout, stderr, terminal):
        self.stage_code("child")
        require(status == CHILD_EXIT)
        require(stdout == CHILD_STDOUT)
        require(stderr.endswith(CHILD_STDERR))
        scan(stdout, self.values)
        scan(stderr, self.values)
        scan(terminal, self.values)
        pattern = broker_summary_pattern(
            self.fixture.vault, self.fixture.helper,
            hashlib.sha256(self.fixture.helper.read_bytes()).hexdigest(),
            self.fixture.run, CHILD_TIMEOUT, TOKEN_ENV, self.item_id, self.revision,
            str(self.fixture.helper.parent), [str(self.fixture.receipt)],
        )
        summary = validate_child_output(
            stdout, stderr, status, self.fixture.receipt, expected_receipt(self.token))
        require(pattern.fullmatch(summary.decode("utf-8")) is not None)
        self.mark("exact_child_streams_and_exit_23")
        self.stage_code("receipt")
        require(self.fixture.receipt.read_bytes() == expected_receipt(self.token))
        self.mark("private_token_digest_receipt")

    def audit(self):
        self.stage_code("audit")
        raw = self.personal("audit", [
            ("主密码: ".encode(), self.master.encode()),
            ("Secret Key: ".encode(), self.secret.encode()),
        ])
        events = json.loads(raw)
        require(isinstance(events, list))
        validate_audit(events, self.item_id, self.revision)
        self.mark("exactly_one_item_run_bundle_intent")

    def privacy(self):
        self.stage_code("privacy")
        validate_settings(self.settings, self.fixture.root)
        self.mark("explicit_settings_inside_fixture")
        self.scan_private_outputs()
        self.mark("public_and_private_fixture_outputs_secret_clean")

    def scan_private_outputs(self):
        """Secret scan without emitting stage or PASS output (also on failure)."""
        if self.fixture is None:
            return
        require(dict(os.environ) == self.parent_environment)
        scan("\n".join(self.output_lines), self.values)
        for path in sorted(self.fixture.root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                scan(path.read_bytes(), self.values)

    # ----------------------------------------------------------------- run --
    def run(self):
        self.stage_code("prerequisites")
        self.prepare()
        self.create_vault()
        self.create_binding()
        self.start_desktop()
        self.unlock()
        status, stdout, stderr, terminal = self.approve()
        self.child_evidence(status, stdout, stderr, terminal)
        self.audit()
        self.privacy()
        self.stage_code("complete")
        self.mark("complete")

    def result(self, success):
        return {
            "success": success,
            "stage": self.stage if self.stage in STAGES else "prerequisites",
            "checks": list(self.checks),
        }

    def write_result(self, success):
        write_private(self.fixture.root / "result.json",
                      json.dumps(self.result(success)).encode())

    def close(self):
        if self.cli_child is not None:
            self.cli_child.terminate()
            self.cli_child = None
        process = self.desktop_process
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        self.desktop_process = None


def main(argv=None):
    parser = __import__("argparse").ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True,
                        help="explicit absolute path to the built cmd/locklark binary")
    parser.add_argument("--desktop", required=True,
                        help="explicit absolute path to the built cmd/locklark-desktop binary")
    parser.add_argument("--timeout", type=int, default=240,
                        help="bounded overall acceptance deadline in seconds")
    args = parser.parse_args(argv)
    os.umask(0o077)
    if current_platform() != "darwin":
        print("UNAVAILABLE: cli-broker platform")
        return 2
    acceptance = None
    success = False
    unavailable = None
    try:
        require(30 <= args.timeout <= 1200)
        acceptance = Acceptance(args)
        acceptance.run()
        success = True
    except Unavailable as error:
        unavailable = error.reason
    except AcceptanceFailure:
        pass
    except Exception:
        pass
    finally:
        if acceptance is not None:
            try:
                acceptance.close()
            except Exception:
                success, acceptance.stage = False, "cleanup"
            if acceptance.fixture is not None:
                if not success:
                    try:
                        acceptance.scan_private_outputs()
                    except Exception:
                        success, acceptance.stage = False, "privacy"
                try:
                    acceptance.write_result(success)
                except Exception:
                    success = False
            if acceptance.stage not in STAGES:
                acceptance.stage = "prerequisites"
    if unavailable is not None:
        print("UNAVAILABLE: cli-broker " + unavailable)
        return 2
    if success:
        return 0
    print("FAIL: cli-broker acceptance at " + (acceptance.stage if acceptance else "prerequisites"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
