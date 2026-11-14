"""Opaque-box E2E harness for the Locklark M5 test track.

The harness deliberately speaks to Locklark only through user-facing
interfaces: the CLI (through a POSIX PTY when private prompts are involved),
the browser native-messaging hosts (4-byte native-endian length-prefixed JSON),
the browser-extension build script, and Node.js child processes.

No test helper imports Locklark's Go packages or reaches into private state.
"""

from __future__ import annotations

import errno
import fcntl
import io
import json
import os
import pty
import re
import secrets
import select
import signal
import shutil
import struct
import subprocess
import sys
import termios
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Fixed identifiers shared with the product
# ---------------------------------------------------------------------------

VALID_TIERS = (1, 2, 3, 4)
# "component_contract" records evidence from an executed component test
# (browser-extension M3/core suites or an existing native package test)
# rather than a whole-browser user journey.
COVERAGE_KINDS = ("functional", "capability_probe", "component_contract")
VALID_FEATURES = tuple(f"F{i}" for i in range(1, 18))
CHROMIUM_EXT_ORIGIN = "chrome-extension://geldnhjapnackobgknocomedmjgphnpe/"
FIREFOX_EXT_ID = "browser@locklark.local"
SECRET_KEY_RE = re.compile(rb"LL1-[A-Z2-7]{26}")
RECOVERY_KIT_RE = re.compile(
    rb"(?:LLR2-[A-Z2-7]{52}-[A-Z2-7]{52}|LLR1-[A-Z2-7]{52})"
)
ISSUED_TOKEN_RE = re.compile(
    rb"(?:LL1-[A-Z2-7]{26}|LLR2-[A-Z2-7]{52}-[A-Z2-7]{52}|LLR1-[A-Z2-7]{52})"
)

# The native messaging limit in internal/browserhost/protocol.go.
_MAX_NATIVE_FRAME = 256 << 10
_E2E_BIN_NAME = "e2e-bin"
PREBUILT_EXTENSION_ERROR = "prebuilt browser extension input rejected"


class FeatureNotImplementedError(Exception):
    """A real probe showed that an in-flight milestone feature is not merged.

    Raising this exception is only legitimate *after* a test has observed the
    current branch through a user-facing entry point (CLI invocation, native
    messaging frame, extension build/artifact, or desktop launch).  It is not a
    substitute for writing a test or for masking an implementation failure.
    """


# ---------------------------------------------------------------------------
# Test registration
# ---------------------------------------------------------------------------


@dataclass
class TestCaseSpec:
    test_id: str
    tier: int
    features: list[str]
    summary: str
    func: Callable[["E2EContext"], Any]
    module: str = ""
    coverage_kind: str = "functional"


REGISTRY: dict[str, TestCaseSpec] = {}


def register_test(
    test_id: str,
    tier: int,
    features: list[str] | tuple[str, ...] | str,
    summary: str = "",
    coverage_kind: str | None = None,
) -> Callable:
    """Register a test function and return it unchanged.

    The decorator is intentionally strict: a malformed test ID, unsupported
    tier, or unknown feature is a programming error in the suite, not a
    runtime skip.
    """

    if not (isinstance(test_id, str) and test_id.strip()):
        raise ValueError("test_id must be a non-empty string")
    if tier not in VALID_TIERS:
        raise ValueError(f"invalid tier {tier!r}; expected one of {VALID_TIERS}")
    if isinstance(features, str):
        features_list = [features]
    else:
        features_list = list(features)
    if not features_list:
        raise ValueError("at least one feature is required")
    if coverage_kind is not None and coverage_kind not in COVERAGE_KINDS:
        raise ValueError(f"invalid coverage_kind {coverage_kind!r}")
    if coverage_kind is None:
        coverage_kind = (
            "capability_probe"
            if tier in (3, 4) or summary.startswith("Capability probe")
            else "functional"
        )
    for feature in features_list:
        if feature not in VALID_FEATURES:
            raise ValueError(
                f"invalid feature {feature!r}; expected one of {VALID_FEATURES}"
            )

    def decorator(fn: Callable[["E2EContext"], Any]) -> Callable:
        if not callable(fn):
            raise TypeError("registered test must be callable")
        existing = REGISTRY.get(test_id)
        if existing is not None and existing.func is not fn:
            raise ValueError(f"Duplicate test_id: {test_id}")
        REGISTRY[test_id] = TestCaseSpec(
            test_id=test_id,
            tier=tier,
            features=features_list,
            summary=summary,
            func=fn,
            module=getattr(fn, "__module__", ""),
            coverage_kind=coverage_kind,
        )
        return fn

    return decorator


e2e_test = register_test


def get_registered_tests() -> list[TestCaseSpec]:
    return list(REGISTRY.values())


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------


@dataclass
class CLIResult:
    returncode: int
    stdout: str
    stderr: str
    args: list[str]

    def json(self) -> Any:
        return json.loads(self.stdout)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


@dataclass
class PTYResult:
    returncode: int
    stdout: str
    transcript: str
    issued: list[str]
    echo_restored: bool

    def json(self) -> Any:
        return json.loads(self.stdout)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


@dataclass
class NativeProbeResult:
    returncode: int | None
    frames: list[dict[str, Any]]
    raw_stdout: bytes
    stderr: str
    timed_out: bool = False

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


# ---------------------------------------------------------------------------
# Native messaging framing (internal/browserhost/protocol.go)
# ---------------------------------------------------------------------------


def encode_native_frame(
    payload_obj: dict[str, Any] | bytes | bytearray | str,
) -> bytes:
    """Encode one native messaging frame using the native 32-bit length."""

    if isinstance(payload_obj, (bytes, bytearray)):
        raw = bytes(payload_obj)
    elif isinstance(payload_obj, str):
        raw = payload_obj.encode("utf-8")
    else:
        raw = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    return struct.pack("=I", len(raw)) + raw


def read_native_frame(stream: Any) -> dict[str, Any]:
    """Read exactly one native messaging frame from *stream*."""

    header = stream.read(4)
    if not header:
        raise EOFError("Native host closed stdout without sending a frame")
    if len(header) != 4:
        raise AssertionError(f"Truncated native frame header: {len(header)} bytes")
    (length,) = struct.unpack("=I", header)
    if length == 0 or length > _MAX_NATIVE_FRAME:
        raise AssertionError(f"Invalid native frame length: {length}")
    body = stream.read(length)
    if len(body) != length:
        raise AssertionError(f"Truncated native frame body: {len(body)}/{length}")
    return json.loads(body.decode("utf-8"))


# ---------------------------------------------------------------------------
# VM environment and binary builds
# ---------------------------------------------------------------------------


def ensure_vm_temp_root() -> Path:
    """Prepare the private VM temporary root required by the test recipe."""

    os.umask(0o077)
    root = Path.home() / ".cache" / "lltmp"
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    os.environ["TMPDIR"] = str(root)
    os.environ.setdefault("GOPROXY", "direct")
    return root


# Cache keyed by (repository, binary directory) so one runner process does not
# invoke ``go build`` for every test.
_BUILD_CACHE: dict[tuple[str, str], Path] = {}
_EXTENSION_BUILD_CACHE: dict[str, tuple[Path, Path]] = {}


def _go_build_targets(repo_root: Path) -> list[tuple[str, str]]:
    targets = [
        ("locklark", "./cmd/locklark"),
        ("locklark-browser-chromium", "./cmd/locklark-browser-chromium"),
        ("locklark-browser-firefox", "./cmd/locklark-browser-firefox"),
        ("locklark-browser-register", "./cmd/locklark-browser-register"),
        ("locklark-desktop", "./cmd/locklark-desktop"),
    ]
    if (repo_root / "cmd" / "locklark-team-sync").is_dir():
        targets.append(("locklark-team-sync", "./cmd/locklark-team-sync"))
    return targets


def _executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def ensure_binaries_built(
    repo_root: Path,
    bin_dir: Path | None = None,
    skip_build: bool = False,
) -> Path:
    """Build (or reuse) every product binary used by the E2E suite."""

    repo_root = Path(repo_root).resolve()
    temp_root = ensure_vm_temp_root()
    if bin_dir is None:
        bin_dir = temp_root / _E2E_BIN_NAME
    bin_dir = Path(bin_dir)
    bin_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(bin_dir, 0o700)

    targets = _go_build_targets(repo_root)
    cache_key = (str(repo_root), str(bin_dir.resolve()))
    all_present = all(_executable(bin_dir / name) for name, _ in targets)

    if skip_build and all_present:
        _BUILD_CACHE[cache_key] = bin_dir
        return bin_dir
    if cache_key in _BUILD_CACHE and all_present:
        return bin_dir

    env = dict(os.environ)
    env["TMPDIR"] = str(temp_root)
    env["GOPROXY"] = "direct"
    for name, package in targets:
        output = bin_dir / name
        proc = subprocess.run(
            ["go", "build", "-o", str(output), package],
            cwd=str(repo_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=900,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"go build failed for {package} (rc={proc.returncode}): "
                f"{(proc.stderr or proc.stdout).strip()}"
            )
        if not _executable(output):
            raise RuntimeError(f"go build did not produce executable {output}")

    _BUILD_CACHE[cache_key] = bin_dir
    return bin_dir


# ---------------------------------------------------------------------------
# E2E context
# ---------------------------------------------------------------------------


def _safe_test_id(test_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", test_id).strip("._-")
    return (cleaned or "test")[:80]


def _surface_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return repr(value)
    return str(value)


XVFB_ARGS = ("-a", "-s", "-screen 0 1280x900x24")

# Save the protocol pipe on fd 9; xvfb-run uses and closes fd 3 internally.
# Launcher/service console output goes to stderr throughout the wrapper chain.
OWNED_SESSION_WRAPPER = 'exec 9>&1; exec 1>&2; exec "$@"'
# Only the host restores the protocol stdout. Arguments always arrive via argv.
OWNED_TARGET_WRAPPER = 'exec "$@" 1>&9 9>&-'


def effective_display(env: dict[str, str]) -> bool:
    """An empty or whitespace-only DISPLAY counts as absent."""

    return bool((env.get("DISPLAY") or "").strip())


def session_bus_usable(env: dict[str, str]) -> bool:
    """True when the supplied DBUS_SESSION_BUS_ADDRESS looks usable."""

    value = (env.get("DBUS_SESSION_BUS_ADDRESS") or "").strip()
    if not value:
        return False
    if value.startswith("unix:path="):
        path = value.split("unix:path=", 1)[1].split(",", 1)[0]
        if path and not Path(path).exists():
            return False
    return True


def owned_gui_command(
    command: list[str] | tuple[str, ...],
    *,
    env: dict[str, str],
    use_xvfb: bool,
) -> list[str]:
    """Return a GUI invocation with a private session and exclusive host stdout.

    Linux GTK/AT-SPI initialisation needs a session bus; CI images do not
    provide one, so the real native acceptance scripts run
    ``dbus-run-session -- xvfb-run ...``.  Their services log to the inherited
    stdout, which corrupts the 4-byte length-prefixed native frames, so the
    launch is wrapped in a fixed fd topology (no shell interpolation, every
    argument supplied through argv):

    ``sh -c OWNED_SESSION_WRAPPER locklark-session`` moves stdout to fd 9 and
    redirects fd 1 to stderr, then runs ``dbus-run-session -- xvfb-run ...
    sh -c OWNED_TARGET_WRAPPER locklark-native <target>`` so only the actual
    host gets the original stdout pipe back.  A supplied usable
    DBUS_SESSION_BUS_ADDRESS is preserved untouched (its services are already
    externally owned), and an empty address is treated as absent.

    Raises AssertionError (validation-blocked, never PASS/pending) when a
    required wrapper is not installed.
    """

    target = [str(part) for part in command]
    xvfb: str | None = None
    if use_xvfb:
        xvfb = shutil.which("xvfb-run")
        if xvfb is None:
            raise AssertionError(
                "validation blocked: xvfb-run unavailable; GUI session cannot be created"
            )
    dbus: str | None = None
    if sys.platform.startswith("linux") and not session_bus_usable(env):
        dbus = shutil.which("dbus-run-session")
        if dbus is None:
            raise AssertionError(
                "validation blocked: DBUS_SESSION_BUS_ADDRESS is unset and "
                "dbus-run-session is unavailable; GTK/AT-SPI GUI session cannot be created"
            )
    if xvfb is None and dbus is None:
        return target
    chain = ["sh", "-c", OWNED_TARGET_WRAPPER, "locklark-native", *target]
    if xvfb is not None:
        chain = [xvfb, *XVFB_ARGS, *chain]
    if dbus is not None:
        chain = [dbus, "--", *chain]
    return ["sh", "-c", OWNED_SESSION_WRAPPER, "locklark-session", *chain]


def first_native_frame_end(data: bytes) -> int | None:
    """Return the byte offset just past the first complete native frame."""

    if len(data) < 4:
        return None
    (length,) = struct.unpack("=I", data[:4])
    if length == 0 or length > _MAX_NATIVE_FRAME:
        return None
    end = 4 + length
    if len(data) < end:
        return None
    return end


def _group_has_members(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except (PermissionError, OSError):
        return True
    return True


def terminate_process_group(
    proc: subprocess.Popen,
    *,
    grace: float = 3.0,
    owned_group: int | None = None,
) -> int | None:
    """Terminate the session/process group this harness launched.

    Launches pass ``start_new_session=True``, so the wrapper, the GUI and any
    broker child form one group whose id equals the wrapper pid.  Ownership is
    verified: a group is signalled only when ``group == proc.pid`` (or an
    explicit ``owned_group`` recorded at launch is supplied) and never when it
    matches our own group, so unrelated user processes cannot be hit.

    The wrapper may exit while descendants remain, and a descendant may ignore
    SIGTERM, so the wait/escalation targets the *group*, not just the wrapper.
    """

    own_group = os.getpgid(0)
    group = owned_group
    if group is None:
        try:
            candidate = os.getpgid(proc.pid)
        except (ProcessLookupError, PermissionError, OSError):
            candidate = None
        group = candidate if candidate == proc.pid else None
    if group is not None and group == own_group:
        group = None
    if group is not None:
        try:
            os.killpg(group, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            group = None
    if group is None:
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                pass
        return proc.poll()

    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not _group_has_members(group):
            break
        time.sleep(0.05)
    if _group_has_members(group):
        try:
            os.killpg(group, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        hard_deadline = time.monotonic() + 2.0
        while time.monotonic() < hard_deadline and _group_has_members(group):
            time.sleep(0.05)
    try:
        proc.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        pass
    return proc.poll()


def relay_first_frame(
    proc: subprocess.Popen,
    raw_input: bytes,
    *,
    timeout: float,
    grace: float = 3.0,
) -> tuple[bytes, bytes, bool]:
    """Keep the relay stdin open until one complete framed reply arrives.

    A real browser keeps the native-messaging pipe open while the host waits
    for the desktop broker, so closing stdin right after the request (what
    ``communicate(input=...)`` does) can stop the host's relay before the reply
    is forwarded.  This helper writes the request, waits for exactly one
    complete length-prefixed frame on stdout, then closes stdin and tears down
    the owned process group.  All reads are select-driven and bounded; EOF
    streams are dropped from the select set, and the final drain never blocks
    on a descendant that inherited the pipes.

    Returns ``(stdout, stderr, timed_out)``; ``timed_out`` is True when no
    complete frame arrived before the deadline.
    """

    buffers: dict[Any, bytearray] = {}
    if proc.stdout is not None:
        buffers[proc.stdout] = bytearray()
    if proc.stderr is not None:
        buffers[proc.stderr] = bytearray()
    complete = False

    def collect(until: float) -> None:
        nonlocal complete
        while True:
            remaining = until - time.monotonic()
            if remaining <= 0:
                return
            live = [stream for stream in buffers if not stream.closed]
            if not live:
                return
            ready, _, _ = select.select(live, [], [], min(0.2, remaining))
            if not ready:
                if proc.poll() is not None and not any(
                    not stream.closed for stream in buffers
                ):
                    return
                continue
            for stream in ready:
                buffer = buffers[stream]
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except (OSError, ValueError):
                    chunk = b""
                if not chunk:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass
                    continue
                buffer.extend(chunk)
                if stream is proc.stdout and first_native_frame_end(bytes(buffer)):
                    complete = True
            if complete:
                return

    deadline = time.monotonic() + timeout
    try:
        if raw_input:
            try:
                proc.stdin.write(raw_input)
                proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                pass
        collect(deadline)
    finally:
        try:
            proc.stdin.close()
        except (OSError, ValueError):
            pass
        if not complete:
            collect(time.monotonic() + 1.0)
        # The relay always owns a start_new_session launch, so the group id is
        # the wrapper pid even after the wrapper itself has exited.
        terminate_process_group(proc, grace=grace, owned_group=proc.pid)
        for stream in list(buffers):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
    stdout = bytes(buffers.get(proc.stdout, b""))
    stderr = bytes(buffers.get(proc.stderr, b""))
    return stdout, stderr, not complete


class E2EContext:
    """Per-test isolated environment and access to user-facing entry points."""

    def __init__(self, repo_root: Path, bin_dir: Path, test_id: str):
        temp_root = ensure_vm_temp_root()
        self.repo_root = Path(repo_root).resolve()
        self.test_id = test_id
        self.bin_dir = Path(bin_dir)
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.bin_dir, 0o700)

        runs_root = temp_root / "e2e-runs"
        runs_root.mkdir(parents=True, exist_ok=True)
        os.chmod(runs_root, 0o700)
        self.temp_dir = runs_root / f"{_safe_test_id(test_id)}-{secrets.token_hex(4)}"
        self.temp_dir.mkdir(mode=0o700, exist_ok=False)
        os.chmod(self.temp_dir, 0o700)

        self.locklark_bin = self.bin_dir / "locklark"
        self.browser_chromium_bin = self.bin_dir / "locklark-browser-chromium"
        self.browser_firefox_bin = self.bin_dir / "locklark-browser-firefox"
        self.browser_register_bin = self.bin_dir / "locklark-browser-register"
        self.desktop_bin = self.bin_dir / "locklark-desktop"
        team_sync = self.bin_dir / "locklark-team-sync"
        self.team_sync_bin: Path | None = team_sync if _executable(team_sync) else None
        # Sanitized, small evidence a test may add to the JSON report.
        self.evidence: dict[str, Any] | None = None
        self._cleaned = False

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> "E2EContext":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self.cleanup()
        return False

    def cleanup(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -- environment helpers ----------------------------------------------

    def _child_env(self, env: dict[str, str] | None) -> dict[str, str]:
        proc_env = dict(os.environ)
        if env:
            proc_env.update({str(key): str(value) for key, value in env.items()})
        # A caller-supplied TMPDIR is an explicit override; otherwise the test
        # gets its own private directory beneath the shared 0700 root.
        if not env or "TMPDIR" not in env:
            proc_env["TMPDIR"] = str(self.temp_dir)
        return proc_env

    # -- CLI / PTY ---------------------------------------------------------

    def run_cli(
        self,
        args: list[Any] | tuple[Any, ...],
        *,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
        timeout: float = 15.0,
        binary: Path | str | None = None,
    ) -> CLIResult:
        executable = Path(binary) if binary is not None else self.locklark_bin
        string_args = [str(arg) for arg in args]
        command = [str(executable), *string_args]
        proc = subprocess.run(
            command,
            cwd=str(cwd or self.temp_dir),
            env=self._child_env(env),
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return CLIResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            args=command,
        )

    def run_pty_cli(
        self,
        args: list[Any] | tuple[Any, ...],
        prompts: (
            list[tuple[str, str | None]] | tuple[tuple[str, str | None], ...]
        ) = (),
        *,
        controlling_tty: bool = False,
        stdin_data: str | bytes | None = None,
        env: dict[str, str] | None = None,
        cwd: Path | str | None = None,
        timeout: float = 20.0,
        binary: Path | str | None = None,
        check_echo: bool = True,
        drain_after_exit: float = 0.2,
    ) -> PTYResult:
        """Run the CLI with a real POSIX PTY and answer hidden prompts.

        Prompts are emitted by Locklark on stderr.  The PTY slave is therefore
        attached to stderr (and to stdin unless pipe input is requested), while
        stdout remains a normal pipe for the JSON receipt.  ``answer=None``
        means "re-use the most recently issued Secret Key / Recovery Kit",
        which exercises the real confirmation prompt rather than assuming it.
        """

        ensure_vm_temp_root()
        executable = Path(binary) if binary is not None else self.locklark_bin
        command = [str(executable), *[str(arg) for arg in args]]
        proc_env = self._child_env(env)

        master, slave = pty.openpty()
        proc: subprocess.Popen[bytes] | None = None
        transcript = bytearray()
        issued_keys: list[str] = []
        stdout_bytes: bytes = b""
        echo_restored = False
        slave_open = True
        master_open = True

        def preexec() -> None:
            os.setsid()
            if controlling_tty:
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

        def drain_available(wait: float = 0.0) -> None:
            deadline = time.monotonic() + max(0.0, wait)
            while True:
                remaining = max(0.0, deadline - time.monotonic())
                try:
                    ready, _, _ = select.select([master], [], [], remaining)
                except (OSError, ValueError):
                    return
                if not ready:
                    return
                try:
                    chunk = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno in (errno.EIO, errno.EBADF):
                        return
                    raise
                if not chunk:
                    return
                transcript.extend(chunk)
                if remaining <= 0:
                    # Only drain bytes that are already buffered; do not block
                    # a second select after a zero-time probe.
                    return

        try:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if stdin_data is not None else slave,
                stdout=subprocess.PIPE,
                stderr=slave,
                cwd=str(cwd or self.temp_dir),
                env=proc_env,
                close_fds=True,
                preexec_fn=preexec,
            )

            if stdin_data is not None:
                data = (
                    stdin_data.encode("utf-8")
                    if isinstance(stdin_data, str)
                    else bytes(stdin_data)
                )
                assert proc.stdin is not None
                try:
                    proc.stdin.write(data)
                    proc.stdin.flush()
                except (BrokenPipeError, ValueError):
                    pass
                finally:
                    try:
                        proc.stdin.close()
                    except (BrokenPipeError, ValueError, OSError):
                        pass
                    # communicate() must not try to flush/close it a second time.
                    proc.stdin = None

            offset = 0
            for prompt_label, answer in prompts:
                label = str(prompt_label)
                marker_text = label if label.endswith(": ") else f"{label}: "
                marker = marker_text.encode("utf-8")
                deadline = time.monotonic() + timeout
                prompt_offset: int | None = None

                while True:
                    found = bytes(transcript).find(marker, offset)
                    if found >= 0:
                        offset = found + len(marker)
                        prompt_offset = offset
                        break

                    if proc.poll() is not None:
                        # The child may have written the prompt and exited
                        # before the final poll; drain once before failing.
                        drain_available(0.2)
                        found = bytes(transcript).find(marker, offset)
                        if found >= 0:
                            offset = found + len(marker)
                            prompt_offset = offset
                            break
                        raise AssertionError(
                            f"Missing prompt {prompt_label!r} "
                            f"(rc={proc.returncode}, "
                            f"transcript={transcript.decode('utf-8', 'replace')!r})"
                        )

                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        drain_available(0.2)
                        if bytes(transcript).find(marker, offset) >= 0:
                            continue
                        raise AssertionError(
                            f"Missing prompt {prompt_label!r} "
                            f"(rc={proc.returncode}, "
                            f"transcript={transcript.decode('utf-8', 'replace')!r})"
                        )

                    ready, _, _ = select.select([master], [], [], remaining)
                    if not ready:
                        continue
                    try:
                        chunk = os.read(master, 65536)
                    except OSError as exc:
                        if exc.errno in (errno.EIO, errno.EBADF):
                            continue
                        raise
                    if not chunk:
                        continue
                    transcript.extend(chunk)

                assert prompt_offset is not None
                if check_echo:
                    try:
                        echo_enabled = bool(
                            termios.tcgetattr(slave)[3] & termios.ECHO
                        )
                    except termios.error:
                        echo_enabled = False
                    if echo_enabled:
                        raise AssertionError(
                            f"Terminal echo was enabled at prompt {prompt_label!r}"
                        )

                if answer is None:
                    matches = list(ISSUED_TOKEN_RE.finditer(bytes(transcript[:offset])))
                    if not matches:
                        raise AssertionError(
                            "Expected issued Secret Key / Recovery Kit before "
                            "confirmation prompt"
                        )
                    answer_text = matches[-1].group(0).decode("ascii")
                    issued_keys.append(answer_text)
                else:
                    answer_text = str(answer)

                if answer_text == "\x03":
                    payload = b"\x03"
                elif answer_text.endswith("\n"):
                    payload = answer_text.encode("utf-8")
                elif len(answer_text) == 1 and ord(answer_text) < 32:
                    payload = answer_text.encode("utf-8")
                else:
                    payload = answer_text.encode("utf-8") + b"\n"
                os.write(master, payload)

            stdout_bytes, _ = proc.communicate(timeout=timeout)
            if stdout_bytes is None:
                stdout_bytes = b""

            try:
                echo_restored = bool(termios.tcgetattr(slave)[3] & termios.ECHO)
            except termios.error:
                echo_restored = False

            # Output written by the child just before it exits can still be in
            # the PTY buffer; callers that assert on late terminal text request
            # a longer bounded drain.  Drain before closing the slave: closing
            # it first makes the pending final write unreadable.
            drain_available(drain_after_exit)
            if slave_open:
                os.close(slave)
                slave_open = False
            return PTYResult(
                returncode=proc.returncode,
                stdout=stdout_bytes.decode("utf-8", "replace"),
                transcript=transcript.decode("utf-8", "replace"),
                issued=issued_keys,
                echo_restored=echo_restored,
            )
        finally:
            if proc is not None:
                if proc.poll() is None:
                    try:
                        proc.terminate()
                        proc.wait(timeout=2)
                    except Exception:
                        try:
                            proc.kill()
                        except OSError:
                            pass
                        try:
                            proc.wait(timeout=2)
                        except Exception:
                            pass
                if proc.stdin is not None:
                    try:
                        proc.stdin.close()
                    except (BrokenPipeError, ValueError, OSError):
                        pass
            if slave_open:
                try:
                    os.close(slave)
                except OSError:
                    pass
            if master_open:
                try:
                    os.close(master)
                except OSError:
                    pass

    # -- vault fixtures ----------------------------------------------------

    def init_vault(
        self,
        vault_path: Path | str | None = None,
        master_password: str = "correct-horse-battery-staple-2026",
    ) -> tuple[Path, str, str]:
        if vault_path is None:
            path = self.temp_dir / f"vault-{uuid.uuid4().hex[:8]}.ll"
        else:
            path = Path(vault_path)
        result = self.run_pty_cli(
            ["personal", "init", "--file", str(path)],
            prompts=[
                ("主密码", master_password),
                ("再次输入主密码", master_password),
                ("重新输入刚保存的 Secret Key", None),
            ],
        )
        if result.returncode != 0:
            raise AssertionError(
                f"personal init failed (rc={result.returncode}): "
                f"{result.transcript}"
            )
        receipt = result.json()
        if receipt.get("status") != "created":
            raise AssertionError(f"personal init did not create a vault: {receipt!r}")
        if len(result.issued) != 1:
            raise AssertionError(
                f"expected one issued Secret Key, got {result.issued!r}"
            )
        return path, master_password, result.issued[0]

    def add_login(
        self,
        vault_path: Path | str,
        master_password: str,
        secret_key: str,
        title: str,
        username: str,
        login_password: str,
    ) -> tuple[str, str]:
        result = self.run_pty_cli(
            ["personal", "add-login", "--file", str(vault_path)],
            prompts=[
                ("主密码", master_password),
                ("Secret Key", secret_key),
                ("登录标题", title),
                ("用户名（可留空）", username),
                ("登录密码", login_password),
            ],
        )
        if result.returncode != 0:
            raise AssertionError(
                f"personal add-login failed (rc={result.returncode}): "
                f"{result.transcript}"
            )
        data = result.json()
        item_id = data["id"]
        revision = data.get("revision")
        if not revision:
            list_result = self.run_pty_cli(
                ["personal", "list", "--file", str(vault_path)],
                prompts=[
                    ("主密码", master_password),
                    ("Secret Key", secret_key),
                ],
            )
            if list_result.returncode != 0:
                raise AssertionError(
                    f"personal list failed (rc={list_result.returncode}): "
                    f"{list_result.transcript}"
                )
            rows = list_result.json()
            row = next((entry for entry in rows if entry.get("id") == item_id), None)
            if row is None:
                raise AssertionError(
                    f"added item {item_id!r} was not present in personal list"
                )
            revision = row["revision"]
        return item_id, revision

    # -- native messaging --------------------------------------------------

    def encode_native_frame(
        self, payload_obj: dict[str, Any] | bytes | bytearray | str
    ) -> bytes:
        return encode_native_frame(payload_obj)

    def read_native_frame(self, stream: Any) -> dict[str, Any]:
        return read_native_frame(stream)

    def probe_native_host_frame(
        self,
        frame_bytes_or_obj: (
            dict[str, Any] | str | bytes | bytearray | list[Any] | tuple[Any, ...] | None
        ),
        *,
        browser: str = "chromium",
        launch_args: list[Any] | tuple[Any, ...] | None = None,
        timeout: float = 10.0,
        use_xvfb: bool | None = None,
        env: dict[str, str] | None = None,
        await_reply: bool = False,
    ) -> NativeProbeResult:
        bin_path = (
            self.browser_chromium_bin
            if browser == "chromium"
            else self.browser_firefox_bin
        )
        if launch_args is None:
            if browser == "chromium":
                launch_args = [CHROMIUM_EXT_ORIGIN]
            else:
                # ValidateLaunch only inspects the canonical absolute path and
                # extension ID; the host itself does not need to read the file.
                launch_args = [
                    str(self.temp_dir / "org.locklark.browser.json"),
                    FIREFOX_EXT_ID,
                ]

        if frame_bytes_or_obj is None:
            raw_input = b""
        elif isinstance(frame_bytes_or_obj, (bytes, bytearray)):
            raw_input = bytes(frame_bytes_or_obj)
        elif isinstance(frame_bytes_or_obj, (dict, str)):
            raw_input = encode_native_frame(frame_bytes_or_obj)
        elif isinstance(frame_bytes_or_obj, (list, tuple)):
            chunks: list[bytes] = []
            for item in frame_bytes_or_obj:
                if isinstance(item, (bytes, bytearray)):
                    chunks.append(bytes(item))
                else:
                    chunks.append(encode_native_frame(item))
            raw_input = b"".join(chunks)
        else:
            raise TypeError(
                "frame_bytes_or_obj must be bytes, str, dict, list, tuple, or None"
            )

        proc_env = dict(os.environ if env is None else env)
        proc_env["TMPDIR"] = str(self.temp_dir)
        if use_xvfb is None:
            use_xvfb = not effective_display(proc_env) and shutil.which("xvfb-run") is not None
        args = [str(arg) for arg in launch_args]
        command = owned_gui_command(
            [str(bin_path), *args], env=proc_env, use_xvfb=bool(use_xvfb)
        )

        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(self.temp_dir),
            env=proc_env,
            start_new_session=True,
        )
        timed_out = False
        stdout_bytes = b""
        stderr_bytes = b""
        if await_reply:
            stdout_bytes, stderr_bytes, timed_out = relay_first_frame(
                proc, raw_input, timeout=timeout
            )
        else:
            first_timeout: subprocess.TimeoutExpired | None = None
            try:
                stdout_bytes, stderr_bytes = proc.communicate(
                    input=raw_input, timeout=timeout
                )
            except subprocess.TimeoutExpired as exc:
                first_timeout = exc
                timed_out = True
                try:
                    proc.kill()
                except OSError:
                    pass
                # collect partial output, but keep the wait bounded even when
                # the host left a grandchild holding the inherited pipes open.
                try:
                    stdout_bytes, stderr_bytes = proc.communicate(timeout=2)
                except subprocess.TimeoutExpired as second:
                    stdout_bytes = (first_timeout.output or b"") + (
                        second.output or b""
                    )
                    stderr_bytes = (first_timeout.stderr or b"") + (
                        second.stderr or b""
                    )
        terminate_process_group(proc, grace=5.0, owned_group=proc.pid)

        returncode: int | None = proc.returncode
        stdout_bytes = stdout_bytes or b""
        stderr_bytes = stderr_bytes or b""

        frames: list[dict[str, Any]] = []
        stream = io.BytesIO(stdout_bytes)
        while True:
            header = stream.read(4)
            if not header:
                break
            if len(header) != 4:
                break
            (length,) = struct.unpack("=I", header)
            if length == 0 or length > _MAX_NATIVE_FRAME:
                break
            body = stream.read(length)
            if len(body) != length:
                break
            try:
                frame = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                break
            if not isinstance(frame, dict):
                break
            frames.append(frame)

        return NativeProbeResult(
            returncode=returncode,
            frames=frames,
            raw_stdout=stdout_bytes,
            stderr=stderr_bytes.decode("utf-8", "replace"),
            timed_out=timed_out,
        )

    # -- Node and extension ------------------------------------------------

    def run_node(
        self,
        js_code: str,
        *,
        cwd: Path | str | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 20.0,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["node", "-e", js_code],
            cwd=str(cwd or self.repo_root),
            env=self._child_env(env),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def _prebuilt_extension_paths(self) -> tuple[Path, Path] | None:
        if os.environ.get("LOCKLARK_BROWSER_REQUIRE_PREBUILT") != "1":
            return None
        prepared = os.environ.get("LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR", "")
        chromium = os.environ.get("LOCKLARK_BROWSER_EXTENSION_CHROMIUM", "")
        firefox = os.environ.get("LOCKLARK_BROWSER_EXTENSION_FIREFOX", "")
        if not prepared or not chromium or not firefox:
            raise AssertionError(PREBUILT_EXTENSION_ERROR)
        try:
            from browserrelease import prebuilt
            for product, dist in (("chromium", chromium), ("firefox", firefox)):
                prebuilt.verify_prebuilt(
                    product, Path(prepared), Path(dist), self.repo_root
                )
        except Exception:
            raise AssertionError(PREBUILT_EXTENSION_ERROR) from None
        return Path(chromium), Path(firefox)

    def ensure_extension_built(self) -> tuple[Path, Path]:
        strict = self._prebuilt_extension_paths()
        if strict is not None:
            return strict
        repo_key = str(self.repo_root.resolve())
        cached = _EXTENSION_BUILD_CACHE.get(repo_key)
        chromium = self.repo_root / "browser-extension" / "dist" / "chromium"
        firefox = self.repo_root / "browser-extension" / "dist" / "firefox"
        if cached is not None:
            cached_chromium, cached_firefox = cached
            if (
                (cached_chromium / "manifest.json").is_file()
                and (cached_firefox / "manifest.json").is_file()
            ):
                return cached

        script = self.repo_root / "browser-extension" / "build.js"
        for mode in ("chromium", "firefox"):
            if not script.is_file():
                raise AssertionError(
                    f"browser extension build script is missing: {script}"
                )
            proc = subprocess.run(
                ["node", "browser-extension/build.js", mode],
                cwd=str(self.repo_root),
                env=self._child_env(None),
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                raise AssertionError(
                    f"extension build failed for {mode} "
                    f"(rc={proc.returncode}): {proc.stderr.strip()}"
                )

        for directory in (chromium, firefox):
            manifest = directory / "manifest.json"
            if not manifest.is_file():
                raise AssertionError(
                    f"extension build did not produce {manifest}"
                )
        _EXTENSION_BUILD_CACHE[repo_key] = (chromium, firefox)
        return chromium, firefox

    # -- assertions / progressive policy -----------------------------------

    def assert_no_canary_leak(self, canary: str, *texts: Any) -> None:
        if not (isinstance(canary, str) and canary):
            raise AssertionError("canary must be a non-empty string")
        for index, value in enumerate(texts):
            surface = _surface_text(value)
            if canary in surface:
                raise AssertionError(
                    f"Secret canary {canary!r} leaked in output #{index}"
                )

    def require_feature(self, feature_id: str, condition: bool, detail: str) -> None:
        if not condition:
            raise FeatureNotImplementedError(
                f"[PROGRESSIVE_UNIMPLEMENTED: {feature_id}] {detail}"
            )

    def record_evidence(self, evidence: dict[str, Any]) -> None:
        """Attach bounded, sanitized evidence to this test's report record."""

        if not isinstance(evidence, dict):
            raise AssertionError("evidence must be a JSON object")
        try:
            serialized = json.dumps(
                evidence, ensure_ascii=False, sort_keys=True, allow_nan=False
            )
        except (TypeError, ValueError):
            raise AssertionError("evidence must be JSON-serializable") from None
        if len(serialized.encode("utf-8")) > 32768:
            raise AssertionError("evidence metadata is too large")
        self.evidence = json.loads(serialized)


__all__ = [
    "CHROMIUM_EXT_ORIGIN",
    "COVERAGE_KINDS",
    "CLIResult",
    "E2EContext",
    "FIREFOX_EXT_ID",
    "FeatureNotImplementedError",
    "ISSUED_TOKEN_RE",
    "NativeProbeResult",
    "OWNED_SESSION_WRAPPER",
    "OWNED_TARGET_WRAPPER",
    "XVFB_ARGS",
    "effective_display",
    "first_native_frame_end",
    "owned_gui_command",
    "session_bus_usable",
    "relay_first_frame",
    "terminate_process_group",
    "PTYResult",
    "RECOVERY_KIT_RE",
    "REGISTRY",
    "SECRET_KEY_RE",
    "TestCaseSpec",
    "VALID_FEATURES",
    "VALID_TIERS",
    "e2e_test",
    "encode_native_frame",
    "ensure_binaries_built",
    "ensure_vm_temp_root",
    "get_registered_tests",
    "read_native_frame",
    "register_test",
]
