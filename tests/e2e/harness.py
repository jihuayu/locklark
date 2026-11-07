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
import shutil
import struct
import subprocess
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


REGISTRY: dict[str, TestCaseSpec] = {}


def register_test(
    test_id: str,
    tier: int,
    features: list[str] | tuple[str, ...] | str,
    summary: str = "",
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

            if slave_open:
                os.close(slave)
                slave_open = False
            drain_available(0.2)
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
            use_xvfb = (
                "DISPLAY" not in proc_env and shutil.which("xvfb-run") is not None
            )
        args = [str(arg) for arg in launch_args]
        if use_xvfb and shutil.which("xvfb-run") is not None:
            command = [
                "xvfb-run",
                "-a",
                "-s",
                "-screen 0 1280x900x24",
                str(bin_path),
                *args,
            ]
        else:
            command = [str(bin_path), *args]

        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(self.temp_dir),
            env=proc_env,
        )
        timed_out = False
        stdout_bytes = b""
        stderr_bytes = b""
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
            # collect partial output, but keep the wait bounded even when the
            # host left a grandchild holding the inherited pipes open.
            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=2)
            except subprocess.TimeoutExpired as second:
                stdout_bytes = (first_timeout.output or b"") + (
                    second.output or b""
                )
                stderr_bytes = (first_timeout.stderr or b"") + (
                    second.stderr or b""
                )
        finally:
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass

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

    def ensure_extension_built(self) -> tuple[Path, Path]:
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


__all__ = [
    "CHROMIUM_EXT_ORIGIN",
    "CLIResult",
    "E2EContext",
    "FIREFOX_EXT_ID",
    "FeatureNotImplementedError",
    "ISSUED_TOKEN_RE",
    "NativeProbeResult",
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
