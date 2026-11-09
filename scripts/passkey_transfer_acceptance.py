#!/usr/bin/env python3
"""Owned passkey-transfer acceptance driver.

This script builds the actual standalone ``locklark`` CLI and drives the real
``personal passkey-invite/export/plan/import`` commands under a genuine
controlling PTY.  The two-factor password and Secret Key are written to the
hidden console only after each prompt has been printed (so terminal raw mode is
already active); consent phrases are typed in the same hidden console.  The
owned Go fixture creates two synthetic local vaults and one real passkey through
public ``internal/personal`` Session APIs, and verifies the imported assertion
against the source creation public key.

It does not use the GUI, does not contact a network or a real credential, and
never writes a factor to a file, argv or the environment.  Normal output is a
fixed sequence of stage names and booleans only.  Captured private PTY streams
are never printed, including on failure.

Known gap that remains open: acceptance evidence from two real physical devices
(52) is not produced by this automated PTY harness.
"""

from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import json
import os
import pty
import re
import secrets
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import termios
import time
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GO_DEFAULT = "/workspace/toolchains/go/bin/go"
IMPORTED_TITLE = "Imported Passkey Login"
IMPORTED_USERNAME = "imported-user"
FORBIDDEN_TEXT_MARKERS = (b"seed", b"signature", b"private_key", b"user_id")
HEX64 = re.compile(rb"\A[0-9a-f]{64}\Z")
TOKEN = re.compile(rb"\A[\x21-\x7e]{1,1024}\Z")


class Refusal(Exception):
    """A fixed, redacted failure code safe to emit as a stage reason."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def refuse(code: str):
    raise Refusal(code)


def require(condition, code: str):
    if not condition:
        refuse(code)


def hex64(value):
    return isinstance(value, str) and bool(HEX64.fullmatch(value.encode("ascii", "strict")))


def token(value):
    return isinstance(value, str) and bool(TOKEN.fullmatch(value.encode("ascii", "strict")))


def credential_id(value):
    if not isinstance(value, str) or not value or len(value) > 1024:
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        return False
    return bool(raw) and base64.urlsafe_b64encode(raw).decode().rstrip("=") == value


def format_secret(raw: bytes) -> str:
    require(len(raw) == 16, "secret_length")
    return "LL1-" + base64.b32encode(raw).decode("ascii").rstrip("=")


def selection_document(item_id: str, parent_revision: str, cred_id: str, child_revision: str) -> bytes:
    return json.dumps(
        [{
            "item_id": item_id,
            "revision": parent_revision,
            "credential_id": cred_id,
            "credential_revision": child_revision,
        }],
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def mapping_document(group_id: str, title: str = IMPORTED_TITLE, username: str = IMPORTED_USERNAME) -> bytes:
    return json.dumps(
        [{"group_id": group_id, "new_title": title, "new_username": username}],
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


class Factors:
    """Per-run source and receiver factors held only in memory/private pipes."""

    def __init__(self):
        self.source_password = "pt-source-" + secrets.token_hex(24)
        self.receiver_password = "pt-receiver-" + secrets.token_hex(24)
        self.source_key_raw = bytearray(secrets.token_bytes(16))
        self.receiver_key_raw = bytearray(secrets.token_bytes(16))
        self.source_secret = format_secret(bytes(self.source_key_raw))
        self.receiver_secret = format_secret(bytes(self.receiver_key_raw))

    def fixture_payload(self) -> bytes:
        return json.dumps({
            "source_password": self.source_password,
            "source_key": self.source_secret,
            "receiver_password": self.receiver_password,
            "receiver_key": self.receiver_secret,
        }, separators=(",", ":")).encode()

    def source_tuple(self):
        return self.source_password.encode(), self.source_secret.encode()

    def receiver_tuple(self):
        return self.receiver_password.encode(), self.receiver_secret.encode()

    def secrets_bytes(self):
        return [
            self.source_password.encode(),
            self.receiver_password.encode(),
            self.source_secret.encode(),
            self.receiver_secret.encode(),
        ]

    def clear(self):
        for raw in (self.source_key_raw, self.receiver_key_raw):
            for i in range(len(raw)):
                raw[i] = 0
        self.source_key_raw = bytearray()
        self.receiver_key_raw = bytearray()


class Recorder:
    def __init__(self, log_path: Path | None):
        self.log_path = log_path
        if log_path is not None:
            parent = log_path.parent
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(parent, 0o700)
            fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)

    def _write(self, line: str):
        print(line, flush=True)
        if self.log_path is not None:
            fd = os.open(self.log_path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
            try:
                os.write(fd, (line + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)

    def stage(self, name: str):
        require(re.fullmatch(r"[a-z0-9_]+", name) is not None, "stage_name")
        self._write(f"stage={name} ok=true")

    def value(self, name: str, fixed_value: str):
        require(re.fullmatch(r"[a-z0-9_]+", name) is not None, "stage_name")
        require(re.fullmatch(r"[a-z0-9_]+", fixed_value) is not None, "stage_value")
        self._write(f"stage={name} value={fixed_value}")

    def fail(self, code: str):
        require(re.fullmatch(r"[a-z0-9_]+", code) is not None, "failure_code")
        self._write(f"stage={code} ok=false")


def make_private_root(artifacts: str | None) -> Path:
    if artifacts:
        parent = Path(artifacts).resolve()
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
        root = Path(tempfile.mkdtemp(prefix="passkey-transfer-", dir=parent))
    else:
        root = Path(tempfile.mkdtemp(prefix="locklark-passkey-transfer-"))
    os.chmod(root, 0o700)
    for name in ("bin", "home", "tmp"):
        (root / name).mkdir(mode=0o700)
        os.chmod(root / name, 0o700)
    return root


def minimal_env(root: Path) -> dict:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root / "home"),
        "TMPDIR": str(root / "tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def write_private(path: Path, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)


def private_file_ok(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
    )


def private_exec_ok(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and stat.S_IMODE(info.st_mode) in (0o600, 0o700)
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
    )


def read_file(path: Path) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def go_binary() -> str:
    if Path(GO_DEFAULT).is_file():
        return GO_DEFAULT
    found = shutil.which("go")
    require(found is not None, "go_missing")
    return found


def build_products(root: Path) -> tuple[Path, Path]:
    go = go_binary()
    env = dict(os.environ)
    env.update({"GOPROXY": "off", "GOTOOLCHAIN": "local", "GOFLAGS": ""})
    cli = root / "bin" / "locklark"
    fixture = root / "bin" / "passkey-transfer-fixture"
    for output, target, code in (
        (cli, "./cmd/locklark", "build_cli"),
        (fixture, "./scripts/passkey_transfer_fixture", "build_fixture"),
    ):
        try:
            done = subprocess.run(
                [go, "build", "-buildvcs=false", "-trimpath", "-o", str(output), target],
                cwd=REPO_ROOT,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
            )
        except (OSError, subprocess.TimeoutExpired):
            refuse(code)
        require(done.returncode == 0 and private_exec_ok(output), code)
        os.chmod(output, 0o700)
    try:
        smoke = subprocess.run(
            [str(cli), "help"],
            env=minimal_env(root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        refuse("cli_smoke")
    require(smoke.returncode == 0, "cli_smoke")
    return cli, fixture


def run_fixture(fixture: Path, args: list[str], payload: bytes, env: dict) -> dict:
    try:
        done = subprocess.run(
            [str(fixture), *args],
            input=payload,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        refuse("fixture_run")
    require(done.returncode == 0, "fixture_refused")
    try:
        value = json.loads(done.stdout)
    except Exception:
        refuse("fixture_output")
    require(isinstance(value, dict), "fixture_output")
    return value


class PtyResult:
    def __init__(self, code: int, capture: bytes, stdout: bytes, stderr: bytes):
        self.code = code
        self.capture = capture
        self.stdout = stdout
        self.stderr = stderr


class PtyProcess:
    """A child with its own session and a genuine controlling terminal."""

    def __init__(self, argv: list[str], env: dict):
        try:
            master, slave = pty.openpty()
            out_r, out_w = os.pipe()
            err_r, err_w = os.pipe()

            def preexec():
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

            self.proc = subprocess.Popen(
                argv,
                stdin=slave,
                stdout=out_w,
                stderr=err_w,
                env=env,
                close_fds=True,
                pass_fds=(slave,),
                preexec_fn=preexec,
            )
        except (OSError, subprocess.SubprocessError):
            for fd in (master, slave, out_r, out_w, err_r, err_w):
                try:
                    os.close(fd)
                except Exception:
                    pass
            refuse("pty_spawn")
        os.close(slave)
        os.close(out_w)
        os.close(err_w)
        self.master = master
        self.out_r = out_r
        self.err_r = err_r
        self.capture = bytearray()
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.deadline = time.monotonic() + 90

    @property
    def fds(self):
        return [fd for fd in (self.master, self.out_r, self.err_r) if fd is not None]

    def _pump(self):
        fds = self.fds
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            refuse("pty_timeout")
        if not fds:
            time.sleep(0.01)
            return
        try:
            ready, _, _ = select.select(fds, [], [], min(remaining, 1.0))
        except OSError:
            refuse("pty_select")
        if not ready:
            if self.proc.poll() is not None:
                time.sleep(0.01)
            return
        for fd in ready:
            try:
                data = os.read(fd, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    data = b""
                else:
                    refuse("pty_read")
            if not data:
                if fd == self.master:
                    self.master = None
                elif fd == self.out_r:
                    self.out_r = None
                else:
                    self.err_r = None
                try:
                    os.close(fd)
                except OSError:
                    pass
                continue
            if fd == self.master:
                self.capture.extend(data)
            elif fd == self.out_r:
                self.stdout.extend(data)
            else:
                self.stderr.extend(data)

    def expect(self, needle: bytes):
        while needle not in self.capture:
            if self.proc.poll() is not None and not self.fds:
                refuse("pty_exited")
            self._pump()

    def send(self, value: bytes):
        try:
            os.write(self.master, value)
        except OSError:
            refuse("pty_write")

    def finish(self) -> PtyResult:
        while True:
            self._pump()
            if self.proc.poll() is not None and not self.fds:
                break
            if time.monotonic() > self.deadline:
                try:
                    self.proc.kill()
                except OSError:
                    pass
                refuse("pty_timeout")
        try:
            code = self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            refuse("pty_wait")
        return PtyResult(code, bytes(self.capture), bytes(self.stdout), bytes(self.stderr))

    def close(self):
        if self.proc.poll() is None:
            try:
                self.proc.kill()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except Exception:
                pass
        for fd in self.fds:
            try:
                os.close(fd)
            except OSError:
                pass


def run_cli_pty(
    cli: Path,
    args: list[str],
    env: dict,
    password: bytes,
    secret: bytes,
    consent: bytes,
    consent_prompt: bytes,
) -> PtyResult:
    process = PtyProcess([str(cli), "personal", *args], env)
    try:
        process.expect("主密码: ".encode())
        process.send(password + b"\r")
        process.expect(b"Secret Key: ")
        process.send(secret + b"\r")
        process.expect(consent_prompt)
        process.send(consent + b"\r")
        return process.finish()
    finally:
        process.close()


def run_cli_no_tty(cli: Path, args: list[str], env: dict) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            [str(cli), "personal", *args],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        refuse("cli_no_tty")


def assert_hidden(
    result: PtyResult,
    factors: Factors,
    prompt: bytes | None = None,
    consent: bytes | None = None,
    blobs: tuple[bytes, ...] = (),
):
    combined = result.capture + result.stdout + result.stderr
    for secret in factors.secrets_bytes():
        require(secret not in combined, "echoed_factor")
    if prompt is not None and consent is not None:
        require(prompt + consent not in result.capture, "echoed_consent")
    for blob in blobs:
        if blob:
            require(blob not in combined, "echoed_private_blob")
            head = blob[:48]
            if len(head) >= 16:
                require(head not in combined, "echoed_private_blob")
    lowered = (result.stdout + result.stderr).lower()
    for marker in FORBIDDEN_TEXT_MARKERS:
        require(marker not in lowered, "private_marker")
    require(result.stdout.strip() == b"" if result.code != 0 else True, "failure_stdout")


def receipt(stdout: bytes, status: str) -> dict:
    try:
        value = json.loads(stdout)
    except Exception:
        refuse("receipt_json")
    require(isinstance(value, dict) and value.get("status") == status, "receipt_status")
    return value


def validate_setup(setup: dict, root: Path) -> dict:
    required = {"source_path", "receiver_path", "item_id", "parent_revision", "credential_id", "child_revision", "creation_public_key"}
    require(set(required) <= set(setup), "fixture_setup_shape")
    source = Path(setup["source_path"])
    receiver = Path(setup["receiver_path"])
    require(source.parent == root and receiver.parent == root, "fixture_setup_path")
    require(private_file_ok(source) and private_file_ok(receiver), "fixture_vault_mode")
    require(token(setup["item_id"]), "fixture_item")
    require(hex64(setup["parent_revision"]) and hex64(setup["child_revision"]), "fixture_revision")
    require(credential_id(setup["credential_id"]), "fixture_credential")
    try:
        raw_public = base64.urlsafe_b64decode(setup["creation_public_key"] + "=" * (-len(setup["creation_public_key"]) % 4))
    except Exception:
        refuse("fixture_public_key")
    require(bool(raw_public), "fixture_public_key")
    return setup


def validate_plan(plan: dict, source_pin: str, target_pin: str, expected_credential: str) -> tuple[str, str]:
    digest = plan.get("digest")
    require(hex64(digest), "plan_digest")
    require(plan.get("source_fingerprint") == source_pin, "plan_source_pin")
    require(plan.get("target_fingerprint") == target_pin, "plan_target_pin")
    groups = plan.get("groups")
    require(isinstance(groups, list) and len(groups) == 1 and isinstance(groups[0], dict), "plan_groups")
    group = groups[0]
    require(hex64(group.get("group_id")), "plan_group_id")
    require(group.get("rp_id") == "example.test", "plan_group_rp")
    ids = group.get("credential_ids")
    require(ids == [expected_credential], "plan_group_credential")

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                require(key not in {"seed", "signature", "private_key", "user_id", "record", "packet"}, "plan_private_key")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(plan)
    return digest, group["group_id"]


def validate_import(receipt_value: dict) -> tuple[str, str]:
    items = receipt_value.get("items")
    require(isinstance(items, list) and len(items) == 1 and isinstance(items[0], dict), "import_items")
    imported = items[0]
    require(token(imported.get("id")), "import_item_id")
    require(hex64(imported.get("revision")), "import_item_revision")
    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                require(key not in {"private_key", "user_id", "seed", "signature", "record", "packet"}, "import_private_key")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(receipt_value)
    return imported["id"], imported["revision"]


def state(fixture: Path, setup: dict, factors: Factors, env: dict) -> dict:
    value = run_fixture(fixture, ["state"], json.dumps({
        "source_path": setup["source_path"],
        "receiver_path": setup["receiver_path"],
        "source_password": factors.source_password,
        "source_key": factors.source_secret,
        "receiver_password": factors.receiver_password,
        "receiver_key": factors.receiver_secret,
    }, separators=(",", ":")).encode(), env)
    required = {"source_items", "source_credentials", "receiver_items", "receiver_credentials", "invite_events", "export_events", "consume_events"}
    require(required <= set(value) and all(isinstance(value[key], int) for key in required), "state_shape")
    return value


def verify(fixture: Path, setup: dict, factors: Factors, env: dict, imported_id: str, imported_revision: str) -> dict:
    value = run_fixture(fixture, ["verify"], json.dumps({
        "source_path": setup["source_path"],
        "receiver_path": setup["receiver_path"],
        "source_password": factors.source_password,
        "source_key": factors.source_secret,
        "receiver_password": factors.receiver_password,
        "receiver_key": factors.receiver_secret,
        "item_id": setup["item_id"],
        "parent_revision": setup["parent_revision"],
        "credential_id": setup["credential_id"],
        "child_revision": setup["child_revision"],
        "creation_public_key": setup["creation_public_key"],
        "imported_id": imported_id,
        "imported_revision": imported_revision,
        "expected_imported_title": IMPORTED_TITLE,
    }, separators=(",", ":")).encode(), env)
    for key in ("source_available", "source_frozen", "credential_present", "title_matches", "identity_matches", "assertion_verified"):
        require(value.get(key) is True, "fixture_verify")
    return value


def assert_state(value: dict, expected: dict):
    for key, count in expected.items():
        require(value.get(key) == count, "state_mismatch")


def privacy_scan(root: Path, factors: Factors, log_path: Path | None):
    secrets_bytes = factors.secrets_bytes()
    text_markers = FORBIDDEN_TEXT_MARKERS
    for current, directories, files in os.walk(root):
        current_path = Path(current)
        info = os.lstat(current_path)
        require(stat.S_ISDIR(info.st_mode) and info.st_mode & 0o077 == 0 and info.st_uid == os.geteuid(), "artifact_mode")
        for directory in directories:
            child = current_path / directory
            child_info = os.lstat(child)
            require(stat.S_ISDIR(child_info.st_mode) and not stat.S_ISLNK(child_info.st_mode), "artifact_type")
            require(child_info.st_mode & 0o077 == 0 and child_info.st_uid == os.geteuid(), "artifact_mode")
        for filename in files:
            child = current_path / filename
            child_info = os.lstat(child)
            require(stat.S_ISREG(child_info.st_mode) and not stat.S_ISLNK(child_info.st_mode), "artifact_type")
            require(child_info.st_mode & 0o077 == 0 and child_info.st_uid == os.geteuid(), "artifact_mode")
            data = read_file(child)
            for secret in secrets_bytes:
                require(secret not in data, "artifact_factor")
            if child.suffix == ".log" or child.name in {"selection.json", "mapping.json"}:
                lowered = data.lower()
                for marker in text_markers:
                    require(marker not in lowered, "artifact_marker")
    if log_path is not None:
        data = read_file(log_path)
        for secret in secrets_bytes:
            require(secret not in data, "log_factor")
        for marker in text_markers:
            require(marker not in data.lower(), "log_marker")


def accept(args) -> int:
    recorder = Recorder(Path(args.log).absolute() if args.log else None)
    factors = Factors()
    root: Path | None = None
    try:
        os.umask(0o077)
        require(Path(GO_DEFAULT).is_file() or shutil.which("go") is not None, "go_missing")
        require((REPO_ROOT / "cmd" / "locklark" / "main.go").is_file(), "repo_missing")
        require((REPO_ROOT / "scripts" / "passkey_transfer_fixture" / "main.go").is_file(), "fixture_missing")
        recorder.stage("prerequisites")

        root = make_private_root(args.artifacts)
        if recorder.log_path is None:
            recorder.log_path = root / "acceptance.log"
            Recorder(recorder.log_path)
        env = minimal_env(root)
        cli, fixture = build_products(root)
        recorder.stage("build")

        setup = validate_setup(run_fixture(fixture, ["setup", str(root)], factors.fixture_payload(), env), root)
        recorder.stage("fixture_setup")
        initial = state(fixture, setup, factors, env)
        assert_state(initial, {"source_items": 1, "source_credentials": 1, "receiver_items": 0, "receiver_credentials": 0, "invite_events": 0, "export_events": 0, "consume_events": 0})
        recorder.stage("fixture_state_initial")

        invite_cancel = root / "invite-cancel.json"
        invite_prompt = b"Enter INVITE to confirm invitation creation: "
        result = run_cli_pty(
            cli,
            ["passkey-invite", "--file", setup["receiver_path"], "--out", str(invite_cancel), "--ttl", "600"],
            env,
            *factors.receiver_tuple(),
            b"NOPE",
            invite_prompt,
        )
        require(result.code != 0 and not invite_cancel.exists(), "invite_cancel")
        assert_hidden(result, factors, invite_prompt, b"NOPE")
        assert_state(state(fixture, setup, factors, env), {"receiver_items": 0, "receiver_credentials": 0, "invite_events": 0})
        recorder.stage("invite_cancel_no_mutation")

        invitation_path = root / "invitation.json"
        result = run_cli_pty(
            cli,
            ["passkey-invite", "--file", setup["receiver_path"], "--out", str(invitation_path), "--ttl", "600"],
            env,
            *factors.receiver_tuple(),
            b"INVITE",
            invite_prompt,
        )
        require(result.code == 0, "invite_exit")
        assert_hidden(result, factors, invite_prompt, b"INVITE")
        invite_value = receipt(result.stdout, "invited")
        target_pin = invite_value.get("fingerprint")
        require(hex64(target_pin) and token(invite_value.get("invitation_id")), "invite_receipt")
        require(private_file_ok(invitation_path), "invite_output_private")
        invitation_bytes = read_file(invitation_path)
        recorder.stage("invite_success")
        recorder.stage("invite_output_private")

        before = read_file(invitation_path)
        overwrite = run_cli_no_tty(cli, ["passkey-invite", "--file", setup["receiver_path"], "--out", str(invitation_path), "--ttl", "600"], env)
        require(overwrite.returncode != 0 and b"usage:" in overwrite.stderr and b"controlling terminal" not in overwrite.stderr, "invite_overwrite_refusal")
        require(read_file(invitation_path) == before and private_file_ok(invitation_path), "invite_overwrite_changed")
        assert_state(state(fixture, setup, factors, env), {"invite_events": 1})
        recorder.stage("invite_no_overwrite")

        selection_path = root / "selection.json"
        write_private(selection_path, selection_document(setup["item_id"], setup["parent_revision"], setup["credential_id"], setup["child_revision"]))
        require(private_file_ok(selection_path), "selection_mode")

        export_cancel = root / "packet-cancel.json"
        export_prompt = b"Enter EXPORT to confirm sealed credential export: "
        result = run_cli_pty(
            cli,
            ["passkey-export", "--file", setup["source_path"], "--invitation", str(invitation_path), "--target-pin", target_pin, "--selection", str(selection_path), "--out", str(export_cancel)],
            env,
            *factors.source_tuple(),
            b"NOPE",
            export_prompt,
        )
        require(result.code != 0 and not export_cancel.exists(), "export_cancel")
        assert_hidden(result, factors, export_prompt, b"NOPE", (invitation_bytes,))
        assert_state(state(fixture, setup, factors, env), {"export_events": 0, "source_items": 1, "source_credentials": 1})
        recorder.stage("export_cancel_no_mutation")

        packet_path = root / "packet.json"
        result = run_cli_pty(
            cli,
            ["passkey-export", "--file", setup["source_path"], "--invitation", str(invitation_path), "--target-pin", target_pin, "--selection", str(selection_path), "--out", str(packet_path)],
            env,
            *factors.source_tuple(),
            b"EXPORT",
            export_prompt,
        )
        require(result.code == 0, "export_exit")
        assert_hidden(result, factors, export_prompt, b"EXPORT", (invitation_bytes,))
        export_value = receipt(result.stdout, "exported")
        source_pin = export_value.get("source_fingerprint")
        require(hex64(source_pin) and export_value.get("target_fingerprint") == target_pin, "export_receipt")
        require(private_file_ok(packet_path), "packet_output_private")
        packet_bytes = read_file(packet_path)
        assert_state(state(fixture, setup, factors, env), {"export_events": 1, "source_items": 1, "source_credentials": 1})
        recorder.stage("export_success")
        recorder.stage("pins_frozen")

        before = read_file(packet_path)
        overwrite = run_cli_no_tty(cli, ["passkey-export", "--file", setup["source_path"], "--invitation", str(invitation_path), "--target-pin", target_pin, "--selection", str(selection_path), "--out", str(packet_path)], env)
        require(overwrite.returncode != 0 and b"usage:" in overwrite.stderr and b"controlling terminal" not in overwrite.stderr, "packet_overwrite_refusal")
        require(read_file(packet_path) == before and private_file_ok(packet_path), "packet_overwrite_changed")
        assert_state(state(fixture, setup, factors, env), {"export_events": 1})
        recorder.stage("packet_no_overwrite")

        plan_prompt = b"Enter PLAN to confirm receiver preview: "
        state_before = state(fixture, setup, factors, env)
        result = run_cli_pty(
            cli,
            ["passkey-plan", "--file", setup["receiver_path"], "--invitation", str(invitation_path), "--packet", str(packet_path), "--source-pin", source_pin],
            env,
            *factors.receiver_tuple(),
            b"NOPE",
            plan_prompt,
        )
        require(result.code != 0 and result.stdout.strip() == b"", "plan_cancel")
        assert_hidden(result, factors, plan_prompt, b"NOPE", (invitation_bytes, packet_bytes))
        assert_state(state(fixture, setup, factors, env), state_before)
        recorder.stage("plan_cancel_no_mutation")

        result = run_cli_pty(
            cli,
            ["passkey-plan", "--file", setup["receiver_path"], "--invitation", str(invitation_path), "--packet", str(packet_path), "--source-pin", source_pin],
            env,
            *factors.receiver_tuple(),
            b"PLAN",
            plan_prompt,
        )
        require(result.code == 0, "plan_exit")
        assert_hidden(result, factors, plan_prompt, b"PLAN", (invitation_bytes, packet_bytes))
        try:
            plan_value = json.loads(result.stdout)
        except Exception:
            refuse("plan_json")
        require(isinstance(plan_value, dict), "plan_json")
        digest, group_id = validate_plan(plan_value, source_pin, target_pin, setup["credential_id"])
        assert_state(state(fixture, setup, factors, env), state_before)
        recorder.stage("plan_success")
        recorder.stage("plan_digest_group_frozen")

        mapping_path = root / "mapping.json"
        write_private(mapping_path, mapping_document(group_id))
        require(private_file_ok(mapping_path), "mapping_mode")

        import_prompt = b"Enter IMPORT to confirm passkey import: "
        state_before = state(fixture, setup, factors, env)
        result = run_cli_pty(
            cli,
            ["passkey-import", "--file", setup["receiver_path"], "--invitation", str(invitation_path), "--packet", str(packet_path), "--source-pin", source_pin, "--digest", digest, "--mapping", str(mapping_path)],
            env,
            *factors.receiver_tuple(),
            b"NOPE",
            import_prompt,
        )
        require(result.code != 0 and result.stdout.strip() == b"", "import_cancel")
        assert_hidden(result, factors, import_prompt, b"NOPE", (invitation_bytes, packet_bytes))
        assert_state(state(fixture, setup, factors, env), state_before)
        recorder.stage("import_cancel_no_mutation")

        result = run_cli_pty(
            cli,
            ["passkey-import", "--file", setup["receiver_path"], "--invitation", str(invitation_path), "--packet", str(packet_path), "--source-pin", source_pin, "--digest", digest, "--mapping", str(mapping_path)],
            env,
            *factors.receiver_tuple(),
            b"IMPORT",
            import_prompt,
        )
        require(result.code == 0, "import_exit")
        assert_hidden(result, factors, import_prompt, b"IMPORT", (invitation_bytes, packet_bytes))
        import_value = receipt(result.stdout, "imported")
        imported_id, imported_revision = validate_import(import_value)
        assert_state(state(fixture, setup, factors, env), {"receiver_items": 1, "receiver_credentials": 1, "consume_events": 1, "source_items": 1, "source_credentials": 1})
        recorder.stage("import_success")

        verify(fixture, setup, factors, env, imported_id, imported_revision)
        recorder.stage("assertion_verified")
        recorder.stage("source_available_frozen")

        state_before = state(fixture, setup, factors, env)
        result = run_cli_pty(
            cli,
            ["passkey-import", "--file", setup["receiver_path"], "--invitation", str(invitation_path), "--packet", str(packet_path), "--source-pin", source_pin, "--digest", digest, "--mapping", str(mapping_path)],
            env,
            *factors.receiver_tuple(),
            b"IMPORT",
            import_prompt,
        )
        require(result.code != 0 and result.stdout.strip() == b"", "replay_refusal")
        assert_hidden(result, factors, import_prompt, b"IMPORT", (invitation_bytes, packet_bytes))
        assert_state(state(fixture, setup, factors, env), state_before)
        recorder.stage("replay_refused_no_duplicate")

        privacy_scan(root, factors, recorder.log_path)
        recorder.stage("privacy_scan")
        recorder.value("two_real_physical_devices", "open")
        recorder.value("scope", "automated_pty")
        print("PASS", flush=True)
        return 0
    except Refusal as error:
        recorder.fail(error.code)
        print("FAIL", flush=True)
        return 1
    except Exception:
        recorder.fail("unexpected")
        print("FAIL", flush=True)
        if args.debug:
            traceback.print_exc()
        return 1
    finally:
        factors.clear()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Owned passkey transfer PTY acceptance")
    parser.add_argument("--artifacts", help="absolute/relative private parent directory for the 0700 run root")
    parser.add_argument("--log", help="fixed redacted stage log path (0600)")
    parser.add_argument("--debug", action="store_true", help="print redacted exception type/line locally; never raw captured streams")
    return accept(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
