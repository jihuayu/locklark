"""Exercise the real create-preparation CLI on owned PTYs; emit finite verdicts only."""

import errno
import hashlib
import json
import os
import pathlib
import pty
import re
import select
import signal
import subprocess
import sys
import time


MASTER = "主密码: ".encode()
MASTER_AGAIN = "再次输入主密码: ".encode()
SECRET = b"Secret Key: "
ISSUED_KEY = re.compile(rb"LL1-[A-Z2-7]{26}")
ISSUED_KIT = re.compile(rb"LLR2-[A-Z2-7]{52}-[A-Z2-7]{52}")
BACKUP_REQUIRED = b'"status":"BACKUP_REQUIRED"'
LOCAL_BASELINE = b'"status":"LOCAL_BASELINE"'


def verdict(stage):
    print(json.dumps({"stage": stage}, separators=(",", ":")), flush=True)


def run_pty(product, args, steps):
    pid, master = pty.fork()
    if pid == 0:
        os.execv(product, [product] + args)
    transcript = bytearray()
    cursor = 0
    values = {}
    deadline = time.monotonic() + 25
    finished = False
    try:
        for pattern, reply in steps:
            matcher = re.compile(pattern)
            while True:
                found = matcher.search(transcript, cursor)
                if found is not None:
                    cursor = found.end()
                    answer = reply(found, values) if callable(reply) else reply
                    os.write(master, answer.encode() + b"\r")
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("prompt timeout")
                ready, _, _ = select.select([master], [], [], 0.2)
                if ready:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError as exc:
                        if exc.errno != errno.EIO:
                            raise
                        chunk = b""
                    if not chunk:
                        raise RuntimeError("early child exit")
                    transcript.extend(chunk)
                    if len(transcript) > 128 * 1024:
                        raise RuntimeError("transcript limit")
        while True:
            if time.monotonic() >= deadline:
                raise RuntimeError("exit timeout")
            ready, _, _ = select.select([master], [], [], 0.2)
            if not ready:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                chunk = b""
            if not chunk:
                break
            transcript.extend(chunk)
            if len(transcript) > 128 * 1024:
                raise RuntimeError("transcript limit")
        _, status = os.waitpid(pid, 0)
        finished = True
        return os.waitstatus_to_exitcode(status), bytes(transcript), values
    finally:
        os.close(master)
        if not finished:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def capture_key(match, values):
    values["key"] = match.group(0).decode("ascii")
    return values["key"]


def capture_kit(match, values):
    values["kit"] = match.group(0).decode("ascii")
    return values["kit"]


def check(product, root, mode):
    root = pathlib.Path(root)
    if not os.path.isabs(product) or not root.is_absolute() or root.stat().st_mode & 0o077:
        return "SETUP"
    for part in ("config", "journal", "archive"):
        (root / part).mkdir(mode=0o700)
    personal = str(root / "personal.ll")
    config = str(root / "config" / "create.json")
    journal = str(root / "journal" / "genesis.journal")
    archive = str(root / "archive" / "published.llb")
    backend = str(root / "backend")
    password = "test-only-full-factor"

    code, output, values = run_pty(product, ["personal", "init", "--file", personal], [
        (MASTER, password), (MASTER_AGAIN, password), (ISSUED_KEY, capture_key)])
    if code != 0 or b'"status":"created"' not in output:
        return "PERSONAL_INIT"
    key = values["key"]
    args = ["vault-file", "create", "--config", config, "--personal-file", personal,
            "--backend-root", backend, "--name", "owned-g", "--journal", journal,
            "--archive", archive]
    steps = [(MASTER, password), (SECRET, key)]
    code, output, _ = run_pty(product, args, steps)
    if code != 0 or BACKUP_REQUIRED not in output or password.encode() in output or key.encode() in output:
        return "FIRST_CREATE"
    manifest_path = pathlib.Path(config)
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    vault_id = manifest.get("vault_id")
    if (manifest_path.stat().st_mode & 0o777 != 0o600 or
            not isinstance(vault_id, str) or re.fullmatch(r"[0-9a-f]{32}", vault_id) is None or
            manifest.get("kind") != "vault_file_create" or
            password.encode() in manifest_bytes or key.encode() in manifest_bytes or
            pathlib.Path(journal).exists() or pathlib.Path(backend).exists() or
            pathlib.Path(archive).exists()):
        return "PRIVATE_MANIFEST"
    inode = manifest_path.stat().st_ino
    code, output, _ = run_pty(product, ["vault-file", "create", "--config", config], steps)
    if (code != 0 or BACKUP_REQUIRED not in output or
            json.loads(manifest_path.read_bytes()).get("vault_id") != vault_id or
            manifest_path.stat().st_ino != inode):
        return "EXACT_RETRY"
    code, output, _ = run_pty(product, ["vault-file", "create", "--config", config],
                              [(MASTER, "wrong-password"), (SECRET, key)])
    if (code == 0 or b"VERIFY_REJECTED" not in output or
            manifest_path.read_bytes() != manifest_bytes or
            pathlib.Path(journal).exists() or pathlib.Path(backend).exists() or
            pathlib.Path(archive).exists()):
        return "BAD_FACTOR"

    foreign = root / "config" / "legacy.json"
    foreign.write_text(json.dumps({"version": 1, "backend_root": backend, "name": "owned-g",
        "journal": journal, "personal_file": personal,
        "checkpoint": {"vault_id": vault_id, "owner_root_key_id": vault_id,
                       "owner_root_public_key": "00" * 32, "policy_seq": 0,
                       "policy_digest": "00" * 32}}))
    foreign.chmod(0o600)
    before = foreign.read_bytes()
    result = subprocess.run([product, "vault-file", "create", "--config", str(foreign)],
                            capture_output=True, timeout=10)
    if result.returncode == 0 or b"LOCAL_REVIEW" not in result.stderr or foreign.read_bytes() != before:
        return "LEGACY_CONFIG"
    unsafe = root / "unsafe"
    unsafe.mkdir(mode=0o700)
    unsafe.chmod(0o755)
    unsafe_config = unsafe / "create.json"
    unsafe_args = args.copy()
    unsafe_args[unsafe_args.index("--config") + 1] = str(unsafe_config)
    result = subprocess.run([product] + unsafe_args, capture_output=True, timeout=10)
    if result.returncode == 0 or unsafe_config.exists():
        return "UNSAFE_PARENT"
    if pathlib.Path(journal).exists() or pathlib.Path(backend).exists() or pathlib.Path(archive).exists():
        return "UNEXPECTED_PUBLICATION"
    if mode == "prepare":
        return "PASS"
    if mode != "publish":
        return "SETUP"

    code, output, values = run_pty(product, ["personal", "backup", "--file", personal,
                                              "--out", archive],
                                   [(MASTER, password), (SECRET, key), (ISSUED_KIT, capture_kit)])
    if code != 0 or b'"status":"backed-up"' not in output or not pathlib.Path(archive).is_file():
        return "BACKUP_PUBLISH"
    kit = values["kit"]
    code, output, _ = run_pty(product, ["vault-file", "create", "--config", config],
                              [(MASTER, password), (SECRET, key), ("备份恢复码: ".encode(), kit)])
    if (code != 0 or LOCAL_BASELINE not in output or b'"remote_freshness":"UNVERIFIED"' not in output or
            password.encode() in output or key.encode() in output or kit.encode() in output or
            not pathlib.Path(journal).is_file() or not pathlib.Path(backend).is_dir()):
        return "GENESIS_PUBLISH"
    companion = pathlib.Path(config + ".baseline")
    if not companion.is_file() or companion.stat().st_mode & 0o777 != 0o600:
        return "COMPANION"
    companion_bytes = companion.read_bytes()
    if key.encode() in companion_bytes or kit.encode() in companion_bytes or password.encode() in companion_bytes:
        return "COMPANION_SECRET"
    code, output, _ = run_pty(product, ["vault-file", "create", "--config", config],
                              [(MASTER, password), (SECRET, key), ("备份恢复码: ".encode(), kit)])
    if code != 0 or LOCAL_BASELINE not in output or companion.read_bytes() != companion_bytes:
        return "ACK_RESTART"
    result = subprocess.run([product, "vault-file", "status", "--config", config],
                            capture_output=True, timeout=10)
    if result.returncode != 0 or b'"status":"CLEAN"' not in result.stdout or b'"remote_freshness":"UNVERIFIED"' not in result.stdout:
        return "STATUS_ADAPTER"
    code, output, _ = run_pty(product, ["vault-file", "open-baseline", "--config", config],
                              [(MASTER, password), (SECRET, key)])
    if code != 0 or LOCAL_BASELINE not in output or b'"remote_freshness":"UNVERIFIED"' not in output:
        return "OPEN_BASELINE_ADAPTER"
    code, output, _ = run_pty(product, ["vault-file", "create", "--config", config],
                              [(MASTER, password), (SECRET, key), ("备份恢复码: ".encode(), "wrong-kit")])
    if code == 0 or b"VERIFY_REJECTED" not in output or companion.read_bytes() != companion_bytes:
        return "WRONG_KIT"
    object_path = pathlib.Path(backend) / "vaultfile-backend" / "v1" / "data" / hashlib.sha256(b"owned-g").hexdigest()
    if not object_path.is_file():
        return "BACKEND_OBJECT"
    original_object = object_path.read_bytes()
    second_config = str(root / "config" / "second.json")
    second_journal = str(root / "journal" / "second.journal")
    second_archive = str(root / "archive" / "second.llb")
    second_args = ["vault-file", "create", "--config", second_config, "--personal-file", personal,
                   "--backend-root", backend, "--name", "owned-g", "--journal", second_journal,
                   "--archive", second_archive]
    code, output, _ = run_pty(product, second_args, steps)
    if code != 0 or BACKUP_REQUIRED not in output:
        return "FOREIGN_PREPARE"
    code, output, values = run_pty(product, ["personal", "backup", "--file", personal,
                                              "--out", second_archive],
                                   [(MASTER, password), (SECRET, key), (ISSUED_KIT, capture_kit)])
    if code != 0 or b'"status":"backed-up"' not in output:
        return "FOREIGN_BACKUP"
    code, output, _ = run_pty(product, ["vault-file", "create", "--config", second_config],
                              [(MASTER, password), (SECRET, key), ("备份恢复码: ".encode(), values["kit"])])
    if (code == 0 or b"LOCAL_REVIEW" not in output or
            not pathlib.Path(second_journal).is_file() or
            object_path.read_bytes() != original_object):
        return "FOREIGN_COLLISION"
    return "PASS"


def main():
    try:
        request = json.load(sys.stdin)
        verdict(check(request["product"], request["root"], request.get("mode", "prepare")))
    except (KeyError, OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
        verdict("HARNESS_ERROR")


if __name__ == "__main__":
    main()
