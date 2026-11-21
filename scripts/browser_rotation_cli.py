#!/usr/bin/env python3
"""Linux browser-to-CLI revision chain for the owned rotation fixture.

This is one external, disposable evidence helper for the existing Linux
Chromium rotation journey only. It never starts a desktop broker, native
messaging path, signed macOS flow, reusable lease, or any product test hook.
It drives the real built `locklark cli init` and `locklark cli run` through the
same `PTYChild` controlling-terminal mechanism as the existing CLI broker
acceptance, with hidden factors and the deliberate RUN consent supplied on
stdin JSON only.

The caller invokes this script twice with one owner-only ephemeral state
directory:

  pre   before the actual website password-change POST: pin R0, prove it once
        through the real local-factor child, and audit exactly that intent.
  post  after the approved browser update to R1: keep the same R0 binding
        byte-identical through one stale refusal, audit zero new intent, then
        explicitly rebind the same item at R1, prove the R1 child, and audit
        exactly two intents total.

Only fixed PASS lines are printed. Raw CLI output, paths, factor values,
exceptions and dynamic diagnostics are never printed or persisted in a public
artifact. Every file this helper creates lives under the caller's ephemeral
state directory and is removed on completion or failure.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from cli_broker_acceptance import (  # noqa: E402
    CHILD_EXIT,
    CHILD_STDERR,
    CHILD_STDOUT,
    CHILD_TIMEOUT,
    PTYChild,
    SECRET_PATTERN,
    TOKEN_ENV,
    TOOL,
    AcceptanceFailure,
    cli_init_arguments,
    expected_receipt,
    file_mode,
    owner_only,
    require,
    require_within,
    scan,
    validate_binary,
    validate_child_output,
    write_private,
)

PROFILE = "token"
SLOT = "token"
FIELD = "password"
MAX_INPUT = 64 * 1024
MAX_EVENTS = 4 * 1024 * 1024
MAX_CHILD_OUTPUT = 64 * 1024
# The owning Node caller allows 150s for one phase. This shorter internal
# deadline lets the helper stop and reap its own PTY child, then report the
# actual fixed stage, before the caller's spawn timeout can kill it.
PHASE_TIMEOUT = 90
SHA256SUM = pathlib.Path("/usr/bin/sha256sum")

MASTER_PROMPT = "主密码: ".encode("utf-8")
SECRET_PROMPT = "Secret Key: ".encode("utf-8")
RUN_PROMPT = "输入 RUN 确认本次可信命令披露: ".encode("utf-8")
STALE_ERROR = b"locklark: login changed; list again and review before retrying\n"

PRE_STDOUT = (
    "PASS: browser-rotation-cli r0_before_website_post\n"
    "PASS: browser-rotation-cli pre_complete\n"
)
POST_STDOUT = (
    "PASS: browser-rotation-cli stale_exact_refusal_no_intent\n"
    "PASS: browser-rotation-cli r1_rebound_same_item\n"
    "PASS: browser-rotation-cli r1_child_two_intents\n"
    "PASS: browser-rotation-cli post_complete\n"
)

STAGES = frozenset({
    "prerequisites", "vault", "audit-baseline", "binding-r0", "r0",
    "audit-r0", "stale", "audit-stale", "binding-r1", "r1", "audit-r1",
    "complete",
})

PRE_KEYS = frozenset({
    "version", "phase", "cli", "vault", "vaultRoot", "stateDir", "itemID",
    "revisionR0", "tokenR0", "masterPassword", "secretKey", "timeout",
})
POST_KEYS = PRE_KEYS | frozenset({"revisionR1", "tokenR1"})
BINDING_KEYS = frozenset({
    "profile", "vault_path", "program", "program_sha256", "targets",
    "helper_path", "passthrough_env", "timeout_seconds", "token_env_name",
})
INIT_KEYS = frozenset({
    "status", "tool", "profile", "program", "program_sha256", "binding_file",
})
SECRET_RECEIPT = re.compile(r"^[0-9a-f]{64}$")
FIXTURE_PASSWORD = re.compile(r"Acceptance-[0-9a-f]{16}")
FIXTURE_R0 = re.compile(r"Synthetic-[0-9a-f]{32}")
FIXTURE_R1 = re.compile(r"Synthetic-updated-[0-9a-f]{32}")
FIXTURE_SECRET = re.compile(r"LL1-[A-Z2-7]{26}")
MAX_FIXTURE = 64 * 1024

# Same fixed child contract as the existing CLI broker acceptance, but the
# Linux digest utility is pinned by absolute path. The helper is generated
# under the ephemeral state directory and is pinned by the real `cli init`.
HELPER_SCRIPT = (
    "#!/bin/sh\n"
    "set -eu\n"
    "umask 077\n"
    ': "$' + TOKEN_ENV + '"\n'
    'digest=$(printf \'%s\' "$' + TOKEN_ENV + '" | /usr/bin/sha256sum)\n'
    "digest=${digest%% *}\n"
    'printf \'%s\\n\' "$digest" > "$1"\n'
    "printf '" + CHILD_STDOUT.decode("ascii").rstrip("\n") + "\\n'\n"
    "printf '" + CHILD_STDERR.decode("ascii").rstrip("\n") + "\\n' >&2\n"
    "exit " + str(CHILD_EXIT) + "\n"
)


class RotationCLI:
    """The owned paths, synthetic values and one bounded pre/post execution."""

    def __init__(self, payload):
        self.phase = payload.get("phase")
        require(self.phase in ("pre", "post"))
        expected = PRE_KEYS if self.phase == "pre" else POST_KEYS
        require(set(payload) == set(expected))
        require(type(payload.get("version")) is int and payload["version"] == 1)
        self.item_id = fixed_hex(payload.get("itemID"), 32)
        self.r0 = fixed_hex(payload.get("revisionR0"), 64)
        self.r1 = (fixed_hex(payload.get("revisionR1"), 64)
                   if self.phase == "post" else None)
        require(self.r1 is None or self.r1 != self.r0)
        self.token_r0 = bounded_text(payload.get("tokenR0"), 4096)
        self.token_r1 = (bounded_text(payload.get("tokenR1"), 4096)
                         if self.phase == "post" else None)
        self.master = bounded_text(payload.get("masterPassword"), 1024)
        self.secret = bounded_text(payload.get("secretKey"), 1024)
        require(SECRET_PATTERN.fullmatch(self.secret.encode("utf-8")) is not None)
        timeout = payload.get("timeout")
        require(type(timeout) is int and 30 <= timeout <= PHASE_TIMEOUT)
        self.deadline = time.monotonic() + timeout
        self.values = [self.master, self.secret, self.token_r0]
        if self.token_r1 is not None:
            self.values.append(self.token_r1)

        self.cli = validate_cli(payload.get("cli"))
        self.vault_root = canonical_private_dir(payload.get("vaultRoot"),
                                                "vault")
        self.state_dir = canonical_private_dir(payload.get("stateDir"),
                                               "rotation-cli-")
        require(self.state_dir.parent == self.vault_root.parent)
        self.vault = canonical_private_file(payload.get("vault"),
                                            "synthetic.ll")
        require(self.vault.parent == self.vault_root)
        require_within(self.vault, self.vault_root)
        fixture = canonical_private_file(
            str(self.vault_root / "fixture.json"), "fixture.json")
        self.require_fixture_scope(fixture)

        self.bin_dir = private_dir(self.state_dir / "bin")
        self.run_dir = private_dir(self.state_dir / "run")
        self.data_dir = private_dir(self.state_dir / "state")
        self.receipt_dir = private_dir(self.state_dir / "receipt")
        self.helper = self.bin_dir / "child-helper"
        self.binding = self.data_dir / "binding.json"
        self.digest_receipt = self.data_dir / "binding.sha256"
        self.receipt = self.receipt_dir / "receipt.txt"
        for path in (self.helper, self.binding, self.digest_receipt,
                     self.receipt):
            require_within(path, self.state_dir)
        self.env = dict(os.environ)
        self.env.pop("LOCKLARK_CLI_ACTIVE", None)
        # Factors never enter the environment or the argv of any process this
        # helper starts. The product alone injects the one pinned slot token
        # into the child it prepares.
        scan("\n".join(self.env.values()), self.values)
        scan(" ".join(sys.argv), self.values)

    def require_fixture_scope(self, path):
        require(owner_only(path))
        raw = path.read_bytes()
        require(0 < len(raw) <= MAX_FIXTURE)
        try:
            fixture = json.loads(raw.decode("utf-8"),
                                 object_pairs_hook=_unique_object)
        except AcceptanceFailure:
            raise
        except BaseException:
            raise AcceptanceFailure() from None
        require(type(fixture) is dict)
        # The payload path, both synthetic factors and the expected R0/R1
        # tokens must be the exact values emitted by the known Go browser
        # fixture before the real token CLI is touched. The structural checks
        # also reject a hand-made or real vault path.
        require(fixture.get("Path") == str(self.vault))
        require(fixture_value(fixture, "Password", FIXTURE_PASSWORD)
                == self.master)
        require(fixture_value(fixture, "Secret", FIXTURE_SECRET)
                == self.secret)
        require(fixture_value(fixture, "Value", FIXTURE_R0)
                == self.token_r0)
        if self.phase == "post":
            require(fixture_value(fixture, "UpdateValue", FIXTURE_R1)
                    == self.token_r1)

    # ------------------------------------------------------------- files --
    def install_helper(self):
        require(SHA256SUM.is_file() and os.access(SHA256SUM, os.X_OK))
        require(not self.helper.exists())
        write_private(self.helper, HELPER_SCRIPT.encode(), 0o700)
        require(owner_only(self.helper, executable=True))
        require(self.helper.read_bytes() == HELPER_SCRIPT.encode())

    def helper_digest(self):
        return hashlib.sha256(self.helper.read_bytes()).hexdigest()

    def binding_digest(self):
        require(owner_only(self.binding))
        return hashlib.sha256(self.binding.read_bytes()).hexdigest()

    def write_digest_receipt(self):
        digest = self.binding_digest()
        write_private(self.digest_receipt, digest.encode("ascii") + b"\n")
        require(owner_only(self.digest_receipt))

    def read_digest_receipt(self):
        require(owner_only(self.digest_receipt))
        raw = self.digest_receipt.read_bytes()
        require(len(raw) == 65 and raw.endswith(b"\n"))
        text = raw[:-1].decode("ascii")
        require(SECRET_RECEIPT.fullmatch(text) is not None)
        return text

    def init_binding(self, revision):
        argv = cli_init_arguments(self.cli, self.vault, self.binding,
                                  self.helper, self.item_id, revision)
        scan(" ".join(argv), self.values)
        try:
            result = subprocess.run(
                argv, cwd=self.run_dir, env=self.env,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise AcceptanceFailure() from None
        require(result.returncode == 0)
        require(len(result.stdout) <= MAX_CHILD_OUTPUT and
                len(result.stderr) <= MAX_CHILD_OUTPUT)
        require(result.stderr == b"")
        scan(result.stdout, self.values)
        scan(result.stderr, self.values)
        try:
            payload = json.loads(result.stdout)
        except (TypeError, ValueError):
            raise AcceptanceFailure() from None
        require(type(payload) is dict and set(payload) == set(INIT_KEYS))
        require(payload["status"] == "bound")
        require(payload["tool"] == TOOL)
        require(payload["profile"] == PROFILE)
        require(payload["program"] == str(self.helper))
        require(payload["program_sha256"] == self.helper_digest())
        require(payload["binding_file"] == str(self.binding))

    def read_binding(self, revision):
        require(owner_only(self.binding))
        raw = self.binding.read_bytes()
        require(len(raw) <= 64 * 1024)
        try:
            store = json.loads(raw)
        except (TypeError, ValueError):
            raise AcceptanceFailure() from None
        require(type(store) is dict and set(store) == {"version", "bindings"})
        require(type(store["version"]) is int and store["version"] == 1)
        bindings = store["bindings"]
        require(type(bindings) is dict and set(bindings) == {TOOL})
        binding = bindings[TOOL]
        require(type(binding) is dict)
        # helper-path and passthrough lists are optional; unknown keys are not.
        require(set(binding) <= set(BINDING_KEYS))
        require(binding.get("profile") == PROFILE)
        require(binding.get("vault_path") == str(self.vault))
        require(binding.get("program") == str(self.helper))
        require(binding.get("program_sha256") == self.helper_digest())
        require(binding.get("token_env_name") == TOKEN_ENV)
        require(binding.get("timeout_seconds") == CHILD_TIMEOUT)
        targets = binding.get("targets")
        require(type(targets) is list and len(targets) == 1)
        target = targets[0]
        require(type(target) is dict and
                set(target) == {"slot", "id", "revision", "field"})
        require(target["slot"] == SLOT)
        require(target["id"] == self.item_id)
        require(target["revision"] == revision)
        require(target["field"] == FIELD)

    # ------------------------------------------------------------ process --
    def run_arguments(self):
        # The real token CLI execs the pinned helper declared by the binding
        # itself and appends only the arguments after `--` to that child. The
        # helper writes its digest to $1, so exactly its own receipt path is
        # passed here; passing the helper too would truncate the helper.
        return [
            str(self.cli), "cli", "run", TOOL,
            "--binding", str(self.binding),
            "--cwd", str(self.run_dir),
            "--timeout", str(CHILD_TIMEOUT),
            "--", str(self.receipt),
        ]

    def start(self, argv, capture_stderr):
        scan(" ".join(argv), self.values)
        return PTYChild(self.cli, argv, self.env, self.run_dir,
                        capture_stderr=capture_stderr)

    def audit(self):
        argv = [str(self.cli), "personal", "audit",
                "--file", str(self.vault)]
        # Personal audit writes its hidden prompts to stderr through the
        # controlling PTY; only stdout (the audit events) is captured privately.
        child = self.start(argv, False)
        try:
            child.start()
            child.expect(MASTER_PROMPT, self.master.encode("utf-8"),
                         self.deadline)
            child.expect(SECRET_PROMPT, self.secret.encode("utf-8"),
                         self.deadline)
            status = child.wait(self.deadline)
            stdout, stderr, terminal = child.stdout(), child.stderr(), child.terminal()
            require(status == 0)
            require(len(stdout) <= MAX_EVENTS and
                    len(stderr) <= MAX_CHILD_OUTPUT)
            require(stderr == b"")
            for raw in (stdout, stderr, terminal):
                scan(raw, self.values)
            try:
                events = json.loads(stdout)
            except (TypeError, ValueError):
                raise AcceptanceFailure() from None
            require(type(events) is list and len(events) <= 100000)
            return events
        finally:
            child.terminate()

    def run_pinned(self, token):
        require(not self.receipt.exists())
        argv = self.run_arguments()
        child = self.start(argv, True)
        try:
            child.start()
            child.expect(MASTER_PROMPT, self.master.encode("utf-8"),
                         self.deadline)
            child.expect(SECRET_PROMPT, self.secret.encode("utf-8"),
                         self.deadline)
            child.expect(RUN_PROMPT, b"RUN", self.deadline)
            status = child.wait(self.deadline)
            stdout, stderr, terminal = child.stdout(), child.stderr(), child.terminal()
            require(len(stdout) <= MAX_CHILD_OUTPUT and
                    len(stderr) <= MAX_CHILD_OUTPUT)
            for raw in (stdout, stderr, terminal):
                scan(raw, self.values)
            # The existing local-factor mechanism is exact: fixed child
            # streams, fixed nonzero exit, and one owner-only SHA-256 receipt.
            prefix = validate_child_output(
                stdout, stderr, status, self.receipt, expected_receipt(token))
            require(prefix == b"")
            require(stdout == CHILD_STDOUT)
            require(stderr == CHILD_STDERR)
            require(self.receipt.read_bytes() == expected_receipt(token))
        finally:
            child.terminate()

    def stale(self):
        require(not self.receipt.exists())
        argv = self.run_arguments()
        child = self.start(argv, True)
        try:
            child.start()
            child.expect(MASTER_PROMPT, self.master.encode("utf-8"),
                         self.deadline)
            child.expect(SECRET_PROMPT, self.secret.encode("utf-8"),
                         self.deadline)
            child.expect(RUN_PROMPT, b"RUN", self.deadline)
            status = child.wait(self.deadline)
            stdout, stderr, terminal = child.stdout(), child.stderr(), child.terminal()
            require(status == 1)
            require(len(stdout) <= MAX_CHILD_OUTPUT and
                    len(stderr) <= MAX_CHILD_OUTPUT)
            for raw in (stdout, stderr, terminal):
                scan(raw, self.values)
            # Exact stale-specific CLI refusal: no child stream marker, no
            # disclosure and no receipt side effect.
            require(stdout == b"")
            require(stderr == STALE_ERROR)
            require(not self.receipt.exists())
        finally:
            child.terminate()

    # -------------------------------------------------------------- audit --
    def intents(self, events):
        return [
            event for event in events
            if type(event) is dict
            and event.get("action") == "item.run.bundle"
            and event.get("result") == "intent"
        ]

    def require_intents(self, events, revisions):
        intents = self.intents(events)
        require(len(intents) == len(revisions))
        for intent, revision in zip(intents, revisions):
            require(intent.get("item_id") == self.item_id)
            require(intent.get("base_revision") == revision)

    # --------------------------------------------------------------- runs --
    def pre(self):
        require(self.phase == "pre")
        self.stage = "vault"
        self.install_helper()
        expected = self.binding_digest() if self.binding.exists() else None
        require(expected is None)
        # Baseline first: the fixture has no CLI run intent yet.
        self.stage = "audit-baseline"
        self.require_intents(self.audit(), [])
        self.stage = "binding-r0"
        require(not self.binding.exists())
        self.init_binding(self.r0)
        self.write_digest_receipt()
        self.read_binding(self.r0)
        self.stage = "r0"
        self.run_pinned(self.token_r0)
        self.stage = "audit-r0"
        self.require_intents(self.audit(), [self.r0])
        require(self.read_digest_receipt() == self.binding_digest())
        self.stage = "complete"

    def post(self):
        require(self.phase == "post")
        self.stage = "vault"
        require(self.helper.exists())
        require(owner_only(self.helper, executable=True))
        require(self.helper.read_bytes() == HELPER_SCRIPT.encode())
        # R0 was created before the browser's actual POST and is still the
        # same binding right now.
        expected = self.read_digest_receipt()
        require(self.binding_digest() == expected)
        self.read_binding(self.r0)
        # Delete only the already-validated pre receipt so a stale attempt has
        # an unambiguous no-child-side-effect check.
        if self.receipt.exists():
            require(owner_only(self.receipt))
            self.receipt.unlink()
        self.stage = "stale"
        self.stale()
        require(self.binding_digest() == expected)
        self.stage = "audit-stale"
        self.require_intents(self.audit(), [self.r0])
        # Explicit rebind/import of the same item at the new R1 revision.
        self.stage = "binding-r1"
        require(self.binding_digest() == expected)
        self.init_binding(self.r1)
        rebound = self.binding_digest()
        require(rebound != expected)
        self.read_binding(self.r1)
        self.stage = "r1"
        self.run_pinned(self.token_r1)
        self.stage = "audit-r1"
        self.require_intents(self.audit(), [self.r0, self.r1])
        self.stage = "complete"

    # ------------------------------------------------------------ cleanup --
    def cleanup(self):
        for path in (self.receipt, self.digest_receipt, self.binding,
                     self.helper):
            if path.exists() or path.is_symlink():
                require_within(path, self.state_dir)
                require(not path.is_symlink() and path.is_file())
                path.unlink()
        for directory in (self.bin_dir, self.run_dir, self.data_dir,
                          self.receipt_dir):
            require(directory.is_dir() and not directory.is_symlink())
            try:
                directory.rmdir()
            except OSError:
                pass
        try:
            self.state_dir.rmdir()
        except OSError:
            # The browser harness owns the final recursive removal; this helper
            # only removes what it created and never deletes foreign entries.
            pass


def bounded_text(value, limit):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= limit)
    require("\n" not in value and "\r" not in value and "\0" not in value)
    return value


def fixture_value(fixture, key, pattern):
    value = fixture.get(key)
    require(type(value) is str and pattern.fullmatch(value) is not None)
    return value


def fixed_hex(value, length):
    require(type(value) is str and len(value) == length)
    require(re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None)
    return value


def validate_cli(value):
    require(type(value) is str and os.path.isabs(value))
    raw = pathlib.Path(value)
    require(not raw.is_symlink() and raw.is_file() and os.access(raw, os.X_OK))
    path = validate_binary(value, "cli")
    require(str(path) == str(raw))
    require(path.stat().st_uid == os.geteuid())
    require(file_mode(path) & 0o022 == 0)
    return path


def canonical_private_dir(value, name):
    require(type(value) is str and os.path.isabs(value))
    path = pathlib.Path(value)
    require(str(path) == os.path.realpath(value))
    require(path.is_dir() and not path.is_symlink())
    require(path.stat().st_uid == os.geteuid())
    require(file_mode(path) & 0o077 == 0)
    if name == "rotation-cli-":
        require(path.name.startswith(name))
    else:
        require(path.name == name)
    return path


def canonical_private_file(value, name):
    require(type(value) is str and os.path.isabs(value))
    path = pathlib.Path(value)
    require(str(path) == os.path.realpath(value))
    require(path.is_file() and not path.is_symlink())
    require(path.name == name)
    require(path.stat().st_uid == os.geteuid())
    require(file_mode(path) & 0o077 == 0)
    return path


def private_dir(path):
    require(pathlib.Path(os.path.realpath(path)) == path)
    if path.exists():
        require(path.is_dir() and not path.is_symlink())
    else:
        path.mkdir(mode=0o700)
    require(path.stat().st_uid == os.geteuid())
    require(file_mode(path) & 0o077 == 0)
    return path


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def read_payload():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    require(0 < len(raw) <= MAX_INPUT)
    try:
        payload = json.loads(raw.decode("utf-8"),
                             object_pairs_hook=_unique_object)
    except AcceptanceFailure:
        raise
    except BaseException:
        raise AcceptanceFailure() from None
    require(type(payload) is dict)
    return payload


def emit(text):
    sys.stdout.write(text)
    sys.stdout.flush()


def main():
    stage = "prerequisites"
    chain = None
    success = False
    try:
        require(sys.platform.startswith("linux"))
        require(len(sys.argv) == 1)
        os.umask(0o077)
        payload = read_payload()
        chain = RotationCLI(payload)
        stage = chain.stage = "vault"
        if chain.phase == "pre":
            try:
                chain.pre()
                success = True
            finally:
                if not success:
                    try:
                        chain.cleanup()
                    except BaseException:
                        pass
            emit(PRE_STDOUT)
        else:
            try:
                chain.post()
                chain.cleanup()
                success = True
            finally:
                if not success:
                    try:
                        chain.cleanup()
                    except BaseException:
                        pass
            emit(POST_STDOUT)
        return 0
    except BaseException:
        current = chain.stage if chain is not None else stage
        if current not in STAGES:
            current = "prerequisites"
        sys.stderr.write("FAIL: browser-rotation-cli " + current + "\n")
        sys.stderr.flush()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
