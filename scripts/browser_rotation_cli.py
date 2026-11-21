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
        through the real local-factor child, audit exactly that intent, then
        run the real `personal health --hibp true` opt-in twice (declined and
        consented) through the existing loopback CONNECT/TLS proxy. The only
        breached active login is the browser save's R0.
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

if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))
try:
    from e2e.support import (  # noqa: E402
        HIBP_FIXED_HOST,
        HIBP_HTTPS_PORT,
        HIBP_NETWORK_PROMPT,
        HIBP_PREFIX_RE,
        HIBP_RANGE_SEGMENT,
        local_hibp_range_proxy,
    )
except BaseException:
    sys.stderr.write("FAIL: browser-rotation-cli prerequisites\n")
    raise SystemExit(1)

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
    "PASS: browser-rotation-cli hibp_pre_website_post\n"
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
    "audit-r0", "hibp-decline", "audit-hibp-decline", "hibp-consent",
    "audit-hibp-consent", "stale", "audit-stale", "binding-r1", "r1",
    "audit-r1", "complete",
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
FIXTURE_VALUE = re.compile(r"Synthetic-[0-9a-f]{32}")
FIXTURE_REJECTED = re.compile(r"Synthetic-rejected-[0-9a-f]{32}")
FIXTURE_R1 = re.compile(r"Synthetic-updated-[0-9a-f]{32}")
FIXTURE_SECRET = re.compile(r"LL1-[A-Z2-7]{26}")
MAX_FIXTURE = 64 * 1024
HIBP_NETWORK_PROMPT_BYTES = HIBP_NETWORK_PROMPT.encode("utf-8")
HIBP_CANCELLED = b"locklark: HIBP network check cancelled"
HIBP_FIXED_TARGET = HIBP_FIXED_HOST + ":" + str(HIBP_HTTPS_PORT)
HIBP_BREACH_COUNT = 7
HIBP_PADDING = "0" * 35 + ":0\r\n"

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
        self.env = dict(os.environ)
        self.env.pop("LOCKLARK_CLI_ACTIVE", None)
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
        self.proxy_dir = self.state_dir / "hibp-proxy"
        for path in (self.helper, self.binding, self.digest_receipt,
                     self.receipt, self.proxy_dir):
            require_within(path, self.state_dir)

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
        # The browser save precondition ran first on this same vault: the
        # original seed and the successfully updated saved login are the two
        # clean controls. CLI opt-in reuses the generated rejected value as R0
        # so the later HIBP scan has exactly one breached active login.
        self.seed_id = fixed_hex(fixture.get("SeedID"), 32)
        require(self.item_id != self.seed_id)
        self.seed_value = fixture_value(fixture, "Value", FIXTURE_VALUE)
        self.update_value = fixture_value(fixture, "UpdateValue", FIXTURE_R1)
        self.rejected_value = fixture_value(
            fixture, "RejectedValue", FIXTURE_REJECTED)
        require(self.token_r0 == self.rejected_value)
        if self.phase == "post":
            require(self.token_r1 == self.update_value)
        for value in (self.seed_value, self.update_value):
            if value not in self.values:
                self.values.append(value)
        # Actual password / full-hash duplication would make the synthetic
        # counts ambiguous. A mere prefix collision is handled by the response
        # builder below and must not be refused.
        require(len({self.rejected_value, self.seed_value,
                     self.update_value}) == 3)
        hashes = {self._hibp_digest(value) for value in
                  (self.rejected_value, self.seed_value, self.update_value)}
        require(len(hashes) == 3)
        self.hibp_hashes = tuple(sorted(hashes))
        self.hibp_suffixes = tuple(value[5:] for value in self.hibp_hashes)
        self.scan_hibp("\n".join(self.env.values()))
        self.scan_hibp(" ".join(sys.argv))

    @staticmethod
    def _hibp_digest(value):
        digest = hashlib.sha1(value.encode("utf-8")).hexdigest().upper()
        require(HIBP_PREFIX_RE.fullmatch(digest[:5]) is not None)
        return digest

    def scan_hibp(self, raw):
        scan(raw, self.values)
        scan(raw, self.hibp_hashes)
        scan(raw, self.hibp_suffixes)

    def hibp_responses(self):
        """One target line per distinct prefix, clean controls stay zero.

        The target is appended first, so an accidental shared five-hex prefix
        still returns its own suffix while a control's suffix is absent (zero).
        Duplicate passwords or identical full hashes were refused above.
        """
        responses = {}
        for value, count in (
            (self.rejected_value, HIBP_BREACH_COUNT),
            (self.seed_value, 0),
            (self.update_value, 0),
        ):
            digest = self._hibp_digest(value)
            lines = responses.setdefault(digest[:5], [])
            if count:
                lines.append((digest[5:], count))
        return responses

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

    def start(self, argv, capture_stderr, environment=None):
        self.scan_hibp(" ".join(argv))
        environment = environment or self.env
        self.scan_hibp("\n".join(environment.values()))
        return PTYChild(self.cli, argv, environment, self.run_dir,
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
                self.scan_hibp(raw)
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

    # --------------------------------------------------------------- hibp --
    def health_arguments(self):
        return [str(self.cli), "personal", "health", "--file", str(self.vault),
                "--hibp", "true"]

    def health_child(self, proxy):
        environment = dict(self.env)
        environment.update(proxy.env)
        return self.start(self.health_arguments(), False, environment)

    def health_session(self, proxy, expected_reply, expect_success):
        child = self.health_child(proxy)
        try:
            child.start()
            child.expect(MASTER_PROMPT, self.master.encode("utf-8"),
                         self.deadline)
            child.expect(SECRET_PROMPT, self.secret.encode("utf-8"),
                         self.deadline)
            child.expect(HIBP_NETWORK_PROMPT_BYTES, expected_reply,
                         self.deadline)
            status = child.wait(self.deadline)
            stdout, stderr, terminal = child.stdout(), child.stderr(), child.terminal()
            require((status == 0) is expect_success)
            require(len(stdout) <= MAX_EVENTS and
                    len(stderr) <= MAX_CHILD_OUTPUT)
            for raw in (stdout, stderr, terminal):
                self.scan_hibp(raw)
            return status, stdout, stderr, terminal
        finally:
            child.terminate()

    def health_decline(self, proxy):
        _status, stdout, stderr, terminal = self.health_session(
            proxy, b"DECLINE", False)
        require(stdout == b"")
        require(stderr == b"")
        require(HIBP_CANCELLED in terminal)
        # The cancelled consent must stop before unlock or any socket.
        require(not proxy.connections)
        require(not proxy.requests)
        require(not proxy.refused)

    def health_consent(self, proxy, responses):
        _status, stdout, stderr, _terminal = self.health_session(
            proxy, b"NETWORK", True)
        require(stderr == b"")
        try:
            payload = json.loads(stdout.decode("utf-8"))
        except (TypeError, ValueError):
            raise AcceptanceFailure() from None
        self.require_health_payload(payload)
        self.require_health_network(proxy, responses)
        return payload

    def require_health_payload(self, payload):
        require(type(payload) is dict)
        require(set(payload) == {
            "status", "hibp_checked", "checked", "skipped", "findings"})
        require(payload["status"] == "checked-hibp")
        require(payload["hibp_checked"] is True)
        require(type(payload["checked"]) is int)
        require(payload["checked"] == 3)
        require(type(payload["skipped"]) is int)
        require(payload["skipped"] == 0)
        findings = payload["findings"]
        require(type(findings) is list and len(findings) == 3)
        for finding in findings:
            require(type(finding) is dict)
            require(set(finding) == {
                "id", "revision", "flags", "breach_count"})
            require(type(finding["id"]) is str and
                    re.fullmatch(r"[0-9a-f]{32}", finding["id"]) is not None)
            require(type(finding["revision"]) is str and
                    re.fullmatch(r"[0-9a-f]{64}", finding["revision"]) is not None)
            require(type(finding["flags"]) is list and
                    all(type(flag) is str for flag in finding["flags"]))
            require(type(finding["breach_count"]) is int)
        require(len({finding["id"] for finding in findings}) == 3)
        require(len({finding["revision"] for finding in findings}) == 3)
        targets = [finding for finding in findings
                   if finding["id"] == self.item_id]
        require(len(targets) == 1)
        target = targets[0]
        require(target["revision"] == self.r0)
        require(target["breach_count"] == HIBP_BREACH_COUNT)
        require("vulnerable" in target["flags"])
        require(any(finding["id"] == self.seed_id for finding in findings))
        for finding in findings:
            if finding is target:
                continue
            require(finding["breach_count"] == 0)
            require("vulnerable" not in finding["flags"])

    def require_health_network(self, proxy, responses):
        connections = list(proxy.connections)
        requests = list(proxy.requests)
        refused = list(proxy.refused)
        require(not refused)
        require(connections)
        require(all(target == HIBP_FIXED_TARGET for target in connections))
        expected = set(responses)
        require(len(requests) == len(expected))
        seen = set()
        forbidden = {"cookie", "authorization", "proxy-authorization"}
        for record in requests:
            require(type(record) is dict)
            path = record.get("path")
            prefix = record.get("prefix")
            headers = record.get("headers")
            require(type(path) is str and type(prefix) is str and
                    type(headers) is dict)
            require(HIBP_PREFIX_RE.fullmatch(prefix) is not None)
            require(path == HIBP_RANGE_SEGMENT + prefix)
            require(prefix in expected and prefix not in seen)
            seen.add(prefix)
            require(record.get("unknown_prefix") is False)
            require(record.get("refused") is not True)
            normalised = {str(name).lower(): str(value)
                          for name, value in headers.items()}
            require(not (set(normalised) & forbidden))
            require(normalised.get("add-padding") == "true")
            self.scan_hibp(path.encode("utf-8"))
            for name, value in normalised.items():
                self.scan_hibp(name.encode("utf-8"))
                self.scan_hibp(value.encode("utf-8"))
            lines = responses[prefix]
            require(record.get("suffixes") == [
                {"suffix": suffix, "count": count}
                for suffix, count in lines])
            body = record.get("body")
            require(type(body) is str)
            expected_body = "".join(
                suffix + ":" + str(count) + "\r\n"
                for suffix, count in lines) + HIBP_PADDING
            require(body == expected_body)
        require(seen == expected)

    def audit_actions(self, events):
        actions = []
        for event in events:
            require(type(event) is dict)
            require(type(event.get("action")) is str and
                    type(event.get("result")) is str)
            if event["action"] == "audit.list":
                continue
            actions.append((event["action"], event["result"]))
        return actions

    def health_pre_website_post(self):
        self.stage = "hibp-decline"
        responses = self.hibp_responses()
        proxy = None
        try:
            proxy = local_hibp_range_proxy(
                None, responses, work_parent=self.proxy_dir)
            before = self.audit()
            self.health_decline(proxy)
            self.stage = "audit-hibp-decline"
            baseline = self.audit_actions(self.audit())
            require(baseline == self.audit_actions(before))
            self.stage = "hibp-consent"
            self.health_consent(proxy, responses)
            self.stage = "audit-hibp-consent"
            delta = self.audit_actions(self.audit())
            require(delta[:len(baseline)] == baseline)
            require(delta[len(baseline):] == [
                ("desktop.unlock", "succeeded"),
                ("vault.health.watchtower", "succeeded"),
                ("vault.health.hibp", "intent"),
                ("vault.health.hibp", "succeeded"),
            ])
        finally:
            try:
                if proxy is not None:
                    proxy.close()
            finally:
                self.cleanup_proxy_material()

    def cleanup_proxy_material(self):
        for name in ("range.pem", "range.key"):
            path = self.proxy_dir / name
            if path.exists() or path.is_symlink():
                require_within(path, self.state_dir)
                require(not path.is_symlink() and path.is_file())
                path.unlink()
        trust = self.proxy_dir / "trust"
        if trust.exists() or trust.is_symlink():
            require_within(trust, self.state_dir)
            require(trust.is_dir() and not trust.is_symlink())
            for entry in trust.iterdir():
                require(not entry.is_symlink() and entry.is_file())
                entry.unlink()
            trust.rmdir()
        if self.proxy_dir.exists() or self.proxy_dir.is_symlink():
            require_within(self.proxy_dir, self.state_dir)
            require(self.proxy_dir.is_dir() and not self.proxy_dir.is_symlink())
            self.proxy_dir.rmdir()

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
        # Still before the caller's website password-change POST. The real
        # HIBP opt-in is driven twice: a cancelled consent, then one consented
        # range check over exactly the three active logins.
        self.health_pre_website_post()
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
        try:
            self.cleanup_proxy_material()
        except BaseException:
            pass
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
