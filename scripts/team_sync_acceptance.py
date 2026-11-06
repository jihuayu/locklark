#!/usr/bin/env python3
"""External, process-separated TLS acceptance for the real team sync library.

Run from the repository with Python 3 and Go 1.27.3 available. All synthetic
keys, canaries and captures are retained under a private /tmp directory; stdout
contains classifications only. --fixture-bin supports an independently fixed
build. This helper is deliberately outside the product package and CI setup.
"""

import argparse
import base64
import concurrent.futures
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time


REPO = pathlib.Path(__file__).resolve().parents[1]


class AcceptanceFailure(Exception):
    pass


class Acceptance:
    def __init__(self, args):
        self.args = args
        parent = pathlib.Path(args.artifacts).resolve()
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="team-sync-", dir=parent))
        self.fixture = self.root / "fixture"
        self.fixture.mkdir(mode=0o700)
        self.capture = self.root / "captures"
        self.capture.mkdir(mode=0o700)
        self.control = self.root / "fault.json"
        self.write(self.control, {})
        self.server = None
        self.server_out = None
        self.server_err = None
        self.completed = []
        self.counter = 0
        self.lock = threading.Lock()
        self.logs = []
        self.scanned = False
        self.binary = pathlib.Path(args.fixture_bin).resolve() if args.fixture_bin else self.root / "team-sync-fixture"

    @staticmethod
    def write(path, data):
        path.write_text(json.dumps(data, separators=(",", ":")) + "\n")
        path.chmod(0o600)

    def check(self, condition, message):
        if not condition:
            raise AcceptanceFailure(message)

    def run(self, *args, label=None, **kwargs):
        # No secret value is ever passed in argv or environment. stdout/stderr
        # are preserved whole and scanned later, including failure output.
        with self.lock:
            self.counter += 1
            number = self.counter
        label = label or args[0]
        prefix = self.root / f"{number:03d}-{label}"
        result = subprocess.run([str(self.binary), *map(str, args)], cwd=REPO,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=35, **kwargs)
        for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = prefix.with_suffix("." + suffix)
            path.write_bytes(raw)
            path.chmod(0o600)
            self.logs.append(path)
        self.check(result.returncode == 0, f"fixture process failed: {label}")
        try:
            return json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise AcceptanceFailure(f"invalid classification output: {label}") from None

    def mark(self, name):
        self.completed.append(name)
        print("PASS " + name, flush=True)

    def build(self):
        if self.args.fixture_bin:
            self.check(self.binary.is_file(), "fixed fixture executable unavailable")
            return
        environment = os.environ.copy()
        environment["GOTOOLCHAIN"] = "go1.27.3"
        go = self.args.go or shutil.which("go")
        self.check(bool(go), "Go executable unavailable")
        result = subprocess.run([go, "build", "-o", str(self.binary), "./scripts/team_sync_fixture"],
                                cwd=REPO, env=environment, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=180)
        for name, raw in (("build.stdout", result.stdout), ("build.stderr", result.stderr)):
            path = self.root / name
            path.write_bytes(raw)
            path.chmod(0o600)
            self.logs.append(path)
        self.check(result.returncode == 0, "fixture build failed")

    def start(self):
        self.run("init", "--root", self.fixture)
        shutil.copyfile(self.fixture / "team.db", self.root / "saved-initial.db")
        self.run("anchor-init", "--anchor", self.fixture / "server.anchor", "--initial", self.fixture / "genesis.json")
        self.server_out = (self.root / "server.stdout").open("wb")
        self.server_err = (self.root / "server.stderr").open("wb")
        self.logs.extend((self.root / "server.stdout", self.root / "server.stderr"))
        ready = self.root / "ready.json"
        self.server = subprocess.Popen([
            str(self.binary), "serve", "--public", str(self.fixture / "server.json"),
            "--captures", str(self.capture), "--control", str(self.control), "--ready", str(ready)],
            cwd=REPO, stdin=subprocess.PIPE, stdout=self.server_out, stderr=self.server_err)
        self.server.stdin.write((self.fixture / "sequencer.json").read_bytes())
        self.server.stdin.close()
        deadline = time.monotonic() + 15
        while not ready.exists() and self.server.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        self.check(ready.exists() and self.server.poll() is None, "TLS server did not become ready")
        self.endpoint = json.loads(ready.read_text())["URL"]
        self.pins = json.loads((self.fixture / "pins.json").read_text())
        for who in ("owner", "device-0", "device-1", "device-2", "anchor-fail"):
            self.config(who)

    def config(self, name, *, pins=None, url=None, roots=None):
        anchor = self.root / (name + ".anchor")
        if pins:
            pins_path = self.root / (name + ".pins.json")
            self.write(pins_path, pins)
            self.run("anchor-init", "--anchor", anchor, "--pins", pins_path, label="anchor-init")
        else:
            self.run("anchor-init", "--anchor", anchor, "--initial", self.fixture / "genesis.json", label="anchor-init")
        config = {"Pins": pins or self.pins, "URL": url or self.endpoint,
                  "Roots": str(roots or self.fixture / "ca.pem"), "Anchor": str(anchor)}
        path = self.root / (name + ".config.json")
        self.write(path, config)
        return path

    def client(self, who, operation="read", *, candidate=None, config=None,
               status="ok", outcome=None, anchor_fail=False, pretend_owner=False):
        view = self.root / f"view-{who}-{self.counter + 1}.json"
        identity = "owner" if who == "owner" else who
        args = ["client", "--config", config or self.root / (who + ".config.json"),
                "--identity", self.fixture / (identity + ".json"), "--operation", operation,
                "--view-out", view]
        if candidate:
            args.extend(("--candidate", candidate))
        if anchor_fail:
            args.append("--anchor-fail")
        if pretend_owner:
            args.append("--pretend-owner")
        result = self.run(*args, label=operation)
        allowed = {status} if isinstance(status, str) else set(status)
        self.check(result.get("status") in allowed,
                   f"unexpected {who} {operation} classification: {result.get('status')}")
        self.check(result.get("success") == (result.get("status") == "ok"), "success/error classification mismatch")
        if outcome:
            self.check(result.get("outcome") == outcome, "wrong reconciliation outcome")
        if result.get("status") != "ok":
            self.check(not view.exists() and "version" not in result, "failed operation exposed success state")
        return result, view

    def prepare(self, kind, view, variant):
        path = self.root / f"candidate-{kind}-{self.counter + 1}.json"
        self.run("prepare", "--root", self.fixture, "--view", view,
                 "--kind", kind, "--variant", variant, "--out", path)
        return path

    def oracle(self, view, device, variant, decrypt=True):
        result = self.run("oracle", "--root", self.fixture, "--view", view,
                          "--device", device, "--variant", variant,
                          "--decrypt=" + str(decrypt).lower())
        self.check(result.get("decrypted") is decrypt, "independent age oracle mismatch")
        if decrypt:
            self.check(result.get("content_matches") and result.get("kdbx41"), "independent KDBX oracle mismatch")

    def fault(self, mode="", replay=""):
        # Atomic replace avoids letting the real HTTP worker observe a partial
        # control file while two distinct client processes publish concurrently.
        temporary = self.control.with_suffix(".new")
        self.write(temporary, {"Mode": mode, "Replay": str(replay)})
        temporary.replace(self.control)

    def assert_version(self, result, version):
        self.check(result.get("version") == version, "unexpected durable head version")
        if "history_length" in result:
            self.check(result["history_length"] == version, "response did not verify complete history")

    def captures_for(self, operation):
        found = []
        for path in sorted(self.capture.glob("*.meta")):
            meta = json.loads(path.read_text())
            if meta["path"] == "/v1/team-sync/" + operation:
                found.append(path)
        return found

    def exercise(self):
        initial, first = self.client("device-0")
        self.assert_version(initial, 1)
        self.oracle(first, 0, "initial")
        self.client("device-1", status="denied")
        owner_initial, _ = self.client("owner")
        self.assert_version(owner_initial, 1)
        self.client("device-0", pretend_owner=True, status=("invalid", "denied"))
        self.mark("separate_tls_processes_independent_identities_owner_boundary")

        admitted = self.prepare("admit", first, "initial")
        self.client("device-0", "publish", candidate=admitted, status=("denied", "invalid"))
        published, _ = self.client("owner", "publish", candidate=admitted)
        self.assert_version(published, 2)
        second, current = self.client("device-1")
        self.assert_version(second, 2)
        self.oracle(current, 1, "initial")
        reader, reader_view = self.client("device-2")
        self.assert_version(reader, 2)
        self.oracle(reader_view, 2, "initial")
        forged = self.prepare("reader-forged", reader_view, "e")
        self.client("device-2", "publish", candidate=forged, status=("denied", "invalid"))
        unchanged, _ = self.client("owner")
        self.assert_version(unchanged, 2)
        self.mark("owner_admission_two_devices_reader_receives_but_cannot_write")

        update = self.prepare("writer-0", current, "a")
        published, _ = self.client("device-0", "publish", candidate=update)
        self.assert_version(published, 3)
        received, current = self.client("device-1")
        self.assert_version(received, 3)
        self.oracle(current, 1, "a")
        _, reader_view = self.client("device-2")
        self.oracle(reader_view, 2, "a")
        self.client("device-0", "publish", candidate=update, status="conflict")
        self.mark("writer_update_reader_decryption_and_exact_parent_cas")

        old_read_response = self.captures_for("read")[0].with_suffix(".response")
        self.fault("replay", old_read_response)
        self.client("device-0", status=("invalid", "freshness"))
        self.fault("tamper")
        self.client("device-0", status="invalid")
        self.fault()
        wrong_pins = dict(self.pins)
        wrong_pins["Sequencer"] = json.loads((self.fixture / "device-2.json").read_text())["device"]["signing"]
        wrong_config = self.config("wrong-pins", pins=wrong_pins)
        self.client("device-0", config=wrong_config, status=("invalid", "denied", "transport"))
        bad_host = self.config("wrong-host", url=self.endpoint.replace("localhost", "127.0.0.1"))
        self.client("device-0", config=bad_host, status="transport")
        self.client("device-0", config=self.root / "anchor-fail.config.json", anchor_fail=True, status="anchor")
        self.mark("new_nonce_replay_tamper_trust_pins_hostname_and_anchor_failure")

        self.fault("delay")
        began = time.monotonic()
        self.client("device-0", status=("freshness", "transport"))
        elapsed = time.monotonic() - began
        self.fault()
        self.check(14 <= elapsed < 19, "fresh read did not enforce the 15 second observation deadline")
        self.mark("delayed_valid_signed_response_exceeds_fresh_observation_deadline")

        # Restore an authentic older signed database while preserving the
        # sequencer's independently retained durable anchor. Even a newly
        # bootstrapped Genesis client must not be served that rollback.
        shutil.copyfile(self.fixture / "team.db", self.root / "saved-current.db")
        rollback_config = self.config("rollback-genesis")
        shutil.copyfile(self.root / "saved-initial.db", self.fixture / "rollback.new")
        (self.fixture / "rollback.new").replace(self.fixture / "team.db")
        self.client("device-0", config=rollback_config, status="invalid")
        shutil.copyfile(self.root / "saved-current.db", self.fixture / "restore.new")
        (self.fixture / "restore.new").replace(self.fixture / "team.db")
        result, _ = self.client("owner")
        self.assert_version(result, 3)
        self.mark("server_independent_anchor_rejects_authentic_database_rollback_for_genesis_client")

        # Both candidates derive from the same signed parent, then travel over
        # two independent client processes and two independent TLS connections.
        left = self.prepare("writer-0", current, "b")
        right = self.prepare("writer-1", current, "c")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(self.client, "device-0", "publish", candidate=left, status=("ok", "conflict"))
            f2 = pool.submit(self.client, "device-1", "publish", candidate=right, status=("ok", "conflict"))
            left_result, right_result = f1.result()[0], f2.result()[0]
        self.check(sorted((left_result["status"], right_result["status"])) == ["conflict", "ok"], "concurrent publications did not have one winner")
        winner = left if left_result["status"] == "ok" else right
        loser = right if winner == left else left
        variant = "b" if winner == left else "c"
        self.client("owner", "reconcile", candidate=winner, outcome="committed")
        self.client("owner", "reconcile", candidate=loser, outcome="conflicted")
        result, current = self.client("owner")
        self.assert_version(result, 4)
        self.oracle(current, 0, variant)
        self.oracle(current, 1, variant)
        self.mark("concurrent_writer_one_winner_and_exact_proposal_reconciliation")

        lost = self.prepare("writer-0", current, "d")
        before = len(self.captures_for("publish"))
        self.fault("drop-after")
        self.client("device-0", "publish", candidate=lost, status="unknown")
        self.fault()
        self.check(len(self.captures_for("publish")) == before + 1, "publish automatically retried after response loss")
        self.client("device-0", "reconcile", candidate=lost, outcome="committed")
        result, current = self.client("owner")
        self.assert_version(result, 5)
        self.oracle(current, 1, "d")

        pending = self.prepare("writer-0", current, "e")
        self.fault("drop-before")
        self.client("device-0", "publish", candidate=pending, status="unknown")
        self.fault()
        self.client("device-0", "reconcile", candidate=pending, outcome="unknown")
        still_parent, _ = self.client("owner")
        self.assert_version(still_parent, 5)
        self.mark("lost_response_unknown_committed_reconcile_and_uncommitted_stays_unknown")

        durable = self.prepare("writer-0", current, "e")
        before_anchor = self.run("anchor-read", "--anchor", self.fixture / "server.anchor")
        self.assert_version(before_anchor, 5)
        self.fault("server-anchor-fail")
        self.client("device-0", "publish", candidate=durable, status="unknown")
        self.client("owner", status="anchor")
        after_failure = self.run("anchor-read", "--anchor", self.fixture / "server.anchor")
        self.assert_version(after_failure, 5)
        self.fault()
        result, current = self.client("owner")
        self.assert_version(result, 6)
        self.oracle(current, 1, "e")
        recovered_anchor = self.run("anchor-read", "--anchor", self.fixture / "server.anchor")
        self.assert_version(recovered_anchor, 6)
        self.client("device-0", "reconcile", candidate=durable, outcome="committed")
        self.mark("server_anchor_failure_withholds_success_and_verified_descendant_recovers")

        revoke = self.prepare("revoke-device", current, "a")
        self.client("owner", "publish", candidate=revoke)
        self.client("device-0", status="denied")
        self.client("device-0", "publish", candidate=pending, status=("denied", "conflict"))
        result, current = self.client("device-1")
        self.assert_version(result, 7)
        self.oracle(current, 0, "a", decrypt=False)
        self.oracle(current, 1, "a")
        revoke = self.prepare("revoke-member", current, "b")
        self.client("owner", "publish", candidate=revoke)
        self.client("device-1", status="denied")
        result, current = self.client("device-2")
        self.assert_version(result, 8)
        self.oracle(current, 0, "b", decrypt=False)
        self.oracle(current, 1, "b", decrypt=False)
        self.oracle(current, 2, "b")
        self.mark("device_and_member_revocation_denies_network_and_new_ciphertext")

        frozen = self.prepare("freeze", current, "b")
        self.client("owner", "publish", candidate=frozen)
        self.client("device-2", status="denied")
        result, view = self.client("owner")
        self.assert_version(result, 9)
        self.check(json.loads(view.read_text())["receipt"]["proposal"]["mode"] == "frozen", "owner did not observe frozen state")
        self.mark("owner_explicit_identity_reads_frozen_complete_history")

    def scan(self, *, complete=True):
        private = json.loads((self.fixture / "private.json").read_text())
        canaries = []
        for items in private["Items"].values():
            for item in items:
                for field in ("Username", "Password", "Notes"):
                    raw = item[field].encode()
                    canaries.extend((raw, base64.b64encode(raw), raw.hex().encode()))
        files = list(self.logs) + list(self.capture.glob("*.request")) + list(self.capture.glob("*.response"))
        for path in files:
            self.check(path.is_file(), "missing complete process or network capture")
            raw = path.read_bytes()
            self.check(all(canary not in raw for canary in canaries), "synthetic plaintext leaked into output or network body")
        if not complete:
            return
        # Every request has a cryptographically fresh nonce. Do not infer this
        # merely from success: independently parse captured wire messages.
        nonces = []
        for path in self.capture.glob("*.request"):
            payload = json.loads(path.read_bytes())
            values = []

            def find(value):
                if isinstance(value, dict):
                    for key, nested in value.items():
                        if key.lower() == "nonce":
                            values.append(nested)
                        else:
                            find(nested)
                elif isinstance(value, list):
                    for nested in value:
                        find(nested)

            # Only envelope nonce, not historical admission proof nonces.
            for key, value in payload.items():
                if key.lower() == "nonce":
                    values.append(value)
            if not values:
                find(payload.get("request", payload.get("Request", {})))
            self.check(len(values) == 1 and isinstance(values[0], str), "wire envelope missing exact request nonce")
            nonce = values[0]
            if len(nonce) == 64 and all(c in "0123456789abcdef" for c in nonce):
                decoded = bytes.fromhex(nonce)
            else:
                try:
                    decoded = base64.b64decode(nonce, validate=True)
                except ValueError:
                    raise AcceptanceFailure("request nonce encoding invalid") from None
            self.check(len(decoded) == 32, "request nonce was not 32 random bytes")
            nonces.append(nonce)
        self.check(len(nonces) > 20 and len(nonces) == len(set(nonces)), "request nonces repeated or capture incomplete")
        self.scanned = True
        self.mark("full_stdout_stderr_wire_body_canary_scan_and_fresh_32byte_nonces")

    def close(self):
        if self.server is not None:
            self.server.terminate()
            try:
                self.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait(timeout=5)
        for handle in (self.server_out, self.server_err):
            if handle:
                handle.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-bin", help="independently fixed fixture executable")
    parser.add_argument("--go", help="Go executable, used only when building fixture")
    parser.add_argument("--artifacts", default="/tmp/locklark-validation", help="private artifact parent")
    args = parser.parse_args()
    os.umask(0o077)
    acceptance = Acceptance(args)
    success = False
    classification = "failed"
    try:
        acceptance.build()
        acceptance.start()
        acceptance.exercise()
        acceptance.close()
        acceptance.scan()
        success = True
        classification = "passed"
    except (AcceptanceFailure, subprocess.TimeoutExpired) as exc:
        # Exception text is solely our fixed classifications, never child stderr.
        classification = str(exc) if isinstance(exc, AcceptanceFailure) else "process deadline exceeded"
        print("FAIL " + classification, file=sys.stderr)
    finally:
        acceptance.close()
        if not acceptance.scanned and (acceptance.fixture / "private.json").is_file():
            try:
                acceptance.scan(complete=False)
            except AcceptanceFailure:
                success = False
                classification = "synthetic plaintext leaked into output or network body"
                print("FAIL " + classification, file=sys.stderr)
        acceptance.write(acceptance.root / "result.json", {
            "success": success, "classification": classification,
            "checks": acceptance.completed, "private_artifacts": str(acceptance.root)})
        print("Private artifacts: " + str(acceptance.root), flush=True)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
