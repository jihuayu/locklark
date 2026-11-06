"""Real CLI bootstrap over TLS and two isolated native Secret Services.

Build the reviewed product CLI, service and this fixture independently and pass
their separately trusted SHA-256 values. Hash equality does not establish the
origin of an arbitrary binary. Keep the entire artifact directory private.
The fixture does public verification and transparent real-OS fault injection;
it does not replace the normal user commands or export protected team keys.
Linux unlocked Secret Service is not a biometric or per-access prompt proof.
Unknown core-generated seeds cannot be external canaries without exporting
them; this scanner covers known synthetic inputs and strict public evidence.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import quote_from_bytes
from xml.sax.saxutils import escape

sys.dont_write_bytecode = True
import team_identity_acceptance as native

GROUPS = (
    "reviewed artifacts and two owned native providers",
    "service identity is protected before public handoff",
    "owner roles and Genesis anchor precede enrollment",
    "lost native protection remains recoverable without replacement",
    "public initial artifact proves the first device",
    "wrong pins fingerprints and altered artifacts are refused",
    "fresh worker initializes the exact directory and checkpoint",
    "first device fetches and decrypts through pinned TLS",
    "untrusted TLS and unavailable OS storage fail closed",
    "fresh processes and provider restart preserve the original bootstrap",
    "uncertain scope adoption never permits a later directory create",
    "missing established anchors and public rollback cannot reset trust",
    "known canaries remain private and owned processes stop",
)
STAGES = {"prerequisites", "provider", "identity", "artifact", "refusal", "initialize", "tls", "fetch", "restart", "unknown", "rollback", "cleanup", "privacy"}


class Failure(Exception):
    def __init__(self, stage): self.stage = stage if stage in STAGES else "prerequisites"


def require(condition, stage="prerequisites"):
    if not condition: raise Failure(stage)


def public_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, separators=(",", ":"))
    Path(path).chmod(0o600)


def fingerprints(signing):
    require(isinstance(signing, str) and len(signing) == 64)
    raw = bytes.fromhex(signing)
    return "SHA256:" + hashlib.sha256(raw).hexdigest()


def service_endpoint(raw):
    require(len(raw) <= 16 << 10, "tls")
    receipt = json.loads(raw)
    require(receipt.get("command") == "serve-profile" and receipt.get("state") == "active", "tls")
    address = receipt.get("listen", "")
    require(isinstance(address, str) and re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]{0,4})", address) and int(address.rsplit(":", 1)[1]) <= 65535, "tls")
    return "https://" + address


def verify_binaries(config):
    require(set(config["binaries"]) == {"cli", "service", "fixture"})
    for record in config["binaries"].values():
        native.verify_fixture(Path(record["path"]), record["sha256"])


def owned_stop(process):
    if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)


def worker(config, participant):
    root = Path(config["root"]) / participant
    native.validate_private_session(root)
    verify_binaries(config)
    prefix = native.verify_dependencies(Path(config["dependencies"]))
    fixture = config["binaries"]["fixture"]
    provider = native.Session(root, Path(fixture["path"]), prefix, fixture["sha256"])
    children, serial = {}, 0
    def reply(value): print(json.dumps(value, separators=(",", ":")), flush=True)
    try:
        provider.start()
        reply({"ready": True})
        for line in sys.stdin.buffer:
            require(len(line) <= 64 << 10)
            q = json.loads(line)
            serial += 1
            operation = q.get("operation")
            extra = {}
            if operation == "quit":
                for child in children.values(): owned_stop(child)
                provider.stop(); provider.assert_provider_absent()
                reply({"id": q["id"], "code": 0, "cleanup": True}); return 0
            if operation == "provider-stop":
                provider.stop(); provider.assert_provider_absent(); code = 0
            elif operation == "provider-start":
                provider.start(); code = 0
            elif operation == "kill":
                require(q["child"] in children)
                owned_stop(children.pop(q["child"])); code = 0
            elif operation in {"run", "start"}:
                verify_binaries(config)
                require(q["binary"] in config["binaries"])
                argv = [config["binaries"][q["binary"]]["path"], *q.get("args", [])]
                require(all(isinstance(value, str) and "\x00" not in value for value in argv))
                out = root / ("child-%04d-stdout-private.log" % serial)
                err = root / ("child-%04d-stderr-private.log" % serial)
                with out.open("wb") as stdout, err.open("wb") as stderr:
                    if operation == "start":
                        require(q["name"] not in children)
                        child = subprocess.Popen(argv, stdin=subprocess.PIPE if "data" in q else subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=provider.environment)
                        children[q["name"]] = child
                        if "data" in q:
                            child.stdin.write(json.dumps(q["data"]).encode()); child.stdin.close()
                        code = 0
                        extra["stdout"] = str(out)
                    else:
                        options = {"input": json.dumps(q["data"]).encode()} if "data" in q else {"stdin": subprocess.DEVNULL}
                        result = subprocess.run(argv, stdout=stdout, stderr=stderr, env=provider.environment, timeout=32, **options)
                        code = result.returncode
            else:
                raise Failure("prerequisites")
            reply({"id": q["id"], "code": code, **extra})
    except BaseException:
        reply({"failed": True})
        return 1
    finally:
        for child in children.values(): owned_stop(child)
        provider.stop()
    return 1


class Participant:
    def __init__(self, config, config_path, name):
        self.root = Path(config["root"]) / name
        self.serial, self.cleaned = 0, False
        self.master, slave = pty.openpty()
        self.tty_log = (self.root / "terminal-private.log").open("wb")
        self.worker_log = (self.root / "worker-private.log").open("wb")
        prefix = Path(config["dependencies"]) / "root"
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(self.root / "home"), "XDG_DATA_HOME": str(self.root / "data"), "XDG_CONFIG_HOME": str(self.root / "config"), "XDG_CACHE_HOME": str(self.root / "cache"), "XDG_RUNTIME_DIR": str(self.root / "runtime"), "XDG_DATA_DIRS": str(prefix / "usr/share"), "LD_LIBRARY_PATH": str(prefix / "usr/lib/x86_64-linux-gnu")}
        bus = self.root / "runtime" / "bus"
        require(len(os.fsencode(bus)) <= 100)
        bus_config = self.root / "bus.conf"
        bus_config.write_text('<busconfig><type>session</type><listen>unix:path=' + escape(str(bus)) + '</listen><auth>EXTERNAL</auth><policy context="default"><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
        argv = [config["binaries"]["fixture"]["path"], "console-exec", os.ttyname(slave), "/usr/bin/dbus-run-session", "--config-file", str(bus_config), "--", sys.executable, str(Path(__file__).resolve()), "--worker", "--config", str(config_path), "--participant", name]
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.worker_log, env=environment, start_new_session=True)
        os.close(slave)
        try: require(self.await_reply().get("ready") is True, "provider")
        except BaseException:
            self.close(); raise

    def await_reply(self, trust=None):
        deadline, observed, supplied = time.monotonic() + 38, b"", False
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.master, self.process.stdout], [], [], min(0.2, deadline - time.monotonic()))
            if self.master in ready:
                try: raw = os.read(self.master, 8192)
                except OSError: raw = b""
                if raw:
                    self.tty_log.write(raw); self.tty_log.flush()
                    observed = (observed + raw)[-16_384:]
                    if trust is not None and not supplied and ("Type TRUST " + trust + " to confirm: ").encode() in observed:
                        os.write(self.master, ("TRUST " + trust + "\n").encode()); supplied = True
            if self.process.stdout in ready:
                line = self.process.stdout.readline(65_537)
                require(bool(line) and len(line) <= 64 << 10, "provider")
                value = json.loads(line)
                require(not value.get("failed"), "provider")
                return value
        raise Failure("provider")

    def call(self, operation="run", trust=None, **values):
        self.serial += 1
        values.update(operation=operation, id=self.serial)
        self.process.stdin.write(json.dumps(values).encode() + b"\n"); self.process.stdin.flush()
        result = self.await_reply(trust)
        require(result.get("id") == self.serial, "provider")
        return result

    def close(self):
        if not self.cleaned and self.process.poll() is None:
            try: self.cleaned = self.call("quit").get("cleanup") is True
            except BaseException: pass
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL); self.process.wait(timeout=5)
        else: self.process.wait()
        self.process.stdin.close(); self.process.stdout.close()
        os.close(self.master); self.tty_log.close(); self.worker_log.close()


class Acceptance:
    def __init__(self, config, config_path):
        self.config, self.config_path = config, config_path
        self.root = Path(config["root"])
        self.server, self.owner, self.completed = None, None, []
        self.stage = "prerequisites"

    def mark(self, index):
        require(index not in self.completed)
        self.completed.append(index)
        print("PASS: team bootstrap " + GROUPS[index], flush=True)

    def command(self, participant, binary, args, *, trust=None, success=True, data=None):
        values = {"binary": binary, "args": list(map(str, args))}
        if data is not None: values["data"] = data
        code = participant.call(trust=trust, **values).get("code")
        require(isinstance(code, int) and (code == 0 if success else code != 0), self.stage)

    def oracle(self, mode, data, participant=None):
        self.command(participant or self.owner, "fixture", [mode], data=data)

    def scenario(self, name, export_artifact=True):
        d = self.root / name; d.mkdir(mode=0o700)
        q = {"Profile": str(d / "service.profile"), "Anchor": str(d / "server.anchor"), "Directory": str(d / "team.db"), "ServiceFile": str(d / "service.json"), "PinsFile": str(d / "pins.json"), "ArtifactFile": str(d / "initial.json")}
        owner = d / "owner.profile"; owner_anchor = d / "owner.anchor"
        self.command(self.server, "service", ["prepare-identity", "--profile", q["Profile"], "--public-out", q["ServiceFile"]])
        service = json.loads(Path(q["ServiceFile"]).read_text())
        self.command(self.owner, "cli", ["team", "create", "--profile", owner, "--anchor", owner_anchor, "--service", q["ServiceFile"], "--expect-sequencer-fingerprint", fingerprints(service["signing"]), "--pins-out", q["PinsFile"]], trust=fingerprints(service["signing"]))
        if export_artifact:
            self.command(self.owner, "cli", ["team", "export-initial", "--profile", owner, "--out", q["ArtifactFile"]])
        return q

    @staticmethod
    def initialization(q, command="initialize"):
        pins = json.loads(Path(q["PinsFile"]).read_text())
        fp = fingerprints(pins["Owners"][0])
        args = [command, "--profile", q["Profile"], "--service", q["ServiceFile"], "--trusted-pins", q["PinsFile"], "--expect-owner-fingerprint", fp, "--artifact", q["ArtifactFile"], "--directory", q["Directory"], "--anchor", q["Anchor"]]
        return args, fp

    def start_server(self, q, name="server", tls_directory="tls"):
        tls = self.root / tls_directory
        args = ["serve-profile", "--profile", q["Profile"], "--service", q["ServiceFile"], "--trusted-pins", q["PinsFile"], "--listen", "127.0.0.1:0", "--certificate", str(tls / "server.pem"), "--tls-key", str(tls / "server.key")]
        response = self.server.call("start", binary="service", args=args, name=name)
        output = Path(response["stdout"])
        require(output.parent == self.server.root, "tls")
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                raw = native.trusted_file(output).read_bytes(); require(len(raw) <= 16 << 10, "tls")
                return service_endpoint(raw)
            except (OSError, json.JSONDecodeError): time.sleep(0.03)
        raise Failure("tls")

    def fetch(self, profile, endpoint, ca, success=True):
        self.command(self.owner, "cli", ["team", "fetch-initial", "--profile", profile, "--endpoint", endpoint, "--ca", ca], success=success)

    def run(self):
        self.stage = "provider"
        self.server = Participant(self.config, self.config_path, "server")
        self.owner = Participant(self.config, self.config_path, "owner")
        self.mark(0)
        d = self.root / "main"; d.mkdir(mode=0o700)
        q = {"Profile": str(d / "service.profile"), "Anchor": str(d / "server.anchor"), "Directory": str(d / "team.db"), "ServiceFile": str(d / "service.json"), "PinsFile": str(d / "pins.json"), "ArtifactFile": str(d / "initial.json")}
        owner, owner_anchor = d / "owner.profile", d / "owner.anchor"
        self.stage = "identity"
        self.command(self.server, "service", ["prepare-identity", "--profile", q["Profile"], "--public-out", q["ServiceFile"]])
        service = json.loads(Path(q["ServiceFile"]).read_text()); require(service["state"] == "pending", self.stage)
        self.oracle("status", {"Profile": q["Profile"], "State": "pending"}, self.server)
        self.mark(1)
        self.command(self.owner, "cli", ["team", "create", "--profile", d / "refused-owner.profile", "--anchor", d / "refused-owner.anchor", "--service", q["ServiceFile"], "--expect-sequencer-fingerprint", "SHA256:" + "0" * 64, "--pins-out", d / "refused-pins.json"], success=False)
        require(not any((d / name).exists() for name in ["refused-owner.profile", "refused-owner.anchor", "refused-pins.json"]), self.stage)
        self.command(self.owner, "cli", ["team", "create", "--profile", owner, "--anchor", owner_anchor, "--service", q["ServiceFile"], "--expect-sequencer-fingerprint", fingerprints(service["signing"]), "--pins-out", q["PinsFile"]], trust=fingerprints(service["signing"]))
        self.oracle("anchor", {"Anchor": str(owner_anchor), "Version": 0})
        owner_before = (d / "owner-before.profile"); owner_before.write_bytes(owner.read_bytes()); owner_before.chmod(0o600)
        service_before = d / "service-before.profile"; service_before.write_bytes(Path(q["Profile"]).read_bytes()); service_before.chmod(0o600)
        self.mark(2)
        unknown = d / "unknown.profile"
        self.oracle("fault-protection", {"Profile": str(unknown), "Output": str(d / "unknown.json")}, self.server)
        self.command(self.server, "service", ["reconcile-protection", "--profile", unknown])
        self.oracle("protection-reconcile", {"Profile": str(unknown)}, self.server)
        for fault in ["owner-claim-lost", "owner-built-lost"]:
            recovery = self.scenario(fault, export_artifact=False)
            profile = Path(recovery["Profile"]).parent / "owner.profile"
            status = profile.parent / "lost-result-status.json"
            self.oracle("fault-build", {"Profile": str(profile), "Fault": fault, "Output": str(status)})
            if fault == "owner-claim-lost":
                self.command(self.owner, "cli", ["team", "export-initial", "--profile", profile, "--out", recovery["ArtifactFile"]], success=False)
                self.oracle("owner-no-rebuild", {"Profile": str(profile)})
                require(not Path(recovery["ArtifactFile"]).exists(), self.stage)
            else:
                self.command(self.owner, "cli", ["team", "export-initial", "--profile", profile, "--out", recovery["ArtifactFile"]])
                self.command(self.owner, "cli", ["team", "reconcile-protection", "--profile", profile])
                observed = profile.parent / "recovered-status.json"
                self.oracle("status", {"Profile": str(profile), "State": "pending", "Output": str(observed)})
                require(json.loads(status.read_text())["artifact_digest"] == json.loads(observed.read_text())["artifact_digest"], self.stage)
                readonly = profile.parent / "readonly-original.json"
                self.oracle("owner-export-readonly", {"Profile": str(profile), "Output": str(readonly)})
                require(readonly.read_bytes() == Path(recovery["ArtifactFile"]).read_bytes(), self.stage)
                self.oracle("verify-initial", {**recovery, "Profile": str(profile)})
        self.mark(3)
        self.stage = "artifact"
        self.command(self.owner, "cli", ["team", "export-initial", "--profile", owner, "--out", q["ArtifactFile"]])
        self.oracle("verify-initial", {**q, "Profile": str(owner)})
        original_outbox = owner.read_bytes()
        owner.write_bytes(owner_before.read_bytes())
        pending_output = d / "must-not-rebuild-pending.json"
        self.command(self.owner, "cli", ["team", "export-initial", "--profile", owner, "--out", pending_output], success=False)
        require(not pending_output.exists(), self.stage)
        self.oracle("owner-no-rebuild", {"Profile": str(owner), "Fault": "require-native-load"})
        self.oracle("anchor", {"Anchor": str(owner_anchor), "Version": 0})
        owner.write_bytes(original_outbox)
        original_export = d / "same-pending-initial.json"
        self.command(self.owner, "cli", ["team", "export-initial", "--profile", owner, "--out", original_export])
        require(original_export.read_bytes() == Path(q["ArtifactFile"]).read_bytes(), self.stage)
        self.mark(4)
        self.stage = "refusal"
        args, fp = self.initialization(q)
        bad = list(args); bad[bad.index("--expect-owner-fingerprint") + 1] = "SHA256:" + "0" * 64
        self.command(self.server, "service", bad, success=False)
        original = json.loads(Path(q["ArtifactFile"]).read_text())
        for field in ["Database", "Envelope", "Signature"]:
            changed = json.loads(json.dumps(original)); encoded = changed["snapshot"][field]
            raw = bytearray(base64.b64decode(encoded)); require(bool(raw)); raw[len(raw) // 2] ^= 1
            changed["snapshot"][field] = base64.b64encode(raw).decode()
            path = d / ("changed-" + field + ".json"); public_json(path, changed)
            altered = list(args); altered[altered.index("--artifact") + 1] = str(path)
            self.command(self.server, "service", altered, trust=fp, success=False)
        pins = json.loads(Path(q["PinsFile"]).read_text()); pins["Team"] = secrets.token_hex(16)
        path = d / "wrong-pins.json"; public_json(path, pins)
        bad = list(args); bad[bad.index("--trusted-pins") + 1] = str(path)
        self.command(self.server, "service", bad, trust=fp, success=False)
        require(not Path(q["Directory"]).exists() and not Path(q["Anchor"]).exists(), self.stage)
        self.mark(5)
        self.stage = "initialize"
        self.command(self.server, "service", args, trust=fp)
        self.oracle("verify-active", {**q, "Output": str(d / "server-checkpoint.json")}, self.server)
        self.mark(6)
        self.stage = "tls"
        for name in ["tls", "wrong-tls", "wrong-name-tls"]:
            folder = self.root / name; folder.mkdir(mode=0o700)
            self.oracle("tls", {"TLSDirectory": str(folder), "Fault": "wrong-name" if name == "wrong-name-tls" else ""})
        endpoint = self.start_server(q)
        self.fetch(owner, endpoint, self.root / "wrong-tls/ca.pem", success=False)
        self.oracle("status", {"Profile": str(owner), "State": "pending"})
        self.oracle("anchor", {"Anchor": str(owner_anchor), "Version": 0})
        wrong_name_endpoint = self.start_server(q, name="wrong-name-server", tls_directory="wrong-name-tls")
        self.fetch(owner, wrong_name_endpoint, self.root / "wrong-name-tls/ca.pem", success=False)
        self.server.call("kill", child="wrong-name-server")
        self.oracle("status", {"Profile": str(owner), "State": "pending"})
        self.oracle("anchor", {"Anchor": str(owner_anchor), "Version": 0})
        self.owner.call("provider-stop")
        self.fetch(owner, endpoint, self.root / "tls/ca.pem", success=False)
        self.oracle("status", {"Profile": str(owner), "State": "pending"})
        self.owner.call("provider-start")
        self.stage = "fetch"
        self.fetch(owner, endpoint, self.root / "tls/ca.pem")
        self.oracle("status", {"Profile": str(owner), "State": "active"})
        self.oracle("anchor", {"Anchor": str(owner_anchor), "Version": 1, "Output": str(d / "owner-checkpoint.json")})
        require(json.loads((d / "owner-checkpoint.json").read_text()) == json.loads((d / "server-checkpoint.json").read_text()), self.stage)
        self.mark(7); self.mark(8)
        self.stage = "restart"
        self.server.call("kill", child="server")
        for participant in [self.server, self.owner]:
            participant.call("provider-stop"); participant.call("provider-start")
        endpoint = self.start_server(q)
        self.fetch(owner, endpoint, self.root / "tls/ca.pem")
        reexport = d / "same-initial.json"
        self.command(self.owner, "cli", ["team", "export-initial", "--profile", owner, "--out", reexport])
        require(reexport.read_bytes() == Path(q["ArtifactFile"]).read_bytes(), self.stage)
        self.mark(9)
        self.stage = "unknown"
        for fault in ["bind-before", "bind-after"]:
            scenario = self.scenario(fault)
            barrier = self.root / fault / "boundary"
            values = {**scenario, "Fault": fault, "Barrier": str(barrier)}
            self.server.call("start", binary="fixture", args=["fault-bind"], name=fault, data=values)
            deadline = time.monotonic() + 8
            while not barrier.exists() and time.monotonic() < deadline: time.sleep(0.02)
            require(barrier.exists() and barrier.read_text() == fault.removeprefix("bind-"), self.stage)
            self.server.call("kill", child=fault)
            recovery, recovery_fp = self.initialization(scenario, "reconcile-initialize")
            self.command(self.server, "service", recovery, trust=recovery_fp, success=False)
            self.oracle("anchor", {"Anchor": scenario["Anchor"], "Version": 0}, self.server)
            self.oracle("no-reset", {**scenario, "MissingDirectory": True}, self.server)
        self.mark(10)
        self.stage = "rollback"
        self.server.call("kill", child="server")
        # Only synthetic public profiles are restored. Independent identity
        # leases and protected OS records are deliberately never rolled back.
        Path(q["Profile"]).write_bytes(service_before.read_bytes())
        self.oracle("no-reset", q, self.server)
        self.oracle("anchor", {"Anchor": q["Anchor"], "Version": 1}, self.server)
        Path(q["Anchor"]).unlink()
        database = hashlib.sha256(Path(q["Directory"]).read_bytes()).hexdigest()
        self.oracle("no-reset", {**q, "MissingAnchor": True}, self.server)
        require(hashlib.sha256(Path(q["Directory"]).read_bytes()).hexdigest() == database, self.stage)
        Path(q["Directory"]).rename(d / "retained-encrypted-team.db")
        self.oracle("no-reset", {**q, "MissingDirectory": True, "MissingAnchor": True}, self.server)
        owner.write_bytes(owner_before.read_bytes())
        self.command(self.owner, "cli", ["team", "export-initial", "--profile", owner, "--out", d / "must-not-rebuild-advanced.json"], success=False)
        self.oracle("anchor", {"Anchor": str(owner_anchor), "Version": 1})
        require(not (d / "must-not-rebuild-advanced.json").exists(), self.stage)
        owner_anchor.unlink()
        output = d / "must-not-rebuild.json"
        self.command(self.owner, "cli", ["team", "export-initial", "--profile", owner, "--out", output], success=False)
        self.fetch(owner, endpoint, self.root / "tls/ca.pem", success=False)
        require(not owner_anchor.exists() and not output.exists(), self.stage)
        self.mark(11)

    def cleanup(self):
        self.stage = "cleanup"
        okay = True
        for participant in [self.owner, self.server]:
            if participant is not None:
                try: participant.close()
                except BaseException: okay = False
        return okay and all(participant is not None and participant.cleaned for participant in [self.owner, self.server])


def privacy(root):
    excluded, patterns = set(), set()
    for name in ["server", "owner"]:
        manifest = root / name / "oracle/canaries.json"
        require(manifest.is_file() and not manifest.is_symlink() and not manifest.stat().st_mode & 0o077, "privacy")
        values = json.loads(manifest.read_text()); require(len(values) == 5 and len(set(values)) == 5, "privacy")
        excluded.add(manifest)
        for value in values:
            raw = base64.b64decode(value, validate=True); require(len(raw) >= 16, "privacy")
            patterns.update([raw, base64.b64encode(raw), base64.urlsafe_b64encode(raw), raw.hex().encode(), raw.hex().upper().encode(), quote_from_bytes(raw, safe="").encode()])
    for name in ["tls", "wrong-tls", "wrong-name-tls"]:
        path = root / name / "server.key"
        if path.is_file():
            require(not path.is_symlink() and not path.stat().st_mode & 0o077, "privacy")
            excluded.add(path); raw = path.read_bytes(); patterns.add(raw)
            lines = raw.splitlines(); require(len(lines) >= 3, "privacy")
            patterns.add(b"".join(lines[1:-1]))
    files = 0
    for path in root.rglob("*"):
        require(not path.is_symlink(), "privacy")
        if path.is_file() and path not in excluded:
            require(not path.stat().st_mode & 0o077 and path.stat().st_size <= 32 << 20, "privacy")
            raw = path.read_bytes(); require(not any(value in raw for value in patterns), "privacy"); files += 1
    return files


def outer(args):
    require(sys.platform == "linux")
    os.umask(0o077)
    requested = Path(args.artifacts)
    require(requested.is_absolute() and not requested.exists())
    root = native.trusted_parent(requested.parent) / requested.name
    config = {"root": str(root), "dependencies": str(native.trusted_parent(Path(args.dependency_root))), "binaries": {key: {"path": getattr(args, key), "sha256": getattr(args, key + "_sha256")} for key in ["cli", "service", "fixture"]}}
    verify_binaries(config); native.verify_dependencies(Path(config["dependencies"]))
    root.mkdir(mode=0o700)
    for participant in ["server", "owner"]:
        directory = root / participant; directory.mkdir(mode=0o700)
        for name in ["home", "data", "config", "cache", "runtime"]: (directory / name).mkdir(mode=0o700)
    config_path = root / "config.json"; native.private_json(config_path, config)
    acceptance = Acceptance(config, config_path)
    okay, cleaned, scanned = False, False, 0
    try:
        acceptance.run(); okay = True
    except BaseException:
        print("FAIL: team bootstrap at " + acceptance.stage, flush=True)
    finally:
        cleaned = acceptance.cleanup()
    actual = {}
    verified_after = False
    try:
        for name, record in config["binaries"].items():
            path = native.trusted_file(Path(record["path"]))
            actual[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        verify_binaries(config); verified_after = True
        scanned = privacy(root)
    except BaseException:
        okay = False
        print("FAIL: team bootstrap at privacy", flush=True)
    okay = okay and cleaned and len(acceptance.completed) == 12
    if okay: acceptance.mark(12)
    native.private_json(root / "result.json", {"passed": okay, "groups": len(acceptance.completed), "scanned_files": scanned, "owned_cleanup": cleaned, "artifacts": config["binaries"], "actual_artifact_sha256": actual, "verified_before": True, "verified_after": verified_after, "source_provenance": "external-reviewed-source-build-required", "unknown_core_seed_canary_coverage": False, "biometric_claim": False, "per_access_prompt_claim": False, "later_enrollment_reveal_revocation_claim": False})
    return 0 if okay else 1


def main(argv=None):
    parser = native.Parser(description=__doc__)
    for name in ["cli", "service", "fixture"]:
        parser.add_argument("--" + name); parser.add_argument("--" + name + "-sha256")
    parser.add_argument("--dependency-root"); parser.add_argument("--artifacts")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--config", help=argparse.SUPPRESS)
    parser.add_argument("--participant", choices=["server", "owner"], help=argparse.SUPPRESS)
    try:
        args = parser.parse_args(argv)
        if args.worker:
            require(args.config and args.participant)
            path = native.trusted_file(Path(args.config)); config = json.loads(path.read_text())
            require(path == Path(config["root"]) / "config.json")
            return worker(config, args.participant)
        require(args.artifacts and args.dependency_root and all(getattr(args, name) and getattr(args, name + "_sha256") for name in ["cli", "service", "fixture"]))
        return outer(args)
    except BaseException:
        print("FAIL: team bootstrap at prerequisites", flush=True)
        return 1


if __name__ == "__main__": sys.exit(main())
