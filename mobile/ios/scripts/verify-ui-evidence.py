#!/usr/bin/env python3
"""Privately export and scan the complete iOS XCTest UI evidence.

Call on xcodebuild success AND failure, before deleting the newly created
Locklark-CI-* simulator. --owned-simulator is the caller's assertion that it
created this simulator for this run. No app hook or secret launch argument is
used: only the XCTest runner's private manifest is read through simctl.
"""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.parse
import uuid
from collections import deque


RUNNER_BUNDLE = "org.locklark.mobile.ios.uitests.xctrunner"
MANIFEST = pathlib.Path("Library/Application Support/LocklarkUITestEvidence/canaries.json")
TEST_NAME = "OfflineVaultFlowTests.testActualOfflineCreateUnlockEditRevealAndBackgroundLock"
STAGES = {"prerequisites", "owned-simulator", "manifest", "xcresult-export", "canary-scan", "test-outcome", "complete"}


class EvidenceFailure(Exception):
    pass


def require(condition):
    if not condition:
        raise EvidenceFailure()


def patterns(values):
    ordinary, numeric = set(), set()
    for value in values:
        require(isinstance(value, str) and 0 < len(value) <= 65536)
        for part in {value, *value.splitlines()}:
            if not part:
                continue
            raw = part.encode()
            encoded = {json.dumps(part, ensure_ascii=True)[1:-1].encode(),
                       json.dumps(part, ensure_ascii=False)[1:-1].encode(),
                       urllib.parse.quote(part, safe="").encode(),
                       base64.b64encode(raw), base64.urlsafe_b64encode(raw),
                       raw.hex().encode(), raw.hex().upper().encode()}
            if re.fullmatch(r"[0-9]{6,8}", part):
                numeric.add(raw)
                encoded.discard(raw)
            else:
                ordinary.add(raw)
            ordinary.update(encoded)
    return ordinary, numeric


def scan_file(path, values):
    ordinary, numeric = patterns(values)
    longest = max((len(value) for value in ordinary | numeric), default=1)
    tail = b""
    total = 0
    # No truncation: stream the entire output, retaining overlap for a canary
    # crossing a chunk boundary. Binary attachments are scanned as raw bytes;
    # intentionally shown pixels are never OCR'd or printed.
    with path.open("rb") as source:
        while chunk := source.read(1 << 20):
            raw = tail + chunk
            raw_start = total - len(tail)
            require(not any(value in raw for value in ordinary))
            for value in numeric:
                # Delay a match ending exactly at a chunk edge until its next
                # byte is known; otherwise a long timestamp could look like OTP.
                require(not any(match.end() < len(raw) and (match.start() > 0 or raw_start == 0)
                                for match in re.finditer(rb"(?<![A-Za-z0-9])" + value + rb"(?![A-Za-z0-9])", raw)))
            tail = raw[-(longest + 1):]
            total += len(chunk)
    require(not any(match.start() > 0 or total == len(tail) for value in numeric
                    for match in re.finditer(rb"(?<![A-Za-z0-9])" + value + rb"(?![A-Za-z0-9])", tail)))


def parse_canaries(raw):
    value = json.loads(raw)
    candidates = value.get("canaries", []) if isinstance(value, dict) else []
    available = [part for part in candidates if isinstance(part, str) and 0 < len(part) <= 65536] if isinstance(candidates, list) else []
    valid = (isinstance(value, dict) and set(value) == {"version", "run_id", "test", "complete", "canaries"}
             and value.get("version") == 1 and value.get("test") == TEST_NAME
             and isinstance(value.get("complete"), bool) and isinstance(candidates, list)
             and len(candidates) <= 128 and len(available) == len(candidates)
             and len(set(available)) == len(available))
    try:
        valid = valid and str(uuid.UUID(value.get("run_id", ""))).upper() == value.get("run_id", "").upper()
    except (ValueError, TypeError, AttributeError):
        valid = False
    complete = bool(valid and value["complete"] and len(available) >= 10
                    and any(re.fullmatch(r"LL1-[A-Z2-7]{26}", part) for part in available)
                    and any(re.fullmatch(r"[0-9]{6}", part) for part in available)
                    and any(part.startswith("otpauth://totp/") for part in available))
    return available, valid, complete


def owned_device(raw, identifier):
    require(bool(re.fullmatch(r"[0-9A-Fa-f-]{36}", identifier)))
    require(str(uuid.UUID(identifier)).upper() == identifier.upper())
    value = json.loads(raw)
    matches = [device for devices in value.get("devices", {}).values() for device in devices
               if device.get("udid", "").upper() == identifier.upper()]
    require(len(matches) == 1)
    device = matches[0]
    require(device.get("isAvailable") is True and device.get("state") == "Booted")
    require(isinstance(device.get("name"), str) and device["name"].startswith("Locklark-CI-"))


def references(value):
    found = {}

    def visit(node):
        if isinstance(node, dict):
            type_value = node.get("_type")
            if isinstance(type_value, dict) and type_value.get("_name") == "Reference":
                identifier = node.get("id", {}).get("_value")
                target = node.get("targetType", {}).get("_value", "")
                require(isinstance(identifier, str) and 0 < len(identifier) <= 1024)
                require(isinstance(target, str))
                found[identifier] = target
            for child in node.values():
                visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(value)
    return found


class EvidenceVerifier:
    def __init__(self, args):
        self.args = args
        parent = pathlib.Path(args.artifacts).resolve()
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="ios-ui-evidence-", dir=parent))
        self.stage = "prerequisites"
        self.files = []
        self.canaries = []
        self.counter = 0
        self.manifest_valid = False
        self.manifest_complete = False
        self.export_complete = False

    def command(self, name, arguments, timeout=90):
        self.counter += 1
        prefix = self.root / f"{self.counter:04d}-{name}"
        output, error = prefix.with_suffix(".stdout"), prefix.with_suffix(".stderr")
        self.files.extend((output, error))
        with output.open("xb") as stdout, error.open("xb") as stderr:
            try:
                result = subprocess.run([self.args.xcrun, *arguments], stdout=stdout, stderr=stderr, timeout=timeout)
                status = result.returncode
            except (subprocess.TimeoutExpired, OSError):
                status = -1
        return status == 0, output

    def load_manifest(self):
        require(self.args.owned_simulator)
        self.stage = "owned-simulator"
        ok, output = self.command("devices", ["simctl", "list", "devices", "--json"])
        require(ok)
        owned_device(output.read_bytes(), self.args.simulator)
        self.stage = "manifest"
        ok, output = self.command("runner-container", ["simctl", "get_app_container", self.args.simulator, RUNNER_BUNDLE, "data"])
        require(ok)
        raw_path = output.read_text().strip()
        require(raw_path and "\n" not in raw_path and "\r" not in raw_path)
        container = pathlib.Path(raw_path).resolve(strict=True)
        require(container.is_dir())
        source = container / MANIFEST
        require(source.is_file() and not source.is_symlink() and source.resolve().is_relative_to(container))
        attributes = source.stat()
        require(stat.S_ISREG(attributes.st_mode) and attributes.st_uid == os.geteuid()
                and stat.S_IMODE(attributes.st_mode) & 0o077 == 0 and attributes.st_size <= 1 << 20)
        raw = source.read_bytes()
        destination = self.root / "runner-canaries-private.json"
        destination.write_bytes(raw)
        destination.chmod(0o600)
        # Retain all available values even for an incomplete/invalid manifest,
        # so a failed UI case still gets the strongest scan possible.
        self.canaries, self.manifest_valid, self.manifest_complete = parse_canaries(raw)
        require(self.manifest_valid)

    def get_object(self, identifier=None):
        tail = ["--path", str(pathlib.Path(self.args.xcresult).resolve()), "--format", "json"]
        if identifier:
            tail.extend(("--id", identifier))
        for prefix in (["xcresulttool", "get", "object", "--legacy"], ["xcresulttool", "get"]):
            ok, output = self.command("xcresult-json", [*prefix, *tail])
            if ok:
                try:
                    return json.loads(output.read_bytes())
                except (ValueError, UnicodeError):
                    pass
        raise EvidenceFailure()

    def export_data(self, identifier):
        prefixes = (["xcresulttool", "export", "object", "--legacy"],
                    ["xcresulttool", "export", "object"], ["xcresulttool", "export"])
        for attempt, prefix in enumerate(prefixes):
            destination = self.root / ("payload-" + hashlib.sha256(identifier.encode()).hexdigest() + f"-{attempt}.private")
            tail = ["--type", "file", "--path", str(pathlib.Path(self.args.xcresult).resolve()),
                    "--id", identifier, "--output-path", str(destination)]
            ok, _ = self.command("xcresult-payload", [*prefix, *tail])
            if destination.is_file() and not destination.is_symlink():
                destination.chmod(0o600)
                self.files.append(destination)
                if ok:
                    return
        raise EvidenceFailure()

    def export_xcresult(self):
        self.stage = "xcresult-export"
        require(pathlib.Path(self.args.xcresult).is_dir())
        root = self.get_object()
        pending = deque(references(root).items())
        seen = set()
        complete = True
        while pending:
            identifier, target = pending.popleft()
            if identifier in seen:
                continue
            seen.add(identifier)
            require(len(seen) <= 2048)
            try:
                if target == "Data":
                    self.export_data(identifier)
                else:
                    try:
                        value = self.get_object(identifier)
                    except EvidenceFailure:
                        self.export_data(identifier)
                    else:
                        pending.extend(references(value).items())
            except Exception:
                complete = False
        require(complete)
        self.export_complete = True

    def scan(self):
        self.stage = "canary-scan"
        for path in self.files:
            scan_file(path, self.canaries)

    def execute(self):
        source = pathlib.Path(self.args.runtime_log)
        require(source.is_file())
        destination = self.root / "runtime-private.log"
        shutil.copyfile(source, destination)
        destination.chmod(0o600)
        self.files.append(destination)
        failures = []
        try:
            self.load_manifest()
        except Exception:
            failures.append(self.stage)
        try:
            self.export_xcresult()
        except Exception:
            failures.append(self.stage)
        try:
            self.scan()
        except Exception:
            failures.insert(0, "canary-scan")
        if not self.manifest_complete or self.args.test_exit_code != 0:
            failures.append("test-outcome")
        self.stage = failures[0] if failures else "complete"
        return not failures


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--simulator", required=True)
    result.add_argument("--owned-simulator", action="store_true")
    result.add_argument("--runtime-log", required=True)
    result.add_argument("--xcresult", required=True)
    result.add_argument("--test-exit-code", required=True, type=int)
    result.add_argument("--xcrun", default="xcrun")
    result.add_argument("--artifacts", default="/tmp/locklark-validation")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    os.umask(0o077)
    verifier = None
    success = False
    try:
        verifier = EvidenceVerifier(args)
        success = verifier.execute()
    except (Exception, KeyboardInterrupt):
        pass
    finally:
        if verifier:
            stage = verifier.stage if verifier.stage in STAGES else "prerequisites"
            # A top-level failure must still scan every available private file.
            try:
                verifier.scan()
            except Exception:
                success = False
                stage = "canary-scan"
            result = {"success": success, "stage": "complete" if success else stage,
                      "manifest_valid": verifier.manifest_valid, "manifest_complete": verifier.manifest_complete,
                      "xcresult_export_complete": verifier.export_complete, "files_scanned": len(verifier.files)}
            (verifier.root / "result.json").write_text(json.dumps(result) + "\n")
        print("PASS: iOS UI evidence canary scan" if success else "FAIL: iOS UI evidence validation")
        if verifier:
            print("Private iOS UI evidence: " + str(verifier.root))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
