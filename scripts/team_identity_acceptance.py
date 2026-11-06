"""Real Linux Secret Service acceptance in an owned, isolated D-Bus session.

This proves native protected storage and dual-key possession, not biometrics,
per-access OS prompting, team admission, or a durable product profile store.

Artifact provenance is an external prerequisite: a trusted operator must first
check the reviewed source manifest, independently build the fixture from that
source, and freeze its private artifact and expected SHA-256. This controller
checks that supplied digest before use and after completion; a digest cannot
establish where an arbitrary executable came from. For example, from the
reviewed checkout (with logs kept private):

    umask 077
    sha256sum -c /tmp/locklark-validation/team-identity-acceptance-reviewed.sha256
    GOTOOLCHAIN=go1.27.3 /tmp/locklark-tools/go/bin/go build \\
      -o /tmp/locklark-tools/team-identity-fixture-reviewed ./scripts/team_identity_fixture
    fixture_digest=$(sha256sum /tmp/locklark-tools/team-identity-fixture-reviewed)
    fixture_digest=${fixture_digest%% *}
    python3 scripts/team_identity_acceptance.py \\
      --fixture-bin /tmp/locklark-tools/team-identity-fixture-reviewed \\
      --fixture-sha256 "$fixture_digest" \\
      --dependency-root /tmp/locklark-tools/secret-service-debian \\
      --artifacts /tmp/locklark-validation/team-identity-native-reviewed

Do not replace the frozen executable or reviewed inputs during a run. Fixture
and dependency arguments must be canonical absolute paths under trusted
ancestors. Runtime artifacts contain synthetic private oracle inputs and must
not be published.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import tarfile
import time
from urllib.parse import quote_from_bytes
from xml.sax.saxutils import escape

PACKAGES = {
    "gnome-keyring": ("48.0-1", "efcfab150b9841aecfe5311e3987bfcba73ac7cbc72e157529f0f8cc6281f8ce"),
    "libsecret-tools": ("0.21.7-1", "1b9a6f4c53cedaa796e9090f1e8d1916031d60262515c8c1a4eeb5245fc8233e"),
    "libgck-1-0": ("3.41.2-3", "dd2d940427cf3215e8aa23647c2524d347597d72d723a292402d741936fe92f9"),
    "libgcr-base-3-1": ("3.41.2-3", "2025724cb3df76d020c61d07d77d674df1f7d502db939cde7bed9d45a3b12923"),
}
GROUPS = (
    "native adapter refuses absent bus",
    "native adapter refuses absent service",
    "failed protection remains unknown without fallback",
    "owned unlocked Secret Service isolation",
    "real native storage across fresh processes",
    "independent libsecret lookup and deletion",
    "generated device protection remains pending",
    "fresh operation proves both keys once",
    "wrong enrollment consumes the proof attempt",
    "daemon loss refuses without fallback",
    "owned daemon restart preserves the protected identity",
    "owned service cleanup",
    "complete runtime canary scan",
)
STAGES = {"prerequisites", "bus", "provider", "unlock", "fixture", "storage", "identity", "proof", "cleanup", "privacy"}
MODES = {"pins", "store", "load", "delete", "unavailable", "protect", "protect-unavailable", "proof", "load-unavailable", "wrong-target"}
STAGES.update("fixture-" + mode for mode in MODES)


class Failure(Exception):
    def __init__(self, stage):
        self.stage = stage if stage in STAGES else "prerequisites"


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Failure("prerequisites")


def private_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
    Path(path).chmod(0o600)


def trusted_parent(path):
    """Reject aliases; a private leaf cannot hide a replaceable ancestor."""
    path = Path(path)
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise Failure("prerequisites")
    for component in reversed((path, *path.parents)):
        info = component.lstat()
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022 and not sticky_root:
            raise Failure("prerequisites")
    return path


def trusted_file(path, *, packaged_root=None, seen=None):
    path = Path(path)
    trusted_parent(path.parent)
    info = path.lstat()
    if info.st_uid not in {0, os.geteuid()}:
        raise Failure("prerequisites")
    if stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022:
        return path
    # Debian SONAME links are fixed by the authenticated package below. Follow
    # only links inside that same trusted extraction, checking every parent and
    # target rather than trusting a final private leaf alone.
    if stat.S_ISLNK(info.st_mode) and packaged_root is not None:
        seen = set() if seen is None else seen
        if path in seen or len(seen) >= 16:
            raise Failure("prerequisites")
        seen.add(path)
        target = Path(os.path.normpath(path.parent / os.readlink(path)))
        if not target.is_relative_to(packaged_root):
            raise Failure("prerequisites")
        return trusted_file(target, packaged_root=packaged_root, seen=seen)
    raise Failure("prerequisites")


def verify_fixture(path, expected):
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise Failure("prerequisites")
    path = trusted_file(path)
    if not os.access(path, os.X_OK):
        raise Failure("prerequisites")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise Failure("prerequisites")
    return path


def validate_private_session(root):
    # The hidden child entrypoint must never accept the user's existing bus,
    # HOME or XDG directories, even if invoked directly by accident.
    trusted_parent(root)
    info = root.lstat()
    if not root.is_absolute() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise Failure("prerequisites")
    expected = {"HOME": "home", "XDG_DATA_HOME": "data", "XDG_CONFIG_HOME": "config", "XDG_CACHE_HOME": "cache", "XDG_RUNTIME_DIR": "runtime"}
    for key, name in expected.items():
        if os.environ.get(key) != str(root / name):
            raise Failure("prerequisites")
        info = (root / name).lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise Failure("prerequisites")
    socket = root / "runtime" / "bus"
    address = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")
    if not re.fullmatch(re.escape("unix:path=" + str(socket)) + r"(?:,guid=[0-9a-f]{32})?", address):
        raise Failure("prerequisites")
    info = socket.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
        raise Failure("prerequisites")


def verify_dependencies(root):
    root = trusted_parent(root)
    prefix = root / "root"
    trusted_parent(prefix)
    trusted_parent(root / "downloads")
    manifest = json.loads(trusted_file(root / "manifest.json").read_text())
    rows = manifest.get("packages")
    if manifest.get("debian") != "trixie" or manifest.get("architecture") != "amd64" or not isinstance(rows, list) or len(rows) != len(PACKAGES):
        raise Failure("prerequisites")
    found = set()
    for row in rows:
        name = row.get("package")
        if name not in PACKAGES or name in found or (row.get("version"), row.get("sha256")) != PACKAGES[name]:
            raise Failure("prerequisites")
        found.add(name)
        package = trusted_file(root / "downloads" / Path(row["filename"]).name)
        if hashlib.sha256(package.read_bytes()).hexdigest() != PACKAGES[name][1]:
            raise Failure("prerequisites")
        result = subprocess.run(["/usr/bin/dpkg-deb", "--fsys-tarfile", str(package)], capture_output=True, timeout=15)
        if result.returncode or len(result.stdout) > 32 << 20:
            raise Failure("prerequisites")
        # Verify the code actually loaded from the extraction, not just the .deb.
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
            for member in archive:
                relative = Path(member.name.removeprefix("./"))
                if relative.is_absolute() or ".." in relative.parts:
                    raise Failure("prerequisites")
                target = prefix / relative
                if member.isfile():
                    trusted_file(target)
                    if target.is_symlink() or not target.is_file() or hashlib.sha256(archive.extractfile(member).read()).digest() != hashlib.sha256(target.read_bytes()).digest():
                        raise Failure("prerequisites")
                elif member.issym():
                    if not target.is_symlink() or os.readlink(target) != member.linkname:
                        raise Failure("prerequisites")
                    trusted_file(target, packaged_root=prefix)
                elif member.isdir():
                    trusted_parent(target)
    return prefix


class Session:
    def __init__(self, root, fixture, prefix, fixture_sha256):
        self.root, self.fixture, self.prefix = root, fixture, prefix
        self.fixture_sha256 = fixture_sha256
        self.stage = "prerequisites"
        self.daemon = None
        self.log = None
        self.serial = 0
        self.password = secrets.token_urlsafe(32).encode()
        self.value = secrets.token_urlsafe(40).encode()
        self.owner = secrets.token_bytes(32)
        self.publisher = secrets.token_bytes(32)
        self.sequencer = secrets.token_bytes(32)
        self.account = secrets.token_hex(32)
        self.member = secrets.token_hex(16)
        self.environment = dict(os.environ, GNOME_KEYRING_CONTROL=str(root / "runtime" / "keyring"))
        (root / "runtime" / "keyring").mkdir(mode=0o700)
        (root / "oracle").mkdir(mode=0o700)
        private_json(root / "oracle" / "canaries.json", [base64.b64encode(value).decode() for value in [self.password, self.value, self.owner, self.publisher, self.sequencer]])

    def passed(self, group):
        if group not in GROUPS:
            raise Failure("prerequisites")
        print("PASS: team identity " + group, flush=True)

    def command(self, argv, *, data=None, environment=None, stage="fixture", record_stdout=True, timeout=15):
        self.stage = stage
        self.serial += 1
        result = subprocess.run(argv, input=data, env=environment or self.environment, capture_output=True, timeout=timeout)
        path = self.root / ("command-%03d-private.log" % self.serial)
        path.write_bytes((result.stdout if record_stdout else b"") + result.stderr)
        path.chmod(0o600)
        return result

    def api(self, mode, values, *, environment=None):
        if mode not in MODES:
            raise Failure("prerequisites")
        verify_fixture(self.fixture, self.fixture_sha256)
        result = self.command([str(self.fixture), mode], data=json.dumps(values).encode(), environment=environment)
        if result.returncode or result.stdout != b"PASS: team identity fixture\n" or result.stderr:
            self.stage = "fixture-" + mode
            raise Failure(self.stage)

    def bus(self, method, name):
        result = self.command(["/usr/bin/gdbus", "call", "--session", "--dest", "org.freedesktop.DBus", "--object-path", "/org/freedesktop/DBus", "--method", "org.freedesktop.DBus." + method, name], stage="bus", timeout=3)
        if result.returncode:
            raise Failure("bus")
        return result.stdout.strip()

    def assert_provider_absent(self):
        if self.bus("NameHasOwner", "org.freedesktop.secrets") != b"(false,)":
            raise Failure("provider")

    def start(self):
        self.stage = "provider"
        self.log = (self.root / ("daemon-%03d-private.log" % self.serial)).open("wb")
        self.daemon = subprocess.Popen([str(self.prefix / "usr/bin/gnome-keyring-daemon"), "--foreground", "--unlock", "--components=secrets", "--control-directory", self.environment["GNOME_KEYRING_CONTROL"]], env=self.environment, stdin=subprocess.PIPE, stdout=self.log, stderr=self.log)
        self.daemon.stdin.write(self.password)
        self.daemon.stdin.close()
        deadline = time.monotonic() + 10
        while True:
            if self.daemon.poll() is not None:
                raise Failure("provider")
            if self.bus("NameHasOwner", "org.freedesktop.secrets") == b"(true,)":
                break
            if time.monotonic() >= deadline:
                raise Failure("provider")
            time.sleep(0.05)
        if self.bus("GetConnectionUnixProcessID", "org.freedesktop.secrets") != ("(uint32 %d,)" % self.daemon.pid).encode():
            raise Failure("provider")
        self.stage = "unlock"
        unlocked = self.command(["/usr/bin/gdbus", "call", "--session", "--dest", "org.freedesktop.secrets", "--object-path", "/org/freedesktop/secrets/collection/login", "--method", "org.freedesktop.DBus.Properties.Get", "org.freedesktop.Secret.Collection", "Locked"], stage="unlock", timeout=3)
        if unlocked.returncode or unlocked.stdout.strip() != b"(<false>,)":
            raise Failure("unlock")

    def stop(self):
        self.stage = "cleanup"
        if self.daemon is not None:
            if self.daemon.poll() is None:
                self.daemon.terminate()
                try:
                    self.daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.daemon.kill()
                    self.daemon.wait(timeout=5)
            self.daemon = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def run(self):
        common = {"id": self.account, "value": base64.b64encode(self.value).decode()}
        absent_bus = dict(self.environment, DBUS_SESSION_BUS_ADDRESS="unix:path=" + str(self.root / "runtime" / "absent"))
        self.api("unavailable", common, environment=absent_bus)
        self.passed(GROUPS[0])
        self.assert_provider_absent()
        self.api("unavailable", common)
        self.passed(GROUPS[1])
        pins_path = self.root / "pins.json"
        self.api("pins", {"owner_seed": base64.b64encode(self.owner).decode(), "publisher_seed": base64.b64encode(self.publisher).decode(), "sequencer_seed": base64.b64encode(self.sequencer).decode(), "output": str(pins_path)})
        pins = json.loads(pins_path.read_text())
        unknown_path = self.root / "unknown.json"
        self.api("protect-unavailable", {"pins": pins, "output": str(unknown_path)})
        unknown = json.loads(unknown_path.read_text())
        self.api("load-unavailable", {"pins": pins, "descriptor": unknown})
        if any(path.is_file() for name in ["home", "data", "config", "cache"] for path in (self.root / name).rglob("*")):
            raise Failure("storage")
        self.passed(GROUPS[2])
        self.start()
        self.passed(GROUPS[3])
        self.api("store", common)
        self.api("load", common)
        self.passed(GROUPS[4])
        lookup = self.command([str(self.prefix / "usr/bin/secret-tool"), "lookup", "service", "app.locklark.unlock.v1", "account", self.account], stage="storage", record_stdout=False)
        if lookup.returncode or lookup.stdout != self.value:
            raise Failure("storage")
        self.api("delete", common)
        missing = self.command([str(self.prefix / "usr/bin/secret-tool"), "lookup", "service", "app.locklark.unlock.v1", "account", self.account], stage="storage", record_stdout=False)
        if missing.returncode == 0 or missing.stdout:
            raise Failure("storage")
        self.passed(GROUPS[5])
        descriptor_path = self.root / "descriptor.json"
        self.api("protect", {"pins": pins, "output": str(descriptor_path)})
        descriptor = json.loads(descriptor_path.read_text())
        if descriptor.get("state") != "pending" or descriptor.get("role") != "device":
            raise Failure("identity")
        self.passed(GROUPS[6])
        proof = {"pins": pins, "descriptor": descriptor, "member": self.member, "owner_seed": base64.b64encode(self.owner).decode()}
        self.api("proof", proof)
        self.passed(GROUPS[7])
        self.api("wrong-target", proof)
        self.passed(GROUPS[8])
        self.stop()
        self.assert_provider_absent()
        self.api("unavailable", common)
        self.api("load-unavailable", {"pins": pins, "descriptor": descriptor})
        self.passed(GROUPS[9])
        self.start()
        self.api("proof", proof)
        self.passed(GROUPS[10])
        self.stop()
        self.assert_provider_absent()
        self.passed(GROUPS[11])


def privacy(root):
    manifest = root / "oracle" / "canaries.json"
    if not manifest.exists() or manifest.is_symlink() or manifest.stat().st_mode & 0o077:
        raise Failure("privacy")
    values = json.loads(manifest.read_text())
    if not isinstance(values, list) or len(values) != 5 or len(set(values)) != 5:
        raise Failure("privacy")
    patterns = set()
    for encoded in values:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) < 16:
            raise Failure("privacy")
        patterns.update((raw, base64.b64encode(raw), base64.urlsafe_b64encode(raw), raw.hex().encode(), raw.hex().upper().encode(), quote_from_bytes(raw, safe="").encode()))
    files = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise Failure("privacy")
        if path.is_file() and path != manifest:
            files += 1
            if path.stat().st_size > 16 << 20 or path.stat().st_mode & 0o077:
                raise Failure("privacy")
            raw = path.read_bytes()
            if any(pattern in raw for pattern in patterns):
                raise Failure("privacy")
    return files


def inner(args):
    validate_private_session(Path(args.artifacts))
    fixture = verify_fixture(Path(args.fixture_bin), args.fixture_sha256)
    prefix = verify_dependencies(Path(args.dependency_root))
    session = Session(Path(args.artifacts), fixture, prefix, args.fixture_sha256)
    try:
        session.run()
    except BaseException:
        print("FAIL: team identity acceptance at " + session.stage, flush=True)
        return 1
    finally:
        session.stop()
    return 0


def outer(args):
    os.umask(0o077)
    if sys.platform != "linux":
        raise Failure("prerequisites")
    fixture = verify_fixture(Path(args.fixture_bin), args.fixture_sha256)
    dependencies = trusted_parent(Path(args.dependency_root))
    prefix = verify_dependencies(dependencies)
    requested = Path(args.artifacts)
    if not requested.is_absolute() or requested.exists() or requested.name in {"", ".", ".."}:
        raise Failure("prerequisites")
    root = trusted_parent(requested.parent) / requested.name
    if len(os.fsencode(root / "runtime" / "bus")) > 100:
        raise Failure("prerequisites")
    root.mkdir(mode=0o700)
    for name in ["home", "data", "config", "cache", "runtime"]:
        (root / name).mkdir(mode=0o700)
    config = root / "bus.conf"
    config.write_text('<busconfig><type>session</type><listen>unix:path=' + escape(str(root / "runtime" / "bus")) + '</listen><auth>EXTERNAL</auth><policy context="default"><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(root / "home"), "XDG_DATA_HOME": str(root / "data"), "XDG_CONFIG_HOME": str(root / "config"), "XDG_CACHE_HOME": str(root / "cache"), "XDG_RUNTIME_DIR": str(root / "runtime"), "XDG_DATA_DIRS": str(prefix / "usr/share"), "LD_LIBRARY_PATH": str(prefix / "usr/lib/x86_64-linux-gnu")}
    command = ["/usr/bin/dbus-run-session", "--config-file", str(config), "--", sys.executable, str(Path(__file__).resolve()), "--private-session", "--fixture-bin", str(fixture), "--fixture-sha256", args.fixture_sha256, "--dependency-root", str(dependencies), "--artifacts", str(root)]
    runtime = root / "runtime-private.log"
    result = 1
    with runtime.open("wb") as log:
        child = subprocess.Popen(command, env=environment, stdout=log, stderr=log, start_new_session=True)
        try:
            result = child.wait(timeout=120)
        except BaseException:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
    public = runtime.read_text(errors="replace").splitlines()
    complete = []
    for group in GROUPS[:-1]:
        label = "PASS: team identity " + group
        if public.count(label) == 1:
            complete.append(label)
            print(label)
    scan_ok = False
    try:
        count = privacy(root)
        scan_ok = True
        print("PASS: team identity " + GROUPS[-1])
    except BaseException:
        count = 0
    verified_after = False
    actual = None
    try:
        actual = hashlib.sha256(trusted_file(fixture).read_bytes()).hexdigest()
        verify_fixture(fixture, args.fixture_sha256)
        verified_after = True
    except BaseException:
        pass
    okay = result == 0 and len(complete) == len(GROUPS) - 1 and scan_ok and verified_after
    private_json(root / "result.json", {"passed": okay, "groups": len(complete) + int(scan_ok), "scanned_files": count, "fixture_expected_sha256": args.fixture_sha256, "fixture_actual_sha256": actual, "fixture_verified_before": True, "fixture_verified_after": verified_after, "fixture_source_provenance": "external-reviewed-source-build-required", "dependency_manifest_sha256": hashlib.sha256((dependencies / "manifest.json").read_bytes()).hexdigest(), "os_prompt_claim": False, "team_admission_claim": False})
    if not okay:
        failure = "FAIL: team identity acceptance at prerequisites" if not verified_after else next((line for line in public if line in {"FAIL: team identity acceptance at " + stage for stage in STAGES}), "FAIL: team identity acceptance at privacy" if not scan_ok else "FAIL: team identity acceptance at fixture")
        print(failure)
        return 1
    return 0


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--fixture-bin", required=True)
    parser.add_argument("--fixture-sha256", required=True)
    parser.add_argument("--dependency-root", required=True)
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--private-session", action="store_true", help=argparse.SUPPRESS)
    try:
        args = parser.parse_args(argv)
        return inner(args) if args.private_session else outer(args)
    except BaseException:
        print("FAIL: team identity acceptance at prerequisites")
        return 1


if __name__ == "__main__":
    sys.exit(main())
