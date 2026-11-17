"""Real MyGo daily-tools acceptance through AT-SPI geometry and XTest.

Caller supplies an isolated DISPLAY and private dbus session. Product values
remain in private pipes and memory; only fixed phases and booleans are logged.
No product test switches, synthetic authorizations, or secret-stage screenshots.
"""
import base64
import hashlib
import hmac
import json
import os
import pathlib
import re
import select
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

from desktop_native_probe import PROBE_REASONS, safe_diagnostic
from browser_native_x11 import CONTROL_LABELS, FAILURE_REASONS, NATIVE_INITIAL_CANCEL_LABEL, safe_click_record
from desktop_clipboard_owner import current_owner
from desktop_native_fence_launch import NativeFenceLaunchError, launch_owned_desktop_child
from desktop_native_fence import NativeFenceClient


ROOT = pathlib.Path(__file__).resolve().parent.parent
TITLE = "Locklark · 本地金库"
MARKER = "Later independent synthetic clipboard owner"
OTP_WINDOW_SECONDS = 20
OTP_WINDOW_MIN_REMAINING = 18
OTP_WINDOW_TIMEOUT = 30
OTP_DIAGNOSTIC_PREFIX = "Desktop OTP failure diagnostic: "
OTP_DIAGNOSTIC_DELTA_LIMIT = 64
OTP_DIAGNOSTIC_LIMIT = 1024
UNAVAILABLE = "unavailable"
# Product encoding: newRecovery emits "LLR2-" + base32(32 bytes); the complete
# checkpoint form is 110 characters with "-" at index 57. Base32 letters, the
# digits 2-7 and "-" are unchanged by JSON string escaping and URL
# percent-encoding, so this canonical byte pattern also covers those forms.
RECOVERY_KIT_PATTERN = re.compile(rb"LLR2-[A-Z2-7]{52}-[A-Z2-7]{52}")
RECOVERY_KIT_TEXT = re.compile(r"LLR2-[A-Z2-7]{52}-[A-Z2-7]{52}")
LOCAL_SCENARIO = "local-vault-file-create"
NATIVE_INITIAL_SCENARIO = "native-initial-account-fanout"
NATIVE_INITIAL_TAGGED_SCENARIO = "native-initial-tagged-held-cancel"
NATIVE_INITIAL_SCENARIOS = (NATIVE_INITIAL_SCENARIO, NATIVE_INITIAL_TAGGED_SCENARIO)
LOCAL_SCENARIOS = (LOCAL_SCENARIO, *NATIVE_INITIAL_SCENARIOS)

NATIVE_INITIAL_BASIC_CASE = "NATIVE_INITIAL_BASIC"
NATIVE_INITIAL_HELD_CANCEL_CASE = "NATIVE_INITIAL_HELD_CANCEL"
NATIVE_INITIAL_LEGACY_CASE = "NATIVE_INITIAL_LEGACY"
NATIVE_INITIAL_CANCEL_BUDGET_SECONDS = 5.0
NATIVE_INITIAL_REQUIRED_READY_CHILDREN = 2

NATIVE_INITIAL_PRIVACY_FAILURE_CODES = frozenset({
    "recovery-kit",
    "known-value",
    "otp-code",
})
NATIVE_INITIAL_PRIVACY_FAILURE_UNCLASSIFIED = "privacy_failure"
NATIVE_INITIAL_PRIVACY_FAILURE_PREFIX = "PRIVACY"
NATIVE_INITIAL_PRIVACY_FAILURE_SEPARATOR = ":"


def native_initial_privacy_failure_category(value):
    if type(value) is str and value in NATIVE_INITIAL_PRIVACY_FAILURE_CODES:
        return value
    return NATIVE_INITIAL_PRIVACY_FAILURE_UNCLASSIFIED


def native_initial_privacy_failure_detail(value):
    return (NATIVE_INITIAL_PRIVACY_FAILURE_PREFIX +
            NATIVE_INITIAL_PRIVACY_FAILURE_SEPARATOR +
            native_initial_privacy_failure_category(value))


def local_scenario(scenario):
    return scenario in LOCAL_SCENARIOS


class NativeInitialPrivacyRegistry:
    """The one known-value/manifest registry shared by every aggregate case."""

    def __init__(self):
        self.values = set()
        self.codes = set()
        self.local_manifest_private_values = {}


def native_initial_host_paths(environ):
    """Return the distinct ordinary and tagged hosts, or None if unusable."""
    ordinary = environ.get("LOCKLARK_DESKTOP_HOST")
    tagged = environ.get("LOCKLARK_DESKTOP_FENCE_HOST")
    if not ordinary or not tagged:
        return None
    if os.path.realpath(ordinary) == os.path.realpath(tagged):
        return None
    return ordinary, tagged
WRONG_RECOVERY_CONFIRMATION = "not-the-issued-recovery-code"
LOCAL_SETTINGS_DEFAULTS = {
    "security.autolock.minutes": 5,
    "security.clipboard.clearAfterSeconds": 30,
    "security.autolock.onSleep": True,
    "security.autolock.onDeviceLock": True,
    "security.autolock.onWindowClose": True,
    "security.revealPasswords": False,
    "privacy.checkHibp": False,
    "appearance.theme": "system",
    "appearance.interfaceDensity": "comfortable",
    "app.keepInTray": True,
    "app.defaultVaultForSaving": "",
}
LOCAL_PROJECTION_FIELDS = (
    "manifest_personal", "manifest_backend", "companion_present",
    "manifest_digest", "journal_present", "archive_present",
    "private_modes", "backend_hash_matches", "factors_absent",
)
LOCAL_PROFILE_ENTRY_LIMIT = 128
LOCAL_PROFILE_FILE_LIMIT = 64 << 10
LOCAL_VAULT_ID = re.compile(r"^[0-9a-f]{32}$")
LOCAL_VAULT_LABEL_SEPARATOR = " · "
LOCAL_VAULT_BIDI_CONTROLS = frozenset({
    0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
})
# Actual select emitter's static pointer label. The request's dynamic vault
# label is never the emitted click label and never enters this response.
LOCAL_VAULT_TARGET_CLICK_LABEL = "pointer"
PRIVACY_FAILURE_PREFIX = "Desktop native privacy barrier: failed reason="
CLEANUP_FAILURE_PREFIX = "Desktop native cleanup failed reason="


class AcceptanceFailure(Exception):
    pass


def require(condition):
    if not condition:
        raise AcceptanceFailure()


def local_vault_valid_name(value):
    """Exact reviewed backend ValidName shape for private display derivation."""
    if type(value) is not str:
        return False
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if not 1 <= len(raw) <= 255 or b"\x00" in raw:
        return False
    if value in (".", "..") or value[0] in ". " or value[-1] in ". ":
        return False
    for char in value:
        codepoint = ord(char)
        if char in "/\\" or codepoint < 0x20 or codepoint == 0x7f:
            return False
    return True


def local_vault_display_name(value):
    """Reviewed helper display copy: visible bidi escapes plus backslash escape."""
    out = []
    for char in value:
        codepoint = ord(char)
        if codepoint in LOCAL_VAULT_BIDI_CONTROLS:
            out.append("\\u%04X" % codepoint)
        elif char == "\\":
            out.append("\\\\")
        else:
            out.append(char)
    return "".join(out)


def local_vault_display_labels(manifests):
    """Whole-list reviewed normal labels; duplicates/invalid shapes refuse."""
    if type(manifests) not in (list, tuple) or not manifests:
        raise AcceptanceFailure()
    ids, names = [], []
    seen_ids = set()
    for manifest in manifests:
        if type(manifest) is not dict:
            raise AcceptanceFailure()
        vault_id, name = manifest.get("vault_id"), manifest.get("name")
        if type(vault_id) is not str or LOCAL_VAULT_ID.fullmatch(vault_id) is None:
            raise AcceptanceFailure()
        if not local_vault_valid_name(name):
            raise AcceptanceFailure()
        if vault_id in seen_ids:
            raise AcceptanceFailure()
        seen_ids.add(vault_id)
        ids.append(vault_id)
        names.append(name)
    labels = []
    for vault_id, name in zip(ids, names):
        prefix_len = 8
        for other in ids:
            if other == vault_id:
                continue
            common = 0
            for left, right in zip(vault_id, other):
                if left != right:
                    break
                common += 1
            prefix_len = max(prefix_len, min(common + 1, 32))
        labels.append(local_vault_display_name(name) + LOCAL_VAULT_LABEL_SEPARATOR + vault_id[:prefix_len])
    if len(set(labels)) != len(labels):
        raise AcceptanceFailure()
    return labels


def local_vault_wrong_secret(secret):
    """One different canonical LL1 secret for a real wrong-factor attempt."""
    if type(secret) is not str or not secret.startswith("LL1-"):
        raise AcceptanceFailure()
    body = list(secret[4:])
    for index, char in enumerate(body):
        if char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567":
            body[index] = "A" if char != "A" else "B"
            candidate = "LL1-" + "".join(body)
            if candidate != secret:
                return candidate
            break
    raise AcceptanceFailure()


def local_vault_profile_dir(settings_path, personal_path):
    """Exact product profile root for this private settings/personal pair."""
    base = pathlib.Path(settings_path).parent / "vaultfile-workspace"
    digest = hashlib.sha256(str(personal_path).encode("utf-8")).hexdigest()
    return base / "profiles" / digest


def _local_vault_manifest_json(raw):
    def reject_constant(value):
        raise AcceptanceFailure()
    def reject_duplicates(pairs):
        record = {}
        for key, value in pairs:
            if key in record:
                raise AcceptanceFailure()
            record[key] = value
        return record
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=reject_constant,
                           object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise AcceptanceFailure() from None
    return value


def _validate_local_vault_manifest(record):
    required = {"version", "kind", "vault_id", "personal_file", "backend_root",
                "name", "journal", "archive"}
    if type(record) is not dict or set(record) != required:
        raise AcceptanceFailure()
    if type(record.get("version")) is not int or record["version"] != 1 or \
            record.get("kind") != "vault_file_create":
        raise AcceptanceFailure()
    if type(record.get("vault_id")) is not str or LOCAL_VAULT_ID.fullmatch(record["vault_id"]) is None:
        raise AcceptanceFailure()
    if not local_vault_valid_name(record.get("name")):
        raise AcceptanceFailure()
    for field in ("personal_file", "backend_root", "journal", "archive"):
        value = record.get(field)
        if type(value) is not str or not os.path.isabs(value) or os.path.normpath(value) != value:
            raise AcceptanceFailure()
    return record


def _parse_local_vault_manifest(raw):
    return _validate_local_vault_manifest(_local_vault_manifest_json(raw))


def _local_vault_manifest_spans(raw):
    """Return only the top-level name/vault_id value byte spans of a valid manifest."""
    try:
        text = raw.decode("utf-8")
        decoder = json.JSONDecoder()
        index, length = 0, len(text)

        def whitespace(value):
            while value < length and text[value] in " \t\r\n":
                value += 1
            return value

        index = whitespace(index)
        if index >= length or text[index] != "{":
            raise AcceptanceFailure()
        index += 1
        seen, spans = set(), []
        while True:
            index = whitespace(index)
            if index < length and text[index] == "}":
                index += 1
                break
            key, index = decoder.raw_decode(text, index)
            if type(key) is not str or key in seen:
                raise AcceptanceFailure()
            seen.add(key)
            index = whitespace(index)
            if index >= length or text[index] != ":":
                raise AcceptanceFailure()
            start = whitespace(index + 1)
            value, index = decoder.raw_decode(text, start)
            if key in ("name", "vault_id"):
                if type(value) is not str:
                    raise AcceptanceFailure()
                spans.append((start + 1, index - 1))
            index = whitespace(index)
            if index < length and text[index] == ",":
                index += 1
                continue
            if index < length and text[index] == "}":
                index += 1
                break
            raise AcceptanceFailure()
        if whitespace(index) != length or len(spans) != 2:
            raise AcceptanceFailure()
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise AcceptanceFailure() from None
    return sorted((len(text[:start].encode("utf-8")),
                   len(text[:end].encode("utf-8"))) for start, end in spans)


def _stable_local_vault_manifest(path, expected):
    """No-follow bounded reread; fail closed unless it is the captured snapshot."""
    path = pathlib.Path(path)
    expected_identity = (expected["device"], expected["inode"])
    try:
        before = os.lstat(path)
    except OSError:
        raise AcceptanceFailure() from None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or \
            (before.st_dev, before.st_ino) != expected_identity:
        raise AcceptanceFailure()
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != expected["size"] or \
                (opened.st_dev, opened.st_ino) != expected_identity:
            raise AcceptanceFailure()
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            raw = source.read(LOCAL_PROFILE_FILE_LIMIT + 1)
    except OSError:
        raise AcceptanceFailure() from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(raw) > LOCAL_PROFILE_FILE_LIMIT or len(raw) != expected["size"] or \
            hashlib.sha256(raw).digest() != expected["digest"]:
        raise AcceptanceFailure()
    record = _parse_local_vault_manifest(raw)
    if record["name"] != expected["name"] or record["vault_id"] != expected["vault_id"]:
        raise AcceptanceFailure()
    try:
        after = os.lstat(path)
    except OSError:
        raise AcceptanceFailure() from None
    if stat.S_ISLNK(after.st_mode) or not stat.S_ISREG(after.st_mode) or \
            after.st_size != expected["size"] or \
            (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
        raise AcceptanceFailure()
    return raw


def _local_manifest_guard(manifest):
    try:
        return {"name": manifest["name"], "vault_id": manifest["vault_id"],
                "device": manifest["device"], "inode": manifest["inode"],
                "size": manifest["size"], "digest": manifest["digest"]}
    except (KeyError, TypeError):
        raise AcceptanceFailure() from None


def read_local_vault_manifests(profile_dir):
    """Bounded read of this run's private profile manifests only."""
    profile_dir = pathlib.Path(profile_dir)
    try:
        info = os.lstat(profile_dir)
    except OSError:
        raise AcceptanceFailure() from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise AcceptanceFailure()
    try:
        entries = list(os.scandir(profile_dir))
    except OSError:
        raise AcceptanceFailure() from None
    if len(entries) > LOCAL_PROFILE_ENTRY_LIMIT:
        raise AcceptanceFailure()
    manifests = []
    for entry in entries:
        if not entry.name.endswith(".json"):
            continue
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            raise AcceptanceFailure()
        try:
            entry_info = entry.stat(follow_symlinks=False)
        except OSError:
            raise AcceptanceFailure() from None
        if not stat.S_ISREG(entry_info.st_mode) or entry_info.st_size > LOCAL_PROFILE_FILE_LIMIT:
            raise AcceptanceFailure()
        descriptor = -1
        try:
            descriptor = os.open(entry.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            opened_info = os.fstat(descriptor)
            if not stat.S_ISREG(opened_info.st_mode) or \
                    opened_info.st_size > LOCAL_PROFILE_FILE_LIMIT or \
                    (opened_info.st_dev, opened_info.st_ino) != (entry_info.st_dev, entry_info.st_ino):
                raise AcceptanceFailure()
            with os.fdopen(descriptor, "rb", closefd=True) as source:
                descriptor = -1
                raw = source.read(LOCAL_PROFILE_FILE_LIMIT + 1)
        except OSError:
            raise AcceptanceFailure() from None
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if len(raw) > LOCAL_PROFILE_FILE_LIMIT:
            raise AcceptanceFailure()
        record = _parse_local_vault_manifest(raw)
        manifests.append({"path": entry.path, "name": record["name"],
                          "vault_id": record["vault_id"],
                          "device": opened_info.st_dev, "inode": opened_info.st_ino,
                          "size": len(raw), "digest": hashlib.sha256(raw).digest()})
    manifests.sort(key=lambda item: item["path"])
    return manifests


def _local_vault_pointer_state(value):
    if type(value) is not dict or set(value) != {"x", "y", "button_mask", "pointer_available"}:
        return False
    if any(type(value.get(key)) is not int for key in ("x", "y", "button_mask")):
        return False
    return type(value.get("pointer_available")) is bool


def _local_vault_select_click(value):
    if type(value) is not dict or set(value) != {"label", "x", "y", "before", "after", "x_test"}:
        return False
    if value.get("label") != LOCAL_VAULT_TARGET_CLICK_LABEL:
        return False
    if type(value.get("x")) is not int or type(value.get("y")) is not int:
        return False
    if not _local_vault_pointer_state(value.get("before")) or \
            not _local_vault_pointer_state(value.get("after")):
        return False
    x_test = value.get("x_test")
    if type(x_test) is not dict or set(x_test) != {"motion", "down", "up"}:
        return False
    for key in ("motion", "down", "up"):
        if type(x_test.get(key)) is not bool or x_test[key] is not True:
            return False
    return True


def parse_local_vault_target_response(action, target_index, result):
    """Strict finite response for one dedicated local-vault target action."""
    if type(result) is not dict:
        raise AcceptanceFailure()
    if action == "select-sidebar":
        if set(result) != {"action", "target_index", "clicks"} or \
                result.get("action") != "select-sidebar" or \
                type(result.get("target_index")) is not int or \
                result["target_index"] != target_index:
            raise AcceptanceFailure()
        clicks = result.get("clicks")
        if type(clicks) is not list or len(clicks) != 1 or \
                not _local_vault_select_click(clicks[0]):
            raise AcceptanceFailure()
        return result
    if action == "wait-title":
        if set(result) != {"action", "matched"} or result.get("action") != "wait-title" or \
                type(result.get("matched")) is not bool or result["matched"] is not True:
            raise AcceptanceFailure()
        return result
    raise AcceptanceFailure()


def parse_local_vault_pair_projection(result):
    """Strict exactly-two-manifest, nine-true-boolean pair observer result."""
    expected = {"manifest_count", *LOCAL_PROJECTION_FIELDS}
    if type(result) is not dict or set(result) != expected:
        raise AcceptanceFailure()
    if type(result.get("manifest_count")) is not int or result["manifest_count"] != 2:
        raise AcceptanceFailure()
    for field in LOCAL_PROJECTION_FIELDS:
        if type(result.get(field)) is not bool or result[field] is not True:
            raise AcceptanceFailure()
    return result


def otp_diagnostic(copy_delta=None, failure_delta=None, clipboard_empty=None):
    """Project failure evidence onto the fixed OTP diagnostic line.

    Each delta is kept only when it is an exact ``int`` (not a bool) within
    ``[-64, 64]``; ``clipboard_empty`` only when it is an exact ``bool``.
    Everything else becomes ``unavailable``. The record has exactly the three
    fixed keys, no embedded newline, and fits the fixed prefix limit.
    """
    def delta(value):
        return value if type(value) is int and abs(value) <= OTP_DIAGNOSTIC_DELTA_LIMIT else UNAVAILABLE

    def empty(value):
        return value if type(value) is bool else UNAVAILABLE

    record = {"copy_window_delta": delta(copy_delta), "failure_window_delta": delta(failure_delta),
              "clipboard_empty": empty(clipboard_empty)}
    line = OTP_DIAGNOSTIC_PREFIX + json.dumps(record, separators=(",", ":"), ensure_ascii=True)
    require(line.isascii() and "\n" not in line and len(line.encode("utf-8")) <= OTP_DIAGNOSTIC_LIMIT)
    return line


class Acceptance:
    def __init__(self, *, native_fence_client=None, scenario=None, host=None, privacy=None):
        # Optional private pipe owner; None keeps the ordinary launch path.
        self.native_fence_client = native_fence_client
        self.privacy_registry = privacy
        self.stage = "setup"
        self.state = pathlib.Path(tempfile.mkdtemp(prefix="locklark-desktop-acceptance-"))
        self.diagnostics = self.state / "diagnostics"
        self.diagnostics.mkdir(mode=0o700)
        self.scenario = scenario if scenario is not None else os.environ.get("LOCKLARK_TEST_SCENARIO")
        if host is not None:
            selected_host = host
        elif self.scenario == NATIVE_INITIAL_TAGGED_SCENARIO:
            selected_host = os.environ["LOCKLARK_DESKTOP_FENCE_HOST"]
        else:
            selected_host = os.environ["LOCKLARK_DESKTOP_HOST"]
        self.host = pathlib.Path(selected_host).resolve(strict=True)
        require(bool(os.environ.get("DISPLAY")))
        self.env = self.scenario_env(self.scenario, os.environ)
        self.go = os.environ.get("LOCKLARK_GO", "go")
        fixture = os.environ.get("LOCKLARK_DESKTOP_FIXTURE")
        self.fixture_prebuilt = bool(fixture)
        self.fixture_binary = pathlib.Path(fixture).resolve() if fixture else self.state / "fixture-observer"
        self.fixture_path = self.state / "vault" / "fixture.json"
        # Exact validated local-vault manifests are private product state, not
        # ordinary diagnostics. Permit only each file's own name/ID while still
        # scanning it for every other registered value and every recovery kit.
        if privacy is None:
            self.values, self.codes = set(), set()
            self.local_manifest_private_values = {}
        else:
            self.values, self.codes = privacy.values, privacy.codes
            self.local_manifest_private_values = privacy.local_manifest_private_values
        self.started = time.time()
        self.app, self.probe = None, None
        self.reason = "acceptance"
        self.account_factor_submissions = 0
        self.target_factor_submissions = 0
        self.target_refreshes = 0
        self.actual_refresh_provenance = False
        self.last_refresh_item_count = 0
        self.a_locked = False
        self.a_locked_observed = False
        self.late_result_coverage = None
        self.case_coverage = None
        self.native_action = "none"
        self.last_native_click = {}
        self.native_failed_index = None
        self.native_x_error_codes = []
        self.native_elapsed_ms = 0
        self.probe_read_attempts_max = 0
        self.probe_operation = "none"
        self.probe_elapsed_ms = 0
        self.probe_healthy = True
        self.probe_diagnostic = {}
        self.foreign_owners = []
        self.foreign_observations = []
        self.output_lines = []
        # Copy probe bookkeeping, kept in memory only: the accepted sample and
        # its copy click (converted with otp_window only for deltas), and the
        # fixed record of the first failed copy.
        self.otp_copy = None
        self.otp_diagnostic = None
        # The recovery-kit barrier is armed before setup and close, so the
        # upcoming local-vault-file-create scenario is covered even when its
        # fixture reader never registers the dynamically issued kit.
        self.privacy_failure = None
        self.log = (self.state / "native.log").open("xb")
        os.chmod(self.state / "native.log", 0o600)

    @staticmethod
    def scenario_env(scenario, environ):
        """Only the local-vault scenario releases classic for its child app."""
        env = {**environ, "GOTOOLCHAIN": "go1.27.3"}
        if local_scenario(scenario):
            env.pop("LOCKLARK_DESKTOP_LAYOUT", None)
        return env

    @staticmethod
    def local_settings_document(vault_path):
        """Real dotted non-secret defaults plus the one local vault path."""
        return {**LOCAL_SETTINGS_DEFAULTS, "app.vaultPath": str(vault_path)}

    def app_command(self):
        if (getattr(self, "scenario", None) in LOCAL_SCENARIOS
                and getattr(self, "settings_path", None) is not None):
            return [str(self.host), "--settings", str(self.settings_path)]
        return [str(self.host)]

    def prepare_settings_dir(self):
        self.settings_dir = self.state / "settings"
        self.settings_dir.mkdir(mode=0o700)
        os.chmod(self.settings_dir, 0o700)
        self.settings_path = self.settings_dir / "settings.json"

    def write_private_settings_file(self):
        raw = json.dumps(self.local_settings_document(self.fixture["Path"]),
                         ensure_ascii=False).encode("utf-8")
        with os.fdopen(os.open(self.settings_path,
                               os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(raw)


    def write_private_settings(self):
        self.prepare_settings_dir()
        self.write_private_settings_file()

    def phase(self, value):
        self.stage = value
        self.emit("Desktop native stage: " + value)

    def emit(self, message):
        self.output_lines.append(message)
        print(message, flush=True)

    def command(self, args, payload=None, timeout=60):
        try:
            result = subprocess.run(args, cwd=ROOT, env=self.env, input=payload,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.reason = "external-command-timeout"
            raise AcceptanceFailure() from None
        if result.returncode:
            # Driver output is fixed, but still parse only its enum; a future
            # dependency error must never introduce an arbitrary exception body.
            match = re.search(rb"Native acceptance input failed \[([a-z-]+) action=([a-z-]+) index=(-?[0-9]+)\]", result.stderr)
            if match:
                self.native_failed_index = int(match[3])
                reason = match[1].decode("ascii")
                self.reason = "native-" + (reason if reason in FAILURE_REASONS.values() else "unexpected")
                codes = re.search(rb"\bx_codes=([0-9,]+)",result.stderr)
                if codes:
                    self.native_x_error_codes = [int(code) for code in codes[1].split(b",")[:16] if 0 <= int(code) <= 255]
            raise AcceptanceFailure()
        return result.stdout

    def input(self, actions=(), inspect=False, timeout=30):
        request = {"title": TITLE, "executable": str(self.host), "actions": actions, "inspect": inspect}
        # Labels come from a fixed public allowlist; never include text-entry
        # payloads or dynamic clipboard/display contents in action diagnostics.
        def action_name(action):
            label = action.get("click_label", action.get("wait_label"))
            return (("click:" if "click_label" in action else "wait:") + label
                    if label in CONTROL_LABELS else "inspect" if inspect else "input")

        self.native_action = action_name(actions[-1] if actions else {})
        self.native_failed_index = None
        self.native_x_error_codes = []
        started = time.monotonic()
        try:
            result = json.loads(self.command([sys.executable, str(ROOT / "scripts/browser_native_x11.py")],
                                            json.dumps(request).encode(), timeout=timeout))
            for click in result.get("clicks",[]):
                self.last_native_click = safe_click_record(click)
            return result
        except json.JSONDecodeError:
            self.reason = "native-response-json"
            raise AcceptanceFailure() from None
        except AcceptanceFailure:
            if self.native_failed_index == -1:
                self.native_action = "window-ready"
            elif self.native_failed_index is not None and 0 <= self.native_failed_index < len(actions):
                self.native_action = action_name(actions[self.native_failed_index])
            raise
        finally:
            self.native_elapsed_ms = round((time.monotonic() - started) * 1000)

    def click(self, label):
        self.input([{"click_label": label}])

    def wait(self, label):
        self.input([{"wait_label": label}])

    def fill(self, label, value):
        self.input([{"click_label": label}, {"key": "Control_L+a"}, {"text": value}])

    def controls(self):
        return self.input(inspect=True)["controls"]

    def eventually(self, check, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(0.05)
        raise AcceptanceFailure()

    def probe_request(self, request):
        op = request.get("op")
        self.probe_operation = op if op in ("clipboard", "display", "own-clipboard") else "unsupported"
        if not self.probe_healthy:
            self.reason = "probe-unavailable"
            raise AcceptanceFailure()
        started = time.monotonic()
        try:
            self.probe.stdin.write(json.dumps(request) + "\n")
            self.probe.stdin.flush()
            if not select.select([self.probe.stdout], [], [], 15)[0]:
                self.reason = "probe-response-timeout"
                self.probe_healthy = False
                raise AcceptanceFailure()
            line = self.probe.stdout.readline()
            if not line:
                self.reason = "probe-response-eof"
                self.probe_healthy = False
                raise AcceptanceFailure()
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                self.reason = "probe-response-json"
                self.probe_healthy = False
                raise AcceptanceFailure() from None
            attempts = result.get("read_attempts")
            if type(attempts) is int and 1 <= attempts <= 64:
                self.probe_read_attempts_max = max(self.probe_read_attempts_max, attempts)
            if result.get("ok") is not True:
                self.probe_diagnostic = safe_diagnostic(result.get("diagnostic"))
                reason = result.get("reason")
                self.reason = "probe-" + (reason if reason in PROBE_REASONS else "unexpected")
            require(result.get("ok") is True)
            return result
        except BrokenPipeError:
            self.reason = "probe-write-failed"
            self.probe_healthy = False
            raise AcceptanceFailure() from None
        finally:
            self.probe_elapsed_ms = round((time.monotonic() - started) * 1000)

    def clipboard(self, expected=()):
        return self.probe_request({"op": "clipboard", "expected": list(expected)})

    def assert_independent_clipboard(self, expected):
        # A fresh process never owns this selection and never initializes an
        # AT-SPI reader. Its response verifies the real external owner rather
        # than the owner's own GTK data cache. Values stay in the private pipe.
        self.probe_operation = "independent-clipboard"
        started = time.monotonic()
        try:
            result = subprocess.run([sys.executable,str(ROOT/"scripts/desktop_native_probe.py")],
                                    input=(json.dumps({"op":"clipboard","expected":[expected]})+"\n").encode(),
                                    stdout=subprocess.PIPE,stderr=self.log,env=self.env,timeout=15)
            if result.returncode:
                self.reason = "independent-clipboard-process"
                raise AcceptanceFailure()
            try:
                lines = [json.loads(line) for line in result.stdout.splitlines()]
            except json.JSONDecodeError:
                self.reason = "independent-clipboard-json"
                raise AcceptanceFailure() from None
            if len(lines) != 2 or lines[0].get("ready") is not True:
                self.reason = "independent-clipboard-protocol"
                raise AcceptanceFailure()
            response = lines[1]
            if response.get("ok") is not True:
                reason = response.get("reason")
                self.reason = "independent-"+(reason if reason in PROBE_REASONS else "unexpected")
                self.probe_diagnostic = safe_diagnostic(response.get("diagnostic"))
                raise AcceptanceFailure()
            if response.get("matches") != [True]:
                self.reason = "independent-clipboard-mismatch"
                raise AcceptanceFailure()
        except subprocess.TimeoutExpired:
            self.reason = "independent-clipboard-response-timeout"
            raise AcceptanceFailure() from None
        finally:
            self.probe_elapsed_ms = round((time.monotonic()-started)*1000)

    def start_foreign_owner(self, marker):
        worker = subprocess.Popen([sys.executable,str(ROOT/"scripts/desktop_clipboard_owner.py")],
                                  env=self.env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                  stderr=self.log,text=True,bufsize=1)
        self.foreign_owners.append(worker)
        worker.stdin.write(json.dumps({"marker":marker})+"\n")
        worker.stdin.flush()
        require(bool(select.select([worker.stdout],[],[],5)[0]))
        response = json.loads(worker.stdout.readline())
        require(response.get("ready") is True and response.get("requests") == 0)
        worker.clipboard_owner_id = response["expected_owner"]
        # Independent server round trip; no pre-read or foreign-client request.
        require(current_owner() == worker.clipboard_owner_id == response["owner"])
        return worker

    def foreign_request(self, worker, op):
        require(op in ("stats","respond"))
        worker.stdin.write(json.dumps({"op":op})+"\n")
        worker.stdin.flush()
        require(bool(select.select([worker.stdout],[],[],3)[0]))
        response = json.loads(worker.stdout.readline())
        require(response.get("ok") is True)
        return response

    def allow_foreign_reads(self, worker, observation):
        # Check the cumulative count at the explicit allow transition too;
        # a request arriving after the prior stats sample must still fail.
        response = self.foreign_request(worker,"respond")
        observation["requests_at_allow"] = response["requests"]
        if response["requests"] != 0:
            self.reason = "foreign-clipboard-request-before-allow"
            raise AcceptanceFailure()

    def finish_foreign_owner(self, worker):
        worker.terminate()
        try:
            worker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait(timeout=5)
        self.foreign_owners.remove(worker)

    def assert_foreign_silent(self, owner, case, ui_ready=True):
        time.sleep(1.25)  # Cover the product's one-second cleanup retry.
        stats = self.foreign_request(owner,"stats")
        unchanged = current_owner() == owner.clipboard_owner_id == stats["owner"]
        observation = {"case":case,"ui_ready":ui_ready,"requests":stats["requests"],
                       "payload_requests":stats["payload_requests"],"metadata_requests":stats["metadata_requests"],
                       "owner_unchanged":unchanged,"pre_read":False,"refusal_watch_ms":1250}
        self.foreign_observations.append(observation)
        if stats["requests"]:
            self.reason = "foreign-clipboard-request"
            raise AcceptanceFailure()
        if not ui_ready:
            self.reason = "foreign-cleanup-ui-timeout"
            raise AcceptanceFailure()
        if not unchanged:
            self.reason = "foreign-owner-changed"
            raise AcceptanceFailure()
        return observation

    def provider_acceptance(self):
        self.select("Daily provider login")
        self.phase("native-provider-large-unicode")
        value = self.fixture["ProviderValue"]
        require(len(value.encode("utf-8")) > 128<<10 and not value.isascii())
        self.click("复制密码")
        self.eventually(lambda:self.clipboard([value])["matches"] == [True])
        self.assert_independent_clipboard(value)
        self.phase("native-provider-own-page-clear")
        self.click("安全设置")
        self.wait("停用系统快捷解锁")
        self.assert_independent_clipboard("")
        self.click("金库")
        self.select("Daily provider login")
        self.phase("native-provider-same-value-new-owner")
        self.click("复制密码")
        self.eventually(lambda:self.clipboard([value])["matches"] == [True])
        original_owner = current_owner()
        foreign = self.start_foreign_owner(value)
        require(foreign.clipboard_owner_id != original_owner)
        started = time.monotonic()
        self.click("安全设置")
        ready = False
        remaining = 3-(time.monotonic()-started)
        if remaining > 0:
            try:
                self.input([{"wait_label":"停用系统快捷解锁"}],timeout=remaining)
                ready = True
            except AcceptanceFailure:
                pass
        observation = self.assert_foreign_silent(foreign,"same-value-page",ready)
        self.allow_foreign_reads(foreign,observation)
        self.assert_independent_clipboard(value)
        observation["post_cleanup_value_verified"] = True
        self.finish_foreign_owner(foreign)
        self.click("金库")

    def foreign_lock_case(self):
        self.select("Daily OTP login")
        self.phase("foreign-owner-lock-no-read")
        self.show_copy_otp()
        owner = self.start_foreign_owner(MARKER)
        started = time.monotonic()
        self.click("立即锁定")  # One real action; never repeated on timeout.
        locked = False
        remaining = 3-(time.monotonic()-started)
        if remaining > 0:
            try:
                self.input([{"wait_label":"解锁"}],timeout=remaining)
                locked = True
            except AcceptanceFailure:
                pass
        elapsed = round((time.monotonic()-started)*1000)
        time.sleep(1.25)  # Observe at least one complete cleanup retry interval.
        stats = self.foreign_request(owner,"stats")
        unchanged = current_owner() == owner.clipboard_owner_id == stats["owner"]
        observation = {"case":"lock","locked_ui":locked,"lock_elapsed_ms":elapsed,
                       "requests":stats["requests"],"payload_requests":stats["payload_requests"],
                       "metadata_requests":stats["metadata_requests"],"owner_unchanged":unchanged,"pre_read":False,"refusal_watch_ms":1250}
        self.foreign_observations.append(observation)
        if stats["requests"] != 0:
            self.reason = "foreign-clipboard-request"
            raise AcceptanceFailure()
        if not locked or elapsed > 3000:
            self.reason = "foreign-lock-ui-timeout"
            raise AcceptanceFailure()
        if not unchanged:
            self.reason = "foreign-owner-changed"
            raise AcceptanceFailure()
        require(self.displays_empty())
        # Only after cleanup results are captured, allow a user reader to ask
        # for the public marker. This cannot cache a response before Lock.
        self.allow_foreign_reads(owner,observation)
        self.assert_independent_clipboard(MARKER)
        require(current_owner() == owner.clipboard_owner_id)
        observation["post_cleanup_marker_verified"] = True

    def display(self, otp=False, expected=()):
        return self.probe_request({"op": "display", "pid": self.app.pid, "executable": str(self.host),
                                   "label": "已授权显示的验证码" if otp else "已授权显示的字段", "expected": list(expected)})

    def displays_empty(self):
        return all(self.display(otp=otp)["empty"] for otp in (False, True))

    def observe(self):
        result = json.loads(self.command([str(self.fixture_binary), "-fixture", str(self.fixture_path), "-private-pipe"]))
        require(result["audit_safe"] is True)
        for item in result["items"]:
            self.values.update(item[field] for field in ("Password", "Username", "OTP") if item[field])
        return result

    @staticmethod
    def target(snapshot, title):
        rows = [item for item in snapshot["items"] if item["title"] == title]
        require(len(rows) == 1)
        return rows[0]

    @staticmethod
    def events(snapshot, action):
        return [event for event in snapshot["events"] if event["action"] == action]

    @staticmethod
    def same_items(before, after):
        require(before["snapshot"] == after["snapshot"])
        require(sorted(before["items"], key=lambda item: item["id"]) == sorted(after["items"], key=lambda item: item["id"]))

    def select(self, title, state="active"):
        self.phase("select-" + {"Daily OTP login":"otp", "Daily other login":"other", "Daily generated login":"generated", "Daily archived login":"archived", "Daily trashed login":"trashed", "Daily provider login":"provider"}.get(title, "manual"))
        self.click(title + " · " + state)
        if state != "trashed":
            self.wait("显示密码")

    def unlock(self):
        self.account_factor_submissions = getattr(self, "account_factor_submissions", 0) + 1
        self.phase("unlock")
        self.input([{"click_label":"金库文件"}, {"key":"Control_L+a"}, {"text":self.fixture["Path"]},
                    {"click_label":"主密码"}, {"text":self.fixture["Password"]},
                    {"click_label":"使用应急资料…"},
                    {"click_label":"Secret Key"}, {"text":self.fixture["Secret"]}, {"click_label":"解锁"},
                    {"wait_label":"新建登录"}])

    def unlock_onevra_submit(self):
        self.account_factor_submissions = getattr(self, "account_factor_submissions", 0) + 1
        self.phase("unlock-onevra")
        self.input([{"click_label":"使用应急资料…"},
                    {"click_label":"主密码"}, {"text":self.fixture["Password"]},
                    {"click_label":"Secret Key"}, {"text":self.fixture["Secret"]},
                    {"click_label":"解锁"}])

    def unlock_onevra_wait(self):
        self.wait("新建登录")

    def unlock_onevra(self):
        self.unlock_onevra_submit()
        self.unlock_onevra_wait()

    def read_recovery(self):
        """Read one kit from the private pipe and register it immediately."""
        request = {"title": TITLE, "executable": str(self.host),
                   "expected_pid": self.app.pid, "preserve_focus": True,
                   "read_recovery": True}
        self.native_action = "read-recovery"
        self.native_failed_index = None
        self.native_x_error_codes = []
        started = time.monotonic()
        try:
            result = json.loads(self.command(
                [sys.executable, str(ROOT / "scripts/browser_native_x11.py")],
                json.dumps(request).encode(), timeout=15))
        except json.JSONDecodeError:
            self.reason = "native-response-json"
            raise AcceptanceFailure() from None
        finally:
            self.native_elapsed_ms = round((time.monotonic() - started) * 1000)
        kit = result.get("recovery") if isinstance(result, dict) else None
        # Establish that the pipe value is a kit, then register it before the
        # only remaining shape check or any failing UI step. A non-kit string
        # is never stored as a known value.
        require(isinstance(result, dict) and type(kit) is str and
                RECOVERY_KIT_TEXT.fullmatch(kit) is not None)
        self.values.add(kit)
        require(set(result) == {"recovery"})
        return kit

    def verify_local_vault(self):
        """Bounded read-only local projection; no unlock, publish or session."""
        workspace = self.settings_dir / "vaultfile-workspace"
        result = json.loads(self.command(
            [str(self.fixture_binary), "-fixture", str(self.fixture_path),
             "-verify-local", str(workspace)]))
        require(isinstance(result, dict) and
                set(result) == {"manifest_count", *LOCAL_PROJECTION_FIELDS})
        require(type(result.get("manifest_count")) is int and
                result["manifest_count"] == 1)
        for field in LOCAL_PROJECTION_FIELDS:
            require(type(result.get(field)) is bool and result[field] is True)
        return result

    def local_vault_profile_dir(self):
        return local_vault_profile_dir(self.settings_path, self.fixture["Path"])

    def read_local_vault_manifests(self):
        try:
            return read_local_vault_manifests(self.local_vault_profile_dir())
        except AcceptanceFailure:
            self.reason = "local-pair-profile"
            raise

    def local_vault_labels(self, manifests):
        try:
            return local_vault_display_labels(manifests)
        except AcceptanceFailure:
            self.reason = "local-pair-profile"
            raise

    def record_local_vault_a(self):
        manifests = self.read_local_vault_manifests()
        require(len(manifests) == 1)
        labels = self.local_vault_labels(manifests)
        self.local_a_manifest = manifests[0]
        self.local_a_label = labels[0]
        self.local_manifest_private_values.update({
            pathlib.Path(manifest["path"]): _local_manifest_guard(manifest)
            for manifest in manifests
        })
        for manifest, label in zip(manifests, labels):
            self.values.update((manifest["vault_id"], manifest["name"], label))

    def record_local_vault_b(self):
        manifests = self.read_local_vault_manifests()
        require(len(manifests) == 2)
        a_path = self.local_a_manifest.get("path")
        a_frozen_id = self.local_a_manifest.get("vault_id")
        a_index = next((index for index, manifest in enumerate(manifests)
                        if manifest.get("path") == a_path), None)
        require(a_index is not None)
        # A's original path and frozen ID are both immutable. An unchanged path
        # with a changed ID is a closed refusal, never a silent new A.
        require(manifests[a_index]["vault_id"] == a_frozen_id)
        b_index = 1 - a_index
        require(manifests[b_index]["path"] != a_path)
        require(manifests[b_index]["vault_id"] != a_frozen_id)
        labels = self.local_vault_labels(manifests)
        require(len(set(labels)) == 2)
        self.local_manifests = manifests
        # local_labels is explicitly [actual A, actual B]; indices are in the
        # same coordinate frame regardless of manifest filename sort order.
        self.local_a_index, self.local_b_index = 0, 1
        self.local_a_label, self.local_b_label = labels[a_index], labels[b_index]
        self.local_labels = [self.local_a_label, self.local_b_label]
        self.local_a_manifest, self.local_b_manifest = manifests[a_index], manifests[b_index]
        self.local_manifest_private_values.update({
            pathlib.Path(manifest["path"]): _local_manifest_guard(manifest)
            for manifest in manifests
        })
        for manifest, label in zip(manifests, labels):
            self.values.update((manifest["vault_id"], manifest["name"], label))

    def record_prebuilt_local_pair(self):
        manifests = self.read_local_vault_manifests()
        require(len(manifests) == 2)
        self.local_a_manifest = manifests[0]
        self.record_local_vault_b()

    def local_vault_target(self, action, labels, index):
        require(action in ("select-sidebar", "wait-title"))
        require(type(labels) in (list, tuple) and 1 <= len(labels) <= 2)
        require(type(index) is int and 0 <= index < len(labels))
        request = {"title": TITLE, "executable": str(self.host),
                   "expected_pid": self.app.pid,
                   "local_vault_target": {"action": action,
                                          "known_labels": list(labels),
                                          "target_index": index}}
        self.native_action = ("local-vault-select" if action == "select-sidebar"
                              else "local-vault-wait")
        self.native_failed_index = None
        self.native_x_error_codes = []
        started = time.monotonic()
        try:
            result = json.loads(self.command(
                [sys.executable, str(ROOT / "scripts/browser_native_x11.py")],
                json.dumps(request).encode(), timeout=15))
        except json.JSONDecodeError:
            self.reason = "native-response-json"
            raise AcceptanceFailure() from None
        finally:
            self.native_elapsed_ms = round((time.monotonic() - started) * 1000)
        try:
            parsed = parse_local_vault_target_response(action, index, result)
        except AcceptanceFailure:
            self.reason = "native-response-schema"
            raise
        if action == "select-sidebar":
            self.last_native_click = safe_click_record(parsed["clicks"][0])
        return parsed

    def select_local_vault(self, labels, index, phase):
        self.phase(phase)
        self.local_vault_target("select-sidebar", labels, index)
        # Click ACK is not selection proof. This is the separate exact-title
        # boolean proof after the target click.
        self.local_vault_target("wait-title", labels, index)

    def refresh_local_vault(self, labels, index, phase):
        self.select_local_vault(labels, index, phase)
        self.wait("显示上次验证结果")
        self.click("刷新本地文件库")
        self.wait("本次刷新已验证")
        snapshot = self.observe()
        require(snapshot.get("audit_safe") is True)
        items = snapshot.get("items")
        require(type(items) is list and len(items) > 0)
        self.last_refresh_item_count = len(items)
        self.target_refreshes = getattr(self, "target_refreshes", 0) + 1
        self.actual_refresh_provenance = True

    def create_local_vault_b(self):
        """Second real Onevra create through the same UI and fresh recovery."""
        self.phase("local-pair-create-b-open")
        self.wait("新建独立文件库")
        self.click("新建独立文件库")
        self.wait("主密码")
        self.wait("Secret Key")
        self.fill("主密码", self.fixture["Password"])
        self.fill("Secret Key", self.fixture["Secret"])
        self.click("准备创建")
        self.wait("重新输入恢复码")
        kit_b = self.read_recovery()
        require(kit_b != self.local_kit_a)
        self.phase("local-pair-create-b-publish")
        self.fill("重新输入恢复码", kit_b)
        self.click("确认并发布备份")
        self.wait("备份恢复码")
        self.phase("local-pair-create-b-complete")
        self.fill("主密码", self.fixture["Password"])
        self.fill("Secret Key", self.fixture["Secret"])
        self.fill("备份恢复码", kit_b)
        self.click("完成创建")
        self.wait("关闭本地基线视图")
        self.wait("已验证本地初始版本 · 远端状态未核实")
        require(self.controls()["关闭本地基线视图"]["present"] is True)
        self.record_local_vault_b()

    def local_vault_pair_flow(self):
        labels = self.local_labels
        a_index, b_index = self.local_a_index, self.local_b_index
        self.refresh_local_vault(labels, a_index, "local-pair-refresh-a")
        self.refresh_local_vault(labels, b_index, "local-pair-refresh-b")

        self.select_local_vault(labels, a_index, "local-pair-select-a-lock")
        self.wait("显示上次验证结果")
        self.click("锁定本地文件库")
        self.wait("本地文件库已锁定")
        self.refresh_local_vault(labels, b_index, "local-pair-refresh-b-after-lock")

        self.select_local_vault(labels, a_index, "local-pair-select-a-unlock")
        self.wait("解锁本地文件库")
        self.click("解锁本地文件库")
        self.wait("解锁独立文件库")
        wrong_password = self.fixture["Password"] + "-wrong"
        wrong_secret = local_vault_wrong_secret(self.fixture["Secret"])
        require(wrong_password != self.fixture["Password"] and wrong_secret != self.fixture["Secret"])
        self.values.update((wrong_password, wrong_secret))
        self.fill("主密码", wrong_password)
        self.fill("Secret Key", wrong_secret)
        self.target_factor_submissions = getattr(self, "target_factor_submissions", 0) + 1
        self.click("完整验证并解锁")
        self.wait("完整验证失败；请重新输入")
        self.fill("主密码", self.fixture["Password"])
        self.fill("Secret Key", self.fixture["Secret"])
        self.target_factor_submissions = getattr(self, "target_factor_submissions", 0) + 1
        self.click("完整验证并解锁")
        self.eventually(lambda: self.controls().get("解锁独立文件库", {}).get("present") is False)
        self.local_vault_target("wait-title", labels, a_index)
        self.wait("显示上次验证结果")
        self.click("刷新本地文件库")
        self.wait("本次刷新已验证")

        self.refresh_local_vault(labels, b_index, "local-pair-refresh-b-after-unlock")
        self.phase("local-pair-close-view")
        self.click("关闭本地基线视图")
        self.select_local_vault(labels, a_index, "local-pair-navigate-back-a")
        self.wait("显示上次验证结果")

    def verify_local_vault_pair(self):
        workspace = self.settings_dir / "vaultfile-workspace"
        try:
            result = json.loads(self.command(
                [str(self.fixture_binary), "-fixture", str(self.fixture_path),
                 "-verify-local-pair", str(workspace)]))
        except json.JSONDecodeError:
            self.reason = "local-pair-observer-json"
            raise AcceptanceFailure() from None
        try:
            return parse_local_vault_pair_projection(result)
        except AcceptanceFailure:
            self.reason = "local-pair-observer"
            raise

    def final_local_vault_pair_validation(self, before_ids):
        self.phase("local-pair-observer")
        self.verify_local_vault_pair()
        after = self.observe()
        require(after.get("audit_safe") is True)
        after_ids = sorted(item["id"] for item in after["items"])
        require(after_ids == before_ids)
        self.phase("local-pair-account-lock")
        self.click("立即锁定")
        self.wait("使用应急资料…")
        controls = self.controls()
        require(controls.get("使用应急资料…", {}).get("present") is True)
        for label in ("刷新本地文件库", "锁定本地文件库",
                      "解锁本地文件库", "关闭本地基线视图"):
            require(controls.get(label, {}).get("present") is False)

    def local_vault_file_create(self):
        """One real Onevra A closure; no product method or fixture create."""
        self.phase("local-create-open")
        before = self.observe()
        before_ids = sorted(item["id"] for item in before["items"])
        self.wait("新建独立文件库")
        self.click("新建独立文件库")
        # The prepare button is correctly disabled until both factors have
        # content. Wait on the real input controls, fill them, then let the
        # original click perform the enabled check on the button itself.
        self.wait("主密码")
        self.wait("Secret Key")
        self.fill("主密码", self.fixture["Password"])
        self.fill("Secret Key", self.fixture["Secret"])
        self.click("准备创建")
        self.wait("重新输入恢复码")
        kit = self.read_recovery()
        self.phase("local-create-wrong-confirm")
        self.fill("重新输入恢复码", WRONG_RECOVERY_CONFIRMATION)
        self.click("确认并发布备份")
        self.wait("恢复码未逐字匹配")
        require(self.controls()["备份恢复码"]["present"] is False)
        self.phase("local-create-publish")
        self.fill("重新输入恢复码", kit)
        self.click("确认并发布备份")
        self.wait("备份恢复码")
        self.phase("local-create-complete")
        self.fill("主密码", self.fixture["Password"])
        self.fill("Secret Key", self.fixture["Secret"])
        self.fill("备份恢复码", kit)
        self.click("完成创建")
        self.wait("关闭本地基线视图")
        self.wait("已验证本地初始版本 · 远端状态未核实")
        require(self.controls()["关闭本地基线视图"]["present"] is True)
        self.local_kit_a = kit
        self.record_local_vault_a()
        self.phase("local-create-baseline")
        after = self.observe()
        require(before["audit_safe"] is True and after["audit_safe"] is True)
        after_ids = sorted(item["id"] for item in after["items"])
        require(len(before_ids) == len(after_ids) and before_ids == after_ids)
        self.verify_local_vault()
        self.create_local_vault_b()
        self.local_vault_pair_flow()
        self.final_local_vault_pair_validation(before_ids)

    def native_initial_pair_evidence(self, expected_account_submits, expected_target_submits, phase_prefix):
        require(type(expected_account_submits) is int and expected_account_submits >= 1)
        require(type(expected_target_submits) is int and expected_target_submits >= 0)
        require(getattr(self, "account_factor_submissions", 0) == expected_account_submits)
        require(getattr(self, "target_factor_submissions", 0) == expected_target_submits)
        self.record_prebuilt_local_pair()
        before = self.observe()
        before_ids = sorted(item["id"] for item in before["items"])
        labels = self.local_labels
        a_index, b_index = self.local_a_index, self.local_b_index
        self.refresh_local_vault(labels, a_index, phase_prefix + "-refresh-a")
        self.refresh_local_vault(labels, b_index, phase_prefix + "-refresh-b")
        require(getattr(self, "target_refreshes", 0) >= 2)
        require(getattr(self, "actual_refresh_provenance", False) is True)
        require(getattr(self, "last_refresh_item_count", 0) > 0)
        self.select_local_vault(labels, a_index, phase_prefix + "-select-a-lock")
        self.wait("显示上次验证结果")
        self.click("锁定本地文件库")
        self.wait("本地文件库已锁定")
        self.a_locked = True
        self.refresh_local_vault(labels, b_index, phase_prefix + "-refresh-b-after-lock")
        self.select_local_vault(labels, a_index, phase_prefix + "-select-a-locked")
        self.wait("解锁本地文件库")
        self.a_locked_observed = True
        self.final_local_vault_pair_validation(before_ids)
        return {
            "accountSubmits": expected_account_submits,
            "targetSubmits": expected_target_submits,
            "actualRefreshes": getattr(self, "target_refreshes", 0),
            "freshItemCount": getattr(self, "last_refresh_item_count", 0),
            "aLocked": self.a_locked,
            "aLockedObserved": self.a_locked_observed,
            "accountLocked": True,
        }

    def native_initial_account_fanout_basic(self):
        coverage = self.native_initial_pair_evidence(1, 0, "native-initial")
        coverage["case"] = NATIVE_INITIAL_BASIC_CASE
        coverage["basic"] = True
        return coverage

    def native_initial_account_fanout(self):
        coverage = self.native_initial_account_fanout_basic()
        self.case_coverage = coverage
        self.late_result_coverage = "NOT_RUN_IN_BASIC_CASE"
        self.phase("native-initial-counts account=%d target=%d refresh=%d" % (
            coverage["accountSubmits"], coverage["targetSubmits"], coverage["actualRefreshes"]))
        self.phase("native-initial-basic-flow-complete")

    def native_initial_window_identity(self):
        require(self.app is not None)
        require(self.app.poll() is None)
        result = self.input(inspect=True)
        window = result.get("window")
        require(type(window) is int and window > 0)
        return self.app.pid, window

    def native_initial_tagged_host_is_distinct(self):
        ordinary = os.environ.get("LOCKLARK_DESKTOP_HOST", "")
        return bool(ordinary and self.host and
                    os.path.realpath(str(self.host)) != os.path.realpath(ordinary))

    def native_initial_require_locked_form(self, phase):
        self.phase(phase)
        controls = self.controls()
        require(controls.get("使用应急资料…", {}).get("present") is True)
        for label in ("刷新本地文件库", "锁定本地文件库",
                      "解锁本地文件库", "关闭本地基线视图"):
            require(controls.get(label, {}).get("present") is False)

    def native_initial_cancel_within_budget(self, ready_at):
        self.click(NATIVE_INITIAL_CANCEL_LABEL)
        elapsed = time.monotonic() - ready_at
        if elapsed > NATIVE_INITIAL_CANCEL_BUDGET_SECONDS:
            self.reason = "native-initial-cancel-timeout"
            raise AcceptanceFailure()
        return elapsed

    def native_initial_held_cancel(self):
        client = getattr(self, "native_fence_client", None)
        require(client is not None)
        require(self.native_initial_tagged_host_is_distinct())
        pid, window = self.native_initial_window_identity()
        self.unlock_onevra_submit()
        ready = client.ready()
        require(ready.child_count == NATIVE_INITIAL_REQUIRED_READY_CHILDREN)
        ready_at = time.monotonic()
        require(client.has_pending_event() is False)
        self.native_initial_cancel_within_budget(ready_at)
        cancelled = client.wait_cancelled_drained()
        require(cancelled.closed_count == NATIVE_INITIAL_REQUIRED_READY_CHILDREN)
        require(cancelled.parent_locked is True)
        same_process = self.app.poll() is None and self.app.pid == pid
        require(same_process)
        same_window = self.native_initial_window_identity()[1] == window
        require(same_window)
        self.native_initial_require_locked_form("native-initial-held-cancelled")
        self.phase("native-initial-retry-submit")
        self.unlock_onevra_submit()
        self.unlock_onevra_wait()
        require(self.app.poll() is None and self.app.pid == pid)
        require(self.native_initial_window_identity()[1] == window)
        evidence = self.native_initial_pair_evidence(2, 0, "native-initial-retry")
        coverage = {
            "case": NATIVE_INITIAL_HELD_CANCEL_CASE,
            "initialAccountSubmits": 1,
            "retryAccountSubmits": 1,
            "totalAccountSubmits": 2,
            "targetSubmits": 0,
            "readyChildCount": ready.child_count,
            "cancelled": True,
            "drainedCount": cancelled.closed_count,
            "parentLocked": cancelled.parent_locked,
            "sameProcess": same_process,
            "sameWindow": same_window,
            "retryActualRefreshes": evidence["actualRefreshes"],
            "retryFreshItemCount": evidence["freshItemCount"],
            "accountLocked": evidence["accountLocked"],
        }
        self.case_coverage = coverage
        self.phase("native-initial-held-counts initial=1 retry=1 total=2 target=0")
        self.phase("native-initial-held-flow-complete")

    def build_fixture(self):
        if self.fixture_prebuilt:
            require(self.fixture_binary.is_file() and os.access(self.fixture_binary, os.X_OK))
            return
        self.command([self.go, "build", "-o", str(self.fixture_binary), "./scripts/desktop_acceptance_fixture"])

    def prepare_initial_pair_fixture(self):
        self.prepare_settings_dir()
        workspace = self.settings_dir / "vaultfile-workspace"
        self.command([str(self.fixture_binary), "-prepare-initial-pair",
                      str(self.fixture_path.parent), "-prepare-workspace", str(workspace)])
        self.fixture = json.loads(self.fixture_path.read_bytes())
        self.write_private_settings_file()
        self.verify_local_vault_pair()

    def setup(self):
        self.build_fixture()
        scenario = getattr(self, "scenario", None)
        if scenario in NATIVE_INITIAL_SCENARIOS:
            self.prepare_initial_pair_fixture()
        else:
            self.command([str(self.fixture_binary), "-out", str(self.state / "vault")])
            self.fixture = json.loads(self.fixture_path.read_bytes())
            if scenario == LOCAL_SCENARIO:
                self.write_private_settings()
        self.values.update(self.fixture[key] for key in ("Password", "Secret", "Username", "Value", "OTPSeed", "OTPConfig", "ProviderValue", "ProviderCanary"))
        # Only this real owned Go desktop child may receive the private fence
        # descriptors. The probe below keeps the unmodified base environment.
        self.app = launch_owned_desktop_child(
            subprocess.Popen, self.app_command(), self.env,
            stdout=self.log, stderr=self.log,
            native_fence_client=getattr(self, "native_fence_client", None))
        self.probe = subprocess.Popen([sys.executable, str(ROOT / "scripts/desktop_native_probe.py")],
                                      env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=self.log, text=True, bufsize=1)
        require(bool(select.select([self.probe.stdout], [], [], 15)[0]))
        require(json.loads(self.probe.stdout.readline()).get("ready") is True)
        if scenario == NATIVE_INITIAL_TAGGED_SCENARIO:
            # The held-cancel case performs its own single account submission.
            self.phase("native-initial-held-locked")
        elif local_scenario(scenario):
            self.unlock_onevra()
        else:
            self.unlock()
        self.probe_request({"op":"own-clipboard", "marker":MARKER})

    def create(self, generated):
        self.phase("create-generated" if generated else "create-manual")
        before = self.observe()
        self.click("新建登录")
        title = "Daily generated login" if generated else "Daily manual login"
        self.fill("登录标题", title)
        self.fill("新登录用户名", self.fixture["Username"])
        self.fill("网站（可选）", self.fixture["URL"])
        if not generated:
            self.fill("新登录密码", self.fixture["Value"])
        self.click("生成强密码并保存" if generated else "保存登录")
        self.wait("新建登录")
        self.eventually(lambda: len(self.observe()["items"]) == len(before["items"]) + 1)
        after = self.observe()
        row = self.target(after, title)
        require(row["URL"] == self.fixture["URL"] and row["Username"] == self.fixture["Username"])
        require(self.displays_empty())
        require(self.clipboard([MARKER])["matches"] == [True])
        if generated:
            require(re.fullmatch(r"[A-Za-z0-9]{24}", row["Password"]) is not None)
            events = self.events(after, "item.generate")
            require(len(events) == 1 and events[0]["result"] == "succeeded" and events[0]["item_id"] == row["id"])
        else:
            require(row["Password"] == self.fixture["Value"])
        return row

    def password_delivery(self, row):
        self.select(row["title"], row["state"])
        self.phase("generated-show")
        self.click("显示密码")
        self.wait("立即隐藏")
        require(self.display(expected=[row["Password"]])["matches"] == [True])
        self.click("立即隐藏")
        require(self.display()["empty"])
        self.phase("generated-copy")
        self.click("复制密码")
        self.eventually(lambda: self.clipboard([row["Password"]])["matches"] == [True])
        self.click("安全设置")
        self.eventually(lambda: self.clipboard()["empty"])
        self.click("金库")

    def regenerate(self, title, state="active"):
        self.select(title, state)
        self.phase("regenerate-cancel")
        before = self.observe()
        self.click("重新生成本地密码")
        self.wait("确认生成并替换")
        require(self.displays_empty())
        # No authorized display group is present here. Match title+executable
        # through the shared driver and capture this native window only.
        xid = self.input(inspect=True)["window"]
        self.command(["import", "-window", str(xid), str(self.diagnostics / ("regenerate-" + state + ".png"))])
        self.click("取消重新生成")
        cancelled = self.observe()
        self.same_items(before, cancelled)
        require(self.events(before, "item.regenerate.password") == self.events(cancelled, "item.regenerate.password"))
        self.phase("regenerate-approve")
        self.click("重新生成本地密码")
        self.fill("密码长度（22–256）", "32")
        self.click("确认生成并替换")
        self.wait("新建登录")
        old = self.target(before, title)
        self.eventually(lambda: self.target(self.observe(), title)["revision"] != old["revision"])
        after = self.observe()
        changed = self.target(after, title)
        require(re.fullmatch(r"[A-Za-z0-9]{32}", changed["Password"]) is not None and changed["Password"] != old["Password"])
        require({k:v for k,v in old.items() if k not in ("Password", "revision")} ==
                {k:v for k,v in changed.items() if k not in ("Password", "revision")})
        require([row for row in before["items"] if row["id"] != old["id"]] ==
                [row for row in after["items"] if row["id"] != old["id"]])
        events = self.events(after, "item.regenerate.password")
        event = events[-1]
        require(event["item_id"] == old["id"] and event["base_revision"] == old["revision"] and event["result"] == "succeeded")
        self.password_delivery(changed)

    def stale_regeneration(self):
        self.select("Daily generated login")
        self.phase("regenerate-stale")
        self.click("重新生成本地密码")
        self.wait("确认生成并替换")
        before = self.observe()
        target = self.target(before, "Daily generated login")
        self.command([str(self.fixture_binary), "-fixture", str(self.fixture_path), "-stale", target["id"]])
        independent = self.observe()
        self.click("确认生成并替换")
        # Observation is read-only on the source. The authenticated business
        # refusal may add audit, but cannot change snapshot, password or ID.
        self.eventually(lambda: len(self.events(self.observe(), "item.regenerate.password")) > len(self.events(independent, "item.regenerate.password")))
        after = self.observe()
        self.same_items(independent, after)
        event = self.events(after, "item.regenerate.password")[-1]
        # Rejection audit links the authenticated current item revision. The
        # requested stale revision remains a refusal predicate, not that link.
        current = self.target(independent, "Daily generated login")
        require(event["result"] == "conflict" and event["item_id"] == target["id"] and event["base_revision"] == current["revision"])
        if self.controls()["取消重新生成"]["present"]:
            self.click("取消重新生成")
        self.click("搜索 / 刷新")

    def otp(self, when=None):
        when = time.time() if when is None else when
        counter = int(when) // 20
        digest = hmac.new(base64.b32decode(self.fixture["OTPSeed"]), struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 15
        value = str((int.from_bytes(digest[offset:offset+4], "big") & 0x7fffffff) % 100000000).zfill(8)
        self.codes.add(value)
        return value

    def align(self, lower, upper):
        self.eventually(lambda: lower <= time.time() % 20 < upper, timeout=22)

    @staticmethod
    def otp_window(now):
        return int(now) // OTP_WINDOW_SECONDS

    @staticmethod
    def otp_remaining(now):
        return OTP_WINDOW_SECONDS - (now % OTP_WINDOW_SECONDS)

    def await_new_otp_window(self, margin=OTP_WINDOW_MIN_REMAINING, timeout=OTP_WINDOW_TIMEOUT):
        """Wait on the public wall clock for a fresh 20-second TOTP window.

        The counter is captured before any sample is accepted, so a sample
        from the pre-rollover window is ignored. A sample is accepted only
        after the counter advances with at least ``margin`` seconds left,
        keeping the fixed product preparation and delivery delays inside the
        same window. The wait times out closed.
        """
        started = self.otp_window(time.time())
        deadline = time.monotonic() + timeout
        while True:
            now = time.time()
            if self.otp_window(now) != started and self.otp_remaining(now) >= margin:
                return now
            if time.monotonic() >= deadline:
                self.reason = "otp-window-timeout"
                raise AcceptanceFailure()
            time.sleep(0.2)

    def record_otp_copy_failure(self):
        """Record one fixed line for a failed OTP copy. Catch-time only.

        The accepted timestamp is a float; it is converted with
        ``self.otp_window`` only to form the failure window delta, and the
        copy click likewise for the copy window delta. A single clipboard read
        records whether it is empty; the copy was just checked, so it is not
        checked, clicked or waited on again. The line reaches stdout directly
        and is never written to an artifact; the original stage, reason,
        native action and exit code are kept and no click is issued. Every
        failure of the probe itself is swallowed.
        """
        original = (self.stage, self.reason, self.native_action)
        # A catch inside the probe itself records nothing and reads nothing.
        busy = getattr(self, "otp_probe_busy", False)
        copy = getattr(self, "otp_copy", None)
        self.otp_copy, self.otp_diagnostic, self.otp_probe_busy = None, None, True
        try:
            if busy or copy is None:
                return
            # Both are converted with self.otp_window only for their deltas.
            sample, click = copy
            copy_window, click_window = self.otp_window(sample), self.otp_window(click)
            # The raw value goes through the projection's exact-bool check:
            # a missing or non-bool reply becomes "unavailable", never false.
            try:
                empty = self.clipboard().get("empty")
            except Exception:
                empty = None
            line = otp_diagnostic(click_window - copy_window,
                                  self.otp_window(time.time()) - copy_window, empty)
            self.otp_diagnostic = line
            print(line, flush=True)
        except BaseException:
            return
        finally:
            self.stage, self.reason, self.native_action = original
            self.otp_probe_busy = False

    def show_copy_otp(self):
        self.wait("显示验证码")
        window = self.await_new_otp_window()
        self.click("显示验证码")
        self.wait("隐藏验证码")
        require(self.display(otp=True, expected=[self.otp(window)])["matches"] == [True])
        copied = time.time()
        self.click("复制验证码")
        # Every attempt replaces the record, so a failure always reports this
        # copy and never an earlier one. Both values stay internal.
        self.otp_copy = (window, copied)
        try:
            self.eventually(lambda: self.clipboard([self.otp(window)])["matches"] == [True])
        except AcceptanceFailure:
            self.record_otp_copy_failure()
            raise

    def otp_acceptance(self):
        self.select("Daily OTP login")
        self.phase("otp-show-independent-hmac-and-expiry")
        before = self.observe()
        self.align(0.2, 2)
        started = time.monotonic()
        self.click("显示验证码")
        self.wait("隐藏验证码")
        require(self.display(otp=True, expected=[self.otp()])["matches"] == [True])
        self.eventually(lambda: self.display(otp=True)["empty"], timeout=16)
        require(time.monotonic() - started < 17)
        after = self.observe()
        self.same_items(before, after)
        action = "item.desktop.show.otp-code"
        require(len(self.events(after, action)) == len(self.events(before, action)) + 1)
        time.sleep(0.4)
        require(self.display(otp=True)["empty"])
        require(len(self.events(self.observe(), action)) == len(self.events(after, action)))
        self.phase("otp-copy-original-window-expiry")
        self.align(14, 16)
        until = (int(time.time()) // 20 + 1) * 20
        self.click("复制验证码")
        self.eventually(lambda: self.clipboard([self.otp()])["matches"] == [True])
        self.eventually(lambda: time.time() >= until + 0.25, timeout=8)
        require(self.clipboard()["empty"])
        self.phase("otp-copy-replaced-by-password-copy")
        self.align(10, 12)
        until = (int(time.time()) // 20 + 1) * 20
        self.click("复制验证码")
        self.eventually(lambda: self.clipboard([self.otp()])["matches"] == [True])
        self.click("复制密码")
        self.eventually(lambda: self.clipboard([self.fixture["Value"]])["matches"] == [True])
        self.eventually(lambda: time.time() >= until + 0.3, timeout=12)
        require(self.clipboard([self.fixture["Value"]])["matches"] == [True])
        self.click("立即锁定")
        self.wait("解锁")
        require(self.clipboard()["empty"])
        self.unlock()
        self.select("Daily OTP login")
        self.phase("otp-selection-clears")
        self.show_copy_otp()
        self.select("Daily other login")
        self.eventually(lambda: self.displays_empty() and self.clipboard()["empty"])
        self.select("Daily OTP login")
        self.phase("otp-page-clears")
        self.show_copy_otp()
        self.click("安全设置")
        self.eventually(lambda: self.displays_empty() and self.clipboard()["empty"])
        self.click("金库")
        self.select("Daily OTP login")
        self.phase("otp-observed-revision-clears")
        self.show_copy_otp()
        self.command([str(self.fixture_binary), "-fixture", str(self.fixture_path), "-stale", self.fixture["IDs"]["OTP"]])
        self.click("搜索 / 刷新")
        self.wait("新建登录")
        self.eventually(lambda: self.displays_empty() and self.clipboard()["empty"])
        self.select("Daily OTP login")
        self.phase("otp-lock-clears")
        self.show_copy_otp()
        self.click("立即锁定")
        self.wait("解锁")
        require(self.displays_empty() and self.clipboard()["empty"])
        self.unlock()
        self.select("Daily OTP login")
        self.phase("otp-expiry-preserves-later-clipboard-owner")
        self.align(14, 16)
        until = (int(time.time()) // 20 + 1) * 20
        self.click("复制验证码")
        self.eventually(lambda: self.clipboard([self.otp()])["matches"] == [True])
        foreign = self.start_foreign_owner(MARKER)
        self.eventually(lambda: time.time() >= until + 0.3, timeout=8)
        observation = self.assert_foreign_silent(foreign,"expiry")
        self.allow_foreign_reads(foreign,observation)
        self.assert_independent_clipboard(MARKER)
        observation["post_cleanup_marker_verified"] = True
        self.finish_foreign_owner(foreign)
        self.phase("otp-later-clipboard-owner-preserved")
        self.show_copy_otp()
        self.probe_request({"op":"own-clipboard", "marker":MARKER})
        self.assert_independent_clipboard(MARKER)
        self.click("立即锁定")
        self.wait("解锁")
        require(self.displays_empty())
        self.assert_independent_clipboard(MARKER)
        self.unlock()
        self.select("Daily OTP login")
        require(self.displays_empty())

    def scan(self):
        self.privacy_failure = None
        if hasattr(self, "fixture"):
            for window in range(int(self.started) // 20, int(time.time()) // 20 + 1):
                self.otp(window * 20)
        patterns = set()
        for value in self.values:
            patterns.update((value.encode(), json.dumps(value, ensure_ascii=True)[1:-1].encode(), urllib.parse.quote(value, safe="").encode()))
        manifest_private_values = getattr(self, "local_manifest_private_values", {})
        count = 0
        for path in self.state.rglob("*"):
            if path == self.fixture_path:
                continue
            allowed = ()
            expected = manifest_private_values.get(path)
            if expected is not None:
                data = _stable_local_vault_manifest(path, expected)
                allowed = _local_vault_manifest_spans(data)
            else:
                if not path.is_file() or path.suffix not in (".log", ".txt", ".json", ".jsonl"):
                    continue
                data = path.read_bytes()
            # Syntax-level barrier for a dynamically issued recovery kit that
            # was never registered in self.values (for example when the
            # fixture reader fails). A match is kept in memory only.
            if RECOVERY_KIT_PATTERN.search(data) is not None:
                self.privacy_failure = "recovery-kit"
                raise AcceptanceFailure()
            # Only a complete match occupying one exact current manifest
            # name/vault_id value span is exempt; all other occurrences scan.
            for pattern in patterns:
                if not pattern:
                    continue
                start = data.find(pattern)
                while start >= 0:
                    if (start, start + len(pattern)) not in allowed:
                        self.privacy_failure = "known-value"
                        raise AcceptanceFailure()
                    start = data.find(pattern, start + 1)
            # Codes are short: match a complete independent token, so an
            # unrelated hexadecimal ID substring cannot produce a false hit.
            for code in self.codes:
                if re.search(rb"(?<![A-Za-z0-9])" + code.encode() + rb"(?![A-Za-z0-9])", data) is not None:
                    self.privacy_failure = "otp-code"
                    raise AcceptanceFailure()
            count += 1
        # A vanished prevalidated manifest is not a pass. Revalidate every
        # captured path after the walk so replacement during scan also fails.
        for path, expected in manifest_private_values.items():
            _stable_local_vault_manifest(path, expected)
        return count

    def close(self):
        try:
            for child in (self.app, self.probe,*self.foreign_owners):
                if child is None:
                    continue
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        finally:
            client = getattr(self, "native_fence_client", None)
            if client is not None:
                client.close()
        self.log.close()

    def run(self):
        success = False
        close_failure = None
        scenario = getattr(self, "scenario", None) or os.environ.get("LOCKLARK_TEST_SCENARIO")
        try:
            self.setup()
            failure_stage = os.environ.get("LOCKLARK_TEST_FAILURE_STAGE")
            if failure_stage and scenario == LOCAL_SCENARIO:
                # This scenario has no old probe-input body. An explicit fault
                # request must fail closed, never be silently ignored into a
                # PASS; the normal cleanup/finish barrier still runs.
                self.reason = "local-vault-fault-stage"
                self.phase("local-vault-fault-stage")
                raise AcceptanceFailure()
            if failure_stage == "probe-input":
                # Add a genuinely newly generated password to the fault's
                # private payload and final scan, alongside unlock/OTP factors.
                self.create(True)
                self.phase("private-probe-failure")
                result = self.probe_request({"op":"unsupported", "private":list(self.values)})
                require(result.get("ok") is True)
            elif failure_stage:
                raise AcceptanceFailure()
            if scenario:
                require(scenario in ("foreign-owner", "provider", LOCAL_SCENARIO, *NATIVE_INITIAL_SCENARIOS))
                if scenario == LOCAL_SCENARIO:
                    self.local_vault_file_create()
                elif scenario == NATIVE_INITIAL_SCENARIO:
                    self.native_initial_account_fanout()
                elif scenario == NATIVE_INITIAL_TAGGED_SCENARIO:
                    self.native_initial_held_cancel()
                elif scenario == "provider":
                    self.provider_acceptance()
                else:
                    self.foreign_lock_case()
            else:
                self.create(False)
                generated = self.create(True)
                self.password_delivery(generated)
                self.regenerate("Daily generated login")
                self.stale_regeneration()
                self.click("归档")
                self.wait("新建登录")
                self.regenerate("Daily archived login", "archived")
                self.click("回收站")
                self.select("Daily trashed login", "trashed")
                self.phase("trashed-actions-absent")
                require(not any(self.controls()[label]["present"] for label in ("重新生成本地密码", "显示验证码", "复制验证码")))
                self.click("全部")
                self.provider_acceptance()
                self.otp_acceptance()
                self.foreign_lock_case()
            self.phase("privacy")
            success = True
        except Exception as error:
            # Never include an arbitrary assertion, subprocess command, native
            # exception, JSON payload, password, seed or code in diagnostics.
            error_class = {AcceptanceFailure:"acceptance", OSError:"os", BrokenPipeError:"pipe", json.JSONDecodeError:"json", NativeFenceLaunchError:"fence-launch"}.get(type(error), "unexpected")
            failure = {"stage":self.stage, "reason":self.reason, "native_action":self.native_action,
                       "native_elapsed_ms":self.native_elapsed_ms, "error_class":error_class,
                       "native_x_error_codes":self.native_x_error_codes,
                       "probe_read_attempts_max":self.probe_read_attempts_max,
                       "probe_operation":self.probe_operation, "probe_elapsed_ms":self.probe_elapsed_ms}
            failure["probe_diagnostic"] = self.probe_diagnostic
            failure["last_native_click"] = self.last_native_click
            failure["foreign_clipboard"] = self.foreign_observations
            try:
                failure["controls"] = self.controls()
            except Exception:
                failure["controls_unavailable"] = True
            if not local_scenario(scenario):
                # The local-vault scenario never reuses the broad display probe
                # after a kit may have appeared. Its failure projection stays
                # on the fixed control allowlist above.
                try:
                    failure["displays"] = {}
                    for name, otp in (("field", False), ("otp", True)):
                        observed = self.display(otp=otp)
                        failure["displays"][name] = {key:observed[key] for key in ("present", "empty")}
                except Exception:
                    failure["displays_unavailable"] = True
            self.reason, self.native_action = failure["reason"], failure["native_action"]
            # An artifact write must never change the failure line or exit code.
            try:
                (self.diagnostics / "failure.json").write_text(json.dumps(failure))
            except Exception:
                pass
        finally:
            # Include a value created immediately before an unrelated failure
            # in the final log scan, without changing the live source vault.
            try:
                if hasattr(self, "fixture"):
                    try:
                        self.observe()
                    except Exception:
                        pass
            finally:
                scenario_failure = not success
                try:
                    self.close()
                except Exception:
                    # A close failure is its own fixed cleanup outcome, never
                    # a success and never an exception-detail projection. The
                    # barrier still runs in finish below.
                    close_failure = "close"
                    success = False
                finally:
                    result = self.finish(success, close_failure, scenario_failure)
        return result

    @staticmethod
    def write_transcript(path, lines, exclusive):
        flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
        with os.fdopen(os.open(path, flags, 0o600), "w") as output:
            output.write("\n".join(lines) + "\n")

    @staticmethod
    def replace_transcript(path, lines):
        """Atomically replace a transcript with a fully written private temp."""
        fd, temp_path = tempfile.mkstemp(dir=str(path.parent),
                                         prefix=".controller-", suffix=".tmp")
        try:
            try:
                output = os.fdopen(fd, "w")
            except Exception:
                os.close(fd)
                raise
            with output:
                output.write("\n".join(lines) + "\n")
            os.replace(temp_path, path)
            temp_path = None
        finally:
            if temp_path is not None:
                # Only the file created by this call is removed. The original
                # transcript is left untouched until the atomic replace.
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def finish(self, success, cleanup_failure=None, scenario_failure=None):
        """Write the transcript, run the barrier, then project fixed lines."""
        try:
            if getattr(self, "foreign_observations", None):
                # Best-effort extra detail: a write failure must never replace
                # the primary outcome or stop the fixed lines below.
                path = self.diagnostics/"clipboard-ownership.json"
                try:
                    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w") as output:
                        json.dump(self.foreign_observations,output,indent=2)
                except Exception:
                    pass
            failure_line = ("Desktop native acceptance failed at " + self.stage + " [" +
                            self.reason + "] action=" + self.native_action)
            otp_line = getattr(self, "otp_diagnostic", None) or "Desktop OTP failure diagnostic: none"
            cleanup_line = CLEANUP_FAILURE_PREFIX + cleanup_failure if cleanup_failure else None
            # When a close failure forces success=False, the earlier scenario
            # outcome is still known separately, so only a real scenario
            # failure contributes its fixed line.
            scenario_failed = (not success) if scenario_failure is None else scenario_failure
            privacy = "passed"
            # The provisional transcript carries every controller phase and
            # the fixed outcome before the success label is known. It is what
            # the barrier scans, so a text PASS is never written first.
            provisional = ["Desktop native private state: " + str(self.state),
                           "Desktop native authorized display read attempts: max=" + str(self.probe_read_attempts_max),
                           "Desktop native private artifact and controller scan: pending"]
            if scenario_failed:
                provisional.append(failure_line)
            if cleanup_line:
                provisional.append(cleanup_line)
            provisional.append(otp_line)
            controller = self.state / "controller.log"
            try:
                self.write_transcript(controller, self.output_lines + provisional, exclusive=True)
            except Exception:
                privacy = "controller-write"
            # The recovery-kit syntax scan is part of scan(), so it runs here
            # on success, scenario failure, close failure and transcript-write
            # failure alike.
            try:
                self.scan()
            except Exception:
                privacy = getattr(self, "privacy_failure", None) or "scan-error"
            if privacy == "passed":
                scenario = getattr(self, "scenario", None) or os.environ.get("LOCKLARK_TEST_SCENARIO")
                success_label = {
                    "foreign-owner":"PASS: real unresponsive foreign clipboard owner, single Lock, zero cleanup requests and preserved marker",
                    "provider":"PASS: real large Unicode native clipboard provider, own cleanup and same-value foreign owner preservation",
                    LOCAL_SCENARIO:"PASS: real native Onevra independent local vault A/B create, wrong-kit refusal, fresh recovery, pair observer, lock/refresh/unlock and cached navigation",
                    NATIVE_INITIAL_SCENARIO: "NATIVE_INITIAL_ACCOUNT_FANOUT_BASIC_ONLY LATE_RESULT=NOT_RUN_IN_BASIC_CASE",
                    NATIVE_INITIAL_TAGGED_SCENARIO: "PASS: real native initial owned-pair held-cancel and retry",
                }.get(scenario,"PASS: real desktop atomic create/generate, exact regeneration, native clipboard ownership and independent TOTP lifecycle")
                # Only now, after the scan passed, may the fixed success line
                # enter the transcript. A rewrite failure also yields no PASS.
                final = ["Desktop native private state: " + str(self.state),
                         "Desktop native authorized display read attempts: max=" + str(self.probe_read_attempts_max),
                         "Desktop native private artifact and controller scan: passed"]
                if success:
                    final.append(success_label)
                elif scenario_failed:
                    final.append(failure_line)
                if cleanup_line:
                    final.append(cleanup_line)
                final.append(otp_line)
                try:
                    self.replace_transcript(controller, self.output_lines + final)
                except Exception:
                    privacy = "controller-write"
            lines = ["Desktop native private state: " + str(self.state),
                     "Desktop native authorized display read attempts: max=" + str(self.probe_read_attempts_max)]
            if privacy == "passed":
                lines.append("Desktop native private artifact and controller scan: passed")
                if success:
                    lines.append(success_label)
                elif scenario_failed:
                    lines.append(failure_line)
            else:
                lines.append("Desktop native privacy scan failed")
                lines.append(PRIVACY_FAILURE_PREFIX + privacy)
                if scenario_failed:
                    lines.append(failure_line)
            if cleanup_line:
                lines.append(cleanup_line)
            lines.append(otp_line)
            self.emit_lines(lines)
            return 0 if success and privacy == "passed" and cleanup_line is None else 1
        except Exception:
            # Fixed fallback only; never include a kit, matched value or path.
            try:
                self.emit_lines(["Desktop native privacy scan failed",
                                 PRIVACY_FAILURE_PREFIX + "finalize"])
            except Exception:
                pass
            return 1

    @staticmethod
    def emit_lines(lines):
        # The OTP line reaches stdout here regardless of transcript or scan.
        for message in lines:
            print(message, flush=True)


class NativeInitialCaseResult:
    __slots__ = ("case", "code", "state", "coverage", "failure")

    def __init__(self, case, code, state=None, coverage=None, failure=None):
        self.case = case
        self.code = code
        self.state = state
        self.coverage = coverage
        self.failure = failure


def native_initial_basic_coverage_ok(coverage):
    if not isinstance(coverage, dict):
        return False
    return (
        coverage.get("case") == NATIVE_INITIAL_BASIC_CASE
        and coverage.get("accountSubmits") == 1
        and coverage.get("targetSubmits") == 0
        and type(coverage.get("actualRefreshes")) is int
        and coverage["actualRefreshes"] >= 2
        and type(coverage.get("freshItemCount")) is int
        and coverage["freshItemCount"] > 0
        and coverage.get("accountLocked") is True
    )


def native_initial_held_coverage_ok(coverage):
    if not isinstance(coverage, dict):
        return False
    return (
        coverage.get("case") == NATIVE_INITIAL_HELD_CANCEL_CASE
        and coverage.get("initialAccountSubmits") == 1
        and coverage.get("retryAccountSubmits") == 1
        and coverage.get("totalAccountSubmits") == 2
        and coverage.get("targetSubmits") == 0
        and coverage.get("readyChildCount") == NATIVE_INITIAL_REQUIRED_READY_CHILDREN
        and coverage.get("cancelled") is True
        and coverage.get("drainedCount") == NATIVE_INITIAL_REQUIRED_READY_CHILDREN
        and coverage.get("parentLocked") is True
        and coverage.get("sameProcess") is True
        and coverage.get("sameWindow") is True
        and type(coverage.get("retryActualRefreshes")) is int
        and coverage["retryActualRefreshes"] >= 2
        and type(coverage.get("retryFreshItemCount")) is int
        and coverage["retryFreshItemCount"] > 0
        and coverage.get("accountLocked") is True
    )


def native_initial_privacy_scan(privacy, states):
    for state in states:
        if state is None:
            continue
        scanner = Acceptance.__new__(Acceptance)
        scanner.state = pathlib.Path(state)
        scanner.fixture_path = scanner.state / ".no-fixture"
        scanner.values = privacy.values
        scanner.codes = privacy.codes
        scanner.local_manifest_private_values = privacy.local_manifest_private_values
        scanner.started = time.time()
        scanner.privacy_failure = None
        try:
            scanner.scan()
        except AcceptanceFailure:
            return getattr(scanner, "privacy_failure", None) or "scan-error"
    return None


def _run_native_initial_case(case, scenario, host, uses_fence,
                             acceptance_factory, client_factory, privacy):
    if not host:
        return NativeInitialCaseResult(case, 1, failure="HOST_UNAVAILABLE")
    client = None
    try:
        if uses_fence:
            client = client_factory()
        subject = acceptance_factory(
            scenario=scenario, host=host,
            native_fence_client=client, privacy=privacy)
        code = subject.run()
        return NativeInitialCaseResult(
            case, code, getattr(subject, "state", None),
            getattr(subject, "case_coverage", None))
    except Exception:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        return NativeInitialCaseResult(case, 1, failure="CASE_EXCEPTION")


def run_default_aggregate(environ=None, acceptance_factory=None, client_factory=None):
    """Run the old default flow and both native initial cases as one gate."""
    environ = os.environ if environ is None else environ
    acceptance_factory = Acceptance if acceptance_factory is None else acceptance_factory
    client_factory = NativeFenceClient if client_factory is None else client_factory
    if not environ.get("LOCKLARK_DESKTOP_FIXTURE"):
        print("NATIVE_INITIAL_AGGREGATE FAIL reason=ARTIFACT_UNAVAILABLE")
        return 1
    ordinary = environ.get("LOCKLARK_DESKTOP_HOST")
    tagged_hosts = native_initial_host_paths(environ)
    privacy = NativeInitialPrivacyRegistry()
    legacy = _run_native_initial_case(
        NATIVE_INITIAL_LEGACY_CASE, None, ordinary, False,
        acceptance_factory, client_factory, privacy)
    basic = _run_native_initial_case(
        NATIVE_INITIAL_BASIC_CASE, NATIVE_INITIAL_SCENARIO, ordinary, False,
        acceptance_factory, client_factory, privacy)
    if tagged_hosts is None:
        held = NativeInitialCaseResult(
            NATIVE_INITIAL_HELD_CANCEL_CASE, 1, failure="HOST_UNAVAILABLE")
    else:
        held = _run_native_initial_case(
            NATIVE_INITIAL_HELD_CANCEL_CASE, NATIVE_INITIAL_TAGGED_SCENARIO,
            tagged_hosts[1], True, acceptance_factory, client_factory, privacy)
    results = (legacy, basic, held)
    failure = None
    if legacy.code != 0:
        failure = legacy.failure or "LEGACY_FAILED"
    elif basic.code != 0:
        failure = basic.failure or "BASIC_FAILED"
    elif held.code != 0:
        failure = held.failure or "HELD_CANCEL_FAILED"
    elif not native_initial_basic_coverage_ok(basic.coverage):
        failure = "BASIC_COVERAGE"
    elif not native_initial_held_coverage_ok(held.coverage):
        failure = "HELD_CANCEL_COVERAGE"
    if failure is None:
        privacy_failure = native_initial_privacy_scan(
            privacy, [result.state for result in results if result.state is not None])
        if privacy_failure is not None:
            failure = native_initial_privacy_failure_detail(privacy_failure)
    print("NATIVE_INITIAL_CASE legacy=%s basic=%s held_cancel=%s" % (
        "PASS" if legacy.code == 0 else "FAIL",
        "PASS" if basic.code == 0 else "FAIL",
        "PASS" if held.code == 0 else "FAIL"))
    if failure is not None:
        print("NATIVE_INITIAL_AGGREGATE FAIL reason=" + failure)
        return 1
    print("NATIVE_INITIAL_COUNTS basic_account=1 held_initial=1 held_retry=1 held_total=2 target=0")
    print("NATIVE_INITIAL_AGGREGATE PASS")
    return 0


def main():
    if os.environ.get("LOCKLARK_TEST_SCENARIO"):
        return Acceptance().run()
    return run_default_aggregate()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("Desktop native acceptance unavailable at setup", file=sys.stderr)
        sys.exit(1)
