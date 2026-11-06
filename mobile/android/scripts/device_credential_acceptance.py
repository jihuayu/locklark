#!/usr/bin/env python3
"""Post-host native OS credential acceptance on one disposable emulator.

Provided factors/PIN/XML stay in private artifacts. It does not reset the vault,
call app methods, synthesize OS authentication, or use a release test endpoint.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tarfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from mobile_android_acceptance import AndroidAcceptance, AcceptanceFailure, PACKAGE, actionable_bounds, center, require
from test_emulator import complete_pass

OS_PACKAGES = {"com.android.systemui", "com.android.settings"}
STAGES = {"prerequisites", "live-vault", "pin-capabilities", "pin-empty-precondition", "pin-set", "enable", "enable-prompt", "quick", "quick-prompt",
          "cancel", "cancel-prompt", "key-policy", "copy-encrypted-state", "reinstall", "restore",
          "copied-capsule-refusal", "full-factor-recovery", "pin-cleanup", "private-canary-scan", "complete"}
AUTH_PHASES = {"OPERATION", "CAPTURE", "DEVICE_SETUP", "DEVICE_READY", "DEVICE_KEY", "DEVICE_CIPHER", "DEVICE_PROMPT",
               "DEVICE_WAIT", "DEVICE_AAD", "DEVICE_CRYPTO", "DEVICE_READ", "DEVICE_WRITE"}
AUTH_CODES = {"LOCKED", "CLOSED", "INVALID", "CONFLICT", "CANCELLED", "UNKNOWN", "EXPIRED", "UNAVAILABLE", "EXISTS", "CAPACITY", "OTHER"}
AUTH_EXCEPTIONS = {"NONE", "USER_NOT_AUTHENTICATED", "KEY_INVALIDATED", "INVALID_KEY", "INVALID_PARAMETER", "KEYSTORE",
                   "PROVIDER", "SECURITY", "IO", "ILLEGAL_ARGUMENT", "ILLEGAL_STATE", "TIMEOUT", "INTERRUPTED", "OTHER"}
AUTH_ERRORS = {"NONE", "HARDWARE_UNAVAILABLE", "UNABLE_TO_PROCESS", "TIMEOUT", "NO_SPACE", "CANCELLED", "LOCKOUT", "VENDOR",
               "PERMANENT_LOCKOUT", "USER_CANCELLED", "NO_BIOMETRICS", "NO_HARDWARE", "NEGATIVE_BUTTON", "NO_DEVICE_CREDENTIAL",
               "SECURITY_UPDATE_REQUIRED", "OTHER"}
REFUSED_PREFIXES = ("操作未完成：", "解锁未完成：", "准备操作未完成：", "结果未确认", "准备设备认证未完成：", "检查设备认证未完成：",
                    "准备设备认证密钥未完成：", "准备设备加密未完成：", "设备认证未完成：", "等待设备认证未完成：",
                    "绑定设备授权未完成：", "处理设备授权未完成：", "读取设备授权未完成：", "保存设备授权未完成：")
KEY_POLICY_STAGES = {"start", "instrument-command", "installation", "capsule-selection", "permissions", "envelope", "key-load",
                     "nonexportable", "key-info", "auth-required", "auth-validity", "cipher-policy", "auth-types",
                     "fresh-init", "fresh-aad", "fresh-finish", "fresh-rejection", "complete"}
KEY_POLICY_ASSERTIONS = {"none", "installation-format", "one-capsule", "capsule-mode", "directory-mode", "envelope-size",
                        "envelope-format", "nonexportable", "auth-required", "per-operation", "aes256-gcm", "exact-auth-types",
                        "fresh-unauthenticated-rejected"}
KEY_LEVELS = {"software", "tee", "strongbox", "unknown", "hardware-unspecified"}


def key_policy_metadata(returncode, raw):
    """Fixed instrumentation categories only; never retain an assertion body."""
    def values(name):
        return re.findall(rb"^INSTRUMENTATION_STATUS: " + name.encode() + rb"=([^\r\n]*)", raw, re.MULTILINE)
    def scalar(name, allowed, default="unknown", last=False):
        observed = values(name)
        if not observed:
            return default
        if not last and len(set(observed)) != 1:
            return "unknown"
        value = observed[-1].decode("ascii", errors="replace")
        return value if value in allowed else "unknown"
    expected_class = b"org.locklark.android.DeviceKeyProtectionTest"
    expected_test = b"realDeviceCapsuleUsesNonexportablePerOperationKey"
    counts = re.findall(rb"OK \(([0-9]{1,3}) tests?\)", raw)
    if not counts:
        counts = re.findall(rb"Tests run: ([0-9]{1,3})", raw)
    levels = values("locklark_key_level")
    level = levels[0].decode("ascii", errors="replace") if len(levels) == 1 else "unknown"
    validity_values = values("locklark_key_auth_validity")
    validity = "unknown"
    if validity_values and len(set(validity_values)) == 1:
        value = validity_values[0]
        if value == b"out-of-range":
            validity = "out-of-range"
        elif re.fullmatch(rb"-1|[0-9]{1,5}", value) and -1 <= int(value) <= 86400:
            validity = str(int(value))
    exceptions = {kind.lower() for kind in AUTH_EXCEPTIONS} | {"assertion"}
    exception = scalar("locklark_key_exception", exceptions, default="none", last=True)
    if exception == "none":
        for marker, category in ((b"java.lang.AssertionError", "assertion"), (b"java.security.ProviderException", "provider"),
                                 (b"java.security.InvalidKeyException", "invalid_key"), (b"java.lang.IllegalStateException", "illegal_state")):
            if marker in raw:
                exception = category; break
    lines = values("locklark_key_source_line")
    line = lines[-1] if lines else next(iter(re.findall(rb"DeviceKeyProtectionTest\.kt:([0-9]{1,5})\)", raw)), b"0")
    return {"exit_code":returncode if isinstance(returncode, int) and -255 <= returncode <= 255 else "outside-range",
            "complete_pass":complete_pass(returncode, raw, expected_tests=1),
            "test_count":int(counts[0]) if len(counts) == 1 else "unknown",
            "class_match":set(values("class")) == {expected_class}, "test_match":set(values("test")) == {expected_test},
            "key_level_count":min(len(levels), 1000), "key_level":level if level in KEY_LEVELS else "unknown",
            "stage":scalar("locklark_key_stage", KEY_POLICY_STAGES, last=True),
            "assertion":scalar("locklark_key_assertion", KEY_POLICY_ASSERTIONS, last=True),
            "exception":exception, "own_source_line":int(line) if re.fullmatch(rb"[0-9]{1,5}", line) else 0,
            "auth_validity":validity,
            "fresh_denial":scalar("locklark_key_fresh_denial", {"none", "user_not_authenticated", "keystore_authentication_required"}),
            **{field:scalar(name, {"true", "false"}) for field, name in (
                ("auth_required", "locklark_key_auth_required"), ("nonexportable", "locklark_key_nonexportable"),
                ("cipher_exact", "locklark_key_cipher_exact"), ("auth_types_exact", "locklark_key_auth_types_exact"),
                ("fresh_rejected", "locklark_key_fresh_rejected"))}}


def key_policy_passed(metadata):
    return (metadata["complete_pass"] and metadata["test_count"] == 1 and metadata["class_match"] and metadata["test_match"]
            and metadata["key_level_count"] == 1 and metadata["stage"] == "complete" and metadata["assertion"] == "none"
            and metadata["exception"] == "none" and metadata["auth_validity"] in {"-1", "0"}
            and metadata["fresh_denial"] in {"user_not_authenticated", "keystore_authentication_required"}
            and all(metadata[field] == "true" for field in ("auth_required", "nonexportable", "cipher_exact", "auth_types_exact", "fresh_rejected")))


def auth_records(raw, pid):
    """Strict fixed-enum messages only; discard arbitrary log text and old PIDs."""
    records = []
    pattern = rb"attempt=([1-9][0-9]{0,18}) pid=([1-9][0-9]{0,9}) event=(begin|failed)(?: stage=([A-Z_]+) code=([A-Z_]+) exception=([A-Z_]+) os=([A-Z_]+))?"
    for line in raw.splitlines():
        match = re.fullmatch(pattern, line)
        if not match or int(match[2]) != pid:
            continue
        attempt = int(match[1])
        if match[3] == b"begin" and match[4] is None:
            records.append((attempt, None))
        elif match[3] == b"failed" and match[4] is not None:
            fields = [match[i].decode("ascii") for i in range(4, 8)]
            if all(field in allowed for field, allowed in zip(fields, (AUTH_PHASES, AUTH_CODES, AUTH_EXCEPTIONS, AUTH_ERRORS))):
                records.append((attempt, dict(zip(("phase", "code", "exception", "os_error"), fields))))
    return records


def fresh_auth_failure(raw, pid, floor):
    begun = set()
    records = [(attempt, failure) for attempt, failure in auth_records(raw, pid) if attempt > floor]
    newest = max((attempt for attempt, _ in records), default=0)
    latest = {}
    for attempt, failure in records:
        if attempt != newest:
            continue
        if failure is None:
            begun.add(attempt)
        elif attempt in begun:
            latest = failure
    return latest


def locksettings_status(result):
    """Only fixed AOSP status classes; never return exception text or a PIN."""
    raw = result.stdout + result.stderr
    classification = "success" if result.returncode == 0 else "command-failed"
    if result.returncode != 0:
        constants = (
            (b"The device does not support lock screen - ignoring the command.", "unsupported-secure-lock-screen"),
            (b"didn't match", "credential-mismatch"),
            (b"Request throttled", "credential-throttled"),
            (b"Profile uses unified challenge", "unified-profile-challenge"),
            (b"Old password provided but user has no password", "unexpected-old-credential"),
            (b"New credential doesn't satisfy admin policies", "credential-policy"),
            (b"java.lang.SecurityException:", "security-exception"),
            (b"java.lang.IllegalArgumentException:", "illegal-argument"),
            (b"java.lang.IllegalStateException:", "illegal-state"),
            (b"android.os.RemoteException:", "remote-exception"),
        )
        classification = next((label for text, label in constants if text in raw), classification)
    return {"exit_code":result.returncode,"classification":classification}


def native_ui_state(nodes):
    app = [node for node in nodes if node.get("package") == PACKAGE]
    if any(node.get("class") == "android.widget.TextView" and node.get("text", "").startswith(REFUSED_PREFIXES) for node in app):
        return "refused"
    controls = [node for node in app if node.get("class") == "android.widget.Button"]
    if any(node.get("text") in {"打开本地金库", "使用此设备认证解锁", "启用此设备认证"} and node.get("enabled") == "false" for node in controls):
        return "busy"
    for label, state in (("新建登录", "unlocked"), ("打开本地金库", "locked"), ("生成新的 Secret Key", "setup")):
        if any(node.get("text") == label and node.get("enabled") == "true" for node in controls):
            return state
    return "unknown"


def private_file(path):
    require(not path.is_symlink() and path.is_file())
    info = path.stat()
    require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0)
    return path.read_bytes()


def validated_evidence(argument):
    root = Path(argument)
    require(not root.is_symlink() and root.is_dir())
    require(root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o077 == 0)
    runs = [p for p in root.iterdir() if p.name.startswith("android-host-ui-")]
    require(len(runs) == 1 and runs[0].is_dir() and not runs[0].is_symlink())
    run = runs[0]
    result = json.loads(private_file(run / "result.json"))
    require(result.get("success") is True and result.get("stage") == "complete")
    require("full_controller_and_logcat_outputs_contain_no_secret_canaries" in result.get("checks", []))
    raw = private_file(run / "expected-private.json")
    fixture = json.loads(raw)
    canaries = json.loads(private_file(run / "canaries.json"))
    require(isinstance(canaries, list) and all(isinstance(value, str) and value for value in canaries))
    require(isinstance(fixture.get("master"), str) and bool(re.fullmatch(r"[A-Za-z0-9_-]+", fixture["master"])))
    require(bool(re.fullmatch(r"LL1-[A-Z2-7]{26}", fixture.get("key", ""))))
    require(fixture["master"] in canaries and fixture["key"] in canaries)
    items = fixture.get("items")
    require(isinstance(items, list) and len(items) == 2)
    for item in items:
        require(bool(re.fullmatch(r"[a-f0-9]{32}", item.get("id", ""))))
        require(bool(re.fullmatch(r"[a-f0-9]{64}", item.get("revision", ""))))
        require(isinstance(item.get("title"), str) and bool(re.fullmatch(r"[A-Za-z0-9_-]+", item["title"])))
        require(item.get("password") in canaries)
    return run, fixture, canaries, hashlib.sha256(raw).hexdigest()


def visible_os_control(node, focused, size=None):
    # The API 35 uiautomator dumper omits invisible children but does not emit
    # a visible-to-user XML attribute. Explicit false/unknown is still refused.
    if node.get("package") != focused or node.get("visible-to-user") not in (None, "true"):
        return False
    viewport = (0, 0, size[0], size[1]) if size else None
    return actionable_bounds(node, viewport) == "ready"


def credential_controls(nodes, focused, size=None):
    require(focused in OS_PACKAGES)
    usable = [node for node in nodes if visible_os_control(node, focused, size)]
    prefix = focused + ":id/"
    input_ids = {prefix + name for name in ("pinEntry", "pin_entry", "passwordEntry", "password_entry", "lockPassword")}
    entries = [node for node in usable if node.get("resource-id") in input_ids]
    keys = {digit:[node for node in usable if node.get("resource-id") == prefix + "key" + digit] for digit in "0123456789"}
    fallback = [node for node in usable if node.get("resource-id") in {prefix + "button_use_credential", prefix + "button_negative"}
                and node.get("class") == "android.widget.Button"
                and node.get("text") in {"Use PIN", "Use pin", "Use screen lock", "使用 PIN 码", "使用PIN码", "使用屏幕锁定"}]
    title = any(node.get("text") == "认证此设备以解封本地金库授权" for node in usable)
    return entries, keys, fallback if title else []


def credential_marker(nodes, focused, size=None):
    if focused not in OS_PACKAGES:
        return False
    entries, keys, fallback = credential_controls(nodes, focused, size)
    return len(entries) == 1 or all(len(values) == 1 for values in keys.values()) or len(fallback) == 1


def exact_package_uid(raw, package):
    require(package in OS_PACKAGES | {PACKAGE})
    pattern = rb"package:" + re.escape(package.encode()) + rb" uid:([1-9][0-9]{0,9})"
    matches = [re.fullmatch(pattern, line.strip()) for line in raw.splitlines()]
    matches = [match for match in matches if match is not None]
    require(len(matches) == 1)
    value = int(matches[0][1])
    require(value <= 2_147_483_647)
    return value


def focus_evidence(raw, nodes, trusted_uids, size=None):
    candidates = sorted(package for package in OS_PACKAGES if credential_marker(nodes, package, size))
    evidence = {"focus_record_present":False, "window_record_present":False,
                "owner_package_verified":False, "system_window_known_uid":False,
                "candidate_package":candidates[0] if len(candidates) == 1 else "multiple" if candidates else "none",
                "credential_resource_marker":bool(candidates)}
    # DisplayContent prints focus; the `windows` subcommand omits that section
    # on API 35. A full dump supplies both focus tokens and WindowState owners.
    tokens = set(re.findall(rb"\bmCurrentFocus=Window\{([a-f0-9]+)\b", raw))
    evidence["focus_record_present"] = bool(tokens)
    if len(tokens) != 1:
        return "unknown", evidence
    token = tokens.pop()
    blocks = re.findall(rb"^\s*Window #[0-9]+ Window\{" + re.escape(token) +
                        rb"\b[^\n]*\}:[\s\S]*?(?=\n\s*Window #[0-9]+ Window\{|\Z)", raw, re.MULTILINE)
    evidence["window_record_present"] = bool(blocks)
    if len(blocks) != 1:
        return "unknown", evidence
    owners = re.findall(rb"\bmOwnerUid=([0-9]+)[^\n]*\bpackage=([a-zA-Z0-9_.]+)\b", blocks[0])
    if len(owners) != 1:
        return "unknown", evidence
    uid, owner = int(owners[0][0]), owners[0][1].decode("ascii")
    evidence["system_window_known_uid"] = any(uid == trusted_uids.get(package) for package in OS_PACKAGES)
    # Never infer ownership from the user-controlled window title/component.
    if owner not in OS_PACKAGES | {PACKAGE} or trusted_uids.get(owner) != uid:
        return "unknown", evidence
    evidence["owner_package_verified"] = True
    return owner, evidence


def focused_identity(raw, nodes, trusted_uids=None):
    return focus_evidence(raw, nodes, trusted_uids or {})[0]


def focus_binding(raw, trusted_uids):
    owner, _ = focus_evidence(raw, [], trusted_uids)
    if owner == "unknown":
        return None
    # Validation above established exactly one token and an authoritative
    # package/UID pair. This tuple stays private and never enters diagnostics.
    token = next(iter(set(re.findall(rb"\bmCurrentFocus=Window\{([a-f0-9]+)\b", raw))))
    return token, trusted_uids[owner], owner


class DeviceCredentialAcceptance(AndroidAcceptance):
    def __init__(self, args, evidence):
        super().__init__(args)
        self.source, self.fixture, canaries, self.source_hash = evidence
        self.canaries = list(canaries)
        self.pin = self.record(str(secrets.randbelow(90_000_000) + 10_000_000))
        self.pin_owned = False
        self.pin_attempted = False
        self.lifecycle = []
        self.key_level = "unknown"
        self.key_policy_diagnostic = {}
        self.locksettings_diagnostic = {}
        self.secure_lock_screen = None
        self.auth_pid = None
        self.auth_floor = 0
        self.trusted_window_uids = {}
        self.focus_diagnostic = focus_evidence(b"", [], {})[1]
        self.last_observation = {"phase":"prerequisites", "focused_package":"unknown", "main_state":"unknown",
                                 "native_ui_state":"unknown", "credential_marker":False}

    def set_stage(self, value):
        require(value in STAGES)
        self.stage = value

    def done(self, name):
        self.checks.append(name)
        print("PASS: Android device credential " + name, flush=True)

    def focused_package(self, nodes=None):
        raw = self.shell("dumpsys", "window").stdout
        focused, self.focus_diagnostic = focus_evidence(raw, nodes or [], self.trusted_window_uids, getattr(self, "size", None))
        return focused

    def bound_snapshot(self, deadline, expected=None):
        before = self.shell("dumpsys", "window", timeout=self.remaining(deadline, 45)).stdout
        first = focus_binding(before, self.trusted_window_uids)
        nodes = self.snapshot(deadline=deadline)
        after = self.shell("dumpsys", "window", timeout=self.remaining(deadline, 45)).stdout
        last = focus_binding(after, self.trusted_window_uids)
        focused, self.focus_diagnostic = focus_evidence(after, nodes, self.trusted_window_uids, self.size)
        stable = first is not None and first == last
        self.focus_diagnostic["stable_window"] = stable
        if expected is not None:
            require(stable and last == expected)
        self.remaining(deadline)
        return nodes, focused if stable else "unknown", last if stable else None

    def load_trusted_window_uids(self):
        mapping = {}
        for package in sorted(OS_PACKAGES | {PACKAGE}):
            # OS identities must be installed SYSTEM packages, not a matching
            # arbitrary app name or a guessed fixed UID. App APK is verified
            # against the owned fixture before this method is called.
            flags = ("-s", "-U") if package in OS_PACKAGES else ("-U",)
            result = self.shell("pm", "list", "packages", *flags, package)
            mapping[package] = exact_package_uid(result.stdout, package)
        self.trusted_window_uids = mapping

    def observe_lifecycle(self, validated_nodes=None, validated_package=None):
        nodes = validated_nodes if validated_nodes is not None else self.snapshot()
        focused = validated_package if validated_package in OS_PACKAGES | {PACKAGE} else self.focused_package(nodes)
        raw = self.shell("dumpsys", "activity", "activities").stdout
        state = "unknown"
        for block in re.split(rb"(?=ActivityRecord\{)", raw):
            if (PACKAGE + "/.MainActivity").encode() in block:
                found = re.search(rb"(?:mState|state|State)=([A-Z]+)", block)
                if found and found[1] in {b"RESUMED", b"PAUSED", b"STOPPED", b"STOPPING", b"PAUSING", b"INITIALIZING", b"DESTROYED"}:
                    state = found[1].decode()
        self.record_observation(nodes, focused, state)
        self.lifecycle.append(self.last_observation.copy())
        self.write_private("lifecycle.json", self.lifecycle)

    def record_observation(self, nodes, focused, state="unknown"):
        self.last_observation = {"phase":self.stage, "focused_package":focused if focused in OS_PACKAGES | {PACKAGE} else "unknown",
                                 "main_state":state, "native_ui_state":native_ui_state(nodes),
                                 "credential_marker":credential_marker(nodes, focused, getattr(self, "size", None)),
                                 "focus":getattr(self, "focus_diagnostic", focus_evidence(b"", [], {})[1]).copy()}

    def failure_metadata(self):
        auth = {}
        try:
            if self.auth_pid is not None and self.shell("pidof", PACKAGE).stdout.strip() == str(self.auth_pid).encode():
                auth = fresh_auth_failure(self.auth_log(self.auth_pid), self.auth_pid, self.auth_floor)
        except Exception:
            pass
        return {"secure_lock_screen_feature":self.secure_lock_screen,
                "locksettings":self.locksettings_diagnostic.copy(), "last_ui":self.last_observation.copy(), "native_auth":auth,
                "key_policy":getattr(self, "key_policy_diagnostic", {}).copy()}

    def auth_log(self, pid):
        return self.shell("logcat", "-d", "-v", "raw", "--pid", str(pid), "-s", "LocklarkAuth:I", "*:S").stdout

    def arm_auth_diagnostic(self):
        raw = self.shell("pidof", PACKAGE).stdout.strip()
        require(bool(re.fullmatch(rb"[1-9][0-9]{0,9}", raw)))
        self.auth_pid = int(raw)
        records = auth_records(self.auth_log(self.auth_pid), self.auth_pid)
        self.auth_floor = max((attempt for attempt, _ in records), default=0)

    def locksettings(self, operation, *arguments, oracle):
        self.locksettings_diagnostic = {"operation":operation,"exit_code":None,"classification":"transport-or-capture-failed"}
        result = self.shell("locksettings", *arguments, oracle=oracle, timeout=60, required=False)
        self.locksettings_diagnostic = {"operation":operation, **locksettings_status(result)}
        require(result.returncode == 0)

    def provision_pin(self):
        self.set_stage("pin-capabilities")
        features = self.shell("pm", "list", "features").stdout.splitlines()
        self.secure_lock_screen = any(line.partition(b"=")[0] == b"feature:android.software.secure_lock_screen" for line in features)
        self.set_stage("pin-empty-precondition")
        # AOSP defaults mOld to empty. ADB joins shell argv, so do not pass an
        # empty --old argument. Missing capability is still a hard failure.
        self.locksettings("verify-empty", "verify", oracle="pin-empty-precondition.txt")
        require(self.secure_lock_screen)
        self.set_stage("pin-set")
        self.pin_attempted = True
        self.locksettings("set-pin", "set-pin", self.pin, oracle="pin-setup.txt")
        self.pin_owned = True

    def setup_owned_emulator(self):
        require(self.args.authorize_device_pin_setup and bool(re.fullmatch(r"emulator-[0-9]+", self.args.serial)))
        require(Path(self.args.apk).is_file())
        require(self.shell("getprop", "ro.kernel.qemu").stdout.strip() == b"1")
        require(self.shell("getprop", "sys.boot_completed").stdout.strip() == b"1")
        require(self.shell("service", "check", "package").stdout.strip() == b"Service package: found")
        require(self.shell("am", "get-current-user").stdout.strip() == b"0")
        paths = self.shell("pm", "path", PACKAGE).stdout.splitlines()
        require(len(paths) == 1 and paths[0].startswith(b"package:/data/app/") and paths[0].endswith(b"/base.apk"))
        remote_apk = paths[0].removeprefix(b"package:").decode()
        actual = self.shell("sha256sum", remote_apk).stdout.split()[0].decode()
        require(actual == hashlib.sha256(Path(self.args.apk).read_bytes()).hexdigest())
        self.load_trusted_window_uids()
        self.size = self.dimensions()
        self.shell("mkdir", "-m", "700", self.remote)
        self.remote_owned = True
        self.start_logcat()
        self.shell("wm", "dismiss-keyguard", required=False)
        self.launch(); self.started = True
        self.set_stage("live-vault")
        self.unlock(self.fixture["master"], self.fixture["key"])
        item = self.fixture["items"][0]
        require(self.select_item(item["title"], item["id"]) == (item["id"], item["revision"]))
        self.tap("立即锁定", class_name="android.widget.Button")
        self.visible("打开本地金库", class_name="android.widget.Button")
        self.observe_lifecycle()
        # This is explicitly provided setup material, like a fixture manifest;
        # locksettings may echo the new PIN to stdout, never ordinary logs.
        self.provision_pin()
        self.done("owned_emulator_and_exact_live_host_vault_verified_before_PIN_setup")

    def os_prompt(self, deadline=None):
        deadline = deadline if deadline is not None else time.monotonic() + self.args.timeout
        seen_busy = False
        while time.monotonic() < deadline:
            nodes, focused, binding = self.bound_snapshot(deadline)
            self.record_observation(nodes, focused)
            if credential_marker(nodes, focused, self.size):
                self.observe_lifecycle(nodes, focused)
                return nodes, focused, binding
            if focused == PACKAGE:
                controls = [node for node in nodes if node.get("package") == PACKAGE and node.get("class") == "android.widget.Button" and
                            node.get("text") in {"打开本地金库", "使用此设备认证解锁", "启用此设备认证"}]
                if any(node.get("enabled") == "false" for node in controls):
                    seen_busy = True
                    time.sleep(.2)
                    continue
                errors = [node.get("text", "") for node in nodes if node.get("package") == PACKAGE and node.get("class") == "android.widget.TextView"]
                refused = any(text.startswith(REFUSED_PREFIXES) for text in errors)
                settled_locked = any(node.get("text") == "打开本地金库" and node.get("enabled") == "true" for node in controls)
                if refused or settled_locked and (seen_busy or self.stage == "enable-prompt"):
                    self.observe_lifecycle(nodes, focused); raise AcceptanceFailure()
            time.sleep(.2)
        self.observe_lifecycle(); raise AcceptanceFailure()

    def authenticate_pin(self):
        deadline = time.monotonic() + self.args.timeout
        nodes, package, binding = self.os_prompt(deadline)

        def fresh():
            current, owner, _ = self.bound_snapshot(deadline, binding)
            require(owner == package and credential_marker(current, owner, self.size))
            entries, keys, fallback = credential_controls(current, owner, self.size)
            require(len(entries) <= 1 and all(len(values) <= 1 for values in keys.values()) and len(fallback) <= 1)
            return entries, keys, fallback

        entries, keypad, fallback = credential_controls(nodes, package, self.size)
        require(len(entries) <= 1 and all(len(values) <= 1 for values in keypad.values()) and len(fallback) <= 1)
        if not entries and not any(keypad.values()):
            _, _, current_fallback = fresh()
            require(len(current_fallback) == 1)
            self.shell("input", "tap", *center(current_fallback[0]), timeout=self.remaining(deadline, 10))
            # One explicit OS fallback transition may create a new window;
            # observe it afresh without reissuing authentication or PIN.
            nodes, package, binding = self.os_prompt(deadline)
            entries, keypad, fallback = credential_controls(nodes, package, self.size)
            require(len(entries) <= 1 and all(len(values) <= 1 for values in keypad.values()))
            require(entries or any(keypad.values()))
        if any(keypad.values()):
            input_mode = "keypad"
            require(all(len(values) == 1 for values in keypad.values()))
            for digit in self.pin:
                _, current_keys, _ = fresh()
                require(all(len(values) == 1 for values in current_keys.values()))
                input_controls = {digit:(values[0].get("resource-id"), values[0].get("class")) for digit, values in current_keys.items()}
                self.shell("input", "tap", *center(current_keys[digit][0]), timeout=self.remaining(deadline, 10))
        else:
            input_mode = "entry"
            current_entries, _, _ = fresh()
            require(len(current_entries) == 1)
            self.shell("input", "tap", *center(current_entries[0]), timeout=self.remaining(deadline, 10))
            current_entries, _, _ = fresh()
            require(len(current_entries) == 1 and current_entries[0].get("focused") == "true")
            input_controls = (current_entries[0].get("resource-id"), current_entries[0].get("class"))
            self.shell("input", "text", self.pin, timeout=self.remaining(deadline, 10))
        current, owner, final_binding = self.bound_snapshot(deadline)
        if final_binding == binding and owner == package and credential_marker(current, owner, self.size):
            entries, keys, _ = credential_controls(current, owner, self.size)
            # A same-token window may have returned to fallback or changed its
            # input mode. Do not send Enter to that different control; the
            # subsequent native enabled/unlocked oracle decides the outcome.
            same_input = (len(entries) == 1 and entries[0].get("focused") == "true"
                          and (entries[0].get("resource-id"), entries[0].get("class")) == input_controls) if input_mode == "entry" else (
                len(entries) <= 1 and all(len(values) == 1 for values in keys.values())
                and {digit:(values[0].get("resource-id"), values[0].get("class")) for digit, values in keys.items()} == input_controls)
            if same_input:
                self.shell("input", "keyevent", "KEYCODE_ENTER", timeout=self.remaining(deadline, 10))

    def enabled(self, nodes):
        return any(node.get("package") == PACKAGE and node.get("class") == "android.widget.TextView" and
                   node.get("text", "").startswith("已启用；") for node in nodes)

    def native_auth_flow(self):
        self.set_stage("enable")
        self.unlock(self.fixture["master"], self.fixture["key"])
        self.arm_auth_diagnostic()
        self.tap("启用此设备认证", class_name="android.widget.Button")
        self.set_stage("enable-prompt"); self.authenticate_pin()
        self.wait(self.enabled)
        self.done("explicit_opt_in_encrypts_capsule_after_real_OS_PIN")
        self.tap("立即锁定", class_name="android.widget.Button")
        self.visible("打开本地金库", class_name="android.widget.Button")
        self.set_stage("quick")
        self.arm_auth_diagnostic()
        self.tap("使用此设备认证解锁", class_name="android.widget.Button")
        self.set_stage("quick-prompt"); self.authenticate_pin()
        self.list_ready()
        item = self.fixture["items"][0]
        identity = self.select_item(item["title"], item["id"])
        require(identity == (item["id"],item["revision"]))
        self.reveal("显示密码",identity,item["password"])
        self.hide(); self.done("real_OS_PIN_unwraps_original_vault_and_exact_target_password")
        self.tap("立即锁定", class_name="android.widget.Button")
        self.visible("打开本地金库", class_name="android.widget.Button")
        self.set_stage("cancel")
        self.arm_auth_diagnostic()
        self.tap("使用此设备认证解锁", class_name="android.widget.Button")
        self.set_stage("cancel-prompt"); self.os_prompt()
        self.shell("input", "keyevent", "KEYCODE_BACK")
        self.visible("打开本地金库", class_name="android.widget.Button")
        require(not any(self.matching(self.snapshot(), "新建登录", "android.widget.Button")))
        self.no_visible_secrets()
        self.done("OS_auth_cancellation_keeps_vault_locked_without_visible_values")

    def key_policy(self):
        self.set_stage("key-policy")
        self.key_policy_diagnostic = key_policy_metadata(-1, b"")
        self.key_policy_diagnostic["stage"] = "instrument-command"
        result = self.command(["shell", "am", "instrument", "-w", "-r", "-e", "class",
                               "org.locklark.android.DeviceKeyProtectionTest",
                               PACKAGE + ".test/androidx.test.runner.AndroidJUnitRunner"], timeout=180, required=False,
                              oracle="key-policy-instrumentation.txt")
        self.key_policy_diagnostic = key_policy_metadata(result.returncode, result.stdout)
        self.key_level = self.key_policy_diagnostic["key_level"]
        self.write_private("key-policy-result.json", {"diagnostic":self.key_policy_diagnostic,
            "reported_security_level":self.key_level, "physical_hardware_verified":False})
        require(key_policy_passed(self.key_policy_diagnostic))
        self.done("actual_app_UID_key_is_nonexportable_per_operation_and_rejects_fresh_unauthenticated_cipher")

    def copy_and_reinstall(self):
        self.set_stage("copy-encrypted-state")
        self.shell("am", "force-stop", PACKAGE)
        archive = self.command(["exec-out", "run-as", PACKAGE, "tar", "-C", "no_backup", "-cf", "-", "personal.ll", "device-unlock"],oracle="encrypted-transfer.tar",timeout=90).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            files = [member for member in bundle.getmembers() if member.isfile()]
            require(any(member.name == "personal.ll" for member in files))
            for member in bundle.getmembers():
                require(not member.issym() and not member.islnk())
                require(member.name.rstrip("/") in {"personal.ll","device-unlock","device-unlock/installation"} or bool(re.fullmatch(r"device-unlock/[a-f0-9]{64}\.capsule",member.name)))
        self.set_stage("reinstall")
        self.command(["uninstall",PACKAGE],timeout=120)
        self.command(["install", "-r",self.args.apk],timeout=180)
        self.load_trusted_window_uids()
        self.launch(); self.visible("生成新的 Secret Key",class_name="android.widget.Button")
        self.shell("am","force-stop",PACKAGE)
        self.set_stage("restore")
        result = subprocess.run(self.adb + ["exec-out","run-as",PACKAGE,"tar","-C","no_backup","-xf","-"],
                                input=archive,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
        self.controller.write(result.stdout + result.stderr); self.controller.flush()
        require(result.returncode == 0)
        self.launch(); self.visible("打开本地金库",class_name="android.widget.Button")
        self.set_stage("copied-capsule-refusal")
        self.arm_auth_diagnostic()
        self.tap("使用此设备认证解锁",class_name="android.widget.Button")
        self.wait(lambda nodes:native_ui_state(nodes) == "refused")
        self.visible("打开本地金库",class_name="android.widget.Button")
        require(not any(self.matching(self.snapshot(),"新建登录","android.widget.Button")))
        self.no_visible_secrets()
        self.done("copied_ciphertext_and_alias_metadata_do_not_transfer_OS_key_after_reinstall")
        self.set_stage("full-factor-recovery")
        self.unlock(self.fixture["master"],self.fixture["key"])
        item = self.fixture["items"][0]
        require(self.select_item(item["title"],item["id"]) == (item["id"],item["revision"]))
        self.tap("立即锁定",class_name="android.widget.Button")
        self.visible("打开本地金库",class_name="android.widget.Button")
        self.done("restored_encrypted_vault_still_requires_and_accepts_original_complete_factors")

    def cleanup_pin(self):
        if self.pin_attempted:
            self.set_stage("pin-cleanup")
            self.shell("am", "force-stop", PACKAGE, required=False)
            # A timeout may have applied the requested PIN. Verify only that
            # exact known value; never remove an unknown/pre-existing lock.
            candidate = self.shell("locksettings", "verify", "--old", self.pin, oracle="pin-candidate-verification.txt", timeout=60, required=False)
            if candidate.returncode == 0:
                self.shell("locksettings", "clear", "--old", self.pin, oracle="pin-cleanup.txt", timeout=60)
            else:
                empty = self.shell("locksettings", "verify", oracle="pin-empty-cleanup.txt", timeout=60, required=False)
                require(empty.returncode == 0)
            self.pin_owned = False
            self.pin_attempted = False


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--adb",required=True)
    result.add_argument("--serial",required=True)
    result.add_argument("--apk",required=True)
    result.add_argument("--evidence-root",required=True)
    result.add_argument("--artifacts",required=True)
    result.add_argument("--authorize-device-pin-setup",action="store_true")
    result.add_argument("--timeout",type=int,default=120)
    return result


def main():
    args = parser().parse_args()
    os.umask(0o077)
    acceptance = None
    success = False
    failure = "prerequisites"
    diagnostic = {}
    try:
        require(args.authorize_device_pin_setup and bool(re.fullmatch(r"emulator-[0-9]+",args.serial)))
        require(10 <= args.timeout <= 180)
        evidence = validated_evidence(args.evidence_root)
        acceptance = DeviceCredentialAcceptance(args,evidence)
        acceptance.setup_owned_emulator()
        acceptance.native_auth_flow()
        acceptance.key_policy()
        acceptance.copy_and_reinstall()
        require(hashlib.sha256(private_file(acceptance.source / "expected-private.json")).hexdigest() == acceptance.source_hash)
        success = True
    except (Exception,KeyboardInterrupt):
        failure = acceptance.stage if acceptance else "prerequisites"
        if acceptance:
            diagnostic = acceptance.failure_metadata()
    finally:
        if acceptance:
            try: acceptance.cleanup_pin()
            except Exception: success=False; failure="pin-cleanup"
            try: acceptance.close(); acceptance.scan()
            except Exception: success=False; failure="private-canary-scan"
            acceptance.write_private("result.json",{"success":success,"stage":"complete" if success else failure,
                "checks":acceptance.checks,"reported_key_security_level":acceptance.key_level,
                "physical_hardware_verified":False,"source_fixture_sha256":acceptance.source_hash,"diagnostic":diagnostic})
            print("Private Android OS credential evidence: " + str(acceptance.root))
    if not success:
        print("FAIL: Android OS credential acceptance at " + failure)
        print("Android OS credential diagnostic: " + json.dumps(diagnostic, sort_keys=True))
    else: print("PASS: native OS credential opt-in, quick unlock, cancellation and nontransferable device key; private canary scan")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
