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
from mobile_android_acceptance import AndroidAcceptance, AcceptanceFailure, PACKAGE, center, require
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


def credential_marker(nodes, focused):
    if focused not in OS_PACKAGES:
        return False
    usable = []
    for node in nodes:
        if node.get("package") != focused or node.get("enabled") != "true":
            continue
        try: center(node)
        except AcceptanceFailure: continue
        usable.append(node)
    if any(node.get("resource-id", "").endswith(("/pinEntry", "/pin_entry", "/passwordEntry", "/password_entry", "/lockPassword")) for node in usable):
        return True
    keys = {digit for digit in "0123456789" if any(node.get("resource-id", "").endswith("/key" + digit) for node in usable)}
    if len(keys) == 10:
        return True
    title = any(node.get("text") == "认证此设备以解封本地金库授权" for node in usable)
    fallback = any(node.get("text") in {"Use PIN", "Use pin", "Use screen lock", "使用 PIN 码", "使用PIN码", "使用屏幕锁定"} for node in usable)
    return title and fallback


def focused_identity(raw, nodes):
    match = re.search(rb"mCurrentFocus=Window\{([a-f0-9]+)[^\n]*", raw)
    if not match:
        return "unknown"
    for package in OS_PACKAGES | {PACKAGE}:
        if (package + "/").encode() in match[0]:
            return package
    # BiometricPrompt sometimes has a title instead of a component. Bind its
    # WindowManager record to the system UID before considering OS nodes.
    block = re.search(rb"Window #[0-9]+ Window\{" + match[1] + rb"[^\n]*\}:[\s\S]*?(?=\n\s*Window #[0-9]+ |\Z)", raw)
    if block and re.search(rb"\bmOwnerUid=1000\b", block[0]):
        candidates = [package for package in OS_PACKAGES if credential_marker(nodes, package)]
        if len(candidates) == 1:
            return candidates[0]
    return "unknown"


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
        self.locksettings_diagnostic = {}
        self.secure_lock_screen = None
        self.auth_pid = None
        self.auth_floor = 0
        self.last_observation = {"phase":"prerequisites", "focused_package":"unknown", "main_state":"unknown",
                                 "native_ui_state":"unknown", "credential_marker":False}

    def set_stage(self, value):
        require(value in STAGES)
        self.stage = value

    def done(self, name):
        self.checks.append(name)
        print("PASS: Android device credential " + name, flush=True)

    def focused_package(self, nodes=None):
        raw = self.shell("dumpsys", "window", "windows").stdout
        return focused_identity(raw, nodes or [])

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
                                 "credential_marker":credential_marker(nodes, focused)}

    def failure_metadata(self):
        auth = {}
        try:
            if self.auth_pid is not None and self.shell("pidof", PACKAGE).stdout.strip() == str(self.auth_pid).encode():
                auth = fresh_auth_failure(self.auth_log(self.auth_pid), self.auth_pid, self.auth_floor)
        except Exception:
            pass
        return {"secure_lock_screen_feature":self.secure_lock_screen,
                "locksettings":self.locksettings_diagnostic.copy(), "last_ui":self.last_observation.copy(), "native_auth":auth}

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
        self.size = self.dimensions()
        self.shell("mkdir", "-m", "700", self.remote)
        self.remote_owned = True
        self.start_logcat()
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

    def os_prompt(self):
        deadline = time.monotonic() + self.args.timeout
        seen_busy = False
        while time.monotonic() < deadline:
            nodes = self.snapshot()
            focused = self.focused_package(nodes)
            self.record_observation(nodes, focused)
            if credential_marker(nodes, focused):
                self.observe_lifecycle(nodes, focused)
                return nodes, focused
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
        nodes, package = self.os_prompt()
        def candidates(current, digit):
            return [node for node in current if node.get("package") == package and node.get("enabled") == "true" and node.get("resource-id", "").endswith("/key" + digit)]
        keypad = {digit: candidates(nodes, digit) for digit in set(self.pin)}
        if all(len(values) == 1 for values in keypad.values()):
            for digit in self.pin:
                require(self.focused_package(self.snapshot()) == package)
                self.shell("input", "tap", *center(keypad[digit][0]))
        else:
            entries = [node for node in nodes if node.get("package") == package and node.get("enabled") == "true" and
                       (node.get("class") == "android.widget.EditText" and node.get("password") == "true" or
                        node.get("resource-id", "").endswith(("/pinEntry", "/pin_entry", "/passwordEntry", "/password_entry", "/lockPassword")))]
            if not entries:
                fallback = [node for node in nodes if node.get("package") == package and node.get("enabled") == "true" and
                            node.get("text", "") in {"Use PIN", "Use pin", "Use screen lock", "使用 PIN 码", "使用PIN码", "使用屏幕锁定"}]
                require(len(fallback) == 1)
                require(self.focused_package(self.snapshot()) == package)
                self.shell("input", "tap", *center(fallback[0]))
                nodes, package = self.os_prompt()
                entries = [node for node in nodes if node.get("package") == package and node.get("enabled") == "true" and
                           (node.get("resource-id", "").endswith(("/pinEntry", "/pin_entry", "/passwordEntry", "/password_entry", "/lockPassword")) or
                            node.get("password") == "true" and node.get("class") == "android.widget.EditText")]
            require(len(entries) == 1 and self.focused_package(self.snapshot()) == package)
            self.shell("input", "tap", *center(entries[0]))
            require(self.focused_package(self.snapshot()) == package)
            self.shell("input", "text", self.pin)
        if self.focused_package(self.snapshot()) in OS_PACKAGES:
            self.shell("input", "keyevent", "KEYCODE_ENTER")

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
        result = self.command(["shell", "am", "instrument", "-w", "-r", "-e", "class",
                               "org.locklark.android.DeviceKeyProtectionTest",
                               PACKAGE + ".test/androidx.test.runner.AndroidJUnitRunner"], timeout=180)
        require(complete_pass(result.returncode,result.stdout,expected_tests=1))
        expected_class = b"org.locklark.android.DeviceKeyProtectionTest"
        expected_test = b"realDeviceCapsuleUsesNonexportablePerOperationKey"
        require(set(re.findall(rb"INSTRUMENTATION_STATUS: class=([^\r\n]+)",result.stdout)) == {expected_class})
        require(set(re.findall(rb"INSTRUMENTATION_STATUS: test=([^\r\n]+)",result.stdout)) == {expected_test})
        levels = re.findall(rb"INSTRUMENTATION_STATUS: locklark_key_level=(software|tee|strongbox|unknown|hardware-unspecified)",result.stdout)
        require(len(levels) == 1)
        self.key_level = levels[0].decode()
        self.write_private("key-policy-result.json", {"class":expected_class.decode(), "test":expected_test.decode(), "count":1,
            "reported_security_level":self.key_level, "physical_hardware_verified":False})
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
