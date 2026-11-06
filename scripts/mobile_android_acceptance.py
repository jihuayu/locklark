#!/usr/bin/env python3
"""Independent host-driven Android UI acceptance; synthetic emulator data only.

No instrumentation, app method calls, screenshots, or test backend are used.
All UI interaction uses ADB tap/text/swipe and public accessibility labels.
XML and explicit disclosures are private oracle artifacts. Every other captured
ADB output and the full logcat stream are scanned for synthetic secret values.
"""

import argparse
import base64
import collections
import hashlib
import hmac
import json
import os
import pathlib
import re
import select
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET


PACKAGE = "org.locklark.android"
COMPONENT = PACKAGE + "/.MainActivity"
STAGES = {"prerequisites", "install", "create", "manual-login", "disclosure",
          "edit-password", "otp", "generated-login", "search", "background-lock",
          "wrong-factors", "full-unlock", "restart", "copy-vault", "audit",
          "kdbx-peer", "private-canary-scan", "complete"}
ACTIVITY_STATES = {"unknown", "initializing", "started", "resumed", "paused", "stopping", "stopped", "destroyed", "mixed"}
FOREGROUND_STATES = {"unknown", "none", "app", "launcher", "system", "other"}
CONTROL_STATES = {"unknown", "no-app", "app-other", "create-form", "unlock-ready", "unlock-busy", "lock-cleanup", "locked-cover",
                  "opening", "list-ready", "list-busy", "detail-ready", "detail-busy", "create-ready", "create-busy"}
WAIT_STATES = {"unknown", "capture-original", "background-stopped", "foreground-app", "locked-form"}
IDENTITY_STATES = {"unknown", "captured", "stopped-match", "resumed-match", "changed", "missing", "ambiguous", "destroyed"}
OPERATIONS = {"unknown", "wait", "locate", "tap", "type-text", "keyboard-check", "keyboard-dismiss"}
COMMANDS = {"unknown", "properties", "display", "install", "app-reset", "private-dir", "launch", "force-stop", "ui-dump",
            "ui-read", "ui-cleanup", "tap", "text", "scroll", "key", "ime", "lifecycle", "db-copy"}
STDERR_CLASSES = {"unknown", "empty", "offline", "service-missing", "permission", "timeout", "spawn-error", "other"}
TARGETS = {"unknown", "row", "field-picker", "generate-key", "new-master", "repeat-master", "backup-ack", "create-vault",
           "new-login", "login-title", "username", "login-password", "generate-password", "save-login", "show-username",
           "show-password", "show-otp", "hide", "edit", "edit-value", "save-field", "field-password", "field-otp",
           "back-list", "query", "search", "unlock", "master", "account-key", "lock"}
CREATE_STEPS = {"unknown", "open-create", "read-account-key", "enter-master", "repeat-master", "ack-backup", "submit-create", "wait-created-list"}
EXCEPTIONS = {"none", "AcceptanceFailure", "TimeoutExpired", "ParseError", "ValueError", "TypeError", "AttributeError",
              "KeyError", "IndexError", "NameError", "OSError", "FileNotFoundError", "BrokenPipeError", "RuntimeError", "unexpected"}
HELPERS = {"unknown", "remaining", "snapshot", "matching", "center", "locate", "locate_candidate", "tap", "enter", "dismiss_keyboard", "record",
           "exercise", "command", "parse_nodes", "wait", "background_and_relaunch", "observe_activity_state"}


class AcceptanceFailure(Exception):
    """The caller prints a fixed stage, never the exception or child output."""


def require(condition):
    if not condition:
        raise AcceptanceFailure()


def validate_target(serial, reset, peer=None, cli=None):
    require(bool(re.fullmatch(r"emulator-[0-9]+", serial)) and reset)
    require(not peer or cli)


def peer_executable(path):
    # A venv's python is commonly a symlink. Resolving it selects the base
    # interpreter and silently drops that venv's installed independent reader.
    return os.path.abspath(path)


def otp_code(seed, counter, digits=6):
    key = base64.b32decode(seed + "=" * (-len(seed) % 8), casefold=False)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
    return str(number % (10 ** digits)).zfill(digits)


def verify_otp(seed, code, before, after):
    require(bool(re.fullmatch(r"[0-9]{6}", code)))
    require(0 <= after - before <= 30 and after // 30 - before // 30 <= 1)
    require(code in {otp_code(seed, n) for n in range(before // 30, after // 30 + 1)})


def scan_public(raw, values):
    """Check raw and common encoded leaks without returning a matched value."""
    for value in values:
        require(isinstance(value, str) and value)
        for part in {value, *value.splitlines()}:
            if not part:
                continue
            encoded = part.encode()
            encodings = (json.dumps(part, ensure_ascii=True)[1:-1].encode(),
                         json.dumps(part, ensure_ascii=False)[1:-1].encode(),
                         urllib.parse.quote(part, safe="").encode(),
                         base64.b64encode(encoded), base64.urlsafe_b64encode(encoded),
                         encoded.hex().encode(), encoded.hex().upper().encode())
            # OTP codes are short numeric values, so match token boundaries.
            if re.fullmatch(r"[0-9]{6,8}", part):
                require(not re.search(rb"(?<![A-Za-z0-9])" + encoded + rb"(?![A-Za-z0-9])", raw))
                encodings = tuple(pattern for pattern in encodings if pattern != encoded)
            else:
                require(encoded not in raw)
            require(not any(pattern and pattern in raw for pattern in encodings))


def parse_nodes(raw):
    return [node.attrib for node in ET.fromstring(raw).iter("node")]


def is_unlock_refusal(nodes):
    return any(node.get("package") == PACKAGE and node.get("class") == "android.widget.TextView"
               and node.get("enabled") == "true" and node.get("text", "").startswith("解锁未完成：")
               for node in nodes)


def app_activity_records(raw):
    text = raw.decode("utf-8", errors="replace")
    component = re.compile(r"\borg\.locklark\.android/(?:\.MainActivity|org\.locklark\.android\.MainActivity)\b")
    headers = list(re.finditer(r"(?m)^[ \t]*\*[ \t]*Hist[ \t]+#\d+:[ \t]*ActivityRecord\{[^\n]*\}", text))
    records = []
    for index, header in enumerate(headers):
        if component.search(header.group()):
            end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
            body = text[header.end():end]
            next_task = re.search(r"(?m)^[ \t]*\*[ \t]*Task\{", body)
            body = body[:next_task.start()] if next_task else body
            match = re.search(r"\b(?:mState|state)=([A-Z_]+)\b", body)
            state = match.group(1).lower() if match else "unknown"
            token = re.search(r"ActivityRecord\{([0-9a-fA-F]{1,16})[ \t]", header.group())
            task = re.search(r"\bt([0-9]+)\b", header.group())
            records.append({"token": token[1] if token else None, "task": task[1] if task else None,
                            "state": state if state in ACTIVITY_STATES else "unknown"})
    return records


def top_resumed_record(raw):
    text = raw.decode("utf-8", errors="replace")

    def selected(values):
        values = {value.strip() for value in values}
        if len(values) != 1:
            return None, False
        value = next(iter(values))
        if value == "null":
            return None, True
        return (value, False) if value.startswith("ActivityRecord{") else (None, False)

    top = re.findall(r"(?m)^[ \t]*(?:mTopResumedActivity|topResumedActivity)[ \t]*[:=][ \t]*([^\n]*)", text)
    if top:
        # A reported top field is authoritative, including null/unknown or
        # conflicting values. A stale legacy record must never override it.
        return selected(top)
    legacy = re.findall(r"(?m)^[ \t]*mResumedActivity[ \t]*[:=][ \t]*([^\n]*)", text)
    return selected(legacy)


def top_activity_identity(raw):
    record, _ = top_resumed_record(raw)
    if record is None or not re.search(r"\borg\.locklark\.android/(?:\.MainActivity|org\.locklark\.android\.MainActivity)\b", record):
        return None
    token = re.search(r"ActivityRecord\{([0-9a-fA-F]{1,16})[ \t]", record)
    task = re.search(r"\bt([0-9]+)\b", record)
    return (token[1], task[1]) if token and task else None


def lifecycle_state(raw):
    component = re.compile(r"\borg\.locklark\.android/(?:\.MainActivity|org\.locklark\.android\.MainActivity)\b")
    states = [record["state"] for record in app_activity_records(raw)]
    activity = "unknown"
    if states and "stopped" in states and set(states) <= {"stopped", "destroyed"}:
        activity = "stopped"
    elif "resumed" in states:
        activity = "resumed"
    elif len(set(states)) == 1:
        activity = states[0]
    elif states:
        activity = "mixed"
    foreground = "unknown"
    record, saw_null = top_resumed_record(raw)
    if record:
        if component.search(record):
            foreground = "app"
        elif re.search(r"\b(?:com\.android\.launcher3|com\.google\.android\.apps\.nexuslauncher)/", record):
            foreground = "launcher"
        elif re.search(r"\b(?:com\.android\.systemui|com\.google\.android\.setupwizard)/", record):
            foreground = "system"
        elif re.search(r"\bu\d+[ \t]+[A-Za-z][A-Za-z0-9_.]*/[A-Za-z0-9_.$]+", record):
            foreground = "other"
    if foreground == "unknown" and saw_null:
        foreground = "none"
    return {"activity": activity, "foreground": foreground}


def background_is_stopped(state):
    return state.get("activity") == "stopped" and state.get("foreground") in {"none", "launcher", "system", "other"}


def ui_control_state(nodes):
    own = [node for node in nodes if node.get("package") == PACKAGE]
    texts = {node.get("text") for node in own}
    for label, value in (("正在完成锁定…", "lock-cleanup"), ("Locklark 已锁定", "locked-cover"),
                         ("正在打开此设备的本地金库…", "opening")):
        if label in texts:
            return value
    for label, ready, busy in (("打开本地金库", "unlock-ready", "unlock-busy"),
                              ("新建登录", "list-ready", "list-busy"),
                              ("显示密码", "detail-ready", "detail-busy"),
                              ("生成新的 Secret Key", "create-ready", "create-busy")):
        control = next((node for node in own if node.get("class") == "android.widget.Button"
                        and label in (node.get("text"), node.get("content-desc"))), None)
        if control:
            return ready if control.get("enabled") == "true" else busy
    if any(node.get("class") == "android.widget.Button" and "创建并解锁" in (node.get("text"), node.get("content-desc")) for node in own):
        return "create-form"
    return "app-other" if own else "no-app"


def safe_host_diagnosis(value):
    value = value if isinstance(value, dict) else {}
    choices = {"activity": ACTIVITY_STATES, "foreground": FOREGROUND_STATES,
               "control": CONTROL_STATES, "wait": WAIT_STATES, "identity": IDENTITY_STATES,
               "ime": {"unknown", "shown", "hidden"}, "operation": OPERATIONS, "target": TARGETS, "step": CREATE_STEPS,
               "command": COMMANDS, "command_exit": {"unknown", "pending", "ok", "nonzero", "timeout", "error"},
               "stderr_class": STDERR_CLASSES,
               "bounds": {"unknown", "missing", "ready", "disabled", "hidden", "invalid-bounds", "offscreen"},
               "exception": EXCEPTIONS, "helper": HELPERS,
               "reason": {"unknown", "assertion", "python-contract", "xml", "deadline", "wait-expired", "control-not-actionable", "command-failed"}}
    result = {key: value.get(key) if isinstance(value.get(key), str) and value[key] in allowed else "unknown"
              for key, allowed in choices.items()}
    for key, lower, upper in (("exit_code", -255, 255), ("source_line", 1, 100000)):
        number = value.get(key)
        result[key] = number if type(number) is int and lower <= number <= upper else None
    for key in ("create_form", "create_master_enabled", "create_repeat_enabled", "backup_acknowledged"):
        result[key] = value.get(key) if type(value.get(key)) is bool else None
    return result


def target_alias(label, class_name=None):
    labels = {"生成新的 Secret Key": "generate-key", "新的主密码": "new-master", "再次输入主密码": "repeat-master",
        "我已离线保存 Secret Key": "backup-ack", "创建并解锁": "create-vault", "新建登录": "new-login",
        "登录标题": "login-title", "用户名": "username", "登录密码": "login-password", "生成强密码": "generate-password",
        "保存登录": "save-login", "显示用户名": "show-username", "显示密码": "show-password", "显示验证码": "show-otp",
        "隐藏已显示字段": "hide", "编辑登录字段": "edit", "新值（原生可见多行正文）": "edit-value",
        "保存字段": "save-field", "password": "field-password", "otp": "field-otp", "返回列表": "back-list",
        "搜索标题": "query", "搜索": "search", "打开本地金库": "unlock", "主密码": "master", "Secret Key": "account-key", "立即锁定": "lock"}
    if isinstance(label, str) and label.startswith("选择登录："):
        return "row"
    if label is not None and not isinstance(label, str):
        return "unknown"
    return labels.get(label, "field-picker" if label is None and class_name == "android.widget.Spinner" else "unknown")


def command_category(arguments):
    parts = tuple(map(str, arguments[:4]))
    categories = {("shell", "getprop"): "properties", ("shell", "wm", "size"): "display", ("install",): "install",
        ("shell", "pm", "clear"): "app-reset", ("shell", "mkdir"): "private-dir", ("shell", "am", "start"): "launch",
        ("shell", "am", "force-stop"): "force-stop", ("shell", "uiautomator", "dump"): "ui-dump",
        ("exec-out", "cat"): "ui-read", ("shell", "rm"): "ui-cleanup", ("shell", "input", "tap"): "tap",
        ("shell", "input", "text"): "text", ("shell", "input", "swipe"): "scroll", ("shell", "input", "keyevent"): "key",
        ("shell", "dumpsys", "input_method"): "ime", ("shell", "dumpsys", "activity"): "lifecycle",
        ("exec-out", "run-as"): "db-copy"}
    return next((value for prefix, value in categories.items() if parts[:len(prefix)] == prefix), "unknown")


def adb_stderr_class(raw):
    """Reduce captured stderr to fixed categories; never return subprocess text."""
    if not raw:
        return "empty"
    lowered = raw.lower()
    if b"device offline" in lowered or b"no devices/emulators found" in lowered or re.search(rb"\bdevice\b[^\r\n]{0,192}\bnot found\b", lowered):
        return "offline"
    if b"can't find service" in lowered or b"cannot find service" in lowered or b"service not found" in lowered:
        return "service-missing"
    if b"permission denied" in lowered or b"permission denial" in lowered or b"securityexception" in lowered or b"device unauthorized" in lowered:
        return "permission"
    return "other"


def verify_audit(events, disclosures, mutations, generated_id, *, expected_exports=0, expected_audits=1):
    """Require the exact fixture item effects, including no extra disclosures.

    Native list/search/unlock events are metadata operations. The host CLI adds
    item.list and audit.list; its optional encrypted export adds exactly one
    itemless vault.export.kdbx intent. Those explicit actions are allowed below;
    they never excuse additional item mutations or disclosure intents.
    """
    manual_ids = {item for _, item, _ in mutations}
    require(len(manual_ids) == 1 and generated_id not in manual_ids)
    manual_id = next(iter(manual_ids))
    fixture_ids = {manual_id, generated_id}
    expected_disclosures = collections.Counter(disclosures)
    require(bool(expected_disclosures) and all(item in fixture_ids for _, item, _ in disclosures))
    expected_mutations = collections.Counter(mutations)
    expected_mutations.update({("item.add", manual_id, None): 1, ("item.generate", generated_id, None): 1})
    observed_disclosures, observed_mutations = collections.Counter(), collections.Counter()
    metadata = collections.Counter()
    allowed_metadata = {"vault.create", "desktop.unlock", "item.list", "item.search", "audit.list", "vault.export.kdbx"}
    for event in events:
        action, item, revision = event["action"], event.get("item_id"), event.get("base_revision")
        result = event["result"]
        if action in allowed_metadata:
            require(not item and not revision)
            require(result == ("intent" if action == "vault.export.kdbx" else "succeeded"))
            metadata[action] += 1
            continue
        require(item in fixture_ids)
        key = (action, item, revision)
        if action.startswith("item.desktop.show."):
            require(result == "intent")
            observed_disclosures[key] += 1
        else:
            require(result == "succeeded")
            observed_mutations[key] += 1
    require(observed_disclosures == expected_disclosures)
    require(observed_mutations == expected_mutations)
    require(metadata["vault.create"] == 1 and metadata["audit.list"] == expected_audits)
    require(metadata["vault.export.kdbx"] == expected_exports)


def center(node):
    match = re.fullmatch(r"\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]", node.get("bounds", ""))
    require(match is not None)
    left, top, right, bottom = map(int, match.groups())
    require(right > left and bottom > top)
    return (left + right) // 2, (top + bottom) // 2


def actionable_bounds(node, viewport=None):
    if node.get("enabled") != "true":
        return "disabled"
    if node.get("visible-to-user") == "false":
        return "hidden"
    try:
        center(node)
    except AcceptanceFailure:
        return "invalid-bounds"
    if viewport:
        left, top, right, bottom = map(int, re.findall(r"[0-9]+", node["bounds"]))
        if left < viewport[0] or top < viewport[1] or right > viewport[2] or bottom > viewport[3]:
            return "offscreen"
    return "ready"


def app_viewport(nodes, size):
    screen = (0, 0, size[0], size[1])
    for node in nodes:
        if node.get("package") == PACKAGE and node.get("class") == "android.widget.ScrollView":
            try:
                center(node)
            except AcceptanceFailure:
                continue
            left, top, right, bottom = map(int, re.findall(r"[0-9]+", node["bounds"]))
            clipped = max(0, left), max(0, top), min(size[0], right), min(size[1], bottom)
            if clipped[2] > clipped[0] and clipped[3] > clipped[1]:
                return clipped
    return screen


class AndroidAcceptance:
    def __init__(self, args):
        self.args = args
        self.stage = "prerequisites"
        parent = pathlib.Path(args.artifacts).resolve()
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="android-host-ui-", dir=parent))
        self.controller = (self.root / "controller.log").open("xb")
        self.logs = [self.root / "controller.log"]
        self.counter = 0
        self.xml_counter = 0
        self.canaries = []
        self.checks = []
        self.disclosures = []
        self.mutations = []
        self.logger = None
        self.log_thread = None
        self.log_failed = threading.Event()
        self.remote = "/data/local/tmp/locklark-host-ui-" + os.urandom(8).hex()
        self.adb = [str(pathlib.Path(args.adb).resolve()), "-s", args.serial]
        self.started = False
        self.remote_owned = False
        self.private_values = {}
        self.diagnosis = safe_host_diagnosis({})
        self.activity_evidence = []
        self.last_activity_records = []
        self.last_foreground_identity = None

    def set_stage(self, stage):
        require(stage in STAGES)
        self.stage = stage
        self.diagnosis["wait"] = "unknown"
        self.diagnosis["step"] = "unknown"

    def record(self, value):
        require(isinstance(value, str) and value)
        self.canaries.append(value)
        self.write_private("canaries.json", self.canaries)
        return value

    def write_private(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")
        path.chmod(0o600)
        return path

    def command(self, arguments, *, oracle=None, timeout=45, required=True):
        # Never record argv: input text includes synthetic complete factors.
        self.counter += 1
        result = None
        self.diagnosis.update({"command": command_category(arguments), "command_exit": "pending", "exit_code": None, "stderr_class": "unknown"})
        try:
            result = subprocess.run(self.adb + list(map(str, arguments)),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            stdout, stderr = result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b"", error.stderr or b""
            self.diagnosis.update({"command_exit": "timeout", "stderr_class": "timeout"})
        except OSError:
            self.diagnosis.update({"command_exit": "error", "stderr_class": "spawn-error"})
            raise
        if result is not None:
            self.diagnosis.update({"command_exit": "ok" if result.returncode == 0 else "nonzero", "exit_code": result.returncode,
                                   "stderr_class": adb_stderr_class(stderr)})
        if oracle:
            path = self.root / oracle
            path.write_bytes(stdout)
            path.chmod(0o600)
        else:
            self.controller.write(f"command {self.counter} stdout\n".encode() + stdout + b"\n")
        self.controller.write(f"command {self.counter} stderr\n".encode() + stderr + b"\n")
        self.controller.flush()
        if result is None or required and result.returncode != 0:
            self.diagnosis["reason"] = "command-failed"
        require(result is not None)
        if required:
            require(result.returncode == 0)
        return result

    def shell(self, *arguments, **kwargs):
        return self.command(["shell", *arguments], **kwargs)

    @staticmethod
    def remaining(deadline, cap=None):
        left = deadline - time.monotonic()
        require(left > 0)
        return min(left, cap) if cap else left

    def snapshot(self, deadline=None):
        self.xml_counter += 1
        remote = self.remote + "/current.xml"
        timeout = self.remaining(deadline, 45) if deadline else 45
        try:
            dump = self.shell("uiautomator", "dump", "--compressed", remote, timeout=timeout, required=False)
        except (AcceptanceFailure, subprocess.TimeoutExpired):
            dump = None
        if dump is None or dump.returncode != 0:
            # A cold-boot emulator can briefly lose focus to the keyguard or a
            # system dialog. Recover once, then require a usable hierarchy.
            try:
                self.shell("wm", "dismiss-keyguard", required=False)
            except (AcceptanceFailure, subprocess.TimeoutExpired):
                pass
            try:
                self.shell("input", "keyevent", "KEYCODE_WAKEUP", required=False)
            except (AcceptanceFailure, subprocess.TimeoutExpired):
                pass
            self.shell("uiautomator", "dump", "--compressed", remote,
                       timeout=self.remaining(deadline, 45) if deadline else 45)
        result = self.command(["exec-out", "cat", remote], oracle=f"ui-{self.xml_counter:04d}.xml",
                              timeout=self.remaining(deadline, 45) if deadline else 45)
        self.shell("rm", "-f", remote, timeout=self.remaining(deadline, 45) if deadline else 45)
        nodes = parse_nodes(result.stdout)
        self.diagnosis["control"] = ui_control_state(nodes)
        self.viewport = app_viewport(nodes, self.size)
        def field(label, class_name):
            return next((node for node in nodes if node.get("package") == PACKAGE and node.get("class") == class_name
                         and label in (node.get("text"), node.get("content-desc"))), None)
        master, repeated, ack = field("新的主密码", "android.widget.EditText"), field("再次输入主密码", "android.widget.EditText"), field("我已离线保存 Secret Key", "android.widget.CheckBox")
        self.diagnosis.update({"create_form": field("创建并解锁", "android.widget.Button") is not None,
            "create_master_enabled": master is not None and master.get("enabled") == "true",
            "create_repeat_enabled": repeated is not None and repeated.get("enabled") == "true",
            "backup_acknowledged": ack is not None and ack.get("checked") == "true"})
        return nodes

    @staticmethod
    def matching(nodes, label=None, class_name=None, prefix=False, viewport=None):
        for node in nodes:
            if node.get("package") != PACKAGE or node.get("enabled") != "true":
                continue
            if class_name and node.get("class") != class_name:
                continue
            texts = (node.get("text", ""), node.get("content-desc", ""))
            if label is not None and not any(text.startswith(label) if prefix else text == label for text in texts):
                continue
            if actionable_bounds(node, viewport) != "ready":
                continue
            yield node

    def wait(self, predicate, timeout=None, deadline=None):
        self.diagnosis["operation"] = "wait"
        end = deadline if deadline is not None else time.monotonic() + (timeout or self.args.timeout)
        while time.monotonic() < end:
            nodes = self.snapshot(deadline=end)
            result = predicate(nodes)
            if result:
                return result
            time.sleep(0.2)
        self.diagnosis["reason"] = "wait-expired"
        raise AcceptanceFailure()

    def visible(self, label, *, class_name=None, prefix=False):
        self.diagnosis["target"] = target_alias(label, class_name)
        return self.wait(lambda nodes: next(self.matching(nodes, label, class_name, prefix), None))

    def dimensions(self):
        raw = self.shell("wm", "size").stdout
        sizes = re.findall(rb"(?:Physical|Override) size: ([0-9]+)x([0-9]+)", raw)
        require(bool(sizes))
        return tuple(map(int, sizes[-1]))

    def swipe(self, down=False):
        left, top, right, bottom = getattr(self, "viewport", (0, 0, self.size[0], self.size[1]))
        start, end = (0.28, 0.78) if down else (0.78, 0.28)
        self.shell("input", "swipe", (left + right) // 2, top + int((bottom - top) * start),
                   (left + right) // 2, top + int((bottom - top) * end), 350)

    def locate_candidate(self, nodes, label, class_name, prefix):
        candidates = []
        for node in nodes:
            if node.get("package") != PACKAGE or class_name and node.get("class") != class_name:
                continue
            texts = (node.get("text", ""), node.get("content-desc", ""))
            if label is None or any(text.startswith(label) if prefix else text == label for text in texts):
                candidates.append(node)
        self.diagnosis["bounds"] = actionable_bounds(candidates[0], self.viewport) if candidates else "missing"
        return next(self.matching(nodes, label, class_name, prefix, viewport=self.viewport), None)

    def locate(self, label=None, *, class_name=None, prefix=False, scroll=True):
        self.diagnosis.update({"operation": "locate", "target": target_alias(label, class_name)})
        nodes = self.snapshot()
        candidate = self.locate_candidate(nodes, label, class_name, prefix)
        if candidate:
            return candidate
        if scroll:
            # Public native forms use a ScrollView. Search both directions and
            # stop only after actual hierarchy content stops changing.
            for down in (True, False):
                previous = None
                unchanged = 0
                for _ in range(12):
                    self.swipe(down)
                    nodes = self.snapshot()
                    candidate = self.locate_candidate(nodes, label, class_name, prefix)
                    if candidate:
                        return candidate
                    fingerprint = [(n.get("text"), n.get("content-desc"), n.get("bounds")) for n in nodes]
                    unchanged = unchanged + 1 if fingerprint == previous else 0
                    previous = fingerprint
                    if unchanged >= 2:
                        break
        self.diagnosis["reason"] = "control-not-actionable"
        raise AcceptanceFailure()

    def tap(self, label=None, *, class_name=None, prefix=False):
        node = self.locate(label, class_name=class_name, prefix=prefix)
        self.diagnosis["operation"] = "tap"
        x, y = center(node)
        self.shell("input", "tap", x, y)

    def dismiss_keyboard(self):
        self.diagnosis["operation"] = "keyboard-check"
        raw = self.shell("dumpsys", "input_method").stdout
        if re.search(rb"(?:mInputShown|mIsInputViewShown)=true", raw):
            self.diagnosis["operation"] = "keyboard-dismiss"
            self.shell("input", "keyevent", "KEYCODE_BACK")

    def enter(self, label, value):
        # This runner creates ASCII-only values deliberately. Shell metacharacters,
        # percent escapes and whitespace never enter `adb shell input text`.
        require(bool(re.fullmatch(r"[A-Za-z0-9_-]+", value)))
        self.tap(label, class_name="android.widget.EditText")
        self.diagnosis["operation"] = "type-text"
        self.shell("input", "text", value)
        self.dismiss_keyboard()

    def enter_manual_password(self, value):
        generate = self.locate("生成强密码", class_name="android.widget.CheckBox")
        require(generate.get("checked") == "true")
        self.tap("生成强密码", class_name="android.widget.CheckBox")
        # `enter` locates an enabled EditText; generated mode deliberately
        # disables this native field until its checkbox is switched off.
        self.enter("登录密码", value)

    def done(self, name):
        self.checks.append(name)
        print("PASS: Android host UI " + name, flush=True)

    def start_logcat(self):
        path = self.root / "logcat.log"
        handle = path.open("xb")
        self.logs.append(path)
        self.logger = subprocess.Popen(self.adb + ["logcat", "-v", "brief", "-T", "1"],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        def capture():
            count = 0
            try:
                while chunk := self.logger.stdout.read(4096):
                    count += len(chunk)
                    if count > 64 << 20:
                        self.log_failed.set()
                        self.logger.terminate()
                        break
                    handle.write(chunk)
            except Exception:
                self.log_failed.set()
            finally:
                handle.close()

        self.log_thread = threading.Thread(target=capture, daemon=True)
        self.log_thread.start()

    def setup(self):
        validate_target(self.args.serial, self.args.reset_test_app, self.args.peer, self.args.cli)
        require(pathlib.Path(self.args.apk).is_file())
        require(self.shell("getprop", "ro.kernel.qemu").stdout.strip() == b"1")
        require(self.shell("getprop", "sys.boot_completed").stdout.strip() == b"1")
        self.size = self.dimensions()
        self.set_stage("install")
        self.command(["install", "-r", self.args.apk], timeout=180)
        # Package is a compile-time constant; no caller-controlled package can
        # reach pm clear, even if the APK or serial input is malformed.
        self.shell("pm", "clear", PACKAGE)
        self.shell("mkdir", "-m", "700", self.remote)
        self.remote_owned = True
        self.start_logcat()
        self.launch()
        self.started = True

    def launch(self, timeout=90, reuse_existing=False):
        arguments = ["am", "start", "-W"]
        if reuse_existing:
            # Android's REORDER_TO_FRONT brings the existing record to the top
            # of its task; SINGLE_TOP delivers to it instead of duplicating it.
            arguments.extend(("--activity-reorder-to-front", "--activity-single-top"))
        self.shell(*arguments, "-n", COMPONENT, timeout=timeout)

    def observe_activity_state(self, deadline=None):
        raw = self.shell("dumpsys", "activity", "activities", timeout=self.remaining(deadline, 45) if deadline else 45).stdout
        state = lifecycle_state(raw)
        self.diagnosis.update(state)
        self.last_activity_records = app_activity_records(raw)
        self.last_foreground_identity = top_activity_identity(raw)
        self.activity_evidence.append({"phase": self.diagnosis["wait"], "state": state, "records": self.last_activity_records,
                                       "foreground_identity": self.last_foreground_identity})
        self.write_private("activity-records-private.json", self.activity_evidence)
        return state

    def resumed_activity_identity(self):
        records = [record for record in self.last_activity_records if record["state"] == "resumed"]
        if len(records) != 1:
            self.diagnosis["identity"] = "ambiguous" if records else "missing"
            raise AcceptanceFailure()
        record = records[0]
        if not record.get("token") or not record.get("task"):
            self.diagnosis["identity"] = "missing"
            raise AcceptanceFailure()
        identity = record["token"], record["task"]
        if self.last_foreground_identity != identity:
            self.diagnosis["identity"] = "changed" if self.last_foreground_identity else "missing"
            raise AcceptanceFailure()
        return identity

    def require_original_activity(self, original):
        records = [record for record in self.last_activity_records if (record.get("token"), record.get("task")) == original]
        if len(records) != 1:
            self.diagnosis["identity"] = "ambiguous" if records else "changed" if self.last_activity_records else "missing"
            raise AcceptanceFailure()
        if records[0]["state"] == "destroyed":
            self.diagnosis["identity"] = "destroyed"
            raise AcceptanceFailure()
        return records[0]

    def background_and_relaunch(self):
        deadline = time.monotonic() + self.args.timeout
        self.diagnosis["wait"] = "capture-original"
        state = self.observe_activity_state(deadline)
        require(state["foreground"] == "app" and state["activity"] == "resumed")
        original = self.resumed_activity_identity()
        self.diagnosis["identity"] = "captured"
        self.write_private("background-original-private.json", {"token": original[0], "task": original[1]})
        self.diagnosis["wait"] = "background-stopped"
        self.shell("input", "keyevent", "KEYCODE_HOME", timeout=self.remaining(deadline, 45))
        while True:
            state = self.observe_activity_state(deadline)
            record = self.require_original_activity(original)
            if background_is_stopped(state):
                require(record["state"] == "stopped")
                self.diagnosis["identity"] = "stopped-match"
                break
            self.remaining(deadline)
            time.sleep(0.2)
        self.diagnosis["wait"] = "foreground-app"
        self.launch(timeout=self.remaining(deadline, 90), reuse_existing=True)
        while True:
            state = self.observe_activity_state(deadline)
            self.require_original_activity(original)
            if state["foreground"] == "app" and state["activity"] == "resumed":
                resumed = self.resumed_activity_identity()
                if resumed != original:
                    self.diagnosis["identity"] = "changed"
                    raise AcceptanceFailure()
                self.diagnosis["identity"] = "resumed-match"
                break
            self.remaining(deadline)
            time.sleep(0.2)
        self.diagnosis["wait"] = "locked-form"

        def locked(nodes):
            controls = (("打开本地金库", "android.widget.Button"), ("主密码", "android.widget.EditText"),
                        ("Secret Key", "android.widget.EditText"))
            return nodes if all(any(self.matching(nodes, label, class_name)) for label, class_name in controls) else None

        nodes = self.wait(locked, deadline=deadline)
        self.no_visible_secrets(nodes)

    def capture_failure_diagnosis(self):
        if not self.started:
            return
        preserved = {key: self.diagnosis[key] for key in ("operation", "target", "step", "command", "command_exit", "exit_code",
                     "stderr_class", "bounds", "exception", "helper", "source_line", "reason")}
        deadline = time.monotonic() + min(10, self.args.timeout)
        try:
            try:
                self.observe_activity_state(min(deadline, time.monotonic() + 2))
            except Exception:
                pass
            try:
                self.snapshot(min(deadline, time.monotonic() + 6))
            except Exception:
                pass
            try:
                raw = self.shell("dumpsys", "input_method", timeout=self.remaining(deadline, 2)).stdout
                match = re.search(rb"(?:mInputShown|mIsInputViewShown)=(true|false)", raw)
                self.diagnosis["ime"] = "shown" if match and match[1] == b"true" else "hidden" if match else "unknown"
            except Exception:
                pass
        finally:
            self.diagnosis.update(preserved)

    def record_failure(self, error):
        name = type(error).__name__
        self.diagnosis["exception"] = name if name in EXCEPTIONS else "unexpected"
        own = []
        trace = error.__traceback__
        while trace:
            frame = trace.tb_frame
            if pathlib.Path(frame.f_code.co_filename).resolve() == pathlib.Path(__file__).resolve() and frame.f_code.co_name != "require":
                own.append((frame.f_code.co_name, trace.tb_lineno))
            trace = trace.tb_next
        if own:
            helper, line = own[-1]
            self.diagnosis.update({"helper": helper if helper in HELPERS else "unknown", "source_line": line})
        if self.diagnosis["reason"] == "unknown":
            self.diagnosis["reason"] = ("deadline" if self.diagnosis["helper"] == "remaining" else "xml" if name == "ParseError"
                else "python-contract" if name in {"TypeError", "AttributeError", "KeyError", "IndexError", "NameError"} else "assertion")

    def list_ready(self):
        self.visible("新建登录", class_name="android.widget.Button")

    def no_visible_secrets(self, nodes=None):
        nodes = nodes or self.snapshot()
        raw = json.dumps(nodes, ensure_ascii=False).encode()
        scan_public(raw, self.canaries)

    def metadata(self):
        nodes = self.snapshot()
        texts = [node.get("text", "") for node in nodes]
        ids = [text[4:] for text in texts if re.fullmatch(r"ID: [a-f0-9]{32}", text)]
        revisions = [text[4:] for text in texts if re.fullmatch(r"修订: [a-f0-9]{64}", text)]
        require(len(ids) == 1 and len(revisions) == 1)
        return ids[0], revisions[0]

    def select_item(self, title, expected_id=None):
        self.tap("选择登录：" + title, class_name="android.widget.Button")
        self.visible("显示密码", class_name="android.widget.Button")
        identity = self.metadata()
        if expected_id:
            require(identity[0] == expected_id)
        self.no_visible_secrets()
        return identity

    def reveal(self, label, identity, expected=None, pattern=None, action=None):
        self.tap(label, class_name="android.widget.Button")
        # The disclosure widget follows the detail actions. Bring that native
        # ScrollView to the bottom immediately, within the 15 second grant.
        self.swipe()
        self.swipe()

        def shown(nodes):
            for node in nodes:
                text = node.get("text", "")
                if node.get("package") == PACKAGE and node.get("class") == "android.widget.TextView":
                    if expected is not None and text == expected or pattern and re.fullmatch(pattern, text):
                        return text
            return None

        value = self.wait(shown, timeout=30)
        if expected is None:
            self.record(value)
        if action:
            self.disclosures.append((action, identity[0], identity[1]))
        return value

    def hide(self):
        self.tap("隐藏已显示字段", class_name="android.widget.Button")
        self.no_visible_secrets()

    def edit(self, title, identity, field, value):
        self.tap("编辑登录字段", class_name="android.widget.Button")
        self.locate(class_name="android.widget.Spinner")
        require(self.metadata() == identity)
        self.tap(class_name="android.widget.Spinner")
        self.tap(field)
        self.enter("新值（原生可见多行正文）", value)
        self.tap("保存字段", class_name="android.widget.Button")
        self.list_ready()
        changed = self.select_item(title, identity[0])
        require(changed[1] != identity[1])
        self.mutations.append(("item.edit." + field, identity[0], identity[1]))
        return changed

    def device_time(self):
        raw = self.shell("date", "+%s").stdout.strip()
        require(bool(re.fullmatch(rb"[0-9]{10,12}", raw)))
        return int(raw)

    def unlock(self, password, key, *, refused=False):
        self.visible("打开本地金库", class_name="android.widget.Button")
        self.enter("主密码", password)
        self.enter("Secret Key", key)
        self.tap("打开本地金库", class_name="android.widget.Button")
        if refused:
            self.wait(is_unlock_refusal)
            self.visible("打开本地金库", class_name="android.widget.Button")
            self.no_visible_secrets()
            require(not any(self.matching(self.snapshot(), "新建登录", "android.widget.Button")))
        else:
            self.list_ready()
            self.no_visible_secrets()

    def exercise(self):
        token = os.urandom(16).hex()
        master = self.record("Master" + token)
        wrong_master = self.record("Wrong" + token)
        username = self.record("User" + token)
        second_user = self.record("GeneratedUser" + os.urandom(16).hex())
        password = self.record("Password" + os.urandom(20).hex())
        edited = self.record("Edited" + os.urandom(20).hex())
        seed = self.record(base64.b32encode(os.urandom(20)).decode().rstrip("="))
        title, generated_title = "HostFirst" + token[:8], "HostGenerated" + token[:8]
        self.set_stage("create")
        self.diagnosis["step"] = "open-create"
        self.visible("生成新的 Secret Key", class_name="android.widget.Button")
        self.tap("生成新的 Secret Key", class_name="android.widget.Button")
        self.diagnosis["step"] = "read-account-key"
        key = self.wait(lambda nodes: next((n.get("text") for n in nodes if re.fullmatch(r"LL1-[A-Z2-7]{26}", n.get("text", ""))), None))
        self.record(key)
        wrong_key = self.record("LL1-" + base64.b32encode(os.urandom(16)).decode().rstrip("="))
        self.diagnosis["step"] = "enter-master"
        self.enter("新的主密码", master)
        self.diagnosis["step"] = "repeat-master"
        self.enter("再次输入主密码", master)
        self.diagnosis["step"] = "ack-backup"
        self.tap("我已离线保存 Secret Key", class_name="android.widget.CheckBox")
        self.diagnosis["step"] = "submit-create"
        self.tap("创建并解锁", class_name="android.widget.Button")
        self.diagnosis["step"] = "wait-created-list"
        self.list_ready()
        self.no_visible_secrets()
        self.done("fresh_creation_with_saved_account_key")

        self.set_stage("manual-login")
        self.tap("新建登录", class_name="android.widget.Button")
        self.enter("登录标题", title)
        self.enter("用户名", username)
        self.enter_manual_password(password)
        self.tap("保存登录", class_name="android.widget.Button")
        self.list_ready()
        identity = self.select_item(title)

        self.set_stage("disclosure")
        self.reveal("显示用户名", identity, username, action="item.desktop.show.username")
        self.hide()
        self.reveal("显示密码", identity, password, action="item.desktop.show.password")
        self.hide()
        self.done("manual_login_explicit_username_password_and_hide")

        self.set_stage("edit-password")
        identity = self.edit(title, identity, "password", edited)
        self.reveal("显示密码", identity, edited, action="item.desktop.show.password")
        self.hide()
        self.done("password_edit_preserves_id_and_changes_exact_revision")

        self.set_stage("otp")
        identity = self.edit(title, identity, "otp", seed)
        deadline = time.monotonic() + 35
        while self.device_time() % 30 > 8:
            require(time.monotonic() < deadline)
            time.sleep(0.3)
        before = self.device_time()
        code = self.reveal("显示验证码", identity, pattern=r"[0-9]{6}", action="item.desktop.show.otp-code")
        after = self.device_time()
        verify_otp(seed, code, before, after)
        self.hide()
        self.done("otp_matches_independent_hmac_and_original_utc_window")

        self.set_stage("generated-login")
        self.tap("返回列表", class_name="android.widget.Button")
        self.list_ready()
        self.tap("新建登录", class_name="android.widget.Button")
        self.enter("登录标题", generated_title)
        self.enter("用户名", second_user)
        require(self.locate("生成强密码", class_name="android.widget.CheckBox").get("checked") == "true")
        self.tap("保存登录", class_name="android.widget.Button")
        self.list_ready()
        generated_identity = self.select_item(generated_title)
        require(generated_identity[0] != identity[0])
        generated = self.reveal("显示密码", generated_identity, pattern=r"[A-Za-z0-9]{24}", action="item.desktop.show.password")
        require(generated not in (password, edited))
        self.hide()
        self.done("generated_login_has_distinct_24_character_password")

        self.set_stage("search")
        self.tap("返回列表", class_name="android.widget.Button")
        self.list_ready()
        self.enter("搜索标题", title)
        self.tap("搜索", class_name="android.widget.Button")
        self.visible("活动登录：1")
        require(self.select_item(title, identity[0]) == identity)
        self.done("title_search_selects_stable_identity")

        self.set_stage("background-lock")
        self.reveal("显示密码", identity, edited, action="item.desktop.show.password")
        self.background_and_relaunch()
        self.done("background_home_requires_both_full_unlock_factors")

        self.set_stage("wrong-factors")
        self.unlock(wrong_master, key, refused=True)
        self.unlock(master, wrong_key, refused=True)
        self.done("wrong_password_and_wrong_account_key_refused")
        self.set_stage("full-unlock")
        self.unlock(master, key)
        require(self.select_item(title, identity[0]) == identity)
        self.reveal("显示密码", identity, edited, action="item.desktop.show.password")
        self.hide()

        self.set_stage("restart")
        self.shell("am", "force-stop", PACKAGE)
        self.launch()
        self.visible("打开本地金库", class_name="android.widget.Button")
        self.no_visible_secrets()
        self.unlock(master, key)
        require(self.select_item(title, identity[0]) == identity)
        self.reveal("显示密码", identity, edited, action="item.desktop.show.password")
        self.hide()
        self.tap("立即锁定", class_name="android.widget.Button")
        self.visible("打开本地金库", class_name="android.widget.Button")
        self.no_visible_secrets()
        self.shell("am", "force-stop", PACKAGE)
        self.done("restart_reopens_real_vault_and_explicit_lock_clears_disclosure")

        self.private_values = {"master": master, "key": key, "seed": seed,
            "items": [{"id": identity[0], "revision": identity[1], "title": title, "username": username, "password": edited, "otp": seed},
                      {"id": generated_identity[0], "revision": generated_identity[1], "title": generated_title, "username": second_user, "password": generated, "otp": ""}]}
        self.write_private("expected-private.json", self.private_values)
        self.set_stage("copy-vault")
        result = self.command(["exec-out", "run-as", PACKAGE, "cat", "no_backup/personal.ll"], oracle="personal.ll", timeout=90)
        require(len(result.stdout) > 4096)
        scan_public(result.stdout, self.canaries)
        self.done("force_stopped_app_database_copied_privately_without_plaintext_canaries")
        if self.args.cli:
            self.audit_and_peer()

    def cli(self, action, answers, options=()):
        import pty
        import termios
        master, slave = pty.openpty()
        terminal = bytearray()
        stdout = b""
        process = None
        self.counter += 1
        prefix = f"cli-{self.counter:04d}-{action}"
        try:
            process = subprocess.Popen([str(pathlib.Path(self.args.cli).resolve()), "personal", action,
                                        "--file", str(self.root / "personal.ll"), *map(str, options)],
                                       stdin=slave, stdout=subprocess.PIPE, stderr=slave, start_new_session=True)
            offset = 0
            for prompt, value in answers:
                marker = (prompt + ": ").encode()
                deadline = time.monotonic() + 90
                while marker not in terminal[offset:]:
                    require(time.monotonic() < deadline and process.poll() is None)
                    if select.select([master], [], [], 0.2)[0]:
                        chunk = os.read(master, 4096)
                        require(bool(chunk))
                        terminal.extend(chunk)
                offset = terminal.index(marker, offset) + len(marker)
                require(not termios.tcgetattr(slave)[3] & termios.ECHO)
                os.write(master, value.encode() + b"\n")
            try:
                stdout, _ = process.communicate(timeout=120)
            except subprocess.TimeoutExpired as error:
                stdout = error.stdout or b""
                raise AcceptanceFailure() from None
            while select.select([master], [], [], 0)[0]:
                chunk = os.read(master, 4096)
                if not chunk:
                    break
                terminal.extend(chunk)
            require(process.returncode == 0)
            return json.loads(stdout)
        finally:
            if process and process.poll() is None:
                process.kill()
                process.wait()
            while select.select([master], [], [], 0)[0]:
                try:
                    chunk = os.read(master, 4096)
                    if not chunk:
                        break
                    terminal.extend(chunk)
                except OSError:
                    break
            for suffix, raw in (("stdout", stdout), ("terminal", bytes(terminal))):
                path = self.root / (prefix + "." + suffix)
                path.write_bytes(raw)
                path.chmod(0o600)
                self.logs.append(path)
            os.close(master)
            os.close(slave)

    def audit_and_peer(self):
        self.set_stage("audit")
        factors = [("主密码", self.private_values["master"]), ("Secret Key", self.private_values["key"])]
        rows = self.cli("list", factors)
        expected = self.private_values["items"]
        require({(r["id"], r["revision"], r["title"]) for r in rows} == {(r["id"], r["revision"], r["title"]) for r in expected})
        events = self.cli("audit", factors)
        verify_audit(events, self.disclosures, self.mutations, expected[1]["id"])
        self.done("copied_vault_cli_verifies_signed_disclosure_and_exact_revision_edit_audit")
        if not self.args.peer:
            return
        self.set_stage("kdbx-peer")
        export_password = self.record("Export" + os.urandom(24).hex())
        destination = self.root / "portable.kdbx"
        self.cli("export-kdbx", factors + [("新导出密码（至少 12 字符）", export_password),
            ("再次输入导出密码", export_password), ("输入 SAVE 确认加密导出", "SAVE")], ("--out", destination))
        exported_events = self.cli("audit", factors)
        verify_audit(exported_events, self.disclosures, self.mutations, expected[1]["id"], expected_exports=1, expected_audits=2)
        # Peer values travel only through a private pipe; stdout/stderr are
        # captured whole, then included in the same canary scan as logcat.
        peer_code = """import json,sys,urllib.parse
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
p=json.load(sys.stdin)
db=PyKeePass(sys.argv[1],password=p['password'])
assert db.version==(4,1) and len(db.entries)==len(p['items'])
entries={e.get_custom_property('Locklark.ID'):e for e in db.entries}
for item in p['items']:
 e=entries[item['id']]
 assert (e.title,e.username,e.password)==(item['title'],item['username'],item['password'])
 otp=e.otp or ''
 actual=urllib.parse.parse_qs(urllib.parse.urlparse(otp).query).get('secret',[otp])[0]
 assert actual==item['otp']
try:
 PyKeePass(sys.argv[1],password=p['password']+'wrong')
except CredentialsError: pass
else: raise AssertionError()
print('PASS: independent KDBX exact fields and wrong-password refusal')
"""
        try:
            result = subprocess.run([peer_executable(self.args.peer), "-c", peer_code, str(destination)],
                                    input=json.dumps({"password": export_password, "items": expected}).encode(),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        except subprocess.TimeoutExpired as error:
            result = subprocess.CompletedProcess([], -1, error.stdout or b"", error.stderr or b"")
        for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = self.root / ("peer." + suffix)
            path.write_bytes(raw)
            path.chmod(0o600)
            self.logs.append(path)
        require(result.returncode == 0)
        self.done("independent_pykeepass_reads_exact_mobile_fields_and_refuses_wrong_password")

    def close(self):
        if self.logger:
            self.logger.terminate()
            try:
                self.logger.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.logger.kill()
                self.logger.wait(timeout=5)
            if self.log_thread:
                self.log_thread.join(timeout=5)
                if self.log_thread.is_alive():
                    self.log_failed.set()
            self.logger = None
        if not self.controller.closed:
            if self.started:
                try:
                    self.shell("am", "force-stop", PACKAGE, required=False)
                except Exception:
                    pass
            if self.remote_owned:
                try:
                    self.shell("rm", "-rf", self.remote, required=False)
                except Exception:
                    pass
            self.controller.close()

    def scan(self):
        require(not self.log_failed.is_set())
        for path in self.logs:
            scan_public(path.read_bytes(), self.canaries)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--adb", required=True)
    result.add_argument("--serial", required=True)
    result.add_argument("--apk", required=True)
    result.add_argument("--reset-test-app", action="store_true", help="explicitly authorize clearing only org.locklark.android on a verified emulator")
    result.add_argument("--cli", help="optional independently fixed personal CLI for signed audit checks")
    result.add_argument("--peer", help="optional Python executable with pykeepass for encrypted KDBX verification; requires --cli")
    result.add_argument("--timeout", type=int, default=180, help="per UI state wait in seconds")
    result.add_argument("--artifacts", default="/tmp/locklark-validation")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    os.umask(0o077)
    acceptance = None
    success = False
    failure_diagnosis = None
    cleanup_ok, scan_ok = True, True
    stage = "prerequisites"
    try:
        validate_target(args.serial, args.reset_test_app, args.peer, args.cli)
        acceptance = AndroidAcceptance(args)
        acceptance.setup()
        acceptance.exercise()
        acceptance.set_stage("private-canary-scan")
        acceptance.close()
        acceptance.scan()
        acceptance.done("full_controller_and_logcat_outputs_contain_no_secret_canaries")
        acceptance.set_stage("complete")
        success = True
    except (Exception, KeyboardInterrupt) as error:
        # Never interpolate exceptions, subprocess argv/stdout/stderr, XML nodes,
        # expected/actual field values or any other user/app data into output.
        stage = acceptance.stage if acceptance else "prerequisites"
        if acceptance:
            try:
                acceptance.record_failure(error)
            except Exception:
                pass
    finally:
        if acceptance:
            if not success:
                try:
                    acceptance.capture_failure_diagnosis()
                except Exception:
                    pass
                # OS observation adds useful state, then freeze the original
                # failure before close() issues force-stop/rm commands.
                failure_diagnosis = safe_host_diagnosis(getattr(acceptance, "diagnosis", {}))
            try:
                acceptance.close()
            except Exception as error:
                cleanup_ok = False
                if success:
                    success = False
                    stage = "private-canary-scan"
                    try:
                        acceptance.record_failure(error)
                    except Exception:
                        pass
                    failure_diagnosis = safe_host_diagnosis(getattr(acceptance, "diagnosis", {}))
            try:
                acceptance.scan()
            except Exception:
                scan_ok = False
                if success:
                    success = False
                    stage = "private-canary-scan"
                    failure_diagnosis = safe_host_diagnosis(getattr(acceptance, "diagnosis", {}))
            acceptance.write_private("result.json", {"success": success,
                "stage": "complete" if success else stage, "checks": acceptance.checks,
                "audit_checked": bool(success and args.cli), "kdbx_peer_checked": bool(success and args.peer),
                "cleanup_ok": cleanup_ok, "scan_ok": scan_ok,
                "diagnosis": failure_diagnosis if failure_diagnosis is not None else safe_host_diagnosis(getattr(acceptance, "diagnosis", {}))})
        if not success:
            print("FAIL: Android host UI at " + stage)
            if acceptance:
                diagnosis = failure_diagnosis if failure_diagnosis is not None else safe_host_diagnosis(getattr(acceptance, "diagnosis", {}))
                print("Fixed Android host diagnosis: " + json.dumps(diagnosis, sort_keys=True))
            if not scan_ok:
                print("FAIL: Android artifact privacy scan")
        if acceptance:
            print("Private Android host UI evidence: " + str(acceptance.root))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
