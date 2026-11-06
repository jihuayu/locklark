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


class AcceptanceFailure(Exception):
    """The caller prints a fixed stage, never the exception or child output."""


def require(condition):
    if not condition:
        raise AcceptanceFailure()


def validate_target(serial, reset, peer=None, cli=None):
    require(bool(re.fullmatch(r"emulator-[0-9]+", serial)) and reset)
    require(not peer or cli)


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

    def set_stage(self, stage):
        require(stage in STAGES)
        self.stage = stage

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
        try:
            result = subprocess.run(self.adb + list(map(str, arguments)),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            stdout, stderr = result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b"", error.stderr or b""
        if oracle:
            path = self.root / oracle
            path.write_bytes(stdout)
            path.chmod(0o600)
        else:
            self.controller.write(f"command {self.counter} stdout\n".encode() + stdout + b"\n")
        self.controller.write(f"command {self.counter} stderr\n".encode() + stderr + b"\n")
        self.controller.flush()
        require(result is not None)
        if required:
            require(result.returncode == 0)
        return result

    def shell(self, *arguments, **kwargs):
        return self.command(["shell", *arguments], **kwargs)

    def snapshot(self):
        self.xml_counter += 1
        remote = self.remote + "/current.xml"
        self.shell("uiautomator", "dump", "--compressed", remote, timeout=45)
        result = self.command(["exec-out", "cat", remote], oracle=f"ui-{self.xml_counter:04d}.xml")
        self.shell("rm", "-f", remote)
        return parse_nodes(result.stdout)

    @staticmethod
    def matching(nodes, label=None, class_name=None, prefix=False):
        for node in nodes:
            if node.get("package") != PACKAGE or node.get("enabled") != "true":
                continue
            if class_name and node.get("class") != class_name:
                continue
            texts = (node.get("text", ""), node.get("content-desc", ""))
            if label is not None and not any(text.startswith(label) if prefix else text == label for text in texts):
                continue
            try:
                center(node)
            except AcceptanceFailure:
                continue
            yield node

    def wait(self, predicate, timeout=None):
        end = time.monotonic() + (timeout or self.args.timeout)
        while time.monotonic() < end:
            nodes = self.snapshot()
            result = predicate(nodes)
            if result:
                return result
            time.sleep(0.2)
        raise AcceptanceFailure()

    def visible(self, label, *, class_name=None, prefix=False):
        return self.wait(lambda nodes: next(self.matching(nodes, label, class_name, prefix), None))

    def dimensions(self):
        raw = self.shell("wm", "size").stdout
        sizes = re.findall(rb"(?:Physical|Override) size: ([0-9]+)x([0-9]+)", raw)
        require(bool(sizes))
        return tuple(map(int, sizes[-1]))

    def swipe(self, down=False):
        width, height = self.size
        start, end = (0.28, 0.78) if down else (0.78, 0.28)
        self.shell("input", "swipe", width // 2, int(height * start), width // 2, int(height * end), 350)

    def locate(self, label=None, *, class_name=None, prefix=False, scroll=True):
        nodes = self.snapshot()
        candidate = next(self.matching(nodes, label, class_name, prefix), None)
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
                    candidate = next(self.matching(nodes, label, class_name, prefix), None)
                    if candidate:
                        return candidate
                    fingerprint = [(n.get("text"), n.get("content-desc"), n.get("bounds")) for n in nodes]
                    unchanged = unchanged + 1 if fingerprint == previous else 0
                    previous = fingerprint
                    if unchanged >= 2:
                        break
        raise AcceptanceFailure()

    def tap(self, label=None, *, class_name=None, prefix=False):
        node = self.locate(label, class_name=class_name, prefix=prefix)
        x, y = center(node)
        self.shell("input", "tap", x, y)

    def dismiss_keyboard(self):
        raw = self.shell("dumpsys", "input_method").stdout
        if re.search(rb"(?:mInputShown|mIsInputViewShown)=true", raw):
            self.shell("input", "keyevent", "KEYCODE_BACK")

    def enter(self, label, value):
        # This runner creates ASCII-only values deliberately. Shell metacharacters,
        # percent escapes and whitespace never enter `adb shell input text`.
        require(bool(re.fullmatch(r"[A-Za-z0-9_-]+", value)))
        self.tap(label, class_name="android.widget.EditText")
        self.shell("input", "text", value)
        self.dismiss_keyboard()

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

    def launch(self):
        self.shell("am", "start", "-W", "-n", COMPONENT, timeout=90)

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
        self.visible("生成新的 Secret Key", class_name="android.widget.Button")
        self.tap("生成新的 Secret Key", class_name="android.widget.Button")
        key = self.wait(lambda nodes: next((n.get("text") for n in nodes if re.fullmatch(r"LL1-[A-Z2-7]{26}", n.get("text", ""))), None))
        self.record(key)
        wrong_key = self.record("LL1-" + base64.b32encode(os.urandom(16)).decode().rstrip("="))
        self.enter("新的主密码", master)
        self.enter("再次输入主密码", master)
        self.tap("我已离线保存 Secret Key", class_name="android.widget.CheckBox")
        self.tap("创建并解锁", class_name="android.widget.Button")
        self.list_ready()
        self.no_visible_secrets()
        self.done("fresh_creation_with_saved_account_key")

        self.set_stage("manual-login")
        self.tap("新建登录", class_name="android.widget.Button")
        self.enter("登录标题", title)
        self.enter("用户名", username)
        self.enter("登录密码", password)
        generate = self.locate("生成强密码", class_name="android.widget.CheckBox")
        require(generate.get("checked") == "true")
        self.tap("生成强密码", class_name="android.widget.CheckBox")
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
        self.shell("input", "keyevent", "KEYCODE_HOME")
        time.sleep(0.5)
        self.launch()
        self.visible("打开本地金库", class_name="android.widget.Button")
        self.locate("主密码", class_name="android.widget.EditText")
        self.locate("Secret Key", class_name="android.widget.EditText")
        self.no_visible_secrets()
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
            result = subprocess.run([str(pathlib.Path(self.args.peer).resolve()), "-c", peer_code, str(destination)],
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
    except (Exception, KeyboardInterrupt):
        # Never interpolate exceptions, subprocess argv/stdout/stderr, XML nodes,
        # expected/actual field values or any other user/app data into output.
        stage = acceptance.stage if acceptance else "prerequisites"
    finally:
        if acceptance:
            try:
                acceptance.close()
            except Exception:
                success = False
                stage = "private-canary-scan"
            try:
                acceptance.scan()
            except Exception:
                success = False
                stage = "private-canary-scan"
            acceptance.write_private("result.json", {"success": success,
                "stage": "complete" if success else stage, "checks": acceptance.checks,
                "audit_checked": bool(success and args.cli), "kdbx_peer_checked": bool(success and args.peer)})
        if not success:
            print("FAIL: Android host UI at " + stage)
        if acceptance:
            print("Private Android host UI evidence: " + str(acceptance.root))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
