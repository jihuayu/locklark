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
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

from desktop_native_probe import PROBE_REASONS, safe_diagnostic
from browser_native_x11 import CONTROL_LABELS, FAILURE_REASONS, safe_click_record
from desktop_clipboard_owner import current_owner


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


class AcceptanceFailure(Exception):
    pass


def require(condition):
    if not condition:
        raise AcceptanceFailure()


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
    def __init__(self):
        self.stage = "setup"
        self.state = pathlib.Path(tempfile.mkdtemp(prefix="locklark-desktop-acceptance-"))
        self.diagnostics = self.state / "diagnostics"
        self.diagnostics.mkdir(mode=0o700)
        self.host = pathlib.Path(os.environ["LOCKLARK_DESKTOP_HOST"]).resolve(strict=True)
        require(bool(os.environ.get("DISPLAY")))
        self.env = {**os.environ, "GOTOOLCHAIN": "go1.27.3"}
        self.go = os.environ.get("LOCKLARK_GO", "go")
        fixture = os.environ.get("LOCKLARK_DESKTOP_FIXTURE")
        self.fixture_prebuilt = bool(fixture)
        self.fixture_binary = pathlib.Path(fixture).resolve() if fixture else self.state / "fixture-observer"
        self.fixture_path = self.state / "vault" / "fixture.json"
        self.values, self.codes = set(), set()
        self.started = time.time()
        self.app, self.probe = None, None
        self.reason = "acceptance"
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
        self.log = (self.state / "native.log").open("xb")
        os.chmod(self.state / "native.log", 0o600)

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
        self.phase("unlock")
        self.input([{"click_label":"金库文件"}, {"key":"Control_L+a"}, {"text":self.fixture["Path"]},
                    {"click_label":"主密码"}, {"text":self.fixture["Password"]},
                    {"click_label":"Secret Key"}, {"text":self.fixture["Secret"]}, {"click_label":"解锁"},
                    {"wait_label":"新建登录"}])

    def build_fixture(self):
        if self.fixture_prebuilt:
            require(self.fixture_binary.is_file() and os.access(self.fixture_binary, os.X_OK))
            return
        self.command([self.go, "build", "-o", str(self.fixture_binary), "./scripts/desktop_acceptance_fixture"])

    def setup(self):
        self.build_fixture()
        self.command([str(self.fixture_binary), "-out", str(self.state / "vault")])
        self.fixture = json.loads(self.fixture_path.read_bytes())
        self.values.update(self.fixture[key] for key in ("Password", "Secret", "Username", "Value", "OTPSeed", "OTPConfig", "ProviderValue", "ProviderCanary"))
        self.app = subprocess.Popen([str(self.host)], env=self.env, stdout=self.log, stderr=self.log)
        self.probe = subprocess.Popen([sys.executable, str(ROOT / "scripts/desktop_native_probe.py")],
                                      env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=self.log, text=True, bufsize=1)
        require(bool(select.select([self.probe.stdout], [], [], 15)[0]))
        require(json.loads(self.probe.stdout.readline()).get("ready") is True)
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
            try:
                empty = self.clipboard().get("empty") is True
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
        if hasattr(self, "fixture"):
            for window in range(int(self.started) // 20, int(time.time()) // 20 + 1):
                self.otp(window * 20)
        patterns = set()
        for value in self.values:
            patterns.update((value.encode(), json.dumps(value, ensure_ascii=True)[1:-1].encode(), urllib.parse.quote(value, safe="").encode()))
        count = 0
        for path in self.state.rglob("*"):
            if not path.is_file() or path == self.fixture_path or path.suffix not in (".log", ".txt", ".json", ".jsonl"):
                continue
            data = path.read_bytes()
            require(not any(value and value in data for value in patterns))
            # Codes are short: match a complete independent token, so an
            # unrelated hexadecimal ID substring cannot produce a false hit.
            for code in self.codes:
                require(re.search(rb"(?<![A-Za-z0-9])" + code.encode() + rb"(?![A-Za-z0-9])", data) is None)
            count += 1
        return count

    def close(self):
        for child in (self.app, self.probe,*self.foreign_owners):
            if child is None:
                continue
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        self.log.close()

    def run(self):
        success = False
        try:
            self.setup()
            if os.environ.get("LOCKLARK_TEST_FAILURE_STAGE") == "probe-input":
                # Add a genuinely newly generated password to the fault's
                # private payload and final scan, alongside unlock/OTP factors.
                self.create(True)
                self.phase("private-probe-failure")
                result = self.probe_request({"op":"unsupported", "private":list(self.values)})
                require(result.get("ok") is True)
            elif os.environ.get("LOCKLARK_TEST_FAILURE_STAGE"):
                raise AcceptanceFailure()
            scenario = os.environ.get("LOCKLARK_TEST_SCENARIO")
            if scenario:
                require(scenario in ("foreign-owner","provider"))
                if scenario == "provider":
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
            error_class = {AcceptanceFailure:"acceptance", OSError:"os", BrokenPipeError:"pipe", json.JSONDecodeError:"json"}.get(type(error), "unexpected")
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
            if hasattr(self, "fixture"):
                try:
                    self.observe()
                except Exception:
                    pass
            self.close()
        if self.foreign_observations:
            path = self.diagnostics/"clipboard-ownership.json"
            with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w") as output:
                json.dump(self.foreign_observations,output,indent=2)
        success_label = {
            "foreign-owner":"PASS: real unresponsive foreign clipboard owner, single Lock, zero cleanup requests and preserved marker",
            "provider":"PASS: real large Unicode native clipboard provider, own cleanup and same-value foreign owner preservation",
        }.get(os.environ.get("LOCKLARK_TEST_SCENARIO"),"PASS: real desktop atomic create/generate, exact regeneration, native clipboard ownership and independent TOTP lifecycle")
        final_lines = ["Desktop native private state: " + str(self.state),
                       "Desktop native authorized display read attempts: max=" + str(self.probe_read_attempts_max),
                       "Desktop native private artifact and controller scan: passed",
                       success_label
                       if success else "Desktop native acceptance failed at " + self.stage + " [" + self.reason + "] action=" + self.native_action,
                       getattr(self, "otp_diagnostic", None) or "Desktop OTP failure diagnostic: none"]
        # Include every controller phase and the final summary in the same
        # scan as native/probe logs and diagnostics. Raw values remain only in
        # memory; the file contains the already public, fixed transcript.
        controller = self.state / "controller.log"
        try:
            with os.fdopen(os.open(controller, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
                output.write("\n".join(self.output_lines + final_lines) + "\n")
            self.scan()
        except Exception:
            self.emit_lines(final_lines)
            print("Desktop native privacy scan failed", flush=True)
            return 1
        self.emit_lines(final_lines)
        return 0 if success else 1

    @staticmethod
    def emit_lines(lines):
        # The OTP line reaches stdout here regardless of transcript or scan.
        for message in lines:
            print(message, flush=True)


if __name__ == "__main__":
    try:
        sys.exit(Acceptance().run())
    except Exception:
        print("Desktop native acceptance unavailable at setup", file=sys.stderr)
        sys.exit(1)
