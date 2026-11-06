#!/usr/bin/env python3
"""External MyGo + real OpenSSH + two owned loopback sshd acceptance.

Requires an owned DISPLAY/private DBus session. All approval is normal native
XTest input. This tool has no product signing, unlock or approval API access.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import select
import shlex
import socket
import struct
import subprocess
import sys
import threading
import time

from run_cli_acceptance import Acceptance as CLIController, AcceptanceFailure, require, scan

ROOT = pathlib.Path(__file__).resolve().parents[1]
TITLE = "Locklark · 本地金库"
STAGES = {"prerequisites", "create", "unlock", "generate", "import", "servers", "identities", "approve", "deny",
          "malformed", "concurrency", "disconnect", "expired", "slow-frame", "openssh", "forwarding", "lock",
          "export", "audit", "privacy", "cleanup", "complete"}
LABELS = {"vault": "金库文件", "master": "主密码", "key": "Secret Key", "unlock": "解锁", "locked": "立即锁定",
          "ssh": "SSH 密钥", "title": "SSH 密钥标题", "generate": "生成 Ed25519 密钥", "import-file": "选择未加密 OpenSSH 私钥…",
          "import-confirm": "确认导入未加密 Ed25519 私钥", "copy-key": "复制 SSH 公钥", "start": "开启本地 SSH agent",
          "copy-endpoint": "复制 SSH_AUTH_SOCK 端点", "stop": "停止本地 SSH agent", "approve": "仅批准本次 SSH 签名",
          "deny": "拒绝本次 SSH 签名", "generated": "选择 SSH 密钥：Owned generated SSH", "imported": "选择 SSH 密钥：Owned imported SSH"}


def ssh_string(value):
    return struct.pack(">I", len(value)) + value


def take_string(value):
    require(len(value) >= 4)
    size = struct.unpack(">I", value[:4])[0]
    require(size <= len(value) - 4)
    return value[4:4 + size], value[4 + size:]


def exact(connection, size):
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        require(bool(part))
        result.extend(part)
    return bytes(result)


def receive(connection):
    size = struct.unpack(">I", exact(connection, 4))[0]
    require(1 <= size <= 65536)
    return exact(connection, size)


def frame(value):
    return struct.pack(">I", len(value)) + value


def identities(value):
    require(value[:1] == b"\x0c" and len(value) >= 5)
    count = struct.unpack(">I", value[1:5])[0]
    require(count <= 64)
    result, rest = [], value[5:]
    for _ in range(count):
        public, rest = take_string(rest)
        comment, rest = take_string(rest)
        kind, tail = take_string(public)
        raw, tail = take_string(tail)
        require(kind == b"ssh-ed25519" and len(raw) == 32 and not tail)
        result.append((public, comment))
    require(not rest)
    return result


def imported_seed(encoded):
    """Parse the ssh-keygen fixture independently, without a product parser."""
    lines = encoded.splitlines()
    require(lines[0] == b"-----BEGIN OPENSSH PRIVATE KEY-----" and lines[-1] == b"-----END OPENSSH PRIVATE KEY-----")
    data = base64.b64decode(b"".join(lines[1:-1]), validate=True)
    require(data.startswith(b"openssh-key-v1\0"))
    cipher, rest = take_string(data[15:])
    kdf, rest = take_string(rest)
    options, rest = take_string(rest)
    require(cipher == b"none" and kdf == b"none" and not options and rest[:4] == struct.pack(">I", 1))
    public, rest = take_string(rest[4:])
    private, rest = take_string(rest)
    require(not rest and private[:4] == private[4:8])
    kind, rest = take_string(private[8:])
    raw_public, rest = take_string(rest)
    private64, rest = take_string(rest)
    _, padding = take_string(rest)
    require(kind == b"ssh-ed25519" and len(private64) == 64 and raw_public == private64[32:]
            and public == ssh_string(kind) + ssh_string(raw_public) and padding == bytes(range(1, len(padding) + 1)))
    return private64[:32], public


def verify_audit(events, approvals):
    creates = [event for event in events if event["action"] in ("item.ssh.generate", "item.ssh.import")]
    require(len(creates) == 2 and {event["action"] for event in creates} == {"item.ssh.generate", "item.ssh.import"}
            and all(event["result"] == "succeeded" for event in creates))
    created_ids = {event["item_id"] for event in creates}
    require(len(created_ids) == 2 and all(view["密钥 ID"] in created_ids for view in approvals))
    relevant = [event for event in events if event["action"].startswith("item.ssh.")]
    signatures = [event for event in relevant if event["action"] == "item.ssh.sign"]
    require(len(relevant) == len(creates) + len(signatures) and len(signatures) == len(approvals))
    require(sorted((event["item_id"], event["base_revision"]) for event in signatures)
            == sorted((view["密钥 ID"], view["精确修订"]) for view in approvals)
            and all(event["result"] == "intent" for event in signatures))
    require(len({view["请求 ID"] for view in approvals}) == len(approvals))


class AgentRelay:
    """Owned transparent transport observer; cannot create approval decisions."""
    def __init__(self, path, target, root):
        self.path, self.target, self.root = path, target, root
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(path))
        os.chmod(path, 0o600)
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.stop = threading.Event()
        self.connections, self.workers, self.captures = [], [], []
        self.lock = threading.Lock()
        self.worker = threading.Thread(target=self.accept, daemon=True)
        self.worker.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            remote = socket.socket(socket.AF_UNIX)
            try:
                remote.connect(self.target)
            except OSError:
                client.close()
                remote.close()
                continue
            with self.lock:
                index = len(self.captures)
                capture = {"request": bytearray(), "response": bytearray()}
                self.captures.append(capture)
                self.connections.extend((client, remote))
            for source, destination, direction in ((client, remote, "request"), (remote, client, "response")):
                worker = threading.Thread(target=self.copy, args=(source, destination, capture, direction), daemon=True)
                self.workers.append(worker)
                worker.start()

    def copy(self, source, destination, capture, direction):
        try:
            while not self.stop.is_set():
                data = source.recv(65536)
                if not data:
                    break
                require(len(capture[direction]) + len(data) <= 4 << 20)
                capture[direction].extend(data)
                destination.sendall(data)
        except Exception:
            pass
        finally:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def close(self):
        self.stop.set()
        self.listener.close()
        for connection in self.connections:
            connection.close()
        self.worker.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=2)
        for index, capture in enumerate(self.captures):
            for direction, raw in capture.items():
                (self.root / ("agent-wire-" + str(index) + "." + direction)).write_bytes(raw)
        self.path.unlink(missing_ok=True)


class Acceptance:
    def __init__(self, args):
        self.args, self.stage, self.operation = args, "prerequisites", "none"
        self.cli = CLIController(args)
        self.root = self.cli.root
        self.host = str(pathlib.Path(args.host).resolve(strict=True))
        self.env = {**os.environ, "HOME": str(self.cli.global_home), "NO_AT_BRIDGE": "0", "GTK_A11Y": "1"}
        self.runtime = self.root / "desktop-runtime"
        self.runtime.mkdir(mode=0o700)
        self.env["TMPDIR"] = str(self.runtime)
        self.app, self.relay, self.servers, self.children, self.wm = None, None, [], [], None
        self.checks, self.approvals, self.key_rows = [], [], {}
        self.log = (self.root / "desktop.stdout-stderr").open("wb")
        self.cli.logs.append((self.root / "desktop.stdout-stderr", set()))
        self.worker_logs, self.secret_bytes = [], []
        self.endpoint = None
        self.reason, self.control_diagnostic = "none", {}
        self.error_class, self.error_line = "none", 0

    def mark(self, name):
        self.checks.append(name)
        print("PASS: SSH " + name, flush=True)

    def command(self, arguments, timeout=30, payload=None, expected=0, env=None):
        result = subprocess.run(arguments, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, env=env or self.env, cwd=self.root)
        self.cli.counter += 1
        for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = self.root / ("external-" + str(self.cli.counter) + "." + suffix)
            path.write_bytes(raw)
            self.cli.logs.append((path, set()))
        if result.returncode != expected:
            match = re.fullmatch(rb"SSH native driver failed \[([a-z-]+)\]\n", result.stderr)
            self.reason = "native-" + match[1].decode() if match and match[1] in (b"control-ready-timeout", b"window-timeout", b"control-ambiguous", b"a11y-query") else "external-command"
        require(result.returncode == expected)
        return result.stdout

    def native(self, actions=(), observe=None, title=TITLE, inspect=False, expected_path=None):
        request = {"title": title, "executable": self.host, "pid": self.app.pid, "actions": actions}
        request["inspect"] = inspect
        if observe:
            request["observe"] = observe
        if expected_path is not None:
            request["expected_path"] = str(expected_path)
        return json.loads(self.command([sys.executable, str(ROOT / "scripts/ssh_native_x11.py")],
                                      payload=json.dumps(request).encode(), timeout=30))

    def click(self, name):
        self.operation = name
        self.native([{"click_label": LABELS[name]}])

    def wait(self, name):
        self.operation = name
        self.native([{"wait_label": LABELS[name]}])

    def fill(self, name, value):
        self.operation = name
        self.native([{"click_label": LABELS[name]}, {"key": "Control_L+a"}, {"text": value}])

    def clipboard(self):
        return self.native(observe="clipboard")["value"]

    def connect(self, relay=True):
        connection = socket.socket(socket.AF_UNIX)
        connection.settimeout(5)
        connection.connect(str(self.relay.path) if relay else self.endpoint)
        return connection

    def send(self, value):
        connection = self.connect()
        connection.sendall(frame(value))
        return connection

    def request(self, public, payload, flags=0):
        return self.send(b"\x0d" + ssh_string(public) + ssh_string(payload) + struct.pack(">I", flags))

    def observed_approval(self, public=None, payload=None, expected_pid=None):
        self.wait("approve")
        values = self.native(observe="approval")["values"]
        require(values.count("目的地未验证") == 1 and values.count("批准本次 SSH 签名？") == 1)
        view = {}
        for value in values:
            if "：" in value:
                key, value = value.split("：", 1)
                require(key not in view)
                view[key] = value
        require(set(view) == {"本机来源", "密钥", "密钥 ID", "精确修订", "公钥指纹", "算法", "签名数据", "载荷 SHA256", "请求 ID", "连接 ID", "批准期限"})
        require(view["算法"] == "ssh-ed25519 · flags=0" and re.fullmatch(r"[a-f0-9]{32}", view["密钥 ID"])
                and re.fullmatch(r"[a-f0-9]{64}", view["精确修订"]))
        if expected_pid is not None:
            require(re.search(r"\bPID " + str(expected_pid) + r"\b", view["本机来源"]) is not None)
        require(view["本机来源"].startswith("UID " + str(os.getuid()) + " · "))
        if public is not None:
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(public).digest()).decode().rstrip("=")
            require(view["公钥指纹"] == fingerprint)
        if payload is not None:
            require(view["载荷 SHA256"] == hashlib.sha256(payload).hexdigest()
                    and view["签名数据"] == str(len(payload)) + " 字节")
        return view

    def approve(self, public=None, payload=None, expected_pid=None):
        view = self.observed_approval(public, payload, expected_pid)
        self.click("approve")
        self.approvals.append(view)
        return view

    def verify_signature(self, response, public, payload, name):
        require(response[:1] == b"\x0e")
        signature, rest = take_string(response[1:])
        algorithm, signature = take_string(signature)
        raw_signature, tail = take_string(signature)
        require(algorithm == b"ssh-ed25519" and len(raw_signature) == 64 and not rest and not tail)
        kind, raw_public = take_string(public)
        raw_public, tail = take_string(raw_public)
        require(kind == b"ssh-ed25519" and not tail)
        paths = [self.root / (name + suffix) for suffix in (".public.der", ".payload-private", ".signature")]
        paths[0].write_bytes(bytes.fromhex("302a300506032b6570032100") + raw_public)
        paths[1].write_bytes(payload)
        paths[2].write_bytes(raw_signature)
        out = self.command(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(paths[0]), "-keyform", "DER", "-rawin",
                            "-in", str(paths[1]), "-sigfile", str(paths[2])])
        require(b"Signature Verified Successfully" in out)

    def create(self):
        require(bool(os.environ.get("DISPLAY")) and bool(os.environ.get("DBUS_SESSION_BUS_ADDRESS")))
        self.cli.build_fixture()
        if self.args.window_manager:
            self.wm = subprocess.Popen([self.args.window_manager, "--replace", "--compositor=off"], env=self.env,
                                       stdout=self.log, stderr=self.log)
        self.stage = "create"
        out, self.cli.key, _ = self.cli.invoke("init", [("主密码", self.cli.master), ("再次输入主密码", self.cli.master),
            ("重新输入刚保存的 Secret Key", None)], issue=True)
        require(json.loads(out)["status"] == "created")
        self.app = subprocess.Popen([self.host], env=self.env, stdout=self.log, stderr=self.log)
        self.stage = "unlock"
        self.native([{"key": "Alt_L+F10"}])
        self.fill("vault", str(self.cli.vault))
        self.fill("master", self.cli.master)
        self.fill("key", self.cli.key)
        self.click("unlock")
        self.wait("ssh")
        self.click("ssh")

    def manage(self):
        self.stage = "generate"
        self.fill("title", "Owned generated SSH")
        self.click("generate")
        self.wait("generated")
        self.click("copy-key")
        generated = self.clipboard()
        self.generated_public = base64.b64decode(generated.split()[1], validate=True)
        (self.root / "generated.pub").write_text(generated)
        self.stage = "import"
        keyfile = self.root / "known-import-key"
        self.command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "owned-key-fixture", "-f", str(keyfile)])
        self.import_seed, self.import_public = imported_seed(keyfile.read_bytes())
        self.secret_bytes.append(self.import_seed)
        self.cli.values.extend((base64.b64encode(self.import_seed).decode(), self.import_seed.hex(),
                                b"".join(keyfile.read_bytes().splitlines()[1:-1]).decode()))
        self.fill("title", "Owned imported SSH")
        self.click("import-file")
        # GTK's location entry may contain the current folder after Ctrl+L.
        # Replace it explicitly, then activate the normal Open button once.
        self.native([{"key": "Control_L+l"}, {"key": "Control_L+a"}, {"text": str(keyfile)}], title="选择未加密 OpenSSH Ed25519 私钥")
        picker = self.native(observe="picker", title="选择未加密 OpenSSH Ed25519 私钥", expected_path=keyfile)
        self.cli.write(self.root / "picker-observation.json", picker)
        require(picker["path_match"] == 1)
        self.native([{"key": "Return"}], title="选择未加密 OpenSSH Ed25519 私钥")
        deadline = time.monotonic() + 10
        while True:
            picker = self.native(observe="picker", title="选择未加密 OpenSSH Ed25519 私钥", expected_path=keyfile)
            self.cli.write(self.root / "picker-observation-after-location.json", picker)
            if not picker["present"] or picker["selected_name_match"]:
                break
            require(time.monotonic() < deadline)
            time.sleep(0.05)
        if picker["present"]:
            self.native([{"click_label": "Open"}], title="选择未加密 OpenSSH Ed25519 私钥")
        request = {"title": "选择未加密 OpenSSH Ed25519 私钥", "executable": self.host, "actions": [], "wait_absent": True}
        require(json.loads(self.command([sys.executable, str(ROOT / "scripts/ssh_native_x11.py")],
                                       payload=json.dumps(request).encode()))["absent"] is True)
        self.click("import-confirm")
        self.wait("imported")
        self.click("copy-key")
        imported = self.clipboard()
        require(base64.b64decode(imported.split()[1], validate=True) == self.import_public)
        (self.root / "imported.pub").write_text(imported)
        self.click("start")
        self.wait("copy-endpoint")
        self.click("copy-endpoint")
        self.endpoint = self.clipboard()
        require(stat_socket(self.endpoint))
        self.relay = AgentRelay(self.root / "observed-agent.sock", self.endpoint, self.root)
        self.mark("native_generate_import_public_copy_and_explicit_start")

    def core_protocol(self):
        self.stage = "identities"
        with self.send(b"\x0b") as connection:
            rows = identities(receive(connection))
        require({value[0] for value in rows} == {self.import_public, self.generated_public})
        self.command(["ssh-add", "-L"], env={**self.env, "SSH_AUTH_SOCK": self.endpoint})
        self.mark("real_ssh_add_and_bounded_public_only_identities")
        self.stage = "approve"
        for index, public in enumerate((self.generated_public, self.import_public)):
            payload = b"Independent exact SSH payload\0" + os.urandom(128)
            with self.request(public, payload) as connection:
                require(not select.select([connection], [], [], 0.25)[0])
                self.approve(public, payload, os.getpid())
                self.verify_signature(receive(connection), public, payload, "approved-" + str(index))
        self.mark("one_native_approval_per_exact_payload_and_independent_ed25519_verification")
        self.stage = "deny"
        with self.request(self.import_public, os.urandom(80)) as connection:
            self.observed_approval()
            self.click("deny")
            require(receive(connection) == b"\x05")
        self.mark("native_denial_returns_no_signature")
        self.stage = "malformed"
        for value in (b"\x11", b"\x12", b"\x13", b"\x14", b"\x16", b"\x1b" + ssh_string(b"session-bind@openssh.com"),
                      b"\x0d", b"\x0d" + ssh_string(self.import_public) + ssh_string(b"value") + struct.pack(">I", 1)):
            with self.send(value) as connection:
                require(receive(connection) == b"\x05")
        for size in (0, 65537, 0xffffffff):
            with self.connect() as connection:
                connection.sendall(struct.pack(">I", size))
                require(connection.recv(1) == b"")
        self.mark("malformed_oversized_unsupported_operations_fail_closed")
        self.stage = "concurrency"
        first_payload, second_payload = os.urandom(64), os.urandom(64)
        with self.request(self.import_public, first_payload) as first:
            self.observed_approval(self.import_public, first_payload)
            with self.request(self.generated_public, second_payload) as second:
                require(receive(second) == b"\x05")
            self.approve(self.import_public, first_payload)
            self.verify_signature(receive(first), self.import_public, first_payload, "concurrency")
        self.mark("concurrent_request_refused_without_reusing_the_pending_approval")
        self.stage = "disconnect"
        connection = self.request(self.import_public, os.urandom(60))
        self.observed_approval()
        connection.close()
        self.wait("copy-endpoint")
        # A new request cannot inherit the abandoned request's decision.
        payload = os.urandom(61)
        with self.request(self.import_public, payload) as connection:
            self.approve(self.import_public, payload)
            self.verify_signature(receive(connection), self.import_public, payload, "after-disconnect")
        self.mark("disconnect_cancels_old_prompt_and_new_connection_requires_new_approval")

    def servers_start(self):
        self.stage = "servers"
        import getpass
        self.username = getpass.getuser()
        self.known_hosts = self.root / "known_hosts"
        self.known_hosts.write_text("")
        self.ports = []
        for index in range(2):
            hostkey = self.root / ("sshd-host-" + str(index))
            self.command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(hostkey)])
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            self.ports.append(port)
            authorized = self.root / ("authorized-" + str(index))
            authorized.write_text((self.root / "imported.pub").read_text())
            config = self.root / ("sshd-" + str(index) + ".conf")
            config.write_text("\n".join(("Port " + str(port), "ListenAddress 127.0.0.1", "HostKey " + str(hostkey),
                "PidFile " + str(self.root / ("sshd-" + str(index) + ".pid")), "AuthorizedKeysFile " + str(authorized),
                "AllowUsers " + self.username, "UsePAM no", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
                "AuthenticationMethods publickey", "PermitRootLogin no", "StrictModes no", "AllowAgentForwarding yes",
                "AllowTcpForwarding no", "X11Forwarding no", "PermitTTY no", "PrintMotd no", "PrintLastLog no", "LogLevel VERBOSE")) + "\n")
            logpath = self.root / ("sshd-" + str(index) + ".log")
            log = logpath.open("wb")
            self.worker_logs.append(log)
            self.cli.logs.append((logpath, set()))
            process = subprocess.Popen([self.args.sshd, "-D", "-e", "-f", str(config)], stdout=log, stderr=log, env=self.env)
            self.servers.append(process)
            deadline = time.monotonic() + 5
            while True:
                require(process.poll() is None and time.monotonic() < deadline)
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            public = hostkey.with_suffix(".pub").read_text().split()
            with self.known_hosts.open("a") as known:
                known.write("[127.0.0.1]:" + str(port) + " " + " ".join(public[:2]) + "\n")

    def ssh_args(self, index, endpoint, forwarding=False):
        return ["/usr/bin/ssh", "-F", "/dev/null", "-p", str(self.ports[index]), "-o", "UserKnownHostsFile=" + str(self.known_hosts),
                "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=" + str(endpoint),
                "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "ConnectTimeout=8", "-o", "LogLevel=ERROR",
                "-i", str(self.root / "imported.pub"), *( ["-A"] if forwarding else []), self.username + "@127.0.0.1"]

    def openssh(self):
        self.servers_start()
        self.stage = "openssh"
        args = self.ssh_args(0, self.endpoint) + ["/usr/bin/printf", "owned-real-ssh-authenticated"]
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        self.children.append(("real-ssh", process))
        self.approve(self.import_public, expected_pid=process.pid)
        out, error = process.communicate(timeout=15)
        self.save_process("real-ssh", out, error)
        require(process.returncode == 0 and out == b"owned-real-ssh-authenticated" and not error)
        self.mark("real_openssh_authentication_to_pinned_owned_loopback_server")
        self.stage = "forwarding"
        # The second client inherits ONLY the forwarded socket created by sshd.
        # IdentityAgent=SSH_AUTH_SOCK explicitly resolves that remote variable.
        second = self.ssh_args(1, "SSH_AUTH_SOCK") + ["/usr/bin/printf", "owned-real-two-hop-forwarding"]
        first = self.ssh_args(0, self.relay.path, forwarding=True) + [shlex.join(second)]
        process = subprocess.Popen(first, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        self.children.append(("two-hop", process))
        one = self.approve(self.import_public, expected_pid=os.getpid())
        two = self.approve(self.import_public, expected_pid=os.getpid())
        require(one["请求 ID"] != two["请求 ID"] and one["载荷 SHA256"] != two["载荷 SHA256"])
        out, error = process.communicate(timeout=15)
        self.save_process("two-hop", out, error)
        require(process.returncode == 0 and out == b"owned-real-two-hop-forwarding" and not error)
        self.mark("real_ssh_A_two_hops_each_require_distinct_native_approval_destination_unverified")

    def save_process(self, name, out, error):
        for suffix, raw in (("stdout", out), ("stderr", error)):
            path = self.root / (name + "." + suffix)
            path.write_bytes(raw)
            self.cli.logs.append((path, set()))

    def deadlines_lock(self):
        self.stage = "expired"
        with self.request(self.import_public, os.urandom(100)) as connection:
            self.observed_approval()
            connection.settimeout(33)
            require(receive(connection) == b"\x05")
        self.wait("copy-endpoint")
        self.mark("original_human_deadline_expires_without_approval_or_signature")
        self.stage = "slow-frame"
        with self.connect() as connection:
            connection.settimeout(38)
            connection.sendall(b"\x00")
            require(connection.recv(1) == b"")
        self.mark("partial_slow_frame_expires_without_native_prompt")
        self.stage = "lock"
        pending = self.request(self.import_public, os.urandom(50))
        self.observed_approval()
        self.click("locked")
        prefix = pending.recv(4)
        if prefix:
            prefix += exact(pending, 4 - len(prefix))
            require(struct.unpack(">I", prefix)[0] == 1 and exact(pending, 1) == b"\x05")
        pending.close()
        self.wait("unlock")
        require(not pathlib.Path(self.endpoint).exists())
        self.fill("master", self.cli.master)
        self.fill("key", self.cli.key)
        self.click("unlock")
        self.wait("ssh")
        self.click("ssh")
        self.wait("start")
        require(not pathlib.Path(self.endpoint).exists())
        self.mark("lock_cancels_pending_signature_and_unlock_does_not_restart_agent")
        self.click("start")
        self.wait("copy-endpoint")
        require(stat_socket(self.endpoint))
        self.click("stop")
        self.wait("start")
        require(not pathlib.Path(self.endpoint).exists())
        self.mark("manual_restart_and_explicit_stop_own_only_the_created_endpoint")

    def final_oracles(self):
        self.click("locked")
        self.wait("unlock")
        self.app.terminate()
        self.app.wait(timeout=10)
        factors = [("主密码", self.cli.master), ("Secret Key", self.cli.key)]
        self.stage = "export"
        export_password = self.cli.secret("Export")
        dest, expected = self.root / "ssh-export.kdbx", self.root / "peer-expectations-private.json"
        out, _, _ = self.cli.invoke("export-kdbx", factors + [("新导出密码（至少 12 字符）", export_password),
            ("再次输入导出密码", export_password), ("输入 SAVE 确认加密导出", "SAVE")], options=("--out", dest))
        require(json.loads(out)["status"] == "exported-encrypted")
        self.cli.write(expected, {"password": export_password, "seed": base64.b64encode(self.import_seed).decode(),
            "public": base64.b64encode(self.import_public).decode(), "generated": base64.b64encode(self.generated_public).decode()})
        peer_result = self.root / "peer-result-private.json"
        self.command([self.args.peer, str(ROOT / "scripts/ssh_kdbx_peer.py"), str(dest), str(expected), str(peer_result)])
        oracle = json.loads(peer_result.read_bytes())
        require(oracle["verified"] is True)
        generated_seed = base64.b64decode(oracle["generated_seed"], validate=True)
        require(len(generated_seed) == 32 and generated_seed != self.import_seed)
        self.secret_bytes.append(generated_seed)
        self.cli.values.extend((base64.b64encode(generated_seed).decode(), generated_seed.hex()))
        self.mark("independent_pykeepass_protected_seed_public_wire_and_generated_key_derivation")
        self.stage = "audit"
        out, _, _ = self.cli.invoke("audit", factors)
        events = json.loads(out)
        verify_audit(events, self.approvals)
        self.mark("signed_journal_exact_key_revision_and_exact_individual_approval_count")

    def privacy(self):
        self.stage = "privacy"
        for path, allowed in self.cli.logs:
            raw = path.read_bytes()
            scan(raw, [value for value in self.cli.values if value not in allowed])
            require(all(value not in raw for value in self.secret_bytes))
        for path in self.root.glob("agent-wire-*.*"):
            raw = path.read_bytes()
            scan(raw, self.cli.values)
            require(all(value not in raw for value in self.secret_bytes))
            if path.suffix == ".response":
                offset = 0
                while offset < len(raw):
                    require(len(raw) - offset >= 4)
                    size = struct.unpack(">I", raw[offset:offset + 4])[0]
                    value = raw[offset + 4:offset + 4 + size]
                    require(size == len(value) and 1 <= size <= 65536 and value[0] in (5, 12, 14))
                    if value[0] == 5:
                        require(value == b"\x05")
                    elif value[0] == 12:
                        identities(value)
                    else:
                        wire, rest = take_string(value[1:])
                        kind, wire = take_string(wire)
                        signature, tail = take_string(wire)
                        require(kind == b"ssh-ed25519" and len(signature) == 64 and not rest and not tail)
                    offset += 4 + size
        self.mark("full_public_outputs_and_observed_agent_wire_contain_no_factors_or_private_seed")

    def run(self):
        self.create()
        self.manage()
        self.core_protocol()
        self.openssh()
        self.deadlines_lock()
        self.final_oracles()

    def diagnose(self):
        for alias, title in (("app", TITLE), ("picker", "选择未加密 OpenSSH Ed25519 私钥")):
            try:
                controls = self.native(title=title, inspect=True)["controls"]
                labels = {**LABELS, "open-en": "Open", "open-zh": "打开", "select-en": "Select", "select-zh": "选择"}
                self.control_diagnostic[alias] = {name: controls[label] for name, label in labels.items() if label in controls}
            except Exception:
                self.control_diagnostic[alias] = {"available": False}

    def close(self):
        for name, child in self.children:
            if child.poll() is None:
                child.terminate()
            if child.stdout and not child.stdout.closed:
                out, error = child.communicate(timeout=5)
                self.save_process(name, out, error)
        if self.app and self.app.poll() is None:
            self.app.terminate()
            self.app.wait(timeout=10)
        for server in self.servers:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=5)
        if self.wm and self.wm.poll() is None:
            self.wm.terminate()
            self.wm.wait(timeout=5)
        if self.relay:
            self.relay.close()
        self.log.close()
        for log in self.worker_logs:
            log.close()


def stat_socket(path):
    import stat
    info = os.lstat(path)
    return stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--gh", default="/usr/bin/gh")
    parser.add_argument("--sshd", default="/usr/sbin/sshd")
    parser.add_argument("--peer", required=True, help="Python executable with independent PyKeePass/cryptography")
    parser.add_argument("--fixture-bin")
    parser.add_argument("--window-manager", help="optional window manager executable for a fresh owned display only")
    parser.add_argument("--artifacts", default="/tmp/locklark-validation")
    args = parser.parse_args(argv)
    os.umask(0o077)
    acceptance, success = None, False
    try:
        acceptance = Acceptance(args)
        acceptance.run()
        success = True
    except Exception as error:
        if acceptance:
            classes = {AcceptanceFailure: "assertion", OSError: "os", subprocess.TimeoutExpired: "timeout",
                       ValueError: "value", TypeError: "type", KeyError: "key", json.JSONDecodeError: "json"}
            acceptance.error_class = classes.get(type(error), "unexpected")
            trace = error.__traceback__
            while trace:
                if pathlib.Path(trace.tb_frame.f_code.co_filename).resolve() == pathlib.Path(__file__).resolve():
                    acceptance.error_line = trace.tb_lineno
                trace = trace.tb_next
            previous_reason = acceptance.reason
            try:
                acceptance.diagnose()
            except Exception:
                pass
            acceptance.reason = previous_reason
    finally:
        if acceptance:
            try:
                acceptance.close()
            except Exception:
                success, acceptance.stage = False, "cleanup"
            previous_stage = acceptance.stage
            try:
                acceptance.privacy()
            except Exception:
                success, previous_stage = False, "privacy"
            acceptance.stage = "complete" if success else previous_stage
            stage = acceptance.stage if acceptance.stage in STAGES else "prerequisites"
            acceptance.cli.write(acceptance.root / "ssh-result.json", {"success": success, "stage": stage,
                "operation": acceptance.operation if acceptance.operation in LABELS else "none", "reason": acceptance.reason,
                "error_class": acceptance.error_class, "source_line": acceptance.error_line,
                "controls": acceptance.control_diagnostic, "checks": acceptance.checks})
            print(("PASS" if success else "FAIL") + ": SSH acceptance at " + stage)
            print("Private SSH evidence: " + str(acceptance.root))
        else:
            print("FAIL: SSH acceptance at prerequisites")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
