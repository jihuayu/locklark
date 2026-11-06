#!/usr/bin/env python3
"""Real RunCLI PTY + actual gh + explicitly owned CONNECT/TLS acceptance.

Only fixed classifications are printed. The TLS receiver intentionally sees
Authorization; its complete request is a private oracle, not a no-disclosure
claim. Initial account-key issuance is also an explicitly private oracle.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import pty
import re
import select
import signal
import socketserver
import ssl
import subprocess
import sys
import tempfile
import termios
import threading
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
STAGES = {"prerequisites", "certificates", "create", "login", "gh-success", "gh-error", "gh-stdin", "gh-pipes", "no-ctty",
          "deny", "stale", "wrong-factors", "forbidden-gh", "stdio-exit", "timeout", "signal", "privacy", "cleanup", "complete"}


class AcceptanceFailure(Exception):
    pass


def require(condition):
    if not condition:
        raise AcceptanceFailure()


def scan(raw, values):
    for value in values:
        source = value.encode()
        for pattern in (source, base64.b64encode(source), source.hex().encode(), json.dumps(value)[1:-1].encode()):
            require(pattern not in raw)


class TLSOracle(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, root, token, certificate, key):
        self.root, self.token, self.requests, self.failures = root, token, [], []
        self.mutex = threading.Lock()
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_3
        self.tls.load_cert_chain(certificate, key)
        super().__init__(("127.0.0.1", 0), OracleConnection)

    def record(self, value):
        with self.mutex:
            self.requests.append(value)
            path = self.root / "tls-request-oracle-private.json"
            path.write_text(json.dumps(self.requests))
            path.chmod(0o600)

    def handle_error(self, request, client_address):
        with self.mutex:
            self.failures.append("owned-tls-request-failed")


class OracleConnection(socketserver.BaseRequestHandler):
    @staticmethod
    def exact(connection, length):
        result = bytearray()
        while len(result) < length:
            chunk = connection.recv(length - len(result))
            require(bool(chunk))
            result.extend(chunk)
        return bytes(result)

    @staticmethod
    def headers(connection):
        value = bytearray()
        while not value.endswith(b"\r\n\r\n"):
            part = connection.recv(1)
            require(bool(part) and len(value) < 65536)
            value.extend(part)
        return bytes(value)

    @classmethod
    def body(cls, connection, headers):
        if "transfer-encoding" not in headers:
            length = int(headers.get("content-length", "0"))
            require(0 <= length <= 1 << 20)
            return cls.exact(connection, length)
        require(headers["transfer-encoding"] == "chunked" and "content-length" not in headers)
        result = bytearray()
        while True:
            line = bytearray()
            while not line.endswith(b"\r\n"):
                require(len(line) < 128)
                line.extend(cls.exact(connection, 1))
            size_text = bytes(line[:-2]).split(b";", 1)[0]
            require(bool(re.fullmatch(rb"[0-9a-fA-F]{1,8}", size_text)))
            size = int(size_text, 16)
            require(size <= (1 << 20) - len(result))
            if size == 0:
                require(cls.exact(connection, 2) == b"\r\n")
                return bytes(result)
            result.extend(cls.exact(connection, size))
            require(cls.exact(connection, 2) == b"\r\n")

    def handle(self):
        self.request.settimeout(8)
        connect = self.headers(self.request)
        require(connect.split(b"\r\n", 1)[0] == b"CONNECT api.github.com:443 HTTP/1.1")
        self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        with self.server.tls.wrap_socket(self.request, server_side=True) as secure:
            raw = self.headers(secure)
            lines = raw.decode("ascii").split("\r\n")
            method, path, version = lines[0].split(" ")
            headers = {line.split(":", 1)[0].lower(): line.split(":", 1)[1].strip() for line in lines[1:] if ":" in line}
            body = self.body(secure, headers)
            authorized = headers.get("authorization") in ("token " + self.server.token, "Bearer " + self.server.token)
            self.server.record({"method": method, "path": path, "headers": headers, "body": bytes(body).decode(),
                                "selected_token_matches": authorized, "tls13": secure.version() == "TLSv1.3"})
            require(authorized and version == "HTTP/1.1")
            if path == "/user" and method == "GET":
                status, response = "200 OK", {"login": "locklark-owned-fixture", "id": 8675309}
            elif path == "/owned-denied" and method == "GET":
                status, response = "403 Forbidden", {"message": "owned fixture refusal"}
            elif path == "/owned-stdin" and method == "POST":
                require(json.loads(body) == {"marker": "owned stdin marker"})
                status, response = "200 OK", {"received": "owned stdin marker"}
            else:
                raise AcceptanceFailure()
            payload = json.dumps(response).encode()
            secure.sendall(("HTTP/1.1 " + status + "\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                            + str(len(payload)) + "\r\n\r\n").encode() + payload)


class Acceptance:
    def __init__(self, args):
        self.args = args
        parent = pathlib.Path(args.artifacts).resolve()
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="run-cli-", dir=parent))
        self.stage, self.checks, self.logs, self.values = "prerequisites", [], [], []
        self.parent_environment = dict(os.environ)
        self.server, self.thread, self.counter = None, None, 0
        self.cli = str(pathlib.Path(args.cli).absolute())
        self.gh = str(pathlib.Path(args.gh).absolute())
        self.wrapper = pathlib.Path(args.fixture_bin).absolute() if args.fixture_bin else self.root / "trusted-gh-fixture"
        self.vault = self.root / "personal.ll"
        self.master = self.secret("Master")
        self.token = self.secret("ghp_")
        self.poison = self.secret("ParentOnly")
        self.key = None
        self.global_home = self.root / "parent-home"
        (self.global_home / ".config/gh").mkdir(mode=0o700, parents=True)
        self.global_config = self.global_home / ".config/gh/hosts.yml"
        self.global_config.write_text("github.com:\n  oauth_token: " + self.poison + "\n")
        self.global_digest = hashlib.sha256(self.global_config.read_bytes()).digest()
        self.temps = self.root / "product-temporary"
        self.temps.mkdir(mode=0o700)
        self.environment = dict(os.environ)
        self.environment.update({"HOME": str(self.global_home), "TMPDIR": str(self.temps), "GH_TOKEN": self.poison,
            "GITHUB_TOKEN": self.poison, "HTTPS_PROXY": "http://127.0.0.1:1", "GH_DEBUG": "api", "GH_HOST": "untrusted.invalid",
            "SSH_AUTH_SOCK": str(self.root / "untrusted.sock"), "GH_CONFIG_DIR": str(self.global_home / ".config/gh")})

    def secret(self, prefix):
        value = prefix + os.urandom(24).hex()
        self.values.append(value)
        return value

    def write(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def mark(self, name):
        self.checks.append(name)
        print("PASS: RunCLI " + name, flush=True)

    def command(self, arguments):
        self.counter += 1
        result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, cwd=ROOT,
                                env={**os.environ, "GOTOOLCHAIN": "go1.27.3"})
        for name, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = self.root / f"command-{self.counter}.{name}"
            path.write_bytes(raw)
            self.logs.append((path, set()))
        require(result.returncode == 0)

    def certificates(self):
        self.stage = "certificates"
        ca, ca_key, key, csr, certificate = (self.root / name for name in ("ca.pem", "ca.key", "server.key", "server.csr", "server.pem"))
        self.command(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-days", "1", "-subj", "/CN=Owned acceptance root",
                      "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(ca_key), "-out", str(ca)])
        self.command(["openssl", "req", "-new", "-newkey", "ed25519", "-nodes", "-subj", "/CN=api.github.com", "-keyout", str(key), "-out", str(csr)])
        extensions = self.root / "server.ext"
        extensions.write_text("subjectAltName=DNS:api.github.com\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n")
        self.command(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1",
                      "-extfile", str(extensions), "-out", str(certificate)])
        self.ca = ca
        self.server = TLSOracle(self.root, self.token, certificate, key)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def build_fixture(self):
        if self.args.fixture_bin:
            require(self.wrapper.is_file())
            return
        self.command([self.args.go, "build", "-o", str(self.wrapper), "./scripts/run_cli_fixture"])

    def invoke(self, action, answers=(), *, options=(), issue=False, stdin=None, record=None, expected=0,
               stdin_pipe=False, stderr_pipe=False, controlling=True, parent_signal=None):
        self.counter += 1
        prefix = self.root / f"pty-{self.counter}-{action}"
        master, slave = pty.openpty()
        terminal, stdout, stderr, issued = bytearray(), b"", b"", None
        process = None
        try:
            arguments = [self.cli, "personal", action, "--file", str(self.vault), *map(str, options)]
            if controlling:
                arguments = [str(self.wrapper), "ctty", os.ttyname(slave), *arguments]
            process = subprocess.Popen(arguments, stdin=subprocess.PIPE if stdin_pipe else slave,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE if stderr_pipe else slave,
                start_new_session=True, env=self.environment, cwd=self.root)
            if stdin_pipe:
                process.stdin.write((stdin or b"") + (b"\n" if stdin is not None else b""))
                process.stdin.close()
                process.stdin = None
            offset = 0
            for prompt, value in answers:
                marker = (prompt + ": ").encode()
                end = time.monotonic() + 20
                while marker not in terminal[offset:]:
                    require(time.monotonic() < end and process.poll() is None)
                    if select.select([master], [], [], 0.1)[0]:
                        chunk = os.read(master, 4096)
                        require(bool(chunk))
                        terminal.extend(chunk)
                offset = terminal.index(marker, offset) + len(marker)
                require(not termios.tcgetattr(slave)[3] & termios.ECHO)
                if value is None:
                    match = re.search(rb"LL1-[A-Z2-7]{26}", terminal)
                    require(issue and match is not None)
                    value = issued = match.group().decode()
                    self.values.append(value)
                os.write(master, value.encode() + b"\n")
            if (stdin is not None and not stdin_pipe) or parent_signal is not None:
                end = time.monotonic() + 10
                while not record.is_file():
                    require(time.monotonic() < end and process.poll() is None)
                    if select.select([master], [], [], 0.05)[0]:
                        terminal.extend(os.read(master, 4096))
                require(bool(termios.tcgetattr(slave)[3] & termios.ECHO))
                if parent_signal is not None:
                    process.send_signal(parent_signal)
                else:
                    os.write(master, stdin + b"\n\x04")
            stdout, stderr = process.communicate(timeout=35)
            stderr = stderr or b""
            while select.select([master], [], [], 0)[0]:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                terminal.extend(chunk)
            require(process.returncode == expected)
            require(bool(termios.tcgetattr(slave)[3] & termios.ECHO))
            return stdout, issued, stderr if stderr_pipe else bytes(terminal)
        finally:
            if process and process.poll() is None:
                process.kill()
            # Preserve complete child pipes even if prompt handling or a
            # deadline failed before the normal communicate call.
            if process and process.stdout and not process.stdout.closed:
                captured_out, captured_err = process.communicate(timeout=5)
                stdout, stderr = captured_out or stdout, captured_err or stderr
            while select.select([master], [], [], 0)[0]:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                terminal.extend(chunk)
            for name, raw in (("stdout", stdout), ("stderr", stderr), ("terminal", bytes(terminal))):
                path = prefix.with_suffix("." + name)
                path.write_bytes(raw)
                path.chmod(0o600)
                self.logs.append((path, {issued} if issue and name == "terminal" and issued else set()))
            os.close(master)
            os.close(slave)

    def request(self, name, gh_args, *, mode="gh", consent="RUN", expected=0, stdin=None, revision=None, master=None, timeout=20,
                stdin_pipe=False, stderr_pipe=False, controlling=True, parent_signal=None):
        record, config = self.root / (name + ".record-private.json"), self.root / (name + ".public.json")
        self.write(config, {"record": str(record), "mode": mode, "gh": self.gh,
                           "proxy": "http://127.0.0.1:" + str(self.server.server_address[1]), "ca": str(self.ca)})
        options = ("--id", self.item["id"], "--revision", revision or self.item["revision"], "--profile", "gh", "--name", "GH_TOKEN",
                   "--cwd", str(self.root), "--timeout", str(timeout), "--", self.wrapper, config, *gh_args)
        answers = [("主密码", master or self.master), ("Secret Key", self.key), ("输入 RUN 确认本次可信命令披露", consent)] if controlling else []
        before = len(self.server.requests)
        stdout, _, terminal = self.invoke("run-cli", answers, options=options, stdin=stdin, record=record, expected=expected,
            stdin_pipe=stdin_pipe, stderr_pipe=stderr_pipe, controlling=controlling, parent_signal=parent_signal)
        if record.is_file():
            value = json.loads(record.read_bytes())
            require(value["started"] and value["only_reviewed_environment"] and value["private_directories"] and value["terminal_echo_restored"])
            require(value["token_digest"] == hashlib.sha256(self.token.encode()).hexdigest())
            require(value["stdio_tty"] == [not stdin_pipe, False, not stderr_pipe] and value["helper_path"] == "")
            require(all(not pathlib.Path(path).exists() for path in value["paths"].values()))
        require(not list(self.temps.iterdir()))
        return stdout, terminal, record, len(self.server.requests) - before

    def run(self):
        require(pathlib.Path(self.cli).is_file() and pathlib.Path(self.gh).is_file())
        self.build_fixture()
        self.certificates()
        self.stage = "create"
        result, self.key, _ = self.invoke("init", [("主密码", self.master), ("再次输入主密码", self.master), ("重新输入刚保存的 Secret Key", None)], issue=True)
        require(json.loads(result)["status"] == "created")
        self.stage = "login"
        result, _, _ = self.invoke("add-login", [("主密码", self.master), ("Secret Key", self.key), ("登录标题", "Owned gh acceptance"),
            ("用户名（可留空）", "owned-fixture"), ("登录密码", self.token)])
        added = json.loads(result)
        rows, _, _ = self.invoke("list", [("主密码", self.master), ("Secret Key", self.key)])
        self.item = next(row for row in json.loads(rows) if row["id"] == added["id"])
        self.stage = "gh-success"
        out, _, record, count = self.request("success", ["api", "/user", "--jq", ".login"])
        require(out == b"locklark-owned-fixture\n" and record.exists() and count == 1)
        self.mark("actual_gh_selected_token_tls13_stdout_and_child_only_environment")
        self.stage = "gh-error"
        out, error, _, count = self.request("http-error", ["api", "/owned-denied"], expected=1)
        require(json.loads(out)["message"] == "owned fixture refusal" and b"owned fixture refusal" in error and b"HTTP 403" in error and count == 1)
        self.mark("actual_gh_error_stderr_and_exact_nonzero_exit")
        self.stage = "gh-stdin"
        out, _, _, count = self.request("stdin", ["api", "/owned-stdin", "--method", "POST", "--input", "-"], stdin=b'{"marker":"owned stdin marker"}')
        require(json.loads(out)["received"] == "owned stdin marker" and count == 1)
        self.mark("actual_gh_reads_original_terminal_stdin_after_hidden_confirmation")
        self.stage = "gh-pipes"
        out, error, _, count = self.request("pipe-stdin", ["api", "/owned-stdin", "--method", "POST", "--input", "-"],
            stdin=b'{"marker":"owned stdin marker"}', stdin_pipe=True, stderr_pipe=True)
        require(json.loads(out)["received"] == "owned stdin marker" and not error and count == 1)
        out, error, _, count = self.request("pipe-stderr", ["api", "/owned-denied"], expected=1, stdin_pipe=True, stderr_pipe=True)
        require(json.loads(out)["message"] == "owned fixture refusal" and b"owned fixture refusal" in error and b"HTTP 403" in error
                and "输入 RUN".encode() not in error and "主密码".encode() not in error and count == 1)
        self.mark("actual_gh_pipe_stdin_untouched_and_pipe_stderr_has_only_child_output")
        self.stage = "no-ctty"
        out, _, record, count = self.request("no-ctty", ["api", "/user"], expected=1, stdin_pipe=True, stderr_pipe=True, controlling=False)
        require(not out and not record.exists() and count == 0)
        self.mark("no_controlling_terminal_refuses_before_start")
        for stage, arguments in (("deny", {"consent": "NO"}), ("stale", {"revision": "0" * 64}),
                                 ("wrong-factors", {"master": self.master + "wrong"})):
            self.stage = stage
            out, _, record, count = self.request(stage, ["api", "/user"], expected=1, **arguments)
            require(not out and not record.exists() and count == 0)
        self.mark("deny_stale_revision_and_wrong_factors_start_zero_children")
        self.stage = "forbidden-gh"
        record = self.root / "forbidden.record-private.json"
        config = self.root / "forbidden.public.json"
        self.write(config, {"record": str(record), "mode": "gh"})
        options = ("--id", self.item["id"], "--revision", self.item["revision"], "--profile", "gh", "--name", "GH_TOKEN", "--cwd", str(self.root),
                   "--timeout", "10", "--", self.wrapper, config, "auth", "login")
        out, _, _ = self.invoke("run-cli", options=options, expected=1)
        require(not out and not record.exists())
        self.mark("persistent_gh_auth_profile_rejected_before_disclosure")
        self.stage = "stdio-exit"
        out, error, _, count = self.request("stdio", [], mode="stdio", expected=23, stdin=b"owned stdin marker")
        require(out == b"owned child stdout\n" and b"owned child stderr" in error and count == 0)
        self.mark("real_standard_streams_and_arbitrary_child_exit_preserved_without_footer")
        self.stage = "timeout"
        out, error, record, count = self.request("timeout", [], mode="slow", expected=1, timeout=1)
        require(not out and record.exists() and b"local process result unavailable" in error and count == 0)
        self.mark("timed_out_started_child_reports_unknown_and_cleans_private_configuration")
        self.stage = "signal"
        for label, signum in (("interrupt", signal.SIGINT), ("terminate", signal.SIGTERM)):
            out, error, record, count = self.request(label, [], mode="slow", expected=1, parent_signal=signum)
            require(not out and record.exists() and b"local process result unavailable" in error and count == 0)
        self.mark("interrupt_and_terminate_after_start_report_unknown_and_cleanup")
        self.stage = "privacy"
        require(not self.server.failures and all(r["selected_token_matches"] and r["tls13"] for r in self.server.requests))
        require(hashlib.sha256(self.global_config.read_bytes()).digest() == self.global_digest and dict(os.environ) == self.parent_environment)
        for path, allowed in self.logs:
            scan(path.read_bytes(), [value for value in self.values if value not in allowed])
        self.mark("all_public_output_canaries_clean_parent_environment_and_global_config_unchanged")
        self.stage = "complete"

    def close(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)
            self.server = None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--gh", default="/usr/bin/gh")
    parser.add_argument("--go", default="go")
    parser.add_argument("--fixture-bin", help="independently fixed trusted fixture executable")
    parser.add_argument("--artifacts", default="/tmp/locklark-validation")
    args = parser.parse_args(argv)
    os.umask(0o077)
    acceptance, success = None, False
    try:
        acceptance = Acceptance(args)
        acceptance.run()
        success = True
    except Exception:
        pass
    finally:
        if acceptance:
            try:
                acceptance.close()
            except Exception:
                success, acceptance.stage = False, "cleanup"
            try:
                for path, allowed in acceptance.logs:
                    scan(path.read_bytes(), [value for value in acceptance.values if value not in allowed])
            except Exception:
                success, acceptance.stage = False, "privacy"
            stage = acceptance.stage if acceptance.stage in STAGES else "prerequisites"
            acceptance.write(acceptance.root / "result.json", {"success": success, "stage": stage, "checks": acceptance.checks})
            if not success:
                print("FAIL: RunCLI acceptance at " + stage)
            print("Private RunCLI evidence: " + str(acceptance.root))
        else:
            print("FAIL: RunCLI acceptance at prerequisites")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
