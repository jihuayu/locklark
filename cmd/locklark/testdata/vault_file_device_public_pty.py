"""Run the real CLI on an owned controlling PTY; emit only a bounded verdict."""

import errno
import json
import os
import pty
import select
import signal
import sys
import time


MASTER_PROMPT = "主密码: ".encode("utf-8")
SECRET_PROMPT = b"Secret Key: "
AUTH_REFUSAL = b"locklark: invalid personal vault, unlock factors or journal\n"
MISSING_REFUSAL = b"locklark: terminal input cancelled or exceeded maximum length\n"


def verdict(status, echoed=False, public=None):
    print(json.dumps({"status": status, "echoed": echoed, "public": public}), flush=True)


def main():
    try:
        request = json.load(sys.stdin)
        product = request["product"]
        path = request["path"]
        password = request["password"].encode("utf-8")
        secret = request["secret"].encode("ascii")
        missing = request["missing_secret"]
        if not os.path.isabs(product) or not os.path.isabs(path):
            verdict("HARNESS_ERROR")
            return
        pid, master = pty.fork()
        if pid == 0:
            os.execv(product, [product, "personal", "vault-file-device-public", "--file", path])
        output = bytearray()
        phase = 0
        deadline = time.monotonic() + 20
        status = None
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        break
                    chunk = b""
                if chunk:
                    output.extend(chunk)
                    if len(output) > 128 * 1024:
                        break
                    if phase == 0 and MASTER_PROMPT in output:
                        os.write(master, password + b"\n")
                        phase = 1
                    if phase == 1 and SECRET_PROMPT in output:
                        os.write(master, b"\x04" if missing else secret + b"\n")
                        phase = 2
            got, wait_status = os.waitpid(pid, os.WNOHANG)
            if got == pid:
                status = wait_status
                break
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            verdict("HARNESS_ERROR")
            return
        echoed = password in output or secret in output
        public = None
        for line in output.splitlines():
            if line.startswith(b"{"):
                try:
                    public = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    pass
        normalized = bytes(output).replace(b"\r\n", b"\n")
        expected = (MASTER_PROMPT + b"\n" + SECRET_PROMPT +
                    (b"" if missing else b"\n") +
                    (MISSING_REFUSAL if missing else AUTH_REFUSAL))
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and phase == 2 and isinstance(public, dict):
            verdict("PUBLIC", echoed, public)
        elif (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 1 and
              phase == 2 and not echoed and public is None and normalized == expected):
            verdict("REFUSED")
        else:
            verdict("HARNESS_ERROR", echoed)
    except (KeyError, OSError, ValueError):
        verdict("HARNESS_ERROR")


if __name__ == "__main__":
    main()
